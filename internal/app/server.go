package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/network/standard"

	"My-OpenWaf/internal/admin"
	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/core"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/core/health"
	"My-OpenWaf/internal/core/lifecycle"
	coreredis "My-OpenWaf/internal/core/redis"
	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/pkg/logger"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf"
)

func Run() {
	log := logger.New("app")
	ctx := context.Background()

	rt, err := core.NewRuntime(ctx)
	if err != nil {
		log.Error("core init failed", slog.Any("err", err))
		os.Exit(1)
	}
	defer func() { _ = rt.Close() }()

	if err := store.AutoMigrate(rt.DB); err != nil {
		log.Error("auto migrate failed", slog.Any("err", err))
		os.Exit(1)
	}

	seedLog := logger.New("seed")
	token, password, err := store.SeedDefaults(rt.DB, rt.Config.AdminBind, seedLog)
	if err != nil {
		log.Error("seed defaults failed", slog.Any("err", err))
		os.Exit(1)
	}
	if token != "" || password != "" {
		var bannerLines []string
		bannerLines = append(bannerLines, "FIRST RUN — save these credentials (shown only once)")
		bannerLines = append(bannerLines, "")
		if password != "" {
			bannerLines = append(bannerLines, "  Admin Username : admin")
			bannerLines = append(bannerLines, "  Admin Password : "+password)
		}
		if token != "" {
			bannerLines = append(bannerLines, "  API Token      : "+token)
		}
		bannerLines = append(bannerLines, "")
		logger.Banner(bannerLines...)
	}

	if err := rt.ReloadSnapshot(); err != nil {
		log.Error("initial snapshot build failed", slog.Any("err", err))
		os.Exit(1)
	}

	// Resolve JWT secret from env or DB.
	jwtSecret := resolveJWTSecret(rt)

	repos := repository.New(rt.DB)

	// Security event writer (async batch insert, non-blocking).
	eventWriter := observability.NewEventWriter(repos.SecurityEvent, logger.New("events"))
	if rt.Redis != nil {
		eventWriter.SetRedis(rt.Redis)
	}
	defer eventWriter.Close()

	// Access log writer (async batch insert, non-blocking).
	accessLogWriter := observability.NewAccessLogWriter(repos.AccessLog, logger.New("access_logs"))
	defer accessLogWriter.Close()

	// Event archiver (auto-delete security events, access logs and drop events older than 30 days).
	archiver := observability.NewArchiver(repos.SecurityEvent, repos.AccessLog, repos.DropEvent, logger.New("archiver"), 30)
	defer archiver.Close()

	responseCache := cache.NewResponseCache(64, 60)
	defer responseCache.Close()

	// Data-plane metrics (shared across all data listeners).
	metrics := dataplane.NewMetrics()

	// Rate limiters — configured from snapshot protection settings.
	sn := rt.Snapshot.Load()
	var prot store.ProtectionConfig
	if sn != nil {
		prot = sn.Protection
	}
	reqRL := waf.NewRateLimiter(prot.RequestRateLimitWindow, prot.RequestRateLimitMax, prot.RequestRateLimitEnabled)
	errRL := waf.NewRateLimiter(prot.ErrorRateLimitWindow, prot.ErrorRateLimitMax, prot.ErrorRateLimitEnabled)
	defer reqRL.Close()
	defer errRL.Close()

	// IP reputation (blacklist + whitelist + auto-ban).
	ipRep := waf.NewIPReputation()
	defer ipRep.Close()
	loadIPLists(ipRep, repos.IPList)
	ipRep.ConfigureAutoBan(prot.AutoBanEnabled, prot.AutoBanThreshold, prot.AutoBanWindow, prot.AutoBanDuration)

	eng := engine.New(rt.Snapshot, reqRL, errRL, ipRep)

	// TLS fingerprinter for native JA3 capture.
	tlsFP := waf.NewTLSFingerprinter()
	waf.SetTLSFingerprinter(tlsFP)

	// Drop executor (TCP connection close strategy).
	dropCfg := rt.Config.Drop
	dropExec := waf.NewDropExecutor(dropCfg.Enabled, logger.New("drop"))
	eng.SetDropExecutor(dropExec)

	// GeoIP resolver for bot two-phase scoring (graceful degradation if DB missing).
	var geoResolver *waf.MaxMindResolver
	botCfg := rt.Config.Bot
	if botCfg.Enabled {
		geoResolver = waf.NewMaxMindResolver(botCfg.GeoIPDBPath, botCfg.GeoIPDBPath, botCfg)
		eng.SetGeoResolver(geoResolver, botCfg.ScoreThreshold)
		// Also set the global GeoResolver so LookupGeo works everywhere.
		waf.SetGeoResolver(geoResolver)
	}

	// Redis config sync (distributed reload notifications).
	configSync := coreredis.NewConfigSync(rt.Redis, logger.New("config_sync"))
	if configSync != nil {
		defer configSync.Close()
	}

	// Prometheus-compatible metrics collector.
	promMetrics := observability.NewMetrics()

	hc := health.New(rt.DB, rt.Snapshot)
	lm := lifecycle.New(log)

	dpLog := logger.New("dataplane")

	// dataListenerOpts holds the shared options for creating data-plane handlers.
	dpOpts := dataplane.Options{
		Holder:          rt.Snapshot,
		Engine:          eng,
		Metrics:         metrics,
		EventWriter:     eventWriter,
		AccessLogWriter: accessLogWriter,
		DropEventRepo:   repos.DropEvent,
		ResponseCache:   responseCache,
		Log:             dpLog,
	}

	// reconcileListeners compares current listeners with snapshot and starts/stops as needed.
	// It also detects config drift (bind address changes, TLS toggle, cert changes)
	// and restarts affected listeners automatically.
	//
	// This implementation now works at the Site level: each enabled Site with valid
	// configuration gets its own Hertz server instance, allowing per-site start/stop.
	reconcileListeners := func() {
		newSn := rt.Snapshot.Load()
		if newSn == nil {
			return
		}

		// Build set of desired site-based listeners.
		type desiredEntry struct {
			siteID uint
			siteRT snapshotpkg.SiteRuntime
			tag    string
		}
		desired := make(map[string]desiredEntry)

		// Iterate through all sites in the snapshot to create per-site listeners.
		for _, siteRT := range newSn.Sites {
			// Each site gets its own listener instance.
			name := siteListenerName(siteRT.Site.ID, siteRT.Bind)
			tag := siteListenerFingerprint(siteRT.Site.ID, siteRT, newSn)
			desired[name] = desiredEntry{
				siteID: siteRT.Site.ID,
				siteRT: siteRT,
				tag:    tag,
			}
		}

		// Remove stale or changed site listeners.
		for _, name := range lm.Names() {
			if !strings.HasPrefix(name, "site:") {
				continue
			}
			de, wantExists := desired[name]
			if !wantExists {
				log.Info("removing stale site listener", slog.String("name", name))
				lm.Remove(name)
				continue
			}
			if lm.Tag(name) != de.tag {
				log.Info("restarting site listener due to config change",
					slog.String("name", name),
					slog.String("old_tag", lm.Tag(name)),
					slog.String("new_tag", de.tag),
				)
				lm.Remove(name)
			}
		}

		// Add new or restarted site listeners.
		for name, de := range desired {
			if lm.Has(name) {
				continue
			}
			srv := buildDataServer(de.siteRT, newSn, dpOpts)
			lm.AddHertzWithTag(name, srv, de.tag)
			lm.StartOne(name)
			log.Info("hot-started site listener",
				slog.String("name", name),
				slog.Uint64("site_id", uint64(de.siteID)),
				slog.String("bind", de.siteRT.Bind),
				slog.Bool("tls", de.siteRT.Site.TLSEnabled),
			)
		}
	}

	reload := func() error {
		if err := store.BumpRevision(rt.DB); err != nil {
			return err
		}
		if err := rt.ReloadSnapshot(); err != nil {
			return err
		}
		// Refresh rate limiter + IP reputation from latest protection config.
		if sn := rt.Snapshot.Load(); sn != nil {
			p := sn.Protection
			reqRL.Reconfigure(p.RequestRateLimitWindow, p.RequestRateLimitMax, p.RequestRateLimitEnabled)
			errRL.Reconfigure(p.ErrorRateLimitWindow, p.ErrorRateLimitMax, p.ErrorRateLimitEnabled)
			ipRep.ConfigureAutoBan(p.AutoBanEnabled, p.AutoBanThreshold, p.AutoBanWindow, p.AutoBanDuration)
		}
		loadIPLists(ipRep, repos.IPList)
		// Hot-reload data-plane listeners.
		reconcileListeners()
		// Notify other nodes via Redis pub/sub.
		if configSync != nil {
			configSync.PublishReload()
		}
		return nil
	}

	// Start Redis config sync subscriber in background.
	if configSync != nil {
		go configSync.Subscribe(func() error {
			if err := rt.ReloadSnapshot(); err != nil {
				return err
			}
			if sn := rt.Snapshot.Load(); sn != nil {
				p := sn.Protection
				reqRL.Reconfigure(p.RequestRateLimitWindow, p.RequestRateLimitMax, p.RequestRateLimitEnabled)
				errRL.Reconfigure(p.ErrorRateLimitWindow, p.ErrorRateLimitMax, p.ErrorRateLimitEnabled)
				ipRep.ConfigureAutoBan(p.AutoBanEnabled, p.AutoBanThreshold, p.AutoBanWindow, p.AutoBanDuration)
			}
			loadIPLists(ipRep, repos.IPList)
			reconcileListeners()
			return nil
		})
	}

	// ─── Auth subsystems ───
	tokenMgr := auth.NewTokenManager(jwtSecret, rt.DB)
	bruteForce := auth.NewBruteForceDetector(5, 15*time.Minute)
	sessionMgr := auth.NewSessionManager(rt.DB)

	// ─── Admin control-plane server ───
	adminSrv := server.Default(server.WithHostPorts(rt.Config.AdminBind))
	adminSrv.GET("/healthz", hc.LivenessHandler())
	adminSrv.GET("/readyz", hc.ReadinessHandler())
	adminSrv.GET("/status", hc.StatusHandler())
	adminSrv.GET("/metrics", observability.PrometheusHandler(promMetrics))
	admin.RegisterRoutes(adminSrv, &admin.Dependencies{
		Repos:      repos,
		Reload:     reload,
		StaticFS:   rt.Config.AdminStaticDir,
		JWTSecret:  jwtSecret,
		Metrics:    metrics,
		DB:         rt.DB,
		TokenMgr:   tokenMgr,
		BruteForce: bruteForce,
		SessionMgr: sessionMgr,
	})
	lm.AddHertz("admin:"+rt.Config.AdminBind, adminSrv)

	// ─── Data-plane listener(s) ───
	// Initialize site-based listeners from snapshot.
	if sn != nil {
		for _, siteRT := range sn.Sites {
			name := siteListenerName(siteRT.Site.ID, siteRT.Bind)
			tag := siteListenerFingerprint(siteRT.Site.ID, siteRT, sn)
			srv := buildDataServer(siteRT, sn, dpOpts)
			lm.AddHertzWithTag(name, srv, tag)
		}
	}

	log.Info("My-OpenWaf ready",
		slog.String("db_driver", rt.Config.DBDriver),
		slog.Bool("redis_enabled", rt.Redis != nil),
		slog.String("admin_bind", rt.Config.AdminBind),
	)

	lm.Start()
	lm.WaitForSignal()
}

// siteListenerName creates a consistent name for a site-based listener.
func siteListenerName(siteID uint, bind string) string {
	return fmt.Sprintf("site:%d:%s", siteID, bind)
}

func loadIPLists(rep *waf.IPReputation, repo *repository.IPListRepo) {
	if repo == nil {
		return
	}
	items, err := repo.AllEnabled()
	if err != nil {
		return
	}
	var blacks, whites []waf.IPListEntry
	for _, it := range items {
		e, ok := waf.ParseIPListEntry(it.Value, it.Note)
		if !ok {
			continue
		}
		if it.Kind == store.IPListBlack {
			blacks = append(blacks, e)
		} else if it.Kind == store.IPListWhite {
			whites = append(whites, e)
		}
	}
	rep.SetLists(blacks, whites)
}

func resolveJWTSecret(rt *core.Runtime) []byte {
	if s := strings.TrimSpace(os.Getenv("MY_OPENWAF_JWT_SECRET")); s != "" {
		return []byte(s)
	}
	var setting store.SystemSettings
	if err := rt.DB.Where("key = ?", "jwt_secret").First(&setting).Error; err == nil && setting.Value != "" {
		return []byte(setting.Value)
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	secret := hex.EncodeToString(b)
	rt.DB.Create(&store.SystemSettings{Key: "jwt_secret", Value: secret})
	return []byte(secret)
}

// ─── Data listener builder ──────────────────────────────────────────

// buildDataServer creates a Hertz server for a data-plane listener,
// optionally configured with TLS termination when the listener has TLS enabled.
func buildDataServer(siteRT snapshotpkg.SiteRuntime, sn *snapshotpkg.Snapshot, dpOpts dataplane.Options) *server.Hertz {
	site := siteRT.Site
	opts := []config.Option{
		server.WithHostPorts(site.Bind),
		server.WithUseRawPath(true),
		server.WithUnescapePathValues(false),
		server.WithDisablePreParseMultipartForm(true),
	}

	if site.TLSEnabled {
		tlsCfg := buildListenerTLS(siteRT, sn)
		if tlsCfg != nil {
			opts = append(opts,
				server.WithTLS(tlsCfg),
				server.WithTransport(standard.NewTransporter),
			)
		}
	}

	srv := server.Default(opts...)
	o := dpOpts
	o.Bind = site.Bind
	handler := dataplane.Handler(o)
	srv.Use(handler)
	return srv
}

// buildListenerTLS constructs a *tls.Config for a data listener.
// It uses the site's certificate and TLS configuration.
func buildListenerTLS(siteRT snapshotpkg.SiteRuntime, sn *snapshotpkg.Snapshot) *tls.Config {
	if sn == nil {
		return nil
	}

	site := siteRT.Site
	var certs []tls.Certificate

	// Use the site's TLS config if available
	if siteRT.TLSConfig != nil {
		return siteRT.TLSConfig
	}

	// Fallback: build from site certificate
	if siteRT.Certificate != nil {
		cert, err := tls.X509KeyPair([]byte(siteRT.Certificate.CertPEM), []byte(siteRT.Certificate.KeyPEM))
		if err == nil {
			certs = append(certs, cert)
		}
	}

	// Per-site SNI certs for this bind address
	for sniKey, cert := range sn.SiteTLSCertBySNI {
		prefix := "sni:" + site.Bind + "\x00"
		if strings.HasPrefix(sniKey, prefix) {
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil
	}

	// Parse TLS version bounds.
	minVer := parseTLSVersion(site.MinTLSVersion)
	maxVer := parseTLSVersion(site.MaxTLSVersion)
	if minVer == 0 {
		minVer = tls.VersionTLS12
	}
	if maxVer == 0 {
		maxVer = tls.VersionTLS13
	}

	// Parse ALPN protocols.
	var alpn []string
	if site.ALPN != "" {
		for _, p := range strings.Split(site.ALPN, ",") {
			if s := strings.TrimSpace(p); s != "" {
				alpn = append(alpn, s)
			}
		}
	}

	cfg := &tls.Config{
		Certificates: certs,
		MinVersion:   minVer,
		MaxVersion:   maxVer,
		NextProtos:   alpn,
	}
	// Wrap with TLS fingerprinter to capture JA3 from ClientHello.
	if fp := waf.GetTLSFingerprinter(); fp != nil {
		cfg = fp.WrapTLSConfig(cfg)
	}
	return cfg
}

// parseTLSVersion converts a string like "TLS12" to a tls version constant.
func parseTLSVersion(v string) uint16 {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "TLS10", "1.0":
		return tls.VersionTLS10
	case "TLS11", "1.1":
		return tls.VersionTLS11
	case "TLS12", "1.2":
		return tls.VersionTLS12
	case "TLS13", "1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
}

// ─── Config drift fingerprint ───────────────────────────────────────

// siteListenerFingerprint produces a short hash that changes whenever the
// site's listener configuration (bind, TLS, cert content) changes.
// This is used by reconcileListeners to detect drift and restart servers.
func siteListenerFingerprint(siteID uint, siteRT snapshotpkg.SiteRuntime, sn *snapshotpkg.Snapshot) string {
	site := siteRT.Site
	h := sha256.New()
	fmt.Fprintf(h, "site=%d bind=%s tls=%v min=%s max=%s alpn=%s",
		siteID, site.Bind, site.TLSEnabled, site.MinTLSVersion, site.MaxTLSVersion, site.ALPN)

	// Include site cert raw bytes in the fingerprint.
	if siteRT.Certificate != nil {
		fmt.Fprintf(h, " cert=%s", siteRT.Certificate.CertPEM[:min(64, len(siteRT.Certificate.CertPEM))])
	}

	// Include per-site SNI cert fingerprints for this bind address.
	prefix := "sni:" + site.Bind + "\x00"
	for sniKey, cert := range sn.SiteTLSCertBySNI {
		if strings.HasPrefix(sniKey, prefix) && len(cert.Certificate) > 0 {
			fmt.Fprintf(h, " sni=%s:len=%d", sniKey, len(cert.Certificate[0]))
		}
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
