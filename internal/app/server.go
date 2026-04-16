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

	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/network/standard"

	"My-OpenWaf/internal/admin"
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
	defer eventWriter.Close()

	// Event archiver (auto-delete events older than 30 days).
	archiver := observability.NewArchiver(repos.SecurityEvent, logger.New("archiver"), 30)
	defer archiver.Close()

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
		Holder:      rt.Snapshot,
		Engine:      eng,
		Metrics:     metrics,
		EventWriter: eventWriter,
		Log:         dpLog,
	}

	// reconcileListeners compares current listeners with snapshot and starts/stops as needed.
	// It also detects config drift (bind address changes, TLS toggle, cert changes)
	// and restarts affected listeners automatically.
	reconcileListeners := func() {
		newSn := rt.Snapshot.Load()
		if newSn == nil {
			return
		}

		// Build set of desired data listener names + fingerprints.
		type desiredEntry struct {
			listener store.Listener
			tag      string // config fingerprint for drift detection
		}
		desired := make(map[string]desiredEntry)
		for lid, l := range newSn.DataListeners {
			name := dataListenerName(lid, l.Bind)
			tag := listenerFingerprint(lid, l, newSn)
			desired[name] = desiredEntry{listener: l, tag: tag}
		}

		// Remove listeners that no longer exist or whose config has changed.
		for _, name := range lm.Names() {
			if !strings.HasPrefix(name, "data:") {
				continue
			}
			de, wantExists := desired[name]
			if !wantExists {
				// Listener was deleted or its bind address changed (new name).
				log.Info("removing stale data listener", slog.String("name", name))
				lm.Remove(name)
				continue
			}
			// Listener still exists — check if config drifted (TLS toggle, cert change, etc.).
			if lm.Tag(name) != de.tag {
				log.Info("restarting data listener due to config change",
					slog.String("name", name),
					slog.String("old_tag", lm.Tag(name)),
					slog.String("new_tag", de.tag),
				)
				lm.Remove(name)
				// Will be re-added in the next loop below.
			}
		}

		// Add new or restarted listeners.
		for name, de := range desired {
			if lm.Has(name) {
				continue
			}
			l := de.listener
			lid := listenerIDFromName(name, newSn.DataListeners)

			srv := buildDataServer(l, lid, newSn, dpOpts)

			lm.AddHertzWithTag(name, srv, de.tag)
			lm.StartOne(name)
			log.Info("hot-started data listener",
				slog.String("bind", l.Bind),
				slog.Uint64("listener_id", uint64(lid)),
				slog.Bool("tls", l.TLSEnabled),
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

	// ─── Admin control-plane server ───
	adminSrv := server.Default(server.WithHostPorts(rt.Config.AdminBind))
	adminSrv.GET("/healthz", hc.LivenessHandler())
	adminSrv.GET("/readyz", hc.ReadinessHandler())
	adminSrv.GET("/status", hc.StatusHandler())
	adminSrv.GET("/metrics", observability.PrometheusHandler(promMetrics))
	admin.RegisterRoutes(adminSrv, &admin.Dependencies{
		Repos:     repos,
		Reload:    reload,
		StaticFS:  rt.Config.AdminStaticDir,
		JWTSecret: jwtSecret,
		Metrics:   metrics,
		DB:        rt.DB,
	})
	lm.AddHertz("admin:"+rt.Config.AdminBind, adminSrv)

	// ─── Data-plane listener(s) ───
	if sn != nil {
		for lid, l := range sn.DataListeners {
			name := dataListenerName(lid, l.Bind)
			tag := listenerFingerprint(lid, l, sn)
			srv := buildDataServer(l, lid, sn, dpOpts)
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

// dataListenerName creates a consistent name for a data listener.
func dataListenerName(lid uint, bind string) string {
	return fmt.Sprintf("data:%d:%s", lid, bind)
}

// listenerIDFromName finds the listener ID by matching the name in the DataListeners map.
func listenerIDFromName(name string, listeners map[uint]store.Listener) uint {
	for lid, l := range listeners {
		if dataListenerName(lid, l.Bind) == name {
			return lid
		}
	}
	return 0
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
func buildDataServer(l store.Listener, lid uint, sn *snapshotpkg.Snapshot, dpOpts dataplane.Options) *server.Hertz {
	opts := []config.Option{
		server.WithHostPorts(l.Bind),
	}

	if l.TLSEnabled {
		tlsCfg := buildListenerTLS(lid, l, sn)
		if tlsCfg != nil {
			opts = append(opts,
				server.WithTLS(tlsCfg),
				server.WithTransport(standard.NewTransporter),
			)
		}
	}

	srv := server.Default(opts...)
	o := dpOpts
	o.ListenerID = lid
	handler := dataplane.Handler(o)
	srv.Use(handler)
	return srv
}

// buildListenerTLS constructs a *tls.Config for a data listener.
// It uses the listener's own certificate and adds SNI-based per-site certs.
func buildListenerTLS(lid uint, l store.Listener, sn *snapshotpkg.Snapshot) *tls.Config {
	if sn == nil {
		return nil
	}

	// Collect all certificates: listener default + per-site SNI.
	var certs []tls.Certificate

	// Listener-level default cert (already parsed in snapshot build).
	if cert, ok := sn.ListenerTLSCert[lid]; ok {
		certs = append(certs, cert)
	}

	// Per-site SNI certs for this listener (key is "sni:<lid>\x00<host>").
	for sniKey, cert := range sn.SiteTLSCertBySNI {
		// SNI keys are prefixed with "sni:<lid>\x00<host>", check listener ID.
		prefix := "sni:" + fmt.Sprintf("%d", lid) + "\x00"
		if strings.HasPrefix(sniKey, prefix) {
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil
	}

	// Parse TLS version bounds.
	minVer := parseTLSVersion(l.MinTLSVersion)
	maxVer := parseTLSVersion(l.MaxTLSVersion)
	if minVer == 0 {
		minVer = tls.VersionTLS12
	}
	if maxVer == 0 {
		maxVer = tls.VersionTLS13
	}

	// Parse ALPN protocols.
	var alpn []string
	if l.ALPN != "" {
		for _, p := range strings.Split(l.ALPN, ",") {
			if s := strings.TrimSpace(p); s != "" {
				alpn = append(alpn, s)
			}
		}
	}

	return &tls.Config{
		Certificates: certs,
		MinVersion:   minVer,
		MaxVersion:   maxVer,
		NextProtos:   alpn,
	}
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

// listenerFingerprint produces a short hash that changes whenever the
// listener's effective configuration (bind, TLS, cert content) changes.
// This is used by reconcileListeners to detect drift and restart servers.
func listenerFingerprint(lid uint, l store.Listener, sn *snapshotpkg.Snapshot) string {
	h := sha256.New()
	fmt.Fprintf(h, "lid=%d bind=%s tls=%v min=%s max=%s alpn=%s",
		lid, l.Bind, l.TLSEnabled, l.MinTLSVersion, l.MaxTLSVersion, l.ALPN)

	// Include listener cert raw bytes in the fingerprint.
	if cert, ok := sn.ListenerTLSCert[lid]; ok && len(cert.Certificate) > 0 {
		fmt.Fprintf(h, " certlen=%d", len(cert.Certificate[0]))
		if len(cert.Certificate[0]) >= 16 {
			fmt.Fprintf(h, " certhead=%x", cert.Certificate[0][:16])
		}
	}

	// Include per-site SNI cert fingerprints for this listener.
	prefix := "sni:" + fmt.Sprintf("%d", lid) + "\x00"
	for sniKey, cert := range sn.SiteTLSCertBySNI {
		if strings.HasPrefix(sniKey, prefix) && len(cert.Certificate) > 0 {
			fmt.Fprintf(h, " sni=%s:len=%d", sniKey, len(cert.Certificate[0]))
		}
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}
