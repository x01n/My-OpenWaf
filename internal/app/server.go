package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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

	// Derive challenge cookie secret from JWT secret for persistence across restarts.
	waf.SetChallengeSecret(jwtSecret)

	repos := repository.New(rt.DB)

	// Security event writer (async batch insert, non-blocking).
	eventWriter := observability.NewEventWriter(repos.SecurityEvent, logger.New("events"))
	if rt.Redis != nil {
		eventWriter.SetRedis(rt.Redis)
	}
	defer eventWriter.Close()

	// Access log writer (async batch insert, non-blocking).
	accessLogWriter := observability.NewAccessLogWriter(repos.AccessLog, logger.New("access_logs"))
	if rt.Redis != nil {
		accessLogWriter.SetRedis(rt.Redis)
	}
	defer accessLogWriter.Close()

	// Event archiver (auto-delete security events, access logs and drop events based on retention config).
	archiver := observability.NewArchiver(repos.SecurityEvent, repos.AccessLog, repos.DropEvent, logger.New("archiver"), 30)
	archiver.SetSettingsRepo(repos.SystemSettings)
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
	var reqRL waf.RateLimiterBackend
	var errRL waf.RateLimiterBackend
	if rt.Redis != nil {
		reqRL = waf.NewRedisRateLimiter(rt.Redis, "openwaf:request", prot.RequestRateLimitWindow, prot.RequestRateLimitMax, prot.RequestRateLimitEnabled)
		errRL = waf.NewRedisRateLimiter(rt.Redis, "openwaf:error", prot.ErrorRateLimitWindow, prot.ErrorRateLimitMax, prot.ErrorRateLimitEnabled)
	}
	if reqRL == nil {
		reqRL = waf.NewRateLimiter(prot.RequestRateLimitWindow, prot.RequestRateLimitMax, prot.RequestRateLimitEnabled)
	}
	if errRL == nil {
		errRL = waf.NewRateLimiter(prot.ErrorRateLimitWindow, prot.ErrorRateLimitMax, prot.ErrorRateLimitEnabled)
	}
	defer reqRL.Close()
	defer errRL.Close()

	// IP reputation (blacklist + whitelist + auto-ban).
	ipRep := waf.NewIPReputation()
	defer ipRep.Close()
	loadIPLists(ipRep, repos.IPList)
	ipRep.ConfigureAutoBan(prot.AutoBanEnabled, prot.AutoBanThreshold, prot.AutoBanWindow, prot.AutoBanDuration)
	ipRep.ConfigureAutoBanAction(prot.AutoBanAction)

	eng := engine.New(rt.Snapshot, reqRL, errRL, ipRep)
	cveFeedInterval, err := time.ParseDuration(rt.Config.CVE.FeedInterval)
	if err != nil || cveFeedInterval <= 0 {
		cveFeedInterval = 6 * time.Hour
	}
	cveFeedMgr := waf.NewCVEFeedManagerWithFeed(rt.DB, eng.CVEDetector(), cveFeedInterval, rt.Config.CVE.NVDAPIKey, rt.Config.CVE.AutoApprove, rt.Config.CVE.FeedEnabled, logger.New("cve_feed"))
	cveFeedMgr.Start()
	defer cveFeedMgr.Stop()

	// TLS fingerprinter for native JA3 capture.
	tlsFP := waf.NewTLSFingerprinter()
	waf.SetTLSFingerprinter(tlsFP)

	// Drop executor (TCP connection close strategy).
	dropCfg := loadDropPolicy(repos.SystemSettings, rt.Config.Drop)
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

	// Challenge managers: CAPTCHA, Shield (5-second), Chain.
	captchaMgr := waf.NewCaptchaManager(rt.Redis, time.Duration(prot.CaptchaTimeout)*time.Second)
	shieldMgr := waf.NewShieldManager(captchaMgr, rt.Redis, prot.ShieldDifficulty)
	chainMgr := waf.NewChainChallengeManager(captchaMgr, rt.Redis)

	// Anti-replay nonce protection manager.
	antiReplayMgr := waf.NewAntiReplayManager("", rt.Redis, 5*time.Minute)
	eng.SetAntiReplayManager(antiReplayMgr)

	// ─── Auth subsystems ───
	tokenMgr := auth.NewTokenManager(jwtSecret, rt.DB)
	bruteForce := auth.NewBruteForceDetector(prot.LoginMaxAttempts, time.Duration(prot.LoginLockoutMinutes)*time.Minute)
	sessionMgr := auth.NewSessionManager(rt.DB)

	// Escalation (step-up response) manager.
	escalationMgr := waf.NewEscalationManager(rt.Redis)
	applyProtectionRuntimeConfig := func(p store.ProtectionConfig) {
		reqRL.Reconfigure(p.RequestRateLimitWindow, p.RequestRateLimitMax, p.RequestRateLimitEnabled)
		errRL.Reconfigure(p.ErrorRateLimitWindow, p.ErrorRateLimitMax, p.ErrorRateLimitEnabled)
		ipRep.ConfigureAutoBan(p.AutoBanEnabled, p.AutoBanThreshold, p.AutoBanWindow, p.AutoBanDuration)
		ipRep.ConfigureAutoBanAction(p.AutoBanAction)
		captchaMgr.SetTimeout(time.Duration(p.CaptchaTimeout) * time.Second)
		shieldMgr.SetDifficulty(p.ShieldDifficulty)
		chainMgr.Reconfigure(parseChainSteps(p.ChainSteps), p.ShieldDifficulty)
		bruteForce.Reconfigure(p.LoginMaxAttempts, time.Duration(p.LoginLockoutMinutes)*time.Minute)
		dropPolicy := loadDropPolicy(repos.SystemSettings, rt.Config.Drop)
		dropExec.Reconfigure(dropPolicy.Enabled)
		eng.SetBotThreshold(dropPolicy.BotScoreThreshold)
		if p.EscalationEnabled {
			steps := p.GetEscalationSteps()
			wafSteps := make([]waf.EscalationStep, len(steps))
			for i, s := range steps {
				wafSteps[i] = waf.EscalationStep{Threshold: s.Threshold, Action: s.Action}
			}
			escalationMgr.SetDefaultConfig(waf.EscalationConfig{
				Enabled:    true,
				WindowSecs: p.EscalationWindowSecs,
				Steps:      wafSteps,
			})
		} else {
			escalationMgr.SetDefaultConfig(waf.EscalationConfig{Enabled: false})
		}
	}
	applyProtectionRuntimeConfig(prot)
	eng.SetEscalationManager(escalationMgr)
	defer escalationMgr.Close()

	// dataListenerOpts holds the shared options for creating data-plane handlers.
	dpOpts := dataplane.Options{
		Holder:                rt.Snapshot,
		Engine:                eng,
		Metrics:               metrics,
		EventWriter:           eventWriter,
		AccessLogWriter:       accessLogWriter,
		DropEventRepo:         repos.DropEvent,
		ResponseCache:         responseCache,
		Log:                   dpLog,
		CaptchaManager:        captchaMgr,
		ShieldManager:         shieldMgr,
		ChainManager:          chainMgr,
		RecordedResourceRepo:  repos.RecordedResource,
		BotScoreRepo:          repos.BotScore,
		FingerprintRepo:       repos.Fingerprint,
	}

	// reconcileListeners compares current listeners with snapshot and starts/stops as needed.
	// It also detects bind-level listener drift and restarts affected listeners automatically.
	reconcileListeners := func() {
		newSn := rt.Snapshot.Load()
		if newSn == nil {
			return
		}

		type desiredEntry struct {
			siteRT snapshotpkg.SiteRuntime
			tag    string
		}
		desired := make(map[string]desiredEntry)
		for _, siteRT := range listenerRuntimesByBind(newSn) {
			name := siteListenerName(siteRT.Bind)
			desired[name] = desiredEntry{
				siteRT: siteRT,
				tag:    siteListenerFingerprint(siteRT.Bind, newSn),
			}
		}

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

		for name, de := range desired {
			if lm.Has(name) {
				continue
			}
			srv := buildDataServer(de.siteRT, newSn, dpOpts)
			if srv == nil {
				log.Warn("skipping site listener without valid TLS config", slog.String("name", name), slog.String("bind", de.siteRT.Bind))
				continue
			}
			lm.AddHertzWithTag(name, srv, de.tag)
			lm.StartOne(name)
			log.Info("hot-started site listener",
				slog.String("name", name),
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
		// Refresh runtime protection settings from latest snapshot.
		if sn := rt.Snapshot.Load(); sn != nil {
			applyProtectionRuntimeConfig(sn.Protection)
		}
		// Do not clear the in-memory response cache on reload: GET entries remain valid
		// across config bumps so upstream outages still hit warm cache when eligible.
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
				applyProtectionRuntimeConfig(sn.Protection)
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
		Repos:         repos,
		Reload:        reload,
		StaticFS:      rt.Config.AdminStaticDir,
		JWTSecret:     jwtSecret,
		Metrics:       metrics,
		DB:            rt.DB,
		TokenMgr:      tokenMgr,
		BruteForce:    bruteForce,
		SessionMgr:    sessionMgr,
		CVEFeedMgr:    cveFeedMgr,
		EscalationMgr: escalationMgr,
		CaptchaMgr:    captchaMgr,
	})
	lm.AddHertz("admin:"+rt.Config.AdminBind, adminSrv)

	// ─── Data-plane listener(s) ───
	if sn != nil {
		for _, siteRT := range listenerRuntimesByBind(sn) {
			name := siteListenerName(siteRT.Bind)
			tag := siteListenerFingerprint(siteRT.Bind, sn)
			srv := buildDataServer(siteRT, sn, dpOpts)
			if srv == nil {
				log.Warn("skipping site listener without valid TLS config", slog.String("name", name), slog.String("bind", siteRT.Bind))
				continue
			}
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

func siteListenerName(bind string) string {
	return fmt.Sprintf("site:%s", bind)
}

func listenerRuntimesByBind(sn *snapshotpkg.Snapshot) []snapshotpkg.SiteRuntime {
	if sn == nil {
		return nil
	}
	byBind := make(map[string]snapshotpkg.SiteRuntime)
	for _, rt := range sn.Sites {
		current, exists := byBind[rt.Bind]
		if !exists || (!current.Site.TLSEnabled && rt.Site.TLSEnabled) {
			byBind[rt.Bind] = rt
		}
	}
	items := make([]snapshotpkg.SiteRuntime, 0, len(byBind))
	for _, rt := range byBind {
		items = append(items, rt)
	}
	return items
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
		e, ok := waf.ParseIPListEntry(it.Value, it.Note, it.Action)
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

func loadDropPolicy(repo *repository.SystemSettingsRepo, fallback core.DropConfig) core.DropConfig {
	if repo == nil {
		return fallback
	}
	val, err := repo.Get("drop_policy")
	if err != nil || strings.TrimSpace(val) == "" {
		return fallback
	}
	type dropPolicy struct {
		Enabled             bool `json:"enabled"`
		BotScoreThreshold   int  `json:"bot_score_threshold"`
		CVEAutoDropCritical bool `json:"cve_auto_drop_critical"`
		CVEAutoDropHigh     bool `json:"cve_auto_drop_high"`
	}
	var stored dropPolicy
	if err := json.Unmarshal([]byte(val), &stored); err != nil {
		return fallback
	}
	cfg := fallback
	cfg.Enabled = stored.Enabled
	if stored.BotScoreThreshold > 0 {
		cfg.BotScoreThreshold = stored.BotScoreThreshold
	}
	cfg.CVEAutoDropCritical = stored.CVEAutoDropCritical
	cfg.CVEAutoDropHigh = stored.CVEAutoDropHigh
	return cfg
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
	opts := []config.Option{
		server.WithHostPorts(siteRT.Bind),
		server.WithUseRawPath(true),
		server.WithUnescapePathValues(false),
		server.WithDisablePreParseMultipartForm(true),
	}

	if siteRT.Site.TLSEnabled {
		tlsCfg := buildListenerTLS(siteRT, sn)
		if tlsCfg == nil {
			return nil
		}
		opts = append(opts,
			server.WithTLS(tlsCfg),
			server.WithTransport(standard.NewTransporter),
		)
	}

	srv := server.Default(opts...)
	o := dpOpts
	o.Bind = siteRT.Bind
	handler := dataplane.Handler(o)
	// Register as NoRoute handler so our handler processes ALL requests.
	// Global Use() middleware only runs when a route matches; since the data-plane
	// has no explicit routes we must use NoRoute to catch everything.
	srv.NoRoute(handler)
	return srv
}

// buildListenerTLS constructs a *tls.Config for a data listener.
// It uses the site's certificate and TLS configuration.
func buildListenerTLS(siteRT snapshotpkg.SiteRuntime, sn *snapshotpkg.Snapshot) *tls.Config {
	if sn == nil {
		return nil
	}

	site := siteRT.Site
	bind := siteRT.Bind
	var certs []tls.Certificate

	if siteRT.TLSConfig != nil && len(siteRT.TLSConfig.Certificates) > 0 {
		certs = append(certs, siteRT.TLSConfig.Certificates...)
	} else if siteRT.Certificate != nil {
		cert, err := tls.X509KeyPair([]byte(siteRT.Certificate.CertPEM), []byte(siteRT.Certificate.KeyPEM))
		if err == nil {
			certs = append(certs, cert)
		}
	}

	// Per-site SNI certs for this bind address
	for sniKey, cert := range sn.SiteTLSCertBySNI {
		prefix := "sni:" + bind + "\x00"
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

// siteListenerFingerprint produces a short hash that changes whenever a bind-level listener changes.
func siteListenerFingerprint(bind string, sn *snapshotpkg.Snapshot) string {
	h := sha256.New()
	fmt.Fprintf(h, "bind=%s", bind)

	seenSites := make(map[uint]struct{})
	for _, rt := range sn.Sites {
		if rt.Bind != bind {
			continue
		}
		if _, seen := seenSites[rt.Site.ID]; seen {
			continue
		}
		seenSites[rt.Site.ID] = struct{}{}
		site := rt.Site
		fmt.Fprintf(h, " site=%d tls=%v min=%s max=%s alpn=%s", site.ID, rt.Site.TLSEnabled, site.MinTLSVersion, site.MaxTLSVersion, site.ALPN)
		if rt.Certificate != nil {
			fmt.Fprintf(h, " cert=%s", rt.Certificate.CertPEM[:min(64, len(rt.Certificate.CertPEM))])
		}
	}

	prefix := "sni:" + bind + "\x00"
	for sniKey, cert := range sn.SiteTLSCertBySNI {
		if strings.HasPrefix(sniKey, prefix) && len(cert.Certificate) > 0 {
			fmt.Fprintf(h, " sni=%s:len=%d", sniKey, len(cert.Certificate[0]))
		}
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

func parseChainSteps(raw string) []waf.ChainStepConfig {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var steps []waf.ChainStepConfig
	if err := json.Unmarshal([]byte(raw), &steps); err != nil {
		return nil
	}
	return steps
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
