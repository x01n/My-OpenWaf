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
	"net"
	"os"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	hertznet "github.com/cloudwego/hertz/pkg/network"
	"github.com/cloudwego/hertz/pkg/network/standard"
	shconfig "github.com/hertz-contrib/http2/config"
	shfactory "github.com/hertz-contrib/http2/factory"

	acmepkg "My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/admin"
	"My-OpenWaf/internal/admin/auth"
	adminsystem "My-OpenWaf/internal/admin/system"
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
	"My-OpenWaf/internal/upstream"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/cve"
	"My-OpenWaf/internal/waf/drop"
	"My-OpenWaf/internal/waf/escalation"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/ratelimit"
)

var selfSignedCache = acmepkg.NewSelfSignedCache()

func maskCredential(s string) string {
	if len(s) <= 6 {
		return s[:1] + strings.Repeat("*", len(s)-1)
	}
	return s[:3] + strings.Repeat("*", len(s)-6) + s[len(s)-3:]
}

func applyLogConfig(repo *repository.SystemSettingsRepo) {
	if repo == nil {
		return
	}
	raw, err := repo.Get("log_config")
	if err != nil || strings.TrimSpace(raw) == "" {
		return
	}
	var cfg struct {
		Level      string `json:"level"`
		FilePath   string `json:"file_path"`
		AlsoStdout bool   `json:"also_stdout"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return
	}
	logger.Configure(logger.Config{Level: cfg.Level, FilePath: cfg.FilePath, AlsoStdout: cfg.AlsoStdout})
}

func adminPasswordMinLength(repo *repository.SystemSettingsRepo) int {
	cfg := store.DefaultProtectionConfig()
	if repo != nil {
		if raw, err := repo.Get("protection"); err == nil && strings.TrimSpace(raw) != "" {
			_ = json.Unmarshal([]byte(raw), &cfg)
		}
	}
	if cfg.LoginMinPasswordLength <= 0 {
		return store.DefaultProtectionConfig().LoginMinPasswordLength
	}
	return cfg.LoginMinPasswordLength
}

func ResetAdminPassword(args []string) error {
	username := "admin"
	passwordArgs := args
	if len(args) == 2 {
		username = args[0]
		passwordArgs = args[1:]
	}
	if len(passwordArgs) != 1 || strings.TrimSpace(passwordArgs[0]) == "" {
		return fmt.Errorf("usage: reset-admin-password [username] <new-password>")
	}

	rt, err := core.NewRuntime(context.Background())
	if err != nil {
		return fmt.Errorf("core init failed: %w", err)
	}
	defer func() { _ = rt.Close() }()

	if err := store.AutoMigrate(rt.DB); err != nil {
		return fmt.Errorf("auto migrate failed: %w", err)
	}

	repo := repository.NewAdminAccountRepo(rt.DB)
	account, err := repo.GetByUsername(username)
	if err != nil {
		return fmt.Errorf("load admin account %q: %w", username, err)
	}
	if account == nil {
		return fmt.Errorf("admin account %q does not exist", username)
	}
	settingsRepo := repository.NewSystemSettingsRepo(rt.DB)
	minLength := adminPasswordMinLength(settingsRepo)
	if len([]rune(passwordArgs[0])) < minLength {
		return fmt.Errorf("new password is shorter than login_min_password_length %d", minLength)
	}
	if err := repo.UpdatePassword(username, passwordArgs[0]); err != nil {
		return fmt.Errorf("reset admin password failed: %w", err)
	}
	fmt.Fprintf(os.Stdout, "Admin password reset successfully for %s\n", username)
	return nil
}

func Run() {
	hlog.SetLevel(hlog.LevelFatal)
	log := logger.New("app")
	ctx := context.Background()
	acmeCtx, cancelACME := context.WithCancel(ctx)
	defer cancelACME()

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
	if err := store.AutoMigrateLogs(rt.LogDB); err != nil {
		log.Error("log auto migrate failed", slog.Any("err", err))
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
	challenge.SetChallengeSecret(jwtSecret)

	repos := repository.NewWithLogDB(rt.DB, rt.LogDB)
	applyLogConfig(repos.SystemSettings)

	// Query count cache: reduces expensive COUNT(*) on access_logs/security_events.
	queryCache := cache.NewQueryCache(5 * time.Second)
	defer queryCache.Close()
	repos.AccessLog.SetCountCache(queryCache)
	repos.SecurityEvent.SetCountCache(queryCache)

	// Hot cache: Redis-backed read-through cache for hot data and large query results.
	hotCache := cache.NewHotCache(rt.Redis, logger.New("hotcache"))
	repos.SetHotCache(hotCache)

	// Write queue: async write queue that batches all DB mutations through a single
	// goroutine, merging high-frequency operations to reduce lock contention.
	writeQueue := observability.NewWriteQueue(rt.LogDB, logger.New("writequeue"))
	defer writeQueue.Close()
	repos.SetWriteQueue(writeQueue)

	// Unified writer: single goroutine drains all observability channels and
	// flushes them in one DB transaction, eliminating SQLite lock contention.
	unifiedWriter := observability.NewUnifiedWriter(rt.LogDB, logger.New("writer"))
	if rt.Redis != nil {
		unifiedWriter.SetRedis(rt.Redis)
	}
	defer unifiedWriter.Close()

	// Event archiver (auto-delete security events, access logs and drop events based on retention config).
	// Also performs database optimization (VACUUM/OPTIMIZE) after each cleanup cycle.
	archiver := observability.NewArchiver(rt.LogDB, repos.SecurityEvent, repos.AccessLog, repos.DropEvent, logger.New("archiver"), 30)
	archiver.SetSettingsRepo(repos.SystemSettings)
	defer archiver.Close()

	responseCache := cache.NewResponseCache(64, 60)
	defer responseCache.Close()

	// Data-plane metrics (shared across all data listeners).
	metrics := dataplane.NewMetrics()
	upstreamPool := upstream.NewPool()
	upstreamPool.Start(ctx, func() []string {
		if sn := rt.Snapshot.Load(); sn != nil {
			return snapshotUpstreams(sn)
		}
		return nil
	}, 10*time.Second, upstream.HTTPProbe(2*time.Second))

	// Rate limiters — configured from snapshot protection settings.
	sn := rt.Snapshot.Load()
	var prot store.ProtectionConfig
	if sn != nil {
		prot = sn.Protection
	}
	var reqRL ratelimit.RateLimiterBackend
	var errRL ratelimit.RateLimiterBackend
	if rt.Redis != nil {
		reqRL = ratelimit.NewRedisRateLimiter(rt.Redis, "openwaf:request", prot.RequestRateLimitWindow, prot.RequestRateLimitMax, prot.RequestRateLimitEnabled)
		errRL = ratelimit.NewRedisRateLimiter(rt.Redis, "openwaf:error", prot.ErrorRateLimitWindow, prot.ErrorRateLimitMax, prot.ErrorRateLimitEnabled)
	}
	if reqRL == nil {
		reqRL = ratelimit.NewRateLimiter(prot.RequestRateLimitWindow, prot.RequestRateLimitMax, prot.RequestRateLimitEnabled)
	}
	if errRL == nil {
		errRL = ratelimit.NewRateLimiter(prot.ErrorRateLimitWindow, prot.ErrorRateLimitMax, prot.ErrorRateLimitEnabled)
	}
	defer reqRL.Close()
	defer errRL.Close()

	// IP reputation (blacklist + whitelist + auto-ban).
	ipRep := iprep.NewIPReputation()
	defer ipRep.Close()
	loadIPLists(ipRep, repos.IPList)
	ipRep.ConfigureAutoBan(prot.AutoBanEnabled, prot.AutoBanThreshold, prot.AutoBanWindow, prot.AutoBanDuration)
	ipRep.ConfigureAutoBanAction(prot.AutoBanAction)

	eng := engine.New(rt.Snapshot, reqRL, errRL, ipRep)
	cveFeedInterval, err := time.ParseDuration(rt.Config.CVE.FeedInterval)
	if err != nil || cveFeedInterval <= 0 {
		cveFeedInterval = 6 * time.Hour
	}
	cveFeedMgr := cve.NewCVEFeedManagerWithFeed(rt.DB, eng.CVEDetector(), cveFeedInterval, rt.Config.CVE.NVDAPIKey, rt.Config.CVE.AutoApprove, rt.Config.CVE.FeedEnabled, logger.New("cve_feed"))
	cveFeedMgr.Start()
	defer cveFeedMgr.Stop()

	// Drop executor (TCP connection close strategy).
	dropCfg := loadDropPolicy(repos.SystemSettings, rt.Config.Drop)
	dropExec := drop.NewDropExecutor(dropCfg.Enabled, logger.New("drop"))
	eng.SetDropExecutor(dropExec)

	// GeoIP resolver for bot two-phase scoring (graceful degradation if DB missing).
	var geoResolver *bot.MaxMindResolver
	botCfg := rt.Config.Bot
	if botCfg.Enabled {
		geoResolver = bot.NewMaxMindResolver(botCfg.GeoIPDBPath, botCfg.GeoIPDBPath, botCfg)
		eng.SetGeoResolver(geoResolver, botCfg.ScoreThreshold)
		// Also set the global GeoResolver so LookupGeo works everywhere.
		bot.SetGeoResolver(geoResolver)
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
	captchaMgr := challenge.NewCaptchaManager(rt.Redis, time.Duration(prot.CaptchaTimeout)*time.Second)

	// 初始化 go-captcha 高级验证码（点击/滑动/旋转）
	goCaptchaCfg := challenge.DefaultGoCaptchaConfig()
	if dir := os.Getenv("MY_OPENWAF_CAPTCHA_DIR"); dir != "" {
		goCaptchaCfg.ResourceDir = dir
	}
	goCaptchaProvider := challenge.NewGoCaptchaProvider(goCaptchaCfg, logger.New("gocaptcha"))
	captchaMgr.SetGoCaptchaProvider(goCaptchaProvider)

	shieldMgr := challenge.NewShieldManager(captchaMgr, rt.Redis, prot.ShieldDifficulty)
	chainMgr := challenge.NewChainChallengeManager(captchaMgr, rt.Redis)

	// Anti-replay nonce protection manager.
	antiReplayMgr := antireplay.NewAntiReplayManager("", rt.Redis, 5*time.Minute)
	eng.SetAntiReplayManager(antiReplayMgr)

	// ─── Auth subsystems ───
	tokenMgr := auth.NewTokenManager(jwtSecret, rt.DB)
	bruteForce := auth.NewBruteForceDetector(prot.LoginMaxAttempts, time.Duration(prot.LoginLockoutMinutes)*time.Minute)
	sessionMgr := auth.NewSessionManager(rt.DB)

	// Escalation (step-up response) manager.
	escalationMgr := escalation.NewEscalationManager(rt.Redis)
	applyProtectionRuntimeConfig := func(p store.ProtectionConfig) {
		reqRL.Reconfigure(p.RequestRateLimitWindow, p.RequestRateLimitMax, p.RequestRateLimitEnabled)
		errRL.Reconfigure(p.ErrorRateLimitWindow, p.ErrorRateLimitMax, p.ErrorRateLimitEnabled)
		ipRep.ConfigureAutoBan(p.AutoBanEnabled, p.AutoBanThreshold, p.AutoBanWindow, p.AutoBanDuration)
		ipRep.ConfigureAutoBanAction(p.AutoBanAction)
		captchaMgr.SetTimeout(time.Duration(p.CaptchaTimeout) * time.Second)
		shieldMgr.SetConfig(challenge.ShieldConfig{
			Difficulty:           p.ShieldDifficulty,
			TimeoutSecs:          p.ShieldTimeoutSecs,
			AutoStartDelay:       p.ShieldAutoStartDelay,
			MaxRetries:           p.ShieldMaxRetries,
			EnvStrictness:        p.ShieldEnvStrictness,
			RequireHTTP2:         p.ShieldRequireHTTP2,
			RequireHTTP3:         p.ShieldRequireHTTP3,
			AllowHTTP1:           p.ShieldAllowHTTP1,
			EnableJSChallenge:    p.ShieldEnableJSChallenge,
			EnableWASM:           p.ShieldEnableWASM,
			EnableEnvCheck:       p.ShieldEnableEnvCheck,
			EnableDevToolsDetect: p.ShieldEnableDevTools,
		})
		chainMgr.Reconfigure(parseChainSteps(p.ChainSteps), p.ShieldDifficulty)
		bruteForce.Reconfigure(p.LoginMaxAttempts, time.Duration(p.LoginLockoutMinutes)*time.Minute)
		dropPolicy := loadDropPolicy(repos.SystemSettings, rt.Config.Drop)
		dropExec.Reconfigure(dropPolicy.Enabled)
		eng.SetBotThreshold(dropPolicy.BotScoreThreshold)
		if p.EscalationEnabled {
			steps := p.GetEscalationSteps()
			wafSteps := make([]escalation.EscalationStep, len(steps))
			for i, s := range steps {
				wafSteps[i] = escalation.EscalationStep{Threshold: s.Threshold, Action: s.Action}
			}
			escalationMgr.SetDefaultConfig(escalation.EscalationConfig{
				Enabled:    true,
				WindowSecs: p.EscalationWindowSecs,
				Steps:      wafSteps,
			})
		} else {
			escalationMgr.SetDefaultConfig(escalation.EscalationConfig{Enabled: false})
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
		Writer:                unifiedWriter,
		ResponseCache:         responseCache,
		AccessLogSamplingRate: 0,
		Log:                   dpLog,
		CaptchaManager:        captchaMgr,
		ShieldManager:         shieldMgr,
		ChainManager:          chainMgr,
		RecordedResourceRepo:  repos.RecordedResource,
		Upstreams:             upstreamPool,
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

			// HTTP/3 QUIC 监听器（与 TCP 并行，仅当 ALPN 包含 h3）
			h3Name := "h3:" + de.siteRT.Bind
			if de.siteRT.Site.TLSEnabled && shouldEnableHTTP3(de.siteRT.Site.ALPN, de.siteRT.NetworkDefaults) && !lm.Has(h3Name) {
				tlsCfg := buildListenerTLS(de.siteRT, newSn)
				if tlsCfg != nil {
					h3Srv := NewHTTP3Server(HTTP3ServerConfig{
						Bind:      de.siteRT.Bind,
						TCPBind:   de.siteRT.Bind,
						TLSConfig: tlsCfg,
						Log:       log.With(slog.String("proto", "h3")),
					})
					lm.Add(h3Name, h3Srv)
					lm.StartOne(h3Name)
					log.Info("hot-started HTTP/3 QUIC listener",
						slog.String("bind", de.siteRT.Bind),
					)
				}
			}
		}

		// 清理不再需要的 HTTP/3 监听器
		for _, name := range lm.Names() {
			if !strings.HasPrefix(name, "h3:") {
				continue
			}
			bind := strings.TrimPrefix(name, "h3:")
			tcpName := "site:" + bind
			// 对应 TCP 监听器不存在 → 清除
			if !lm.Has(tcpName) {
				log.Info("removing stale HTTP/3 listener (TCP gone)", slog.String("name", name))
				lm.Remove(name)
				continue
			}
			// TCP 存在但该站点 ALPN 不再包含 h3 → 清除
			if de, ok := desired[tcpName]; ok && !shouldEnableHTTP3(de.siteRT.Site.ALPN, de.siteRT.NetworkDefaults) {
				log.Info("removing HTTP/3 listener (h3 removed from ALPN)", slog.String("name", name))
				lm.Remove(name)
			}
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
	adminSrv.NoHijackConnPool = true
	adminSrv.GET("/healthz", hc.LivenessHandler())
	adminSrv.GET("/readyz", hc.ReadinessHandler())
	adminSrv.GET("/status", hc.StatusHandler())
	adminSrv.GET("/metrics", observability.PrometheusHandler(promMetrics))
	acmeStore := adminsystem.NewACMEManagerStore(repos.SystemSettings, repos.Certificate, reload, logger.New("acme"))
	dpOpts.ACMEChallengeResponse = acmeStore.GetChallengeResponse
	go acmeStore.RenewLoop(acmeCtx, 12*time.Hour)
	redisKV := cache.NewRedisKV(rt.Redis)
	realtimeHub := adminsystem.NewRealtimeHub(&adminsystem.DashboardDeps{Metrics: metrics, ConfigDB: rt.DB, LogDB: rt.LogDB, Cache: redisKV}, upstreamPool, hc, repos.AccessLog, repos.SecurityEvent)
	realtimeHub.Start(ctx)

	admin.RegisterRoutes(adminSrv, &admin.Dependencies{
		Repos:         repos,
		Reload:        reload,
		StaticFS:      rt.Config.AdminStaticDir,
		JWTSecret:     jwtSecret,
		Metrics:       metrics,
		DB:            rt.DB,
		LogDB:         rt.LogDB,
		TokenMgr:      tokenMgr,
		BruteForce:    bruteForce,
		SessionMgr:    sessionMgr,
		CVEFeedMgr:    cveFeedMgr,
		EscalationMgr: escalationMgr,
		CaptchaMgr:    captchaMgr,
		ChainMgr:      chainMgr,
		ACMEStore:     acmeStore,
		Realtime:      realtimeHub,
		Cache:         redisKV,
		Upstreams:     upstreamPool,
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

			// 初始化时也创建 HTTP/3 QUIC 监听器
			if siteRT.Site.TLSEnabled && shouldEnableHTTP3(siteRT.Site.ALPN, siteRT.NetworkDefaults) {
				tlsCfg := buildListenerTLS(siteRT, sn)
				if tlsCfg != nil {
					h3Name := "h3:" + siteRT.Bind
					h3Srv := NewHTTP3Server(HTTP3ServerConfig{
						Bind:      siteRT.Bind,
						TCPBind:   siteRT.Bind,
						TLSConfig: tlsCfg,
						Log:       log.With(slog.String("proto", "h3")),
					})
					lm.Add(h3Name, h3Srv)
					log.Info("HTTP/3 QUIC listener registered", slog.String("bind", siteRT.Bind))
				}
			}
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

func snapshotUpstreams(sn *snapshotpkg.Snapshot) []string {
	if sn == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var urls []string
	for _, rt := range sn.Sites {
		for _, raw := range rt.UpstreamURLs {
			if raw == "" {
				continue
			}
			if _, ok := seen[raw]; ok {
				continue
			}
			seen[raw] = struct{}{}
			urls = append(urls, raw)
		}
	}
	return urls
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

func loadIPLists(rep *iprep.IPReputation, repo *repository.IPListRepo) {
	if repo == nil {
		return
	}
	items, err := repo.AllEnabled()
	if err != nil {
		return
	}
	var blacks, whites []iprep.IPListEntry
	for _, it := range items {
		e, ok := iprep.ParseIPListEntry(it.Value, it.Note, it.Action)
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
		Enabled             *bool `json:"enabled"`
		BotScoreThreshold   *int  `json:"bot_score_threshold"`
		CVEAutoDropCritical *bool `json:"cve_auto_drop_critical"`
		CVEAutoDropHigh     *bool `json:"cve_auto_drop_high"`
	}
	var stored dropPolicy
	if err := json.Unmarshal([]byte(val), &stored); err != nil {
		return fallback
	}
	cfg := fallback
	if stored.Enabled != nil {
		cfg.Enabled = *stored.Enabled
	}
	if stored.BotScoreThreshold != nil && *stored.BotScoreThreshold > 0 {
		cfg.BotScoreThreshold = *stored.BotScoreThreshold
	}
	if stored.CVEAutoDropCritical != nil {
		cfg.CVEAutoDropCritical = *stored.CVEAutoDropCritical
	}
	if stored.CVEAutoDropHigh != nil {
		cfg.CVEAutoDropHigh = *stored.CVEAutoDropHigh
	}
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

// buildDataServer creates a Hertz server for a data-plane listener,
// optionally configured with TLS termination when the listener has TLS enabled.
// 支持 IPv4 和 IPv6 绑定地址。
func buildDataServer(siteRT snapshotpkg.SiteRuntime, sn *snapshotpkg.Snapshot, dpOpts dataplane.Options) *server.Hertz {
	network, _ := snapshotpkg.EffectiveSiteNetwork(siteRT.Site.ALPN, siteRT.Site.Network, siteRT.NetworkDefaults, siteRT.TLSDefaults)
	// 自动检测 IPv6 地址格式（如 [::]:8080）
	if strings.HasPrefix(siteRT.Bind, "[") {
		network = "tcp6"
	}

	rawLn, err := net.Listen(network, siteRT.Bind)
	if err != nil {
		slog.Error("data listener bind failed",
			slog.String("bind", siteRT.Bind),
			slog.String("network", network),
			slog.Any("err", err),
		)
		return nil
	}

	// TLS 由 Hertz standard transporter 处理，避免手动 tls.NewListener 后 ALPN 分派失效。
	// TLS 站点只 peek ClientHello；FixURIListener 只能用于明文 HTTP，不能读取 TLS ClientHello。
	var ln net.Listener = rawLn
	var tlsCfg *tls.Config
	if siteRT.Site.TLSEnabled {
		tlsCfg = buildListenerTLS(siteRT, sn)
		if tlsCfg == nil {
			rawLn.Close()
			return nil
		}
		ln = dataplane.NewTLSFingerprintListener(rawLn)
		effectiveHTTP2 := alpnSliceIncludes(tlsCfg.NextProtos, "h2")
		slog.Info("TLS listener configured",
			slog.String("bind", siteRT.Bind),
			slog.String("network", network),
			slog.Bool("http2_enabled", effectiveHTTP2),
			slog.Bool("http3_enabled", shouldEnableHTTP3(siteRT.Site.ALPN, siteRT.NetworkDefaults)),
			slog.String("min_tls", tlsVersionName(tlsCfg.MinVersion)),
			slog.String("max_tls", tlsVersionName(tlsCfg.MaxVersion)),
			slog.Any("next_protos", tlsCfg.NextProtos),
			slog.Int("cipher_suite_count", len(tlsCfg.CipherSuites)),
			slog.Int("curve_count", len(tlsCfg.CurvePreferences)),
		)
	}
	if !siteRT.Site.TLSEnabled {
		ln = dataplane.NewFixURIListener(ln)
	}

	transporter := standard.NewTransporter
	if siteRT.Site.TLSEnabled {
		transporter = dataplane.NewFixURITLSTransporter
	}

	opts := []config.Option{
		server.WithListener(ln),
		server.WithTransport(transporter),
		server.WithUseRawPath(true),
		server.WithUnescapePathValues(false),
		server.WithDisablePreParseMultipartForm(true),
		server.WithMaxRequestBodySize(32 << 20),
		server.WithMaxKeepBodySize(64 << 10),
	}
	if siteRT.Site.TLSEnabled {
		opts = append(opts,
			server.WithTLS(tlsCfg),
			server.WithOnAccept(func(conn net.Conn) context.Context {
				ctx := context.Background()
				if fp, ok := bot.TLSFingerprintFromConn(conn); ok {
					ctx = dataplane.ContextWithTLSFingerprint(ctx, fp)
				}
				return ctx
			}),
			server.WithOnConnect(func(ctx context.Context, conn hertznet.Conn) context.Context {
				if tlsConn, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
					state := tlsConn.ConnectionState()
					setTLSHandshakeInfo(conn, state)
					if fp, ok := bot.TLSFingerprintFromConn(conn); ok {
						ctx = dataplane.ContextWithTLSFingerprint(ctx, fp)
					}
					ctx = dataplane.ContextWithTLSHandshakeInfo(ctx, tlsVersionName(state.Version), state.ServerName, state.NegotiatedProtocol)
				}
				return ctx
			}),
		)
	}
	if siteRT.Site.TLSEnabled && alpnIncludes(siteRT.Site.ALPN, "h2") {
		opts = append(opts, server.WithALPN(true))
	}
	srv := server.Default(opts...)
	if siteRT.Site.TLSEnabled && alpnIncludes(siteRT.Site.ALPN, "h2") {
		srv.AddProtocol("h2", shfactory.NewServerFactory(
			shconfig.WithReadTimeout(time.Minute),
			shconfig.WithDisableKeepAlive(false),
			shconfig.WithPermitProhibitedCipherSuites(true),
		))
		slog.Info("HTTP/2 protocol factory registered", slog.String("bind", siteRT.Bind))
	}
	o := dpOpts
	o.Bind = siteRT.Bind
	handler := dataplane.Handler(o)

	// 如果 ALPN 包含 h3，向 HTTP/1.1 和 HTTP/2 响应注入 Alt-Svc 头
	if shouldEnableHTTP3(siteRT.Site.ALPN, siteRT.NetworkDefaults) {
		port := extractPort(siteRT.Bind)
		altSvcValue := fmt.Sprintf(`h3=":%s"; ma=86400`, port)
		slog.Info("HTTP/3 Alt-Svc enabled", slog.String("bind", siteRT.Bind), slog.String("alt_svc", altSvcValue))
		origHandler := handler
		handler = func(ctx context.Context, c *app.RequestContext) {
			c.Response.Header.Set("Alt-Svc", altSvcValue)
			origHandler(ctx, c)
		}
	}

	srv.NoRoute(dataplane.HandlerForBind(siteRT.Bind, handler))
	return srv
}

// buildListenerTLS constructs a *tls.Config for a data listener.
// 使用 GetCertificate 回调实现动态证书选择：
//   - SNI 匹配到已知站点 → 返回该站点的真实证书
//   - SNI 为空（IP 直接访问）或不匹配任何站点 → 返回自签证书
//
// 这样可以防止通过 IP 扫描泄露后端真实站点的域名信息。
func buildListenerTLS(siteRT snapshotpkg.SiteRuntime, sn *snapshotpkg.Snapshot) *tls.Config {
	if sn == nil {
		return nil
	}

	site := siteRT.Site
	bind := siteRT.Bind

	// 构建 SNI → 证书 的映射（仅本 bind 地址）
	sniCertMap := make(map[string]*tls.Certificate)
	for sniKey, cert := range sn.SiteTLSCertBySNI {
		prefix := "sni:" + bind + "\x00"
		if strings.HasPrefix(sniKey, prefix) {
			sni := strings.TrimPrefix(sniKey, prefix)
			c := cert // 避免闭包引用循环变量
			sniCertMap[sni] = &c
		}
	}

	// 站点自身证书
	var defaultSiteCert *tls.Certificate
	if siteRT.TLSConfig != nil && len(siteRT.TLSConfig.Certificates) > 0 {
		defaultSiteCert = &siteRT.TLSConfig.Certificates[0]
	} else if siteRT.Certificate != nil {
		cert, err := tls.X509KeyPair([]byte(siteRT.Certificate.CertPEM), []byte(siteRT.Certificate.KeyPEM))
		if err == nil {
			defaultSiteCert = &cert
		}
	}

	// 如果没有任何证书且 SNI 映射也为空，生成一个自签证书兜底
	if defaultSiteCert == nil && len(sniCertMap) == 0 {
		selfSigned, err := selfSignedCache.GetOrCreatePtr(bind)
		if err != nil {
			slog.Warn("自签证书生成失败", slog.String("bind", bind), slog.Any("err", err))
			return nil
		}
		defaultSiteCert = selfSigned
		slog.Info("无站点证书，仅使用自签证书", slog.String("bind", bind))
	}

	minTLSVersion, maxTLSVersion, cipherSuiteNames := snapshotpkg.EffectiveSiteTLS(site.MinTLSVersion, site.MaxTLSVersion, site.CipherSuites, siteRT.TLSDefaults)
	_, effectiveALPN := snapshotpkg.EffectiveSiteNetwork(site.ALPN, site.Network, siteRT.NetworkDefaults, siteRT.TLSDefaults)

	// Parse TLS version bounds.
	minVer := snapshotpkg.ParseTLSVersion(minTLSVersion)
	maxVer := snapshotpkg.ParseTLSVersion(maxTLSVersion)
	if minVer == 0 {
		minVer = tls.VersionTLS10
	}
	if maxVer == 0 {
		maxVer = tls.VersionTLS13
	}

	// Parse ALPN protocols.
	alpn := tcpTLSALPNProtocols(effectiveALPN)

	// 解析 TLS 密码套件
	var cipherSuites []uint16
	if cipherSuiteNames != "" {
		cipherSuites = parseCipherSuites(cipherSuiteNames)
	}
	curves := snapshotpkg.ParseCurvePreferences(siteRT.TLSDefaults.CurvePreferences)
	if len(curves) == 0 {
		curves = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	}

	cfg := &tls.Config{
		MinVersion:               minVer,
		MaxVersion:               maxVer,
		NextProtos:               alpn,
		CipherSuites:             cipherSuites,
		CurvePreferences:         curves,
		PreferServerCipherSuites: siteRT.TLSDefaults.PreferServerCipherSuites,
		// GetCertificate 在 TLS 握手时被调用，根据 ClientHello 中的 SNI 动态选择证书。
		// 核心安全逻辑：只有当 SNI 匹配到已知站点时才返回真实证书，
		// 否则（IP 直接访问或未知域名）返回自签证书，防止域名信息泄露。
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.Conn != nil {
				setTLSHandshakeInfo(hello.Conn, tls.ConnectionState{ServerName: hello.ServerName})
			}
			return nil, nil
		},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := strings.ToLower(strings.TrimSpace(hello.ServerName))

			clientTLSMin := uint16(0)
			if len(hello.SupportedVersions) > 0 {
				clientTLSMin = hello.SupportedVersions[0]
			}
			slog.Debug("TLS ClientHello received",
				slog.String("bind", bind),
				slog.String("sni", sni),
				slog.Any("client_alpn", hello.SupportedProtos),
				slog.Int("client_tls_first", int(clientTLSMin)),
			)

			// 情况 1：SNI 为空 → IP 直接访问
			if sni == "" {
				if siteRT.TLSDefaults.SelfSignedOnIP {
					return selfSignedForBind(bind), nil
				}
				if defaultSiteCert != nil {
					return defaultSiteCert, nil
				}
				return selfSignedForBind(bind), nil
			}

			// 情况 2：SNI 精确匹配已知证书
			if cert, ok := sniCertMap[sni]; ok {
				return cert, nil
			}

			// 情况 3：尝试通配符匹配（*.example.com）
			if idx := strings.Index(sni, "."); idx > 0 {
				wild := "*." + sni[idx+1:]
				if cert, ok := sniCertMap[wild]; ok {
					return cert, nil
				}
			}

			// 情况 4：SNI 不匹配任何已知站点 → 检查 snapshot 是否有此站点
			if _, found := sn.MatchSite(bind, sni); !found {
				// 站点不存在：返回自签证书，防止证书泄露真实域名
				slog.Debug("未知 SNI，返回自签证书",
					slog.String("sni", sni),
					slog.String("bind", bind),
				)
				return selfSignedForBind(bind), nil
			}

			// 情况 5：站点存在但没有专用证书，使用默认站点证书
			if defaultSiteCert != nil {
				return defaultSiteCert, nil
			}

			// 兜底：自签证书
			return selfSignedForBind(bind), nil
		},
	}
	return cfg
}

// selfSignedForBind 获取或生成指定 bind 地址的自签证书。
func selfSignedForBind(bind string) *tls.Certificate {
	cert, err := selfSignedCache.GetOrCreatePtr(bind)
	if err != nil {
		slog.Warn("自签证书生成失败", slog.String("bind", bind), slog.Any("err", err))
		return nil
	}
	return cert
}

// parseCipherSuites 将逗号分隔的密码套件名称转换为 TLS 密码套件 ID 列表。
func parseALPNProtocols(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(proto string) {
		proto = strings.TrimSpace(proto)
		if proto == "" {
			return
		}
		if _, ok := seen[proto]; ok {
			return
		}
		seen[proto] = struct{}{}
		out = append(out, proto)
	}
	if raw != "" {
		for _, proto := range strings.Split(raw, ",") {
			add(proto)
		}
	} else {
		add("h2")
		add("http/1.1")
	}
	if len(out) == 0 {
		out = []string{"h2", "http/1.1"}
	}
	return out
}

func tcpTLSALPNProtocols(raw string) []string {
	protos := parseALPNProtocols(raw)
	out := make([]string, 0, len(protos))
	for _, proto := range protos {
		if proto == "h3" {
			continue
		}
		out = append(out, proto)
	}
	if len(out) == 0 {
		out = []string{"h2", "http/1.1"}
	}
	return out
}

type tlsHandshakeInfoSetter interface {
	SetTLSHandshakeInfo(version string, sni string, alpn string)
}

func setTLSHandshakeInfo(conn net.Conn, state tls.ConnectionState) {
	for conn != nil {
		if setter, ok := conn.(tlsHandshakeInfoSetter); ok {
			setter.SetTLSHandshakeInfo(tlsVersionName(state.Version), state.ServerName, state.NegotiatedProtocol)
			return
		}
		if unwrapper, ok := conn.(interface{ NetConn() net.Conn }); ok {
			conn = unwrapper.NetConn()
			continue
		}
		break
	}
}

func firstALPN(protos []string) string {
	if len(protos) == 0 {
		return ""
	}
	return protos[0]
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS10"
	case tls.VersionTLS11:
		return "TLS11"
	case tls.VersionTLS12:
		return "TLS12"
	case tls.VersionTLS13:
		return "TLS13"
	default:
		return ""
	}
}

func alpnIncludes(raw, proto string) bool {
	for _, p := range parseALPNProtocols(raw) {
		if p == proto {
			return true
		}
	}
	return false
}

func alpnSliceIncludes(values []string, proto string) bool {
	for _, value := range values {
		if value == proto {
			return true
		}
	}
	return false
}

func parseCipherSuites(raw string) []uint16 {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	nameToID := make(map[string]uint16)
	for _, suite := range tls.CipherSuites() {
		nameToID[suite.Name] = suite.ID
		nameToID[strings.ToUpper(suite.Name)] = suite.ID
		short := strings.TrimPrefix(suite.Name, "TLS_")
		nameToID[short] = suite.ID
		nameToID[strings.ToUpper(short)] = suite.ID
	}
	for _, suite := range tls.InsecureCipherSuites() {
		nameToID[suite.Name] = suite.ID
		nameToID[strings.ToUpper(suite.Name)] = suite.ID
		short := strings.TrimPrefix(suite.Name, "TLS_")
		nameToID[short] = suite.ID
		nameToID[strings.ToUpper(short)] = suite.ID
	}

	seen := make(map[uint16]struct{})
	var suites []uint16
	for _, name := range strings.Split(raw, ",") {
		key := strings.TrimSpace(name)
		if key == "" {
			continue
		}
		id, ok := nameToID[key]
		if !ok {
			id, ok = nameToID[strings.ToUpper(key)]
		}
		if !ok {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		suites = append(suites, id)
	}
	return suites
}

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
		effectiveNetwork, effectiveALPN := snapshotpkg.EffectiveSiteNetwork(site.ALPN, site.Network, rt.NetworkDefaults, rt.TLSDefaults)
		effectiveMinTLS, effectiveMaxTLS, effectiveCiphers := snapshotpkg.EffectiveSiteTLS(site.MinTLSVersion, site.MaxTLSVersion, site.CipherSuites, rt.TLSDefaults)
		fmt.Fprintf(h, " site=%d tls=%v network=%s min=%s max=%s alpn=%s", site.ID, rt.Site.TLSEnabled, effectiveNetwork, effectiveMinTLS, effectiveMaxTLS, effectiveALPN)
		fmt.Fprintf(h, " ciphers=%s self_signed_on_ip=%v", effectiveCiphers, rt.TLSDefaults.SelfSignedOnIP)
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

func parseChainSteps(raw string) []challenge.ChainStepConfig {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var steps []challenge.ChainStepConfig
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
