package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	hertznet "github.com/cloudwego/hertz/pkg/network"
	"github.com/cloudwego/hertz/pkg/network/standard"
	shconfig "github.com/hertz-contrib/http2/config"
	shfactory "github.com/hertz-contrib/http2/factory"
	goredis "github.com/redis/go-redis/v9"
	"golang.org/x/crypto/hkdf"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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
	"My-OpenWaf/internal/pkg/memreclaim"
	"My-OpenWaf/internal/proxy"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/tlsmeta"
	"My-OpenWaf/internal/upstream"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/cve"
	"My-OpenWaf/internal/waf/drop"
	"My-OpenWaf/internal/waf/escalation"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/luaplugin"
	"My-OpenWaf/internal/waf/owasp"
	"My-OpenWaf/internal/waf/ratelimit"
	"My-OpenWaf/internal/waf/threatintel"
)

var selfSignedCache = acmepkg.NewSelfSignedCache()

func http2ServerFactoryOptions(cfg snapshotpkg.HTTP2Config) []shconfig.Option {
	return []shconfig.Option{
		shconfig.WithReadTimeout(time.Duration(cfg.ReadTimeoutSeconds) * time.Second),
		shconfig.WithDisableKeepAlive(cfg.DisableKeepalive),
		shconfig.WithPermitProhibitedCipherSuites(cfg.PermitProhibitedCipherSuites),
		shconfig.WithMaxConcurrentStreams(cfg.MaxConcurrentStreams),
		shconfig.WithMaxReadFrameSize(cfg.MaxReadFrameSize),
		shconfig.WithIdleTimeout(time.Duration(cfg.IdleTimeoutSeconds) * time.Second),
		shconfig.WithMaxUploadBufferPerConnection(cfg.MaxUploadBufferPerConnection),
		shconfig.WithMaxUploadBufferPerStream(cfg.MaxUploadBufferPerStream),
		shconfig.WithServerMaxHeaderListSize(uint32(cfg.MaxHeaderBytes + cfg.MaxHeaderFields*32)),
		shconfig.WithServerMaxHeaderFields(cfg.MaxHeaderFields),
	}
}

func buildRateLimiterBackend(client *goredis.Client, prefix string, windowSec, maxReqs int, enabled bool) ratelimit.RateLimiterBackend {
	if rl := ratelimit.NewRedisRateLimiter(client, prefix, windowSec, maxReqs, enabled); rl != nil {
		return rl
	}
	return ratelimit.NewRateLimiter(windowSec, maxReqs, enabled)
}

func effectiveHTTP2Config(sn *snapshotpkg.Snapshot) snapshotpkg.HTTP2Config {
	if sn == nil {
		return snapshotpkg.DefaultHTTP2Config()
	}
	return sn.HTTP2Config
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
	ctx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()
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
	if err := owasp.ReconcileBuiltinCatalog(rt.DB); err != nil {
		log.Error("reconcile OWASP catalog failed", slog.Any("err", err))
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

	// Resolve the persistent process secret before building snapshots so dynamic
	// protection never falls back to its deterministic public key material.
	jwtSecret, err := resolveJWTSecret(rt)
	if err != nil {
		log.Error("resolve persistent JWT secret failed", slog.Any("err", err))
		os.Exit(1)
	}
	if err := rt.SetSnapshotDynamicKeyBase(deriveDynamicProtectionKeyBase(jwtSecret)); err != nil {
		log.Error("configure snapshot dynamic protection key failed", slog.Any("err", err))
		os.Exit(1)
	}
	if err := rt.ReloadSnapshot(); err != nil {
		log.Error("initial snapshot build failed", slog.Any("err", err))
		os.Exit(1)
	}

	// Derive challenge cookie secret from JWT secret for persistence across restarts.
	challenge.SetChallengeSecret(jwtSecret)

	repos := repository.NewWithLogDB(rt.DB, rt.LogDB)
	applyLogConfig(repos.SystemSettings)
	redisKV := cache.NewRedisKV(rt.Redis)
	rt.RedisKV = redisKV

	var runtimeStateMu sync.RWMutex
	runtimeState := func() (core.Config, bool) {
		runtimeStateMu.RLock()
		cfg := rt.Config
		redisEnabled := rt.Redis != nil
		runtimeStateMu.RUnlock()
		return cfg, redisEnabled
	}

	// Query count cache: reduces expensive COUNT(*) on access_logs/security_events.
	queryCache := cache.NewQueryCache(5 * time.Second)
	defer queryCache.Close()
	repos.AccessLog.SetCountCache(queryCache)
	repos.SecurityEvent.SetCountCache(queryCache)
	repos.DropEvent.SetCountCache(queryCache)

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
	unifiedWriter.SetRedis(rt.Redis)
	defer unifiedWriter.Close()

	// Event archiver (auto-delete security events, access logs and drop events based on retention config).
	// Also performs database optimization (VACUUM/OPTIMIZE) after each cleanup cycle.
	archiver := observability.NewArchiver(rt.LogDB, repos.SecurityEvent, repos.AccessLog, repos.DropEvent, logger.New("archiver"), 30)
	archiver.SetSettingsRepo(repos.SystemSettings)
	archiver.SetSyncLogRepo(repos.ThreatIntelSyncLog)
	defer archiver.Close()

	responseCache := cache.NewResponseCache(rt.Config.ResponseCacheMB, rt.Config.ResponseCacheTTLSec)
	defer responseCache.Close()
	// 高并发峰值后周期性将空闲 heap 归还 OS，降低 RSS 粘滞。
	stopMemReclaim := memreclaim.Start(memreclaim.Config{Logger: logger.New("memreclaim")})
	defer stopMemReclaim()

	// Data-plane metrics (shared across all data listeners).
	metrics := dataplane.NewMetrics()
	upstreamPool := upstream.NewPool()
	upstreamPool.StartWithResult(ctx, func() []string {
		if sn := rt.Snapshot.Load(); sn != nil {
			return snapshotUpstreams(sn)
		}
		return nil
	}, 10*time.Second, upstream.HTTPProbeWithResult(2*time.Second))

	// Rate limiters — configured from snapshot protection settings.
	sn := rt.Snapshot.Load()
	var prot store.ProtectionConfig
	if sn != nil {
		prot = sn.Protection
	}
	reqRL := ratelimit.NewDynamicRateLimiter(buildRateLimiterBackend(rt.Redis, "openwaf:request", prot.RequestRateLimitWindow, prot.RequestRateLimitMax, prot.RequestRateLimitEnabled))
	errRL := ratelimit.NewDynamicRateLimiter(buildRateLimiterBackend(rt.Redis, "openwaf:error", prot.ErrorRateLimitWindow, prot.ErrorRateLimitMax, prot.ErrorRateLimitEnabled))
	defer reqRL.Close()
	defer errRL.Close()

	// IP reputation (blacklist + whitelist + auto-ban).
	ipRep := iprep.NewIPReputation()
	defer ipRep.Close()
	loadIPLists(ipRep, repos.IPList)
	ipRep.ConfigureAutoBan(prot.AutoBanEnabled, prot.AutoBanThreshold, prot.AutoBanWindow, prot.AutoBanDuration)
	ipRep.ConfigureAutoBanAction(prot.AutoBanAction)

	eng := engine.New(rt.Snapshot, reqRL, errRL, ipRep)

	// 自定义 Lua 策略引擎：脚本由 snapshot 在构建期编译，此处只负责持有与热替换。
	// KV 复用 RedisKV，Redis 不可用时脚本侧 kv.available() 返回 false，
	// 策略降级而非站点不可用。
	luaEngine := luaplugin.NewEngine(rt.RedisKV, logger.New("lua_plugin"))
	eng.SetLuaPlugins(luaEngine)
	// 用初始 snapshot 装载一次，避免首个 reload 之前脚本不生效。
	if sn := rt.Snapshot.Load(); sn != nil {
		luaEngine.Reload(sn.LuaPlugins)
	}
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
	// loadedGeoIPPath 记录 resolver 当前打开的库路径，供 reload 时判断是否需要换库。
	loadedGeoIPPath := botCfg.GeoIPDBPath
	if botCfg.Enabled {
		geoResolver = bot.NewMaxMindResolver(botCfg.GeoIPDBPath, botCfg.GeoIPDBPath, botCfg)
		// 持有 city/asn 两个 maxminddb 文件句柄，与本函数里其余资源一样在退出时释放。
		// 放在这里而不是函数开头：Close 会取锁，nil 接收者会 panic。
		defer geoResolver.Close()
		eng.SetGeoResolver(geoResolver, botCfg.ScoreThreshold)
		// Also set the global GeoResolver so LookupGeo works everywhere.
		bot.SetGeoResolver(geoResolver)
	}

	configSyncLog := logger.New("config_sync")
	var configSyncMu sync.RWMutex
	var configSync *coreredis.ConfigSync

	// Prometheus-compatible metrics collector.
	promMetrics := observability.NewMetrics()
	promMetrics.SetUnifiedWriterStatsProvider(unifiedWriter)
	promMetrics.SetDataPlaneMetricsProvider(func() observability.DataPlaneMetricsSnapshot {
		s := metrics.Summary()
		return observability.DataPlaneMetricsSnapshot{
			QPS1s:         s.QPS1s,
			QPS5s:         s.QPS5s,
			RequestsTotal: s.ReqTotal,
			Status2xx:     s.Status2xx,
			Status4xx:     s.Status4xx,
			Status5xx:     s.Status5xx,
			WAFBlocks:     s.WAFBlocks,
			WAFObserves:   s.WAFObserves,
			BuiltinHits:   s.BuiltinHits,
			UptimeSec:     s.UptimeSec,
			UniqueIPs:     s.UniqueIPs,
			AttackIPs:     s.AttackIPs,
		}
	})
	promMetrics.SetUpstreamMetricsProvider(func() observability.UpstreamMetricsSnapshot {
		states := upstreamPool.Snapshot()
		snapshot := observability.UpstreamMetricsSnapshot{
			KnownCount: int64(len(states)),
		}
		var latencySum int64
		var latencyTargets int64
		for _, st := range states {
			if st.Healthy {
				snapshot.HealthyCount++
			} else {
				snapshot.UnhealthyCount++
			}
			if !st.CheckedAt.IsZero() {
				snapshot.CheckedCount++
			}
			if st.LatencySamples > 0 {
				snapshot.LatencySamples += st.LatencySamples
				latencyTargets++
				latencySum += st.AverageLatencyMs
				if st.LastLatencyMs > snapshot.MaxLastLatencyMs {
					snapshot.MaxLastLatencyMs = st.LastLatencyMs
				}
			}
		}
		if latencyTargets > 0 {
			snapshot.AverageLatencyMs = float64(latencySum) / float64(latencyTargets)
		}
		return snapshot
	})
	// 缓存命中率指标：汇总各缓存层的 hits/misses，通过 /metrics 暴露。
	promMetrics.SetCacheStatsProvider(func() []observability.CacheLayerStats {
		qcHits, qcMisses := queryCache.HitStats()
		hcHits, hcMisses := hotCache.HitStats()
		rcHits, rcMisses := responseCache.HitStats()
		return []observability.CacheLayerStats{
			{Name: "query", Hits: qcHits, Misses: qcMisses},
			// hot 层走 Redis，故障（不可达/超时）与「键不存在」分开计数，
			// 便于区分「缓存未命中」与「依赖不可用导致穿透」。
			{Name: "hot", Hits: hcHits, Misses: hcMisses, Errors: hotCache.ErrorCount()},
			{Name: "response", Hits: rcHits, Misses: rcMisses},
		}
	})
	// Lua 策略脚本指标：脚本失败/超时只写日志就静默跳过，没有指标就无法告警。
	// 这里做单位换算与结构适配，observability 不反向依赖 luaplugin。
	promMetrics.SetLuaScriptStatsProvider(func() []observability.LuaScriptStats {
		stats := luaEngine.Stats()
		out := make([]observability.LuaScriptStats, 0, len(stats))
		for _, s := range stats {
			out = append(out, observability.LuaScriptStats{
				Name:          s.Name,
				Stage:         s.Stage,
				Runs:          s.Runs,
				Failures:      s.Failures,
				Timeouts:      s.Timeouts,
				AvgDurationMs: float64(s.AvgTime.Nanoseconds()) / 1e6,
			})
		}
		return out
	})

	hc := health.New(rt.DB, rt.Snapshot)
	lm := lifecycle.New(log)
	hc.SetReadyFunc(lm.Ready)

	dpLog := logger.New("dataplane")

	// Challenge managers: CAPTCHA, Shield (5-second), Chain.
	// 三者都会启动内存态会话清理协程，必须随进程优雅关闭一并停止。
	captchaMgr := challenge.NewCaptchaManager(rt.Redis, time.Duration(prot.CaptchaTimeout)*time.Second)
	defer captchaMgr.Close()

	// 初始化 go-captcha 高级验证码（点击/滑动/旋转）
	goCaptchaCfg := challenge.DefaultGoCaptchaConfig()
	if dir := os.Getenv("MY_OPENWAF_CAPTCHA_DIR"); dir != "" {
		goCaptchaCfg.ResourceDir = dir
	}
	goCaptchaProvider := challenge.NewGoCaptchaProvider(goCaptchaCfg, logger.New("gocaptcha"))
	captchaMgr.SetGoCaptchaProvider(goCaptchaProvider)

	shieldMgr := challenge.NewShieldManager(captchaMgr, rt.Redis, prot.ShieldDifficulty)
	defer shieldMgr.Close()
	chainMgr := challenge.NewChainChallengeManager(captchaMgr, rt.Redis)
	defer chainMgr.Close()

	// Anti-replay nonce protection manager.
	antiReplayMgr := antireplay.NewAntiReplayManager("", rt.Redis, 5*time.Minute)
	eng.SetAntiReplayManager(antiReplayMgr)

	// ─── Auth subsystems ───
	tokenMgr := auth.NewTokenManager(jwtSecret, rt.DB)
	defer tokenMgr.Close()
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
			EnableEnvCheck:       p.ShieldEnableEnvCheck,
			EnableDevToolsDetect: p.ShieldEnableDevTools,
		})
		chainMgr.Reconfigure(parseChainSteps(p.ChainSteps), p.ShieldDifficulty)
		bruteForce.Reconfigure(p.LoginMaxAttempts, time.Duration(p.LoginLockoutMinutes)*time.Minute)
		runtimeCfg, _ := runtimeState()
		dropPolicy := loadDropPolicy(repos.SystemSettings, runtimeCfg.Drop)
		dropExec.Reconfigure(dropPolicy.Enabled)
		eng.SetBotThreshold(dropPolicy.BotScoreThreshold)

		// 把管理界面保存的 GeoIP 配置同步给 resolver。不做这一步的话，
		// UI 上的高风险国家 / 机房 ASN / VPN ASN 保存成功却永远不生效。
		if geoResolver != nil {
			geoCfg := loadBotGeoConfig(repos.SystemSettings, runtimeCfg.Bot)
			// 换库要重新打开 mmap 文件，只在路径真的变了时做。
			if geoCfg.GeoIPDBPath != loadedGeoIPPath {
				geoResolver.Reload(geoCfg.GeoIPDBPath, geoCfg.GeoIPDBPath)
				loadedGeoIPPath = geoCfg.GeoIPDBPath
			}
			geoResolver.UpdateConfig(geoCfg)
		}
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

	// resourceAggregator 将 AppRoute 命中在内存中按资源唯一键聚合后批量落库，
	// 替代每命中一次 spawn goroutine + 同步 Upsert，显著降低高频写放大与 CPU 占用。
	resourceAggregator := dataplane.NewRecordedResourceAggregator(repos.RecordedResource, logger.New("resource-agg"))
	resourceAggregator.SetRedis(redisKV)
	defer resourceAggregator.Close()

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
		ResourceAggregator:    resourceAggregator,
		Upstreams:             upstreamPool,
		AccessControlRepo:     repos.AccessControl,
		JWTSecret:             jwtSecret,
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
		desiredH3 := buildHTTP3ServerPlans(newSn)

		for _, name := range lm.Names() {
			if !strings.HasPrefix(name, "h3:") {
				continue
			}
			plan, wantExists := desiredH3[name]
			if !wantExists {
				log.Info("removing stale HTTP/3 listener", slog.String("name", name))
				lm.Remove(name)
				continue
			}
			if lm.Tag(name) != plan.Tag {
				log.Info("restarting HTTP/3 listener due to config change",
					slog.String("name", name),
					slog.String("old_tag", lm.Tag(name)),
					slog.String("new_tag", plan.Tag),
				)
				lm.Remove(name)
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
			srv := buildDataServerWithHTTP3Plans(de.siteRT, newSn, dpOpts, desiredH3)
			if srv == nil {
				log.Warn("skipping site listener without valid TLS config", slog.String("name", name), slog.String("bind", de.siteRT.Bind))
				continue
			}
			lm.AddHertzWithTag(name, srv, de.tag)
			if err := lm.StartOne(name); err != nil {
				log.Error("hot-started site listener failed", slog.String("name", name), slog.Any("err", err))
				lm.Remove(name)
				continue
			}
			log.Info("hot-started site listener",
				slog.String("name", name),
				slog.String("bind", de.siteRT.Bind),
				slog.Bool("tls", de.siteRT.Site.TLSEnabled),
			)
		}
		for name, plan := range desiredH3 {
			if lm.Has(name) {
				continue
			}
			h3Srv := NewHTTP3Server(HTTP3ServerConfig{
				Bind:       plan.Bind,
				RouteTable: plan.RouteTable,
				TLSConfig:  plan.TLSConfig,
				Log:        log.With(slog.String("proto", "h3"), slog.String("udp_bind", plan.Bind)),
				Allow0RTT:  newSn.TLSDefaults.SessionTicketsEnabled,
			})
			lm.AddWithTag(name, h3Srv, plan.Tag)
			if err := lm.StartOne(name); err != nil {
				log.Error("hot-started HTTP/3 listener failed", slog.String("name", name), slog.Any("err", err))
				lm.Remove(name)
				continue
			}
				slog.String("name", name),
				slog.String("bind", plan.Bind),
				slog.String("targets", plan.RouteTable.targetSummary()),
			)
		}
	}

	currentProtectionConfig := func() store.ProtectionConfig {
		if current := rt.Snapshot.Load(); current != nil {
			return current.Protection
		}
		return prot
	}

	replaceConfigSync := func(client *goredis.Client, subscribeReload func() error) {
		configSyncMu.Lock()
		old := configSync
		configSync = coreredis.NewConfigSync(client, configSyncLog, "")
		next := configSync
		configSyncMu.Unlock()

		if old != nil {
			old.Close()
		}
		if next != nil && subscribeReload != nil {
			go next.Subscribe(subscribeReload)
		}
	}

	// replaceConfigSync 只关掉被替换下来的那个，最后一个实例得在退出时收尾——
	// 否则它的 Subscribe goroutine 会在优雅关闭期间继续消费 reload 通知。
	// Close 用 sync.Once 且 nil 安全，与上面的 old.Close() 重复调用也无妨。
	defer func() {
		configSyncMu.RLock()
		current := configSync
		configSyncMu.RUnlock()
		current.Close()
	}()

	publishConfigReload := func() {
		configSyncMu.RLock()
		current := configSync
		configSyncMu.RUnlock()
		if current != nil {
			current.PublishReload()
		}
	}

	applySnapshotReload := func() error {
		previousSnapshot := rt.Snapshot.Load()
		if err := rt.ReloadSnapshot(); err != nil {
			return err
		}
		currentSnapshot := rt.Snapshot.Load()
		if currentSnapshot != nil {
			applyProtectionRuntimeConfig(currentSnapshot.Protection)
			// 热替换 Lua 脚本集合：整体替换是原子的，正在执行的调用继续用旧集合跑完。
			luaEngine.Reload(currentSnapshot.LuaPlugins)
			for name, msg := range currentSnapshot.LuaPluginErrors {
				log.Warn("lua plugin compile failed, skipped",
					slog.String("script", name), slog.String("err", msg))
			}
		}
		loadIPLists(ipRep, repos.IPList)
		reconcileListeners()
		upstreamEndpointsChanged := snapshotUpstreamSetChanged(previousSnapshot, currentSnapshot)
		prunedUpstreamTransports := proxy.PruneInactiveUpstreamTransports(currentSnapshot)
		closedHTTPTransports, closedH2CTransports, closedHTTP3Transports := 0, 0, 0
		if upstreamEndpointsChanged {
			closedHTTPTransports, closedH2CTransports, closedHTTP3Transports = proxy.CloseIdleUpstreamTransports()
		}
		upstreamTransportStats := proxy.UpstreamTransportPoolStatsSnapshot()
		if upstreamEndpointsChanged || closedHTTPTransports > 0 || closedH2CTransports > 0 || closedHTTP3Transports > 0 || prunedUpstreamTransports.Changed() {
			log.Info("reconciled idle upstream transports after snapshot reload",
				slog.Bool("upstream_endpoints_changed", upstreamEndpointsChanged),
				slog.Int("http_transports", closedHTTPTransports),
				slog.Int("http2_cleartext_transports", closedH2CTransports),
				slog.Int("http3_transports", closedHTTP3Transports),
				slog.Int("pruned_http_transports", prunedUpstreamTransports.HTTPTransports),
				slog.Int("pruned_http2_cleartext_transports", prunedUpstreamTransports.HTTP2CleartextTransports),
				slog.Int("pruned_http_clients", prunedUpstreamTransports.HTTPClients),
				slog.Int("pruned_http_no_timeout_clients", prunedUpstreamTransports.HTTPNoTimeoutClients),
				slog.Int("pruned_http3_transports", prunedUpstreamTransports.HTTP3Transports),
				slog.Int("pruned_http3_clients", prunedUpstreamTransports.HTTP3Clients),
				slog.Int("pruned_http3_no_timeout_clients", prunedUpstreamTransports.HTTP3NoTimeoutClients),
				slog.Int("http_transport_pool_size", upstreamTransportStats.HTTPTransports),
				slog.Int("http2_cleartext_transport_pool_size", upstreamTransportStats.HTTP2CleartextTransports),
				slog.Int("http3_transport_pool_size", upstreamTransportStats.HTTP3Transports),
				slog.Int("http_client_pool_size", upstreamTransportStats.HTTPClients),
				slog.Int("http_no_timeout_client_pool_size", upstreamTransportStats.HTTPNoTimeoutClients),
				slog.Int("http3_client_pool_size", upstreamTransportStats.HTTP3Clients),
				slog.Int("http3_no_timeout_client_pool_size", upstreamTransportStats.HTTP3NoTimeoutClients),
			)
		}
		return nil
	}

	var runtimeReloadMu sync.Mutex
	var reloadRuntime func(propagate bool) error

	var reloadRedisRuntimeInternal func() error
	reloadRedisRuntimeInternal = func() error {
		stored, err := adminsystem.LoadRedisConfig(repos.SystemSettings)
		if err != nil {
			return err
		}
		var nextClient *goredis.Client
		if stored.Enabled {
			nextClient = coreredis.OptionalClient(coreredis.RedisOptions{
				Addr:     strings.TrimSpace(stored.Addr),
				Password: stored.Password,
				DB:       stored.DB,
			})
			pingCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := coreredis.Ping(pingCtx, nextClient); err != nil {
				if nextClient != nil {
					_ = nextClient.Close()
				}
				return err
			}
		}

		updatedCfg := applyRedisRuntimeReload(rt, stored, nextClient, redisRuntimeReloadDeps{
			runtimeStateMu: &runtimeStateMu,
			redisKV:        redisKV,
			hotCache:       hotCache,
			unifiedWriter:  unifiedWriter,
			captchaMgr:     captchaMgr,
			shieldMgr:      shieldMgr,
			chainMgr:       chainMgr,
			antiReplayMgr:  antiReplayMgr,
			escalationMgr:  escalationMgr,
			reqRL:          reqRL,
			errRL:          errRL,
			currentProtection: func() store.ProtectionConfig {
				return currentProtectionConfig()
			},
			replaceConfigSync: func(client *goredis.Client) {
				replaceConfigSync(client, func() error {
					if reloadRuntime == nil {
						return nil
					}
					return reloadRuntime(false)
				})
			},
		})

		log.Info("redis runtime reloaded",
			slog.Bool("enabled", nextClient != nil),
			slog.String("addr", updatedCfg.RedisAddr),
			slog.Int("db", updatedCfg.RedisDB),
		)
		return nil
	}

	ensureRedisRuntime := func() error {
		runtimeCfg, runtimeRedisEnabled := runtimeState()
		stored, err := adminsystem.LoadRedisConfig(repos.SystemSettings)
		if err != nil {
			return err
		}
		if !redisRuntimeSyncNeeded(stored, runtimeCfg, runtimeRedisEnabled) {
			return nil
		}
		if err := reloadRedisRuntimeInternal(); err != nil {
			log.Warn("redis runtime sync failed during reload",
				slog.Bool("stored_enabled", stored.Enabled),
				slog.String("stored_addr", strings.TrimSpace(stored.Addr)),
				slog.Int("stored_db", stored.DB),
				slog.Any("err", err),
			)
			return fmt.Errorf("redis runtime sync: %w", err)
		}
		return nil
	}

	reloadRuntime = func(propagate bool) error {
		runtimeReloadMu.Lock()
		defer runtimeReloadMu.Unlock()
		if propagate {
			if err := store.BumpRevision(rt.DB); err != nil {
				return err
			}
		}
		if err := applySnapshotReload(); err != nil {
			return err
		}
		stored, err := adminsystem.LoadRedisConfig(repos.SystemSettings)
		if err != nil {
			return err
		}
		runtimeCfg, runtimeRedisEnabled := runtimeState()
		prePublish := shouldPublishConfigReloadBeforeRedisSwitch(propagate, stored, runtimeCfg, runtimeRedisEnabled)
		if prePublish {
			publishConfigReload()
		}
		if err := ensureRedisRuntime(); err != nil {
			return err
		}
		if propagate && !prePublish {
			publishConfigReload()
		}
		return nil
	}

	reload := func() error {
		return reloadRuntime(true)
	}

	// 威胁情报 IP 订阅：后台定时从各订阅源拉取 IP/CIDR 列表并全量替换其派生条目。
	threatIntelMgr := threatintel.NewManager(rt.DB, logger.New("threatintel"), reload)
	threatIntelMgr.Start()
	defer threatIntelMgr.Stop()

	replaceConfigSync(rt.Redis, func() error {
		return reloadRuntime(false)
	})
	defer func() {
		configSyncMu.RLock()
		current := configSync
		configSyncMu.RUnlock()
		if current != nil {
			current.Close()
		}
	}()

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
	realtimeHub := adminsystem.NewRealtimeHub(&adminsystem.DashboardDeps{Metrics: metrics, ConfigDB: rt.DB, LogDB: rt.LogDB, Cache: redisKV}, upstreamPool, hc, repos.AccessLog, repos.SecurityEvent)
	realtimeHub.Start(ctx)

	admin.RegisterRoutes(adminSrv, &admin.Dependencies{
		Repos:  repos,
		Reload: reload,
		ReloadRedis: func() error {
			runtimeReloadMu.Lock()
			defer runtimeReloadMu.Unlock()
			return reloadRedisRuntimeInternal()
		},
		RuntimeState:  runtimeState,
		Snapshot:      rt.Snapshot,
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
		ThreatIntel:   threatIntelMgr,
		LuaEngine:     luaEngine,
	})
	lm.AddHertz("admin:"+rt.Config.AdminBind, adminSrv)

	// ─── Data-plane listener(s) ───
	if sn != nil {
		http3Plans := buildHTTP3ServerPlans(sn)
		for _, siteRT := range listenerRuntimesByBind(sn) {
			name := siteListenerName(siteRT.Bind)
			tag := siteListenerFingerprint(siteRT.Bind, sn)
			srv := buildDataServerWithHTTP3Plans(siteRT, sn, dpOpts, http3Plans)
			if srv == nil {
				log.Warn("skipping site listener without valid TLS config", slog.String("name", name), slog.String("bind", siteRT.Bind))
				continue
			}
			lm.AddHertzWithTag(name, srv, tag)
		}
		for name, plan := range http3Plans {
			h3Srv := NewHTTP3Server(HTTP3ServerConfig{
				Bind:       plan.Bind,
				RouteTable: plan.RouteTable,
				TLSConfig:  plan.TLSConfig,
				Log:        log.With(slog.String("proto", "h3"), slog.String("udp_bind", plan.Bind)),
				Allow0RTT:  sn.TLSDefaults.SessionTicketsEnabled,
			})
			lm.AddWithTag(name, h3Srv, plan.Tag)
			log.Info("HTTP/3 QUIC listener registered",
				slog.String("name", name),
				slog.String("bind", plan.Bind),
				slog.String("targets", plan.RouteTable.targetSummary()),
			)
		}
	}

	log.Info("My-OpenWaf ready",
		slog.String("db_driver", rt.Config.DBDriver),
		slog.Bool("redis_enabled", rt.Redis != nil),
		slog.String("admin_bind", rt.Config.AdminBind),
	)

	if err := lm.Start(); err != nil {
		log.Error("server startup failed", slog.Any("err", err))
		lm.Shutdown(context.Background())
		return
	}
	stopBackground()
}

func siteListenerName(bind string) string {
	return fmt.Sprintf("site:%s", bind)
}

func dataServerHTTP2Enabled(siteRT snapshotpkg.SiteRuntime, tlsCfg *tls.Config) bool {
	return siteRT.Site.TLSEnabled && tlsCfg != nil && alpnSliceIncludes(tlsCfg.NextProtos, "h2")
}

type redisRuntimeReloadDeps struct {
	runtimeStateMu    *sync.RWMutex
	redisKV           *cache.RedisKV
	hotCache          *cache.HotCache
	unifiedWriter     *observability.UnifiedWriter
	captchaMgr        *challenge.CaptchaManager
	shieldMgr         *challenge.ShieldManager
	chainMgr          *challenge.ChainChallengeManager
	antiReplayMgr     *antireplay.AntiReplayManager
	escalationMgr     *escalation.EscalationManager
	reqRL             *ratelimit.DynamicRateLimiter
	errRL             *ratelimit.DynamicRateLimiter
	currentProtection func() store.ProtectionConfig
	replaceConfigSync func(*goredis.Client)
}

func applyRedisRuntimeReload(rt *core.Runtime, stored adminsystem.RedisConfig, nextClient *goredis.Client, deps redisRuntimeReloadDeps) core.Config {
	if rt == nil {
		return core.Config{}
	}

	lock := func() {}
	unlock := func() {}
	if deps.runtimeStateMu != nil {
		lock = deps.runtimeStateMu.Lock
		unlock = deps.runtimeStateMu.Unlock
	}

	lock()
	oldClient := rt.Redis
	updatedCfg := rt.Config
	if stored.Enabled {
		updatedCfg.RedisAddr = strings.TrimSpace(stored.Addr)
		updatedCfg.RedisPassword = stored.Password
		updatedCfg.RedisDB = stored.DB
	} else {
		updatedCfg.RedisAddr = ""
		updatedCfg.RedisPassword = ""
		updatedCfg.RedisDB = 0
	}
	rt.Config = updatedCfg
	rt.Redis = nextClient
	unlock()

	if deps.redisKV != nil {
		deps.redisKV.SetClient(nextClient)
	}
	if deps.hotCache != nil {
		deps.hotCache.SetRedis(nextClient)
	}
	if deps.unifiedWriter != nil {
		deps.unifiedWriter.SetRedis(nextClient)
	}
	if deps.captchaMgr != nil {
		deps.captchaMgr.SetRedis(nextClient)
	}
	if deps.shieldMgr != nil {
		deps.shieldMgr.SetRedis(nextClient)
	}
	if deps.chainMgr != nil {
		deps.chainMgr.SetRedis(nextClient)
	}
	if deps.antiReplayMgr != nil {
		deps.antiReplayMgr.SetRedis(nextClient)
	}
	if deps.escalationMgr != nil {
		deps.escalationMgr.SetRedis(nextClient)
	}

	if deps.reqRL != nil || deps.errRL != nil {
		protection := store.DefaultProtectionConfig()
		if deps.currentProtection != nil {
			protection = deps.currentProtection()
		}
		if deps.reqRL != nil {
			deps.reqRL.Swap(buildRateLimiterBackend(nextClient, "openwaf:request", protection.RequestRateLimitWindow, protection.RequestRateLimitMax, protection.RequestRateLimitEnabled))
		}
		if deps.errRL != nil {
			deps.errRL.Swap(buildRateLimiterBackend(nextClient, "openwaf:error", protection.ErrorRateLimitWindow, protection.ErrorRateLimitMax, protection.ErrorRateLimitEnabled))
		}
	}

	if deps.replaceConfigSync != nil {
		deps.replaceConfigSync(nextClient)
	}

	if oldClient != nil && oldClient != nextClient {
		_ = oldClient.Close()
	}

	return updatedCfg
}

func redisRuntimeSyncNeeded(stored adminsystem.RedisConfig, runtimeCfg core.Config, runtimeEnabled bool) bool {
	storedAddr := strings.TrimSpace(stored.Addr)
	runtimeAddr := strings.TrimSpace(runtimeCfg.RedisAddr)

	if !stored.Enabled {
		return runtimeEnabled || runtimeAddr != "" || runtimeCfg.RedisPassword != "" || runtimeCfg.RedisDB != 0
	}
	if !runtimeEnabled {
		return true
	}
	return runtimeAddr != storedAddr || runtimeCfg.RedisPassword != stored.Password || runtimeCfg.RedisDB != stored.DB
}

func shouldPublishConfigReloadBeforeRedisSwitch(propagate bool, stored adminsystem.RedisConfig, runtimeCfg core.Config, runtimeEnabled bool) bool {
	return propagate && runtimeEnabled && redisRuntimeSyncNeeded(stored, runtimeCfg, runtimeEnabled)
}

func snapshotUpstreams(sn *snapshotpkg.Snapshot) []string {
	if sn == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var urls []string
	for _, rt := range sn.Sites {
		for _, raw := range rt.UpstreamURLs {
			raw = strings.TrimSpace(raw)
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
	sort.Strings(urls)
	return urls
}

func snapshotUpstreamSetChanged(previous, current *snapshotpkg.Snapshot) bool {
	previousUpstreams := snapshotUpstreams(previous)
	currentUpstreams := snapshotUpstreams(current)
	if len(previousUpstreams) != len(currentUpstreams) {
		return true
	}
	for i := range previousUpstreams {
		if previousUpstreams[i] != currentUpstreams[i] {
			return true
		}
	}
	return false
}

func listenerRuntimesByBind(sn *snapshotpkg.Snapshot) []snapshotpkg.SiteRuntime {
	if sn == nil {
		return nil
	}
	byBind := make(map[string]snapshotpkg.SiteRuntime)
	for _, rt := range sn.Sites {
		current, exists := byBind[rt.Bind]
		if !exists || (!current.Site.TLSEnabled && rt.Site.TLSEnabled) {
			byBind[rt.Bind] = *rt
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
	items, err := repo.AllEnabledGlobal()
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

/**
 * loadBotGeoConfig 把管理界面保存的 bot_settings 合并进启动时的 BotConfig。
 *
 * 管理端把高风险国家、机房 ASN、VPN/代理 ASN 与 GeoIP 库路径写进 SystemSettings 的
 * `bot_settings`，但 `core.BotConfig` 只来自硬编码默认值加两个环境变量，两条线原先
 * 没有交汇——UI 上保存成功，评分时用的却仍是默认值（`HighRiskCountries` 默认为 nil，
 * 意味着高风险国家评分从未生效）。这里补上缺的那一环。
 *
 * 只覆盖请求里出现过的字段：nil 切片表示「没配过」，保留 fallback；空切片是用户
 * 主动清空，如实生效。
 *
 * @param repo     系统设置仓储，nil 时原样返回 fallback。
 * @param fallback 启动时的 BotConfig（默认值 + 环境变量）。
 * @return 合并后的配置；读取或解析失败时返回 fallback，不让坏数据打断 reload。
 */
func loadBotGeoConfig(repo *repository.SystemSettingsRepo, fallback core.BotConfig) core.BotConfig {
	if repo == nil {
		return fallback
	}
	val, err := repo.Get("bot_settings")
	if err != nil || strings.TrimSpace(val) == "" {
		return fallback
	}
	// 字段名对齐管理端的 BotSettingsResponse：注意那边是 DatacenterASNs（小写 c）、
	// 这边 core.BotConfig 是 DataCenterASNs，靠 json tag 对应而非字段名。
	type botGeoSettings struct {
		HighRiskCountries []string `json:"high_risk_countries"`
		DatacenterASNs    []uint32 `json:"datacenter_asns"`
		VPNProxyASNs      []uint32 `json:"vpn_proxy_asns"`
		GeoIPDBPath       *string  `json:"geoip_db_path"`
	}
	var stored botGeoSettings
	if err := json.Unmarshal([]byte(val), &stored); err != nil {
		return fallback
	}

	cfg := fallback
	if stored.HighRiskCountries != nil {
		cfg.HighRiskCountries = stored.HighRiskCountries
	}
	if stored.DatacenterASNs != nil {
		cfg.DataCenterASNs = uint32SliceToUint(stored.DatacenterASNs)
	}
	if stored.VPNProxyASNs != nil {
		cfg.VPNProxyASNs = uint32SliceToUint(stored.VPNProxyASNs)
	}
	// 路径留空表示沿用环境变量配置的库，不要用空串把已加载的库顶掉。
	if stored.GeoIPDBPath != nil && strings.TrimSpace(*stored.GeoIPDBPath) != "" {
		cfg.GeoIPDBPath = strings.TrimSpace(*stored.GeoIPDBPath)
	}
	return cfg
}

// uint32SliceToUint 转换 ASN 列表：管理端用 uint32，core.BotConfig 用 uint。
func uint32SliceToUint(in []uint32) []uint {
	out := make([]uint, len(in))
	for i, v := range in {
		out[i] = uint(v)
	}
	return out
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

func resolveJWTSecret(rt *core.Runtime) ([]byte, error) {
	return resolveJWTSecretWithRandomRead(rt, rand.Read)
}

func resolveJWTSecretWithRandomRead(rt *core.Runtime, randomRead func([]byte) (int, error)) ([]byte, error) {
	if s := strings.TrimSpace(os.Getenv("MY_OPENWAF_JWT_SECRET")); s != "" {
		return []byte(s), nil
	}
	var setting store.SystemSettings
	err := rt.DB.Where(clause.Eq{Column: clause.Column{Name: "key"}, Value: store.SettingKeyJWTSecret}).First(&setting).Error
	if err == nil {
		if setting.Value != "" {
			return []byte(setting.Value), nil
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("load JWT secret from database: %w", err)
	}

	b := make([]byte, 32)
	if _, err := randomRead(b); err != nil {
		return nil, fmt.Errorf("generate JWT secret: %w", err)
	}
	secret := hex.EncodeToString(b)
	if err := rt.DB.Create(&store.SystemSettings{Key: store.SettingKeyJWTSecret, Value: secret}).Error; err != nil {
		return nil, fmt.Errorf("persist generated JWT secret: %w", err)
	}
	return []byte(secret), nil
}

const dynamicProtectionKeyInfo = "my-openwaf/dynamic-protection/encryption-key-base/v1"

// deriveDynamicProtectionKeyBase derives a dedicated 32-byte dynamic-protection
// key base from the existing persistent JWT secret without reusing the JWT key directly.
func deriveDynamicProtectionKeyBase(jwtSecret []byte) []byte {
	reader := hkdf.New(sha256.New, jwtSecret, nil, []byte(dynamicProtectionKeyInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		panic("dynamic protection key derivation failed: " + err.Error())
	}
	return key
}

// buildDataServer creates a Hertz server for a data-plane listener,
// optionally configured with TLS termination when the listener has TLS enabled.
// 支持 IPv4 和 IPv6 绑定地址。
func buildDataServer(siteRT snapshotpkg.SiteRuntime, sn *snapshotpkg.Snapshot, dpOpts dataplane.Options) *server.Hertz {
	return buildDataServerWithHTTP3Plans(siteRT, sn, dpOpts, nil)
}

func buildDataServerWithHTTP3Plans(siteRT snapshotpkg.SiteRuntime, sn *snapshotpkg.Snapshot, dpOpts dataplane.Options, http3Plans map[string]http3ServerPlan) *server.Hertz {
	network, _ := snapshotpkg.EffectiveSiteNetwork(siteRT.Site.ALPN, siteRT.Site.Network, siteRT.NetworkDefaults, siteRT.TLSDefaults)
	http2cfg := effectiveHTTP2Config(sn)
	http3Enabled := effectiveHTTP3Enabled(siteRT)
	http3AltSvc, http3AltSvcEnabled := buildHTTP3AltSvcAdvertisementWithPlans(siteRT, sn, http3Plans)
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
	needsClientHelloFingerprint := false
	if siteRT.Site.TLSEnabled {
		tlsCfg = buildListenerTLS(siteRT, sn)
		if tlsCfg == nil {
			rawLn.Close()
			return nil
		}
		needsClientHelloFingerprint = needsTLSClientHelloFingerprint(siteRT)
		if needsClientHelloFingerprint {
			ln = dataplane.NewTLSFingerprintListener(rawLn)
		}
		effectiveHTTP2 := alpnSliceIncludes(tlsCfg.NextProtos, "h2")
		slog.Info("TLS listener configured",
			slog.String("bind", siteRT.Bind),
			slog.String("network", network),
			slog.Bool("http2_enabled", effectiveHTTP2),
			slog.Bool("http3_enabled", http3Enabled),
			slog.Bool("client_hello_fingerprint_enabled", needsClientHelloFingerprint),
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
		server.WithStreamBody(true),
		server.WithUseRawPath(true),
		server.WithUnescapePathValues(false),
		server.WithDisablePreParseMultipartForm(true),
		server.WithMaxHeaderBytes(http2cfg.MaxHeaderBytes),
		server.WithMaxRequestBodySize(32 << 20),
		server.WithMaxKeepBodySize(64 << 10),
		server.WithSenseClientDisconnection(true),
		// 将连接读缓冲从默认 4KB 提升到 16KB，减少读取请求头/体时的
		// read 系统调用次数，属于保守的读路径吞吐优化，不影响超时与保活语义。
		server.WithReadBufferSize(16 << 10),
	}
	if siteRT.Site.TLSEnabled {
		opts = append(opts,
			server.WithTLS(tlsCfg),
			server.WithOnConnect(func(ctx context.Context, conn hertznet.Conn) context.Context {
				if tlsConn, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
					state := tlsConn.ConnectionState()
					setTLSHandshakeInfo(conn, state)
					if needsClientHelloFingerprint {
						if fp, ok := bot.TLSFingerprintFromConn(conn); ok {
							ctx = dataplane.ContextWithTLSFingerprint(ctx, fp)
						}
					}
					ctx = dataplane.ContextWithTLSHandshakeInfo(ctx, tlsVersionName(state.Version), state.ServerName, state.NegotiatedProtocol)
				}
				return ctx
			}),
		)
	}
	http2Enabled := dataServerHTTP2Enabled(siteRT, tlsCfg)
	if http2Enabled {
		opts = append(opts, server.WithALPN(true))
	}
	srv := server.Default(opts...)
	if http2Enabled {
		srv.AddProtocol("h2", shfactory.NewServerFactory(http2ServerFactoryOptions(http2cfg)...))
		slog.Info("HTTP/2 protocol factory registered", slog.String("bind", siteRT.Bind))
	}
	o := dpOpts
	o.Bind = siteRT.Bind
	handler := dataplane.Handler(o)

	if http3AltSvcEnabled {
		slog.Info("HTTP/3 Alt-Svc enabled",
			slog.String("bind", siteRT.Bind),
			slog.String("http3_bind", http3AltSvc.udpBind),
			slog.String("alt_svc", http3AltSvc.value),
		)
		origHandler := handler
		handler = func(ctx context.Context, c *app.RequestContext) {
			if altSvcValue, ok := http3AltSvc.valueForHost(string(c.Host())); ok {
				c.Response.Header.Set("Alt-Svc", altSvcValue)
			}
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
			if staple, ok := snapshotpkg.ParseOCSPStaple(siteRT.Certificate.OCSPStaplePEM); ok {
				cert.OCSPStaple = staple
			}
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
	alpn := tcpTLSALPNProtocols(effectiveALPN, siteRT.NetworkDefaults)
	if maxTLSVersionBelow(maxVer, tls.VersionTLS12) {
		alpn = removeALPNProtocol(alpn, "h2")
	}

	// 解析 TLS 密码套件
	var cipherSuites []uint16
	if cipherSuiteNames != "" {
		cipherSuites = parseCipherSuites(cipherSuiteNames)
	}
	curves := snapshotpkg.ParseCurvePreferences(siteRT.TLSDefaults.CurvePreferences)
	if len(curves) == 0 {
		curves = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	}

	var cfg *tls.Config
	cfg = &tls.Config{
		MinVersion:               minVer,
		MaxVersion:               maxVer,
		NextProtos:               alpn,
		CipherSuites:             cipherSuites,
		CurvePreferences:         curves,
		PreferServerCipherSuites: siteRT.TLSDefaults.PreferServerCipherSuites,
		SessionTicketsDisabled:   !siteRT.TLSDefaults.SessionTicketsEnabled,
		// GetCertificate 在 TLS 握手时被调用，根据 ClientHello 中的 SNI 动态选择证书。
		// 核心安全逻辑：只有当 SNI 匹配到已知站点时才返回真实证书，
		// 否则（IP 直接访问或未知域名）返回自签证书，防止域名信息泄露。
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.Conn != nil {
				setTLSHandshakeInfo(hello.Conn, tls.ConnectionState{ServerName: hello.ServerName})
			}
			return tcpTLSConfigForClientHello(cfg, hello), nil
		},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := strings.ToLower(strings.TrimSpace(hello.ServerName))

			// 该回调在每次 TLS 握手时执行。slog 的可变参数在调用点即求值并装箱，
			// 因此必须先判级别再构造属性，否则默认 info 级别下每次握手都会产生
			// 一批立刻被丢弃的堆分配。
			if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
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
			}

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
				// 站点不存在：返回自签证书，防止证书泄露真实域名。
				// IP 扫描与随机 SNI 探测会把这条路径打热，同样需要先判级别。
				if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
					slog.Debug("未知 SNI，返回自签证书",
						slog.String("sni", sni),
						slog.String("bind", bind),
					)
				}
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

// parseALPNProtocols 将逗号分隔的 ALPN 协议名称规范化为小写并去重。
func parseALPNProtocols(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(proto string) {
		proto = strings.ToLower(strings.TrimSpace(proto))
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

func tcpTLSALPNProtocols(raw string, defaults snapshotpkg.NetworkDefaults) []string {
	protos := parseALPNProtocols(raw)
	out := make([]string, 0, len(protos))
	hasH2 := false
	hasH3 := false
	for _, proto := range protos {
		if proto == "h3" {
			hasH3 = true
			continue
		}
		if proto == "h2" {
			hasH2 = true
		}
		out = append(out, proto)
	}
	if hasH3 && !hasH2 && defaults.HTTP2Enabled {
		if len(out) == 0 {
			return []string{"h2", "http/1.1"}
		}
		out = append([]string{"h2"}, out...)
	}
	if len(out) == 0 {
		if defaults.HTTP2Enabled {
			out = []string{"h2", "http/1.1"}
		} else {
			out = []string{"http/1.1"}
		}
	}
	return out
}

func tcpTLSConfigForClientHello(base *tls.Config, hello *tls.ClientHelloInfo) *tls.Config {
	if base == nil || hello == nil {
		return nil
	}
	if !alpnSliceIncludes(base.NextProtos, "h2") {
		return nil
	}
	if !serverMaxTLSVersionBelow(base, tls.VersionTLS12) && !clientHelloMaxTLSVersionBelow(hello, tls.VersionTLS12) {
		return nil
	}
	nextProtos := removeALPNProtocol(base.NextProtos, "h2")
	if len(nextProtos) == len(base.NextProtos) {
		return nil
	}
	cfg := base.Clone()
	cfg.NextProtos = nextProtos
	return cfg
}

func serverMaxTLSVersionBelow(cfg *tls.Config, version uint16) bool {
	return cfg != nil && maxTLSVersionBelow(cfg.MaxVersion, version)
}

func maxTLSVersionBelow(maxVersion uint16, version uint16) bool {
	return maxVersion != 0 && maxVersion < version
}

func clientHelloMaxTLSVersionBelow(hello *tls.ClientHelloInfo, version uint16) bool {
	if hello == nil || len(hello.SupportedVersions) == 0 {
		return false
	}
	maxVersion := uint16(0)
	for _, supported := range hello.SupportedVersions {
		switch supported {
		case tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13:
			if supported > maxVersion {
				maxVersion = supported
			}
		}
	}
	return maxVersion != 0 && maxVersion < version
}

func removeALPNProtocol(protos []string, removed string) []string {
	out := make([]string, 0, len(protos))
	for _, proto := range protos {
		if proto == removed {
			continue
		}
		out = append(out, proto)
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

func tlsVersionName(version uint16) string {
	return tlsmeta.CanonicalVersionName(version)
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
	return tlsmeta.ParseTLSConfigCipherSuites(raw)
}

func tlsCertificateFingerprintMaterial(cert tls.Certificate) string {
	h := sha256.New()
	for _, der := range cert.Certificate {
		fmt.Fprintf(h, " cert_der_len=%d", len(der))
		_, _ = h.Write(der)
	}
	if len(cert.OCSPStaple) > 0 {
		fmt.Fprintf(h, " ocsp_len=%d", len(cert.OCSPStaple))
		_, _ = h.Write(cert.OCSPStaple)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// siteListenerFingerprint produces a short hash that changes whenever a bind-level listener changes.
func siteListenerFingerprint(bind string, sn *snapshotpkg.Snapshot) string {
	h := sha256.New()
	fmt.Fprintf(h, "bind=%s", bind)

	runtimes := make([]snapshotpkg.SiteRuntime, 0)
	seenSites := make(map[uint]struct{})
	for _, rt := range sn.Sites {
		if rt.Bind != bind {
			continue
		}
		if _, seen := seenSites[rt.Site.ID]; seen {
			continue
		}
		seenSites[rt.Site.ID] = struct{}{}
		runtimes = append(runtimes, *rt)
	}
	sort.Slice(runtimes, func(i, j int) bool {
		if runtimes[i].Site.ID != runtimes[j].Site.ID {
			return runtimes[i].Site.ID < runtimes[j].Site.ID
		}
		if runtimes[i].Bind != runtimes[j].Bind {
			return runtimes[i].Bind < runtimes[j].Bind
		}
		return runtimes[i].Site.Host < runtimes[j].Site.Host
	})
	for _, rt := range runtimes {
		site := rt.Site
		effectiveNetwork, effectiveALPN := snapshotpkg.EffectiveSiteNetwork(site.ALPN, site.Network, rt.NetworkDefaults, rt.TLSDefaults)
		effectiveMinTLS, effectiveMaxTLS, effectiveCiphers := snapshotpkg.EffectiveSiteTLS(site.MinTLSVersion, site.MaxTLSVersion, site.CipherSuites, rt.TLSDefaults)
		fmt.Fprintf(h, " site=%d tls=%v network=%s min=%s max=%s alpn=%s", site.ID, rt.Site.TLSEnabled, effectiveNetwork, effectiveMinTLS, effectiveMaxTLS, effectiveALPN)
		fmt.Fprintf(h, " http3_enabled=%v http3_bind=%s ciphers=%s curves=%s prefer_server_cipher_suites=%v session_tickets_enabled=%v self_signed_on_ip=%v",
			rt.NetworkDefaults.HTTP3Enabled,
			strings.TrimSpace(rt.NetworkDefaults.HTTP3Bind),
			effectiveCiphers,
			strings.TrimSpace(rt.TLSDefaults.CurvePreferences),
			rt.TLSDefaults.PreferServerCipherSuites,
			rt.TLSDefaults.SessionTicketsEnabled,
			rt.TLSDefaults.SelfSignedOnIP,
		)
		if rt.Certificate != nil {
			cert, err := tls.X509KeyPair([]byte(rt.Certificate.CertPEM), []byte(rt.Certificate.KeyPEM))
			if err == nil {
				if staple, ok := snapshotpkg.ParseOCSPStaple(rt.Certificate.OCSPStaplePEM); ok {
					cert.OCSPStaple = staple
				}
				fmt.Fprintf(h, " cert_material=%s", tlsCertificateFingerprintMaterial(cert))
			}
		}
	}
	fmt.Fprintf(h, " http2_read_timeout=%d http2_disable_keepalive=%v http2_permit_prohibited_cipher_suites=%v http2_max_concurrent_streams=%d http2_max_read_frame_size=%d http2_idle_timeout=%d http2_max_upload_buffer_per_connection=%d http2_max_upload_buffer_per_stream=%d http2_max_header_bytes=%d http2_max_header_fields=%d http2_max_handlers=%d http2_max_queued_control_frames=%d",
		sn.HTTP2Config.ReadTimeoutSeconds,
		sn.HTTP2Config.DisableKeepalive,
		sn.HTTP2Config.PermitProhibitedCipherSuites,
		sn.HTTP2Config.MaxConcurrentStreams,
		sn.HTTP2Config.MaxReadFrameSize,
		sn.HTTP2Config.IdleTimeoutSeconds,
		sn.HTTP2Config.MaxUploadBufferPerConnection,
		sn.HTTP2Config.MaxUploadBufferPerStream,
		sn.HTTP2Config.MaxHeaderBytes,
		sn.HTTP2Config.MaxHeaderFields,
		sn.HTTP2Config.MaxHandlers,
		sn.HTTP2Config.MaxQueuedControlFrames,
	)

	prefix := "sni:" + bind + "\x00"
	sniKeys := make([]string, 0)
	for sniKey := range sn.SiteTLSCertBySNI {
		if strings.HasPrefix(sniKey, prefix) {
			sniKeys = append(sniKeys, sniKey)
		}
	}
	sort.Strings(sniKeys)
	for _, sniKey := range sniKeys {
		cert := sn.SiteTLSCertBySNI[sniKey]
		if strings.HasPrefix(sniKey, prefix) && len(cert.Certificate) > 0 {
			fmt.Fprintf(h, " sni=%s:material=%s", sniKey, tlsCertificateFingerprintMaterial(cert))
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
