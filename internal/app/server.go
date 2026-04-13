package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"

	"github.com/cloudwego/hertz/pkg/app/server"

	"My-OpenWaf/internal/admin"
	"My-OpenWaf/internal/core"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/core/health"
	"My-OpenWaf/internal/core/lifecycle"
	coreredis "My-OpenWaf/internal/core/redis"
	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/pkg/logger"
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
			return nil
		})
	}

	hc := health.New(rt.DB, rt.Snapshot)
	lm := lifecycle.New(log)

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
	dpLog := logger.New("dataplane")
	if sn != nil {
		for lid, l := range sn.DataListeners {
			srv := server.Default(server.WithHostPorts(l.Bind))
			handler := dataplane.Handler(dataplane.Options{
				ListenerID:  lid,
				Holder:      rt.Snapshot,
				Engine:      eng,
				Metrics:     metrics,
				EventWriter: eventWriter,
				Log:         dpLog,
			})
			srv.Use(handler)
			lm.AddHertz("data:"+l.Bind, srv)
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
