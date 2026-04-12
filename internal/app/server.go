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
	"My-OpenWaf/internal/dataplane"
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

	token, err := store.SeedDefaults(rt.DB, rt.Config.AdminBind, logger.New("seed"))
	if err != nil {
		log.Error("seed defaults failed", slog.Any("err", err))
		os.Exit(1)
	}
	if token != "" {
		log.Info("=== FIRST RUN: admin API token (save it, shown only once) ===",
			slog.String("token", token))
	}

	if err := rt.ReloadSnapshot(); err != nil {
		log.Error("initial snapshot build failed", slog.Any("err", err))
		os.Exit(1)
	}

	// Resolve JWT secret from env or DB.
	jwtSecret := resolveJWTSecret(rt)

	repos := repository.New(rt.DB)
	reload := func() error {
		if err := store.BumpRevision(rt.DB); err != nil {
			return err
		}
		return rt.ReloadSnapshot()
	}

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

	eng := engine.New(rt.Snapshot, reqRL, errRL)

	hc := health.New(rt.DB, rt.Snapshot)
	lm := lifecycle.New(log)

	// ─── Admin control-plane server ───
	adminSrv := server.Default(server.WithHostPorts(rt.Config.AdminBind))
	adminSrv.GET("/healthz", hc.LivenessHandler())
	adminSrv.GET("/readyz", hc.ReadinessHandler())
	adminSrv.GET("/status", hc.StatusHandler())
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
				ListenerID: lid,
				Holder:     rt.Snapshot,
				Engine:     eng,
				Metrics:    metrics,
				Log:        dpLog,
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
