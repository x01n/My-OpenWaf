package core

import (
	"context"
	"fmt"

	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/core/database"
	redisx "My-OpenWaf/internal/core/redis"
	"My-OpenWaf/internal/snapshot"
)

// Runtime wires SQL + optional Redis + cache + snapshot for the rest of the app.
type Runtime struct {
	Config   Config
	DB       *gorm.DB
	Redis    *goredis.Client
	Snapshot *snapshot.Holder
	Cache    *cache.Layer
}

// NewRuntime opens DB (and optional Redis) from env-based Config.
func NewRuntime(ctx context.Context) (*Runtime, error) {
	cfg := LoadConfigFromEnv()
	db, err := database.Open(database.Options{
		Driver:  cfg.DBDriver,
		DSN:     cfg.DBDSN,
		DataDir: cfg.DataDir,
	})
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	rcli := redisx.OptionalClient(redisx.RedisOptions{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	if err := redisx.Ping(ctx, rcli); err != nil {
		if rcli != nil {
			_ = rcli.Close()
		}
		return nil, fmt.Errorf("redis: %w", err)
	}

	cl, err := cache.NewLayer()
	if err != nil {
		return nil, fmt.Errorf("cache: %w", err)
	}

	return &Runtime{
		Config:   cfg,
		DB:       db,
		Redis:    rcli,
		Snapshot: &snapshot.Holder{},
		Cache:    cl,
	}, nil
}

// ReloadSnapshot builds a new snapshot from DB and stores it atomically.
func (r *Runtime) ReloadSnapshot() error {
	rev, err := currentRevision(r.DB)
	if err != nil {
		return err
	}
	if sn, ok := r.Cache.GetSnapshot(rev); ok {
		r.Snapshot.Store(sn)
		return nil
	}
	sn, err := snapshot.Build(r.DB, rev)
	if err != nil {
		return fmt.Errorf("snapshot build: %w", err)
	}
	r.Cache.SetSnapshot(rev, sn)
	r.Snapshot.Store(sn)
	return nil
}

func currentRevision(db *gorm.DB) (uint64, error) {
	type rev struct {
		ID       uint   `gorm:"primaryKey"`
		Revision uint64 `gorm:"not null"`
	}
	var r rev
	if err := db.Table("config_revisions").FirstOrCreate(&r, rev{ID: 1}).Error; err != nil {
		return 0, err
	}
	return r.Revision, nil
}

// Close releases Redis; GORM/sql.DB is closed via underlying sql.DB if needed.
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	if r.Redis != nil {
		_ = r.Redis.Close()
	}
	sqlDB, err := r.DB.DB()
	if err == nil {
		_ = sqlDB.Close()
	}
	return nil
}
