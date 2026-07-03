package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/core/database"
	"My-OpenWaf/internal/core/redis"
	"My-OpenWaf/internal/pkg/logger"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"

	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Runtime struct {
	Config   Config
	DB       *gorm.DB
	LogDB    *gorm.DB
	Redis    *goredis.Client
	RedisKV  *cache.RedisKV
	Snapshot *snapshot.Holder
	Cache    *cache.Layer
}

func NewRuntime(ctx context.Context) (*Runtime, error) {
	cfg := LoadConfigFromEnv()
	preflightCfg := cfg
	// Redis can be overridden by the stored redis_config row, so bootstrap
	// validation must not fail on environment Redis values before the database
	// has been opened and the stored override applied.
	preflightCfg.RedisAddr = ""
	preflightCfg.RedisPassword = ""
	preflightCfg.RedisDB = 0

	log := logger.New("config")
	warnings, err := preflightCfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	for _, w := range warnings {
		log.Warn(w)
	}

	db, err := database.Open(database.Options{
		Driver:  cfg.DBDriver,
		DSN:     cfg.DBDSN,
		DataDir: cfg.DataDir,
	})
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	cfg = applyStoredRedisConfig(db, cfg)
	warnings, err = cfg.Validate()
	if err != nil {
		closeRuntimeDB(db)
		return nil, fmt.Errorf("config: %w", err)
	}
	for _, w := range warnings {
		log.Warn(w)
	}
	logDB, err := database.Open(database.Options{
		Driver:  cfg.DBDriver,
		DSN:     cfg.LogDBDSN,
		DataDir: cfg.DataDir,
	})
	if err != nil {
		closeRuntimeDB(db)
		return nil, fmt.Errorf("log database: %w", err)
	}

	rcli := redis.OptionalClient(redis.RedisOptions{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	if err := redis.Ping(ctx, rcli); err != nil {
		if rcli != nil {
			_ = rcli.Close()
			rcli = nil
		}
		if strings.TrimSpace(cfg.RedisAddr) != "" {
			log.Warn("redis unavailable, continuing without redis",
				"addr", cfg.RedisAddr,
				"db", cfg.RedisDB,
				"err", err,
			)
		}
	}

	cl, err := cache.NewLayer()
	if err != nil {
		if rcli != nil {
			_ = rcli.Close()
		}
		closeRuntimeDB(db)
		closeRuntimeDB(logDB)
		return nil, fmt.Errorf("cache: %w", err)
	}

	redisKV := cache.NewRedisKV(rcli)
	if redisKV.Available() {
		log.Info("redis distributed cache enabled")
	}

	return &Runtime{
		Config:   cfg,
		DB:       db,
		LogDB:    logDB,
		Redis:    rcli,
		RedisKV:  redisKV,
		Snapshot: &snapshot.Holder{},
		Cache:    cl,
	}, nil
}

type storedRedisConfig struct {
	Enabled  bool   `json:"enabled"`
	Addr     string `json:"addr"`
	Password string `json:"password,omitempty"`
	DB       int    `json:"db"`
}

func systemSettingKeyEquals(key string) clause.Eq {
	return clause.Eq{Column: clause.Column{Name: "key"}, Value: key}
}

func applyStoredRedisConfig(db *gorm.DB, cfg Config) Config {
	if db == nil || !db.Migrator().HasTable(&store.SystemSettings{}) {
		return cfg
	}
	var setting store.SystemSettings
	if err := db.Where(systemSettingKeyEquals(store.SettingKeyRedisConfig)).First(&setting).Error; err != nil || setting.Value == "" {
		return cfg
	}
	var stored storedRedisConfig
	if err := json.Unmarshal([]byte(setting.Value), &stored); err != nil {
		return cfg
	}
	if !stored.Enabled {
		cfg.RedisAddr = ""
		cfg.RedisPassword = ""
		cfg.RedisDB = 0
		return cfg
	}
	cfg.RedisAddr = strings.TrimSpace(stored.Addr)
	cfg.RedisPassword = stored.Password
	if stored.DB >= 0 {
		cfg.RedisDB = stored.DB
	}
	return cfg
}

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

type runtimeConfigRevision struct {
	ID       uint   `gorm:"primaryKey"`
	Revision uint64 `gorm:"not null"`
}

func (runtimeConfigRevision) TableName() string { return "config_revisions" }

func currentRevision(db *gorm.DB) (uint64, error) {
	var r runtimeConfigRevision
	if err := db.FirstOrCreate(&r, runtimeConfigRevision{ID: 1}).Error; err != nil {
		return 0, err
	}
	return r.Revision, nil
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	if r.Redis != nil {
		_ = r.Redis.Close()
	}
	closeRuntimeDB(r.DB)
	if r.LogDB != r.DB {
		closeRuntimeDB(r.LogDB)
	}
	return nil
}

func closeRuntimeDB(db *gorm.DB) {
	if db == nil {
		return
	}
	sqlDB, err := db.DB()
	if err == nil {
		_ = sqlDB.Close()
	}
}
