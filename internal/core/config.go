package core

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is process bootstrap: SQL backend + optional Redis (cache / future pubsub).
type Config struct {
	// DBDriver: sqlite | mysql | postgres (default sqlite).
	DBDriver string
	// DBDSN: sqlite file path, or full DSN for mysql/postgres.
	// If empty with sqlite, falls back to DataDir/waf.db.
	DBDSN string
	// DataDir used when sqlite DSN has no directory part.
	DataDir string

	// Redis (optional). Empty Addr → no Redis client.
	RedisAddr     string
	RedisPassword string
	RedisDB       int

	// AdminBind is the address the admin control-plane server listens on.
	AdminBind string
	// AdminStaticDir overrides embedded frontend for local development.
	AdminStaticDir string
}

func LoadConfigFromEnv() Config {
	dsn := strings.TrimSpace(os.Getenv("MY_OPENWAF_DSN"))
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("MY_OPENWAF_DB"))
	}
	dir := strings.TrimSpace(os.Getenv("MY_OPENWAF_DATA"))
	if dir == "" {
		dir = "./data"
	}
	if dsn == "" {
		dsn = filepath.Join(dir, "waf.db")
	}

	driver := strings.ToLower(strings.TrimSpace(os.Getenv("MY_OPENWAF_DB_DRIVER")))
	if driver == "" {
		driver = "sqlite"
	}

	rd, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("MY_OPENWAF_REDIS_DB")))

	adminBind := strings.TrimSpace(os.Getenv("MY_OPENWAF_ADMIN_BIND"))
	if adminBind == "" {
		adminBind = ":9443"
	}

	return Config{
		DBDriver:       driver,
		DBDSN:          dsn,
		DataDir:        dir,
		RedisAddr:      strings.TrimSpace(os.Getenv("MY_OPENWAF_REDIS_ADDR")),
		RedisPassword:  strings.TrimSpace(os.Getenv("MY_OPENWAF_REDIS_PASSWORD")),
		RedisDB:        rd,
		AdminBind:      adminBind,
		AdminStaticDir: strings.TrimSpace(os.Getenv("MY_OPENWAF_ADMIN_STATIC_DIR")),
	}
}
