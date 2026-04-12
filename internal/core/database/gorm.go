package database

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Options are DB connection parameters (kept here to avoid import cycles with [core]).
type Options struct {
	Driver  string // sqlite | mysql | postgres
	DSN     string
	DataDir string // used when sqlite DSN is empty
}

// Open returns a GORM handle for the configured SQL dialect.
func Open(opt Options) (*gorm.DB, error) {
	gcfg := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	}

	switch opt.Driver {
	case "sqlite", "":
		path := opt.DSN
		if path == "" {
			path = filepath.Join(opt.DataDir, "waf.db")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir sqlite dir: %w", err)
		}
		return gorm.Open(sqlite.Open(path), gcfg)

	case "mysql":
		dsn := strings.TrimSpace(opt.DSN)
		if dsn == "" {
			return nil, fmt.Errorf("mysql requires MY_OPENWAF_DSN (e.g. user:pass@tcp(127.0.0.1:3306)/waf?charset=utf8mb4&parseTime=True&loc=Local)")
		}
		return gorm.Open(mysql.Open(dsn), gcfg)

	case "postgres", "postgresql":
		dsn := strings.TrimSpace(opt.DSN)
		if dsn == "" {
			return nil, fmt.Errorf("postgres requires MY_OPENWAF_DSN (e.g. postgres://user:pass@localhost:5432/waf?sslmode=disable)")
		}
		return gorm.Open(postgres.Open(dsn), gcfg)

	default:
		return nil, fmt.Errorf("unsupported MY_OPENWAF_DB_DRIVER %q (use sqlite, mysql, postgres)", opt.Driver)
	}
}
