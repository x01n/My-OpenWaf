package database

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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

// Open returns a GORM handle for the configured SQL dialect with tuned connection pool.
func Open(opt Options) (*gorm.DB, error) {
	gcfg := &gorm.Config{
		Logger:                 logger.Default.LogMode(logger.Warn),
		SkipDefaultTransaction: true, // avoid wrapping every single INSERT in a transaction
		PrepareStmt:            true, // cache prepared statements for repeated queries
	}

	var db *gorm.DB
	var err error

	switch opt.Driver {
	case "sqlite", "":
		db, err = openSQLite(opt, gcfg)
	case "mysql":
		db, err = openMySQL(opt, gcfg)
	case "postgres", "postgresql":
		db, err = openPostgres(opt, gcfg)
	default:
		return nil, fmt.Errorf("unsupported MY_OPENWAF_DB_DRIVER %q (use sqlite, mysql, postgres)", opt.Driver)
	}
	if err != nil {
		return nil, err
	}

	// Tune connection pool for non-SQLite databases.
	if opt.Driver != "sqlite" && opt.Driver != "" {
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.SetMaxOpenConns(25)
			sqlDB.SetMaxIdleConns(10)
			sqlDB.SetConnMaxLifetime(30 * time.Minute)
			sqlDB.SetConnMaxIdleTime(5 * time.Minute)
		}
	}

	return db, nil
}

func openSQLite(opt Options, gcfg *gorm.Config) (*gorm.DB, error) {
	path := opt.DSN
	if path == "" {
		path = filepath.Join(opt.DataDir, "waf.db")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir sqlite dir: %w", err)
	}

	// SQLite pragmas for performance:
	//   journal_mode=WAL       — concurrent reads during writes
	//   busy_timeout=10000     — wait up to 10s on lock contention instead of immediate SQLITE_BUSY
	//   synchronous=NORMAL     — balanced durability vs speed (safe with WAL)
	//   cache_size=-64000      — 64MB page cache
	//   foreign_keys=ON        — enforce FK constraints
	//   wal_autocheckpoint=1000 — checkpoint every 1000 pages to avoid long WAL stalls
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=cache_size(-64000)&_pragma=foreign_keys(ON)&_pragma=wal_autocheckpoint(1000)"

	db, err := gorm.Open(sqlite.Open(dsn), gcfg)
	if err != nil {
		return nil, err
	}

	// SQLite should use a single connection to avoid locking issues.
	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
		sqlDB.SetConnMaxLifetime(0) // no lifetime limit for single connection
	}

	return db, nil
}

func openMySQL(opt Options, gcfg *gorm.Config) (*gorm.DB, error) {
	dsn := strings.TrimSpace(opt.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("mysql requires MY_OPENWAF_DSN (e.g. user:pass@tcp(127.0.0.1:3306)/waf?charset=utf8mb4&parseTime=True&loc=Local)")
	}
	return gorm.Open(mysql.Open(dsn), gcfg)
}

func openPostgres(opt Options, gcfg *gorm.Config) (*gorm.DB, error) {
	dsn := strings.TrimSpace(opt.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("postgres requires MY_OPENWAF_DSN (e.g. postgres://user:pass@localhost:5432/waf?sslmode=disable)")
	}
	return gorm.Open(postgres.Open(dsn), gcfg)
}
