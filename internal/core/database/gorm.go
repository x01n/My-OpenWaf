package database

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	mysqldriver "github.com/go-sql-driver/mysql"
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
		Logger: logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Error,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		}),
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

	// WAL 模式允许「多读者 + 单写者」并发，因此读连接不应被限制为 1：
	// 单连接会把 dashboard 统计、访问日志分页等读操作也串行化，
	// 实测 16 协程并发读时吞吐仅为 8 连接的约 1/4.7。
	//
	// 写侧的安全性由两层保证：应用层 observability.WriteQueue 把高频写归并到
	// 单 goroutine；仍并发的写由 busy_timeout(10000) 吸收锁等待。已实测
	// 16 协程 × 60 次并发写在 8 连接下零失败。
	//
	// 取 8 而非更大值：实测 8 已达吞吐平台期（16 连接无进一步收益），
	// 更多连接只是徒增 SQLite 内部锁竞争与内存占用。
	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(sqliteMaxOpenConns)
		sqlDB.SetMaxIdleConns(sqliteMaxOpenConns)
		sqlDB.SetConnMaxLifetime(0) // 本地文件连接无需轮换
	}

	return db, nil
}

// sqliteMaxOpenConns 是 SQLite 的最大连接数。
// 见 openSQLite 中关于 WAL 读并发与写安全性的说明。
const sqliteMaxOpenConns = 8

func openMySQL(opt Options, gcfg *gorm.Config) (*gorm.DB, error) {
	dsn := strings.TrimSpace(opt.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("mysql requires MY_OPENWAF_DSN (e.g. user:pass@tcp(127.0.0.1:3306)/waf?charset=utf8mb4&parseTime=True&loc=Local)")
	}
	// parseTime=True 是必需的：缺失时 DATE/DATETIME 列会被扫描成 []byte，
	// 而模型里是 time.Time，导致 created_at 等字段读取报错。
	// 这类问题只在运行时首次查询才暴露，故在启动阶段就给出明确提示。
	if !strings.Contains(strings.ToLower(dsn), "parsetime=true") {
		return nil, fmt.Errorf("mysql DSN must include parseTime=True so DATETIME columns scan into time.Time (got %q)", maskDSN(dsn))
	}
	return gorm.Open(mysql.New(mysql.Config{
		DSN: dsn,
		// 让 GORM 用 MySQL 8+ 的原生 ALTER 语义；低版本会自动回退。
		DontSupportRenameIndex:  false,
		DontSupportRenameColumn: false,
	}), gcfg)
}

func openPostgres(opt Options, gcfg *gorm.Config) (*gorm.DB, error) {
	dsn := strings.TrimSpace(opt.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("postgres requires MY_OPENWAF_DSN (e.g. postgres://user:pass@localhost:5432/waf?sslmode=disable)")
	}
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN: dsn,
		// PreferSimpleProtocol=false 保留 prepared statement（与 gcfg.PrepareStmt 配合）。
		// 若部署在 PgBouncer 的 transaction 模式后，需要显式关闭——见文档说明。
		PreferSimpleProtocol: preferSimpleProtocolFromDSN(dsn),
	}), gcfg)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", maskDatabaseOpenError(err, dsn))
	}
	return db, nil
}

// preferSimpleProtocolFromDSN 在 DSN 里出现 pgbouncer=true 时改用简单协议。
//
// PgBouncer 的 transaction/statement 池化模式不保证同一连接，服务端 prepared
// statement 会失效并报 "prepared statement does not exist"。此时必须退回简单协议。
func preferSimpleProtocolFromDSN(dsn string) bool {
	return strings.Contains(strings.ToLower(dsn), "pgbouncer=true")
}

// maskDSN 遮蔽 DSN 中的口令，供错误信息安全输出。
func maskDSN(dsn string) string {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return ""
	}
	if u, err := url.Parse(trimmed); err == nil {
		changed := false
		if u.User != nil {
			username := u.User.Username()
			if username == "" {
				u.User = url.UserPassword("******", "******")
			} else {
				u.User = url.UserPassword(username, "******")
			}
			changed = true
		}
		query := u.Query()
		for key, values := range query {
			if !isDSNSecretKey(key) {
				continue
			}
			for index := range values {
				values[index] = "******"
			}
			query[key] = values
			changed = true
		}
		if changed {
			u.RawQuery = query.Encode()
			return u.String()
		}
	}
	if cfg, err := mysqldriver.ParseDSN(trimmed); err == nil && cfg.Passwd != "" {
		cfg.Passwd = "******"
		return cfg.FormatDSN()
	}
	return maskDSNKeywordValues(trimmed)
}

func maskDatabaseOpenError(err error, dsn string) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	if dsn != "" {
		message = strings.ReplaceAll(message, dsn, maskDSN(dsn))
	}
	return errors.New(maskDSN(message))
}

func isDSNSecretKey(key string) bool {
	switch {
	case strings.EqualFold(key, "password"),
		strings.EqualFold(key, "passwd"),
		strings.EqualFold(key, "pwd"),
		strings.EqualFold(key, "sslpassword"):
		return true
	default:
		return false
	}
}

func maskDSNKeywordValues(dsn string) string {
	var masked strings.Builder
	last := 0
	for index := 0; index < len(dsn); {
		if isDSNWhitespace(dsn[index]) {
			index++
			continue
		}

		keyStart := index
		for index < len(dsn) && !isDSNWhitespace(dsn[index]) && dsn[index] != '=' {
			index++
		}
		keyEnd := index
		for index < len(dsn) && isDSNWhitespace(dsn[index]) {
			index++
		}
		if keyStart == keyEnd || index == len(dsn) || dsn[index] != '=' {
			continue
		}

		index++
		for index < len(dsn) && isDSNWhitespace(dsn[index]) {
			index++
		}
		valueStart := index
		valueEnd, complete := scanDSNKeywordValueEnd(dsn, valueStart)
		if !complete {
			return "[redacted]"
		}
		if isDSNSecretKey(dsn[keyStart:keyEnd]) {
			masked.WriteString(dsn[last:valueStart])
			masked.WriteString("******")
			last = valueEnd
		}
		index = valueEnd
	}
	if last == 0 {
		return dsn
	}
	masked.WriteString(dsn[last:])
	return masked.String()
}

func scanDSNKeywordValueEnd(dsn string, start int) (int, bool) {
	if start == len(dsn) {
		return start, true
	}
	quote := dsn[start]
	if quote != '\'' && quote != '"' {
		for index := start; index < len(dsn); index++ {
			if dsn[index] == '\\' {
				if index+1 == len(dsn) {
					return len(dsn), false
				}
				index++
				continue
			}
			if isDSNWhitespace(dsn[index]) {
				return index, true
			}
		}
		return len(dsn), true
	}

	for index := start + 1; index < len(dsn); index++ {
		if dsn[index] == '\\' {
			if index+1 == len(dsn) {
				return len(dsn), false
			}
			index++
			continue
		}
		if dsn[index] != quote {
			continue
		}
		if index+1 < len(dsn) && !isDSNWhitespace(dsn[index+1]) {
			return len(dsn), false
		}
		return index + 1, true
	}
	return len(dsn), false
}

func isDSNWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}
