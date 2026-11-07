package repository

import (
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// archiveDeleter 是四条归档路径共用的最小接口，仅用于方言 DryRun 断言。
type archiveDeleter interface {
	DeleteOlderThan(before time.Time) (int64, error)
}

/**
 * TestArchiveDeleteOlderThanUsesDerivedTable 锁住归档删除的方言安全 SQL 形态。
 *
 * 背景：四条归档路径原先都生成
 *
 *	DELETE FROM t WHERE id IN (SELECT id FROM t WHERE created_at < ? LIMIT 5000)
 *
 * 这种写法在 SQLite 与 PostgreSQL 上可用，但在 MySQL 8.0 上必然失败：
 *   - ERROR 1235：`LIMIT & IN/ALL/ANY/SOME subquery` 不支持；
 *   - 即便去掉 LIMIT，同表子查询还会撞 ERROR 1093。
 *
 * 修复是把带 LIMIT 的子查询包进 derived table。含 LIMIT 的派生表不会被 MySQL
 * 合并回外层，这正是绕过 1235/1093 的机制；派生表必须带别名，否则 ERROR 1248。
 *
 * 本用例不连接真实 MySQL：用 DryRun + SkipDefaultTransaction 让 gorm 只生成 SQL。
 * SkipDefaultTransaction 不可省 —— 否则 Delete 的 gorm:begin_transaction 仍会
 * 真的连库，DryRun 下会报 connection refused。MySQL 驱动还需
 * SkipInitializeWithVersion，否则初始化时执行 SELECT VERSION() 同样连库。
 */
func TestArchiveDeleteOlderThanUsesDerivedTable(t *testing.T) {
	before := time.Now().UTC()

	dialects := []struct {
		name string
		new  func() gorm.Dialector
	}{
		{"sqlite", func() gorm.Dialector { return sqlite.Open(":memory:") }},
		{"mysql", func() gorm.Dialector {
			return mysql.New(mysql.Config{
				DSN:                       "u:p@tcp(127.0.0.1:3306)/db?parseTime=True",
				SkipInitializeWithVersion: true,
			})
		}},
		{"postgres", func() gorm.Dialector {
			return postgres.New(postgres.Config{
				DSN:                  "host=127.0.0.1 user=openwaf dbname=openwaf sslmode=disable",
				PreferSimpleProtocol: true,
			})
		}},
	}

	repos := []struct {
		name string
		new  func(db *gorm.DB) archiveDeleter
	}{
		{"security_event", func(db *gorm.DB) archiveDeleter { return NewSecurityEventRepo(db) }},
		{"access_log", func(db *gorm.DB) archiveDeleter { return NewAccessLogRepo(db) }},
		{"drop_event", func(db *gorm.DB) archiveDeleter { return NewDropEventRepo(db) }},
		{"threat_intel_sync_log", func(db *gorm.DB) archiveDeleter { return NewThreatIntelSyncLogRepo(db) }},
	}

	for _, d := range dialects {
		for _, r := range repos {
			t.Run(d.name+"/"+r.name, func(t *testing.T) {
				db, err := gorm.Open(d.new(), &gorm.Config{
					DryRun:                 true,
					DisableAutomaticPing:   true,
					SkipDefaultTransaction: true,
					Logger:                 logger.Default.LogMode(logger.Silent),
				})
				if err != nil {
					t.Fatalf("open dry-run db: %v", err)
				}
				if got := db.Dialector.Name(); got != d.name {
					t.Fatalf("Dialector.Name() = %q, want %q", got, d.name)
				}

				var captured string
				if err := db.Callback().Delete().After("gorm:delete").Register(
					"test:capture_archive_sql", func(tx *gorm.DB) {
						captured = tx.Statement.SQL.String()
					}); err != nil {
					t.Fatalf("register capture callback: %v", err)
				}

				// DryRun 下 RowsAffected 恒为 0，循环只跑一轮。
				if _, err := r.new(db).DeleteOlderThan(before); err != nil {
					t.Fatalf("DeleteOlderThan: %v", err)
				}
				if !strings.Contains(captured, "id IN (SELECT id FROM (SELECT ") {
					t.Fatalf("带 LIMIT 的子查询必须包进 derived table（MySQL ERROR 1235/1093）：%s", captured)
				}
				if !strings.Contains(captured, ") AS archive_batch)") {
					t.Fatalf("derived table 必须带别名（MySQL ERROR 1248）：%s", captured)
				}
			})
		}
	}
}
