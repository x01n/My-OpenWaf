package store

import (
	"os"
	"testing"
	"time"

	"gorm.io/gorm"

	"My-OpenWaf/internal/core/database"
)

// TestAutoMigrateOnExternalDialect 在真实 MySQL / PostgreSQL 上跑完整 AutoMigrate。
//
// 存在意义：SQLite 宽容得多，多个只在 MySQL/PG 触发的 schema 问题无法被内存
// SQLite 测试发现。已实际踩到两类：
//   - TEXT 列带 DEFAULT（MySQL Error 1101）
//   - 复合唯一索引键长超过 3072 字节（MySQL Error 1071）
//
// 通过环境变量启用，未设置时跳过，故本地与默认 CI 不受影响：
//
//	MY_OPENWAF_TEST_MYSQL_DSN='root:pass@tcp(127.0.0.1:3306)/waf?charset=utf8mb4&parseTime=True&loc=Local'
//	MY_OPENWAF_TEST_POSTGRES_DSN='postgres://postgres:pass@127.0.0.1:5432/waf?sslmode=disable'
func TestAutoMigrateOnExternalDialect(t *testing.T) {
	cases := []struct {
		name   string
		driver string
		envKey string
	}{
		{"mysql", "mysql", "MY_OPENWAF_TEST_MYSQL_DSN"},
		{"postgres", "postgres", "MY_OPENWAF_TEST_POSTGRES_DSN"},
	}

	ran := 0
	for _, c := range cases {
		dsn := os.Getenv(c.envKey)
		if dsn == "" {
			t.Logf("跳过 %s：未设置 %s", c.name, c.envKey)
			continue
		}
		ran++
		t.Run(c.name, func(t *testing.T) {
			db, err := database.Open(database.Options{Driver: c.driver, DSN: dsn})
			if err != nil {
				t.Fatalf("连接 %s 失败：%v", c.name, err)
			}

			// AutoMigrate 必须成功——这是本用例的首要断言。
			if err := AutoMigrate(db); err != nil {
				t.Fatalf("%s AutoMigrate 失败：%v", c.name, err)
			}
			// 幂等：重复执行不得报错。
			if err := AutoMigrate(db); err != nil {
				t.Fatalf("%s AutoMigrate 重复执行失败（应幂等）：%v", c.name, err)
			}
			if err := AutoMigrateLogs(db); err != nil {
				t.Fatalf("%s AutoMigrateLogs 失败：%v", c.name, err)
			}
			if err := AutoMigrateLogs(db); err != nil {
				t.Fatalf("%s AutoMigrateLogs 重复执行失败（应幂等）：%v", c.name, err)
			}

			assertDedupKeyIndexUsable(t, db, c.name)
			assertHourBucketFormat(t, db, c.name)
			assertLogPaginationIndexes(t, db, c.name)
		})
	}

	if ran == 0 {
		t.Skip("未配置任何外部数据库 DSN，跳过多方言迁移验证")
	}
}

func assertLogPaginationIndexes(t *testing.T, db *gorm.DB, dialect string) {
	t.Helper()
	tests := []struct {
		model     any
		indexName string
	}{
		{model: &AccessLog{}, indexName: "idx_al_site_created_id"},
		{model: &SecurityEvent{}, indexName: "idx_se_site_created_id"},
	}
	want := []string{"site_id", "created_at", "id"}
	for _, tt := range tests {
		indexes, err := db.Migrator().GetIndexes(tt.model)
		if err != nil {
			t.Fatalf("%s: 读取索引 %s 失败：%v", dialect, tt.indexName, err)
		}
		found := false
		for _, index := range indexes {
			if index.Name() != tt.indexName {
				continue
			}
			found = true
			columns := index.Columns()
			if len(columns) != len(want) {
				t.Fatalf("%s: 索引 %s 列=%v，期望=%v", dialect, tt.indexName, columns, want)
			}

			// 列序断言仅对 mysql/sqlite 生效：两种方言的 GetIndexes 都按
			// 索引真实列序读回（mysql 用 SEQ_IN_INDEX 排序，sqlite 依赖
			// PRAGMA index_info.seqno）。postgres 驱动用
			// `a.attnum = ANY(i.indkey)` 读回且无 ORDER BY，读回顺序依赖
			// pg_index 的行序，任意且不可信。因此 postgres 上只断言
			// 「列集合相同且首列含义为 site_id」——列序本身在迁移过程中
			// 就是 gorm 声明顺序（events.go 里三个字段的 priority 为
			// 1/2/3 即 site_id/created_at/id）。
			if dialect == "postgres" {
				// gorm postgres 驱动 GetIndexes 用 `a.attnum = ANY(i.indkey)` 读回且
				// 无 ORDER BY，ColumnList 顺序依赖 pg_index 行序，任意（CI 实测为
				// [id created_at site_id]）。索引真实列序由迁移期 gorm 声明 priority
				// 保证——这里无法从读回面断言顺序，只能断言列集合完全相等，防止
				// 三列中任何一列被漏建或重建为含其他列。
				got := map[string]struct{}{}
				for _, col := range columns {
					got[col] = struct{}{}
				}
				if len(got) != len(want) {
					t.Fatalf("%s: 索引 %s 列数=%d，期望=%d，实际列=%v", dialect, tt.indexName, len(got), len(want), columns)
				}
				for _, w := range want {
					if _, ok := got[w]; !ok {
						t.Fatalf("%s: 索引 %s 缺少列 %q，实际列=%v", dialect, tt.indexName, w, columns)
					}
				}
				continue
			}

			for i := range want {
				if columns[i] != want[i] {
					t.Fatalf("%s: 索引 %s 第 %d 列=%q，期望=%q", dialect, tt.indexName, i, columns[i], want[i])
				}
			}
		}
		if !found {
			t.Fatalf("%s: 缺少日志分页索引 %s", dialect, tt.indexName)
		}
	}
}

// assertDedupKeyIndexUsable 验证摘要唯一索引真实生效：
// 同一 dedup_key 的第二次插入必须被拒绝。
func assertDedupKeyIndexUsable(t *testing.T, db *gorm.DB, dialect string) {
	t.Helper()
	now := time.Now().UTC()
	mk := func() *RecordedResource {
		return &RecordedResource{
			SiteID: 990, Method: "GET", Host: "dialect.test", Path: "/idx", QueryString: "k=1",
			FirstSeen: now, LastSeen: now, HitCount: 1,
		}
	}

	db.Where("site_id = ?", 990).Delete(&RecordedResource{})

	first := mk()
	if err := db.Create(first).Error; err != nil {
		t.Fatalf("%s: 首次插入应成功：%v", dialect, err)
	}
	if first.DedupKey == "" {
		t.Fatalf("%s: BeforeSave 钩子未填充 DedupKey", dialect)
	}

	if err := db.Create(mk()).Error; err == nil {
		t.Errorf("%s: 相同 dedup_key 的第二次插入应被唯一索引拒绝", dialect)
	}

	db.Where("site_id = ?", 990).Delete(&RecordedResource{})
}

// assertHourBucketFormat 验证方言相关的小时分桶表达式产出 "YYYY-MM-DD HH:00"。
//
// 三种方言必须格式一致：前端按空格切分取 HH:mm 作为图表轴标签，
// 任一方言输出 ISO 的 T 分隔符都会让该库下的图表轴错乱。
func assertHourBucketFormat(t *testing.T, db *gorm.DB, dialect string) {
	t.Helper()
	var expr string
	switch dialect {
	case "mysql":
		expr = "DATE_FORMAT(NOW(), '%Y-%m-%d %H:00')"
	case "postgres":
		expr = "to_char(date_trunc('hour', NOW()), 'YYYY-MM-DD HH24:00')"
	default:
		t.Fatalf("未知方言 %q", dialect)
	}

	var got string
	if err := db.Raw("SELECT " + expr).Scan(&got).Error; err != nil {
		t.Fatalf("%s: 分桶表达式执行失败：%v", dialect, err)
	}
	if len(got) != len("2026-07-26 12:00") {
		t.Errorf("%s: 分桶格式长度异常：%q", dialect, got)
	}
	if _, err := time.Parse("2006-01-02 15:04", got); err != nil {
		t.Errorf("%s: 分桶输出 %q 不符合 'YYYY-MM-DD HH:00'：%v", dialect, got, err)
	}
}
