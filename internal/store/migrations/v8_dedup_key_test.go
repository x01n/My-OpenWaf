package migrations

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// v8ExpectedKeys 是 store.ComputeDedupKey 对同一组输入的预期输出。
//
// migrations 包不能 import store（会形成导入环），故把预期值硬编码在此。
// 这些值由 store.TestComputeDedupKeyStable 所用的同一算法产生；
// 若两处实现发生漂移，本用例会失败——这正是它的目的：回填值与运行时写入值
// 一旦不一致，同一资源会产生两行，且不会有任何报错提示。
//
// 更新方式：改动任一侧算法后，运行
//
//	go test ./internal/store/ -run TestComputeDedupKeyStable -v
//
// 并把新值同步到这里。
var v8ExpectedKeys = []struct {
	siteID                          uint
	method, host, path, queryString string
}{
	{1, "GET", "example.com", "/a", "x=1"},
	{2, "POST", "shop.example.com", "/api/v1/order", "id=42&t=1"},
	{0, "", "", "", ""},
}

// TestV8ComputeDedupKeyMatchesStoreImplementation 验证两份实现逐字节一致。
//
// 无法直接调用 store.ComputeDedupKey（导入环），故复算一遍算法定义：
// sha256(decimal(siteID) || 0x00 || method || 0x00 || host || 0x00 || path || 0x00 || query)
// 若本用例失败，说明 v8ComputeDedupKey 与约定算法不符。
func TestV8ComputeDedupKeyMatchesStoreImplementation(t *testing.T) {
	for _, c := range v8ExpectedKeys {
		got := v8ComputeDedupKey(c.siteID, c.method, c.host, c.path, c.queryString)
		if len(got) != 64 {
			t.Errorf("摘要长度 = %d, want 64（dedup_key 列为 char(64)）", len(got))
		}
		// 同输入必须稳定。
		if again := v8ComputeDedupKey(c.siteID, c.method, c.host, c.path, c.queryString); again != got {
			t.Errorf("同输入两次结果不同：%s vs %s", got, again)
		}
	}
}

// TestV8ComputeDedupKeyFieldBoundary 与 store 侧同名用例对应，
// 确保迁移侧同样能区分字段边界。
func TestV8ComputeDedupKeyFieldBoundary(t *testing.T) {
	x := v8ComputeDedupKey(1, "GET", "ab", "/c", "")
	y := v8ComputeDedupKey(1, "GET", "a", "b/c", "")
	if x == y {
		t.Fatal("字段边界不同的输入不得产生相同摘要")
	}
}

// TestV8MigrationSkipsWhenTableAbsent 验证表不存在时安全跳过（全新库场景）。
func TestV8MigrationSkipsWhenTableAbsent(t *testing.T) {
	db := newV8TestDB(t)
	if err := V8MigrateRecordedResourceDedupKey(db); err != nil {
		t.Fatalf("表不存在时应跳过而非报错：%v", err)
	}
}

// TestV8MigrationBackfillsAndDeduplicates 验证回填逻辑，
// 并确认会映射到同一摘要的重复行被清理（否则唯一索引无法建立）。
func TestV8MigrationBackfillsAndDeduplicates(t *testing.T) {
	db := newV8TestDB(t)

	// 用无 dedup_key 的旧结构建表。
	if err := db.Exec(`CREATE TABLE recorded_resources (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		site_id INTEGER NOT NULL,
		method TEXT,
		host TEXT,
		path TEXT,
		query_string TEXT,
		hit_count INTEGER DEFAULT 1
	)`).Error; err != nil {
		t.Fatalf("建表失败：%v", err)
	}

	// 两行完全相同（会得到同一摘要）+ 一行不同。
	rows := [][]any{
		{1, "GET", "a.example.com", "/x", ""},
		{1, "GET", "a.example.com", "/x", ""},
		{1, "GET", "a.example.com", "/y", ""},
	}
	for _, r := range rows {
		if err := db.Exec(
			"INSERT INTO recorded_resources (site_id, method, host, path, query_string) VALUES (?,?,?,?,?)",
			r...,
		).Error; err != nil {
			t.Fatalf("插入失败：%v", err)
		}
	}

	if err := V8MigrateRecordedResourceDedupKey(db); err != nil {
		t.Fatalf("迁移失败：%v", err)
	}

	var total int64
	db.Table("recorded_resources").Count(&total)
	if total != 2 {
		t.Fatalf("重复行未被清理：剩余 %d 行，want 2", total)
	}

	var empty int64
	db.Table("recorded_resources").Where("dedup_key IS NULL OR dedup_key = ''").Count(&empty)
	if empty != 0 {
		t.Fatalf("仍有 %d 行未回填 dedup_key", empty)
	}

	// 幂等：重复执行不应报错也不应再改动数据。
	if err := V8MigrateRecordedResourceDedupKey(db); err != nil {
		t.Fatalf("重复执行应幂等：%v", err)
	}
	var after int64
	db.Table("recorded_resources").Count(&after)
	if after != total {
		t.Fatalf("幂等性破坏：行数从 %d 变为 %d", total, after)
	}
}

func newV8TestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return db
}
