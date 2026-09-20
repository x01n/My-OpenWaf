package migrations

import (
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func openMemDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	return db
}

// TestV9EnsureDefaultPolicyRepairsReferencesIdempotently 验证默认策略迁移会忽略软删除策略并幂等修复规则与站点引用。
func TestV9EnsureDefaultPolicyRepairsReferencesIdempotently(t *testing.T) {
	db := openMemDB(t)
	statements := []string{
		`CREATE TABLE policies (id INTEGER PRIMARY KEY, created_at DATETIME, updated_at DATETIME, deleted_at DATETIME, name TEXT, description TEXT, default_slot INTEGER)`,
		`CREATE TABLE rules (id INTEGER PRIMARY KEY, policy_id INTEGER)`,
		`CREATE TABLE sites (id INTEGER PRIMARY KEY, policy_id INTEGER)`,
		`INSERT INTO policies (id, name, default_slot, deleted_at) VALUES (1, 'deleted default', 1, '2026-01-01T00:00:00Z'), (2, 'active policy', NULL, NULL)`,
		`INSERT INTO rules (id, policy_id) VALUES (1, NULL), (2, 0), (3, 99), (4, 2)`,
		`INSERT INTO sites (id, policy_id) VALUES (1, NULL), (2, 0), (3, 99), (4, 2)`,
	}
	for _, statement := range statements {
		if err := db.Exec(statement).Error; err != nil {
			t.Fatalf("setup migration fixture: %v", err)
		}
	}

	if err := V9EnsureDefaultPolicy(db); err != nil {
		t.Fatalf("first V9 migration: %v", err)
	}
	if err := V9EnsureDefaultPolicy(db); err != nil {
		t.Fatalf("second V9 migration: %v", err)
	}

	var defaults []struct {
		ID uint
	}
	if err := db.Raw("SELECT id FROM policies WHERE default_slot = 1 AND deleted_at IS NULL").Scan(&defaults).Error; err != nil {
		t.Fatalf("load default policies: %v", err)
	}
	if len(defaults) != 1 || defaults[0].ID != 3 {
		t.Fatalf("expected one active default policy with id 3, got %+v", defaults)
	}

	var rulePolicies []struct {
		PolicyID *uint `gorm:"column:policy_id"`
	}
	if err := db.Raw("SELECT policy_id FROM rules ORDER BY id").Scan(&rulePolicies).Error; err != nil {
		t.Fatalf("load repaired rule references: %v", err)
	}
	for i, item := range rulePolicies {
		if i < 3 {
			if item.PolicyID == nil || *item.PolicyID != 3 {
				t.Fatalf("unexpected rule reference at index %d: %+v", i, item)
			}
			continue
		}
		if item.PolicyID == nil || *item.PolicyID != 2 {
			t.Fatalf("unexpected rule reference at index %d: %+v", i, item)
		}
	}

	var sitePolicies []struct {
		PolicyID *uint `gorm:"column:policy_id"`
	}
	if err := db.Raw("SELECT policy_id FROM sites ORDER BY id").Scan(&sitePolicies).Error; err != nil {
		t.Fatalf("load repaired site references: %v", err)
	}
	for i, item := range sitePolicies {
		if i < 3 && item.PolicyID != nil || i == 3 && (item.PolicyID == nil || *item.PolicyID != 2) {
			t.Fatalf("unexpected site reference at index %d: %+v", i, item)
		}
	}
}

// TestIsIgnorableDropDefaultError 验证各类 MySQL/Postgres 错误消息的判断逻辑。
func TestIsIgnorableDropDefaultError(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"can't drop field", true},
		{"CAN'T DROP FIELD", true},
		{"cannot drop column", true},
		{"check that column/key exists", true},
		{"doesn't have a default value", true},
		{"some other error", false},
		{"", false},
	}
	for _, tc := range cases {
		var err error
		if tc.msg != "" {
			err = errors.New(tc.msg)
		}
		got := isIgnorableDropDefaultError(err)
		if got != tc.want {
			t.Errorf("isIgnorableDropDefaultError(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

func TestIsIgnorableDropDefaultErrorNilReturnsFalse(t *testing.T) {
	if isIgnorableDropDefaultError(nil) {
		t.Error("nil error should return false")
	}
}

// TestV2MigrateSingleSiteSkipsWhenNoListenerTable 验证 listeners 表不存在时幂等返回 nil。
func TestV2MigrateSingleSiteSkipsWhenNoListenerTable(t *testing.T) {
	db := openMemDB(t)
	if err := V2MigrateSingleSite(db); err != nil {
		t.Errorf("V2MigrateSingleSite on empty DB: %v", err)
	}
}

// TestV3MigrateLegacyRulePhasesSkipsWhenNoRulesTable 验证 rules 表不存在时幂等返回 nil。
func TestV3MigrateLegacyRulePhasesSkipsWhenNoRulesTable(t *testing.T) {
	db := openMemDB(t)
	if err := V3MigrateLegacyRulePhases(db); err != nil {
		t.Errorf("V3MigrateLegacyRulePhases on empty DB: %v", err)
	}
}

// TestV4MigrateSkipsWhenNoTable 验证前置表不存在时各 v4 函数幂等返回 nil。
func TestV4RecordedResourceQueryStringSkipsWhenNoTable(t *testing.T) {
	db := openMemDB(t)
	if err := V4MigrateRecordedResourceQueryString(db); err != nil {
		t.Errorf("V4MigrateRecordedResourceQueryString on empty DB: %v", err)
	}
}

// TestV5MigrateSiteTLSInheritanceDefaultsSkipsOnSQLite 验证 SQLite 方言时直接幂等返回。
func TestV5MigrateSiteTLSInheritanceDefaultsSkipsOnSQLite(t *testing.T) {
	db := openMemDB(t)
	// SQLite 路径：直接返回 nil（不做任何 ALTER）
	if err := V5MigrateSiteTLSInheritanceDefaults(db); err != nil {
		t.Errorf("V5MigrateSiteTLSInheritanceDefaults on SQLite: %v", err)
	}
}

// TestV6MigrateSkipsOnSQLite 验证 SQLite 下 v6 迁移幂等返回 nil。
func TestV6MigrateSiteTLSMinVersionSkipsOnSQLite(t *testing.T) {
	db := openMemDB(t)
	if err := V6MigrateSiteTLSMinVersionInheritance(db); err != nil {
		t.Errorf("V6MigrateSiteTLSMinVersionInheritance on SQLite: %v", err)
	}
}

// TestV7MigrateAccessControlIdempotent 验证 V7 在 SQLite 内存库上建表后重复调用不返回错误。
func TestV7MigrateAccessControlIdempotent(t *testing.T) {
	db := openMemDB(t)
	if err := V7MigrateAccessControl(db); err != nil {
		t.Fatalf("V7MigrateAccessControl first call: %v", err)
	}
	// 幂等性：第二次调用也应成功
	if err := V7MigrateAccessControl(db); err != nil {
		t.Errorf("V7MigrateAccessControl second call (idempotent): %v", err)
	}
}

func TestV10MigrateSiteXFFModesSkipsWhenSitesOrXFFModeMissing(t *testing.T) {
	t.Run("sites missing", func(t *testing.T) {
		db := openMemDB(t)
		for pass := 1; pass <= 2; pass++ {
			if err := V10MigrateSiteXFFModes(db); err != nil {
				t.Fatalf("migration pass %d: %v", pass, err)
			}
		}
	})

	t.Run("xff_mode missing", func(t *testing.T) {
		db := openMemDB(t)
		if err := db.Exec("CREATE TABLE sites (id INTEGER PRIMARY KEY)").Error; err != nil {
			t.Fatalf("create sites table: %v", err)
		}
		for pass := 1; pass <= 2; pass++ {
			if err := V10MigrateSiteXFFModes(db); err != nil {
				t.Fatalf("migration pass %d: %v", pass, err)
			}
		}
	})
}

// TestV3MigrateLegacyRulePhasesWithRulesTable 验证有 rules 表时迁移可执行完成。
func TestV3MigrateLegacyRulePhasesWithRulesTable(t *testing.T) {
	db := openMemDB(t)
	if err := db.AutoMigrate(&ruleTable{}); err != nil {
		t.Fatalf("AutoMigrate ruleTable: %v", err)
	}
	// 插入需要迁移的行
	db.Exec("INSERT INTO rules (phase) VALUES (?)", "rate_limit")
	db.Exec("INSERT INTO rules (phase) VALUES (?)", "owasp_default")
	db.Exec("INSERT INTO rules (phase) VALUES (?)", "custom")

	if err := V3MigrateLegacyRulePhases(db); err != nil {
		t.Fatalf("V3MigrateLegacyRulePhases: %v", err)
	}

	var count int64
	db.Model(&ruleTable{}).Where("phase != ?", "custom").Count(&count)
	if count != 0 {
		t.Errorf("after migration, expected 0 non-custom rows, got %d", count)
	}
}
