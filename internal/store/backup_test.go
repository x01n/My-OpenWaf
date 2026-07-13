package store

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// newBackupTestDB 创建带完整配置表的内存测试库。
func newBackupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&Certificate{}, &Policy{}, &Rule{}, &Site{}, &SiteListener{},
		&SystemSettings{}, &IPListEntry{}, &ThreatIntelFeed{}, &CVERuleRecord{},
		&ApplicationRouteRule{}, &SiteAccessConfig{}, &AccessProvider{},
		&AccessUser{}, &AccessPathRule{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// seedBackupData 填充一组有外键关联的配置数据。
func seedBackupData(t *testing.T, db *gorm.DB) {
	t.Helper()
	cert := Certificate{Name: "test-cert"}
	if err := db.Create(&cert).Error; err != nil {
		t.Fatalf("create cert: %v", err)
	}
	policy := Policy{Name: "test-policy"}
	if err := db.Create(&policy).Error; err != nil {
		t.Fatalf("create policy: %v", err)
	}
	site := Site{Host: "example.com", Bind: ":8080", CertID: &cert.ID, PolicyID: &policy.ID}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("create site: %v", err)
	}
	ip := IPListEntry{Kind: IPListBlack, Value: "1.2.3.4", Action: "intercept", SiteID: &site.ID}
	if err := db.Create(&ip).Error; err != nil {
		t.Fatalf("create ip: %v", err)
	}
	if err := db.Create(&SystemSettings{Key: "test_key", Value: "test_val"}).Error; err != nil {
		t.Fatalf("create setting: %v", err)
	}
}

func TestExportBackup(t *testing.T) {
	db := newBackupTestDB(t)
	seedBackupData(t, db)

	data, err := ExportBackup(db)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if data.Version != BackupVersion {
		t.Errorf("version = %d, want %d", data.Version, BackupVersion)
	}
	if len(data.Certificates) != 1 {
		t.Errorf("certificates = %d, want 1", len(data.Certificates))
	}
	if len(data.Sites) != 1 {
		t.Errorf("sites = %d, want 1", len(data.Sites))
	}
	if len(data.IPListEntries) != 1 {
		t.Errorf("ip entries = %d, want 1", len(data.IPListEntries))
	}
	if len(data.SystemSettings) != 1 {
		t.Errorf("settings = %d, want 1", len(data.SystemSettings))
	}
}

func TestImportBackupRoundTrip(t *testing.T) {
	src := newBackupTestDB(t)
	seedBackupData(t, src)
	data, err := ExportBackup(src)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// 导入到一个全新的空库。
	dst := newBackupTestDB(t)
	if err := ImportBackup(dst, data, false); err != nil {
		t.Fatalf("import: %v", err)
	}

	restored, err := ExportBackup(dst)
	if err != nil {
		t.Fatalf("re-export: %v", err)
	}
	if len(restored.Sites) != 1 {
		t.Fatalf("restored sites = %d, want 1", len(restored.Sites))
	}
	// 验证外键 ID 被保留。
	if restored.Sites[0].CertID == nil || data.Sites[0].CertID == nil ||
		*restored.Sites[0].CertID != *data.Sites[0].CertID {
		t.Errorf("restored site CertID mismatch")
	}
	if restored.Sites[0].ID != data.Sites[0].ID {
		t.Errorf("restored site ID = %d, want %d (original ID must be preserved)", restored.Sites[0].ID, data.Sites[0].ID)
	}
	if len(restored.IPListEntries) != 1 {
		t.Errorf("restored ip entries = %d, want 1", len(restored.IPListEntries))
	}
	if len(restored.SystemSettings) != 1 {
		t.Errorf("restored settings = %d, want 1", len(restored.SystemSettings))
	}
}

func TestImportBackupReplaceMode(t *testing.T) {
	dst := newBackupTestDB(t)
	// 目标库先放一些旧数据。
	oldCert := Certificate{Name: "old-cert"}
	if err := dst.Create(&oldCert).Error; err != nil {
		t.Fatalf("seed old cert: %v", err)
	}
	oldSite := Site{Host: "old.com", Bind: ":9999"}
	if err := dst.Create(&oldSite).Error; err != nil {
		t.Fatalf("seed old site: %v", err)
	}

	// 从另一个库导出新配置。
	src := newBackupTestDB(t)
	seedBackupData(t, src)
	data, err := ExportBackup(src)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// replaceMode 应清空旧数据后导入新数据。
	if err := ImportBackup(dst, data, true); err != nil {
		t.Fatalf("import replace: %v", err)
	}

	restored, err := ExportBackup(dst)
	if err != nil {
		t.Fatalf("re-export: %v", err)
	}
	// 旧的 old.com 应被清除，只剩 example.com。
	if len(restored.Sites) != 1 {
		t.Fatalf("sites after replace = %d, want 1", len(restored.Sites))
	}
	if restored.Sites[0].Host != "example.com" {
		t.Errorf("site host = %q, want example.com (old data must be replaced)", restored.Sites[0].Host)
	}
	if len(restored.Certificates) != 1 {
		t.Errorf("certificates after replace = %d, want 1", len(restored.Certificates))
	}
}

func TestImportBackupEmptyIsNoop(t *testing.T) {
	db := newBackupTestDB(t)
	seedBackupData(t, db)

	// 合并模式导入空备份不应删除现有数据。
	empty := &BackupData{Version: BackupVersion}
	if err := ImportBackup(db, empty, false); err != nil {
		t.Fatalf("import empty: %v", err)
	}
	data, err := ExportBackup(db)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(data.Sites) != 1 {
		t.Errorf("sites = %d, want 1 (empty merge import must not delete)", len(data.Sites))
	}
}
