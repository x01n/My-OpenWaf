package realtime

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

/*
本文件存放本包测试共用的内存库 helper。

newDashboardConfigDBForTest / newDashboardLogDBForTest 原先定义在
internal/admin/system/dashboard_test.go；dashboard 文件组与本组同时迁出，
本包测试仍需要它们，故按 internal/admin/protect 各子包的既有做法保留同名副本，
函数体与原实现一致。
*/

/**
 * newDashboardConfigDBForTest 建立仅含系统设置与配置版本表的内存库。
 */
func newDashboardConfigDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}, &store.ConfigRevision{}); err != nil {
		t.Fatalf("migrate config db: %v", err)
	}
	return db
}

/**
 * newDashboardLogDBForTest 建立完成日志表迁移的内存库。
 */
func newDashboardLogDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	return db
}
