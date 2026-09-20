package site

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// errTestReload 是各用例中模拟 reload 失败时统一返回的错误。
var errTestReload = errors.New("reload boom")

// errTestWrite 是各用例中模拟写库失败时统一返回的错误。
var errTestWrite = errors.New("write boom")

/**
 * requireErrorMessage 断言响应体是 {"error": "..."} 形式且消息完全匹配。
 *
 * @param body 处理器写入的原始响应体
 * @param want 期望的 error 字段值
 */
func requireErrorMessage(t *testing.T, body []byte, want string) {
	t.Helper()
	var resp map[string]string
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode error response: %v (body=%s)", err, body)
	}
	if resp["error"] != want {
		t.Fatalf("error = %q, want %q", resp["error"], want)
	}
}

// newSiteRepoWithDB 与 newSiteRepoForTest 等价，但同时返回底层 DB 以便注入写失败回调。
func newSiteRepoWithDB(t *testing.T) (*repository.SiteRepo, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}); err != nil {
		t.Fatalf("migrate sites: %v", err)
	}
	return repository.NewSiteRepo(db), db
}

// newSiteAndListenerReposWithDB 迁移站点与监听器表，并返回底层 DB。
func newSiteAndListenerReposWithDB(t *testing.T) (*repository.SiteRepo, *repository.SiteListenerRepo, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.SiteListener{}); err != nil {
		t.Fatalf("migrate site listener tables: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewSiteListenerRepo(db), db
}

/**
 * failSubsequentUpdates 在 GORM 的 update 回调链最前端注入一个必定失败的回调，
 * 用于覆盖 handler 中「读取成功但写库失败」的 500 分支。
 * 必须在种子数据写入完成之后调用，否则种子数据也会失败。
 */
func failSubsequentUpdates(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Callback().Update().Before("gorm:update").Register("test:fail_update", func(tx *gorm.DB) {
		_ = tx.AddError(errTestWrite)
	}); err != nil {
		t.Fatalf("register update failure callback: %v", err)
	}
}

// failSubsequentDeletes 与 failSubsequentUpdates 同理，作用于 delete 回调链。
func failSubsequentDeletes(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Callback().Delete().Before("gorm:delete").Register("test:fail_delete", func(tx *gorm.DB) {
		_ = tx.AddError(errTestWrite)
	}); err != nil {
		t.Fatalf("register delete failure callback: %v", err)
	}
}
