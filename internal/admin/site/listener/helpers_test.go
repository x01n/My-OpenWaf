package listener

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// errTestReload 是各用例中模拟 reload 失败时统一返回的错误。
var errTestWrite = errors.New("write boom")
var errTestReload = errors.New("reload boom")

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

func newSiteAndListenerReposForTest(t *testing.T) (*repository.SiteRepo, *repository.SiteListenerRepo) {
	siteRepo, listenerRepo, _ := newSiteAndListenerReposWithDBForTest(t)
	return siteRepo, listenerRepo
}

func newSiteAndListenerReposWithDBForTest(t *testing.T) (*repository.SiteRepo, *repository.SiteListenerRepo, *gorm.DB) {
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

func newSiteListenerCertReposForTest(t *testing.T) (*repository.SiteRepo, *repository.SiteListenerRepo, *repository.CertificateRepo) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.SiteListener{}, &store.Certificate{}); err != nil {
		t.Fatalf("migrate listener tables: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewSiteListenerRepo(db), repository.NewCertificateRepo(db)
}

func invokeCreateSiteListenerHandler(t *testing.T, handler app.HandlerFunc, siteID uint, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/1/listeners")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: strconv.FormatUint(uint64(siteID), 10)}}
	handler(context.Background(), ctx)
	return ctx
}

func invokeUpdateSiteListenerHandler(t *testing.T, handler app.HandlerFunc, siteID uint, listenerID uint, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/1/listeners/1/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{
		{Key: "id", Value: strconv.FormatUint(uint64(siteID), 10)},
		{Key: "lid", Value: strconv.FormatUint(uint64(listenerID), 10)},
	}
	handler(context.Background(), ctx)
	return ctx
}

func uintPtr(v uint) *uint {
	return &v
}

func invokeSiteRouteHandler(t *testing.T, handler app.HandlerFunc, method, uri string, params param.Params, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = params
	handler(context.Background(), ctx)
	return ctx
}

func idParams(id string) param.Params {
	return param.Params{{Key: "id", Value: id}}
}

func newSiteReposWithoutListenerTable(t *testing.T) (*repository.SiteRepo, *repository.SiteListenerRepo) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}); err != nil {
		t.Fatalf("migrate sites: %v", err)
	}
	return repository.NewSiteRepo(db), repository.NewSiteListenerRepo(db)
}

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

func failSubsequentUpdates(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Callback().Update().Before("gorm:update").Register("test:fail_update", func(tx *gorm.DB) {
		_ = tx.AddError(errTestWrite)
	}); err != nil {
		t.Fatalf("register update failure callback: %v", err)
	}
}

func failSubsequentDeletes(t *testing.T, db *gorm.DB) {
	t.Helper()
	if err := db.Callback().Delete().Before("gorm:delete").Register("test:fail_delete", func(tx *gorm.DB) {
		_ = tx.AddError(errTestWrite)
	}); err != nil {
		t.Fatalf("register delete failure callback: %v", err)
	}
}
