package presetbots

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/store/iplist"
	"My-OpenWaf/internal/store/repository"
)

/*
本文件存放本包测试共用的 helper。

invokeThreatIntelHandler 原先定义在 internal/admin/system/threat_intel_test.go，
newIPListRepoForTest 原先定义在 internal/admin/system/iplist_test.go；
两份源文件所属的文件组均已迁出，本包测试仍需这两个 helper，故按
internal/admin/protect 各子包的既有做法保留同名副本，函数体与原实现一致。
*/

// invokeThreatIntelHandler 直接驱动 Hertz handler 并返回响应上下文。
func invokeThreatIntelHandler(t *testing.T, handler app.HandlerFunc, method, uri string, params param.Params, payload []byte) *app.RequestContext {
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
	// 测试默认授予 admin 角色——认证头值遮蔽只对 non-admin 生效，
	// 单独用例通过 ctx.Set("auth_role", ...) 覆盖为 readonly/operator。
	ctx.Set("auth_role", auth.RoleAdmin)
	handler(context.Background(), ctx)
	return ctx
}

/**
 * newIPListRepoForTest 建立仅含 IP 名单表的内存库。
 */
func newIPListRepoForTest(t *testing.T) *repository.IPListRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&iplist.IPListEntry{}); err != nil {
		t.Fatalf("migrate IP list entries: %v", err)
	}
	return repository.NewIPListRepo(db)
}
