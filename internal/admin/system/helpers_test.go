package system

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/iplist"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/store/threatintel"
)

/*
本文件存放切包后父包仍需的跨文件测试 helper。

这些 helper 原先分散在已迁出的组文件中：
  - assertErr / newDashboardConfigDBForTest / newDashboardLogDBForTest
    原在 dashboard_test.go（现 internal/admin/system/dashboard）与
    upstream_test.go（现 internal/admin/system/upstream）；
  - newIPListRepoForTest 原在 iplist_test.go（现 internal/admin/system/iplist）；
  - newPolicyRepoForTest / invokePolicyHandler 原在 policy_test.go
    （现 internal/admin/system/policy）；
  - newThreatIntelDBForTest / invokeThreatIntelHandler 原在 threat_intel_test.go
    （现 internal/admin/system/threatintel）；
  - invokeCertificateHandlerForTest 原在 certificate_test.go
    （现 internal/admin/system/certificate）。

父包内的 realtime_dashboard_test.go / system_readonly_test.go /
system_misc_test.go / acme_handlers_test.go / reload_defect_test.go /
js_plugin*_test.go / lua_plugin_test.go 仍引用它们，故按
internal/admin/protect 各子包的既有做法在父包保留同名副本，
函数体与原实现逐字一致。
*/

// assertErr 是固定返回 "err" 的 error 实现，用于构造上游探测失败场景。
type assertErr struct{}

func (assertErr) Error() string { return "err" }

/**
 * newIPListRepoForTest 建立仅含 IP 名单表的内存库。
 *
 * 原先定义在 iplist_test.go，该文件已随 iplist 文件组迁入
 * internal/admin/system/iplist 子包；父包的 reload_defect_test.go 仍引用它。
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

/**
 * newPolicyRepoForTest 建立仅含策略表的内存库。
 *
 * 原先定义在 policy_test.go，该文件已随 policy 文件组迁入
 * internal/admin/system/policy 子包；父包的 system_misc_test.go 与
 * system_readonly_test.go 仍引用它。
 */
func newPolicyRepoForTest(t *testing.T) *repository.PolicyRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Policy{}); err != nil {
		t.Fatalf("migrate policies: %v", err)
	}
	return repository.NewPolicyRepo(db)
}

/**
 * newThreatIntelDBForTest 建立含订阅源、IP 条目与同步日志表的内存库。
 *
 * 原先定义在 threat_intel_test.go，该文件已随 threatintel 文件组迁入
 * internal/admin/system/threatintel 子包；父包的 reload_defect_test.go 仍引用它。
 */
func newThreatIntelDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&threatintel.ThreatIntelFeed{}, &iplist.IPListEntry{}, &threatintel.ThreatIntelSyncLog{}); err != nil {
		t.Fatalf("migrate threat intel tables: %v", err)
	}
	return db
}

/**
 * invokeThreatIntelHandler 直接驱动 Hertz handler 并返回响应上下文。
 *
 * 原先定义在 threat_intel_test.go，随 threatintel 文件组迁出后，父包的
 * js_plugin / lua_plugin / reload_defect 测试仍需同名副本。
 */
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
 * invokePolicyHandler 直接驱动 Hertz handler 并返回响应上下文。
 *
 * 原先定义在 policy_test.go，随 policy 文件组迁出后，父包测试仍需同名副本。
 */
func invokePolicyHandler(t *testing.T, handler app.HandlerFunc, method, uri string, params param.Params, payload []byte) *app.RequestContext {
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

/**
 * invokeCertificateHandlerForTest 直接驱动 Hertz handler 并返回响应上下文。
 */
func invokeCertificateHandlerForTest(t *testing.T, handler app.HandlerFunc, method, uri string, params param.Params, payload []byte) *app.RequestContext {
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
