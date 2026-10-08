package iplist

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/admin/auth"
)

/*
本文件存放本包测试共用的请求驱动 helper。

invokeThreatIntelHandler 原先定义在 internal/admin/system/threat_intel_test.go；
本包测试整体迁出后需要同名的本地副本，故按 internal/admin/protect 各子包的
既有做法保留一份定义，函数体与该 helper 原实现一致。
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
