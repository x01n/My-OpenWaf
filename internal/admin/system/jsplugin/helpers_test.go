package jsplugin

import (
	"context"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/admin/auth"
)

/*
本文件存放本包测试共用的 helper。

invokeThreatIntelHandler 原先定义在 internal/admin/system/threat_intel_test.go，
idParam 原先定义在 internal/admin/system/lua_plugin_test.go；两份源文件所属的
文件组均已迁出，本包测试仍需这两个 helper，故按 internal/admin/protect
各子包的既有做法保留同名副本，函数体与原实现逐字一致。
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
 * idParam 构造 :id 路由参数。
 */
func idParam(id uint) param.Params {
	return param.Params{{Key: "id", Value: strconv.FormatUint(uint64(id), 10)}}
}
