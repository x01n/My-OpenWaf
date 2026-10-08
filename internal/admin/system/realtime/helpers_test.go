package realtime

import (
	"context"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
)

/*
本文件存放本包测试共用的请求驱动 helper。

invokeRealtimeHandler 与 internal/admin/system/network_test.go 的
invokeSystemConfigHandler 行为一致，仅为本包保留一份副本。
*/

// invokeRealtimeHandler 直接驱动 Hertz handler 并返回响应上下文。
func invokeRealtimeHandler(t *testing.T, handler app.HandlerFunc, method, uri string, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}
