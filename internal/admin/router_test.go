package admin

import (
	"bytes"
	"context"
	"os"
	"regexp"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route"
)

func TestRegisterRoutesUsesOnlyGetAndPost(t *testing.T) {
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}

	forbidden := regexp.MustCompile(`\.(PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(`)
	if match := forbidden.Find(src); match != nil {
		t.Fatalf("admin routes must use only GET and POST, found %s", match)
	}
}

// TestLuaPluginStatsRouteBeatsIDParam 守护 /lua-plugins/stats 不被 /lua-plugins/:id 吞掉。
//
// 两条路由在路由树同一层分别是静态段与参数段。Hertz 目前静态优先，但这是路由库的
// 行为而非我们的代码——升级 Hertz 若改变优先级，statsHandler 会静默失效并让
// GetLuaPlugin 收到 id="stats" 的 400。此测试用真实路由树验证匹配结果。
func TestLuaPluginStatsRouteBeatsIDParam(t *testing.T) {
	e := route.NewEngine(config.NewOptions(nil))
	// 注册顺序照 router.go：stats 在 :id 之前。
	var hit string
	e.GET("/api/v1/lua-plugins/stats", func(_ context.Context, c *app.RequestContext) {
		hit = "stats"
	})
	e.GET("/api/v1/lua-plugins/:id", func(_ context.Context, c *app.RequestContext) {
		hit = "id=" + c.Param("id")
	})

	for _, tt := range []struct{ uri, want string }{
		{"/api/v1/lua-plugins/stats", "stats"},
		{"/api/v1/lua-plugins/7", "id=7"},
	} {
		hit = ""
		var req protocol.Request
		req.SetMethod("GET")
		req.SetRequestURI(tt.uri)
		ctx := app.NewContext(0)
		req.CopyTo(&ctx.Request)
		e.ServeHTTP(context.Background(), ctx)
		if hit != tt.want {
			t.Errorf("GET %s 命中 %q，want %q（status=%d）", tt.uri, hit, tt.want, ctx.Response.StatusCode())
		}
	}
}

// TestJSPluginRuntimeRouteBeatsIDParam 守护 runtime/stats 静态端点不被 :id 吞掉。
func TestJSPluginRuntimeRouteBeatsIDParam(t *testing.T) {
	e := route.NewEngine(config.NewOptions(nil))
	var hit string
	e.GET("/api/v1/js-plugins/stats", func(_ context.Context, c *app.RequestContext) {
		hit = "stats"
	})
	e.GET("/api/v1/js-plugins/runtime", func(_ context.Context, c *app.RequestContext) {
		hit = "runtime"
	})
	e.GET("/api/v1/js-plugins/:id", func(_ context.Context, c *app.RequestContext) {
		hit = "id=" + c.Param("id")
	})

	for _, tt := range []struct{ uri, want string }{
		{"/api/v1/js-plugins/stats", "stats"},
		{"/api/v1/js-plugins/runtime", "runtime"},
		{"/api/v1/js-plugins/7", "id=7"},
	} {
		hit = ""
		var req protocol.Request
		req.SetMethod("GET")
		req.SetRequestURI(tt.uri)
		ctx := app.NewContext(0)
		req.CopyTo(&ctx.Request)
		e.ServeHTTP(context.Background(), ctx)
		if hit != tt.want {
			t.Errorf("GET %s 命中 %q，want %q（status=%d）", tt.uri, hit, tt.want, ctx.Response.StatusCode())
		}
	}
}

// TestSecurityEventRequestsRouteBeatsIDParam 守护 /security-events/requests 不被 :id 吞掉。
//
// requests 是按 request_id 聚合的请求级列表，:id 是单条事件详情。若参数段抢先匹配，
// GetSecurityEvent 会收到 id="requests" 并返回 400 invalid id，聚合视图静默失效。
func TestSecurityEventRequestsRouteBeatsIDParam(t *testing.T) {
	e := route.NewEngine(config.NewOptions(nil))
	// 注册顺序照 router.go：stats/timeline/requests 都在 :id 之前。
	var hit string
	e.GET("/api/v1/security-events/stats", func(_ context.Context, c *app.RequestContext) {
		hit = "stats"
	})
	e.GET("/api/v1/security-events/timeline", func(_ context.Context, c *app.RequestContext) {
		hit = "timeline"
	})
	e.GET("/api/v1/security-events/requests", func(_ context.Context, c *app.RequestContext) {
		hit = "requests"
	})
	e.GET("/api/v1/security-events/:id", func(_ context.Context, c *app.RequestContext) {
		hit = "id=" + c.Param("id")
	})

	for _, tt := range []struct{ uri, want string }{
		{"/api/v1/security-events/requests", "requests"},
		{"/api/v1/security-events/stats", "stats"},
		{"/api/v1/security-events/timeline", "timeline"},
		{"/api/v1/security-events/42", "id=42"},
	} {
		hit = ""
		var req protocol.Request
		req.SetMethod("GET")
		req.SetRequestURI(tt.uri)
		ctx := app.NewContext(0)
		req.CopyTo(&ctx.Request)
		e.ServeHTTP(context.Background(), ctx)
		if hit != tt.want {
			t.Errorf("GET %s 命中 %q，want %q（status=%d）", tt.uri, hit, tt.want, ctx.Response.StatusCode())
		}
	}
}

// TestRouterRegistersSecurityEventRequestsRoute 守护聚合 handler 真的被接线。
//
// 上面的优先级测试用的是独立路由树，无法发现 router.go 漏注册。这里直接扫源码，
// 让「handler 写好了但没挂路由」这类缺口在 CI 暴露。
func TestRouterRegistersSecurityEventRequestsRoute(t *testing.T) {
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}
	if !regexp.MustCompile(`GET\("/security-events/requests",\s*event\.ListSecurityEventRequests\(`).Match(src) {
		t.Fatal("router.go 未注册 GET /security-events/requests -> event.ListSecurityEventRequests")
	}
}

// extractGroupBlock 返回 src 中 marker 行之后第一个花括号块的内部内容。
//
// marker 是各权限分组的 Use 调用签名，src 中三组该签名互不相同，
// 因此可以唯一定位 readGroup / opsGroup / adminGroup 的注册块。
// 块内可能嵌套闭包花括号（如 backup/import 的刷新回调），
// 故用深度计数找到匹配的闭合括号。
func extractGroupBlock(t *testing.T, src []byte, marker string) []byte {
	t.Helper()
	idx := bytes.Index(src, []byte(marker))
	if idx < 0 {
		t.Fatalf("router.go 缺少分组标记 %q", marker)
	}
	open := bytes.IndexByte(src[idx:], '{')
	if open < 0 {
		t.Fatalf("分组标记 %q 后缺少 '{'", marker)
	}
	start := idx + open
	depth := 0
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start+1 : i]
			}
		}
	}
	t.Fatalf("分组标记 %q 的块未闭合", marker)
	return nil
}

// TestRouterReadonlyConvergenceGroupGates 守护权限收敛后的路由分组位置。
//
// 后端 RBAC 收敛约定：
//   - 配置读端点（network/tls/cipher-suites/http2/redis/log）与证书 PEM 解析
//     必须在 readGroup，三角色可读；
//   - 对应配置写端点必须在 adminGroup（仅 admin），不允许滞留于 opsGroup 或
//     意外降级；
//   - /certificates/parse 不得同时残留在 opsGroup。
//
// 采用与 TestRouterRegistersSecurityEventRequestsRoute 相同的源码扫描策略：
// 按分组标记切出三个注册块后做包含/排除断言，出现分组错位时 CI 立即可见。
func TestRouterReadonlyConvergenceGroupGates(t *testing.T) {
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}

	readBlock := extractGroupBlock(t, src, `readGroup.Use(RequireRole(auth.RoleAdmin, auth.RoleOperator, auth.RoleReadonly))`)
	opsBlock := extractGroupBlock(t, src, `opsGroup.Use(RequireRole(auth.RoleAdmin, auth.RoleOperator))`)
	adminBlock := extractGroupBlock(t, src, `adminGroup.Use(RequireRole(auth.RoleAdmin))`)

	// 配置读端点与证书解析位于 readGroup。
	for _, line := range []string{
		`readGroup.GET("/network-config", system.GetNetworkConfig(r.SystemSettings))`,
		`readGroup.GET("/tls-config", system.GetTLSDefaultConfig(r.SystemSettings))`,
		`readGroup.GET("/tls-cipher-suites", system.ListCipherSuites())`,
		`readGroup.GET("/http2-config", system.GetHTTP2Config(r.SystemSettings))`,
		`readGroup.GET("/redis-config", system.GetRedisConfig(r.SystemSettings, false))`,
		`readGroup.GET("/log-config", system.GetLogConfig(r.SystemSettings))`,
		`readGroup.POST("/certificates/parse", system.ParseCertificate(r.Site))`,
	} {
		if !bytes.Contains(readBlock, []byte(line)) {
			t.Errorf("readGroup 缺少注册: %s", line)
		}
	}

	// opsGroup 不得残留 parse（应已收敛到 readGroup）。
	if bytes.Contains(opsBlock, []byte(`/certificates/parse`)) {
		t.Error("opsGroup 残留 /certificates/parse 注册，应已移至 readGroup")
	}

	// 配置写端点仍在 adminGroup，且 adminGroup 不得残留对应读端点。
	for _, line := range []string{
		`adminGroup.POST("/network-config", system.UpdateNetworkConfig(r.SystemSettings, reload))`,
		`adminGroup.POST("/http2-config", system.UpdateHTTP2Config(r.SystemSettings, reload))`,
		`adminGroup.POST("/redis-config", system.UpdateRedisConfig(r.SystemSettings, deps.ReloadRedis))`,
		`adminGroup.POST("/log-config", system.UpdateLogConfig(r.SystemSettings))`,
		`adminGroup.POST("/tls-config", system.UpdateTLSDefaultConfig(r.SystemSettings, reload))`,
	} {
		if !bytes.Contains(adminBlock, []byte(line)) {
			t.Errorf("adminGroup 缺少注册: %s", line)
		}
	}
	for _, residue := range []string{
		`GET("/network-config"`,
		`GET("/tls-config"`,
		`GET("/tls-cipher-suites"`,
		`GET("/http2-config"`,
		`GET("/redis-config"`,
		`GET("/log-config"`,
		`POST("/certificates/parse"`,
	} {
		if bytes.Contains(adminBlock, []byte(residue)) {
			t.Errorf("adminGroup 残留只读路由 %s，应已移至 readGroup", residue)
		}
	}
}
