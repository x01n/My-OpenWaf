package admin

import (
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
