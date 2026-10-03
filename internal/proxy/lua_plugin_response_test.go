package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
)

// TestTransformLuaResponseRewritesAppliesStatusBodyHeaders 锁定 Lua post 响应
// 改写的应用语义：状态码、响应体与响应头增删都在链上生效。
func TestTransformLuaResponseRewritesAppliesStatusBodyHeaders(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Response.SetStatusCode(http.StatusOK)
	ctx.Response.Header.Set("X-Upstream", "1")

	body := "maintenance"
	entity := identityResponseEntity{Body: []byte("upstream body")}
	rewritten := transformLuaResponseRewritesForTest(ctx, []LuaResponseRewrite{{
		StatusCode:    http.StatusServiceUnavailable,
		Body:          &body,
		SetHeaders:    map[string]string{"X-Served-By": "waf"},
		DeleteHeaders: []string{"X-Upstream"},
	}}, entity)

	if got := ctx.Response.StatusCode(); got != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", got)
	}
	if string(rewritten.Body) != "maintenance" {
		t.Fatalf("body = %q, want maintenance", rewritten.Body)
	}
	if got := string(ctx.Response.Header.Peek("X-Served-By")); got != "waf" {
		t.Fatalf("X-Served-By = %q, want waf", got)
	}
	if got := string(ctx.Response.Header.Peek("X-Upstream")); got != "" {
		t.Fatalf("X-Upstream = %q, want deleted", got)
	}
}

// TestTransformLuaResponseRewritesSkipsInvalidEntries 锁定 fail-safe：非法
// 改写条目被跳过，合法条目照常生效，上游正常响应不会因为脚本笔误变成错误页。
func TestTransformLuaResponseRewritesSkipsInvalidEntries(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Response.SetStatusCode(http.StatusOK)
	body := "kept"
	rewritten := transformLuaResponseRewritesForTest(ctx, []LuaResponseRewrite{
		{StatusCode: 42, Body: &body},
		{SetHeaders: map[string]string{"Bad Header": "v"}},
		{Body: &body, SetHeaders: map[string]string{"X-Ok": "1"}},
	}, identityResponseEntity{Body: []byte("upstream")})

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want 200 unchanged", got)
	}
	if string(rewritten.Body) != "kept" {
		t.Fatalf("body = %q, want kept", rewritten.Body)
	}
	if got := string(ctx.Response.Header.Peek("X-Ok")); got != "1" {
		t.Fatalf("X-Ok = %q, want 1", got)
	}
}

// TestTransformLuaResponseRewritesKeepsBodyWhenNil 确认 Body 为 nil 时不改响应体。
func TestTransformLuaResponseRewritesKeepsBodyWhenNil(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Response.SetStatusCode(http.StatusOK)
	rewritten := transformLuaResponseRewritesForTest(ctx, []LuaResponseRewrite{
		{StatusCode: http.StatusTeapot},
	}, identityResponseEntity{Body: []byte("upstream")})
	if string(rewritten.Body) != "upstream" {
		t.Fatalf("body = %q, want upstream", rewritten.Body)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", got)
	}
}

// transformLuaResponseRewritesForTest 用给定的改写集合驱动生产路径。
//
// 生产路径的改写来自请求上下文查找函数；测试直接注入同形状的切片，避免为
// 一个纯函数造整条数据面。
func transformLuaResponseRewritesForTest(c *app.RequestContext, rewrites []LuaResponseRewrite, entity identityResponseEntity) identityResponseEntity {
	previous := luaResponseRewriteLookup
	luaResponseRewriteLookup = func(*app.RequestContext, uint) []LuaResponseRewrite { return rewrites }
	defer func() { luaResponseRewriteLookup = previous }()
	return transformLuaResponseRewrites(c, 1, entity)
}

// TestLuaResponseRewriteLookupAbsentIsNoop 确认未注入查找函数时链上不做任何事。
func TestLuaResponseRewriteLookupAbsentIsNoop(t *testing.T) {
	previous := luaResponseRewriteLookup
	luaResponseRewriteLookup = nil
	defer func() { luaResponseRewriteLookup = previous }()

	ctx := app.NewContext(0)
	ctx.Response.SetStatusCode(http.StatusOK)
	entity := identityResponseEntity{Body: []byte("upstream")}
	got := transformLuaResponseRewrites(ctx, 1, entity)
	if string(got.Body) != "upstream" || ctx.Response.StatusCode() != http.StatusOK {
		t.Fatalf("noop rewrite changed entity: body=%q status=%d", got.Body, ctx.Response.StatusCode())
	}
	_ = context.Background()
}
