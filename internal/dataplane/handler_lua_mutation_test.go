package dataplane

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/luaplugin"
)

// newLuaMutationHandler 构造只挂 Lua 插件、上游为一个 httptest 服务的数据面。
//
// 与 handler_test.go 的 Lua 用例同构：OWASP/CVE/bot 关闭，观察点收窄到
// 「脚本改写是否到达上游」与「响应改写是否到达客户端」。
func newLuaMutationHandler(t *testing.T, upstreamURL string, scripts []*luaplugin.Script) app.HandlerFunc {
	t.Helper()
	protection := store.DefaultProtectionConfig()
	protection.OWASPEnabled = false
	protection.CVEEnabled = false
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site:                store.Site{ID: 1, Host: "lua-mutation.example.test", Bind: ":80"},
		Bind:                ":80",
		UpstreamURLs:        []string{upstreamURL},
		EffectiveProtection: &protection,
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", rt.Site.Host): &rt,
		},
	})
	luaEngine := luaplugin.NewEngine(handlerLuaKV{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	luaEngine.Reload(scripts)
	wafEngine := engine.New(holder, nil, nil, nil)
	wafEngine.SetLuaPlugins(luaEngine)
	return Handler(Options{
		Holder: holder,
		Engine: wafEngine,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Bind:   ":80",
	})
}

// TestHandlerLuaPreRewritesUpstreamRequest 锁定 pre 阶段请求改写的端到端效果：
// 脚本改的方法、路径、查询、请求头与请求体全部到达上游。
func TestHandlerLuaPreRewritesUpstreamRequest(t *testing.T) {
	type captured struct {
		method  string
		path    string
		query   string
		body    string
		headers http.Header
	}
	var seen atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		seen.Store(captured{method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, body: string(raw), headers: r.Header.Clone()})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	script, err := luaplugin.Compile("lua-rewrite", luaplugin.StagePre, `
function handle(ctx)
  return {
    request = {
      method = "POST",
      path = "/internal/rewritten",
      query = "debug=1",
      body = "rewritten-body",
      headers = { ["X-Internal"] = "1" },
      delete_headers = { "X-Remove" }
    }
  }
end`)
	if err != nil {
		t.Fatalf("compile Lua plugin: %v", err)
	}
	script.SetID(101)
	handler := newLuaMutationHandler(t, upstream.URL, []*luaplugin.Script{script})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/original?keep=1")
	ctx.Request.Header.SetHost("lua-mutation.example.test")
	ctx.Request.Header.Set("X-Remove", "gone")
	ctx.Request.Header.Set("X-Keep", "kept")
	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", got, ctx.Response.Body())
	}
	got, _ := seen.Load().(captured)
	if got.method != "POST" {
		t.Fatalf("upstream method = %q, want POST", got.method)
	}
	if got.path != "/internal/rewritten" {
		t.Fatalf("upstream path = %q, want /internal/rewritten", got.path)
	}
	if got.query != "debug=1" {
		t.Fatalf("upstream query = %q, want debug=1", got.query)
	}
	if got.body != "rewritten-body" {
		t.Fatalf("upstream body = %q, want rewritten-body", got.body)
	}
	if value := got.headers.Get("X-Internal"); value != "1" {
		t.Fatalf("upstream X-Internal = %q, want 1", value)
	}
	if value := got.headers.Get("X-Remove"); value != "" {
		t.Fatalf("upstream X-Remove = %q, want deleted", value)
	}
	if value := got.headers.Get("X-Keep"); value != "kept" {
		t.Fatalf("upstream X-Keep = %q, want kept", value)
	}
}

// TestHandlerLuaPostRewritesUpstreamResponse 锁定 post 阶段响应改写的端到端
// 效果：客户端拿到的是脚本改写后的状态码、响应体与响应头。
func TestHandlerLuaPostRewritesUpstreamResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Header", "1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-body"))
	}))
	defer upstream.Close()

	script, err := luaplugin.Compile("lua-response", luaplugin.StagePost, `
function handle(ctx)
  return {
    response = {
      status_code = 503,
      body = "maintenance",
      headers = { ["X-Served-By"] = "waf" },
      delete_headers = { "X-Upstream-Header" }
    }
  }
end`)
	if err != nil {
		t.Fatalf("compile Lua plugin: %v", err)
	}
	script.SetID(102)
	handler := newLuaMutationHandler(t, upstream.URL, []*luaplugin.Script{script})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/api")
	ctx.Request.Header.SetHost("lua-mutation.example.test")
	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", got, ctx.Response.Body())
	}
	if got := string(ctx.Response.Body()); got != "maintenance" {
		t.Fatalf("body = %q, want maintenance", got)
	}
	if got := string(ctx.Response.Header.Peek("X-Served-By")); got != "waf" {
		t.Fatalf("X-Served-By = %q, want waf", got)
	}
	if got := string(ctx.Response.Header.Peek("X-Upstream-Header")); got != "" {
		t.Fatalf("X-Upstream-Header = %q, want deleted", got)
	}
}

// TestHandlerLuaPreRewriteKeepsVerdictShortCircuit 确认改写不会让判定失效：
// 同一脚本既改写又拦截时，请求仍被拦下。
func TestHandlerLuaPreRewriteKeepsVerdictShortCircuit(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	script, err := luaplugin.Compile("lua-rewrite-block", luaplugin.StagePre, `
function handle(ctx)
  return {action = "intercept", request = {path = "/blocked"}}
end`)
	if err != nil {
		t.Fatalf("compile Lua plugin: %v", err)
	}
	script.SetID(103)
	handler := newLuaMutationHandler(t, upstream.URL, []*luaplugin.Script{script})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/original")
	ctx.Request.Header.SetHost("lua-mutation.example.test")
	handler(context.Background(), ctx)

	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got)
	}
}

// TestHandlerLuaPreInvalidRewriteStillProxies 锁定 fail-safe：非法改写（绝对
// URL）被放弃，请求仍按原样代理，站点不会因为脚本笔误不可用。
func TestHandlerLuaPreInvalidRewriteStillProxies(t *testing.T) {
	var upstreamPath atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath.Store(r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	script, err := luaplugin.Compile("lua-bad-rewrite", luaplugin.StagePre, `
function handle(ctx)
  return {request = {path = "//evil.example/x"}}
end`)
	if err != nil {
		t.Fatalf("compile Lua plugin: %v", err)
	}
	script.SetID(104)
	handler := newLuaMutationHandler(t, upstream.URL, []*luaplugin.Script{script})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/original")
	ctx.Request.Header.SetHost("lua-mutation.example.test")
	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
	if got, _ := upstreamPath.Load().(string); got != "/original" {
		t.Fatalf("upstream path = %q, want /original (rewrite rejected)", got)
	}
	if !strings.Contains(string(ctx.Response.Body()), "upstream-ok") {
		t.Fatalf("body = %q", ctx.Response.Body())
	}
}
