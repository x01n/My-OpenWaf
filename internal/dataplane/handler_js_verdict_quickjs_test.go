//go:build cgo && quickjs

package dataplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

// TestHandlerJSRequestStageVerdictShortCircuitsUpstream 锁定请求阶段裁决
// 语义：脚本给出 action 后请求不再走上游，响应码与内容按脚本要求渲染。
func TestHandlerJSRequestStageVerdictShortCircuitsUpstream(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	script := compileRequestScript(t, "verdict-script", `export default {
		fetch(request) {
			if (request.path === "/deny") {
				return {
					action: "intercept",
					status_code: 418,
					response_body: "<html>script blocked</html>",
					set_headers: {"X-Script-Verdict": "deny"},
					message: "script denied the request",
					tags: ["script", "deny"]
				};
			}
			return null;
		}
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 31, Stage: store.JSStageRequest, Priority: 1, FailureMode: store.JSFailureModeOpen,
	})
	handler := newJSHandler(t, upstream.URL, nil, []*jsplugin.Script{script})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/deny")
	ctx.Request.Header.SetHost("js.example.com")
	handler(context.Background(), ctx)

	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0 (verdict must not proxy)", got)
	}
	if got := ctx.Response.StatusCode(); got != 418 {
		t.Fatalf("status = %d, want 418", got)
	}
	if body := string(ctx.Response.Body()); !strings.Contains(body, "script blocked") {
		t.Fatalf("body = %q, want script response body", body)
	}
	if got := string(ctx.Response.Header.Peek("X-Script-Verdict")); got != "deny" {
		t.Fatalf("X-Script-Verdict = %q, want deny", got)
	}
}

// TestHandlerJSRequestStageWithoutVerdictProxies 确认没有裁决时脚本仍然只改
// 请求并继续走上游，既有语义不变。
func TestHandlerJSRequestStageWithoutVerdictProxies(t *testing.T) {
	var upstreamPath atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath.Store(r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	script := compileRequestScript(t, "rewrite-script", `export default {
		fetch(request) {
			return {path: request.path + "-rewritten", set_headers: {"X-Rewritten": "1"}};
		}
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 32, Stage: store.JSStageRequest, Priority: 1, FailureMode: store.JSFailureModeOpen,
	})
	handler := newJSHandler(t, upstream.URL, nil, []*jsplugin.Script{script})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/plain")
	ctx.Request.Header.SetHost("js.example.com")
	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
	if got, _ := upstreamPath.Load().(string); got != "/plain-rewritten" {
		t.Fatalf("upstream path = %q, want /plain-rewritten", got)
	}
}

// TestHandlerJSRequestStageRejectsUnknownAction 锁定「拼错的动作必须可见」：
// 未知动作会让计划校验失败，fail-open 脚本被跳过而不是静默按放行处理。
func TestHandlerJSRequestStageRejectsUnknownAction(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	script := compileRequestScript(t, "typo-script", `export default {
		fetch() { return {action: "blcok"}; }
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 33, Stage: store.JSStageRequest, Priority: 1, FailureMode: store.JSFailureModeOpen,
	})
	handler := newJSHandler(t, upstream.URL, nil, []*jsplugin.Script{script})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/typo")
	ctx.Request.Header.SetHost("js.example.com")
	handler(context.Background(), ctx)

	// fail-open：请求照常放行，但失败被记录，用户能在管理端看到拼错的动作。
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 (fail-open continues)", got)
	}
	fault := script.LastFault()
	if fault == nil || !strings.Contains(fault.Message, "blcok") {
		t.Fatalf("fault = %#v, want recorded unknown action error", fault)
	}
}

// TestHandlerJSRequestStageRedirectVerdict 锁定 redirect 裁决走数据面既有
// 重定向分支，且目标来自脚本。
func TestHandlerJSRequestStageRedirectVerdict(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	script := compileRequestScript(t, "redirect-script", `export default {
		fetch() { return {action: "redirect", redirect_to: "/maintenance", status_code: 307}; }
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 34, Stage: store.JSStageRequest, Priority: 1, FailureMode: store.JSFailureModeOpen,
	})
	handler := newJSHandler(t, upstream.URL, nil, []*jsplugin.Script{script})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/redirect-me")
	ctx.Request.Header.SetHost("js.example.com")
	handler(context.Background(), ctx)

	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}
	if got := ctx.Response.StatusCode(); got != 307 {
		t.Fatalf("status = %d, want 307", got)
	}
	if got := string(ctx.Response.Header.Peek("Location")); got != "/maintenance" {
		t.Fatalf("Location = %q, want /maintenance", got)
	}
}

// TestHandlerJSRequestStageVerdictBeatsBuiltin 锁定裁决优先于内置管道：
// 脚本的放行/拦截决定不会被内置检测覆盖。
func TestHandlerJSRequestStageVerdictBeatsBuiltin(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	script := compileRequestScript(t, "intercept-script", `export default {
		fetch() { return {action: "intercept", response_body: "blocked-by-script"}; }
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 35, Stage: store.JSStageRequest, Priority: 1, FailureMode: store.JSFailureModeOpen,
	})
	handler := newJSHandler(t, upstream.URL, nil, []*jsplugin.Script{script})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/any")
	ctx.Request.Header.SetHost("js.example.com")
	handler(context.Background(), ctx)

	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("upstream calls = %d, want 0", got)
	}
	if body := string(ctx.Response.Body()); !strings.Contains(body, "blocked-by-script") {
		t.Fatalf("body = %q, want script response body", body)
	}
}
