//go:build cgo && quickjs

package proxy

import (
	"net"
	"net/http"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

// buildResponsePlugin 编译一段带指定失败模式的 response 阶段脚本并创建引擎。
func buildResponsePlugin(t *testing.T, source string, failureMode string) (*jsplugin.Script, *jsplugin.Engine) {
	t.Helper()
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	script, err := jsplugin.CompileWithMetadata(
		"response-test",
		source,
		jsplugin.ScriptOptions{},
		jsplugin.ScriptMetadata{
			ID:          1,
			Stage:       store.JSStageResponse,
			Priority:    10,
			FailureMode: failureMode,
		},
	)
	if err != nil {
		t.Fatalf("compile response script: %v", err)
	}
	return script, engine
}

func newResponseRequestContext() *app.RequestContext {
	c := &app.RequestContext{}
	c.Request.SetMethod("GET")
	c.Request.SetRequestURI("/page?first=1")
	c.Response.Header.Set("X-Request-ID", "req-1")
	return c
}

// TestJSPluginResponseTransformerExecutesPlan 通过真实 QuickJS 执行验证
// status/body/头变更三条路径由代理层 transform 消费。
func TestJSPluginResponseTransformerExecutesPlan(t *testing.T) {
	script, engine := buildResponsePlugin(t, `export default {
		fetch(response) {
			return {
				status: 201,
				body: "mutated:" + response.body,
				set_headers: {"X-JS-Response": "yes"},
				delete_headers: ["X-Upstream"]
			};
		}
	}`, store.JSFailureModeOpen)
	transformer := &jsPluginResponseTransformer{
		siteID:   7,
		scripts:  []*jsplugin.Script{script},
		executor: engine,
	}
	c := newResponseRequestContext()
	c.Response.Header.Set("X-Upstream", "remove-me")
	c.Response.SetStatusCode(http.StatusOK)

	transformed, err := transformer.Transform(identityResponseEntity{
		Path:        "/page",
		ContentType: "text/html",
		Body:        []byte("hello"),
		Request:     c,
		ClientIP:    net.ParseIP("192.0.2.10"),
	})
	if err != nil {
		t.Fatalf("Transform error = %v", err)
	}
	if string(transformed.Body) != "mutated:hello" {
		t.Fatalf("transformed body = %q, want mutated:hello", transformed.Body)
	}
	if got := c.Response.StatusCode(); got != http.StatusCreated {
		t.Fatalf("status code = %d, want 201", got)
	}
	if got := string(c.Response.Header.Peek("X-JS-Response")); got != "yes" {
		t.Fatalf("X-JS-Response = %q, want yes", got)
	}
	if got := string(c.Response.Header.Peek("X-Upstream")); got != "" {
		t.Fatalf("X-Upstream = %q, want deleted", got)
	}
}

// TestJSPluginResponseTransformerSnapshotContract 固定响应脚本接收的快照
// 字段（path/method/raw_query/client_ip/请求头/响应头/status）。
func TestJSPluginResponseTransformerSnapshotContract(t *testing.T) {
	script, engine := buildResponsePlugin(t, `export default {
		fetch(response) {
			if (response.path !== "/page" || response.method !== "GET" ||
				response.raw_query !== "first=1" || response.client_ip !== "192.0.2.10" ||
				response.request_headers["x-client"] !== "c" ||
				response.headers["x-upstream"] !== "u" || response.status !== 200 ||
				response.request_id !== "req-1" || response.site_id !== 7) {
				throw new Error("response snapshot contract mismatch");
			}
			return {set_headers: {"X-Contract": "ok"}};
		}
	}`, store.JSFailureModeOpen)
	transformer := &jsPluginResponseTransformer{
		siteID:   7,
		scripts:  []*jsplugin.Script{script},
		executor: engine,
	}
	c := newResponseRequestContext()
	c.Request.Header.Set("X-Client", "c")
	c.Response.Header.Set("X-Upstream", "u")
	c.Response.SetStatusCode(http.StatusOK)

	if _, err := transformer.Transform(identityResponseEntity{
		Path:        "/page",
		ContentType: "text/html",
		Body:        []byte("ok"),
		Request:     c,
		ClientIP:    net.ParseIP("192.0.2.10"),
	}); err != nil {
		t.Fatalf("Transform error = %v", err)
	}
	if got := string(c.Response.Header.Peek("X-Contract")); got != "ok" {
		t.Fatalf("X-Contract = %q, want ok", got)
	}
}

// TestJSPluginResponseTransformerFailureModes 固定失败语义：fail-open 跳过
// 该脚本继续，fail-closed 向上抛错（对 buffered 路径即上游错误处理）。
func TestJSPluginResponseTransformerFailureModes(t *testing.T) {
	entity := identityResponseEntity{Path: "/page", Body: []byte("keep"), ClientIP: net.ParseIP("192.0.2.10")}

	failOpenScript, failOpenEngine := buildResponsePlugin(t, `export default {
		fetch() { throw new Error("response boom"); }
	}`, store.JSFailureModeOpen)
	openTransformer := &jsPluginResponseTransformer{
		siteID:   7,
		scripts:  []*jsplugin.Script{failOpenScript},
		executor: failOpenEngine,
	}
	transformed, err := openTransformer.Transform(entity)
	if err != nil {
		t.Fatalf("fail-open Transform error = %v", err)
	}
	if string(transformed.Body) != "keep" {
		t.Fatalf("fail-open body = %q, want keep", transformed.Body)
	}

	failClosedScript, failClosedEngine := buildResponsePlugin(t, `export default {
		fetch() { throw new Error("response boom"); }
	}`, store.JSFailureModeClosed)
	closedTransformer := &jsPluginResponseTransformer{
		siteID:   7,
		scripts:  []*jsplugin.Script{failClosedScript},
		executor: failClosedEngine,
	}
	if _, err := closedTransformer.Transform(entity); err == nil {
		t.Fatal("fail-closed Transform error = nil, want error")
	}
}

// TestJSPluginResponseTransformerRejectsInvalidPlan 固定宿主应用前校验：
// 脚本返回非法状态码时 fail-closed 报错且不改变响应状态。
func TestJSPluginResponseTransformerRejectsInvalidPlan(t *testing.T) {
	c := newResponseRequestContext()
	c.Response.SetStatusCode(http.StatusOK)
	entity := identityResponseEntity{Path: "/page", Body: []byte("keep"), ClientIP: net.ParseIP("192.0.2.10")}
	invalidStatusScript, invalidEngine := buildResponsePlugin(t, `export default {
		fetch() { return {status: 99}; }
	}`, store.JSFailureModeClosed)
	transformer := &jsPluginResponseTransformer{
		siteID:   7,
		scripts:  []*jsplugin.Script{invalidStatusScript},
		executor: invalidEngine,
	}
	if _, err := transformer.Transform(entity); err == nil {
		t.Fatal("invalid status Transform error = nil, want error")
	}
	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("invalid plan changed status = %d, want untouched 200", got)
	}
}
