//go:build cgo && quickjs

package dataplane

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

func TestExecuteJSRequestStageAppliesScriptsSequentially(t *testing.T) {
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	first := compileRequestScript(t, "first", `export default {
		fetch(request) {
			return {
				method: "POST",
				path: request.path + "/first",
				raw_query: "phase=one",
				body: request.body + "-one",
				set_headers: {"X-First": "yes"},
				delete_headers: ["X-Delete"]
			};
		}
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 1, Stage: store.JSStageRequest, Priority: 10, FailureMode: store.JSFailureModeOpen,
	})
	second := compileRequestScript(t, "second", `export default {
		fetch(request) {
			if (request.method !== "POST" || request.path !== "/start/first" ||
				request.raw_query !== "phase=one" || request.body !== "body-one" ||
				request.headers["x-first"] !== "yes" || request.headers["x-delete"] !== undefined ||
				request.query_params.phase !== "one") {
				throw new Error("prior mutation missing");
			}
			return {
				path: request.path + "/second",
				raw_query: "phase=two",
				body: request.body + "-two",
				set_headers: {"X-Second": request.headers["x-first"]}
			};
		}
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 2, Stage: store.JSStageRequest, Priority: 20, FailureMode: store.JSFailureModeClosed,
	})
	siteID := uint(99)
	nonMatchingSite := compileRequestScript(t, "other-site", `export default {
		fetch() { return {path: "/wrong-site"}; }
	}`, jsplugin.ScriptOptions{SiteIDs: []uint{siteID}}, jsplugin.ScriptMetadata{
		ID: 3, Stage: store.JSStageRequest, Priority: 30, FailureMode: store.JSFailureModeClosed, SiteID: &siteID,
	})
	responseStage := compileRequestScript(t, "response", `export default {
		fetch() { return {path: "/wrong-stage"}; }
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 4, Stage: store.JSStageResponse, Priority: 40, FailureMode: store.JSFailureModeClosed,
	})

	c := &app.RequestContext{}
	c.Request.SetMethod("GET")
	c.Request.SetRequestURI("/start?phase=zero")
	c.Request.Header.Set("X-Delete", "remove")
	c.Request.SetBodyString("body")
	reqCtx := &pipeline.RequestCtx{
		RequestID:        "request-1",
		SiteID:           7,
		Method:           "GET",
		Path:             "/start",
		RawQuery:         "phase=zero",
		Body:             []byte("body"),
		Headers:          map[string]string{"x-delete": "remove"},
		HeadersLowercase: true,
		QueryParams:      map[string]string{"phase": "zero"},
		QueryValues:      map[string][]string{"phase": {"zero"}},
	}

	state, failed, err := executeJSRequestStage(
		context.Background(), c, reqCtx,
		[]*jsplugin.Script{first, second, nonMatchingSite, responseStage},
		engine,
	)
	if err != nil {
		t.Fatalf("executeJSRequestStage() error = %v, failed = %v", err, failed)
	}
	if failed != nil {
		t.Fatalf("executeJSRequestStage() failed script = %q", failed.Name())
	}
	if state.method != "POST" || state.path != "/start/first/second" ||
		state.rawQuery != "phase=two" || state.body != "body-one-two" {
		t.Fatalf("state = %#v", state)
	}
	if got := string(c.Request.Header.Peek("X-First")); got != "yes" {
		t.Fatalf("X-First = %q", got)
	}
	if got := string(c.Request.Header.Peek("X-Second")); got != "yes" {
		t.Fatalf("X-Second = %q", got)
	}
	if got := string(c.Request.Header.Peek("X-Delete")); got != "" {
		t.Fatalf("X-Delete = %q", got)
	}
	if reqCtx.QueryParams["phase"] != "two" {
		t.Fatalf("QueryParams = %#v", reqCtx.QueryParams)
	}
	if _, ok := reqCtx.Headers["x-delete"]; ok {
		t.Fatalf("deleted header remained visible after sequential scripts: %#v", reqCtx.Headers)
	}
	headerCounts := make(map[string]int, len(reqCtx.HeaderKeys))
	for _, key := range reqCtx.HeaderKeys {
		headerCounts[strings.ToLower(key)]++
	}
	for key, count := range headerCounts {
		if count != 1 {
			t.Fatalf("header %q appears %d times in HeaderKeys: %#v", key, count, reqCtx.HeaderKeys)
		}
	}
}

func TestExecuteJSRequestStageCachesOriginalBodyForSequentialReadOnlyScripts(t *testing.T) {
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	first := compileRequestScript(t, "first-read", `export default {
		fetch(request) {
			return {set_headers: {"X-First-Body": request.body === "original-body" ? "yes" : "no"}};
		}
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 1, Stage: store.JSStageRequest, Priority: 10, FailureMode: store.JSFailureModeClosed,
	})
	second := compileRequestScript(t, "second-read", `export default {
		fetch(request) {
			return {set_headers: {"X-Second-Body": request.body === "original-body" ? "yes" : "no"}};
		}
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 2, Stage: store.JSStageRequest, Priority: 20, FailureMode: store.JSFailureModeClosed,
	})

	c := &app.RequestContext{}
	c.Request.SetMethod("POST")
	c.Request.SetRequestURI("/start")
	c.Request.SetBodyString("original-body")
	reqCtx := &pipeline.RequestCtx{
		SiteID:           7,
		Method:           "POST",
		Path:             "/start",
		Body:             []byte("original-body"),
		Headers:          map[string]string{},
		HeadersLowercase: true,
	}

	state, failed, err := executeJSRequestStage(
		context.Background(), c, reqCtx, []*jsplugin.Script{first, second}, engine,
	)
	if err != nil || failed != nil {
		t.Fatalf("executeJSRequestStage() error = %v, failed = %v", err, failed)
	}
	if !state.bodyLoaded || state.bodySet || state.body != "original-body" {
		t.Fatalf("body state = %#v, want cached unchanged body", state)
	}
	if got := string(c.Request.Body()); got != "original-body" {
		t.Fatalf("request body = %q, want original-body", got)
	}
	if got := string(reqCtx.Body); got != "original-body" {
		t.Fatalf("request context body = %q, want original-body", got)
	}
	if got := string(c.Request.Header.Peek("X-First-Body")); got != "yes" {
		t.Fatalf("X-First-Body = %q, want yes", got)
	}
	if got := string(c.Request.Header.Peek("X-Second-Body")); got != "yes" {
		t.Fatalf("X-Second-Body = %q, want yes", got)
	}
}

func TestExecuteJSRequestStageHonorsFailureModes(t *testing.T) {
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	failOpen := compileRequestScript(t, "fail-open", `export default {
		fetch() { throw new Error("open failure"); }
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 1, Stage: store.JSStageRequest, Priority: 10, FailureMode: store.JSFailureModeOpen,
	})
	afterOpen := compileRequestScript(t, "after-open", `export default {
		fetch() { return {path: "/after-open"}; }
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 2, Stage: store.JSStageRequest, Priority: 20, FailureMode: store.JSFailureModeClosed,
	})
	failClosed := compileRequestScript(t, "fail-closed", `export default {
		fetch() { throw new Error("closed failure"); }
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 3, Stage: store.JSStageRequest, Priority: 30, FailureMode: store.JSFailureModeClosed,
	})

	c := &app.RequestContext{}
	c.Request.SetMethod("GET")
	c.Request.SetRequestURI("/start")
	reqCtx := &pipeline.RequestCtx{
		SiteID:           7,
		Method:           "GET",
		Path:             "/start",
		Headers:          map[string]string{},
		HeadersLowercase: true,
	}
	state, failed, err := executeJSRequestStage(
		context.Background(), c, reqCtx,
		[]*jsplugin.Script{failOpen, afterOpen, failClosed},
		engine,
	)
	if err == nil {
		t.Fatal("executeJSRequestStage() error = nil")
	}
	if failed != failClosed {
		t.Fatalf("failed script = %v, want %q", failed, failClosed.Name())
	}
	if state.path != "/after-open" || reqCtx.Path != "/after-open" {
		t.Fatalf("fail-open continuation state=%#v request_context_path=%q", state, reqCtx.Path)
	}
}

func TestExecuteJSRequestStageHonorsMutationValidationFailureModes(t *testing.T) {
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	failOpen := compileRequestScript(t, "invalid-open", `export default {
		fetch() { return {path: "relative"}; }
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 1, Stage: store.JSStageRequest, Priority: 10, FailureMode: store.JSFailureModeOpen,
	})
	afterOpen := compileRequestScript(t, "after-invalid-open", `export default {
		fetch(request) { return {path: request.path + "/after-open"}; }
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 2, Stage: store.JSStageRequest, Priority: 20, FailureMode: store.JSFailureModeClosed,
	})
	failClosed := compileRequestScript(t, "invalid-closed", `export default {
		fetch() { return {path: "//invalid"}; }
	}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 3, Stage: store.JSStageRequest, Priority: 30, FailureMode: store.JSFailureModeClosed,
	})

	c := &app.RequestContext{}
	c.Request.SetMethod("GET")
	c.Request.SetRequestURI("/start")
	reqCtx := &pipeline.RequestCtx{
		SiteID:           7,
		Method:           "GET",
		Path:             "/start",
		Headers:          map[string]string{},
		HeadersLowercase: true,
	}
	state, failed, err := executeJSRequestStage(
		context.Background(), c, reqCtx,
		[]*jsplugin.Script{failOpen, afterOpen, failClosed},
		engine,
	)
	if err == nil {
		t.Fatal("executeJSRequestStage() error = nil")
	}
	if failed != failClosed {
		t.Fatalf("failed script = %v, want %q", failed, failClosed.Name())
	}
	if state.path != "/start/after-open" || reqCtx.Path != "/start/after-open" {
		t.Fatalf("fail-open mutation continuation state=%#v request_context_path=%q", state, reqCtx.Path)
	}
}

func TestExecuteJSRequestStageHandlesUnavailableExecutor(t *testing.T) {
	failOpen := compileRequestScript(t, "open", `export default {fetch() { return {}; }}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 1, Stage: store.JSStageRequest, FailureMode: store.JSFailureModeOpen,
	})
	failClosed := compileRequestScript(t, "closed", `export default {fetch() { return {}; }}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 2, Stage: store.JSStageRequest, FailureMode: store.JSFailureModeClosed,
	})

	c := &app.RequestContext{}
	c.Request.SetMethod("GET")
	c.Request.SetRequestURI("/start")
	reqCtx := &pipeline.RequestCtx{SiteID: 7, Method: "GET", Path: "/start", Headers: map[string]string{}}
	state, failed, err := executeJSRequestStage(
		context.Background(), c, reqCtx,
		[]*jsplugin.Script{failOpen, failClosed},
		nil,
	)
	if err != jsplugin.ErrCGODisabled {
		t.Fatalf("error = %v, want ErrCGODisabled", err)
	}
	if failed != failClosed {
		t.Fatalf("failed script = %v, want %q", failed, failClosed.Name())
	}
	if state.path != "/start" {
		t.Fatalf("state = %#v", state)
	}
}

func TestExecuteJSRequestStageHandlesTypedNilExecutor(t *testing.T) {
	failClosed := compileRequestScript(t, "typed-nil", `export default {fetch() { return {}; }}`, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{
		ID: 4, Stage: store.JSStageRequest, FailureMode: store.JSFailureModeClosed,
	})

	c := &app.RequestContext{}
	c.Request.SetMethod("GET")
	c.Request.SetRequestURI("/start")
	reqCtx := &pipeline.RequestCtx{SiteID: 7, Method: "GET", Path: "/start", Headers: map[string]string{}}
	var executor *jsplugin.Engine
	_, failed, err := executeJSRequestStage(
		context.Background(), c, reqCtx,
		[]*jsplugin.Script{failClosed},
		executor,
	)
	if err != jsplugin.ErrCGODisabled {
		t.Fatalf("error = %v, want ErrCGODisabled", err)
	}
	if failed != failClosed {
		t.Fatalf("failed script = %v, want %q", failed, failClosed.Name())
	}
}

func compileRequestScript(
	t *testing.T,
	name string,
	source string,
	opts jsplugin.ScriptOptions,
	metadata jsplugin.ScriptMetadata,
) *jsplugin.Script {
	t.Helper()
	script, err := jsplugin.CompileWithMetadata(name, source, opts, metadata)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return script
}
