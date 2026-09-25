//go:build cgo && quickjs

package jsplugin

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"My-OpenWaf/internal/store"
)

func TestQuickJSCompileUsesName(t *testing.T) {
	script, err := Compile("named-script", `export default {fetch() { return {}; }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if script.Name() != "named-script" {
		t.Fatalf("script name = %q, want named-script", script.Name())
	}
}

// TestQuickJSValidateWithOptionsAcceptsResponseStage 验证快速编译路径对
// response 阶段的语法校验与 request 同轨。
func TestQuickJSValidateWithOptionsAcceptsResponseStage(t *testing.T) {
	if err := ValidateWithOptions(
		store.JSStageResponse,
		`export default {fetch() { return {}; }}`,
		ScriptOptions{},
	); err != nil {
		t.Fatalf("ValidateWithOptions(response) error = %v", err)
	}
	if err := ValidateWithOptions(
		"pre",
		`export default {fetch() { return {}; }}`,
		ScriptOptions{},
	); err == nil {
		t.Fatal("ValidateWithOptions(pre) error = nil, want unknown-stage error")
	}
}

func TestQuickJSCompileValidationDeadlineIsIndependentFromRuntimeTimeout(t *testing.T) {
	const workers = 16
	const iterations = 4
	var wg sync.WaitGroup
	errs := make(chan error, workers*iterations)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_, err := Compile("validation-pressure", `export default {fetch() { return {}; }}`, ScriptOptions{Timeout: time.Nanosecond})
				if err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("valid script failed compile validation under pressure: %v", err)
	}
}

func TestQuickJSCompileValidationInterruptsTopLevelLoop(t *testing.T) {
	started := time.Now()
	_, err := Compile("validation-loop", `export default (() => { for (;;) {} })()`, ScriptOptions{ValidationTimeout: 20 * time.Millisecond})
	if !errors.Is(err, ErrScriptTimeout) {
		t.Fatalf("top-level loop validation error = %v, want %v", err, ErrScriptTimeout)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("top-level loop validation took %s, want less than 1s", elapsed)
	}
}

func TestQuickJSEngineExecutesMutationPlan(t *testing.T) {
	script, err := Compile("test", `export default {
		fetch(request, env, ctx) {
			return {method: "POST", path: request.path + "/checked", set_headers: {"X-JS": request.method}, delete_headers: ["X-Delete"]};
		}
	}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	plan, err := engine.Evaluate(context.Background(), script, RequestSnapshot{SiteID: 1, Method: "GET", Path: "/test"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Method == nil || *plan.Method != "POST" || plan.Path == nil || *plan.Path != "/test/checked" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.SetHeaders["X-JS"] != "GET" || len(plan.DeleteHeaders) != 1 || plan.DeleteHeaders[0] != "X-Delete" {
		t.Fatalf("unexpected headers: %+v", plan)
	}
}

// TestQuickJSEngineExecutesResponseMutationPlan 通过真实 QuickJS 执行验证
// response 阶段契约：fetch(response, env, ctx) 的响应快照字段与
// ResponseMutationPlan 提取（body/set_headers/delete_headers）两条路径。
func TestQuickJSEngineExecutesResponseMutationPlan(t *testing.T) {
	script, err := CompileWithMetadata(
		"response-stage",
		`export default {
			fetch(response) {
				if (response.request_id !== "resp-1" || response.site_id !== 9 ||
					response.status !== 200 || response.path !== "/api" ||
					response.content_type !== "application/json" ||
					response.body !== "{\"ok\":true}" ||
					response.headers["x-upstream"] !== "u" ||
					response.method !== "POST" || response.raw_query !== "q=1" ||
					response.client_ip !== "192.0.2.10" ||
					response.request_headers["x-client"] !== "c") {
					throw new Error("response snapshot contract mismatch");
				}
				return {status: 201, body: response.body + "-done", set_headers: {"X-JS": String(response.status)}, delete_headers: ["X-Upstream"]};
			}
		}`,
		ScriptOptions{},
		ScriptMetadata{ID: 1, Stage: store.JSStageResponse, Priority: 10, FailureMode: store.JSFailureModeOpen},
	)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	plan, err := engine.ExecuteResponse(context.Background(), script, ResponseSnapshot{
		RequestID:      "resp-1",
		SiteID:         9,
		Status:         200,
		Path:           "/api",
		ContentType:    "application/json",
		Body:           `{"ok":true}`,
		Headers:        map[string]string{"x-upstream": "u"},
		Method:         "POST",
		RawQuery:       "q=1",
		ClientIP:       "192.0.2.10",
		RequestHeaders: map[string]string{"x-client": "c"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status == nil || *plan.Status != 201 || plan.Body == nil || *plan.Body != `{"ok":true}-done` {
		t.Fatalf("unexpected response plan: %+v", plan)
	}
	if plan.SetHeaders["X-JS"] != "200" || len(plan.DeleteHeaders) != 1 || plan.DeleteHeaders[0] != "X-Upstream" {
		t.Fatalf("unexpected response headers: %+v", plan)
	}
}

// TestQuickJSEngineRejectsResponseStageOnRequestExecutor 确保 response 阶段
// 脚本不得通过 request 执行入口运行，反之亦然。
func TestQuickJSEngineRejectsCrossStageExecution(t *testing.T) {
	responseScript, err := CompileWithMetadata(
		"response-stage",
		`export default {fetch() { return {status: 201}; }}`,
		ScriptOptions{},
		ScriptMetadata{Stage: store.JSStageResponse},
	)
	if err != nil {
		t.Fatal(err)
	}
	requestScript, err := CompileWithMetadata(
		"request-stage",
		`export default {fetch() { return {path: "/must-not-run"}; }}`,
		ScriptOptions{},
		ScriptMetadata{Stage: store.JSStageRequest},
	)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	for _, run := range []struct {
		name string
		fn   func() error
	}{
		{name: "response script via execute", fn: func() error {
			_, err := engine.Execute(context.Background(), responseScript, RequestSnapshot{Method: "GET", Path: "/"})
			return err
		}},
		{name: "response script via validate", fn: func() error {
			_, err := engine.Validate(context.Background(), responseScript, CanonicalValidationRequest(0))
			return err
		}},
		{name: "request script via execute response", fn: func() error {
			_, err := engine.ExecuteResponse(context.Background(), requestScript, CanonicalValidationResponse(0))
			return err
		}},
		{name: "request script via validate response", fn: func() error {
			_, err := engine.ValidateResponse(context.Background(), requestScript, CanonicalValidationResponse(0))
			return err
		}},
	} {
		t.Run(run.name, func(t *testing.T) {
			if err := run.fn(); err == nil || !strings.Contains(err.Error(), "cannot use") {
				t.Fatalf("error = %v, want cross-stage error", err)
			}
		})
	}
	if runs, failures, timeouts, average := responseScript.Stats(); runs != 0 || failures != 0 || timeouts != 0 || average != 0 {
		t.Fatalf("cross-stage rejection changed stats: runs=%d failures=%d timeouts=%d average=%s", runs, failures, timeouts, average)
	}
}

// TestQuickJSEngineRejectsResponseMutationPlanUnsafeChanges 验证响应计划在
// host 应用前就被拒绝：越界状态码、保留头、请求侧未知字段。
func TestQuickJSEngineRejectsResponseMutationPlanUnsafeChanges(t *testing.T) {
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	cases := []struct {
		name       string
		returnExpr string
	}{
		{name: "status below range", returnExpr: `{status: 99}`},
		{name: "content length set", returnExpr: `{body: "fine", set_headers: {"Content-Length": "1"}}`},
		{name: "request-only field", returnExpr: `{status: 200, method: "GET"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script, err := CompileWithMetadata(
				tc.name,
				`export default {fetch() { return `+tc.returnExpr+`; }}`,
				ScriptOptions{},
				ScriptMetadata{Stage: store.JSStageResponse},
			)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := engine.EvaluateResponse(context.Background(), script, ResponseSnapshot{SiteID: 1})
			if err == nil || plan.Status != nil || plan.Body != nil || plan.SetHeaders != nil {
				t.Fatalf("%s result = %#v, %v, want rejection", tc.returnExpr, plan, err)
			}
		})
	}
}

func TestQuickJSValidateDoesNotChangeRuntimeStats(t *testing.T) {
	script, err := Compile("validation-stats", `export default {fetch() { return {}; }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if _, err := engine.Validate(context.Background(), script, CanonicalValidationRequest(0)); err != nil {
		t.Fatal(err)
	}
	runs, failures, timeouts, avg := script.Stats()
	if runs != 0 || failures != 0 || timeouts != 0 || avg != 0 {
		t.Fatalf("validation changed stats: runs=%d failures=%d timeouts=%d avg=%s", runs, failures, timeouts, avg)
	}
}

func TestQuickJSRejectsNonMutationPlanReturnShapes(t *testing.T) {
	tests := []struct {
		name       string
		returnExpr string
		wantError  string
	}{
		{name: "request snapshot", returnExpr: "request", wantError: "unknown field"},
		{name: "unknown field", returnExpr: `{path: "/ok", headers: {"x-test": "value"}}`, wantError: `unknown field "headers"`},
		{name: "array", returnExpr: `[]`, wantError: "must be a MutationPlan object"},
		{name: "string", returnExpr: `"/not-a-plan"`, wantError: "must be a MutationPlan object"},
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			script, err := Compile(tc.name, `export default {fetch(request) { return `+tc.returnExpr+`; }}`, ScriptOptions{})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := engine.Evaluate(context.Background(), script, RequestSnapshot{Method: "GET", Path: "/original"})
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("result = %#v, error = %v, want error containing %q", plan, err, tc.wantError)
			}
		})
	}
}

func TestQuickJSAcceptsEmptyMutationPlanReturns(t *testing.T) {
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	for _, returnExpr := range []string{"null", "undefined", "{}"} {
		script, err := Compile("empty-plan", `export default {fetch() { return `+returnExpr+`; }}`, ScriptOptions{})
		if err != nil {
			t.Fatal(err)
		}
		plan, err := engine.Evaluate(context.Background(), script, RequestSnapshot{})
		if err != nil || plan.Method != nil || plan.Path != nil || plan.RawQuery != nil || plan.Body != nil || len(plan.SetHeaders) != 0 || len(plan.DeleteHeaders) != 0 {
			t.Fatalf("return %s result = %#v, %v", returnExpr, plan, err)
		}
	}
}

func TestQuickJSRequestSnapshotJSONPreservesContract(t *testing.T) {
	script, err := Compile("request-contract", `export default {
		fetch(request) {
			if (request.request_id !== "req-1" || request.site_id !== 42 ||
				request.method !== "POST" || request.path !== "/orders" ||
				request.raw_query !== "page=2" || request.host !== "example.test" ||
				request.client_ip !== "192.0.2.10" || request.user_agent !== "test-agent" ||
				request.content_type !== "application/json" || request.body !== "{\"ok\":true}" ||
				request.headers["x-test"] !== "value" || request.query_params.page !== "2") {
				throw new Error("request snapshot contract mismatch");
			}
			return {path: "/contract-ok"};
		}
	}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	plan, err := engine.Evaluate(context.Background(), script, RequestSnapshot{
		RequestID:   "req-1",
		SiteID:      42,
		Method:      "POST",
		Path:        "/orders",
		RawQuery:    "page=2",
		Host:        "example.test",
		ClientIP:    "192.0.2.10",
		UserAgent:   "test-agent",
		ContentType: "application/json",
		Body:        `{"ok":true}`,
		Headers:     map[string]string{"x-test": "value"},
		QueryParams: map[string]string{"page": "2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Path == nil || *plan.Path != "/contract-ok" {
		t.Fatalf("request contract result = %#v", plan)
	}
}

func TestQuickJSScriptsWithSameTopLevelLexicalBindingRemainIsolated(t *testing.T) {
	first, err := Compile("first", `const marker = "/first";
		export default { fetch() { return {path: marker}; } };`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile("second", `const marker = "/second";
		export default { fetch() { return {path: marker}; } };`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	for _, tc := range []struct {
		script *Script
		path   string
	}{
		{script: first, path: "/first"},
		{script: second, path: "/second"},
		{script: first, path: "/first"},
	} {
		plan, err := engine.Evaluate(context.Background(), tc.script, RequestSnapshot{})
		if err != nil {
			t.Fatalf("evaluate %q: %v", tc.script.Name(), err)
		}
		if plan.Path == nil || *plan.Path != tc.path {
			t.Fatalf("%q path = %#v, want %q", tc.script.Name(), plan, tc.path)
		}
	}
}

func TestQuickJSCompiledCacheEvictsOldestScript(t *testing.T) {
	engine, err := NewEngine(EngineOptions{PoolSize: 1, CompiledCacheSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	scripts := make([]*Script, 3)
	for i, name := range []string{"first", "second", "third"} {
		scripts[i], err = Compile(name, `export default {fetch() { return {}; }}`, ScriptOptions{})
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		if _, err := engine.Evaluate(context.Background(), scripts[i], RequestSnapshot{}); err != nil {
			t.Fatalf("evaluate %s: %v", name, err)
		}
	}

	slot := engine.slots[0]
	if len(slot.compiled) != 2 || slot.compiledOrder.Len() != 2 {
		t.Fatalf("compiled cache size = %d/%d, want 2/2", len(slot.compiled), slot.compiledOrder.Len())
	}
	if _, ok := slot.compiled[scripts[0]]; ok {
		t.Fatal("oldest compiled script was not evicted")
	}
	if _, ok := slot.compiled[scripts[1]]; !ok {
		t.Fatal("second compiled script was unexpectedly evicted")
	}
	if _, ok := slot.compiled[scripts[2]]; !ok {
		t.Fatal("newest compiled script is missing")
	}
}

func TestQuickJSRejectsCRLFMutationHeader(t *testing.T) {
	script, err := Compile("crlf", `export default {fetch() { return {set_headers: {"X-Test": "bad\r\nvalue"}}; }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	plan, err := engine.Evaluate(context.Background(), script, RequestSnapshot{})
	if err == nil || plan.SetHeaders != nil {
		t.Fatalf("CR/LF mutation result = %#v, %v", plan, err)
	}
}

func TestQuickJSEngineRejectsFailureAndTimeout(t *testing.T) {
	engine, err := NewEngine(EngineOptions{PoolSize: 1, Timeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	bad, err := Compile("bad", `export default {fetch() { throw new Error("boom") }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Evaluate(context.Background(), bad, RequestSnapshot{})
	if err == nil || plan.Method != nil || plan.Path != nil || plan.RawQuery != nil || plan.Body != nil || len(plan.SetHeaders) != 0 || len(plan.DeleteHeaders) != 0 || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("failure result = %#v, %v", plan, err)
	}
	badRuns, badFailures, badTimeouts, badAverage := bad.Stats()
	if badRuns != 1 || badFailures != 1 || badTimeouts != 0 || badAverage <= 0 {
		t.Fatalf("failure stats = runs=%d failures=%d timeouts=%d average=%s, want 1/1/0/>0", badRuns, badFailures, badTimeouts, badAverage)
	}
	loop, err := Compile("loop", `export default {fetch() { for (;;) {} }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err = engine.Evaluate(context.Background(), loop, RequestSnapshot{})
	if !errors.Is(err, ErrScriptTimeout) || plan.Method != nil || plan.Path != nil || plan.RawQuery != nil || plan.Body != nil || len(plan.SetHeaders) != 0 || len(plan.DeleteHeaders) != 0 {
		t.Fatalf("timeout result = %#v, %v", plan, err)
	}
	loopRuns, loopFailures, loopTimeouts, loopAverage := loop.Stats()
	if loopRuns != 1 || loopFailures != 0 || loopTimeouts != 1 || loopAverage <= 0 {
		t.Fatalf("timeout stats = runs=%d failures=%d timeouts=%d average=%s, want 1/0/1/>0", loopRuns, loopFailures, loopTimeouts, loopAverage)
	}
}

func TestQuickJSPendingPromiseReturnsQuickly(t *testing.T) {
	script, err := Compile("pending", `export default {fetch() { return new Promise(() => {}); }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	started := time.Now()
	plan, err := engine.Evaluate(context.Background(), script, RequestSnapshot{})
	if !errors.Is(err, ErrAsyncPromise) || plan.Method != nil || plan.Path != nil || plan.RawQuery != nil || plan.Body != nil || len(plan.SetHeaders) != 0 || len(plan.DeleteHeaders) != 0 {
		t.Fatalf("pending Promise result = %#v, %v", plan, err)
	}
	if elapsed := time.Since(started); elapsed >= 100*time.Millisecond {
		t.Fatalf("pending Promise took %s, want less than 100ms", elapsed)
	}
}

func TestQuickJSPoolRemainsUsableAfterPendingPromise(t *testing.T) {
	pending, err := Compile("pending", `export default {fetch() { return new Promise(() => {}); }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	synchronous, err := Compile("synchronous", `export default {fetch() { return {method: "POST"}; }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	if _, err := engine.Evaluate(context.Background(), pending, RequestSnapshot{}); !errors.Is(err, ErrAsyncPromise) {
		t.Fatalf("pending Promise error = %v, want %v", err, ErrAsyncPromise)
	}
	plan, err := engine.Evaluate(context.Background(), synchronous, RequestSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Method == nil || *plan.Method != "POST" {
		t.Fatalf("synchronous result = %#v, want POST mutation", plan)
	}
}

func TestQuickJSPromiseResolveAndReject(t *testing.T) {
	resolved, err := Compile("resolved", `export default {fetch() { return Promise.resolve({path: "/resolved"}); }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := Compile("rejected", `export default {fetch() { return Promise.reject(new Error("rejected")); }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	plan, err := engine.Evaluate(context.Background(), resolved, RequestSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Path == nil || *plan.Path != "/resolved" {
		t.Fatalf("resolved Promise result = %#v, want /resolved", plan)
	}
	plan, err = engine.Evaluate(context.Background(), rejected, RequestSnapshot{})
	if err == nil || plan.Method != nil || plan.Path != nil || plan.RawQuery != nil || plan.Body != nil || len(plan.SetHeaders) != 0 || len(plan.DeleteHeaders) != 0 || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("rejected Promise result = %#v, %v", plan, err)
	}
}

func TestQuickJSEngineCloseRejectsQueuedRequest(t *testing.T) {
	script, err := Compile("close-queue", `export default {fetch() { for (;;) {} }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(EngineOptions{PoolSize: 1, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	firstDone := make(chan error, 1)
	go func() {
		_, evalErr := engine.Evaluate(context.Background(), script, RequestSnapshot{})
		firstDone <- evalErr
	}()
	deadline := time.Now().Add(time.Second)
	for {
		scriptRuns, _, _, _ := script.Stats()
		if scriptRuns > 0 {
			break
		}
		if time.Now().After(deadline) {
			_ = engine.Close()
			t.Fatal("first request did not start")
		}
		time.Sleep(time.Millisecond)
	}

	secondDone := make(chan error, 1)
	go func() {
		_, evalErr := engine.Evaluate(context.Background(), script, RequestSnapshot{})
		secondDone <- evalErr
	}()

	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case evalErr := <-secondDone:
		if !errors.Is(evalErr, ErrEngineClosed) {
			t.Fatalf("queued request error = %v, want %v", evalErr, ErrEngineClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("queued request did not receive a result")
	}
	select {
	case evalErr := <-firstDone:
		if !errors.Is(evalErr, ErrScriptTimeout) {
			t.Fatalf("running request error = %v, want %v", evalErr, ErrScriptTimeout)
		}
	case <-time.After(time.Second):
		t.Fatal("running request did not receive a result")
	}
}
func TestQuickJSDoesNotExposeHostModules(t *testing.T) {
	if _, err := Compile("module", `export default {fetch() { return typeof os; }}`, ScriptOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Compile("import", `import x from "os"; export default {fetch() { return {}; }}`, ScriptOptions{}); err == nil {
		t.Fatal("module import unexpectedly compiled")
	}
}

func TestQuickJSExportDefaultTransformationIsSyntaxAware(t *testing.T) {
	source := "// export default inside a comment\n" +
		"const literal = \"export default inside a string\";\n" +
		"const matcher = /export default/;\n" +
		"const template = `export default inside a template`;\n" +
		"export default { fetch() { return {set_headers: {\"X-AST\": String(matcher.test(literal) && template.includes(\"export default\"))}}; } };"
	script, err := Compile("syntax-aware", source, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script.source, "globalThis.__owaf_plugin") {
		t.Fatalf("transformed source leaked plugin through global state: %q", script.source)
	}
	if !strings.HasPrefix(script.source, "(function () {\n\"use strict\";") {
		t.Fatalf("transformed source is not a strict IIFE: %q", script.source)
	}

	engine, err := NewEngine(EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	plan, err := engine.Evaluate(context.Background(), script, RequestSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.SetHeaders["X-AST"] != "true" {
		t.Fatalf("syntax-aware transformation result = %#v", plan)
	}
}

func TestQuickJSExportValidation(t *testing.T) {
	valid := `const plugin = {fetch() { return {}; }}; export default plugin;`
	if _, err := Compile("valid", valid, ScriptOptions{}); err != nil {
		t.Fatalf("unique default export failed: %v", err)
	}

	for name, source := range map[string]string{
		"missing default":   `const plugin = {fetch() { return {}; }};`,
		"duplicate default": `export default {fetch() { return {}; }}; export default {fetch() { return {}; }};`,
		"named export":      `export const plugin = {fetch() { return {}; }}; export default {fetch() { return {}; }};`,
		"named re-export":   `const plugin = {fetch() { return {}; }}; export {plugin} from "plugin"; export default plugin;`,
		"import":            `import plugin from "plugin"; export default {fetch() { return {}; }};`,
		"not object":        `export default 1;`,
		"missing fetch":     `export default {};`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile(name, source, ScriptOptions{}); err == nil {
				t.Fatal("unexpectedly compiled")
			}
		})
	}
}

func BenchmarkQuickJSEngineEvaluate(b *testing.B) {
	request := RequestSnapshot{
		RequestID:   "req-benchmark",
		SiteID:      42,
		Method:      "POST",
		Path:        "/api/orders",
		RawQuery:    "page=2&sort=created_at&order=desc",
		Host:        "benchmark.example.test",
		ClientIP:    "192.0.2.10",
		UserAgent:   "Mozilla/5.0 benchmark",
		ContentType: "application/json",
		Body:        `{"order_id":1024,"items":[{"sku":"A-100","quantity":2}],"note":"benchmark payload"}`,
		Headers: map[string]string{
			"accept":          "application/json",
			"accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
			"content-type":    "application/json",
			"host":            "benchmark.example.test",
			"user-agent":      "Mozilla/5.0 benchmark",
			"x-request-id":    "req-benchmark",
		},
		QueryParams: map[string]string{
			"page":  "2",
			"sort":  "created_at",
			"order": "desc",
		},
	}
	cases := []struct {
		name   string
		source string
	}{
		{
			name:   "NoMutation",
			source: `export default { fetch() { return {}; } }`,
		},
		{
			name: "HeaderPathBodyMutation",
			source: `export default {
				fetch(request) {
					return {
						path: request.path + "/checked",
						body: request.body,
						set_headers: {"x-js-plugin": "benchmark"},
						delete_headers: ["x-request-id"]
					};
				}
			}`,
		},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			script, err := Compile(tc.name, tc.source, ScriptOptions{})
			if err != nil {
				b.Fatal(err)
			}
			engine, err := NewEngine(EngineOptions{PoolSize: 1})
			if err != nil {
				b.Fatal(err)
			}
			defer engine.Close()
			if _, err := engine.Evaluate(context.Background(), script, request); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := engine.Evaluate(context.Background(), script, request); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
