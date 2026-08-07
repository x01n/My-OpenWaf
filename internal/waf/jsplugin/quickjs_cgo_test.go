//go:build cgo

package jsplugin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

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
	loop, err := Compile("loop", `export default {fetch() { for (;;) {} }}`, ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err = engine.Evaluate(context.Background(), loop, RequestSnapshot{})
	if !errors.Is(err, ErrScriptTimeout) || plan.Method != nil || plan.Path != nil || plan.RawQuery != nil || plan.Body != nil || len(plan.SetHeaders) != 0 || len(plan.DeleteHeaders) != 0 {
		t.Fatalf("timeout result = %#v, %v", plan, err)
	}
	_, _, timeouts, _ := loop.Stats()
	if timeouts != 1 {
		t.Fatalf("timeouts = %d, want 1", timeouts)
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
