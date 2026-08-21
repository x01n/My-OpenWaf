//go:build cgo && quickjs

package app

import (
	"testing"

	"My-OpenWaf/internal/waf/jsplugin"
)

func TestEnsureJSPluginEngineForDryRunCreatesExecutorWithoutScripts(t *testing.T) {
	engine, err := ensureJSPluginEngineForDryRun(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	script, err := jsplugin.Compile("dry-run", `export default {fetch() { return {path: "/dry-run"}; }}`, jsplugin.ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := engine.Execute(t.Context(), script, jsplugin.RequestSnapshot{})
	if err != nil {
		t.Fatalf("dry-run executor failed: %v", err)
	}
	if plan.Path == nil || *plan.Path != "/dry-run" {
		t.Fatalf("mutation plan = %#v", plan)
	}
}

func TestEnsureJSPluginEngineKeepsExecutorAcrossEmptyGeneration(t *testing.T) {
	script, err := jsplugin.Compile("lifecycle", `export default {fetch() { return {path: "/kept"}; }}`, jsplugin.ScriptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := ensureJSPluginEngine(nil, []*jsplugin.Script{script})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	afterEmpty, err := ensureJSPluginEngine(engine, nil)
	if err != nil {
		t.Fatal(err)
	}
	if afterEmpty != engine {
		t.Fatal("empty script generation replaced the process-scoped executor")
	}
	plan, err := afterEmpty.Execute(t.Context(), script, jsplugin.RequestSnapshot{})
	if err != nil {
		t.Fatalf("old snapshot script failed after empty generation: %v", err)
	}
	if plan.Path == nil || *plan.Path != "/kept" {
		t.Fatalf("mutation plan = %#v", plan)
	}
}
