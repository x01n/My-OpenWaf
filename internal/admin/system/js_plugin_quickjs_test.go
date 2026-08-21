//go:build cgo && quickjs

package system

import (
	"bytes"
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

func TestDryRunJSPluginLoadsCurrentEnginePerRequest(t *testing.T) {
	var current *jsplugin.Engine
	handler := DryRunJSPlugin(func() *jsplugin.Engine { return current })
	body := []byte(`{"stage":"request","source":"export default {fetch(request) { return {path: request.path + '/checked'}; }}","sample_request":{"path":"/start"}}`)

	unavailable := invokeThreatIntelHandler(t, handler, "POST", "/x", nil, body)
	if unavailable.Response.StatusCode() != 503 {
		t.Fatalf("unavailable status = %d, want 503; body=%s", unavailable.Response.StatusCode(), bytes.TrimSpace(unavailable.Response.Body()))
	}

	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	current = engine

	available := invokeThreatIntelHandler(t, handler, "POST", "/x", nil, body)
	if available.Response.StatusCode() != 200 {
		t.Fatalf("available status = %d, want 200; body=%s", available.Response.StatusCode(), bytes.TrimSpace(available.Response.Body()))
	}
	var response struct {
		Result jsplugin.MutationPlan `json:"result"`
		Error  string                `json:"error"`
	}
	if err := json.Unmarshal(available.Response.Body(), &response); err != nil {
		t.Fatalf("decode dry-run response: %v", err)
	}
	if response.Error != "" || response.Result.Path == nil || *response.Result.Path != "/start/checked" {
		t.Fatalf("dry-run response = %#v", response)
	}
}

func TestDryRunJSPluginRejectsResponseStage(t *testing.T) {
	ctx := invokeThreatIntelHandler(t, DryRunJSPlugin(nil), "POST", "/x", nil, []byte(`{"stage":"response","source":"export default {fetch() { return {}; }}"}`))
	if ctx.Response.StatusCode() != 400 || !bytes.Contains(ctx.Response.Body(), []byte(jsResponseStageUnavailableMessage)) {
		t.Fatalf("response-stage dry-run = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
}

func TestDryRunJSPluginRejectsUnsafeMutationPlan(t *testing.T) {
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	handler := DryRunJSPlugin(func() *jsplugin.Engine { return engine })
	body := []byte(`{"stage":"request","source":"export default {fetch() { return {path: 'https://example.test/admin'}; }}"}`)
	ctx := invokeThreatIntelHandler(t, handler, "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("dry-run status = %d, want 200; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var response struct {
		Error  string          `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode dry-run response: %v", err)
	}
	if response.Error != "jsplugin: invalid path mutation" || string(response.Result) != "null" {
		t.Fatalf("dry-run response = %#v", response)
	}
}

func TestGetJSPluginStatsReadsCurrentSnapshotScripts(t *testing.T) {
	script, err := jsplugin.CompileWithMetadata(
		"runtime-stats",
		`export default {fetch() { return {}; }}`,
		jsplugin.ScriptOptions{},
		jsplugin.ScriptMetadata{
			ID:          77,
			Stage:       store.JSStageRequest,
			Priority:    5,
			FailureMode: store.JSFailureModeOpen,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if _, err := engine.Execute(t.Context(), script, jsplugin.RequestSnapshot{}); err != nil {
		t.Fatal(err)
	}

	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{Revision: 9, JSPlugins: []*jsplugin.Script{script}})
	ctx := invokeThreatIntelHandler(t, GetJSPluginStats(holder), "GET", "/x", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("stats status = %d; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var response struct {
		Items []jsPluginStatsItem `json:"items"`
		Total int                 `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode stats response: %v", err)
	}
	if response.Total != 1 || len(response.Items) != 1 {
		t.Fatalf("stats response = %#v", response)
	}
	item := response.Items[0]
	if item.ID != 77 || item.Name != "runtime-stats" || item.Stage != store.JSStageRequest || item.Runs != 1 || item.Failures != 0 || item.Timeouts != 0 || item.AvgMS < 0 {
		t.Fatalf("stats item = %#v", item)
	}
}
