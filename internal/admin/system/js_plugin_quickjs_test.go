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

func TestDryRunJSPluginExecutesResponseStage(t *testing.T) {
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	handler := DryRunJSPlugin(func() *jsplugin.Engine { return engine })

	body := []byte(`{"stage":"response","source":"export default {fetch(response) { return {status: 201, body: response.body + '-done', set_headers: {\"X-Dry\": String(response.status)}}; }}","sample_response":{"status":200,"path":"/api","body":"hello","request_headers":{"x-client":"c"}}}`)
	ctx := invokeThreatIntelHandler(t, handler, "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("response dry-run status = %d, want 200; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var response struct {
		Error  string                        `json:"error"`
		Result jsplugin.ResponseMutationPlan `json:"result"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode response dry-run: %v", err)
	}
	if response.Error != "" || response.Result.Status == nil || *response.Result.Status != 201 ||
		response.Result.Body == nil || *response.Result.Body != "hello-done" ||
		response.Result.SetHeaders["X-Dry"] != "200" {
		t.Fatalf("response dry-run = %#v", response)
	}
}

func TestDryRunJSPluginRejectsResponseUnsafePlan(t *testing.T) {
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	handler := DryRunJSPlugin(func() *jsplugin.Engine { return engine })
	body := []byte(`{"stage":"response","source":"export default {fetch() { return {status: 99}; }}"}`)
	ctx := invokeThreatIntelHandler(t, handler, "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status = %d; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var response struct {
		Error  string          `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode response dry-run: %v", err)
	}
	if response.Error != "jsplugin: invalid status mutation" || string(response.Result) != "null" {
		t.Fatalf("response dry-run = %#v", response)
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

func TestEnabledJSPluginPersistenceExecutesCanonicalFetchBeforeWrite(t *testing.T) {
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	loadEngine := func() *jsplugin.Engine { return engine }

	t.Run("create", func(t *testing.T) {
		repo := newJSPluginRepoForTest(t)
		reloaded := 0
		body := []byte(`{"name":"bad-create","source":"export default { async fetch(request) { return request; } }","stage":"request","failure_mode":"fail_open"}`)
		ctx := invokeThreatIntelHandler(t, CreateJSPlugin(repo, nil, func() error { reloaded++; return nil }, loadEngine), "POST", "/x", nil, body)
		if ctx.Response.StatusCode() != 400 || !bytes.Contains(ctx.Response.Body(), []byte("mutation plan contains unknown field")) {
			t.Fatalf("status = %d; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		items, listErr := repo.List()
		if listErr != nil || len(items) != 0 || reloaded != 0 {
			t.Fatalf("items=%d reloads=%d err=%v", len(items), reloaded, listErr)
		}
	})

	t.Run("update", func(t *testing.T) {
		repo := newJSPluginRepoForTest(t)
		seed := store.JSPlugin{Name: "draft", Source: `export default { fetch() { return {}; } }`, Stage: store.JSStageRequest, FailureMode: store.JSFailureModeOpen, Enabled: false}
		if err := repo.Create(&seed); err != nil {
			t.Fatal(err)
		}
		body := []byte(`{"enabled":true,"source":"export default { fetch(request) { return request; } }"}`)
		ctx := invokeThreatIntelHandler(t, UpdateJSPlugin(repo, nil, func() error { return nil }, loadEngine), "POST", "/x", idParam(seed.ID), body)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("status = %d; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		stored, getErr := repo.Get(seed.ID)
		if getErr != nil || stored.Enabled || stored.Source != seed.Source {
			t.Fatalf("stored=%+v err=%v", stored, getErr)
		}
	})

	t.Run("toggle", func(t *testing.T) {
		repo := newJSPluginRepoForTest(t)
		seed := store.JSPlugin{Name: "draft", Source: `export default { fetch(request) { return request; } }`, Stage: store.JSStageRequest, FailureMode: store.JSFailureModeOpen, Enabled: false}
		if err := repo.Create(&seed); err != nil {
			t.Fatal(err)
		}
		ctx := invokeThreatIntelHandler(t, ToggleJSPlugin(repo, func() error { return nil }, loadEngine), "POST", "/x", idParam(seed.ID), []byte(`{"enabled":true}`))
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("status = %d; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		stored, getErr := repo.Get(seed.ID)
		if getErr != nil || stored.Enabled {
			t.Fatalf("stored=%+v err=%v", stored, getErr)
		}
	})
}

func TestValidateJSPluginExecutesFetchContract(t *testing.T) {
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	handler := ValidateJSPlugin(func() *jsplugin.Engine { return engine })
	ctx := invokeThreatIntelHandler(t, handler, "POST", "/x", nil, []byte(`{"stage":"request","source":"export default { fetch(request) { return request; } }"}`))
	if ctx.Response.StatusCode() != 200 || !bytes.Contains(ctx.Response.Body(), []byte(`"valid":false`)) || !bytes.Contains(ctx.Response.Body(), []byte("mutation plan contains unknown field")) {
		t.Fatalf("status = %d; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestGetJSPluginRuntimeReportsReadyQuickJS(t *testing.T) {
	repo := newJSPluginRepoForTest(t)
	row := store.JSPlugin{Name: "ready", Source: `export default { fetch() { return {}; } }`, Stage: store.JSStageRequest, FailureMode: store.JSFailureModeOpen, Enabled: true}
	if err := repo.Create(&row); err != nil {
		t.Fatal(err)
	}
	script, err := jsplugin.CompileWithMetadata(row.Name, row.Source, jsplugin.ScriptOptions{}, jsplugin.ScriptMetadata{ID: row.ID, Stage: row.Stage, FailureMode: row.FailureMode})
	if err != nil {
		t.Fatal(err)
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{JSPlugins: []*jsplugin.Script{script}})
	engine, err := jsplugin.NewEngine(jsplugin.EngineOptions{PoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	ctx := invokeThreatIntelHandler(t, GetJSPluginRuntime(repo, holder, func() *jsplugin.Engine { return engine }), "GET", "/x", nil, nil)
	var status jsPluginRuntimeStatus
	if err := json.Unmarshal(ctx.Response.Body(), &status); err != nil {
		t.Fatal(err)
	}
	if ctx.Response.StatusCode() != 200 || status.Backend != jsplugin.BackendQuickJS || !status.Available || !status.EngineReady || status.Enabled != 1 || status.Compiled != 1 || status.CompileErrors != 0 || !status.RequestSupported || !status.ResponseSupported {
		t.Fatalf("status=%d runtime=%+v", ctx.Response.StatusCode(), status)
	}
}
