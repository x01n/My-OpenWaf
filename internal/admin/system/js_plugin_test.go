package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/jsplugin"
)

func newJSPluginRepoForTest(t *testing.T) *repository.JSPluginRepo {
	t.Helper()
	return repository.NewJSPluginRepo(newJSPluginDBForTest(t))
}

func newJSPluginDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.JSPlugin{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestJSPluginInputLimitsAndUTF8Validation(t *testing.T) {
	validName := strings.Repeat("界", 128)
	validDescription := strings.Repeat("描", 512)
	validSource := strings.Repeat("x", jsplugin.MaxScriptBytes)
	base := store.JSPlugin{Name: "original", Source: "original-source", Stage: store.JSStageRequest, FailureMode: store.JSFailureModeOpen, Description: "original-description"}

	tests := []struct {
		name     string
		req      jsPluginRequest
		wantErr  string
		wantItem store.JSPlugin
	}{
		{name: "boundary values accepted", req: jsPluginRequest{Name: validName, Source: validSource, Description: &validDescription}, wantItem: store.JSPlugin{Name: validName, Source: validSource, Stage: store.JSStageRequest, FailureMode: store.JSFailureModeOpen, Description: validDescription}},
		{name: "name rune limit", req: jsPluginRequest{Name: validName + "界"}, wantErr: "name must be at most 128 characters"},
		{name: "description rune limit", req: jsPluginRequest{Description: ptrString(validDescription + "描")}, wantErr: "description must be at most 512 characters"},
		{name: "source byte limit", req: jsPluginRequest{Source: validSource + "x"}, wantErr: "source must be at most 262144 bytes"},
		{name: "invalid name utf8", req: jsPluginRequest{Name: string([]byte{0xff})}, wantErr: "name must be valid UTF-8"},
		{name: "invalid description utf8", req: jsPluginRequest{Description: ptrString(string([]byte{0xff}))}, wantErr: "description must be valid UTF-8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			item := base
			before := item
			gotErr := applyJSPluginRequest(&item, tt.req, false)
			if gotErr != tt.wantErr {
				t.Fatalf("error = %q, want %q", gotErr, tt.wantErr)
			}
			if tt.wantErr != "" {
				if !reflect.DeepEqual(item, before) {
					t.Fatalf("validation failure mutated item: before=%+v after=%+v", before, item)
				}
				return
			}
			if item.Name != tt.wantItem.Name || item.Source != tt.wantItem.Source || item.Description != tt.wantItem.Description {
				t.Fatalf("updated item fields = name %q, source length %d, description length %d", item.Name, len(item.Source), len([]rune(item.Description)))
			}
		})
	}
}

func TestUpdateJSPluginValidationFailureKeepsPersistedItem(t *testing.T) {
	repo := newJSPluginRepoForTest(t)
	item := store.JSPlugin{Name: "edge", Source: "source", Stage: store.JSStageResponse, Enabled: true, Priority: 10, FailureMode: store.JSFailureModeOpen, Description: "description"}
	if err := repo.Create(&item); err != nil {
		t.Fatal(err)
	}

	req := jsPluginRequest{Name: strings.Repeat("界", 129), Priority: ptrInt(1)}
	if errMsg := applyJSPluginRequest(&item, req, false); errMsg == "" {
		t.Fatal("expected invalid name")
	}
	got, err := repo.Get(item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "edge" || got.Priority != 10 {
		t.Fatalf("persisted item changed after rejected update: %+v", got)
	}
}

func ptrString(value string) *string { return &value }

func ptrInt(value int) *int { return &value }

func TestCreateJSPluginPersistsAndReloads(t *testing.T) {
	repo := newJSPluginRepoForTest(t)
	reloaded := 0
	body, _ := json.Marshal(map[string]any{
		"name": "edge-request", "source": "return 1", "stage": "request",
		"failure_mode": "fail_closed", "priority": 7, "timeout_ms": 35,
	})
	ctx := invokeThreatIntelHandler(t, CreateJSPlugin(repo, nil, func() error { reloaded++; return nil }), "POST", "/api/v1/js-plugins", nil, body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("want 201, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloaded != 1 {
		t.Fatalf("reload count = %d, want 1", reloaded)
	}
	items, err := repo.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("persisted items = %d, err=%v", len(items), err)
	}
	if items[0].Stage != store.JSStageRequest || items[0].FailureMode != store.JSFailureModeClosed || items[0].TimeoutMS != 35 {
		t.Fatalf("persisted fields = %+v", items[0])
	}
}

// TestJSPluginReadResponsesAttachCompileErrorsByStableID 固定列表与单项响应都按脚本 ID
// 关联当前 snapshot 的编译或元数据错误，同名脚本不得互相污染。
func TestJSPluginReadResponsesAttachCompileErrorsByStableID(t *testing.T) {
	repo := newJSPluginRepoForTest(t)
	failed := store.JSPlugin{
		Name:        "duplicate-name",
		Source:      "broken",
		Enabled:     true,
		Priority:    10,
		Stage:       store.JSStageRequest,
		FailureMode: store.JSFailureModeOpen,
	}
	healthy := failed
	healthy.Source = "healthy"
	healthy.Priority = 20
	if err := repo.Create(&failed); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(&healthy); err != nil {
		t.Fatal(err)
	}

	const compileError = "unsupported stage metadata"
	holder := &snapshotpkg.Holder{}
	holder.Store(&snapshotpkg.Snapshot{JSPluginErrors: map[string]string{
		snapshotpkg.JSPluginErrorKey(failed.ID): compileError,
	}})

	listCtx := invokeThreatIntelHandler(t, ListJSPlugins(repo, holder), "GET", "/x", nil, nil)
	if listCtx.Response.StatusCode() != 200 {
		t.Fatalf("list status = %d; body=%s", listCtx.Response.StatusCode(), bytes.TrimSpace(listCtx.Response.Body()))
	}
	var listResponse struct {
		Items []jsPluginItemResponse `json:"items"`
		Total int                    `json:"total"`
	}
	if err := json.Unmarshal(listCtx.Response.Body(), &listResponse); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if listResponse.Total != 2 || len(listResponse.Items) != 2 {
		t.Fatalf("list response = %#v", listResponse)
	}
	if listResponse.Items[0].ID != failed.ID || listResponse.Items[0].CompileError != compileError {
		t.Fatalf("failed list item = %#v", listResponse.Items[0])
	}
	if listResponse.Items[1].ID != healthy.ID || listResponse.Items[1].CompileError != "" {
		t.Fatalf("healthy list item = %#v", listResponse.Items[1])
	}

	failedCtx := invokeThreatIntelHandler(t, GetJSPlugin(repo, holder), "GET", "/x", idParam(failed.ID), nil)
	var failedResponse jsPluginItemResponse
	if err := json.Unmarshal(failedCtx.Response.Body(), &failedResponse); err != nil {
		t.Fatalf("decode failed item response: %v", err)
	}
	if failedResponse.CompileError != compileError {
		t.Fatalf("failed item build error = %q, want %q", failedResponse.CompileError, compileError)
	}

	healthyCtx := invokeThreatIntelHandler(t, GetJSPlugin(repo, holder), "GET", "/x", idParam(healthy.ID), nil)
	var healthyResponse jsPluginItemResponse
	if err := json.Unmarshal(healthyCtx.Response.Body(), &healthyResponse); err != nil {
		t.Fatalf("decode healthy item response: %v", err)
	}
	if healthyResponse.CompileError != "" {
		t.Fatalf("healthy item inherited duplicate-name error: %#v", healthyResponse)
	}
}

// TestCreateJSPluginReloadFailureIncludesCurrentCompileDiagnostic 固定重载失败响应保留
// 当前 snapshot 的编译诊断，前端可以在保存失败后直接定位问题。
func TestCreateJSPluginReloadFailureIncludesCurrentCompileDiagnostic(t *testing.T) {
	repo := newJSPluginRepoForTest(t)
	holder := &snapshotpkg.Holder{}
	const compileError = "jsplugin: unexpected token"
	const reloadError = "snapshot reload failed"
	handler := CreateJSPlugin(repo, holder, func() error {
		items, err := repo.List()
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 {
			t.Fatalf("persisted items = %d, want 1", len(items))
		}
		holder.Store(&snapshotpkg.Snapshot{JSPluginErrors: map[string]string{
			snapshotpkg.JSPluginErrorKey(items[0].ID): compileError,
		}})
		return errors.New(reloadError)
	})
	body := []byte(`{"name":"broken","source":"export default { fetch() { return {}; } }","stage":"request","failure_mode":"fail_closed"}`)
	ctx := invokeThreatIntelHandler(t, handler, "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("status = %d; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var response struct {
		ReloadError string               `json:"reload_error"`
		Item        jsPluginItemResponse `json:"item"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode reload failure response: %v", err)
	}
	if response.ReloadError != reloadError {
		t.Fatalf("reload error = %q, want %q", response.ReloadError, reloadError)
	}
	if response.Item.CompileError != compileError {
		t.Fatalf("compile error = %q, want %q", response.Item.CompileError, compileError)
	}
}

func TestCreateJSPluginRejectsInvalidContract(t *testing.T) {
	repo := newJSPluginRepoForTest(t)
	cases := []string{
		`{"source":"x","stage":"request","failure_mode":"fail_open"}`,
		`{"name":"x","source":"x","stage":"pre","failure_mode":"fail_open"}`,
		`{"name":"x","source":"x","stage":"request","failure_mode":"closed"}`,
		`{"name":"x","source":"x","stage":"response","failure_mode":"fail_open","timeout_ms":1001}`,
	}
	for _, raw := range cases {
		ctx := invokeThreatIntelHandler(t, CreateJSPlugin(repo, nil, func() error { return nil }), "POST", "/x", nil, []byte(raw))
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("invalid body %s: status=%d", raw, ctx.Response.StatusCode())
		}
	}
	items, _ := repo.List()
	if len(items) != 0 {
		t.Fatalf("invalid scripts persisted: %d", len(items))
	}
}

func TestUpdateJSPluginPreservesFieldsAndParsesSiteScope(t *testing.T) {
	repo := newJSPluginRepoForTest(t)
	siteID := uint(9)
	item := store.JSPlugin{Name: "edge", Source: "x", Stage: store.JSStageRequest, Enabled: true, Priority: 10, SiteID: &siteID, FailureMode: store.JSFailureModeOpen}
	if err := repo.Create(&item); err != nil {
		t.Fatal(err)
	}
	handler := UpdateJSPlugin(repo, nil, func() error { return nil })
	invokeThreatIntelHandler(t, handler, "POST", "/x", idParam(item.ID), []byte(`{"priority":2}`))
	got, _ := repo.Get(item.ID)
	if got.Priority != 2 || got.SiteID == nil || *got.SiteID != 9 {
		t.Fatalf("partial update lost fields: %+v", got)
	}
	invokeThreatIntelHandler(t, handler, "POST", "/x", idParam(item.ID), []byte(`{"site_id":null}`))
	got, _ = repo.Get(item.ID)
	if got.SiteID != nil {
		t.Fatalf("site_id null should clear scope: %+v", got.SiteID)
	}
}

func TestJSPluginResponseStageCannotBeConfigured(t *testing.T) {
	repo := newJSPluginRepoForTest(t)
	reloaded := 0
	reload := func() error {
		reloaded++
		return nil
	}

	ctx := invokeThreatIntelHandler(t, CreateJSPlugin(repo, nil, reload), "POST", "/x", nil, []byte(`{"name":"response","source":"x","stage":"response","failure_mode":"fail_open"}`))
	if ctx.Response.StatusCode() != 400 || !bytes.Contains(ctx.Response.Body(), []byte(jsResponseStageUnavailableMessage)) {
		t.Fatalf("create response stage = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	items, err := repo.List()
	if err != nil || len(items) != 0 {
		t.Fatalf("response stage create persisted items=%d err=%v", len(items), err)
	}

	requestPlugin := store.JSPlugin{Name: "request", Source: "x", Stage: store.JSStageRequest, Enabled: true, Priority: 10, FailureMode: store.JSFailureModeOpen}
	if err := repo.Create(&requestPlugin); err != nil {
		t.Fatal(err)
	}
	ctx = invokeThreatIntelHandler(t, UpdateJSPlugin(repo, nil, reload), "POST", "/x", idParam(requestPlugin.ID), []byte(`{"stage":"response"}`))
	if ctx.Response.StatusCode() != 400 || !bytes.Contains(ctx.Response.Body(), []byte(jsResponseStageUnavailableMessage)) {
		t.Fatalf("update to response stage = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	got, err := repo.Get(requestPlugin.ID)
	if err != nil || got.Stage != store.JSStageRequest {
		t.Fatalf("request plugin changed after rejected update: %+v, err=%v", got, err)
	}

	legacyResponsePlugin := store.JSPlugin{Name: "legacy-response", Source: "x", Stage: store.JSStageResponse, Enabled: false, Priority: 10, FailureMode: store.JSFailureModeOpen}
	if err := repo.Create(&legacyResponsePlugin); err != nil {
		t.Fatal(err)
	}
	ctx = invokeThreatIntelHandler(t, UpdateJSPlugin(repo, nil, reload), "POST", "/x", idParam(legacyResponsePlugin.ID), []byte(`{"priority":2}`))
	if ctx.Response.StatusCode() != 400 || !bytes.Contains(ctx.Response.Body(), []byte(jsResponseStageUnavailableMessage)) {
		t.Fatalf("update legacy response stage = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	got, err = repo.Get(legacyResponsePlugin.ID)
	if err != nil || got.Priority != 10 {
		t.Fatalf("legacy response plugin changed after rejected update: %+v, err=%v", got, err)
	}

	ctx = invokeThreatIntelHandler(t, ToggleJSPlugin(repo, reload), "POST", "/x", idParam(legacyResponsePlugin.ID), []byte(`{"enabled":true}`))
	if ctx.Response.StatusCode() != 400 || !bytes.Contains(ctx.Response.Body(), []byte(jsResponseStageUnavailableMessage)) {
		t.Fatalf("enable response stage = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	got, err = repo.Get(legacyResponsePlugin.ID)
	if err != nil || got.Enabled {
		t.Fatalf("legacy response plugin enabled after rejected toggle: %+v, err=%v", got, err)
	}
	if reloaded != 0 {
		t.Fatalf("reloaded %d times for rejected response stage requests", reloaded)
	}
}

// TestJSPluginRuntimeEndpointsRejectInvalidStage 固定 stage 校验先于运行时装配。
//
// 空请求体在两个端点都必须停在 400，否则未装配运行时会掩盖入参错误。
func TestJSPluginRuntimeEndpointsRejectInvalidStage(t *testing.T) {
	validate := invokeThreatIntelHandler(t, ValidateJSPlugin(), "POST", "/x", nil, []byte(`{}`))
	if validate.Response.StatusCode() != 400 || !bytes.Contains(validate.Response.Body(), []byte("stage must be request")) {
		t.Fatalf("validate response = %d %s", validate.Response.StatusCode(), validate.Response.Body())
	}
	dryRun := invokeThreatIntelHandler(t, DryRunJSPlugin(nil), "POST", "/x", nil, []byte(`{}`))
	if dryRun.Response.StatusCode() != 400 || !bytes.Contains(dryRun.Response.Body(), []byte("stage must be request or response")) {
		t.Fatalf("dry-run response = %d %s", dryRun.Response.StatusCode(), dryRun.Response.Body())
	}
}

func TestValidateJSPluginRejectsUnavailableStageAndTimeout(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want string
	}{
		{
			name: "response stage",
			body: []byte(`{"stage":"response","source":"export default {}"}`),
			want: jsResponseStageUnavailableMessage,
		},
		{
			name: "negative timeout",
			body: []byte(`{"stage":"request","source":"export default {}","timeout_ms":-1}`),
			want: "timeout_ms must be between 0 and 1000",
		},
		{
			name: "timeout above maximum",
			body: []byte(`{"stage":"request","source":"export default {}","timeout_ms":1001}`),
			want: "timeout_ms must be between 0 and 1000",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := invokeThreatIntelHandler(t, ValidateJSPlugin(), "POST", "/x", nil, tc.body)
			if ctx.Response.StatusCode() != 400 || !bytes.Contains(ctx.Response.Body(), []byte(tc.want)) {
				t.Fatalf("validate response = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
			}
		})
	}
}

// TestDryRunJSPluginValidatesTimeoutBeforeEngine 固定超时范围校验的优先级。
func TestDryRunJSPluginValidatesTimeoutBeforeEngine(t *testing.T) {
	body := []byte(`{"stage":"request","source":"export default {}","timeout_ms":1001}`)
	ctx := invokeThreatIntelHandler(t, DryRunJSPlugin(nil), "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 400 || !bytes.Contains(ctx.Response.Body(), []byte("timeout_ms must be between 0 and 1000")) {
		t.Fatalf("dry-run response = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
}

// TestDryRunJSPluginWithoutEngineReportsUnavailable 固定 engine 为 nil 时不 panic
// 且返回明确的运行时不可用，而不是伪装成一次成功执行。
func TestDryRunJSPluginWithoutEngineReportsUnavailable(t *testing.T) {
	body := []byte(`{"stage":"request","source":"export default {}"}`)
	ctx := invokeThreatIntelHandler(t, DryRunJSPlugin(nil), "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 503 || !bytes.Contains(ctx.Response.Body(), []byte(jsRuntimeUnavailableMessage)) {
		t.Fatalf("dry-run response = %d %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
}

// TestGetJSPluginStatsReturnsEmptyList 固定统计端点是常规读端点。
//
// 脚本集合尚未由 snapshot 接入，空集合不等于运行时故障，故必须是 200 而非 503。
func TestGetJSPluginStatsReturnsEmptyList(t *testing.T) {
	stats := invokeThreatIntelHandler(t, GetJSPluginStats(nil), "GET", "/x", nil, nil)
	if stats.Response.StatusCode() != 200 || !bytes.Contains(stats.Response.Body(), []byte(`"items":[]`)) {
		t.Fatalf("stats response = %d %s", stats.Response.StatusCode(), stats.Response.Body())
	}
}

// TestBuildJSDryRunSnapshotMapsSampleFields 固定 sample_request 到
// jsplugin.RequestSnapshot 的键名映射，非字符串值必须被跳过而非强转。
func TestBuildJSDryRunSnapshotMapsSampleFields(t *testing.T) {
	got := buildJSDryRunSnapshot(map[string]any{
		"method":       "POST",
		"path":         "/api/login",
		"raw_query":    "a=1",
		"host":         "example.test",
		"client_ip":    "203.0.113.9",
		"user_agent":   "curl/8.0",
		"content_type": "application/json",
		"body":         `{"x":1}`,
		"headers":      map[string]any{"X-Trace": "abc", "X-Skipped": 42},
		"query_params": map[string]any{"a": "1"},
	})
	if got.RequestID != "dry-run" || got.SiteID != 0 {
		t.Fatalf("request id / site scope = %q / %d", got.RequestID, got.SiteID)
	}
	if got.Method != "POST" || got.Path != "/api/login" || got.RawQuery != "a=1" || got.Host != "example.test" {
		t.Fatalf("scalar mapping = %+v", got)
	}
	if got.ClientIP != "203.0.113.9" || got.UserAgent != "curl/8.0" || got.ContentType != "application/json" || got.Body != `{"x":1}` {
		t.Fatalf("scalar mapping = %+v", got)
	}
	if len(got.Headers) != 1 || got.Headers["X-Trace"] != "abc" {
		t.Fatalf("headers = %+v, non-string values must be skipped", got.Headers)
	}
	if len(got.QueryParams) != 1 || got.QueryParams["a"] != "1" {
		t.Fatalf("query params = %+v", got.QueryParams)
	}
}

// TestBuildJSDryRunSnapshotIgnoresWrongTypes 固定类型不符时不写入字段。
func TestBuildJSDryRunSnapshotIgnoresWrongTypes(t *testing.T) {
	got := buildJSDryRunSnapshot(map[string]any{
		"method":       42,
		"path":         nil,
		"headers":      "not-an-object",
		"query_params": map[string]any{"a": 1},
	})
	if got.Method != "" || got.Path != "" || got.Headers != nil || got.QueryParams != nil {
		t.Fatalf("wrong-typed sample fields leaked into snapshot: %+v", got)
	}
}
