package system

import (
	"encoding/json"
	"errors"
	"testing"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/jsplugin"
)

var errTestStatsFault = errors.New("jsplugin: mutation plan contains unknown field \"status_code\"")

// statsScript 构造一个带元数据的脚本；无 QuickJS 的构建同样可用。
func statsScript(t *testing.T, id uint, stage string) *jsplugin.Script {
	t.Helper()
	script, err := jsplugin.CompileWithMetadata(
		"stats-fault",
		`export default {fetch() { return {}; }}`,
		jsplugin.ScriptOptions{},
		jsplugin.ScriptMetadata{ID: id, Stage: stage, FailureMode: store.JSFailureModeOpen},
	)
	if err != nil {
		// 无 cgo 构建下 CompileWithMetadata 返回 ErrCGODisabled：失败记录与执行
		// 后端无关，退回一个零值脚本继续验证管理端读数。
		if !errors.Is(err, jsplugin.ErrCGODisabled) {
			t.Fatalf("CompileWithMetadata error = %v", err)
		}
		return jsplugin.NewScriptForTest(id, "stats-fault", stage, store.JSFailureModeOpen)
	}
	return script
}

// TestGetJSPluginStatsReportsLastError 锁定管理端可发现性：脚本失败必须在
// 统计端点回显，用户才能不改数据面日志就看到「脚本上次执行错误」。
func TestGetJSPluginStatsReportsLastError(t *testing.T) {
	script := statsScript(t, 21, store.JSStageRequest)
	jsplugin.ObserveScriptFault(&jsplugin.Engine{}, script, store.JSStageResponse, errTestStatsFault)

	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{JSPlugins: []*jsplugin.Script{script}})
	ctx := invokeThreatIntelHandler(t, GetJSPluginStats(holder), "GET", "/x", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status = %d, want 200", ctx.Response.StatusCode())
	}
	var body struct {
		Items []jsPluginStatsItem `json:"items"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &body); err != nil {
		t.Fatalf("decode stats body: %v", err)
	}
	if len(body.Items) != 1 {
		t.Fatalf("items = %#v, want 1", body.Items)
	}
	item := body.Items[0]
	if item.LastError != errTestStatsFault.Error() {
		t.Fatalf("last_error = %q, want %q", item.LastError, errTestStatsFault.Error())
	}
	if item.LastErrorStage != store.JSStageResponse {
		t.Fatalf("last_error_stage = %q, want %q", item.LastErrorStage, store.JSStageResponse)
	}
	if item.LastErrorCount != 1 {
		t.Fatalf("last_error_count = %d, want 1", item.LastErrorCount)
	}
	if item.LastErrorAt == "" {
		t.Fatal("last_error_at is empty, want timestamp")
	}
}

// TestGetJSPluginStatsOmitsLastErrorWhenHealthy 确认从未失败的脚本不产生
// last_error 字段，前端表格据此留空而不是显示零值时间。
func TestGetJSPluginStatsOmitsLastErrorWhenHealthy(t *testing.T) {
	script := statsScript(t, 22, store.JSStageResponse)
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{JSPlugins: []*jsplugin.Script{script}})
	ctx := invokeThreatIntelHandler(t, GetJSPluginStats(holder), "GET", "/x", nil, nil)
	var body struct {
		Items []jsPluginStatsItem `json:"items"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &body); err != nil {
		t.Fatalf("decode stats body: %v", err)
	}
	if len(body.Items) != 1 {
		t.Fatalf("items = %#v, want 1", body.Items)
	}
	if body.Items[0].LastError != "" || body.Items[0].LastErrorStage != "" || body.Items[0].LastErrorAt != "" {
		t.Fatalf("healthy script reported last error: %#v", body.Items[0])
	}
}
