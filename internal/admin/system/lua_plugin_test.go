package system

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/luaplugin"
)

func newLuaPluginRepoForTest(t *testing.T) *repository.LuaPluginRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.LuaPlugin{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return repository.NewLuaPluginRepo(db)
}

const validLuaSource = `function handle(ctx) return nil end`

type luaTestKV struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newLuaTestKV() *luaTestKV {
	return &luaTestKV{data: map[string][]byte{}}
}

func (k *luaTestKV) Available() bool { return true }

func (k *luaTestKV) Get(key string) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.data[key]
	return v, ok
}

func (k *luaTestKV) Set(key string, value []byte, _ time.Duration) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.data[key] = append([]byte(nil), value...)
	return nil
}

func (k *luaTestKV) Delete(key string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.data, key)
}

func (k *luaTestKV) Incr(key string, _ time.Duration) (int64, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := int64(1)
	if raw, ok := k.data[key]; ok {
		if parsed, err := strconv.ParseInt(string(raw), 10, 64); err == nil {
			n = parsed + 1
		}
	}
	k.data[key] = []byte(strconv.FormatInt(n, 10))
	return n, nil
}

func idParam(id uint) param.Params {
	return param.Params{{Key: "id", Value: strconv.FormatUint(uint64(id), 10)}}
}

// ---- 创建：编译校验 ----

// TestCreateLuaPluginRejectsSyntaxError 是核心校验：
// 语法错误必须在保存时就被拦截，而不是等到 reload 才发现——
// 后者会让用户以为保存成功、实际策略从未生效。
func TestCreateLuaPluginRejectsSyntaxError(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	reloaded := 0
	body, _ := json.Marshal(map[string]any{
		"name":   "bad",
		"stage":  "pre",
		"source": `function handle( end`,
	})

	ctx := invokeThreatIntelHandler(t, CreateLuaPlugin(repo, func() error { reloaded++; return nil }),
		"POST", "/api/v1/lua-plugins", nil, body)

	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("语法错误应返回 400，得到 %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloaded != 0 {
		t.Error("校验失败时不应触发 reload")
	}
	items, _ := repo.List()
	if len(items) != 0 {
		t.Error("校验失败的脚本不应入库")
	}
}

func TestCreateLuaPluginRequiresFields(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	handler := CreateLuaPlugin(repo, func() error { return nil })

	cases := []struct {
		name string
		body map[string]any
	}{
		{"缺 name", map[string]any{"stage": "pre", "source": validLuaSource}},
		{"缺 stage", map[string]any{"name": "x", "source": validLuaSource}},
		{"缺 source", map[string]any{"name": "x", "stage": "pre"}},
		{"非法 stage", map[string]any{"name": "x", "stage": "middle", "source": validLuaSource}},
	}
	for _, tt := range cases {
		body, _ := json.Marshal(tt.body)
		ctx := invokeThreatIntelHandler(t, handler, "POST", "/api/v1/lua-plugins", nil, body)
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("%s: 应返回 400，得到 %d", tt.name, ctx.Response.StatusCode())
		}
	}
}

func TestCreateLuaPluginRejectsOverlongMetadata(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	handler := CreateLuaPlugin(repo, func() error { return nil })
	cases := []map[string]any{
		{"name": strings.Repeat("n", 129), "stage": "pre", "source": validLuaSource},
		{"name": "valid", "stage": "pre", "source": validLuaSource, "description": strings.Repeat("d", 513)},
	}
	for _, request := range cases {
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		ctx := invokeThreatIntelHandler(t, handler, "POST", "/x", nil, body)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("overlong metadata should return 400, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
		}
	}
	items, err := repo.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("invalid metadata must not persist, got %d items", len(items))
	}
}

func TestCreateLuaPluginPersistsAndReloads(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	reloaded := 0
	body, _ := json.Marshal(map[string]any{
		"name":        "block-scanner",
		"stage":       "pre",
		"source":      validLuaSource,
		"priority":    50,
		"description": "拦截扫描器",
	})

	ctx := invokeThreatIntelHandler(t, CreateLuaPlugin(repo, func() error { reloaded++; return nil }),
		"POST", "/api/v1/lua-plugins", nil, body)

	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("want 201, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloaded != 1 {
		t.Errorf("应触发一次 reload，实际 %d 次", reloaded)
	}

	var got store.LuaPlugin
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Name != "block-scanner" || got.Stage != "pre" || got.Priority != 50 {
		t.Errorf("字段未正确保存: %+v", got)
	}
	if !got.Enabled {
		t.Error("默认应为启用")
	}
}

// TestCreateLuaPluginHonorsExplicitDisabled 验证显式禁用被持久化。
//
// Enabled 带 gorm default:true，插入 false 会被当作零值改用默认值，
// repo 需在插入后回写该列（今天在 access 相关表上修过同类缺陷）。
func TestCreateLuaPluginHonorsExplicitDisabled(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	body, _ := json.Marshal(map[string]any{
		"name": "disabled", "stage": "post", "source": validLuaSource, "enabled": false,
	})

	ctx := invokeThreatIntelHandler(t, CreateLuaPlugin(repo, func() error { return nil }),
		"POST", "/api/v1/lua-plugins", nil, body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("want 201, got %d", ctx.Response.StatusCode())
	}

	items, _ := repo.List()
	if len(items) != 1 {
		t.Fatalf("应有 1 条，得到 %d", len(items))
	}
	if items[0].Enabled {
		t.Error("显式 enabled=false 必须被持久化，而非被 gorm 默认值覆盖")
	}
}

func TestCreateLuaPluginRejectsExcessiveTimeout(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	body, _ := json.Marshal(map[string]any{
		"name": "slow", "stage": "pre", "source": validLuaSource, "timeout_ms": luaMaxTimeoutMS + 1,
	})
	ctx := invokeThreatIntelHandler(t, CreateLuaPlugin(repo, func() error { return nil }),
		"POST", "/api/v1/lua-plugins", nil, body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("超限 timeout 应返回 400，得到 %d", ctx.Response.StatusCode())
	}
}

// ---- 更新 ----

func TestUpdateLuaPluginPartialFields(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	seed := store.LuaPlugin{Name: "orig", Stage: "pre", Source: validLuaSource, Enabled: true, Priority: 100}
	if err := repo.Create(&seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	body, _ := json.Marshal(map[string]any{"priority": 10})
	ctx := invokeThreatIntelHandler(t, UpdateLuaPlugin(repo, func() error { return nil }),
		"POST", "/api/v1/lua-plugins/1/update", idParam(seed.ID), body)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	got, _ := repo.Get(seed.ID)
	if got.Priority != 10 {
		t.Errorf("Priority = %d, want 10", got.Priority)
	}
	if got.Name != "orig" {
		t.Errorf("未提供的字段应保持原值，Name = %q", got.Name)
	}
}

// TestUpdateLuaPluginSiteScopeTriState 验证 site_id 的三态语义。
//
// 未提供保持原值、显式 null 改回全站、具体值绑定站点。
// **uint 在 Go 里做不到这点（encoding/json 对 null 的语义是「不修改目标」），
// 故用 json.RawMessage — 今天在 iplist/threat_intel 上修过同一问题。
func TestUpdateLuaPluginSiteScopeTriState(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	siteID := uint(9)
	seed := store.LuaPlugin{Name: "s", Stage: "pre", Source: validLuaSource, Enabled: true, SiteID: &siteID}
	if err := repo.Create(&seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	handler := UpdateLuaPlugin(repo, func() error { return nil })

	// 未提供 site_id：保持原值。
	body, _ := json.Marshal(map[string]any{"priority": 20})
	invokeThreatIntelHandler(t, handler, "POST", "/x", idParam(seed.ID), body)
	if got, _ := repo.Get(seed.ID); got.SiteID == nil || *got.SiteID != 9 {
		t.Fatal("未提供 site_id 时应保持原值")
	}

	// 显式 null：改回全站。
	invokeThreatIntelHandler(t, handler, "POST", "/x", idParam(seed.ID), []byte(`{"site_id":null}`))
	if got, _ := repo.Get(seed.ID); got.SiteID != nil {
		t.Fatalf("显式 null 应改回全站，得到 site_id=%d", *got.SiteID)
	}

	// 具体值：绑定站点。
	invokeThreatIntelHandler(t, handler, "POST", "/x", idParam(seed.ID), []byte(`{"site_id":3}`))
	if got, _ := repo.Get(seed.ID); got.SiteID == nil || *got.SiteID != 3 {
		t.Fatal("应绑定到站点 3")
	}
}

func TestUpdateLuaPluginRejectsBadSourceAndMissingID(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	seed := store.LuaPlugin{Name: "s", Stage: "pre", Source: validLuaSource, Enabled: true}
	if err := repo.Create(&seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	handler := UpdateLuaPlugin(repo, func() error { return nil })

	bad, _ := json.Marshal(map[string]any{"source": `function handle( end`})
	if ctx := invokeThreatIntelHandler(t, handler, "POST", "/x", idParam(seed.ID), bad); ctx.Response.StatusCode() != 400 {
		t.Errorf("语法错误应返回 400，得到 %d", ctx.Response.StatusCode())
	}
	if ctx := invokeThreatIntelHandler(t, handler, "POST", "/x", idParam(9999), []byte(`{}`)); ctx.Response.StatusCode() != 404 {
		t.Errorf("不存在应返回 404，得到 %d", ctx.Response.StatusCode())
	}
}

// ---- 删除与切换 ----

func TestDeleteLuaPlugin(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	seed := store.LuaPlugin{Name: "s", Stage: "pre", Source: validLuaSource, Enabled: true}
	if err := repo.Create(&seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	reloaded := 0
	ctx := invokeThreatIntelHandler(t, DeleteLuaPlugin(repo, func() error { reloaded++; return nil }),
		"POST", "/x", idParam(seed.ID), nil)

	if ctx.Response.StatusCode() != 204 {
		t.Fatalf("want 204, got %d", ctx.Response.StatusCode())
	}
	if reloaded != 1 {
		t.Errorf("应触发 reload")
	}
	if items, _ := repo.List(); len(items) != 0 {
		t.Error("应已删除")
	}
}

func TestToggleLuaPlugin(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	seed := store.LuaPlugin{Name: "s", Stage: "pre", Source: validLuaSource, Enabled: true}
	if err := repo.Create(&seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	handler := ToggleLuaPlugin(repo, func() error { return nil })

	// 无 body：翻转。
	ctx := invokeThreatIntelHandler(t, handler, "POST", "/x", idParam(seed.ID), nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if got, _ := repo.Get(seed.ID); got.Enabled {
		t.Error("应被翻转为禁用")
	}

	// 显式指定。
	invokeThreatIntelHandler(t, handler, "POST", "/x", idParam(seed.ID), []byte(`{"enabled":true}`))
	if got, _ := repo.Get(seed.ID); !got.Enabled {
		t.Error("应被显式启用")
	}
}

// ---- 校验与试运行 ----

func TestValidateLuaPluginEndpoint(t *testing.T) {
	handler := ValidateLuaPlugin()

	ok, _ := json.Marshal(map[string]any{"stage": "pre", "source": validLuaSource})
	ctx := invokeThreatIntelHandler(t, handler, "POST", "/x", nil, ok)
	var okResp struct {
		Valid bool `json:"valid"`
	}
	json.Unmarshal(ctx.Response.Body(), &okResp)
	if !okResp.Valid {
		t.Errorf("合法脚本应通过校验: %s", ctx.Response.Body())
	}

	bad, _ := json.Marshal(map[string]any{"stage": "pre", "source": `function handle( end`})
	ctx2 := invokeThreatIntelHandler(t, handler, "POST", "/x", nil, bad)
	var badResp struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	json.Unmarshal(ctx2.Response.Body(), &badResp)
	if badResp.Valid || badResp.Error == "" {
		t.Errorf("语法错误应返回 valid=false 与错误信息: %s", ctx2.Response.Body())
	}
}

// TestDryRunLuaPluginReturnsDecision 验证试运行能返回脚本对样例请求的判定。
//
// 策略脚本的错误往往只在真实请求形态下暴露，光有语法校验不够。
func TestDryRunLuaPluginReturnsDecision(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"stage": "pre",
		"source": `
function handle(ctx)
  if ctx.path == "/admin" and ctx.user_agent == "curl/8.0" then
    return {action="intercept", message="blocked"}
  end
  return nil
end`,
		"request": map[string]any{
			"path":       "/admin",
			"user_agent": "curl/8.0",
			"method":     "GET",
		},
	})

	ctx := invokeThreatIntelHandler(t, DryRunLuaPlugin(), "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		CompileError string `json:"compile_error"`
		RuntimeError string `json:"runtime_error"`
		Decision     struct {
			Action  string `json:"Action"`
			Message string `json:"Message"`
		} `json:"decision"`
		ElapsedMS float64 `json:"elapsed_ms"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.CompileError != "" || resp.RuntimeError != "" {
		t.Fatalf("不应有错误: compile=%q runtime=%q", resp.CompileError, resp.RuntimeError)
	}
	if resp.Decision.Action != "intercept" {
		t.Errorf("Action = %q, want intercept", resp.Decision.Action)
	}
	if resp.Decision.Message != "blocked" {
		t.Errorf("Message = %q, want blocked", resp.Decision.Message)
	}
}

// TestDryRunLuaPluginReportsCompileError 验证试运行会报告编译错误而非 500。
func TestDryRunLuaPluginDoesNotUseProductionKV(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"stage":      "pre",
		"iterations": 2,
		"source": `
function handle(ctx)
  if ctx.kv.available() then
    return {action="intercept", message="production KV was exposed"}
  end
  local ok = ctx.kv.set("rl:" .. ctx.client_ip, "1", 60)
  if ok then
    return {action="intercept", message="dry-run wrote KV"}
  end
  return nil
end`,
		"request": map[string]any{"client_ip": "203.0.113.7", "method": "GET", "path": "/"},
	})
	ctx := invokeThreatIntelHandler(t, DryRunLuaPlugin(), "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		KVAvailable bool `json:"kv_available"`
		Decision    struct {
			Action string `json:"Action"`
		} `json:"decision"`
		Runs []struct {
			Decision struct {
				Action string `json:"Action"`
			} `json:"decision"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.KVAvailable {
		t.Fatalf("dry-run must not expose production KV: %s", ctx.Response.Body())
	}
	if resp.Decision.Action != "" || len(resp.Runs) != 2 || resp.Runs[0].Decision.Action != "" || resp.Runs[1].Decision.Action != "" {
		t.Fatalf("KV-dependent dry-run must produce no decision: %s", ctx.Response.Body())
	}
}

func TestDryRunLuaPluginReportsCompileError(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"stage": "pre", "source": `function handle( end`,
	})
	ctx := invokeThreatIntelHandler(t, DryRunLuaPlugin(), "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("试运行本身不应失败，want 200, got %d", ctx.Response.StatusCode())
	}
	var resp struct {
		CompileError string `json:"compile_error"`
	}
	json.Unmarshal(ctx.Response.Body(), &resp)
	if resp.CompileError == "" {
		t.Error("应报告编译错误")
	}
}

// TestDryRunLuaPluginTimesOut 验证死循环脚本在试运行中被中断而非挂住请求。
func TestDryRunLuaPluginTimesOut(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"stage":      "pre",
		"source":     `function handle(ctx) while true do end end`,
		"timeout_ms": 50,
	})
	ctx := invokeThreatIntelHandler(t, DryRunLuaPlugin(), "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d", ctx.Response.StatusCode())
	}
	var resp struct {
		RuntimeError string `json:"runtime_error"`
	}
	json.Unmarshal(ctx.Response.Body(), &resp)
	if resp.RuntimeError == "" {
		t.Error("死循环应产生运行时错误（超时）")
	}
}

func TestDryRunLuaPluginRejectsBadStage(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"stage": "middle", "source": validLuaSource})
	ctx := invokeThreatIntelHandler(t, DryRunLuaPlugin(), "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("非法 stage 应返回 400，得到 %d", ctx.Response.StatusCode())
	}
}

func TestDryRunLuaPluginRejectsInvalidTimeout(t *testing.T) {
	for _, timeout := range []int{-1, luaMaxTimeoutMS + 1} {
		body, err := json.Marshal(map[string]any{
			"stage": "pre", "source": validLuaSource, "timeout_ms": timeout,
		})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		ctx := invokeThreatIntelHandler(t, DryRunLuaPlugin(), "POST", "/x", nil, body)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("timeout %d should return 400, got %d: %s", timeout, ctx.Response.StatusCode(), ctx.Response.Body())
		}
	}
}

func TestDryRunLuaPluginClearsPreVerdictFields(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"stage": "pre",
		"source": `function handle(ctx)
			if ctx.phase == "" and ctx.action == "" then return "observe" end
			return "intercept"
		end`,
		"request": map[string]any{"phase": "owasp", "action": "intercept"},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	ctx := invokeThreatIntelHandler(t, DryRunLuaPlugin(), "POST", "/x", nil, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var response struct {
		Decision struct {
			Action string `json:"Action"`
		} `json:"decision"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.Decision.Action != "observe" {
		t.Fatalf("pre dry-run must clear phase/action, got %q", response.Decision.Action)
	}
}

// ---- 列表与详情 ----

func TestListAndGetLuaPlugin(t *testing.T) {
	repo := newLuaPluginRepoForTest(t)
	for _, p := range []store.LuaPlugin{
		{Name: "a", Stage: "pre", Source: validLuaSource, Enabled: true, Priority: 10},
		{Name: "b", Stage: "post", Source: validLuaSource, Enabled: true, Priority: 20},
	} {
		item := p
		if err := repo.Create(&item); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	ctx := invokeThreatIntelHandler(t, ListLuaPlugins(repo), "GET", "/x", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d", ctx.Response.StatusCode())
	}
	var listResp struct {
		Items []store.LuaPlugin `json:"items"`
		Total int               `json:"total"`
	}
	json.Unmarshal(ctx.Response.Body(), &listResp)
	if listResp.Total != 2 {
		t.Errorf("Total = %d, want 2", listResp.Total)
	}

	get := invokeThreatIntelHandler(t, GetLuaPlugin(repo), "GET", "/x", idParam(1), nil)
	if get.Response.StatusCode() != 200 {
		t.Errorf("详情 want 200, got %d", get.Response.StatusCode())
	}
	miss := invokeThreatIntelHandler(t, GetLuaPlugin(repo), "GET", "/x", idParam(9999), nil)
	if miss.Response.StatusCode() != 404 {
		t.Errorf("不存在 want 404, got %d", miss.Response.StatusCode())
	}
}

// ---- 运行时统计 ----

// luaStatsResponse 是统计端点的响应形态，字段名即对外契约。
type luaStatsResponse struct {
	Items []struct {
		ID       uint    `json:"id"`
		Name     string  `json:"name"`
		Stage    string  `json:"stage"`
		Runs     int64   `json:"runs"`
		Failures int64   `json:"failures"`
		Timeouts int64   `json:"timeouts"`
		AvgMS    float64 `json:"avg_ms"`
	} `json:"items"`
	Total int `json:"total"`
}

func decodeLuaStats(t *testing.T, body []byte) luaStatsResponse {
	t.Helper()
	var resp luaStatsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, body)
	}
	return resp
}

// TestGetLuaPluginStatsReportsRuns 验证统计端点如实反映脚本执行情况。
//
// 这是运维唯一的可见信号：脚本失败/超时在数据面只写一条 warn 就静默跳过。
func TestGetLuaPluginStatsReportsRuns(t *testing.T) {
	engine := luaplugin.NewEngine(newLuaTestKV(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	okScript, err := luaplugin.Compile("ok", luaplugin.StagePre, validLuaSource)
	if err != nil {
		t.Fatalf("compile ok: %v", err)
	}
	badScript, err := luaplugin.Compile("boom", luaplugin.StagePost, `function handle(ctx) error("boom") end`)
	if err != nil {
		t.Fatalf("compile boom: %v", err)
	}
	okScript.SetID(1)
	badScript.SetID(2)
	engine.Reload([]*luaplugin.Script{okScript, badScript})

	for i := 0; i < 3; i++ {
		engine.Evaluate(context.Background(), luaplugin.StagePre, luaplugin.RequestView{})
	}
	engine.Evaluate(context.Background(), luaplugin.StagePost, luaplugin.RequestView{})

	ctx := invokeThreatIntelHandler(t, GetLuaPluginStats(engine), "GET", "/api/v1/lua-plugins/stats", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	resp := decodeLuaStats(t, ctx.Response.Body())
	if resp.Total != 2 || len(resp.Items) != 2 {
		t.Fatalf("应有 2 条统计，得到 total=%d items=%d", resp.Total, len(resp.Items))
	}

	byName := map[string]int{}
	for i, item := range resp.Items {
		byName[item.Name] = i
	}
	okIdx, found := byName["ok"]
	if !found {
		t.Fatalf("缺少脚本 ok 的统计: %+v", resp.Items)
	}
	if got := resp.Items[okIdx]; got.Runs != 3 || got.Stage != "pre" || got.Failures != 0 {
		t.Errorf("ok 统计 = %+v，want Runs=3 Stage=pre Failures=0", got)
	}

	boomIdx, found := byName["boom"]
	if !found {
		t.Fatalf("缺少脚本 boom 的统计: %+v", resp.Items)
	}
	if got := resp.Items[boomIdx]; got.Failures != 1 || got.Stage != "post" {
		t.Errorf("boom 统计 = %+v，want Failures=1 Stage=post", got)
	}
}

func TestGetLuaPluginStatsDistinguishesDuplicateNamesByID(t *testing.T) {
	engine := luaplugin.NewEngine(newLuaTestKV(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	first, err := luaplugin.Compile("duplicate", luaplugin.StagePre, validLuaSource)
	if err != nil {
		t.Fatalf("compile first: %v", err)
	}
	second, err := luaplugin.Compile("duplicate", luaplugin.StagePre, validLuaSource)
	if err != nil {
		t.Fatalf("compile second: %v", err)
	}
	first.SetID(101)
	second.SetID(202)
	engine.Reload([]*luaplugin.Script{first, second})
	engine.Evaluate(context.Background(), luaplugin.StagePre, luaplugin.RequestView{})

	ctx := invokeThreatIntelHandler(t, GetLuaPluginStats(engine), "GET", "/x", nil, nil)
	response := decodeLuaStats(t, ctx.Response.Body())
	if len(response.Items) != 2 {
		t.Fatalf("want 2 stats items, got %#v", response.Items)
	}
	ids := map[uint]int64{}
	for _, item := range response.Items {
		ids[item.ID] = item.Runs
	}
	if ids[101] != 1 || ids[202] != 1 {
		t.Fatalf("duplicate names must retain independent stats, got %#v", ids)
	}
}

// TestGetLuaPluginStatsAvgIsMilliseconds 验证 avg_ms 的单位是毫秒而非纳秒。
//
// AvgTime 是 time.Duration（纳秒），漏掉换算会让 200µs 显示成 200000，
// 用户按毫秒读就会误判脚本慢了六个数量级。
func TestGetLuaPluginStatsAvgIsMilliseconds(t *testing.T) {
	engine := luaplugin.NewEngine(newLuaTestKV(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	script, err := luaplugin.Compile("timed", luaplugin.StagePre, validLuaSource)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	engine.Reload([]*luaplugin.Script{script})
	engine.Evaluate(context.Background(), luaplugin.StagePre, luaplugin.RequestView{})

	// 以引擎自身的 Duration 统计为基准做换算断言，不依赖具体耗时数值，
	// 故不受机器负载影响。
	raw := engine.Stats()
	if len(raw) != 1 || raw[0].Runs != 1 {
		t.Fatalf("引擎统计异常: %+v", raw)
	}
	wantMS := float64(raw[0].AvgTime.Nanoseconds()) / 1e6

	ctx := invokeThreatIntelHandler(t, GetLuaPluginStats(engine), "GET", "/x", nil, nil)
	resp := decodeLuaStats(t, ctx.Response.Body())
	if len(resp.Items) != 1 {
		t.Fatalf("应有 1 条统计，得到 %d", len(resp.Items))
	}
	if got := resp.Items[0].AvgMS; got != wantMS {
		t.Errorf("avg_ms = %v, want %v（纳秒值为 %d）", got, wantMS, raw[0].AvgTime.Nanoseconds())
	}
	// 单次空脚本调用远低于 1ms，若未换算会是数万级的纳秒值。
	if resp.Items[0].AvgMS >= 1000 {
		t.Errorf("avg_ms = %v，量级异常，疑似未做纳秒→毫秒换算", resp.Items[0].AvgMS)
	}
}

// TestGetLuaPluginStatsWithoutScripts 验证无脚本与 nil 引擎都返回空列表而非 500/panic。
//
// items 必须是 []，不能是 null——前端直接 .map() 会炸。
func TestGetLuaPluginStatsWithoutScripts(t *testing.T) {
	cases := map[string]*luaplugin.Engine{
		"nil 引擎": nil,
		"无脚本":    luaplugin.NewEngine(nil, slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	for name, engine := range cases {
		ctx := invokeThreatIntelHandler(t, GetLuaPluginStats(engine), "GET", "/x", nil, nil)
		if ctx.Response.StatusCode() != 200 {
			t.Errorf("%s: want 200, got %d: %s", name, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			continue
		}
		body := ctx.Response.Body()
		if !bytes.Contains(body, []byte(`"items":[]`)) {
			t.Errorf("%s: items 应序列化为 []，得到 %s", name, bytes.TrimSpace(body))
		}
		if resp := decodeLuaStats(t, body); resp.Total != 0 {
			t.Errorf("%s: Total = %d, want 0", name, resp.Total)
		}
	}
}
