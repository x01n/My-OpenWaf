package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/cve"
)

// invokeCVEHandler 构造 POST 请求（含可选路由参数和请求体）并调用 handler。
func invokeCVEHandler(t *testing.T, handler app.HandlerFunc, method, uri string, idParam string, body []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(body)
	}
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	if idParam != "" {
		ctx.Params = param.Params{{Key: "id", Value: idParam}}
	}
	handler(context.Background(), ctx)
	return ctx
}

func seedOneCVERule(t *testing.T, repo interface{ Create(*cve.CVERuleModel) error }) *cve.CVERuleModel {
	t.Helper()
	rule := &cve.CVERuleModel{
		CVEID:    "CVE-2024-9999",
		Category: "general",
		Pattern:  "select.*from",
		Target:   "body",
		Severity: "high",
		Action:   "intercept",
		Source:   "custom",
		Approved: true,
		Enabled:  true,
	}
	if err := repo.Create(rule); err != nil {
		t.Fatalf("seed cve rule: %v", err)
	}
	return rule
}

// ---- CreateCVERule ----

func TestCreateCVERulePersists(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	body, _ := json.Marshal(map[string]any{
		"cve_id":       "CVE-2025-0001",
		"category":     "sqli",
		"pattern":      `(?i)union\s+select`,
		"target":       "url",
		"severity":     "high",
		"action":       "captcha_challenge",
		"captcha_type": "slide",
		"enabled":      true,
	})
	ctx := invokeCVEHandler(t, CreateCVERule(repo, nil), "POST", "/api/v1/cve-rules", "", body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("want 201, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var item cve.CVERuleModel
	if err := json.Unmarshal(ctx.Response.Body(), &item); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if item.Source != "custom" {
		t.Fatalf("source must be forced to \"custom\", got %q", item.Source)
	}
	if item.CaptchaType != "slide" {
		t.Fatalf("captcha_type = %q, want slide", item.CaptchaType)
	}
	if !item.Approved {
		t.Fatal("approved must be forced to true")
	}
}

func TestCreateCVERuleAcceptsURLBodyTarget(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	body := []byte(`{"cve_id":"CVE-2025-0001-URL-BODY","category":"general","pattern":"url-body-marker","target":"url_body","severity":"high","action":"intercept","enabled":true}`)
	ctx := invokeCVEHandler(t, CreateCVERule(repo, nil), "POST", "/api/v1/cve-rules", "", body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("url_body target: want 201, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestCreateCVERuleRejectsInvalidRegex(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	body, _ := json.Marshal(map[string]any{
		"cve_id":  "CVE-2025-0002",
		"pattern": `(?invalid`,
		"action":  "intercept",
	})
	ctx := invokeCVEHandler(t, CreateCVERule(repo, nil), "POST", "/api/v1/cve-rules", "", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid regex: want 400, got %d", ctx.Response.StatusCode())
	}
}

func TestCreateCVERuleRejectsInvalidAction(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	body, _ := json.Marshal(map[string]any{
		"cve_id":  "CVE-2025-0003",
		"pattern": `test`,
		"action":  "not_a_real_action",
	})
	ctx := invokeCVEHandler(t, CreateCVERule(repo, nil), "POST", "/api/v1/cve-rules", "", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid action: want 400, got %d", ctx.Response.StatusCode())
	}
}

func TestCreateCVERuleRejectsUnsupportedTarget(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	body, _ := json.Marshal(map[string]any{
		"cve_id":  "CVE-2025-0004",
		"pattern": `test`,
		"target":  "query",
		"action":  "intercept",
	})
	ctx := invokeCVEHandler(t, CreateCVERule(repo, nil), "POST", "/api/v1/cve-rules", "", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unsupported target: want 400, got %d", ctx.Response.StatusCode())
	}
}

// ---- UpdateCVERule ----

func TestUpdateCVERuleReturnsNotFoundForMissingID(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	body, _ := json.Marshal(map[string]any{"severity": "low"})
	ctx := invokeCVEHandler(t, UpdateCVERule(repo, nil), "POST", "/api/v1/cve-rules/9999/update", "9999", body)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing id: want 404, got %d", ctx.Response.StatusCode())
	}
}

func TestUpdateCVERulePatchesFields(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := seedOneCVERule(t, repo)
	idStr := strconv.FormatUint(uint64(rule.ID), 10)

	body, _ := json.Marshal(map[string]any{
		"severity":    "critical",
		"description": "patched",
		"enabled":     false,
	})
	ctx := invokeCVEHandler(t, UpdateCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/update", idStr, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var updated cve.CVERuleModel
	if err := json.Unmarshal(ctx.Response.Body(), &updated); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if updated.Severity != "critical" {
		t.Fatalf("severity not patched: got %q", updated.Severity)
	}
	if updated.Description != "patched" {
		t.Fatalf("description not patched: got %q", updated.Description)
	}
	if updated.Enabled {
		t.Fatal("enabled should be false after patch")
	}
	// Approved 必须被强制为 true
	if !updated.Approved {
		t.Fatal("approved must be forced to true on update")
	}
}

func TestUpdateCVERuleOmittedEnabledPreservesValue(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := seedOneCVERule(t, repo)
	idStr := strconv.FormatUint(uint64(rule.ID), 10)
	body, _ := json.Marshal(map[string]any{"description": "description-only"})
	ctx := invokeCVEHandler(t, UpdateCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/update", idStr, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	updated, err := repo.Get(rule.ID)
	if err != nil {
		t.Fatalf("read updated rule: %v", err)
	}
	if !updated.Enabled {
		t.Fatal("omitted enabled must preserve the existing enabled value")
	}
}

func TestUpdateCVERuleExplicitEmptyDescriptionAndCVEIDAreApplied(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := seedOneCVERule(t, repo)
	idStr := strconv.FormatUint(uint64(rule.ID), 10)
	body, _ := json.Marshal(map[string]any{"description": "", "cve_id": ""})
	ctx := invokeCVEHandler(t, UpdateCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/update", idStr, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	updated, err := repo.Get(rule.ID)
	if err != nil {
		t.Fatalf("read updated rule: %v", err)
	}
	if updated.Description != "" || updated.CVEID != "" {
		t.Fatalf("explicit empty fields were not applied: %+v", updated)
	}
}

func TestUpdateCVERuleRejectsBuiltinRule(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := &cve.CVERuleModel{
		CVEID: "CVE-2024-BUILTIN", Pattern: "builtin-pattern", Action: "intercept",
		Source: "catalog", Approved: true, Enabled: true,
	}
	if err := repo.Create(rule); err != nil {
		t.Fatalf("seed builtin: %v", err)
	}
	idStr := strconv.FormatUint(uint64(rule.ID), 10)
	body, _ := json.Marshal(map[string]any{"description": "must-not-change"})
	ctx := invokeCVEHandler(t, UpdateCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/update", idStr, body)
	if ctx.Response.StatusCode() != 403 {
		t.Fatalf("builtin update: want 403, got %d", ctx.Response.StatusCode())
	}
}

func TestResetCVERuleOverrideUsesBodyScope(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	if err := repo.DB().AutoMigrate(&store.Policy{}); err != nil {
		t.Fatalf("migrate policies: %v", err)
	}
	defaultSlot := uint(1)
	policy := store.Policy{Name: "policy-reset", DefaultSlot: &defaultSlot}
	if err := repo.DB().Create(&policy).Error; err != nil {
		t.Fatalf("create policy: %v", err)
	}
	rule := seedOneCVERule(t, repo)
	globalEnabled := false
	policyEnabled := false
	if err := repo.DB().Create(&store.CVERuleScopeOverride{RuleID: rule.ID, ScopeType: store.CVEScopeGlobal, ScopeID: 0, Enabled: &globalEnabled}).Error; err != nil {
		t.Fatalf("create global override: %v", err)
	}
	if err := repo.DB().Create(&store.CVERuleScopeOverride{RuleID: rule.ID, ScopeType: store.CVEScopePolicy, ScopeID: policy.ID, Enabled: &policyEnabled}).Error; err != nil {
		t.Fatalf("create policy override: %v", err)
	}
	idStr := strconv.FormatUint(uint64(rule.ID), 10)
	body, _ := json.Marshal(map[string]any{"scope": "policy", "policy_id": policy.ID})
	ctx := invokeCVEHandler(t, ResetCVERuleOverride(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/reset", idStr, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("reset status=%d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var remaining []store.CVERuleScopeOverride
	if err := repo.DB().Where("rule_id = ?", rule.ID).Find(&remaining).Error; err != nil {
		t.Fatalf("load remaining overrides: %v", err)
	}
	if len(remaining) != 1 || remaining[0].ScopeType != store.CVEScopeGlobal {
		t.Fatalf("body scope reset removed wrong overrides: %#v", remaining)
	}
}

func TestUpdateCVERuleRejectsInvalidRegex(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := seedOneCVERule(t, repo)
	idStr := strconv.FormatUint(uint64(rule.ID), 10)

	body, _ := json.Marshal(map[string]any{"pattern": `(?bad`})
	ctx := invokeCVEHandler(t, UpdateCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/update", idStr, body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid regex: want 400, got %d", ctx.Response.StatusCode())
	}
}

// ---- DeleteCVERule ----

func TestDeleteCVERuleReturnsNotFoundForMissingID(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	ctx := invokeCVEHandler(t, DeleteCVERule(repo, nil), "POST", "/api/v1/cve-rules/9999/delete", "9999", nil)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing id: want 404, got %d", ctx.Response.StatusCode())
	}
}

func TestDeleteCVERuleRejectsFeedSourced(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	// 插入一条 Source="feed" 的规则
	rule := &cve.CVERuleModel{
		CVEID:    "CVE-2024-FEED",
		Pattern:  "test",
		Action:   "intercept",
		Source:   "feed",
		Approved: false,
		Enabled:  false,
	}
	if err := repo.Create(rule); err != nil {
		t.Fatalf("seed: %v", err)
	}
	idStr := strconv.FormatUint(uint64(rule.ID), 10)
	ctx := invokeCVEHandler(t, DeleteCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/delete", idStr, nil)
	if ctx.Response.StatusCode() != 403 {
		t.Fatalf("feed rule: want 403, got %d", ctx.Response.StatusCode())
	}
}

func TestDeleteCVERuleSucceeds(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := seedOneCVERule(t, repo)
	idStr := strconv.FormatUint(uint64(rule.ID), 10)

	ctx := invokeCVEHandler(t, DeleteCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/delete", idStr, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	// 确认已从数据库删除（再次 Delete 应返回 404）
	ctx2 := invokeCVEHandler(t, DeleteCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/delete", idStr, nil)
	if ctx2.Response.StatusCode() != 404 {
		t.Fatalf("after delete: want 404, got %d", ctx2.Response.StatusCode())
	}
}

// ---- ToggleCVERule ----

func TestToggleCVERuleReturnsNotFoundForMissingID(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	ctx := invokeCVEHandler(t, ToggleCVERule(repo, nil), "POST", "/api/v1/cve-rules/9999/toggle", "9999", nil)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing id: want 404, got %d", ctx.Response.StatusCode())
	}
}

func TestToggleCVERuleFlipsEnabled(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := seedOneCVERule(t, repo) // Enabled=true
	idStr := strconv.FormatUint(uint64(rule.ID), 10)

	ctx := invokeCVEHandler(t, ToggleCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/toggle", idStr, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["enabled"] != false {
		t.Fatalf("enabled should be flipped to false, got %v", resp["enabled"])
	}
}

func TestToggleCVERuleExplicitEnabledSetsApproved(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := &cve.CVERuleModel{
		CVEID:    "CVE-2024-TOGGLE",
		Pattern:  "test",
		Action:   "intercept",
		Source:   "custom",
		Approved: false,
		Enabled:  false,
	}
	if err := repo.Create(rule); err != nil {
		t.Fatalf("seed: %v", err)
	}
	idStr := strconv.FormatUint(uint64(rule.ID), 10)

	body, _ := json.Marshal(map[string]any{"enabled": true})
	ctx := invokeCVEHandler(t, ToggleCVERule(repo, nil), "POST", "/api/v1/cve-rules/"+idStr+"/toggle", idStr, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["enabled"] != true {
		t.Fatalf("enabled should be true, got %v", resp["enabled"])
	}
	// 启用时 approved 必须被强制为 true
	if resp["approved"] != true {
		t.Fatalf("approved should be true when enabling, got %v", resp["approved"])
	}
}

// ---- SyncCVERules ----

func TestSyncCVERulesNilManagerReturns503(t *testing.T) {
	ctx := invokeCVEHandler(t, SyncCVERules(nil), "POST", "/api/v1/cve-rules/sync", "", nil)
	if ctx.Response.StatusCode() != 503 {
		t.Fatalf("nil feed manager: want 503, got %d", ctx.Response.StatusCode())
	}
}

// ---- GetCVEFeedStatus ----

func TestGetCVEFeedStatusNilManagerReturnsErrorField(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	ctx := invokeCVEHandler(t, GetCVEFeedStatus(nil, repo), "GET", "/api/v1/cve-rules/feed-status", "", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d", ctx.Response.StatusCode())
	}
	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	errVal, ok := resp["last_error"]
	if !ok {
		t.Fatal("response missing last_error field")
	}
	if errVal != "feed manager not initialized" {
		t.Fatalf("last_error = %q, want \"feed manager not initialized\"", errVal)
	}
	if resp["syncing"] != false {
		t.Fatalf("syncing should be false, got %v", resp["syncing"])
	}
}
