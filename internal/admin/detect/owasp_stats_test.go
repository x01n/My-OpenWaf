package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/owasp"
)

// invokeOWASPGet 构造 GET 请求并调用 handler。
func invokeOWASPGet(t *testing.T, handler app.HandlerFunc, uri string) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI(uri)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

// invokeOWASPPost 构造 POST 请求（可选 id 路由参数）并调用 handler。
func invokeOWASPPost(t *testing.T, handler app.HandlerFunc, uri, idParam string, body []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
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

// ---- GetOWASPRuleStats ----

func TestGetOWASPRuleStatsCountsRegistry(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeOWASPGet(t, GetOWASPRuleStats(repo), "/api/v1/owasp-rules/stats")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Total         int            `json:"total"`
		EnabledCount  int            `json:"enabled_count"`
		DisabledCount int            `json:"disabled_count"`
		ByCategory    map[string]int `json:"by_category"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	catalogTotal := len(owasp.BuiltinRuleDefinitions())
	if resp.Total != catalogTotal {
		t.Fatalf("total = %d, want %d", resp.Total, catalogTotal)
	}
	if resp.EnabledCount+resp.DisabledCount != resp.Total {
		t.Fatalf("enabled(%d) + disabled(%d) != total(%d)", resp.EnabledCount, resp.DisabledCount, resp.Total)
	}
	if len(resp.ByCategory) == 0 {
		t.Fatal("by_category should not be empty")
	}
}

// TestGetOWASPRuleStatsRespectsDisableOverride 验证 enabled=false 覆盖会计入 disabled_count。
func TestGetOWASPRuleStatsRespectsDisableOverride(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)

	before := invokeOWASPGet(t, GetOWASPRuleStats(repo), "/api/v1/owasp-rules/stats")
	var beforeResp struct {
		EnabledCount  int `json:"enabled_count"`
		DisabledCount int `json:"disabled_count"`
	}
	if err := json.Unmarshal(before.Response.Body(), &beforeResp); err != nil {
		t.Fatalf("decode before: %v", err)
	}

	invokeOWASPUpdate(t, UpdateSingleOWASPRule(repo, func() error { return nil }), ruleID, map[string]any{
		"enabled": false,
	})

	after := invokeOWASPGet(t, GetOWASPRuleStats(repo), "/api/v1/owasp-rules/stats")
	var afterResp struct {
		EnabledCount  int `json:"enabled_count"`
		DisabledCount int `json:"disabled_count"`
	}
	if err := json.Unmarshal(after.Response.Body(), &afterResp); err != nil {
		t.Fatalf("decode after: %v", err)
	}
	if afterResp.DisabledCount != beforeResp.DisabledCount+1 {
		t.Fatalf("disabled_count = %d, want %d", afterResp.DisabledCount, beforeResp.DisabledCount+1)
	}
	if afterResp.EnabledCount != beforeResp.EnabledCount-1 {
		t.Fatalf("enabled_count = %d, want %d", afterResp.EnabledCount, beforeResp.EnabledCount-1)
	}
}

// ---- ListOWASPRulesFromRegistry ----

func TestListOWASPRulesFiltersByCategory(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	rules := owasp.BuiltinRuleDefinitions()
	if len(rules) == 0 {
		t.Fatal("expected default OWASP rules")
	}
	category := rules[0].Category
	want := 0
	for _, r := range rules {
		if r.Category == category {
			want++
		}
	}

	ctx := invokeOWASPGet(t, ListOWASPRulesFromRegistry(repo), "/api/v1/owasp-rules?category="+category)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Items   []owaspRuleView            `json:"items"`
		Grouped map[string][]owaspRuleView `json:"grouped"`
		Total   int                        `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Total != want || len(resp.Items) != want {
		t.Fatalf("total = %d, items = %d, want %d", resp.Total, len(resp.Items), want)
	}
	for _, item := range resp.Items {
		if item.Category != category {
			t.Fatalf("item %q has category %q, want %q", item.ID, item.Category, category)
		}
	}
	if len(resp.Grouped) != 1 {
		t.Fatalf("grouped should contain exactly one category, got %d", len(resp.Grouped))
	}
}

func TestListOWASPRulesReturnsWhitelistOverride(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	invokeOWASPUpdate(t, UpdateSingleOWASPRule(repo, func() error { return nil }), ruleID, map[string]any{
		"whitelist": []string{"/healthz", "/metrics"},
	})

	ctx := invokeOWASPGet(t, ListOWASPRulesFromRegistry(repo), "/api/v1/owasp-rules?page_size=500")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d", ctx.Response.StatusCode())
	}
	var resp struct {
		Items []owaspRuleView `json:"items"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, item := range resp.Items {
		if item.ID != ruleID {
			continue
		}
		if len(item.Whitelist) != 2 || item.Whitelist[0] != "/healthz" || item.Whitelist[1] != "/metrics" {
			t.Fatalf("whitelist = %#v, want [/healthz /metrics]", item.Whitelist)
		}
		return
	}
	t.Fatalf("rule %s not found in response", ruleID)
}

// TestListOWASPRulesSortsByID 验证响应按规则 ID 升序排列。
func TestListOWASPRulesSortsByID(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeOWASPGet(t, ListOWASPRulesFromRegistry(repo), "/api/v1/owasp-rules?page_size=500")
	var resp struct {
		Items []owaspRuleView `json:"items"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for i := 1; i < len(resp.Items); i++ {
		if resp.Items[i-1].ID > resp.Items[i].ID {
			t.Fatalf("items not sorted by ID at index %d: %q > %q", i, resp.Items[i-1].ID, resp.Items[i].ID)
		}
	}
}

// ---- UpdateSingleOWASPRule 边界路径 ----

func TestUpdateSingleOWASPRuleUnknownRuleReturns404(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeOWASPPost(t, UpdateSingleOWASPRule(repo, func() error { return nil }),
		"/api/v1/owasp-rules/no-such-rule/update", "no-such-rule", []byte(`{"enabled":false}`))
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("unknown rule: want 404, got %d", ctx.Response.StatusCode())
	}
}

func TestUpdateSingleOWASPRuleRejectsAllowAndTagActions(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	handler := UpdateSingleOWASPRule(repo, func() error { return nil })

	for _, bad := range []string{"allow", "tag", "not_a_real_action"} {
		body, _ := json.Marshal(map[string]any{"action": bad})
		ctx := invokeOWASPPost(t, handler, "/api/v1/owasp-rules/"+ruleID+"/update", ruleID, body)
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("action %q: want 400, got %d", bad, ctx.Response.StatusCode())
		}
	}
}

func TestUpdateSingleOWASPRuleAcceptsRedirectWithTarget(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	invokeOWASPUpdate(t, UpdateSingleOWASPRule(repo, func() error { return nil }), ruleID, map[string]any{
		"action":      "redirect",
		"redirect_to": "https://example.com/blocked",
	})
	var config store.PolicyOWASPRuleConfig
	if err := repo.DB().Where("rule_id = ?", ruleID).First(&config).Error; err != nil {
		t.Fatalf("load override: %v", err)
	}
	if config.Action == nil || *config.Action != "redirect" || config.RedirectTo == nil || *config.RedirectTo != "https://example.com/blocked" {
		t.Fatalf("unexpected override: %#v", config)
	}
}

// ---- BatchUpdateOWASPRules ----

func TestBatchUpdateOWASPRulesRejectsEmptyArray(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeOWASPPost(t, BatchUpdateOWASPRules(repo, func() error { return nil }),
		"/api/v1/owasp-rules/batch-update", "", []byte(`{"rules":[]}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("empty rules: want 400, got %d", ctx.Response.StatusCode())
	}
}

func TestBatchUpdateOWASPRulesAppliesOverrides(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	rules := owasp.BuiltinRuleDefinitions()
	if len(rules) < 2 {
		t.Skip("registry needs at least 2 rules for batch test")
	}
	id1, id2 := rules[0].RuleID, rules[1].RuleID

	body, _ := json.Marshal(map[string]any{
		"rules": []map[string]any{
			{"id": id1, "enabled": false},
			{"id": id2, "sensitivity": "strict"},
		},
	})
	ctx := invokeOWASPPost(t, BatchUpdateOWASPRules(repo, func() error { return nil }),
		"/api/v1/owasp-rules/batch-update", "", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Updated int `json:"updated"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Updated != 2 {
		t.Fatalf("updated=%d, want 2", resp.Updated)
	}

	var config1, config2 store.PolicyOWASPRuleConfig
	if err := repo.DB().Where("rule_id = ?", id1).First(&config1).Error; err != nil {
		t.Fatalf("load first override: %v", err)
	}
	if config1.Enabled == nil || *config1.Enabled {
		t.Fatalf("rule %s enabled override = %#v, want false", id1, config1.Enabled)
	}
	if err := repo.DB().Where("rule_id = ?", id2).First(&config2).Error; err != nil {
		t.Fatalf("load second override: %v", err)
	}
	if config2.Sensitivity == nil || *config2.Sensitivity != "strict" {
		t.Fatalf("rule %s sensitivity override = %#v, want strict", id2, config2.Sensitivity)
	}
}

// TestBatchUpdateOWASPRulesSkipsUnknownIDs 验证未知规则 ID 被跳过而非计入 updated。
func TestBatchUpdateOWASPRulesRejectsUnknownIDsAtomically(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	body, _ := json.Marshal(map[string]any{
		"rules": []map[string]any{
			{"id": ruleID, "enabled": false},
			{"id": "definitely-not-a-rule", "enabled": false},
		},
	})
	ctx := invokeOWASPPost(t, BatchUpdateOWASPRules(repo, func() error { return nil }),
		"/api/v1/owasp-rules/batch-update", "", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("want 400, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var count int64
	if err := repo.DB().Model(&store.PolicyOWASPRuleConfig{}).Count(&count).Error; err != nil {
		t.Fatalf("count configs: %v", err)
	}
	if count != 0 {
		t.Fatalf("config count = %d, want 0 after atomic rejection", count)
	}
}

// TestBatchUpdateOWASPRulesSkipsRedirectWithoutTarget 验证启用态 redirect 缺 target 时被跳过。
func TestBatchUpdateOWASPRulesRejectsRedirectWithoutTarget(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	body, _ := json.Marshal(map[string]any{
		"rules": []map[string]any{
			{"id": ruleID, "action": "redirect"},
		},
	})
	ctx := invokeOWASPPost(t, BatchUpdateOWASPRules(repo, func() error { return nil }),
		"/api/v1/owasp-rules/batch-update", "", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("want 400, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var count int64
	if err := repo.DB().Model(&store.PolicyOWASPRuleConfig{}).Count(&count).Error; err != nil {
		t.Fatalf("count configs: %v", err)
	}
	if count != 0 {
		t.Fatalf("config count = %d, want 0 after invalid redirect", count)
	}
}

// ---- overrideHasRedirectActionWithoutTarget ----

func TestOverrideHasRedirectActionWithoutTarget(t *testing.T) {
	tests := []struct {
		name     string
		override map[string]interface{}
		want     bool
	}{
		{"no action", map[string]interface{}{}, false},
		{"non-redirect action", map[string]interface{}{"action": "intercept"}, false},
		{"redirect without target", map[string]interface{}{"action": "redirect"}, true},
		{"redirect with blank target", map[string]interface{}{"action": "redirect", "redirect_to": "   "}, true},
		{"redirect with target", map[string]interface{}{"action": "redirect", "redirect_to": "/blocked"}, false},
		{"disabled redirect without target", map[string]interface{}{"enabled": false, "action": "redirect"}, false},
	}
	for _, tt := range tests {
		if got := overrideHasRedirectActionWithoutTarget(tt.override); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}
