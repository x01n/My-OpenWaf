package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/cve"
)

func newCVERuleRepoForTest(t *testing.T) *repository.CVERuleRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&cve.CVERuleModel{}, &store.CVERuleScopeOverride{}); err != nil {
		t.Fatalf("migrate cve rules: %v", err)
	}
	return repository.NewCVERuleRepo(db)
}

func invokeCVERuleListHandler(t *testing.T, handler app.HandlerFunc, uri string) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI(uri)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

func TestListCVERulesFiltersByQueryBeforePagination(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	seed := []cve.CVERuleModel{
		{
			CVEID:       "CVE-2024-0001",
			Category:    "general",
			Pattern:     "first",
			Target:      "url",
			Severity:    "low",
			Action:      "intercept",
			Enabled:     true,
			Description: "ordinary rule",
			Source:      "custom",
			Approved:    true,
		},
		{
			CVEID:       "CVE-2026-49975",
			Category:    "general",
			Pattern:     "second",
			Target:      "url",
			Severity:    "critical",
			Action:      "intercept",
			Enabled:     true,
			Description: "Microsoft SharePoint ToolShell exploit detection",
			Source:      "custom",
			Approved:    true,
		},
	}
	for i := range seed {
		if err := repo.Create(&seed[i]); err != nil {
			t.Fatalf("seed cve rule %d: %v", i, err)
		}
	}

	ctx := invokeCVERuleListHandler(
		t,
		ListCVERules(repo),
		"/api/v1/cve-rules?page=1&page_size=1&q=SHAREPOINT",
	)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		Items []cve.CVERuleModel `json:"items"`
		Total int64              `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total < 1 {
		t.Fatalf("total = %d, want at least 1", resp.Total)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("items len = %d, want 1", len(resp.Items))
	}
	if resp.Items[0].CVEID != "CVE-2026-49975" && resp.Items[0].CVEID != "CVE-2025-53770" {
		t.Fatalf("matched cve_id = %q, want SharePoint CVE", resp.Items[0].CVEID)
	}
}

func TestListCVERulesReturnsCatalogRulesWhenDBEmpty(t *testing.T) {
	repo := newCVERuleRepoForTest(t)

	ctx := invokeCVERuleListHandler(t, ListCVERules(repo), "/api/v1/cve-rules?page=1&page_size=100&source=catalog")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Items []cveScopedRuleView `json:"items"`
		Total int64               `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total == 0 || len(resp.Items) == 0 {
		t.Fatal("catalog CVE rules should be listed when database starts empty")
	}
	for _, item := range resp.Items {
		if item.Source != "catalog" {
			t.Fatalf("source = %q, want catalog", item.Source)
		}
		if item.CVEID == "" || item.Category == "" || item.Severity == "" {
			t.Fatalf("catalog rule has incomplete fields: %#v", item.CVERuleModel)
		}
	}
}

func TestListCVERulesCatalogUsesPatternIdentity(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	if err := ensureCatalogCVERules(repo); err != nil {
		t.Fatalf("sync catalog rules: %v", err)
	}
	registry := cve.GetGlobalCVERuleRegistry()
	if registry == nil {
		t.Fatal("expected CVE registry")
	}
	seen := make(map[string]bool)
	for _, rule := range registry.All() {
		if rule.CVE == "" || rule.ID == "" {
			continue
		}
		seen[rule.ID] = true
		var got cve.CVERuleModel
		if err := repo.DB().Where("source = ? AND pattern = ?", "catalog", rule.ID).First(&got).Error; err != nil {
			t.Fatalf("load catalog rule %q: %v", rule.ID, err)
		}
		if got.CVEID != rule.CVE {
			t.Fatalf("catalog rule %q cve_id = %q, want %q", rule.ID, got.CVEID, rule.CVE)
		}
		if !got.Approved {
			t.Fatalf("catalog rule %q should be approved for runtime snapshot", rule.ID)
		}
	}
	var total int64
	if err := repo.DB().Model(&cve.CVERuleModel{}).Where("source = ?", "catalog").Count(&total).Error; err != nil {
		t.Fatalf("count catalog rules: %v", err)
	}
	if int(total) != len(seen) {
		t.Fatalf("catalog rows = %d, want %d unique registry patterns", total, len(seen))
	}
}

func TestSaveCVEScopeOverrideMergesPartialPatch(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rule := cve.CVERuleModel{
		CVEID:       "CVE-2026-50001",
		Category:    "general",
		Pattern:     "merge-partial",
		Target:      "url",
		Severity:    "high",
		Action:      "intercept",
		Enabled:     true,
		Description: "merge partial override",
		Source:      "custom",
		Approved:    true,
	}
	if err := repo.Create(&rule); err != nil {
		t.Fatalf("seed cve rule: %v", err)
	}
	action := "redirect"
	statusCode := 302
	redirectTo := "https://example.com/blocked"
	scope := cveScopeContext{ScopeType: store.CVEScopeGlobal, ScopeID: 0}
	if err := saveCVEScopeOverride(repo.DB(), rule.ID, scope, store.CVERuleScopeOverride{Action: &action, StatusCode: &statusCode, RedirectTo: &redirectTo}); err != nil {
		t.Fatalf("save initial override: %v", err)
	}
	enabled := false
	if err := saveCVEScopeOverride(repo.DB(), rule.ID, scope, store.CVERuleScopeOverride{Enabled: &enabled}); err != nil {
		t.Fatalf("save partial override: %v", err)
	}

	var got store.CVERuleScopeOverride
	if err := repo.DB().Where("rule_id = ? AND scope_type = ? AND scope_id = ?", rule.ID, store.CVEScopeGlobal, 0).First(&got).Error; err != nil {
		t.Fatalf("load override: %v", err)
	}
	if got.Enabled == nil || *got.Enabled {
		t.Fatalf("enabled override = %v, want false", got.Enabled)
	}
	if got.Action == nil || *got.Action != action {
		t.Fatalf("action override = %v, want %q", got.Action, action)
	}
	if got.StatusCode == nil || *got.StatusCode != statusCode {
		t.Fatalf("status code override = %v, want %d", got.StatusCode, statusCode)
	}
	if got.RedirectTo == nil || *got.RedirectTo != redirectTo {
		t.Fatalf("redirect_to override = %v, want %q", got.RedirectTo, redirectTo)
	}
}

func TestCVERuleStatsUseEffectiveScopeOverrides(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rules := []cve.CVERuleModel{
		{
			CVEID:       "CVE-2026-50002",
			Category:    "general",
			Pattern:     "enabled-by-default",
			Target:      "url",
			Severity:    "high",
			Action:      "intercept",
			Enabled:     true,
			Description: "enabled rule",
			Source:      "custom",
			Approved:    true,
		},
		{
			CVEID:       "CVE-2026-50003",
			Category:    "general",
			Pattern:     "disabled-by-default",
			Target:      "url",
			Severity:    "medium",
			Action:      "intercept",
			Enabled:     false,
			Description: "disabled rule",
			Source:      "custom",
			Approved:    true,
		},
	}
	for i := range rules {
		if err := repo.Create(&rules[i]); err != nil {
			t.Fatalf("seed cve rule %d: %v", i, err)
		}
	}
	overrideEnabled := true
	if err := repo.DB().Create(&store.CVERuleScopeOverride{RuleID: rules[1].ID, ScopeType: store.CVEScopeGlobal, ScopeID: 0, Enabled: &overrideEnabled}).Error; err != nil {
		t.Fatalf("seed override: %v", err)
	}

	ctx := invokeCVERuleListHandler(t, GetCVERuleStats(repo), "/api/v1/cve-rules/stats?scope=global")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Total         int64 `json:"total"`
		EnabledCount  int   `json:"enabled_count"`
		DisabledCount int   `json:"disabled_count"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total < 2 || resp.EnabledCount < 2 || resp.DisabledCount != 0 {
		t.Fatalf("stats = total %d enabled %d disabled %d, want at least 2 enabled and no disabled", resp.Total, resp.EnabledCount, resp.DisabledCount)
	}
}

func TestListCVERulesFiltersByEffectiveEnabled(t *testing.T) {
	repo := newCVERuleRepoForTest(t)
	rules := []cve.CVERuleModel{
		{
			CVEID:       "CVE-2026-50004",
			Category:    "general",
			Pattern:     "catalog-enabled",
			Target:      "url",
			Severity:    "high",
			Action:      "intercept",
			Enabled:     true,
			Description: "catalog enabled",
			Source:      "custom",
			Approved:    true,
		},
		{
			CVEID:       "CVE-2026-50005",
			Category:    "general",
			Pattern:     "scope-enabled",
			Target:      "url",
			Severity:    "medium",
			Action:      "intercept",
			Enabled:     false,
			Description: "scope enabled",
			Source:      "custom",
			Approved:    true,
		},
	}
	for i := range rules {
		if err := repo.Create(&rules[i]); err != nil {
			t.Fatalf("seed cve rule %d: %v", i, err)
		}
	}
	overrideEnabled := true
	if err := repo.DB().Create(&store.CVERuleScopeOverride{RuleID: rules[1].ID, ScopeType: store.CVEScopeGlobal, ScopeID: 0, Enabled: &overrideEnabled}).Error; err != nil {
		t.Fatalf("seed override: %v", err)
	}

	ctx := invokeCVERuleListHandler(t, ListCVERules(repo), "/api/v1/cve-rules?page=1&page_size=1&enabled=true&scope=global")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Items []cveScopedRuleView `json:"items"`
		Total int64               `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total < 2 || len(resp.Items) != 1 {
		t.Fatalf("response total/items = %d/%d, want at least 2/1", resp.Total, len(resp.Items))
	}
	if !resp.Items[0].Effective.Enabled {
		t.Fatal("listed rule should be effectively enabled")
	}
}
