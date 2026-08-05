package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/owasp"
)

func newSystemSettingsRepoForTest(t *testing.T) *repository.SystemSettingsRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&store.SystemSettings{},
		&store.Policy{},
		&store.OWASPRuleCatalog{},
		&store.PolicyOWASPRuleConfig{},
	); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	defaultSlot := uint(1)
	if err := db.Create(&store.Policy{Name: "Default", DefaultSlot: &defaultSlot}).Error; err != nil {
		t.Fatalf("create default policy: %v", err)
	}
	if err := owasp.ReconcileBuiltinCatalog(db); err != nil {
		t.Fatalf("reconcile OWASP catalog: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

func firstOWASPRuleID(t *testing.T) string {
	t.Helper()
	rules := owasp.BuiltinRuleDefinitions()
	if len(rules) == 0 {
		t.Fatalf("expected default OWASP rules")
	}
	for _, rule := range rules {
		if rule.DefaultEnabled {
			return rule.RuleID
		}
	}
	return rules[0].RuleID
}

func invokeOWASPUpdate(t *testing.T, handler app.HandlerFunc, ruleID string, payload map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/owasp-rules/" + ruleID + "/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: ruleID}}
	handler(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestUpdateSingleOWASPRuleClearsActionOverride(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	handler := UpdateSingleOWASPRule(repo, func() error { return nil })

	invokeOWASPUpdate(t, handler, ruleID, map[string]any{
		"action":      "intercept",
		"status_code": 403,
		"redirect_to": "https://example.com/blocked",
	})
	var config store.PolicyOWASPRuleConfig
	if err := repo.DB().Where("rule_id = ?", ruleID).First(&config).Error; err != nil {
		t.Fatalf("load override: %v", err)
	}
	if config.Action == nil || *config.Action != "intercept" || config.StatusCode == nil || config.RedirectTo == nil {
		t.Fatalf("expected action override to be set, got %#v", config)
	}

	invokeOWASPUpdate(t, handler, ruleID, map[string]any{
		"action":      "",
		"status_code": 0,
		"redirect_to": "",
	})
	if err := repo.DB().Where("rule_id = ?", ruleID).First(&config).Error; err != nil {
		t.Fatalf("reload override: %v", err)
	}
	if config.Action != nil || config.StatusCode != nil || config.RedirectTo != nil {
		t.Fatalf("expected action fields to be cleared, got %#v", config)
	}
}

func TestUpdateSingleOWASPRuleSavesSensitivityOverride(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	handler := UpdateSingleOWASPRule(repo, func() error { return nil })

	invokeOWASPUpdate(t, handler, ruleID, map[string]any{
		"sensitivity": "strict",
	})

	var config store.PolicyOWASPRuleConfig
	if err := repo.DB().Where("rule_id = ?", ruleID).First(&config).Error; err != nil {
		t.Fatalf("load override: %v", err)
	}
	if config.Sensitivity == nil || *config.Sensitivity != "strict" {
		t.Fatalf("expected sensitivity override to be set, got %#v", config)
	}

	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/owasp-rules?page_size=500")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ListOWASPRulesFromRegistry(repo)(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Items []owaspRuleView `json:"items"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, item := range resp.Items {
		if item.ID == ruleID {
			if item.Sensitivity != "strict" {
				t.Fatalf("response sensitivity = %q want strict", item.Sensitivity)
			}
			return
		}
	}
	t.Fatalf("rule %s not found in response", ruleID)
}

func TestUpdateSingleOWASPRuleRejectsEnabledRedirectWithoutTarget(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	handler := UpdateSingleOWASPRule(repo, func() error { return nil })

	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/owasp-rules/" + ruleID + "/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody([]byte(`{"action":"redirect"}`))
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: ruleID}}
	handler(context.Background(), ctx)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	invokeOWASPUpdate(t, handler, ruleID, map[string]any{
		"enabled":     false,
		"action":      "redirect",
		"redirect_to": "",
	})
}
