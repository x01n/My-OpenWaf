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

	"My-OpenWaf/internal/admin/shared"
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
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

func firstOWASPRuleID(t *testing.T) string {
	t.Helper()
	rules := owasp.DefaultOWASPRegistry.All()
	if len(rules) == 0 {
		t.Fatalf("expected default OWASP rules")
	}
	return rules[0].ID
}

func invokeOWASPUpdate(t *testing.T, handler app.HandlerFunc, ruleID string, payload map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var req protocol.Request
	var resp protocol.Response
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/owasp-rules/" + ruleID + "/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Response = resp
	ctx.Params = param.Params{{Key: "id", Value: ruleID}}
	handler(context.Background(), ctx)
	if resp.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode(), bytes.TrimSpace(resp.Body()))
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
	cfg := shared.LoadProtectionConfig(repo)
	override := cfg.GetOWASPRulesConfig()[ruleID].(map[string]interface{})
	if override["action"] != "intercept" || override["status_code"] == nil || override["redirect_to"] == nil {
		t.Fatalf("expected action override to be set, got %#v", override)
	}

	invokeOWASPUpdate(t, handler, ruleID, map[string]any{
		"action":      "",
		"status_code": 0,
		"redirect_to": "",
	})
	cfg = shared.LoadProtectionConfig(repo)
	override = cfg.GetOWASPRulesConfig()[ruleID].(map[string]interface{})
	if _, ok := override["action"]; ok {
		t.Fatalf("expected action override to be cleared, got %#v", override)
	}
	if _, ok := override["status_code"]; ok {
		t.Fatalf("expected status_code override to be cleared, got %#v", override)
	}
	if _, ok := override["redirect_to"]; ok {
		t.Fatalf("expected redirect_to override to be cleared, got %#v", override)
	}
}
