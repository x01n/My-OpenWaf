package owasprules

import (
	"encoding/json"
	"strings"
	"testing"

	"My-OpenWaf/internal/store/owasp"
)

func TestOWASPRuleOverridePersistsCaptchaTypeNoteAndWhitelist(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	body, err := json.Marshal(map[string]any{
		"policy_id":    1,
		"action":       "captcha_challenge",
		"captcha_type": "slide",
		"note":         "工单 SEC-2026-08",
		"whitelist":    []string{" /healthz ", "/static/*", "/healthz"},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	ctx := invokeOWASPPost(t, UpdateSingleOWASPRule(repo, func() error { return nil }), "/api/v1/owasp-rules/"+ruleID+"/update", ruleID, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status=%d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var config owasp.PolicyOWASPRuleConfig
	if err := repo.DB().Where("policy_id = ? AND rule_id = ?", 1, ruleID).First(&config).Error; err != nil {
		t.Fatalf("load persisted override: %v", err)
	}
	if config.CaptchaType == nil || *config.CaptchaType != "slide" || config.Note == nil || *config.Note != "工单 SEC-2026-08" {
		t.Fatalf("persisted override=%#v", config)
	}
	var whitelist []string
	if config.Whitelist == nil || json.Unmarshal([]byte(*config.Whitelist), &whitelist) != nil || len(whitelist) != 2 || whitelist[0] != "/healthz" || whitelist[1] != "/static/*" {
		t.Fatalf("persisted whitelist=%#v raw=%v", whitelist, config.Whitelist)
	}

	snapshot, err := getOWASPReadSnapshot(repo.DB(), 1)
	if err != nil {
		t.Fatalf("load read snapshot: %v", err)
	}
	for i := range snapshot.views {
		if snapshot.views[i].ID != ruleID {
			continue
		}
		if snapshot.views[i].CaptchaType != "slide" || snapshot.views[i].Note != "工单 SEC-2026-08" {
			t.Fatalf("read view=%#v", snapshot.views[i])
		}
		return
	}
	t.Fatalf("rule %s missing from read snapshot", ruleID)
}

func TestOWASPRuleOverrideRejectsInvalidCaptchaWhitelistAndNote(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ruleID := firstOWASPRuleID(t)
	tests := []map[string]any{
		{"policy_id": 1, "captcha_type": "drag"},
		{"policy_id": 1, "whitelist": []string{"relative/path"}},
		{"policy_id": 1, "note": strings.Repeat("x", owaspRuleNoteMaxBytes+1)},
	}
	for i, payload := range tests {
		body, _ := json.Marshal(payload)
		ctx := invokeOWASPPost(t, UpdateSingleOWASPRule(repo, func() error { return nil }), "/api/v1/owasp-rules/"+ruleID+"/update", ruleID, body)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("case %d status=%d body=%s", i, ctx.Response.StatusCode(), ctx.Response.Body())
		}
	}
	var count int64
	if err := repo.DB().Model(&owasp.PolicyOWASPRuleConfig{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("rejected payloads changed database: count=%d err=%v", count, err)
	}
}

func TestRuleOverridesRejectCaptchaTypeForNonCaptchaAction(t *testing.T) {
	actionValue := "intercept"
	captchaValue := "slide"
	if err := validateOWASPPatch(&owaspRulePatch{Action: &actionValue, CaptchaType: &captchaValue}); err == nil {
		t.Fatal("OWASP override accepted captcha_type with intercept action")
	}
}
