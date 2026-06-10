package protect

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
)

func invokeProtectHandler(t *testing.T, handler app.HandlerFunc, method, uri string, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

func TestProtectionResponseUsesEffectiveCategorySensitivity(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.OWASPModules = `{"sqli":"high","xss":"low"}`
	cfg.SetCategorySensitivity(map[string]string{"xss": "strict"})

	got := buildProtectionResponse(cfg)
	sensitivity, ok := got["category_sensitivity"].(map[string]string)
	if !ok {
		t.Fatalf("category_sensitivity missing or wrong type: %#v", got["category_sensitivity"])
	}
	if sensitivity["sqli"] != "high" || sensitivity["xss"] != "strict" {
		t.Fatalf("expected effective sensitivity to merge legacy modules, got %#v", sensitivity)
	}
}

func TestUpdateSensitivityConfigClearsLegacyOWASPModules(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.OWASPModules = `{"sqli":"high"}`
	cfg.SetCategorySensitivity(map[string]string{"xss": "low"})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	body := []byte(`{"category_sensitivity":{"cmd_injection":"strict"}}`)
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/protection/global/sensitivity")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "global"}}

	UpdateSensitivityConfig(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.OWASPModules != "{}" {
		t.Fatalf("expected legacy owasp_modules to be cleared, got %q", loaded.OWASPModules)
	}
	sensitivity := loaded.GetCategorySensitivity()
	if len(sensitivity) != 1 || sensitivity["cmd_injection"] != "strict" {
		t.Fatalf("unexpected category_sensitivity after update: %#v", sensitivity)
	}

	var resp sensitivityRequest
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CategorySensitivity["cmd_injection"] != "strict" {
		t.Fatalf("unexpected response sensitivity: %#v", resp.CategorySensitivity)
	}
}

func TestGetProtectionSettingsDefaultsMissingCVEAutoDropFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("protection", `{"cve_enabled":true,"cve_action":"intercept"}`); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, GetProtectionSettings(repo), "GET", "/api/v1/protection-settings", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["cve_auto_drop_critical"] != true || got["cve_auto_drop_high"] != true {
		t.Fatalf("expected missing CVE auto-drop fields to default true, got %#v", got)
	}
}

func TestProtectionResponseDefaultsJSONFields(t *testing.T) {
	cfg := store.DefaultProtectionConfig()

	got := buildProtectionResponse(cfg)
	for _, key := range []string{"cc_rules", "chain_steps", "escalation_steps"} {
		items, ok := got[key].([]any)
		if !ok || len(items) != 0 {
			t.Fatalf("%s should default to empty array, got %#v", key, got[key])
		}
	}
	for _, key := range []string{"owasp_modules", "owasp_rules_config", "cve_rules_config", "category_sensitivity"} {
		obj, ok := got[key].(map[string]any)
		if !ok || len(obj) != 0 {
			if typed, typedOK := got[key].(map[string]string); !typedOK || len(typed) != 0 {
				t.Fatalf("%s should default to empty object, got %#v", key, got[key])
			}
		}
	}
}

func TestPutProtectionSettingsPartialBodyPreservesChallengeFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.ChainEnabled = true
	cfg.ChainSteps = `[{"type":"captcha","condition":"all","captcha_type":"math"}]`
	cfg.CaptchaEnabled = true
	cfg.ShieldEnabled = true
	cfg.EscalationEnabled = true
	cfg.EscalationWindowSecs = 120
	cfg.SetEscalationSteps([]store.EscalationStepDef{{Threshold: 3, Action: "challenge"}})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "PUT", "/api/v1/protection-settings", []byte(`{"builtin_owasp_on_hit":"observe"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.OWASPAction != "observe" {
		t.Fatalf("partial update did not update requested field: %#v", loaded)
	}
	if !loaded.ChainEnabled || loaded.ChainSteps != cfg.ChainSteps || !loaded.CaptchaEnabled || !loaded.ShieldEnabled || !loaded.EscalationEnabled || loaded.EscalationWindowSecs != 120 {
		t.Fatalf("partial update should preserve challenge fields: %#v", loaded)
	}
	steps := loaded.GetEscalationSteps()
	if len(steps) != 1 || steps[0].Threshold != 3 || steps[0].Action != "challenge" {
		t.Fatalf("partial update should preserve escalation steps: %#v", steps)
	}
}

func TestPutProtectionSettingsRejectsRedirectWithoutTargetField(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "PUT", "/api/v1/protection-settings", []byte(`{"request_ratelimit_action":"redirect"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestPutProtectionSettingsRejectsCCRuleRedirectWithoutTargetField(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "PUT", "/api/v1/protection-settings", []byte(`{
		"cc_use_custom": true,
		"cc_rules": [
			{
				"enabled": true,
				"action": "redirect",
				"conditions": [{"target":"url_path","operator":"prefix","value":"/admin"}]
			}
		]
	}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestPutProtectionSettingsSavesStructuredCCRules(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CCUseCustom = false
	cfg.CCRules = "[]"
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	body := []byte(`{
		"cc_use_custom": true,
		"cc_rules": [
			{
				"enabled": true,
				"action": "challenge",
				"conditions": [
					{"target":"url_path","operator":"prefix","value":"/admin"},
					{"target":"method","operator":"equals","value":"POST"}
				],
				"window": 60,
				"threshold": 100,
				"duration": 5
			}
		]
	}`)
	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "PUT", "/api/v1/protection-settings", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.CCUseCustom {
		t.Fatal("cc_use_custom was not saved")
	}
	var rules []map[string]any
	if err := json.Unmarshal([]byte(loaded.CCRules), &rules); err != nil {
		t.Fatalf("cc_rules was not stored as array JSON: %v; raw=%s", err, loaded.CCRules)
	}
	if len(rules) != 1 {
		t.Fatalf("stored cc_rules length = %d want 1: %#v", len(rules), rules)
	}
	if rules[0]["action"] != "challenge" {
		t.Fatalf("stored action = %#v want challenge", rules[0]["action"])
	}
	if rules[0]["window"] != float64(60) || rules[0]["threshold"] != float64(100) || rules[0]["duration"] != float64(5) {
		t.Fatalf("stored rate settings were not preserved: %#v", rules[0])
	}

	resp := buildProtectionResponse(loaded)
	exposed, ok := resp["cc_rules"].([]any)
	if !ok || len(exposed) != 1 {
		t.Fatalf("response cc_rules should expand to array, got %#v", resp["cc_rules"])
	}
}

func TestPutProtectionSettingsLoginPatchPreservesSensitivityFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.OWASPModules = `{"sqli":"high"}`
	cfg.SetCategorySensitivity(map[string]string{"xss": "strict"})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "PUT", "/api/v1/protection-settings", []byte(`{"login_max_attempts":7}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.LoginMaxAttempts != 7 {
		t.Fatalf("login_max_attempts was not updated: %#v", loaded)
	}
	if loaded.OWASPModules != `{"sqli":"high"}` {
		t.Fatalf("login patch should preserve owasp_modules, got %q", loaded.OWASPModules)
	}
	sensitivity := loaded.GetCategorySensitivity()
	if len(sensitivity) != 1 || sensitivity["xss"] != "strict" {
		t.Fatalf("login patch should preserve category_sensitivity, got %#v", sensitivity)
	}
}

func TestGetDropPolicyDefaultsMissingCVEAutoDropFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("drop_policy", `{"enabled":true,"bot_score_threshold":90}`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	ctx := invokeProtectHandler(t, GetDropPolicy(repo), "GET", "/api/v1/drop-policy", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got DropPolicyResponse
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.Enabled || got.BotScoreThreshold != 90 || !got.CVEAutoDropCritical || !got.CVEAutoDropHigh {
		t.Fatalf("expected missing CVE auto-drop fields to default true, got %#v", got)
	}
}

func TestGetDropPolicyDefaultsEmptyStoredPolicy(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("drop_policy", `{}`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	ctx := invokeProtectHandler(t, GetDropPolicy(repo), "GET", "/api/v1/drop-policy", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got DropPolicyResponse
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.Enabled || got.BotScoreThreshold != 80 || !got.CVEAutoDropCritical || !got.CVEAutoDropHigh {
		t.Fatalf("expected empty stored drop policy to use defaults, got %#v", got)
	}
}

func TestGetDropPolicyDerivesMissingSharedFieldsFromProtectionAndBotSettings(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CVEAutoDropCritical = false
	cfg.CVEAutoDropHigh = false
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if err := repo.Set("bot_settings", `{"enabled":true,"score_threshold":91}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	ctx := invokeProtectHandler(t, GetDropPolicy(repo), "GET", "/api/v1/drop-policy", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got DropPolicyResponse
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.Enabled || got.BotScoreThreshold != 91 || got.CVEAutoDropCritical || got.CVEAutoDropHigh {
		t.Fatalf("expected drop policy to derive shared fields, got %#v", got)
	}
}

func TestUpdateDropPolicyEnabledPatchDoesNotSyncDefaultSharedFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CVEAutoDropCritical = false
	cfg.CVEAutoDropHigh = false
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if err := repo.Set("bot_settings", `{"enabled":true,"score_threshold":91}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	ctx := invokeProtectHandler(t, UpdateDropPolicy(repo, func() error { return nil }), "POST", "/api/v1/drop-policy/update", []byte(`{"enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	protection := shared.LoadProtectionConfig(repo)
	if protection.CVEAutoDropCritical || protection.CVEAutoDropHigh {
		t.Fatalf("enabled-only patch should not sync default CVE flags into protection: %#v", protection)
	}

	val, err := repo.Get("bot_settings")
	if err != nil {
		t.Fatalf("load bot settings: %v", err)
	}
	var bot shared.BotSettingsResponse
	if err := json.Unmarshal([]byte(val), &bot); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if bot.ScoreThreshold != 91 {
		t.Fatalf("enabled-only patch should not sync default bot threshold, got %d", bot.ScoreThreshold)
	}

	val, err = repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("load drop policy: %v", err)
	}
	var dropPolicy DropPolicyResponse
	if err := json.Unmarshal([]byte(val), &dropPolicy); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if dropPolicy.Enabled || dropPolicy.BotScoreThreshold != 91 || dropPolicy.CVEAutoDropCritical || dropPolicy.CVEAutoDropHigh {
		t.Fatalf("drop policy should save enabled change over derived shared fields, got %#v", dropPolicy)
	}
}

func TestGetBotSettingsDerivesMissingSettingsFromProtectionAndDropPolicy(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.BotDetectionEnabled = true
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if err := repo.Set("drop_policy", `{"enabled":true,"bot_score_threshold":88}`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	ctx := invokeProtectHandler(t, GetBotSettings(repo), "GET", "/api/v1/bot-settings", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got shared.BotSettingsResponse
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.Enabled || got.ScoreThreshold != 88 {
		t.Fatalf("expected bot settings to derive enabled/threshold, got %#v", got)
	}
}

func TestUpdateBotSettingsListPatchDoesNotSyncDefaultEnabledOrThreshold(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.BotDetectionEnabled = true
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if err := repo.Set("drop_policy", `{"enabled":true,"bot_score_threshold":92,"cve_auto_drop_critical":true,"cve_auto_drop_high":true}`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	ctx := invokeProtectHandler(t, UpdateBotSettings(repo, func() error { return nil }), "POST", "/api/v1/bot-settings/update", []byte(`{"high_risk_countries":["CN","RU"]}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	protection := shared.LoadProtectionConfig(repo)
	if !protection.BotDetectionEnabled {
		t.Fatalf("bot list-only patch should not sync default enabled=false into protection: %#v", protection)
	}

	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("load drop policy: %v", err)
	}
	var dropPolicy struct {
		BotScoreThreshold int `json:"bot_score_threshold"`
	}
	if err := json.Unmarshal([]byte(val), &dropPolicy); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if dropPolicy.BotScoreThreshold != 92 {
		t.Fatalf("bot list-only patch should not sync default threshold=60 into drop policy, got %d", dropPolicy.BotScoreThreshold)
	}
}

func TestUpdateBotSettingsRejectsInvalidScoreThreshold(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	for _, body := range [][]byte{
		[]byte(`{"score_threshold":0}`),
		[]byte(`{"score_threshold":101}`),
	} {
		ctx := invokeProtectHandler(t, UpdateBotSettings(repo, func() error { return nil }), "POST", "/api/v1/bot-settings/update", body)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("expected invalid score_threshold to return 400, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	}
	if val, err := repo.Get("bot_settings"); err == nil && val != "" {
		t.Fatalf("invalid score_threshold should not create bot_settings, got %s", val)
	}
}

func TestUpdateDropPolicyRejectsInvalidBotScoreThreshold(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	for _, body := range [][]byte{
		[]byte(`{"bot_score_threshold":0}`),
		[]byte(`{"bot_score_threshold":101}`),
	} {
		ctx := invokeProtectHandler(t, UpdateDropPolicy(repo, func() error { return nil }), "POST", "/api/v1/drop-policy/update", body)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("expected invalid bot_score_threshold to return 400, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	}
	if val, err := repo.Get("drop_policy"); err == nil && val != "" {
		t.Fatalf("invalid bot_score_threshold should not create drop_policy, got %s", val)
	}
}
