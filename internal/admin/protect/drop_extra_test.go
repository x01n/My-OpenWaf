package protect

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
)

// TestDefaultDropPolicyResponseWithNilRepo 验证仓储为 nil 时返回硬编码默认值。
func TestDefaultDropPolicyResponseWithNilRepo(t *testing.T) {
	got := defaultDropPolicyResponse(nil)
	if !got.Enabled || got.BotScoreThreshold != 80 || !got.CVEAutoDropCritical || !got.CVEAutoDropHigh {
		t.Fatalf("nil repo should yield hardcoded defaults: %#v", got)
	}
}

// TestDefaultDropPolicyResponseIgnoresCorruptedBotSettings 验证 bot_settings 损坏时沿用默认阈值。
func TestDefaultDropPolicyResponseIgnoresCorruptedBotSettings(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("bot_settings", `not-json`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}
	if got := defaultDropPolicyResponse(repo); got.BotScoreThreshold != 80 {
		t.Fatalf("corrupted bot_settings should keep default threshold 80, got %d", got.BotScoreThreshold)
	}

	// 阈值为 0 时同样不覆盖默认值。
	if err := repo.Set("bot_settings", `{"score_threshold":0}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}
	if got := defaultDropPolicyResponse(repo); got.BotScoreThreshold != 80 {
		t.Fatalf("zero threshold should keep default 80, got %d", got.BotScoreThreshold)
	}
}

// TestGetDropPolicyFallsBackOnCorruptedStoredJSON 验证 drop_policy 损坏时回落到派生默认值。
func TestGetDropPolicyFallsBackOnCorruptedStoredJSON(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CVEAutoDropCritical = false
	cfg.CVEAutoDropHigh = true
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if err := repo.Set("bot_settings", `{"score_threshold":77}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}
	if err := repo.Set("drop_policy", `not-json`); err != nil {
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
	if !got.Enabled || got.BotScoreThreshold != 77 || got.CVEAutoDropCritical || !got.CVEAutoDropHigh {
		t.Fatalf("corrupted drop_policy should fall back to derived defaults: %#v", got)
	}
}

// TestUpdateDropPolicyRejectsInvalidBody 验证请求体非法时返回 400。
func TestUpdateDropPolicyRejectsInvalidBody(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, UpdateDropPolicy(repo, func() error { return nil }), "POST", "/api/v1/drop-policy/update", []byte(`{"enabled":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for malformed body, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdateDropPolicyReloadFailureReturns500 验证 reload 失败时返回 500 并回带已保存的策略。
func TestUpdateDropPolicyReloadFailureReturns500(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, UpdateDropPolicy(repo, func() error { return errors.New("reload boom") }), "POST", "/api/v1/drop-policy/update", []byte(`{"bot_score_threshold":58}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 on reload failure, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		Error  string             `json:"error"`
		Policy DropPolicyResponse `json:"policy"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == "" || resp.Policy.BotScoreThreshold != 58 {
		t.Fatalf("reload failure response should carry the applied policy: %#v", resp)
	}
	if val, err := repo.Get("drop_policy"); err != nil || val == "" {
		t.Fatal("drop_policy should already be saved before reload is attempted")
	}
}

// TestUpdateDropPolicyWithNilReload 验证 reload 为 nil 时不会 panic。
func TestUpdateDropPolicyWithNilReload(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, UpdateDropPolicy(repo, nil), "POST", "/api/v1/drop-policy/update", []byte(`{"enabled":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdateDropPolicyPreservesUnrelatedProtectionFields 验证 drop 快捷页保存不清空其他防护字段。
func TestUpdateDropPolicyPreservesUnrelatedProtectionFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaEnabled = true
	cfg.CaptchaType = "slide"
	cfg.ShieldEnabled = true
	cfg.ChainEnabled = true
	cfg.ChainSteps = `[{"type":"captcha","condition":"all","captcha_type":"rotate"}]`
	cfg.EscalationEnabled = true
	cfg.EscalationWindowSecs = 180
	cfg.SetEscalationSteps([]store.EscalationStepDef{{Threshold: 2, Action: "chain_challenge"}})
	cfg.SetCategorySensitivity(map[string]string{"sqli": "very_high"})
	cfg.CVEAutoDropCritical = false
	cfg.CVEAutoDropHigh = false
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, UpdateDropPolicy(repo, func() error { return nil }), "POST", "/api/v1/drop-policy/update", []byte(`{"cve_auto_drop_critical":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.CVEAutoDropCritical {
		t.Fatal("cve_auto_drop_critical was not synced into protection")
	}
	if loaded.CVEAutoDropHigh {
		t.Fatal("cve_auto_drop_high must stay untouched when it is not submitted")
	}
	if !loaded.CaptchaEnabled || loaded.CaptchaType != "slide" || !loaded.ShieldEnabled {
		t.Fatalf("drop update clobbered captcha/shield config: %#v", loaded)
	}
	if !loaded.ChainEnabled || loaded.ChainSteps != cfg.ChainSteps {
		t.Fatalf("drop update clobbered chain config: %#v", loaded)
	}
	if !loaded.EscalationEnabled || loaded.EscalationWindowSecs != 180 {
		t.Fatalf("drop update clobbered escalation config: %#v", loaded)
	}
	steps := loaded.GetEscalationSteps()
	if len(steps) != 1 || steps[0].Action != "chain_challenge" {
		t.Fatalf("drop update clobbered escalation steps: %#v", steps)
	}
	if sens := loaded.GetCategorySensitivity(); sens["sqli"] != "very_high" {
		t.Fatalf("drop update clobbered category sensitivity: %#v", sens)
	}
}
