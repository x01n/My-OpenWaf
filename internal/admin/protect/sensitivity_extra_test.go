package protect

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
)

// TestGetSensitivityConfigRejectsInvalidID 验证非 global 且非数字的 id 返回 400。
func TestGetSensitivityConfigRejectsInvalidID(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	for _, id := range []string{"notanumber", "", "-1"} {
		ctx := invokeSensitivityHandler(t, GetSensitivityConfig(repo), id, nil)
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("id=%q: expected 400, got %d", id, ctx.Response.StatusCode())
		}
	}
}

// TestSensitivityConfigAcceptsNumericSiteID 验证站点级路径参数（数字 id）被接受。
func TestSensitivityConfigAcceptsNumericSiteID(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSensitivityHandler(t, GetSensitivityConfig(repo), "7", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("GET with numeric id: unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	ctx = invokeSensitivityHandler(t, UpdateSensitivityConfig(repo, func() error { return nil }), "7", []byte(`{"category_sensitivity":{"sqli":"high"}}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("POST with numeric id: unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestGetSensitivityConfigReturnsEmptyMapWhenUnset 验证未配置时返回空对象而不是 null。
func TestGetSensitivityConfigReturnsEmptyMapWhenUnset(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CategorySensitivity = ""
	cfg.OWASPModules = ""
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeSensitivityHandler(t, GetSensitivityConfig(repo), "global", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(ctx.Response.Body(), &raw); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	value, ok := raw["category_sensitivity"]
	if !ok {
		t.Fatalf("response missing category_sensitivity: %s", ctx.Response.Body())
	}
	if string(value) == "null" {
		t.Fatalf("category_sensitivity should be an object, got null")
	}
}

// TestUpdateSensitivityConfigRejectsInvalidBody 验证请求体非法时返回 400。
func TestUpdateSensitivityConfigRejectsInvalidBody(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeSensitivityHandler(t, UpdateSensitivityConfig(repo, func() error { return nil }), "global", []byte(`{"category_sensitivity":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for malformed body, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdateSensitivityConfigAcceptsEmptyMap 验证空映射清空全部分类灵敏度。
func TestUpdateSensitivityConfigAcceptsEmptyMap(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.SetCategorySensitivity(map[string]string{"sqli": "strict"})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeSensitivityHandler(t, UpdateSensitivityConfig(repo, func() error { return nil }), "global", []byte(`{"category_sensitivity":{}}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if sens := loaded.GetCategorySensitivity(); len(sens) != 0 {
		t.Fatalf("empty map should clear category sensitivity, got %#v", sens)
	}
	if loaded.OWASPModules != "{}" {
		t.Fatalf("legacy owasp_modules should be cleared, got %q", loaded.OWASPModules)
	}
}

// TestUpdateSensitivityConfigAcceptsOffLevel 验证 off/none 级别可保存。
func TestUpdateSensitivityConfigAcceptsOffLevel(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeSensitivityHandler(t, UpdateSensitivityConfig(repo, func() error { return nil }), "global", []byte(`{"category_sensitivity":{"sqli":"off","xss":"none","rce":"low"}}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	sens := loaded.GetCategorySensitivity()
	if sens["sqli"] != "off" || sens["xss"] != "off" || sens["rce"] != "low" {
		t.Fatalf("unexpected stored sensitivity: %#v", sens)
	}
}

// TestUpdateSensitivityConfigReloadFailureReturns500 验证 reload 失败时返回 500，但配置已落库。
func TestUpdateSensitivityConfigReloadFailureReturns500(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeSensitivityHandler(t, UpdateSensitivityConfig(repo, func() error { return errors.New("reload boom") }), "global", []byte(`{"category_sensitivity":{"sqli":"strict"}}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 on reload failure, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	loaded := shared.LoadProtectionConfig(repo)
	if sens := loaded.GetCategorySensitivity(); sens["sqli"] != "strict" {
		t.Fatalf("config should already be saved before reload is attempted: %#v", sens)
	}
}

// TestUpdateSensitivityConfigPreservesUnrelatedProtectionFields 验证灵敏度保存不清空验证码/链式/升级字段。
func TestUpdateSensitivityConfigPreservesUnrelatedProtectionFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaEnabled = true
	cfg.ShieldEnabled = true
	cfg.ShieldDifficulty = 5
	cfg.ChainEnabled = true
	cfg.ChainSteps = `[{"type":"pow","condition":"all"}]`
	cfg.EscalationEnabled = true
	cfg.EscalationWindowSecs = 200
	cfg.CCUseCustom = true
	cfg.CCRules = `[{"enabled":true,"action":"captcha_challenge"}]`
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeSensitivityHandler(t, UpdateSensitivityConfig(repo, func() error { return nil }), "global", []byte(`{"category_sensitivity":{"sqli":"mid"}}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.CaptchaEnabled || !loaded.ShieldEnabled || loaded.ShieldDifficulty != 5 {
		t.Fatalf("sensitivity update clobbered captcha/shield config: %#v", loaded)
	}
	if !loaded.ChainEnabled || loaded.ChainSteps != cfg.ChainSteps {
		t.Fatalf("sensitivity update clobbered chain config: %#v", loaded)
	}
	if !loaded.EscalationEnabled || loaded.EscalationWindowSecs != 200 {
		t.Fatalf("sensitivity update clobbered escalation config: %#v", loaded)
	}
	if !loaded.CCUseCustom || loaded.CCRules != cfg.CCRules {
		t.Fatalf("sensitivity update clobbered CC rules: %#v", loaded)
	}
}
