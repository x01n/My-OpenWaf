package protect

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/challenge"
)

// TestGetCaptchaConfigReturnsStoredProtectionValues 验证读取接口直接反映 protection 中的验证码/盾配置。
func TestGetCaptchaConfigReturnsStoredProtectionValues(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaEnabled = true
	cfg.CaptchaType = "slide"
	cfg.CaptchaTimeout = 77
	cfg.CaptchaPassTTL = 888
	cfg.ShieldEnabled = true
	cfg.ShieldDifficulty = 5
	cfg.ShieldTimeoutSecs = 19
	cfg.ShieldMaxRetries = 3
	cfg.ShieldEnvStrictness = 2
	cfg.ShieldRequireHTTP2 = true
	cfg.ShieldEnableJSChallenge = true
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, GetCaptchaConfig(repo), "GET", "/api/v1/captcha/config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got captchaConfigResponse
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.CaptchaEnabled || got.CaptchaType != "slide" || got.CaptchaTimeout != 77 || got.CaptchaPassTTL != 888 {
		t.Fatalf("captcha fields not reflected: %#v", got)
	}
	if !got.ShieldEnabled || got.ShieldDifficulty != 5 || got.ShieldTimeoutSecs != 19 || got.ShieldMaxRetries != 3 || got.ShieldEnvStrictness != 2 {
		t.Fatalf("shield fields not reflected: %#v", got)
	}
	if !got.ShieldRequireHTTP2 || !got.ShieldEnableJSChallenge {
		t.Fatalf("shield boolean fields not reflected: %#v", got)
	}
}

// TestUpdateCaptchaConfigRejectsInvalidBody 验证请求体非法时返回 400。
func TestUpdateCaptchaConfigRejectsInvalidBody(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, UpdateCaptchaConfig(repo, func() error { return nil }), "POST", "/api/v1/captcha/config", []byte(`{"captcha_enabled":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for malformed body, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdateCaptchaConfigRejectsUnknownCaptchaType 验证 captcha_type 只接受 math/click/slide/rotate，
// 挑战动作名（shield_challenge / chain_challenge）不得被当作验证码类型混入。
func TestUpdateCaptchaConfigRejectsUnknownCaptchaType(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaType = "math"
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	for _, invalid := range []string{"drag", "shield_challenge", "chain_challenge", "captcha_challenge", "MATH"} {
		ctx := invokeProtectHandler(t, UpdateCaptchaConfig(repo, func() error { return nil }), "POST", "/api/v1/captcha/config", []byte(`{"captcha_type":"`+invalid+`"}`))
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("captcha_type=%q: expected 400, got %d: %s", invalid, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		if loaded := shared.LoadProtectionConfig(repo); loaded.CaptchaType != "math" {
			t.Fatalf("captcha_type=%q: rejected value must not be stored, got %q", invalid, loaded.CaptchaType)
		}
	}
}

// TestUpdateCaptchaConfigAcceptsAllValidCaptchaTypes 验证四种合法验证码类型都能保存。
func TestUpdateCaptchaConfigAcceptsAllValidCaptchaTypes(t *testing.T) {
	for _, valid := range []string{"math", "click", "slide", "rotate"} {
		repo := newSystemSettingsRepoForTest(t)
		ctx := invokeProtectHandler(t, UpdateCaptchaConfig(repo, func() error { return nil }), "POST", "/api/v1/captcha/config", []byte(`{"captcha_type":"`+valid+`"}`))
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("captcha_type=%q: unexpected status %d: %s", valid, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		if loaded := shared.LoadProtectionConfig(repo); loaded.CaptchaType != valid {
			t.Fatalf("captcha_type=%q was not persisted, got %q", valid, loaded.CaptchaType)
		}
	}
}

// TestUpdateCaptchaConfigIgnoresNonPositiveNumbers 验证非正数的超时/难度/重试值被忽略而不是清零。
func TestUpdateCaptchaConfigIgnoresNonPositiveNumbers(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaTimeout = 120
	cfg.CaptchaPassTTL = 600
	cfg.ShieldDifficulty = 4
	cfg.ShieldTimeoutSecs = 15
	cfg.ShieldMaxRetries = 3
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	body := []byte(`{"captcha_timeout":0,"captcha_pass_ttl":-1,"shield_difficulty":0,"shield_timeout_secs":-5,"shield_max_retries":0}`)
	ctx := invokeProtectHandler(t, UpdateCaptchaConfig(repo, func() error { return nil }), "POST", "/api/v1/captcha/config", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.CaptchaTimeout != 120 || loaded.CaptchaPassTTL != 600 {
		t.Fatalf("non-positive captcha numbers should be ignored: %#v", loaded)
	}
	if loaded.ShieldDifficulty != 4 || loaded.ShieldTimeoutSecs != 15 || loaded.ShieldMaxRetries != 3 {
		t.Fatalf("non-positive shield numbers should be ignored: %#v", loaded)
	}
}

// TestUpdateCaptchaConfigAppliesPositiveShieldNumbers 验证正数的盾难度/超时/重试值被写入。
func TestUpdateCaptchaConfigAppliesPositiveShieldNumbers(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.ShieldDifficulty = 3
	cfg.ShieldTimeoutSecs = 10
	cfg.ShieldMaxRetries = 2
	cfg.ShieldAutoStartDelay = 100
	cfg.ShieldEnvStrictness = 0
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	body := []byte(`{"shield_difficulty":7,"shield_timeout_secs":25,"shield_max_retries":5,"shield_auto_start_delay":1500,"shield_env_strictness":3}`)
	ctx := invokeProtectHandler(t, UpdateCaptchaConfig(repo, func() error { return nil }), "POST", "/api/v1/captcha/config", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.ShieldDifficulty != 7 || loaded.ShieldTimeoutSecs != 25 || loaded.ShieldMaxRetries != 5 {
		t.Fatalf("positive shield numbers not applied: %#v", loaded)
	}
	if loaded.ShieldAutoStartDelay != 1500 || loaded.ShieldEnvStrictness != 3 {
		t.Fatalf("shield delay/strictness not applied: %#v", loaded)
	}
}

// TestUpdateCaptchaConfigIgnoresNegativeEnvStrictnessAndDelay 验证仅负值被忽略，0 是合法取值。
func TestUpdateCaptchaConfigIgnoresNegativeEnvStrictnessAndDelay(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.ShieldAutoStartDelay = 500
	cfg.ShieldEnvStrictness = 2
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, UpdateCaptchaConfig(repo, func() error { return nil }), "POST", "/api/v1/captcha/config", []byte(`{"shield_auto_start_delay":-1,"shield_env_strictness":-1}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.ShieldAutoStartDelay != 500 || loaded.ShieldEnvStrictness != 2 {
		t.Fatalf("negative shield values should be ignored: %#v", loaded)
	}
}

// TestUpdateCaptchaConfigPreservesUnrelatedProtectionFields 验证验证码页保存不会清空 CC / 升级 / 灵敏度等无关字段。
func TestUpdateCaptchaConfigPreservesUnrelatedProtectionFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.ChainEnabled = true
	cfg.ChainSteps = `[{"type":"pow","condition":"all"}]`
	cfg.EscalationEnabled = true
	cfg.EscalationWindowSecs = 240
	cfg.SetEscalationSteps([]store.EscalationStepDef{{Threshold: 4, Action: "captcha_challenge"}})
	cfg.CCUseCustom = true
	cfg.CCRules = `[{"enabled":true,"action":"challenge"}]`
	cfg.SetCategorySensitivity(map[string]string{"xss": "very_high"})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, UpdateCaptchaConfig(repo, func() error { return nil }), "POST", "/api/v1/captcha/config", []byte(`{"captcha_enabled":true,"captcha_type":"click"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.ChainEnabled || loaded.ChainSteps != cfg.ChainSteps {
		t.Fatalf("captcha update clobbered chain config: %#v", loaded)
	}
	if !loaded.EscalationEnabled || loaded.EscalationWindowSecs != 240 {
		t.Fatalf("captcha update clobbered escalation config: %#v", loaded)
	}
	steps := loaded.GetEscalationSteps()
	if len(steps) != 1 || steps[0].Action != "captcha_challenge" {
		t.Fatalf("captcha update clobbered escalation steps: %#v", steps)
	}
	if !loaded.CCUseCustom || loaded.CCRules != cfg.CCRules {
		t.Fatalf("captcha update clobbered CC rules: %#v", loaded)
	}
	if sens := loaded.GetCategorySensitivity(); sens["xss"] != "very_high" {
		t.Fatalf("captcha update clobbered category sensitivity: %#v", sens)
	}
}

// TestUpdateCaptchaConfigReloadFailureReturns500 验证 reload 失败时返回 500，但配置已落库。
func TestUpdateCaptchaConfigReloadFailureReturns500(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, UpdateCaptchaConfig(repo, func() error { return errors.New("reload boom") }), "POST", "/api/v1/captcha/config", []byte(`{"captcha_enabled":true}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 on reload failure, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !shared.LoadProtectionConfig(repo).CaptchaEnabled {
		t.Fatal("config should already be saved before reload is attempted")
	}
}

// TestTestCaptchaWithoutManagerReturns503 验证验证码管理器未初始化时返回 503。
func TestTestCaptchaWithoutManagerReturns503(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, TestCaptcha(repo, nil), "POST", "/api/v1/captcha/test", nil)
	if ctx.Response.StatusCode() != 503 {
		t.Fatalf("expected 503 when captcha manager is nil, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestTestCaptchaGeneratesPreview 验证测试接口返回会话 ID、提示语与配置的超时/通过时长。
func TestTestCaptchaGeneratesPreview(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaType = "math"
	cfg.CaptchaTimeout = 95
	cfg.CaptchaPassTTL = 480
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	mgr := challenge.NewCaptchaManager(nil, 30*time.Second)
	defer mgr.Close()

	ctx := invokeProtectHandler(t, TestCaptcha(repo, mgr), "POST", "/api/v1/captcha/test", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if sid, ok := got["session_id"].(string); !ok || sid == "" {
		t.Fatalf("preview response missing session_id: %#v", got)
	}
	if got["captcha_type"] != "math" {
		t.Fatalf("captcha_type = %#v, want math", got["captcha_type"])
	}
	if got["type"] != string(challenge.CaptchaTypeMath) {
		t.Fatalf("generated challenge type = %#v, want math", got["type"])
	}
	if prompt, ok := got["prompt"].(string); !ok || prompt == "" {
		t.Fatalf("preview response missing prompt: %#v", got)
	}
	if got["timeout"] != float64(95) || got["pass_ttl"] != float64(480) {
		t.Fatalf("preview did not echo configured timeout/pass_ttl: %#v", got)
	}
}

// TestTestCaptchaFallsBackToMathWhenTypeUnset 验证未配置类型时回落到内置数学验证码。
func TestTestCaptchaFallsBackToMathWhenTypeUnset(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaType = ""
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	mgr := challenge.NewCaptchaManager(nil, 30*time.Second)
	defer mgr.Close()

	ctx := invokeProtectHandler(t, TestCaptcha(repo, mgr), "POST", "/api/v1/captcha/test", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var got map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["type"] != string(challenge.CaptchaTypeMath) {
		t.Fatalf("empty captcha_type should fall back to math, got %#v", got["type"])
	}
}
