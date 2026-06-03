package protect

import (
	"bytes"
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
)

func TestNormalizeChainStepPayloadUsesRuntimeFields(t *testing.T) {
	raw := json.RawMessage(`[{"type":"captcha","condition":"all","captcha_type":"rotate"},{"type":"pow","match":"score>50","captcha_type":"click"}]`)
	got, ok := normalizeChainStepPayload(raw)
	if !ok {
		t.Fatal("normalizeChainStepPayload() rejected valid steps")
	}
	var steps []chainStepPayload
	if err := json.Unmarshal([]byte(got), &steps); err != nil {
		t.Fatalf("normalizeChainStepPayload() returned invalid JSON: %v", err)
	}
	if len(steps) != 2 || steps[0].Type != "captcha" || steps[0].Condition != "all" || steps[0].CaptchaType != "rotate" || steps[1].Type != "pow" || steps[1].Condition != "score>50" || steps[1].CaptchaType != "" {
		t.Fatalf("normalizeChainStepPayload() decoded to %#v", steps)
	}
}

func TestNormalizeChainStepPayloadRejectsUnsupportedStep(t *testing.T) {
	if _, ok := normalizeChainStepPayload(json.RawMessage(`[{"type":"shield","condition":"all"}]`)); ok {
		t.Fatal("normalizeChainStepPayload() accepted unsupported shield step")
	}
}

func TestUpdateChainConfigPreservesOmittedEnabled(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.ChainEnabled = true
	cfg.ChainSteps = `[{"type":"captcha","condition":"all","captcha_type":"slide"}]`
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, UpdateChainConfig(repo, func() error { return nil }), "POST", "/api/v1/chain/config", []byte(`{"chain_steps":[{"type":"env","condition":"all"}]}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.ChainEnabled {
		t.Fatalf("steps-only patch should preserve enabled=true: %#v", loaded)
	}
	if loaded.ChainSteps != `[{"type":"env","condition":"all"}]` {
		t.Fatalf("steps-only patch did not update chain steps: %s", loaded.ChainSteps)
	}
}

func TestUpdateChainConfigExplicitFalsePreservesOmittedSteps(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.ChainEnabled = true
	cfg.ChainSteps = `[{"type":"pow","condition":"score>50"}]`
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeProtectHandler(t, UpdateChainConfig(repo, func() error { return nil }), "POST", "/api/v1/chain/config", []byte(`{"chain_enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.ChainEnabled {
		t.Fatalf("explicit chain_enabled=false was not persisted: %#v", loaded)
	}
	if loaded.ChainSteps != cfg.ChainSteps {
		t.Fatalf("enabled-only patch should preserve chain steps, got %s", loaded.ChainSteps)
	}
}
