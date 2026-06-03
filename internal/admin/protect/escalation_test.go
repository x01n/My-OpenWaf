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

func invokeEscalationConfigHandler(t *testing.T, handler app.HandlerFunc, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/protection/global/escalation")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "global"}}
	handler(context.Background(), ctx)
	return ctx
}

func TestUpdateEscalationConfigPreservesOmittedEnabledAndWindow(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.EscalationEnabled = true
	cfg.EscalationWindowSecs = 120
	cfg.SetEscalationSteps([]store.EscalationStepDef{
		{Threshold: 3, Action: "challenge"},
		{Threshold: 5, Action: "block"},
	})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeEscalationConfigHandler(t, UpdateEscalationConfig(repo, func() error { return nil }), []byte(`{"escalation_steps":[{"threshold":7,"action":"intercept"}]}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.EscalationEnabled || loaded.EscalationWindowSecs != 120 {
		t.Fatalf("steps-only patch should preserve enabled/window: %#v", loaded)
	}
	steps := loaded.GetEscalationSteps()
	if len(steps) != 1 || steps[0].Threshold != 7 || steps[0].Action != "intercept" {
		t.Fatalf("steps-only patch did not update escalation steps: %#v", steps)
	}
}

func TestUpdateEscalationConfigExplicitFalsePreservesOmittedSteps(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.EscalationEnabled = true
	cfg.EscalationWindowSecs = 90
	cfg.SetEscalationSteps([]store.EscalationStepDef{{Threshold: 3, Action: "challenge"}})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeEscalationConfigHandler(t, UpdateEscalationConfig(repo, func() error { return nil }), []byte(`{"escalation_enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.EscalationEnabled {
		t.Fatalf("explicit escalation_enabled=false was not persisted: %#v", loaded)
	}
	if loaded.EscalationWindowSecs != 90 {
		t.Fatalf("enabled-only patch should preserve escalation window, got %d", loaded.EscalationWindowSecs)
	}
	steps := loaded.GetEscalationSteps()
	if len(steps) != 1 || steps[0].Threshold != 3 || steps[0].Action != "challenge" {
		t.Fatalf("enabled-only patch should preserve escalation steps: %#v", steps)
	}
}

func TestUpdateEscalationConfigExplicitEmptyStepsClearsSteps(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.EscalationEnabled = true
	cfg.SetEscalationSteps([]store.EscalationStepDef{{Threshold: 3, Action: "challenge"}})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeEscalationConfigHandler(t, UpdateEscalationConfig(repo, func() error { return nil }), []byte(`{"escalation_steps":[]}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if steps := loaded.GetEscalationSteps(); len(steps) != 0 {
		t.Fatalf("explicit empty escalation_steps should clear steps: %#v", steps)
	}

	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if steps, ok := resp["escalation_steps"].([]any); !ok || len(steps) != 0 {
		t.Fatalf("response should include cleared escalation_steps, got %#v", resp["escalation_steps"])
	}
}

func TestUpdateEscalationConfigRejectsExplicitZeroWindow(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.EscalationWindowSecs = 90
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeEscalationConfigHandler(t, UpdateEscalationConfig(repo, func() error { return nil }), []byte(`{"escalation_window_secs":0}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected explicit zero window to be rejected, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.EscalationWindowSecs != 90 {
		t.Fatalf("rejected window update should preserve stored window, got %d", loaded.EscalationWindowSecs)
	}
}
