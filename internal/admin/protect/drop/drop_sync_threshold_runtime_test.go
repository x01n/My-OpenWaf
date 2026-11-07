package drop

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	botpkg "My-OpenWaf/internal/admin/protect/bot"
	"My-OpenWaf/internal/admin/shared"
)

func TestUpdateDropPolicyOnEmptyBotSettingsPreservesBotDefaults(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeDropPolicyHandler(t, UpdateDropPolicy(repo, func() error { return nil }), map[string]any{
		"bot_score_threshold": 65,
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	value, err := repo.Get("bot_settings")
	if err != nil {
		t.Fatalf("get bot settings: %v", err)
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &stored); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if len(stored) != 1 || string(stored["score_threshold"]) != "65" {
		t.Fatalf("expected partial bot settings containing only score_threshold, got %s", value)
	}

	ctx = invokeBotSettingsGet(t, botpkg.GetBotSettings(repo))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected bot settings status %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var got shared.BotSettingsResponse
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode bot settings response: %v", err)
	}
	defaults := shared.LoadProtectionConfig(repo)
	if got.ScoreThreshold != 65 || got.Enabled != defaults.BotDetectionEnabled || got.CaptchaEnabled != defaults.CaptchaEnabled ||
		got.AntiReplayEnabled != defaults.AntiReplayEnabled || got.BrowserSignEnabled != defaults.BrowserSignEnabled {
		t.Fatalf("bot settings response did not preserve protection defaults: got=%+v defaults=%+v", got, defaults)
	}
}

func invokeBotSettingsGet(t *testing.T, handler app.HandlerFunc) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/bot-settings")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}
