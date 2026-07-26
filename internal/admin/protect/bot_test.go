package protect

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
)

func invokeBotSettingsHandler(t *testing.T, handler app.HandlerFunc, payload map[string]any) *app.RequestContext {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/bot-settings/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

// TestUpdateBotSettingsPreservesUnsetFields 验证局部更新不覆盖未发送的字段。
func TestUpdateBotSettingsPreservesUnsetFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.BotDetectionEnabled = true
	cfg.CaptchaEnabled = true
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatal(err)
	}

	// 植入完整 bot_settings 初始状态
	initial := shared.BotSettingsResponse{
		Enabled:                  true,
		ScoreThreshold:           70,
		CaptchaEnabled:           true,
		DynamicProtectionEnabled: false,
		HTMLObfuscation:          true,
		JSObfuscation:            false,
		ImageWatermark:           true,
		AntiReplayEnabled:        true,
		BrowserSignEnabled:       false,
		BrowserSignTTL:           300,
		BrowserSignAction:        "challenge",
	}
	data, _ := json.Marshal(initial)
	if err := repo.Set("bot_settings", string(data)); err != nil {
		t.Fatal(err)
	}

	// 只更新 ScoreThreshold
	ctx := invokeBotSettingsHandler(t, UpdateBotSettings(repo, func() error { return nil }), map[string]any{
		"score_threshold": 85,
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get("bot_settings")
	if err != nil {
		t.Fatal(err)
	}
	var saved shared.BotSettingsResponse
	if err := json.Unmarshal([]byte(val), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.ScoreThreshold != 85 {
		t.Fatalf("ScoreThreshold not updated: got %d", saved.ScoreThreshold)
	}
	if !saved.Enabled {
		t.Fatal("Enabled was unexpectedly cleared")
	}
	if !saved.CaptchaEnabled {
		t.Fatal("CaptchaEnabled was unexpectedly cleared")
	}
	if !saved.HTMLObfuscation {
		t.Fatal("HTMLObfuscation was unexpectedly cleared")
	}
	if !saved.ImageWatermark {
		t.Fatal("ImageWatermark was unexpectedly cleared")
	}
	if !saved.AntiReplayEnabled {
		t.Fatal("AntiReplayEnabled was unexpectedly cleared")
	}
}

// TestUpdateBotSettingsInvalidScoreThreshold 验证 score_threshold 超出范围时返回 400。
func TestUpdateBotSettingsInvalidScoreThreshold(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	for _, invalid := range []int{0, 101, -1, 200} {
		ctx := invokeBotSettingsHandler(t, UpdateBotSettings(repo, func() error { return nil }), map[string]any{
			"score_threshold": invalid,
		})
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("score_threshold=%d: expected 400, got %d", invalid, ctx.Response.StatusCode())
		}
	}
}

// TestUpdateBotSettingsSyncsBotDetectionEnabled 验证 enabled 字段同步写入 protection 配置。
func TestUpdateBotSettingsSyncsBotDetectionEnabled(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.BotDetectionEnabled = false
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatal(err)
	}

	ctx := invokeBotSettingsHandler(t, UpdateBotSettings(repo, func() error { return nil }), map[string]any{
		"enabled": true,
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.BotDetectionEnabled {
		t.Fatalf("BotDetectionEnabled not synced to protection config: got %v", loaded.BotDetectionEnabled)
	}
}

// TestGetBotSettingsBackfillsBrowserSignFromProtection 验证 GetBotSettings 始终以 protection 为权威回填 BrowserSign 字段。
func TestGetBotSettingsBackfillsBrowserSignFromProtection(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.BrowserSignEnabled = true
	cfg.BrowserSignTTL = 600
	cfg.BrowserSignAction = "block"
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatal(err)
	}

	// bot_settings 中存储的是旧值（false/0/"challenge"）
	old := shared.BotSettingsResponse{
		Enabled:            true,
		BrowserSignEnabled: false,
		BrowserSignTTL:     0,
		BrowserSignAction:  "challenge",
	}
	data, _ := json.Marshal(old)
	if err := repo.Set("bot_settings", string(data)); err != nil {
		t.Fatal(err)
	}

	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/bot-settings")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	GetBotSettings(repo)(context.Background(), ctx)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d", ctx.Response.StatusCode())
	}
	var resp shared.BotSettingsResponse
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.BrowserSignEnabled {
		t.Fatal("BrowserSignEnabled not backfilled from protection")
	}
	if resp.BrowserSignTTL != 600 {
		t.Fatalf("BrowserSignTTL not backfilled: got %d", resp.BrowserSignTTL)
	}
	if resp.BrowserSignAction != "block" {
		t.Fatalf("BrowserSignAction not backfilled: got %s", resp.BrowserSignAction)
	}
}
