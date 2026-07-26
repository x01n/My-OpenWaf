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

func invokeDropPolicyHandler(t *testing.T, handler app.HandlerFunc, payload map[string]any) *app.RequestContext {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/drop-policy/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

// TestDropPolicyDefaultValues 验证首次无存储时的默认值。
func TestDropPolicyDefaultValues(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	resp := defaultDropPolicyResponse(repo)
	if !resp.Enabled {
		t.Fatal("default Enabled should be true")
	}
	if resp.BotScoreThreshold != 80 {
		t.Fatalf("default BotScoreThreshold should be 80, got %d", resp.BotScoreThreshold)
	}
	if !resp.CVEAutoDropCritical || !resp.CVEAutoDropHigh {
		t.Fatalf("default CVEAutoDrop should be true: critical=%v, high=%v", resp.CVEAutoDropCritical, resp.CVEAutoDropHigh)
	}
}

// TestUpdateDropPolicyPreservesUnsetFields 验证局部更新不覆盖未发送的字段。
func TestUpdateDropPolicyPreservesUnsetFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CVEAutoDropCritical = true
	cfg.CVEAutoDropHigh = true
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatal(err)
	}

	// 植入完整初始状态
	seed := invokeDropPolicyHandler(t, UpdateDropPolicy(repo, func() error { return nil }), map[string]any{
		"enabled":                true,
		"bot_score_threshold":    75,
		"cve_auto_drop_critical": true,
		"cve_auto_drop_high":     true,
	})
	if seed.Response.StatusCode() != 200 {
		t.Fatalf("seed: unexpected status %d", seed.Response.StatusCode())
	}

	// 只更新 enabled，其余字段不变
	ctx := invokeDropPolicyHandler(t, UpdateDropPolicy(repo, func() error { return nil }), map[string]any{
		"enabled": false,
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatal(err)
	}
	var saved DropPolicyResponse
	if err := json.Unmarshal([]byte(val), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Enabled {
		t.Fatal("Enabled should be false after update")
	}
	if saved.BotScoreThreshold != 75 {
		t.Fatalf("BotScoreThreshold was overwritten: got %d", saved.BotScoreThreshold)
	}
	if !saved.CVEAutoDropCritical || !saved.CVEAutoDropHigh {
		t.Fatalf("CVEAutoDrop fields were overwritten: critical=%v, high=%v", saved.CVEAutoDropCritical, saved.CVEAutoDropHigh)
	}
}

// TestUpdateDropPolicySyncsCVEToProtection 验证 CVE 字段同步写入 protection 配置。
func TestUpdateDropPolicySyncsCVEToProtection(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CVEAutoDropCritical = false
	cfg.CVEAutoDropHigh = false
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatal(err)
	}

	ctx := invokeDropPolicyHandler(t, UpdateDropPolicy(repo, func() error { return nil }), map[string]any{
		"cve_auto_drop_critical": true,
		"cve_auto_drop_high":     true,
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.CVEAutoDropCritical || !loaded.CVEAutoDropHigh {
		t.Fatalf("CVE auto drop not synced: critical=%v, high=%v", loaded.CVEAutoDropCritical, loaded.CVEAutoDropHigh)
	}
}

// TestUpdateDropPolicyInvalidBotScoreThreshold 验证 bot_score_threshold 超出 1-100 范围时返回 400。
func TestUpdateDropPolicyInvalidBotScoreThreshold(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	for _, invalid := range []int{0, 101} {
		ctx := invokeDropPolicyHandler(t, UpdateDropPolicy(repo, func() error { return nil }), map[string]any{
			"bot_score_threshold": invalid,
		})
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("bot_score_threshold=%d: expected 400, got %d", invalid, ctx.Response.StatusCode())
		}
	}
}

// TestUpdateDropPolicySyncsBotThresholdToBotSettings 验证 bot_score_threshold 反向同步到 bot_settings。
func TestUpdateDropPolicySyncsBotThresholdToBotSettings(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeDropPolicyHandler(t, UpdateDropPolicy(repo, func() error { return nil }), map[string]any{
		"bot_score_threshold": 65,
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, _ := repo.Get("bot_settings")
	if val != "" {
		var bot shared.BotSettingsResponse
		if err := json.Unmarshal([]byte(val), &bot); err == nil {
			if bot.ScoreThreshold != 65 {
				t.Fatalf("bot ScoreThreshold not synced from drop policy: got %d", bot.ScoreThreshold)
			}
		}
	}
	// 通过 defaultDropPolicyResponse 验证：drop_policy 的默认 bot 阈值读自 bot_settings
	resp := defaultDropPolicyResponse(repo)
	if resp.BotScoreThreshold != 65 {
		t.Fatalf("drop policy default BotScoreThreshold should reflect synced value 65, got %d", resp.BotScoreThreshold)
	}
}
