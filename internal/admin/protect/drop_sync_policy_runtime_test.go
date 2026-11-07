package protect

import (
	"encoding/json"
	"testing"

	botpkg "My-OpenWaf/internal/admin/protect/bot"
)

func TestBotThresholdUpdateOnEmptySettingsWritesPartialDropPolicy(t *testing.T) {
	repo := newSystemSettingsRepoForProtectionTest(t)
	ctx := invokeProtectionHandler(t, botpkg.UpdateBotSettings(repo, func() error { return nil }), "POST", "/api/v1/bot-settings/update", []byte(`{"score_threshold":55}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected bot settings update 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	ctx = invokeProtectionHandler(t, botpkg.GetBotSettings(repo), "GET", "/api/v1/bot-settings", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected bot settings read 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var botSettings map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &botSettings); err != nil {
		t.Fatalf("decode bot settings response: %v", err)
	}
	if got := botSettings["score_threshold"]; got != float64(55) {
		t.Fatalf("expected score_threshold 55, got %v", got)
	}

	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("get drop policy: %v", err)
	}
	var dropPolicy map[string]json.RawMessage
	if err := json.Unmarshal([]byte(val), &dropPolicy); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if len(dropPolicy) != 1 || string(dropPolicy["bot_score_threshold"]) != "55" {
		t.Fatalf("expected only bot_score_threshold in drop policy, got %s", val)
	}
}

func TestProtectionCVEAutoDropUpdateOnEmptySettingsWritesPartialDropPolicy(t *testing.T) {
	repo := newSystemSettingsRepoForProtectionTest(t)
	ctx := invokeProtectionHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", []byte(`{"cve_auto_drop_critical":false,"cve_auto_drop_high":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("expected protection update 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	val, err := repo.Get("drop_policy")
	if err != nil {
		t.Fatalf("get drop policy: %v", err)
	}
	var dropPolicy map[string]json.RawMessage
	if err := json.Unmarshal([]byte(val), &dropPolicy); err != nil {
		t.Fatalf("decode drop policy: %v", err)
	}
	if len(dropPolicy) != 2 || string(dropPolicy["cve_auto_drop_critical"]) != "false" || string(dropPolicy["cve_auto_drop_high"]) != "true" {
		t.Fatalf("expected only CVE auto-drop fields in drop policy, got %s", val)
	}
}
