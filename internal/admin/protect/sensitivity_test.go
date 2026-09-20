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
	"github.com/cloudwego/hertz/pkg/route/param"
)

func invokeSensitivityHandler(t *testing.T, handler app.HandlerFunc, id string, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/protection/" + id + "/sensitivity")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: id}}
	handler(context.Background(), ctx)
	return ctx
}

// TestNormalizeSensitivityLevelAliases 验证所有允许的别名都正确归一化。
func TestNormalizeSensitivityLevelAliases(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"off", "off"},
		{"none", "off"},
		{"OFF", "off"},
		{"low", "low"},
		{"LOW", "low"},
		{"medium", "mid"},
		{"mid", "mid"},
		{"MEDIUM", "mid"},
		{"high", "high"},
		{"HIGH", "high"},
		{"very_high", "very_high"},
		{"very-high", "very_high"},
		{"veryhigh", "very_high"},
		{"VERY_HIGH", "very_high"},
		{"strict", "strict"},
		{"STRICT", "strict"},
		{"unknown", ""},
		{"", ""},
		{"  high  ", "high"},
	}
	for _, tc := range cases {
		got := normalizeSensitivityLevel(tc.input)
		if got != tc.want {
			t.Errorf("normalizeSensitivityLevel(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestUpdateSensitivityConfigRejectsInvalidLevel 验证非法灵敏度级别返回 400，不写入存储。
func TestUpdateSensitivityConfigRejectsInvalidLevel(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	body := []byte(`{"category_sensitivity":{"sqli":"invalid_level"}}`)
	ctx := invokeSensitivityHandler(t, UpdateSensitivityConfig(repo, func() error { return nil }), "global", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for invalid level, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if val, err := repo.Get("protection"); err == nil && val != "" {
		t.Fatalf("invalid sensitivity level should not persist protection config, got %s", val)
	}
}

// TestUpdateSensitivityConfigRejectsInvalidID 验证非法 id 参数返回 400。
func TestUpdateSensitivityConfigRejectsInvalidID(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	body := []byte(`{"category_sensitivity":{"sqli":"high"}}`)
	ctx := invokeSensitivityHandler(t, UpdateSensitivityConfig(repo, func() error { return nil }), "notanumber", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for invalid id, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestGetSensitivityConfigReturnsEffectiveSensitivity 验证 GetSensitivityConfig 返回已存储的有效灵敏度配置。
func TestGetSensitivityConfigReturnsEffectiveSensitivity(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.SetCategorySensitivity(map[string]string{"sqli": "strict", "xss": "high"})
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/protection/global/sensitivity")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "global"}}
	GetSensitivityConfig(repo)(context.Background(), ctx)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp sensitivityRequest
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CategorySensitivity["sqli"] != "strict" || resp.CategorySensitivity["xss"] != "high" {
		t.Fatalf("unexpected sensitivity in response: %#v", resp.CategorySensitivity)
	}
}

// TestUpdateSensitivityConfigNormalizesAliasesBeforeSaving 验证别名在保存前被归一化（medium→mid, very-high→very_high）。
func TestUpdateSensitivityConfigNormalizesAliasesBeforeSaving(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	body := []byte(`{"category_sensitivity":{"sqli":"medium","xss":"very-high","rce":"STRICT"}}`)
	ctx := invokeSensitivityHandler(t, UpdateSensitivityConfig(repo, func() error { return nil }), "global", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	sensitivity := loaded.GetCategorySensitivity()
	if sensitivity["sqli"] != "mid" {
		t.Errorf("alias 'medium' should normalize to 'mid', got %q", sensitivity["sqli"])
	}
	if sensitivity["xss"] != "very_high" {
		t.Errorf("alias 'very-high' should normalize to 'very_high', got %q", sensitivity["xss"])
	}
	if sensitivity["rce"] != "strict" {
		t.Errorf("alias 'STRICT' should normalize to 'strict', got %q", sensitivity["rce"])
	}
}
