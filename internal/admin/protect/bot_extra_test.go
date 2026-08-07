package protect

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
)

// TestUpdateBotSettingsAppliesEveryField 验证请求体中每个字段都被写入 bot_settings。
func TestUpdateBotSettingsAppliesEveryField(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := shared.SaveProtectionConfig(repo, store.DefaultProtectionConfig()); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	body := []byte(`{
		"enabled": true,
		"score_threshold": 42,
		"high_risk_countries": ["CN","RU"],
		"datacenter_asns": [13335, 16509],
		"vpn_proxy_asns": [9009],
		"geoip_db_path": "/opt/geoip/City.mmdb",
		"captcha_enabled": true,
		"dynamic_protection_enabled": true,
		"html_obfuscation": true,
		"js_obfuscation": true,
		"image_watermark": true,
		"anti_replay_enabled": true,
		"browser_sign_enabled": true,
		"browser_sign_ttl": 900,
		"browser_sign_action": "captcha_challenge",
		"js_obfuscation_paths": ["/app.js"],
		"js_protection_mode": "all",
		"decrypt_cache_ttl_seconds": 45,
		"image_watermark_paths": ["/img/*"],
		"watermark_text": "confidential",
		"exclude_record_headers": ["Authorization","Cookie"]
	}`)
	ctx := invokeProtectHandler(t, UpdateBotSettings(repo, func() error { return nil }), "POST", "/api/v1/bot-settings/update", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get("bot_settings")
	if err != nil {
		t.Fatalf("load bot settings: %v", err)
	}
	var saved shared.BotSettingsResponse
	if err := json.Unmarshal([]byte(val), &saved); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if !saved.Enabled || saved.ScoreThreshold != 42 {
		t.Fatalf("enabled/score_threshold not applied: %#v", saved)
	}
	if len(saved.HighRiskCountries) != 2 || saved.HighRiskCountries[0] != "CN" {
		t.Fatalf("high_risk_countries not applied: %#v", saved.HighRiskCountries)
	}
	if len(saved.DatacenterASNs) != 2 || saved.DatacenterASNs[0] != 13335 {
		t.Fatalf("datacenter_asns not applied: %#v", saved.DatacenterASNs)
	}
	if len(saved.VPNProxyASNs) != 1 || saved.VPNProxyASNs[0] != 9009 {
		t.Fatalf("vpn_proxy_asns not applied: %#v", saved.VPNProxyASNs)
	}
	if saved.GeoIPDBPath != "/opt/geoip/City.mmdb" {
		t.Fatalf("geoip_db_path not applied: %q", saved.GeoIPDBPath)
	}
	if !saved.CaptchaEnabled || !saved.DynamicProtectionEnabled || !saved.HTMLObfuscation || !saved.JSObfuscation || !saved.ImageWatermark || !saved.AntiReplayEnabled {
		t.Fatalf("boolean toggles not applied: %#v", saved)
	}
	if !saved.BrowserSignEnabled || saved.BrowserSignTTL != 900 || saved.BrowserSignAction != "captcha_challenge" {
		t.Fatalf("browser sign fields not applied: %#v", saved)
	}
	if len(saved.JSObfuscationPaths) != 1 || saved.JSProtectionMode != "all" || saved.DecryptCacheTTLSeconds != 45 {
		t.Fatalf("js protection fields not applied: %#v", saved)
	}
	if len(saved.ImageWatermarkPaths) != 1 || saved.WatermarkText != "confidential" {
		t.Fatalf("watermark fields not applied: %#v", saved)
	}
	if len(saved.ExcludeRecordHeaders) != 2 {
		t.Fatalf("exclude_record_headers not applied: %#v", saved.ExcludeRecordHeaders)
	}
}

// TestUpdateBotSettingsSyncsCaptchaAndBrowserSignToProtection 验证验证码与浏览器签名开关同步进 protection。
func TestUpdateBotSettingsSyncsCaptchaAndBrowserSignToProtection(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaEnabled = false
	cfg.BrowserSignEnabled = false
	cfg.BrowserSignTTL = 300
	cfg.BrowserSignAction = "challenge"
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	body := []byte(`{"captcha_enabled":true,"browser_sign_enabled":true,"browser_sign_ttl":1200,"browser_sign_action":"shield_challenge"}`)
	ctx := invokeProtectHandler(t, UpdateBotSettings(repo, func() error { return nil }), "POST", "/api/v1/bot-settings/update", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.CaptchaEnabled {
		t.Fatal("captcha_enabled was not synced into protection")
	}
	// 浏览器签名动作必须保留具体的挑战子类型。
	if !loaded.BrowserSignEnabled || loaded.BrowserSignTTL != 1200 || loaded.BrowserSignAction != "shield_challenge" {
		t.Fatalf("browser sign config was not synced into protection: %#v", loaded)
	}
}

// TestUpdateBotSettingsPreservesProtectionCaptchaOnPartialPatch 验证 Bot 局部更新不会把旧 CAPTCHA 投影写回权威配置。
func TestUpdateBotSettingsPreservesProtectionCaptchaOnPartialPatch(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaEnabled = true
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if err := repo.Set("bot_settings", `{"enabled":true,"captcha_enabled":false}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	ctx := invokeProtectHandler(t, UpdateBotSettings(repo, func() error { return nil }), "POST", "/api/v1/bot-settings/update", []byte(`{"enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var got shared.BotSettingsResponse
	val, err := repo.Get("bot_settings")
	if err != nil {
		t.Fatalf("load bot settings: %v", err)
	}
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if got.CaptchaEnabled != true {
		t.Fatalf("partial bot update persisted stale captcha_enabled: %#v", got)
	}
	if !shared.LoadProtectionConfig(repo).CaptchaEnabled {
		t.Fatal("partial bot update changed protection captcha_enabled")
	}
}

// TestUpdateBotSettingsIgnoresNonPositiveBrowserSignTTLAndEmptyAction 验证非正 TTL 与空动作被忽略。
func TestUpdateBotSettingsIgnoresNonPositiveBrowserSignTTLAndEmptyAction(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("bot_settings", `{"enabled":true,"browser_sign_ttl":600,"browser_sign_action":"chain_challenge"}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	body := []byte(`{"browser_sign_ttl":0,"browser_sign_action":""}`)
	ctx := invokeProtectHandler(t, UpdateBotSettings(repo, func() error { return nil }), "POST", "/api/v1/bot-settings/update", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get("bot_settings")
	if err != nil {
		t.Fatalf("load bot settings: %v", err)
	}
	var saved shared.BotSettingsResponse
	if err := json.Unmarshal([]byte(val), &saved); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if saved.BrowserSignTTL != 600 || saved.BrowserSignAction != "chain_challenge" {
		t.Fatalf("non-positive TTL / empty action should be ignored: %#v", saved)
	}
}

// TestUpdateBotSettingsRejectsInvalidBody 验证请求体非法时返回 400。
func TestUpdateBotSettingsRejectsInvalidBody(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, UpdateBotSettings(repo, func() error { return nil }), "POST", "/api/v1/bot-settings/update", []byte(`{"enabled":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for malformed body, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdateBotSettingsReloadFailureReturns500 验证 reload 失败时返回 500 并回带已保存的配置。
func TestUpdateBotSettingsReloadFailureReturns500(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, UpdateBotSettings(repo, func() error { return errors.New("reload boom") }), "POST", "/api/v1/bot-settings/update", []byte(`{"score_threshold":55}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 on reload failure, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		Error    string                     `json:"error"`
		Settings shared.BotSettingsResponse `json:"settings"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error == "" || resp.Settings.ScoreThreshold != 55 {
		t.Fatalf("reload failure response should carry the applied settings: %#v", resp)
	}
	val, err := repo.Get("bot_settings")
	if err != nil {
		t.Fatalf("config should already be saved before reload is attempted: %v", err)
	}
	if val == "" {
		t.Fatal("bot_settings was not persisted before reload")
	}
}

// TestUpdateBotSettingsWithNilReload 验证 reload 为 nil 时不会 panic。
func TestUpdateBotSettingsWithNilReload(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeProtectHandler(t, UpdateBotSettings(repo, nil), "POST", "/api/v1/bot-settings/update", []byte(`{"enabled":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestGetBotSettingsFallsBackOnCorruptedStoredJSON 验证 bot_settings 损坏时回落到派生默认值。
func TestGetBotSettingsFallsBackOnCorruptedStoredJSON(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.BotDetectionEnabled = true
	cfg.CaptchaEnabled = true
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if err := repo.Set("bot_settings", `not-json`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}
	if err := repo.Set("drop_policy", `{"bot_score_threshold":83}`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	ctx := invokeProtectHandler(t, GetBotSettings(repo), "GET", "/api/v1/bot-settings", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var got shared.BotSettingsResponse
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.Enabled || !got.CaptchaEnabled || got.ScoreThreshold != 83 {
		t.Fatalf("corrupted bot_settings should fall back to derived defaults: %#v", got)
	}
}

// TestDefaultBotSettingsResponseNormalizesBrowserSignDefaults 验证 TTL/动作缺省值补齐规则。
func TestDefaultBotSettingsResponseNormalizesBrowserSignDefaults(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.BrowserSignTTL = 0
	cfg.BrowserSignAction = ""
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	got := defaultBotSettingsResponse(repo)
	if got.BrowserSignTTL != 300 {
		t.Fatalf("BrowserSignTTL default = %d, want 300", got.BrowserSignTTL)
	}
	if got.BrowserSignAction != "challenge" {
		t.Fatalf("BrowserSignAction default = %q, want challenge", got.BrowserSignAction)
	}
	if got.ScoreThreshold != 60 {
		t.Fatalf("ScoreThreshold default = %d, want 60", got.ScoreThreshold)
	}
}

// TestDefaultBotSettingsResponseIgnoresCorruptedDropPolicy 验证 drop_policy 损坏时沿用默认阈值。
func TestDefaultBotSettingsResponseIgnoresCorruptedDropPolicy(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("drop_policy", `not-json`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}
	if got := defaultBotSettingsResponse(repo); got.ScoreThreshold != 60 {
		t.Fatalf("corrupted drop_policy should keep default threshold 60, got %d", got.ScoreThreshold)
	}

	// 阈值为 0 时同样不覆盖默认值。
	if err := repo.Set("drop_policy", `{"bot_score_threshold":0}`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}
	if got := defaultBotSettingsResponse(repo); got.ScoreThreshold != 60 {
		t.Fatalf("zero threshold should keep default 60, got %d", got.ScoreThreshold)
	}
}

// TestGetBotSettingsNormalizesBrowserSignFallbacks 验证存储与 protection 都缺失时补齐 TTL/动作缺省值。
func TestGetBotSettingsNormalizesBrowserSignFallbacks(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.BrowserSignTTL = 0
	cfg.BrowserSignAction = ""
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if err := repo.Set("bot_settings", `{"enabled":true,"browser_sign_ttl":0,"browser_sign_action":""}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	ctx := invokeProtectHandler(t, GetBotSettings(repo), "GET", "/api/v1/bot-settings", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var got shared.BotSettingsResponse
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.BrowserSignTTL != 300 || got.BrowserSignAction != "challenge" {
		t.Fatalf("browser sign fallbacks not applied: %#v", got)
	}
}

// TestGetBotSettingsUsesProtectionCaptchaValue 验证 GET Bot 设置始终返回 protection 中的 CAPTCHA 开关。
func TestGetBotSettingsUsesProtectionCaptchaValue(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaEnabled = true
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if err := repo.Set("bot_settings", `{"captcha_enabled":false,"enabled":true}`); err != nil {
		t.Fatalf("seed bot settings: %v", err)
	}

	ctx := invokeProtectHandler(t, GetBotSettings(repo), "GET", "/api/v1/bot-settings", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var got shared.BotSettingsResponse
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode bot settings: %v", err)
	}
	if !got.CaptchaEnabled {
		t.Fatalf("GET bot settings returned stale captcha_enabled: %#v", got)
	}
}
