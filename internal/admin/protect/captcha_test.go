package protect

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newSystemSettingsRepoForTest(t *testing.T) *repository.SystemSettingsRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

func invokeCaptchaConfigHandler(t *testing.T, handler app.HandlerFunc, payload map[string]any) *app.RequestContext {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/captcha/config")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

func TestCaptchaConfigPersistsShieldRuntimeFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaEnabled = true
	cfg.CaptchaType = "rotate"
	cfg.CaptchaTimeout = 90
	cfg.CaptchaPassTTL = 180
	cfg.ShieldEnabled = true
	cfg.ShieldDifficulty = 5
	cfg.ShieldTimeoutSecs = 17
	cfg.ShieldAutoStartDelay = 1200
	cfg.ShieldMaxRetries = 4
	cfg.ShieldEnvStrictness = 2
	cfg.ShieldRequireHTTP2 = true
	cfg.ShieldRequireHTTP3 = false
	cfg.ShieldAllowHTTP1 = false
	cfg.ShieldEnableWASM = false
	cfg.ShieldEnableJSChallenge = true
	cfg.ShieldEnableEnvCheck = false
	cfg.ShieldEnableDevTools = false

	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatal(err)
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.CaptchaType != "rotate" || !loaded.CaptchaEnabled || loaded.CaptchaTimeout != 90 || loaded.CaptchaPassTTL != 180 {
		t.Fatalf("captcha fields not persisted: %#v", loaded)
	}
	if !loaded.ShieldEnabled || loaded.ShieldDifficulty != 5 || loaded.ShieldTimeoutSecs != 17 || loaded.ShieldAutoStartDelay != 1200 || loaded.ShieldMaxRetries != 4 || loaded.ShieldEnvStrictness != 2 {
		t.Fatalf("shield numeric fields not persisted: %#v", loaded)
	}
	if !loaded.ShieldRequireHTTP2 || loaded.ShieldRequireHTTP3 || loaded.ShieldAllowHTTP1 || loaded.ShieldEnableWASM || !loaded.ShieldEnableJSChallenge || loaded.ShieldEnableEnvCheck || loaded.ShieldEnableDevTools {
		t.Fatalf("shield boolean fields not persisted: %#v", loaded)
	}
}

func TestUpdateCaptchaConfigPreservesOmittedShieldFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.ShieldEnabled = true
	cfg.ShieldDifficulty = 6
	cfg.ShieldTimeoutSecs = 45
	cfg.ShieldAutoStartDelay = 1200
	cfg.ShieldMaxRetries = 7
	cfg.ShieldEnvStrictness = 2
	cfg.ShieldRequireHTTP2 = true
	cfg.ShieldRequireHTTP3 = true
	cfg.ShieldAllowHTTP1 = true
	cfg.ShieldEnableWASM = true
	cfg.ShieldEnableJSChallenge = true
	cfg.ShieldEnableEnvCheck = true
	cfg.ShieldEnableDevTools = true
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeCaptchaConfigHandler(t, UpdateCaptchaConfig(repo, func() error { return nil }), map[string]any{
		"captcha_enabled":  true,
		"captcha_type":     "slide",
		"captcha_timeout":  90,
		"captcha_pass_ttl": 180,
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if !loaded.CaptchaEnabled || loaded.CaptchaType != "slide" || loaded.CaptchaTimeout != 90 || loaded.CaptchaPassTTL != 180 {
		t.Fatalf("captcha fields not updated: %#v", loaded)
	}
	if !loaded.ShieldEnabled || loaded.ShieldDifficulty != 6 || loaded.ShieldTimeoutSecs != 45 || loaded.ShieldAutoStartDelay != 1200 || loaded.ShieldMaxRetries != 7 || loaded.ShieldEnvStrictness != 2 {
		t.Fatalf("omitted shield numeric fields were changed: %#v", loaded)
	}
	if !loaded.ShieldRequireHTTP2 || !loaded.ShieldRequireHTTP3 || !loaded.ShieldAllowHTTP1 || !loaded.ShieldEnableWASM || !loaded.ShieldEnableJSChallenge || !loaded.ShieldEnableEnvCheck || !loaded.ShieldEnableDevTools {
		t.Fatalf("omitted shield boolean fields were changed: %#v", loaded)
	}
}

func TestUpdateCaptchaConfigPersistsExplicitFalseAndZero(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	cfg := store.DefaultProtectionConfig()
	cfg.ShieldEnabled = true
	cfg.ShieldRequireHTTP2 = true
	cfg.ShieldRequireHTTP3 = true
	cfg.ShieldAllowHTTP1 = true
	cfg.ShieldEnableWASM = true
	cfg.ShieldEnableJSChallenge = true
	cfg.ShieldEnableEnvCheck = true
	cfg.ShieldEnableDevTools = true
	cfg.ShieldAutoStartDelay = 800
	cfg.ShieldEnvStrictness = 1
	if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
		t.Fatalf("seed protection: %v", err)
	}

	ctx := invokeCaptchaConfigHandler(t, UpdateCaptchaConfig(repo, func() error { return nil }), map[string]any{
		"shield_enabled":             false,
		"shield_require_http2":       false,
		"shield_require_http3":       false,
		"shield_allow_http1":         false,
		"shield_enable_wasm":         false,
		"shield_enable_js_challenge": false,
		"shield_enable_env_check":    false,
		"shield_enable_devtools":     false,
		"shield_auto_start_delay":    0,
		"shield_env_strictness":      0,
	})
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded := shared.LoadProtectionConfig(repo)
	if loaded.ShieldEnabled || loaded.ShieldRequireHTTP2 || loaded.ShieldRequireHTTP3 || loaded.ShieldAllowHTTP1 || loaded.ShieldEnableWASM || loaded.ShieldEnableJSChallenge || loaded.ShieldEnableEnvCheck || loaded.ShieldEnableDevTools {
		t.Fatalf("explicit false shield fields were not persisted: %#v", loaded)
	}
	if loaded.ShieldAutoStartDelay != 0 || loaded.ShieldEnvStrictness != 0 {
		t.Fatalf("explicit zero shield numeric fields were not persisted: %#v", loaded)
	}
}

func TestCaptchaConfigResponseIncludesShieldRuntimeFields(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.CaptchaType = "click"
	cfg.ShieldTimeoutSecs = 21
	cfg.ShieldAutoStartDelay = 333
	cfg.ShieldMaxRetries = 6
	cfg.ShieldEnvStrictness = 2
	cfg.ShieldRequireHTTP2 = true
	cfg.ShieldAllowHTTP1 = false
	cfg.ShieldEnableWASM = false
	cfg.ShieldEnableEnvCheck = false
	cfg.ShieldEnableDevTools = false

	body, err := json.Marshal(buildCaptchaConfigResponse(cfg))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"shield_timeout_secs", "shield_auto_start_delay", "shield_max_retries", "shield_env_strictness", "shield_require_http2", "shield_allow_http1", "shield_enable_wasm", "shield_enable_env_check", "shield_enable_devtools"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("captcha config response missed %s: %s", key, body)
		}
	}
}
