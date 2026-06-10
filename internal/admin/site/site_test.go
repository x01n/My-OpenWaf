package site

import (
	"bytes"
	"context"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/store"
)

func invokeSiteHandler(t *testing.T, handler app.HandlerFunc, siteID uint, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/" + strconv.FormatUint(uint64(siteID), 10) + "/update")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: strconv.FormatUint(uint64(siteID), 10)}}
	handler(context.Background(), ctx)
	return ctx
}

func requireBoolPtr(t *testing.T, name string, got *bool, want bool) {
	t.Helper()
	if got == nil || *got != want {
		t.Fatalf("%s = %#v, want %v", name, got, want)
	}
}

func TestUpdateSiteClearsProtectionFieldsWhenNullableOverrideInherits(t *testing.T) {
	repo := newSiteRepoForTest(t)
	enabled := true
	item := store.Site{
		Host:                 "inherit.example",
		UpstreamURLs:         "http://127.0.0.1:8080",
		Bind:                 ":8080",
		Network:              "tcp",
		Enabled:              true,
		BotProtectionEnabled: &enabled,
		OWASPEnabled:         &enabled,
		OWASPSensitivity:     "strict",
		OWASPAction:          "drop",
		CVEEnabled:           &enabled,
		CVEAction:            "drop",
		RateLimitEnabled:     &enabled,
		RateLimitWindow:      1,
		RateLimitMax:         2,
		RateLimitAction:      "drop",
		BotProtectionLevel:   "medium",
	}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	body := []byte(`{"bot_protection_enabled":null,"owasp_enabled":null,"cve_enabled":null,"rate_limit_enabled":null}`)
	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.OWASPEnabled != nil || loaded.OWASPSensitivity != "" || loaded.OWASPAction != "" {
		t.Fatalf("OWASP inherit should clear site fields, got %#v", loaded)
	}
	if loaded.CVEEnabled != nil || loaded.CVEAction != "" {
		t.Fatalf("CVE inherit should clear site fields, got %#v", loaded)
	}
	if loaded.RateLimitEnabled != nil || loaded.RateLimitWindow != 0 || loaded.RateLimitMax != 0 || loaded.RateLimitAction != "" {
		t.Fatalf("rate limit inherit should clear site fields, got %#v", loaded)
	}
	if loaded.BotProtectionEnabled != nil || loaded.BotProtectionLevel != "" {
		t.Fatalf("bot inherit should clear site fields, got %#v", loaded)
	}
}

func TestUpdateSiteSavesOWASPCVEOverrideActions(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{
		Host:         "override.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	body := []byte(`{"owasp_enabled":true,"owasp_sensitivity":"strict","owasp_action":"drop","cve_enabled":true,"cve_action":"captcha_challenge"}`)
	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	requireBoolPtr(t, "OWASPEnabled", loaded.OWASPEnabled, true)
	if loaded.OWASPSensitivity != "strict" || loaded.OWASPAction != "drop" {
		t.Fatalf("OWASP override mismatch, got %#v", loaded)
	}
	requireBoolPtr(t, "CVEEnabled", loaded.CVEEnabled, true)
	if loaded.CVEAction != "captcha_challenge" {
		t.Fatalf("CVE action = %q, want %q", loaded.CVEAction, "captcha_challenge")
	}
}

func TestUpdateSiteRejectsRedirectWithoutTargetField(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{
		Host:         "redirect.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	body := []byte(`{"owasp_enabled":true,"owasp_action":"redirect"}`)
	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestUpdateSiteRejectsUnsupportedAntiReplayAction(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{
		Host:         "anti-replay.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	body := []byte(`{"anti_replay_action":"rate_limit"}`)
	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestUpdateSiteProtectionModeSyncsRuntimeOverrides(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{
		Host:         "mode.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, []byte(`{"attack_protection_level":"observe","maintenance_enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected observe status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load observe site: %v", err)
	}
	if loaded.AttackProtectionLevel != store.SiteProtectionModeObserve || loaded.MaintenanceEnabled {
		t.Fatalf("observe mode fields not saved, got %#v", loaded)
	}
	requireBoolPtr(t, "BotProtectionEnabled", loaded.BotProtectionEnabled, false)
	requireBoolPtr(t, "OWASPEnabled", loaded.OWASPEnabled, true)
	if loaded.OWASPSensitivity != "mid" || loaded.OWASPAction != string(store.ActionObserve) {
		t.Fatalf("observe OWASP override mismatch, got %#v", loaded)
	}
	requireBoolPtr(t, "CVEEnabled", loaded.CVEEnabled, true)
	if loaded.CVEAction != string(store.ActionObserve) {
		t.Fatalf("observe CVE action = %q, want %q", loaded.CVEAction, store.ActionObserve)
	}
	requireBoolPtr(t, "RateLimitEnabled", loaded.RateLimitEnabled, true)
	if loaded.RateLimitAction != string(store.ActionObserve) {
		t.Fatalf("observe rate limit action = %q, want %q", loaded.RateLimitAction, store.ActionObserve)
	}

	ctx = invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, []byte(`{"attack_protection_level":"protect","maintenance_enabled":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected protect status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	loaded, err = repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load protect site: %v", err)
	}
	if loaded.AttackProtectionLevel != store.SiteProtectionModeProtect || !loaded.MaintenanceEnabled {
		t.Fatalf("protect maintenance fields not saved, got %#v", loaded)
	}
	requireBoolPtr(t, "BotProtectionEnabled", loaded.BotProtectionEnabled, true)
	requireBoolPtr(t, "OWASPEnabled", loaded.OWASPEnabled, true)
	if loaded.OWASPAction != string(store.ActionIntercept) {
		t.Fatalf("protect OWASP action = %q, want %q", loaded.OWASPAction, store.ActionIntercept)
	}
	requireBoolPtr(t, "CVEEnabled", loaded.CVEEnabled, true)
	if loaded.CVEAction != string(store.ActionIntercept) {
		t.Fatalf("protect CVE action = %q, want %q", loaded.CVEAction, store.ActionIntercept)
	}
	requireBoolPtr(t, "RateLimitEnabled", loaded.RateLimitEnabled, true)
	if loaded.RateLimitAction != string(store.ActionRateLimit) {
		t.Fatalf("protect rate limit action = %q, want %q", loaded.RateLimitAction, store.ActionRateLimit)
	}
}
