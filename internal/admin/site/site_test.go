package site

import (
	"bytes"
	"context"
	"encoding/json"
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

func invokeCreateSiteHandler(t *testing.T, handler app.HandlerFunc, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
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

func TestCreateSiteAllowsInheritedTLSVersionsAndALPN(t *testing.T) {
	repo := newSiteRepoForTest(t)

	body := []byte(`{
		"host":"inherit-tls.example",
		"upstream_urls":"http://127.0.0.1:8080",
		"bind":":8443",
		"network":"tcp",
		"enabled":true,
		"tls_enabled":true,
		"cert_id":1,
		"min_tls_version":"",
		"max_tls_version":"",
		"alpn":""
	}`)
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	items, total, err := repo.List(0, 10)
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("expected one site, total=%d items=%d", total, len(items))
	}
	if items[0].MinTLSVersion != "" {
		t.Fatalf("created site min_tls_version = %q, want empty", items[0].MinTLSVersion)
	}
	if items[0].MaxTLSVersion != "" {
		t.Fatalf("created site max_tls_version = %q, want empty", items[0].MaxTLSVersion)
	}
	if items[0].ALPN != "" {
		t.Fatalf("created site alpn = %q, want empty", items[0].ALPN)
	}
}

func TestCreateSiteNormalizesRuntimeTLSVersions(t *testing.T) {
	repo := newSiteRepoForTest(t)

	body := []byte(`{
		"host":"site-tls-version.example",
		"upstream_urls":"http://127.0.0.1:8080",
		"bind":":8443",
		"network":"tcp",
		"enabled":true,
		"tls_enabled":true,
		"cert_id":1,
		"min_tls_version":"TLS 1.0",
		"max_tls_version":"0x0304"
	}`)
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	items, total, err := repo.List(0, 10)
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("expected one site, total=%d items=%d", total, len(items))
	}
	if items[0].MinTLSVersion != "TLS10" {
		t.Fatalf("created site min_tls_version = %q, want TLS10", items[0].MinTLSVersion)
	}
	if items[0].MaxTLSVersion != "TLS13" {
		t.Fatalf("created site max_tls_version = %q, want TLS13", items[0].MaxTLSVersion)
	}
}

func TestCreateSiteNormalizesALPN(t *testing.T) {
	repo := newSiteRepoForTest(t)

	body := []byte(`{
		"host":"site-alpn.example",
		"upstream_urls":"http://127.0.0.1:8080",
		"bind":":8443",
		"network":"tcp",
		"enabled":true,
		"tls_enabled":true,
		"cert_id":1,
		"alpn":" H2 , h2 , HTTP/1.1 , acme-tls/1 "
	}`)
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	items, total, err := repo.List(0, 10)
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("expected one site, total=%d items=%d", total, len(items))
	}
	if items[0].ALPN != "h2,http/1.1,acme-tls/1" {
		t.Fatalf("created site alpn = %q, want h2,http/1.1,acme-tls/1", items[0].ALPN)
	}
}

func TestCreateSiteRejectsUnsupportedRuntimeTLSVersions(t *testing.T) {
	tests := []struct {
		name       string
		tlsPayload string
		wantError  string
	}{
		{name: "min ssl3", tlsPayload: `"min_tls_version":"SSL3"`, wantError: "unsupported min_tls_version"},
		{name: "min ssl2", tlsPayload: `"min_tls_version":"SSL2"`, wantError: "unsupported min_tls_version"},
		{name: "min ssl1", tlsPayload: `"min_tls_version":"SSL1"`, wantError: "unsupported min_tls_version"},
		{name: "max ssl wire value", tlsPayload: `"max_tls_version":"0x0300"`, wantError: "unsupported max_tls_version"},
		{name: "max unknown", tlsPayload: `"max_tls_version":"TLS14"`, wantError: "unsupported max_tls_version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSiteRepoForTest(t)
			body := []byte(`{
				"host":"reject-runtime-tls.example",
				"upstream_urls":"http://127.0.0.1:8080",
				"bind":":8443",
				"network":"tcp",
				"enabled":true,
				"tls_enabled":true,
				"cert_id":1,
				` + tt.tlsPayload + `
			}`)

			reloadCalled := false
			ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error {
				reloadCalled = true
				return nil
			}), body)
			if ctx.Response.StatusCode() != 400 {
				t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			if reloadCalled {
				t.Fatal("reload should not be called")
			}
			var resp map[string]string
			if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp["error"] != tt.wantError {
				t.Fatalf("error = %q, want %q", resp["error"], tt.wantError)
			}
		})
	}
}

func TestCreateSiteValidatesConfigurableCipherSuites(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantStatus int
		wantError  string
	}{
		{name: "tls12 suite", payload: `"cipher_suites":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"`, wantStatus: 201},
		{name: "tls12 alias", payload: `"cipher_suites":"0xc02f,ECDHE_RSA_WITH_AES_256_GCM_SHA384"`, wantStatus: 201},
		{name: "tls13 suite", payload: `"cipher_suites":"TLS_AES_128_GCM_SHA256"`, wantStatus: 400, wantError: "unsupported cipher_suites: TLS_AES_128_GCM_SHA256"},
		{name: "unknown suite", payload: `"cipher_suites":"UNKNOWN_SUITE_EXAMPLE"`, wantStatus: 400, wantError: "unsupported cipher_suites: UNKNOWN_SUITE_EXAMPLE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSiteRepoForTest(t)
			body := []byte(`{
				"host":"site-cipher-suite.example",
				"upstream_urls":"http://127.0.0.1:8080",
				"bind":":8443",
				"network":"tcp",
				"enabled":true,
				"tls_enabled":true,
				"cert_id":1,
				` + tt.payload + `
			}`)

			ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), body)
			if ctx.Response.StatusCode() != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", ctx.Response.StatusCode(), tt.wantStatus, bytes.TrimSpace(ctx.Response.Body()))
			}
			if tt.wantStatus == 201 {
				return
			}
			var resp map[string]string
			if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp["error"] != tt.wantError {
				t.Fatalf("error = %q, want %q", resp["error"], tt.wantError)
			}
		})
	}
}

func TestCreateSiteAllowsExplicitH2CAndH3Upstreams(t *testing.T) {
	repo := newSiteRepoForTest(t)

	body := []byte(`{
		"host":"protocols.example",
		"upstream_urls":["h2c://127.0.0.1:8080","h3://127.0.0.1:8443/base"],
		"bind":":8080",
		"network":"tcp",
		"enabled":true
	}`)
	reloadCalled := false
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error {
		reloadCalled = true
		return nil
	}), body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !reloadCalled {
		t.Fatal("reload was not called")
	}

	items, total, err := repo.List(0, 10)
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("expected one site, total=%d items=%d", total, len(items))
	}
	if items[0].UpstreamURLs != `["h2c://127.0.0.1:8080","h3://127.0.0.1:8443/base"]` {
		t.Fatalf("created site upstream_urls = %q", items[0].UpstreamURLs)
	}
}

func TestCreateSiteAllowsUpstreamHostOverride(t *testing.T) {
	repo := newSiteRepoForTest(t)

	body := []byte(`{
		"host":"upstream-host.example",
		"upstream_urls":"http://127.0.0.1:8080",
		"upstream_host":"backend.example.com",
		"bind":":8080",
		"network":"tcp",
		"enabled":true
	}`)
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	items, total, err := repo.List(0, 10)
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("expected one site, total=%d items=%d", total, len(items))
	}
	if items[0].UpstreamHost != "backend.example.com" {
		t.Fatalf("created site upstream_host = %q", items[0].UpstreamHost)
	}
}

func TestCreateSiteRejectsInvalidNetwork(t *testing.T) {
	repo := newSiteRepoForTest(t)

	body := []byte(`{
		"host":"invalid-network.example",
		"upstream_urls":"http://127.0.0.1:8080",
		"bind":":8080",
		"network":"udp",
		"enabled":true
	}`)
	reloadCalled := false
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error {
		reloadCalled = true
		return nil
	}), body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload should not be called")
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid network" {
		t.Fatalf("error = %q, want invalid network", resp["error"])
	}
	_, total, err := repo.List(0, 10)
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	if total != 0 {
		t.Fatalf("site was created after invalid network, total=%d", total)
	}
}

func TestUpdateSiteRejectsInvalidNetwork(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{
		Host:         "update-invalid-network.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp4",
		Enabled:      true,
	}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	reloadCalled := false
	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error {
		reloadCalled = true
		return nil
	}), item.ID, []byte(`{"network":"udp"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload should not be called")
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid network" {
		t.Fatalf("error = %q, want invalid network", resp["error"])
	}
	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.Network != "tcp4" {
		t.Fatalf("network changed after rejected update: %q", loaded.Network)
	}
}

func TestCreateSiteRejectsUnsupportedUpstreamScheme(t *testing.T) {
	repo := newSiteRepoForTest(t)

	body := []byte(`{
		"host":"invalid-upstream.example",
		"upstream_urls":["ftp://127.0.0.1:21"],
		"bind":":8080",
		"network":"tcp",
		"enabled":true
	}`)
	reloadCalled := false
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error {
		reloadCalled = true
		return nil
	}), body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload should not be called")
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "upstream_urls supports only http, https, h2c, h3" {
		t.Fatalf("error = %q", resp["error"])
	}
}

func TestUpdateSiteRejectsUnsupportedUpstreamScheme(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{
		Host:         "update-invalid-upstream.example",
		UpstreamURLs: `["http://127.0.0.1:8080"]`,
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	reloadCalled := false
	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error {
		reloadCalled = true
		return nil
	}), item.ID, []byte(`{"upstream_urls":["ftp://127.0.0.1:21"]}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload should not be called")
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.UpstreamURLs != `["http://127.0.0.1:8080"]` {
		t.Fatalf("rejected update should preserve upstream_urls, got %s", loaded.UpstreamURLs)
	}
}

func TestUpdateSiteAllowsUpstreamHostTemplate(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{
		Host:         "update-upstream-host.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8080",
		Network:      "tcp",
		Enabled:      true,
	}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, []byte(`{"upstream_host":"{{.Host}}.internal"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.UpstreamHost != "{{.Host}}.internal" {
		t.Fatalf("updated site upstream_host = %q", loaded.UpstreamHost)
	}
}

func TestUpdateSiteNormalizesRuntimeTLSVersions(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{
		Host:          "update-runtime-tls.example",
		UpstreamURLs:  "http://127.0.0.1:8080",
		Bind:          ":8443",
		Network:       "tcp",
		Enabled:       true,
		TLSEnabled:    true,
		CertID:        uintPtr(1),
		MinTLSVersion: "TLS12",
		MaxTLSVersion: "TLS13",
	}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	body := []byte(`{"min_tls_version":"1.1","max_tls_version":"772"}`)
	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.MinTLSVersion != "TLS11" {
		t.Fatalf("updated site min_tls_version = %q, want TLS11", loaded.MinTLSVersion)
	}
	if loaded.MaxTLSVersion != "TLS13" {
		t.Fatalf("updated site max_tls_version = %q, want TLS13", loaded.MaxTLSVersion)
	}
}

func TestUpdateSiteNormalizesALPN(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{
		Host:         "update-alpn.example",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":8443",
		Network:      "tcp",
		Enabled:      true,
		TLSEnabled:   true,
		CertID:       uintPtr(1),
		ALPN:         "h2,http/1.1",
	}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	body := []byte(`{"alpn":" H3 , h3 , HTTP/1.1 , acme-tls/1 "}`)
	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.ALPN != "h3,http/1.1,acme-tls/1" {
		t.Fatalf("updated site alpn = %q, want h3,http/1.1,acme-tls/1", loaded.ALPN)
	}
}

func TestUpdateSiteRejectsUnsupportedRuntimeTLSVersions(t *testing.T) {
	tests := []struct {
		name       string
		tlsPayload string
		wantError  string
	}{
		{name: "min ssl3", tlsPayload: `{"min_tls_version":"SSL3"}`, wantError: "unsupported min_tls_version"},
		{name: "max ssl3", tlsPayload: `{"max_tls_version":"SSL3"}`, wantError: "unsupported max_tls_version"},
		{name: "min unknown", tlsPayload: `{"min_tls_version":"TLS14"}`, wantError: "unsupported min_tls_version"},
		{name: "max ssl wire value", tlsPayload: `{"max_tls_version":"768"}`, wantError: "unsupported max_tls_version"},
		{name: "invalid range", tlsPayload: `{"min_tls_version":"TLS13","max_tls_version":"TLS12"}`, wantError: "invalid tls version range"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSiteRepoForTest(t)
			item := store.Site{
				Host:          "update-reject-runtime-tls.example",
				UpstreamURLs:  "http://127.0.0.1:8080",
				Bind:          ":8443",
				Network:       "tcp",
				Enabled:       true,
				TLSEnabled:    true,
				CertID:        uintPtr(1),
				MinTLSVersion: "TLS12",
				MaxTLSVersion: "TLS13",
			}
			if err := repo.Create(&item); err != nil {
				t.Fatalf("seed site: %v", err)
			}

			reloadCalled := false
			ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error {
				reloadCalled = true
				return nil
			}), item.ID, []byte(tt.tlsPayload))
			if ctx.Response.StatusCode() != 400 {
				t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			if reloadCalled {
				t.Fatal("reload should not be called")
			}
			var resp map[string]string
			if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp["error"] != tt.wantError {
				t.Fatalf("error = %q, want %q", resp["error"], tt.wantError)
			}

			loaded, err := repo.Get(item.ID)
			if err != nil {
				t.Fatalf("load site: %v", err)
			}
			if loaded.MinTLSVersion != "TLS12" || loaded.MaxTLSVersion != "TLS13" {
				t.Fatalf("rejected update should preserve TLS versions, got min=%q max=%q", loaded.MinTLSVersion, loaded.MaxTLSVersion)
			}
		})
	}
}

func TestUpdateSiteValidatesConfigurableCipherSuites(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantStatus int
		wantError  string
	}{
		{name: "tls12 suite", payload: `{"cipher_suites":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}`, wantStatus: 200},
		{name: "tls12 alias", payload: `{"cipher_suites":"0xc02f,ECDHE_RSA_WITH_AES_256_GCM_SHA384"}`, wantStatus: 200},
		{name: "tls13 suite", payload: `{"cipher_suites":"TLS_AES_128_GCM_SHA256"}`, wantStatus: 400, wantError: "unsupported cipher_suites: TLS_AES_128_GCM_SHA256"},
		{name: "unknown suite", payload: `{"cipher_suites":"UNKNOWN_SUITE_EXAMPLE"}`, wantStatus: 400, wantError: "unsupported cipher_suites: UNKNOWN_SUITE_EXAMPLE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSiteRepoForTest(t)
			item := store.Site{
				Host:         "update-cipher-suite.example",
				UpstreamURLs: "http://127.0.0.1:8080",
				Bind:         ":8443",
				Network:      "tcp",
				Enabled:      true,
				TLSEnabled:   true,
				CertID:       uintPtr(1),
			}
			if err := repo.Create(&item); err != nil {
				t.Fatalf("seed site: %v", err)
			}

			ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, []byte(tt.payload))
			if ctx.Response.StatusCode() != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", ctx.Response.StatusCode(), tt.wantStatus, bytes.TrimSpace(ctx.Response.Body()))
			}
			if tt.wantStatus == 200 {
				return
			}
			var resp map[string]string
			if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp["error"] != tt.wantError {
				t.Fatalf("error = %q, want %q", resp["error"], tt.wantError)
			}
		})
	}
}

func TestCreateSiteRejectsInvalidRuntimeTLSRange(t *testing.T) {
	repo := newSiteRepoForTest(t)
	body := []byte(`{
		"host":"invalid-range.example",
		"upstream_urls":"http://127.0.0.1:8080",
		"bind":":8443",
		"network":"tcp",
		"enabled":true,
		"tls_enabled":true,
		"cert_id":1,
		"min_tls_version":"TLS13",
		"max_tls_version":"TLS12"
	}`)

	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid tls version range" {
		t.Fatalf("error = %q, want invalid tls version range", resp["error"])
	}
}

func TestUpdateSiteAllowsInheritedTLSVersionsAndALPN(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{
		Host:          "override-tls.example",
		UpstreamURLs:  "http://127.0.0.1:8080",
		Bind:          ":8443",
		Network:       "tcp",
		Enabled:       true,
		TLSEnabled:    true,
		CertID:        uintPtr(1),
		MinTLSVersion: "TLS12",
		MaxTLSVersion: "TLS13",
		ALPN:          "h2,http/1.1",
	}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	body := []byte(`{"min_tls_version":"","max_tls_version":"","alpn":""}`)
	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.MinTLSVersion != "" {
		t.Fatalf("updated site min_tls_version = %q, want empty", loaded.MinTLSVersion)
	}
	if loaded.MaxTLSVersion != "" {
		t.Fatalf("updated site max_tls_version = %q, want empty", loaded.MaxTLSVersion)
	}
	if loaded.ALPN != "" {
		t.Fatalf("updated site alpn = %q, want empty", loaded.ALPN)
	}
}

func uintPtr(v uint) *uint {
	return &v
}
