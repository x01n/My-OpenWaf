package dataplane

import (
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf"
)

func TestErrorRateLimitActionDefaultsToIntercept(t *testing.T) {
	got := errorRateLimitAction("")
	if got.Type != action.Intercept || !got.Matched || got.Phase != "error_rate_limit" {
		t.Fatalf("errorRateLimitAction() = %#v", got)
	}
}

func TestShouldApplyErrorRateLimitUsesHistoricalErrors(t *testing.T) {
	rl := waf.NewRateLimiter(60, 1, true)
	defer rl.Close()
	eng := engine.New(&snapshot.Holder{}, nil, rl, nil)
	key := "1.2.3.4|example.com"

	rl.Increment(key)
	if shouldApplyErrorRateLimit(eng, store.ProtectionConfig{}, key) {
		t.Fatal("rate limit applied at threshold instead of above threshold")
	}
	rl.Increment(key)
	if !shouldApplyErrorRateLimit(eng, store.ProtectionConfig{}, key) {
		t.Fatal("rate limit did not apply after historical errors exceeded threshold")
	}
}

func TestIncrementErrorRateLimitStatusHonorsConfiguredBuckets(t *testing.T) {
	rl := waf.NewRateLimiter(60, 1, true)
	defer rl.Close()
	eng := engine.New(&snapshot.Holder{}, nil, rl, nil)
	key := "1.2.3.4|example.com"
	prot := store.ProtectionConfig{ErrorRateLimitCount4xx: true}

	incrementErrorRateLimitStatus(eng, prot, key, 500)
	if shouldApplyErrorRateLimit(eng, prot, key) {
		t.Fatal("5xx response was counted while only 4xx bucket is enabled")
	}
	incrementErrorRateLimitStatus(eng, prot, key, 404)
	incrementErrorRateLimitStatus(eng, prot, key, 401)
	if !shouldApplyErrorRateLimit(eng, prot, key) {
		t.Fatal("4xx responses were not counted")
	}
}

func TestIncrementErrorRateLimitBlockHonorsSwitch(t *testing.T) {
	rl := waf.NewRateLimiter(60, 0, true)
	defer rl.Close()
	eng := engine.New(&snapshot.Holder{}, nil, rl, nil)
	key := "1.2.3.4|example.com"

	incrementErrorRateLimitBlock(eng, store.ProtectionConfig{}, key)
	if shouldApplyErrorRateLimit(eng, store.ProtectionConfig{}, key) {
		t.Fatal("block was counted while error_ratelimit_count_block is disabled")
	}
	incrementErrorRateLimitBlock(eng, store.ProtectionConfig{ErrorRateLimitCountBlock: true}, key)
	if !shouldApplyErrorRateLimit(eng, store.ProtectionConfig{}, key) {
		t.Fatal("block was not counted while error_ratelimit_count_block is enabled")
	}
}

func TestSiteErrorPageUsesConfiguredHTMLTemplate(t *testing.T) {
	rt := snapshot.SiteRuntime{Site: store.Site{CustomErrorPages: `{"502":{"status_code":502,"title":"Custom Upstream","html":"<h1>{{.StatusCode}}</h1><p>{{.Message}}</p>","content_type":"text/html"}}`}}

	cfg := siteErrorPage(&rt, 502)
	if cfg == nil {
		t.Fatal("siteErrorPage() returned nil for configured status code")
	}
	if cfg.Title != "Custom Upstream" || cfg.StatusCode != 502 {
		t.Fatalf("siteErrorPage() = %#v", cfg)
	}
	if got, want := string(waf.RenderErrorPage(502, cfg)), "<h1>502</h1><p>Custom Upstream</p>"; got != want {
		t.Fatalf("RenderErrorPage() = %q, want %q", got, want)
	}
	if cfg := siteErrorPage(&rt, 504); cfg != nil {
		t.Fatalf("siteErrorPage() returned %#v for unconfigured status code", cfg)
	}
}

func TestSiteErrorPageFillsMissingStatusCode(t *testing.T) {
	rt := snapshot.SiteRuntime{Site: store.Site{CustomErrorPages: `{"503":{"title":"Maintenance","html":"maintenance"}}`}}

	cfg := siteErrorPage(&rt, 503)
	if cfg == nil {
		t.Fatal("siteErrorPage() returned nil for configured status code")
	}
	if cfg.StatusCode != 503 {
		t.Fatalf("siteErrorPage().StatusCode = %d, want 503", cfg.StatusCode)
	}
}
