package dataplane

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/pages"
	"My-OpenWaf/internal/waf/ratelimit"
)

func TestNormalizeAntiReplayActionKeepsChallengeActions(t *testing.T) {
	cases := map[string]string{
		"":                  "challenge",
		"shield_challenge":  "shield_challenge",
		"captcha_challenge": "captcha_challenge",
		"chain_challenge":   "chain_challenge",
		"block":             "intercept",
		"drop":              "challenge",
	}
	for input, want := range cases {
		if got := normalizeAntiReplayAction(input); got != want {
			t.Fatalf("normalizeAntiReplayAction(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestErrorRateLimitActionDefaultsToRateLimit(t *testing.T) {
	got := errorRateLimitAction("")
	if got.Type != action.RateLimit || !got.Matched || got.Phase != "error_rate_limit" || got.StatusCode != 429 {
		t.Fatalf("errorRateLimitAction() = %#v", got)
	}
}

func TestErrorRateLimitActionKeepsConfiguredIntercept(t *testing.T) {
	got := errorRateLimitAction("intercept")
	if got.Type != action.Intercept || got.StatusCode != 0 {
		t.Fatalf("errorRateLimitAction(intercept) = %#v", got)
	}
}

func TestRateLimitActionUsesDefault429Status(t *testing.T) {
	res := action.Result{Type: action.RateLimit, Matched: true}
	if got := res.ResponseStatusCode(); got != 429 {
		t.Fatalf("rate limit response status = %d, want 429", got)
	}
}

func TestAccessLogKeepsSpecificChallengeActions(t *testing.T) {
	for _, actionName := range []string{
		"challenge",
		"captcha_challenge",
		"shield_challenge",
		"chain_challenge",
	} {
		ctx := app.NewContext(0)
		entry := buildAccessLogEntry(ctx, accessLogInfo{WAFAction: actionName, StatusCode: 422})
		if entry.WAFAction != actionName {
			t.Fatalf("access log WAFAction = %q, want %q", entry.WAFAction, actionName)
		}
	}
}

func TestRecordSecurityEventAddsTLSMetadata(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/tls-security-event?q=1")
	ctx.Request.Header.Set("Host", "127.0.0.1")
	ctx.Request.Header.Set("User-Agent", "tls-security-event-test")
	reqCtx := ContextWithTLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		JA3:        "771,4865-4866,0-11,29,0",
		JA3Hash:    "0123456789abcdef0123456789abcdef",
		JA4:        "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
		TLSVersion: "TLS13",
		SNI:        "security-event.example",
		ALPN:       []string{"h2", "http/1.1"},
	})
	if fp, ok := tlsFingerprintFromContext(reqCtx); ok {
		ctx.Set(tlsFingerprintContextKey, fp)
	}

	recordSecurityEvent(ctx, Options{Writer: writer}, store.SecurityEvent{
		SiteID:     1,
		RequestID:  "req-tls-security",
		ClientIP:   "127.0.0.1",
		Host:       "127.0.0.1",
		Path:       "/tls-security-event",
		Method:     "GET",
		UserAgent:  "tls-security-event-test",
		RuleIDStr:  "owasp:sqli:001",
		Phase:      "owasp_default",
		Action:     "intercept",
		Category:   "sqli",
		MatchDesc:  "SQL injection signals",
		StatusCode: 403,
	})
	writer.Close()

	var got store.SecurityEvent
	if err := db.Where("request_id = ?", "req-tls-security").First(&got).Error; err != nil {
		t.Fatalf("read security event: %v", err)
	}
	if got.TLSSNI != "security-event.example" || got.TLSVersion != "TLS13" || got.TLSALPN != "h2,http/1.1" {
		t.Fatalf("security event missed TLS metadata: %#v", got)
	}
	if got.TLSJA3Hash != "0123456789abcdef0123456789abcdef" || got.TLSJA4 == "" || got.TLSJA3 == "" {
		t.Fatalf("security event missed TLS fingerprint: %#v", got)
	}
	if got.HeaderOrder == "" {
		t.Fatalf("security event missed header order: %#v", got)
	}
}

func TestScrubResponseHopByHopHeaders(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Transfer-Encoding", "chunked")
	ctx.Response.Header.Set("Upgrade", "websocket")

	scrubResponseHopByHopHeaders(ctx)

	for _, key := range []string{"Connection", "Transfer-Encoding", "Upgrade"} {
		if got := string(ctx.Response.Header.Peek(key)); got != "" {
			t.Fatalf("%s header was not scrubbed: %q", key, got)
		}
	}
}

func TestShouldApplyErrorRateLimitUsesHistoricalErrors(t *testing.T) {
	rl := ratelimit.NewRateLimiter(60, 1, true)
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
	rl := ratelimit.NewRateLimiter(60, 1, true)
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
	rl := ratelimit.NewRateLimiter(60, 0, true)
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
	if got, want := string(pages.RenderErrorPage(502, cfg)), "<h1>502</h1><p>Custom Upstream</p>"; got != want {
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

func TestSetChallengeCookieSignsValue(t *testing.T) {
	value := challenge.SignChallengePassValue("example.com", nil, time.Unix(100, 0), time.Hour)
	if value == "1" {
		t.Fatal("challenge pass value must not be a forgeable boolean")
	}
	if !challenge.VerifyChallengePassValue(value, "example.com", nil, time.Unix(101, 0)) {
		t.Fatal("signed challenge pass value did not verify")
	}
	if challenge.VerifyChallengePassValue(value, "other.example", nil, time.Unix(101, 0)) {
		t.Fatal("signed challenge pass value verified for the wrong host")
	}
}

func TestShouldLogDropConsoleCount(t *testing.T) {
	cases := map[uint64]bool{
		1:    true,
		16:   true,
		17:   false,
		1023: false,
		1024: true,
		1025: false,
		2048: true,
	}
	for count, want := range cases {
		if got := shouldLogDropConsoleCount(count); got != want {
			t.Fatalf("shouldLogDropConsoleCount(%d) = %v, want %v", count, got, want)
		}
	}
}

func TestShouldLogNoSiteMatchConsoleCount(t *testing.T) {
	cases := map[uint64]bool{
		1:    true,
		16:   true,
		17:   false,
		1023: false,
		1024: true,
		1025: false,
		2048: true,
	}
	for count, want := range cases {
		if got := shouldLogNoSiteMatchConsoleCount(count); got != want {
			t.Fatalf("shouldLogNoSiteMatchConsoleCount(%d) = %v, want %v", count, got, want)
		}
	}
}
