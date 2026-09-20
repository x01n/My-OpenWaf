package rules

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/iprep"
)

func TestIPReputationPhaseSiteWhitelistSkipsGlobalCheckButContinuesPipeline(t *testing.T) {
	global := iprep.NewIPReputation()
	defer global.Close()
	globalEntry, ok := iprep.ParseIPListEntry("192.0.2.10", "global blacklist", "intercept")
	if !ok {
		t.Fatal("failed to parse global blacklist entry")
	}
	global.SetLists([]iprep.IPListEntry{globalEntry}, nil)
	siteEntry, ok := iprep.ParseIPListEntry("192.0.2.10", "site whitelist", "intercept")
	if !ok {
		t.Fatal("failed to parse site whitelist entry")
	}
	phase := NewIPReputationPhase(global, []iprep.IPListEntry{siteEntry}, nil)
	result, stop := phase.Execute(&pipeline.RequestCtx{ClientIP: net.ParseIP("192.0.2.10")})
	if stop {
		t.Fatal("site whitelist must not terminate the IP phase")
	}
	if result.Type != action.Allow || result.Category != "whitelist" {
		t.Fatalf("site whitelist result = %#v, want non-terminal whitelist allow", result)
	}
}

func TestAntiReplayPhaseSkipsAlreadyConsumedCookieNonce(t *testing.T) {
	manager := antireplay.NewAntiReplayManager("phase-test-secret", nil, 5*time.Minute)
	nonce := manager.GenerateNonce("192.0.2.10")
	valid, replay, _ := manager.ValidateAndRotate(nonce, "192.0.2.10", 0)
	if !valid || replay {
		t.Fatalf("failed to seed consumed nonce: valid=%v replay=%v", valid, replay)
	}

	ctx := &pipeline.RequestCtx{
		ClientIP:                net.ParseIP("192.0.2.10"),
		Headers:                 map[string]string{"x-nonce": nonce},
		AntiReplayConsumedNonce: nonce,
	}
	result, stop := NewAntiReplayPhase(manager).Execute(ctx)
	if stop || result.Type != action.Pass().Type {
		t.Fatalf("same consumed nonce result = %#v stop=%v, want pass without stop", result, stop)
	}
}

func TestIPReputationPhaseSiteBlacklistPreservesAction(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string
		want   action.Type
	}{
		{name: "intercept", action: "intercept", want: action.Intercept},
		{name: "drop", action: "drop", want: action.Drop},
		{name: "legacy block", action: "block", want: action.Drop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry, ok := iprep.ParseIPListEntry("2001:db8::10", "site blacklist", tc.action)
			if !ok {
				t.Fatal("failed to parse site blacklist entry")
			}
			phase := NewIPReputationPhase(nil, nil, []iprep.IPListEntry{entry})
			result, stop := phase.Execute(&pipeline.RequestCtx{ClientIP: net.ParseIP("2001:db8::10")})
			if !stop {
				t.Fatal("site blacklist must terminate the IP phase")
			}
			if result.Type != tc.want {
				t.Fatalf("site blacklist action = %q, want %q", result.Type, tc.want)
			}
		})
	}
}

func TestIPReputationPhaseGlobalBlacklistPreservesDropAction(t *testing.T) {
	entry, ok := iprep.ParseIPListEntry("203.0.113.7", "global drop", "drop")
	if !ok {
		t.Fatal("failed to parse global blacklist entry")
	}
	global := iprep.NewIPReputation()
	defer global.Close()
	global.SetLists([]iprep.IPListEntry{entry}, nil)
	result, stop := NewIPReputationPhase(global, nil, nil).Execute(&pipeline.RequestCtx{ClientIP: net.ParseIP("203.0.113.7")})
	if !stop || result.Type != action.Drop {
		t.Fatalf("global blacklist result = %#v stop=%v, want drop and stop", result, stop)
	}
}

func TestIPReputationPhaseExpiredSiteEntryDoesNotMatch(t *testing.T) {
	entry, ok := iprep.ParseIPListEntry("198.51.100.14", "expired", "drop")
	if !ok {
		t.Fatal("failed to parse expired site entry")
	}
	entry.ExpireAt = time.Now().Add(-time.Minute).Unix()
	result, stop := NewIPReputationPhase(nil, nil, []iprep.IPListEntry{entry}).Execute(&pipeline.RequestCtx{ClientIP: net.ParseIP("198.51.100.14")})
	if stop || result.Matched {
		t.Fatalf("expired site entry result = %#v stop=%v, want pass", result, stop)
	}
}

func TestBotPhaseStoreBotScoreDetailsOnlyForHighRisk(t *testing.T) {
	phase := &botPhase{threshold: 80}
	ctx := &pipeline.RequestCtx{}
	phase.storeBotScore(ctx, bot.BotVerdict{Category: "suspicious", Score: 50}, bot.BotScore{Total: 50, Details: map[string]string{"ua": "10"}})
	if ctx.BotScoreResult == nil {
		t.Fatal("expected bot score result")
	}
	if ctx.BotScoreResult.Details != nil {
		t.Fatalf("non-high-risk bot score should skip details, got %v", ctx.BotScoreResult.Details)
	}

	ctx = &pipeline.RequestCtx{}
	phase.storeBotScore(ctx, bot.BotVerdict{Category: "malicious", Score: 90}, bot.BotScore{Total: 90, IsHighRisk: true, Details: map[string]string{"ua": "10"}})
	if ctx.BotScoreResult == nil || len(ctx.BotScoreResult.Details) == 0 {
		t.Fatalf("high-risk bot score should keep details: %#v", ctx.BotScoreResult)
	}
}

func TestCtxFromPipelineAddsTLSSNIHeader(t *testing.T) {
	ctx := &pipeline.RequestCtx{
		Headers: map[string]string{"User-Agent": "Mozilla/5.0"},
		TLS: bot.TLSClientFingerprint{
			SNI: "login.example.com",
		},
	}

	mc := ctxFromPipeline(ctx, true)
	if mc.TLS == nil || mc.TLS.SNI != "login.example.com" {
		t.Fatalf("expected TLS SNI to be preserved in context, got %#v", mc.TLS)
	}
	if mc.Headers["User-Agent"] != "Mozilla/5.0" {
		t.Fatalf("expected original headers to be preserved, got %#v", mc.Headers)
	}
}

func TestCtxFromPipelineAddsTLSCipherSuitesHeader(t *testing.T) {
	ctx := &pipeline.RequestCtx{
		Headers: map[string]string{"User-Agent": "Mozilla/5.0"},
		TLS: bot.TLSClientFingerprint{
			CipherSuites: []uint16{4865, 4866},
		},
	}

	mc := ctxFromPipeline(ctx, true)
	want := "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384"
	if mc.TLSCipherSuites != want {
		t.Fatalf("expected TLS cipher suites to be preserved in context %q, got %#v", want, mc.TLSCipherSuites)
	}
}

func TestCtxFromPipelinePreservesDerivedContextFields(t *testing.T) {
	ctx := &pipeline.RequestCtx{
		Headers: map[string]string{"User-Agent": "Mozilla/5.0"},
		Host:    "cached.example.com",
		TLS: bot.TLSClientFingerprint{
			SNI: "login.example.com",
		},
		HeaderKeys: []string{"Host", "User-Agent", "Accept"},
	}

	mc := ctxFromPipeline(ctx, true)
	if mc.Host != "cached.example.com" {
		t.Fatalf("expected host to be preserved in context, got %q", mc.Host)
	}
	if mc.TLS == nil || mc.TLS.SNI != "login.example.com" {
		t.Fatalf("expected TLS SNI to be preserved in context, got %#v", mc.TLS)
	}
	if mc.HeaderOrder != "Host,User-Agent,Accept" {
		t.Fatalf("expected header order to be preserved in context, got %q", mc.HeaderOrder)
	}
}

func TestCtxFromPipelineUsesLowercaseHeaderFastPath(t *testing.T) {
	ctx := &pipeline.RequestCtx{
		Headers:          map[string]string{"user-agent": "sqlmap/1.7.8"},
		HeadersLowercase: true,
	}

	mc := ctxFromPipeline(ctx, false)
	if !mc.HeadersLowercase {
		t.Fatal("expected lowercase header marker to be preserved in match context")
	}
	rules := Compile([]store.Rule{
		{
			ID:       1,
			Phase:    store.PhaseCustom,
			Pattern:  "block_user_agent:sqlmap",
			Action:   store.ActionIntercept,
			Priority: 1,
			Enabled:  true,
		},
	})
	if len(rules) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(rules))
	}
	if !rules[0].Match(mc) {
		t.Fatal("lowercase user-agent header should match with lowercase fast path")
	}
}

func TestCustomPhaseUsesDirectTLSContextFields(t *testing.T) {
	rules := Compile([]store.Rule{
		{
			ID:       1,
			Phase:    store.PhaseCustom,
			Pattern:  `{"op":"and","children":[{"kind":"block_path","arg":"/admin"},{"kind":"tls_sni","arg":"login.example.com"},{"kind":"tls_version","arg":"TLS13"}]}`,
			Action:   store.ActionIntercept,
			Priority: 1,
			Enabled:  true,
		},
	})
	if len(rules) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(rules))
	}

	phase := NewCustomPhasePrecompiled(rules)
	ctx := &pipeline.RequestCtx{
		Path: "/admin/panel",
		TLS: bot.TLSClientFingerprint{
			SNI:        "login.example.com",
			TLSVersion: "TLS13",
		},
	}

	result, stop := phase.Execute(ctx)

	if !stop {
		t.Fatal("compound TLS rule should stop the custom phase")
	}
	if result.Type != action.Intercept {
		t.Fatalf("result type = %q, want %q", result.Type, action.Intercept)
	}
	if result.RuleID != 1 {
		t.Fatalf("result rule id = %d, want 1", result.RuleID)
	}
}

func TestCtxFromPipelineUsesHostForHostMatchers(t *testing.T) {
	ctx := &pipeline.RequestCtx{
		Host: "admin.example.com:443",
	}

	mc := ctxFromPipeline(ctx, false)
	rules := Compile([]store.Rule{
		{
			ID:       1,
			Phase:    store.PhaseCustom,
			Pattern:  "host:admin.example.com",
			Action:   store.ActionIntercept,
			Priority: 1,
			Enabled:  true,
		},
	})
	phase := NewCustomPhasePrecompiled(rules)
	result, stop := phase.Execute(ctx)

	if !stop {
		t.Fatal("host matcher should stop the custom phase")
	}
	if result.RuleID != 1 {
		t.Fatalf("result rule id = %d, want 1", result.RuleID)
	}
	if mc.Host != "admin.example.com:443" {
		t.Fatalf("expected host to remain available in match context, got %q", mc.Host)
	}
}

func TestCustomPhaseKeepsObserveAuditButReturnsLaterTerminal(t *testing.T) {
	phase := NewCustomPhasePrecompiled([]Compiled{
		{ID: 1, Phase: "custom", Action: action.Observe, Kind: "always", matcher: &alwaysMatcher{}},
		{ID: 2, Phase: "custom", Action: action.Intercept, Kind: "always", matcher: &alwaysMatcher{}},
	})

	ctx := &pipeline.RequestCtx{}
	result, stop := phase.Execute(ctx)

	if !stop {
		t.Fatal("later terminal match should stop the pipeline")
	}
	if result.Type != action.Intercept {
		t.Fatalf("phase result type = %q, want %q", result.Type, action.Intercept)
	}
	if result.RuleID != 2 {
		t.Fatalf("phase result rule id = %d, want 2", result.RuleID)
	}
	buffered := ctx.DrainPhaseObserveHits()
	if len(buffered) != 1 {
		t.Fatalf("buffered observe hits = %d, want 1", len(buffered))
	}
	if buffered[0].Type != action.Observe || buffered[0].RuleID != 1 {
		t.Fatalf("buffered observe hit = %#v, want observe rule 1", buffered[0])
	}
}

func TestCustomPhaseReturnsObserveWhenNoTerminalRuleMatches(t *testing.T) {
	phase := NewCustomPhasePrecompiled([]Compiled{
		{ID: 1, Phase: "custom", Action: action.Observe, Kind: "always", matcher: &alwaysMatcher{}},
		{ID: 2, Phase: "custom", Action: action.Intercept, Kind: "never", matcher: &neverMatcher{}},
	})

	result, stop := phase.Execute(&pipeline.RequestCtx{})

	if stop {
		t.Fatal("observe-only match should not stop phase execution")
	}
	if result.Type != action.Observe {
		t.Fatalf("phase result type = %q, want %q", result.Type, action.Observe)
	}
	if result.RuleID != 1 {
		t.Fatalf("phase result rule id = %d, want 1", result.RuleID)
	}
}

func TestPrecompiledPhaseInitializesRuntimeMetadataOnce(t *testing.T) {
	rules := []Compiled{
		{ID: 7, Phase: "custom", Action: action.Intercept, Kind: "tls_sni", Arg: "login.example.com", matcher: &tlsFingerprintMatcher{name: "x-owaf-tls-sni", value: "login.example.com"}},
	}
	phase := NewCustomPhasePrecompiled(rules)

	custom, ok := phase.(*customPhase)
	if !ok {
		t.Fatalf("phase type = %T, want *customPhase", phase)
	}
	if len(custom.rules) != 1 {
		t.Fatalf("precompiled rules length = %d, want 1", len(custom.rules))
	}
	if custom.rules[0].ruleIDStr != "rule:custom:tls_sni" {
		t.Fatalf("ruleIDStr = %q, want %q", custom.rules[0].ruleIDStr, "rule:custom:tls_sni")
	}
	if custom.rules[0].matchDesc != "tls_sni:login.example.com" {
		t.Fatalf("matchDesc = %q, want %q", custom.rules[0].matchDesc, "tls_sni:login.example.com")
	}
	if custom.rules[0].runtimeAction != action.Intercept {
		t.Fatalf("runtimeAction = %q, want %q", custom.rules[0].runtimeAction, action.Intercept)
	}
}

func TestACLPhaseKeepsHigherPriorityObserveBeforeLaterAllow(t *testing.T) {
	phase := NewACLPhasePrecompiled([]Compiled{
		{ID: 1, Phase: "acl", Action: action.Observe, Kind: "always", matcher: &alwaysMatcher{}},
		{ID: 2, Phase: "acl", Action: action.Allow, Kind: "always", matcher: &alwaysMatcher{}},
	})

	result, stop := phase.Execute(&pipeline.RequestCtx{})

	if stop {
		t.Fatal("higher-priority observe should keep lower-priority allow from short-circuiting")
	}
	if result.Type != action.Observe {
		t.Fatalf("phase result type = %q, want %q", result.Type, action.Observe)
	}
	if result.RuleID != 1 {
		t.Fatalf("phase result rule id = %d, want 1", result.RuleID)
	}
}

func TestACLPhaseAllowDoesNotStopPipeline(t *testing.T) {
	phase := NewACLPhasePrecompiled([]Compiled{
		{ID: 1, Phase: "acl", Action: action.Allow, Kind: "always", matcher: &alwaysMatcher{}},
		{ID: 2, Phase: "acl", Action: action.Intercept, Kind: "always", matcher: &alwaysMatcher{}},
	})

	result, stop := phase.Execute(&pipeline.RequestCtx{})

	if stop {
		t.Fatal("allow must not stop later pipeline phases")
	}
	if result.Type != action.Allow {
		t.Fatalf("phase result type = %q, want %q", result.Type, action.Allow)
	}
	if result.RuleID != 1 {
		t.Fatalf("phase result rule id = %d, want 1", result.RuleID)
	}
}

func BenchmarkACLPhaseFreshRequestCtxWithoutDerivedHeaders(b *testing.B) {
	phase := NewACLPhasePrecompiled([]Compiled{
		{ID: 1, Phase: "acl", Action: action.Intercept, Kind: "block_path", Arg: "/admin", matcher: &pathPrefixMatcher{prefix: "/admin"}},
	})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ctx := pipeline.AcquireCtx()
		ctx.Path = "/admin/panel"
		ctx.Host = "example.com"
		ctx.Headers["User-Agent"] = "Mozilla/5.0"
		_, _ = phase.Execute(ctx)
		pipeline.ReleaseCtx(ctx)
	}
}

func BenchmarkCustomPhaseFreshRequestCtxWithTLSDerivedHeaders(b *testing.B) {
	phase := NewCustomPhasePrecompiled([]Compiled{
		{ID: 1, Phase: "custom", Action: action.Intercept, Kind: "tls_sni", matcher: &tlsFingerprintMatcher{name: "x-owaf-tls-sni", value: "login.example.com"}},
	})

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ctx := pipeline.AcquireCtx()
		ctx.Host = "example.com"
		ctx.TLS.SNI = "login.example.com"
		ctx.Headers["User-Agent"] = "Mozilla/5.0"
		_, _ = phase.Execute(ctx)
		pipeline.ReleaseCtx(ctx)
	}
}

func TestCustomPhaseCarriesCaptchaTypeInActionResult(t *testing.T) {
	phase := NewCustomPhasePrecompiled([]Compiled{{
		ID:          9,
		Phase:       "custom",
		Action:      action.CaptchaChallenge,
		CaptchaType: "rotate",
		Kind:        "always",
		matcher:     &alwaysMatcher{},
	}})

	result, stop := phase.Execute(&pipeline.RequestCtx{})
	if !stop {
		t.Fatal("captcha challenge should stop phase execution")
	}
	if result.Type != action.CaptchaChallenge {
		t.Fatalf("phase result type = %q, want %q", result.Type, action.CaptchaChallenge)
	}
	if result.CaptchaType != "rotate" {
		t.Fatalf("phase result captcha_type = %q, want rotate", result.CaptchaType)
	}
}

func TestExtractBodyTargetsSkipsCleanOpaqueBody(t *testing.T) {
	body := []byte("\x10\x14\x10\x17\x18\x02\x22\x76\x0a\x74https://www.baidu.com/link?url=v9rmp7zwgcafttycljbacgyvpcdxksjlxwd0etm4fgm&wd=&eqid=b3bd902700001c8f0000000464a293cd")

	targets := extractBodyTargets(body, "application/x-protobuf")

	if len(targets) != 0 {
		t.Fatalf("clean opaque body targets = %#v, want none", targets)
	}
}

func TestExtractBodyTargetsKeepsSuspiciousOpaqueBody(t *testing.T) {
	body := []byte("\x10\x14\x22\x20<script>alert(1)</script>")

	targets := extractBodyTargets(body, "application/x-protobuf")

	if len(targets) != 1 {
		t.Fatalf("suspicious opaque body targets length = %d, want 1: %#v", len(targets), targets)
	}
	if targets[0] == "" {
		t.Fatal("suspicious opaque body target should not be empty")
	}
}

func TestExtractBodyTargetsRawFallbackForInvalidJSON(t *testing.T) {
	body := []byte("d2hvYW1p\x00whoami")

	targets := extractBodyTargets(body, "application/json")

	if len(targets) != 1 {
		t.Fatalf("invalid JSON raw fallback targets length = %d, want 1: %#v", len(targets), targets)
	}
	if targets[0] != string(body) {
		t.Fatalf("invalid JSON raw fallback target = %#v, want %#v", targets[0], string(body))
	}
}

func TestExtractBodyTargetsAcceptsMixedCaseContentType(t *testing.T) {
	if targets := extractBodyTargets([]byte(`{"username":"admin"}`), "Application/JSON; Charset=UTF-8"); len(targets) == 0 {
		t.Fatal("mixed-case JSON content type should still be parsed")
	}
	if targets := extractBodyTargets([]byte("name=value"), "Application/X-WWW-Form-Urlencoded"); len(targets) == 0 {
		t.Fatal("mixed-case form content type should still be parsed")
	}
}

func TestExtractBodyTargetsDedupesRepeatedFormValues(t *testing.T) {
	body := []byte("first=false&second=false&third=true&fourth=false")

	targets := extractBodyTargets(body, "application/x-www-form-urlencoded")

	want := []string{"false", "first", "second", "true", "third", "fourth"}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("form body targets = %#v, want %#v", targets, want)
	}
}

func TestDedupeBodyTargetsPreservesFirstOccurrenceOrder(t *testing.T) {
	targets := []string{"a", "b", "a", "c", "b"}

	got := dedupeBodyTargets(targets)

	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("deduped body targets = %#v, want %#v", got, want)
	}
}

func TestOWASPPhaseDetectsMultipartUploadSemantics(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.OWASPEnabled = true
	cfg.OWASPSensitivity = "mid"
	cfg.OWASPAction = "intercept"
	phase := NewOWASPPhase(&cfg)

	tests := []struct {
		name        string
		filename    string
		contentType string
		content     string
		blocked     bool
	}{
		{name: "direct executable", filename: "console.php", contentType: "application/octet-stream", content: "<?php echo 1; ?>", blocked: true},
		{name: "double extension", filename: "avatar.php.jpg", contentType: "image/jpeg", content: "<?php echo 1; ?>", blocked: true},
		{name: "semicolon separator", filename: "avatar.php;.jpg", contentType: "image/jpeg", content: "<?php echo 1; ?>", blocked: true},
		{name: "space separator", filename: "avatar.php .jpg", contentType: "image/jpeg", content: "<?php echo 1; ?>", blocked: true},
		{name: "null byte", filename: "avatar.php%00.jpg", contentType: "image/jpeg", content: "<?php echo 1; ?>", blocked: true},
		{name: "path traversal", filename: "../../var/www/console.php", contentType: "application/octet-stream", content: "<?php echo 1; ?>", blocked: true},
		{name: "image polyglot", filename: "avatar.jpg", contentType: "image/jpeg", content: "GIF89a<?php system($_GET['task']); ?>", blocked: true},
		{name: "clean image", filename: "quarterly photo.jpg", contentType: "image/jpeg", content: "JPEG image content", blocked: false},
		{name: "internal spaces do not form extension", filename: "report.p h p.jpg", contentType: "image/jpeg", content: "ordinary report", blocked: false},
		{name: "similar extension token", filename: "manual.phpunit.jpg", contentType: "image/jpeg", content: "ordinary report", blocked: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, contentType := multipartRequestBody(t, tt.filename, tt.contentType, tt.content)
			result, stop := phase.Execute(&pipeline.RequestCtx{
				Method:      http.MethodPost,
				Path:        "/upload",
				Body:        body,
				ContentType: contentType,
			})
			blocked := stop && result.IsTerminal()
			if blocked != tt.blocked {
				t.Fatalf("blocked = %v, want %v: action=%q phase=%q rule=%q", blocked, tt.blocked, result.Type, result.Phase, result.RuleIDStr)
			}
			if blocked && result.Phase != "owasp_default" {
				t.Fatalf("phase = %q, want owasp_default", result.Phase)
			}
		})
	}
}

func TestOWASPPhaseDetectsRawNullByteMultipartFilenames(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.OWASPEnabled = true
	cfg.OWASPSensitivity = "mid"
	cfg.OWASPAction = "intercept"
	phase := NewOWASPPhase(&cfg)

	const boundary = "blaze-null-byte-boundary"
	for _, filename := range []string{"info.php\x00.jpg", "111.php\x00.png"} {
		body := []byte("--" + boundary + "\r\n" +
			"Content-Disposition: form-data; name=\"uploaded\"; filename=\"" + filename + "\"\r\n" +
			"Content-Type: image/png\r\n\r\nGIF89a\r\n" +
			"--" + boundary + "--\r\n")
		result, stop := phase.Execute(&pipeline.RequestCtx{
			Method:      http.MethodPost,
			Path:        "/vulnerabilities/upload/",
			Body:        body,
			ContentType: "multipart/form-data; boundary=" + boundary,
		})
		if !stop || result.Type != action.Intercept || result.RuleIDStr != "owasp:upload:001" {
			t.Fatalf("raw null-byte filename %q result=%#v stop=%v, want intercept owasp:upload:001", filename, result, stop)
		}
	}
}

func TestOWASPPhaseSeparatesIndependentEncodedXSSContexts(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.OWASPEnabled = true
	cfg.OWASPSensitivity = "mid"
	cfg.OWASPAction = "intercept"
	phase := NewOWASPPhase(&cfg)

	tests := []struct {
		name    string
		body    string
		blocked bool
	}{
		{name: "active scheme in one decode chain", body: nestedEncodedXSSBody(`<iframe src="j a v a s c r i p t:alert(1)"></iframe>`), blocked: true},
		{name: "deep semantic decode chain", body: layeredEncodedXSSBody(`&lt;iframe src=&quot;java&#13;scri&#10;pt&#9;&#58;alert(1)&quot;&gt;&lt;/iframe&gt;`), blocked: true},
		{name: "deep benign decode chain", body: layeredEncodedXSSBody(`&lt;iframe src=&quot;https&#58;//example.invalid/help&quot;&gt;&lt;/iframe&gt;`), blocked: false},
		{name: "independent benign sibling tokens", body: "markup=PGlmcmFtZSBzcmM9XCJodHRwczovL2V4YW1wbGUuaW52YWxpZFwiPjwvaWZyYW1lPg==&text=amF2YXNjcmlwdCBhbGVydCBkb2N1bWVudGF0aW9u", blocked: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, stop := phase.Execute(&pipeline.RequestCtx{
				Method:      http.MethodPost,
				Path:        "/submit",
				Body:        []byte(tt.body),
				ContentType: "application/x-www-form-urlencoded",
			})
			blocked := stop && result.IsTerminal()
			if blocked != tt.blocked {
				t.Fatalf("blocked = %v, want %v: action=%q phase=%q rule=%q", blocked, tt.blocked, result.Type, result.Phase, result.RuleIDStr)
			}
		})
	}
}

func TestOWASPPhaseContinuesAfterSkippingEarlyCRLF(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.OWASPEnabled = true
	cfg.OWASPSensitivity = "mid"
	cfg.OWASPAction = "intercept"
	cfg.OWASPRulesConfig = `{"owasp:crlf:005":{"whitelist":["/safe%0d%0a"]}}`
	phase := NewOWASPPhase(&cfg)

	result, stop := phase.Execute(&pipeline.RequestCtx{
		Method:   http.MethodGet,
		Path:     "/safe%0d%0a",
		RawQuery: "q=<script>alert(1)</script>",
	})
	if !stop || !result.IsTerminal() {
		t.Fatalf("expected terminal XSS result after skipping CRLF, got action=%q rule=%q", result.Type, result.RuleIDStr)
	}
	if result.Category != "xss" {
		t.Fatalf("expected XSS result after skipping CRLF, got category=%q rule=%q", result.Category, result.RuleIDStr)
	}
}

func multipartRequestBody(t *testing.T, filename, partContentType, content string) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="document"; filename=%q`, filename))
	header.Set("Content-Type", partContentType)
	part, err := writer.CreatePart(header)
	if err != nil {
		t.Fatalf("create multipart part: %v", err)
	}
	if _, err := io.WriteString(part, content); err != nil {
		t.Fatalf("write multipart part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return body.Bytes(), writer.FormDataContentType()
}

func nestedEncodedXSSBody(payload string) string {
	inner := base64.StdEncoding.EncodeToString([]byte(payload))
	var escaped strings.Builder
	for _, b := range []byte(inner) {
		fmt.Fprintf(&escaped, `\u%04X`, b)
	}
	outer := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"payload":"%s"}`, escaped.String())))
	return "payload=" + outer
}

func layeredEncodedXSSBody(payload string) string {
	return nestedEncodedXSSBody(strings.Repeat("&#65;", 180) + payload)
}

func encryptBrowserSignEnv(t *testing.T, keyHex, aad string, plaintext []byte) string {
	t.Helper()
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		t.Fatalf("decode browser sign environment key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new aes cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("new gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("read environment nonce: %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(aad))
	return "v1." + base64.RawURLEncoding.EncodeToString(append(nonce, ciphertext...))
}

func TestBrowserSignPhaseRequiresAPISignature(t *testing.T) {
	cfg := &store.ProtectionConfig{
		BrowserSignEnabled: true,
		BrowserSignAction:  string(action.Challenge),
	}
	phase := NewBrowserSignPhase(cfg)

	// non-api document navigation should pass
	pass, terminal := phase.Execute(&pipeline.RequestCtx{
		Method: "GET",
		Path:   "/",
		Headers: map[string]string{
			"accept":         "text/html",
			"sec-fetch-mode": "navigate",
			"sec-fetch-dest": "document",
		},
	})
	if terminal || pass.Matched {
		t.Fatalf("document request should pass, terminal=%v result=%+v", terminal, pass)
	}

	// api without headers should challenge
	result, terminal := phase.Execute(&pipeline.RequestCtx{
		Method: "POST",
		Path:   "/api/v1/items",
		Host:   "example.com",
		SiteID: 1,
		Headers: map[string]string{
			"content-type": "application/json",
			"accept":       "application/json",
		},
	})
	if !terminal || result.Type != action.Challenge {
		t.Fatalf("missing signature should challenge, terminal=%v result=%+v", terminal, result)
	}
	if result.Phase != "browser_sign" {
		t.Fatalf("phase = %q", result.Phase)
	}

	now := time.Now()
	ticket := challenge.IssueBrowserSignTicket(1, 60)
	rawQuery := "filter=active&sort=created%2Bdesc"
	ts := now.Unix()
	envPlaintext := []byte(`{"webdriver":false,"chrome_present":true,"plugins_count":3,"languages":"zh-CN","canvas_hash":"1","webgl_renderer":"NVIDIA","screen_width":1920,"screen_height":1080,"hardware_concurrency":8,"session_storage":true,"indexed_db":true,"cookie_enabled":true,"platform":"Linux","web_assembly":true,"screen_consistency":true,"timezone_consistency":true,"language_consistency":true,"math_consistency":true}`)
	env := encryptBrowserSignEnv(t, ticket.EnvKeyHex, ticket.EnvAAD, envPlaintext)
	signKey, err := hex.DecodeString(ticket.SignKey)
	if err != nil {
		t.Fatalf("decode browser sign key: %v", err)
	}
	payload := "POST|/api/v1/items|" + rawQuery + "|" + strconv.FormatInt(ts, 10) + "|" + ticket.Nonce + "|" + env
	mac := hmac.New(sha256.New, signKey)
	_, _ = mac.Write([]byte(payload))
	headers := map[string]string{
		"content-type":                   "application/json",
		"accept":                         "application/json",
		challenge.BrowserSignHeaderNonce: ticket.Nonce,
		challenge.BrowserSignHeaderExp:   strconv.FormatInt(ticket.ExpiresAt, 10),
		challenge.BrowserSignHeaderMAC:   ticket.TicketMAC,
		challenge.BrowserSignHeaderTS:    strconv.FormatInt(ts, 10),
		challenge.BrowserSignHeaderSig:   hex.EncodeToString(mac.Sum(nil)),
		challenge.BrowserSignHeaderEnv:   env,
	}

	pass, terminal = phase.Execute(&pipeline.RequestCtx{
		Method:   "POST",
		Path:     "/api/v1/items",
		RawQuery: rawQuery,
		Host:     "example.com",
		SiteID:   1,
		Headers:  headers,
	})
	if terminal || pass.Matched {
		t.Fatalf("valid query-bound signature should pass, terminal=%v result=%+v", terminal, pass)
	}

	result, terminal = phase.Execute(&pipeline.RequestCtx{
		Method:   "POST",
		Path:     "/api/v1/items",
		RawQuery: rawQuery + "&page=2",
		Host:     "example.com",
		SiteID:   1,
		Headers:  headers,
	})
	if !terminal || result.MatchDesc != "浏览器签名请求 MAC 校验失败" {
		t.Fatalf("modified raw query should challenge, terminal=%v result=%+v", terminal, result)
	}
}

func TestChallengePassCookieUsesPreMutationIdentity(t *testing.T) {
	now := time.Now()
	clientIP := net.ParseIP("203.0.113.10")
	cookie := challenge.BuildChallengePassCookieWithClaims(challenge.ChallengePassClaims{
		Host:      "example.com",
		ClientIP:  clientIP,
		UserAgent: "original-agent",
		SiteID:    7,
		Bind:      ":443",
	}, true, now, time.Hour)

	ctx := &pipeline.RequestCtx{
		Bind:                       ":443",
		ClientIP:                   clientIP,
		Host:                       "example.com",
		UserAgent:                  "mutated-agent",
		ChallengeIdentityCaptured:  true,
		ChallengeIdentityUserAgent: "original-agent",
		ChallengeIdentityCookie:    cookie,
		SiteID:                     7,
		Method:                     "POST",
		Path:                       "/api/v1/items",
		Headers: map[string]string{
			"content-type": "application/json",
			"accept":       "application/json",
		},
	}

	browser := NewBrowserSignPhase(&store.ProtectionConfig{
		BrowserSignEnabled: true,
		BrowserSignAction:  string(action.Challenge),
	})
	if result, terminal := browser.Execute(ctx); terminal || result.Matched {
		t.Fatalf("browser sign should trust the pre-mutation pass cookie, terminal=%v result=%+v", terminal, result)
	}

	botPhase := &botPhase{threshold: 80}
	if result, terminal := botPhase.Execute(ctx); terminal || result.Matched {
		t.Fatalf("bot phase should trust the pre-mutation pass cookie, terminal=%v result=%+v", terminal, result)
	}
}
