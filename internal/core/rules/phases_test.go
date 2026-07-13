package rules

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"reflect"
	"strings"
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/bot"
)

func TestBotPhaseStoreBotScoreDetailsOnlyForHighRisk(t *testing.T) {
	phase := &botPhase{threshold: 80}
	ctx := &pipeline.RequestCtx{}
	phase.storeBotScore(ctx, bot.BotVerdict{Category: "suspicious", Score: 50}, bot.BotScore{Total: 50, Details: map[string]string{"ua": "10"}})
	if ctx.BotScoreResult == nil {
		t.Fatal("expected bot score result")
	}
	if ctx.BotScoreResult.Details != "" {
		t.Fatalf("non-high-risk bot score should skip JSON details, got %q", ctx.BotScoreResult.Details)
	}

	ctx = &pipeline.RequestCtx{}
	phase.storeBotScore(ctx, bot.BotVerdict{Category: "malicious", Score: 90}, bot.BotScore{Total: 90, IsHighRisk: true, Details: map[string]string{"ua": "10"}})
	if ctx.BotScoreResult == nil || ctx.BotScoreResult.Details == "" {
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

func TestACLPhaseAllowShortCircuitsWhenItIsHighestPriorityMatch(t *testing.T) {
	phase := NewACLPhasePrecompiled([]Compiled{
		{ID: 1, Phase: "acl", Action: action.Allow, Kind: "always", matcher: &alwaysMatcher{}},
		{ID: 2, Phase: "acl", Action: action.Intercept, Kind: "always", matcher: &alwaysMatcher{}},
	})

	result, stop := phase.Execute(&pipeline.RequestCtx{})

	if !stop {
		t.Fatal("highest-priority allow should short-circuit phase execution")
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
