package snapshot

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/store"
)

func TestLoadDefaultsFallbackOnInvalidJSON(t *testing.T) {
	network := LoadNetworkDefaults(`{"default_network":"tcp6","default_alpn":`)
	if network.DefaultNetwork != DefaultNetworkDefaults().DefaultNetwork || network.DefaultALPN != DefaultNetworkDefaults().DefaultALPN {
		t.Fatalf("invalid network config should use defaults, got %+v", network)
	}

	tlsDefaults := LoadTLSDefaults(`{"min_version":"TLS13","default_alpn":`)
	if tlsDefaults.MinVersion != DefaultTLSDefaults().MinVersion || tlsDefaults.DefaultALPN != DefaultTLSDefaults().DefaultALPN {
		t.Fatalf("invalid TLS config should use defaults, got %+v", tlsDefaults)
	}
}

func TestLoadDefaultsPreserveMissingCriticalFields(t *testing.T) {
	network := LoadNetworkDefaults(`{"http3_enabled":true}`)
	if !network.HTTP3Enabled || network.DefaultNetwork != "tcp" || network.DefaultALPN != "h2,h3,http/1.1" {
		t.Fatalf("partial network config should preserve defaults, got %+v", network)
	}

	tlsDefaults := LoadTLSDefaults(`{"cipher_suites":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}`)
	if tlsDefaults.MinVersion != "TLS10" || tlsDefaults.MaxVersion != "TLS13" || tlsDefaults.DefaultALPN != "h2,h3,http/1.1" {
		t.Fatalf("partial TLS config should preserve defaults, got %+v", tlsDefaults)
	}
}

func TestParseTLSCipherSuitesRecognizesNamesAndDeduplicates(t *testing.T) {
	got := parseTLSCipherSuites("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,ECDHE_RSA_WITH_AES_128_GCM_SHA256,tls_ecdhe_rsa_with_aes_128_gcm_sha256")
	if len(got) != 1 || got[0] == 0 {
		t.Fatalf("unexpected cipher suites: %#v", got)
	}
}

func TestParseALPNProtocolsDeduplicates(t *testing.T) {
	got := parseALPNProtocols(" h2 , http/1.1 , h2 ")
	want := []string{"h2", "http/1.1"}
	if len(got) != len(want) {
		t.Fatalf("unexpected ALPN list: %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected ALPN list: got=%#v want=%#v", got, want)
		}
	}
}

func TestParseCurvePreferencesAliasesAndDeduplicates(t *testing.T) {
	got := ParseCurvePreferences("X25519,P-256,CurveP256,p384")
	if len(got) != 3 {
		t.Fatalf("unexpected curves: %#v", got)
	}
}

func testSiteRuntime(id uint, bind, host string) SiteRuntime {
	return SiteRuntime{
		Site: store.Site{
			ID:   id,
			Host: host,
		},
		Bind: bind,
	}
}

func TestMatchSiteMatchesWithinCurrentBind(t *testing.T) {
	sn := &Snapshot{
		Sites: map[string]SiteRuntime{
			SiteMapKey(":443", "app.example.com"): testSiteRuntime(1, ":443", "app.example.com"),
			SiteMapKey(":443", "*.example.com"):   testSiteRuntime(2, ":443", "*.example.com"),
		},
	}

	tests := []struct {
		name   string
		bind   string
		host   string
		wantID uint
	}{
		{name: "exact match", bind: ":443", host: "app.example.com", wantID: 1},
		{name: "host header with port", bind: ":443", host: "app.example.com:443", wantID: 1},
		{name: "wildcard match", bind: ":443", host: "api.example.com", wantID: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sn.MatchSite(tt.bind, tt.host)
			if !ok {
				t.Fatalf("MatchSite(%q, %q) = no match, want site %d", tt.bind, tt.host, tt.wantID)
			}
			if got.Site.ID != tt.wantID {
				t.Fatalf("MatchSite(%q, %q) = site %d, want %d", tt.bind, tt.host, got.Site.ID, tt.wantID)
			}
		})
	}
}

func TestMatchSiteDoesNotFallbackAcrossBinds(t *testing.T) {
	sn := &Snapshot{
		Sites: map[string]SiteRuntime{
			SiteMapKey(":80", "public.example.com"):                testSiteRuntime(1, ":80", "public.example.com"),
			SiteMapKey(":80", "other.example.com"):                 testSiteRuntime(2, ":80", "other.example.com"),
			SiteMapKey("127.0.0.1:8081", "admin.internal.example"): testSiteRuntime(3, "127.0.0.1:8081", "admin.internal.example"),
		},
	}

	if got, ok := sn.MatchSite(":80", "admin.internal.example"); ok {
		t.Fatalf("MatchSite matched cross-bind site %d on bind %q", got.Site.ID, got.Bind)
	}
}

func TestMatchSiteNoMatchReturnsFalse(t *testing.T) {
	sn := &Snapshot{
		Sites: map[string]SiteRuntime{
			SiteMapKey(":8800", "a.example.com"): testSiteRuntime(1, ":8800", "a.example.com"),
			SiteMapKey(":8800", "b.example.com"): testSiteRuntime(2, ":8800", "b.example.com"),
			SiteMapKey(":8800", "*.example.com"): testSiteRuntime(3, ":8800", "*.example.com"),
		},
	}

	tests := []struct {
		name   string
		bind   string
		host   string
		wantOK bool
		wantID uint
	}{
		{name: "exact match a", bind: ":8800", host: "a.example.com", wantOK: true, wantID: 1},
		{name: "exact match b", bind: ":8800", host: "b.example.com", wantOK: true, wantID: 2},
		{name: "wildcard match c", bind: ":8800", host: "c.example.com", wantOK: true, wantID: 3},
		{name: "no match different domain", bind: ":8800", host: "d.other.com", wantOK: false},
		{name: "no match different port", bind: ":9999", host: "a.example.com", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sn.MatchSite(tt.bind, tt.host)
			if ok != tt.wantOK {
				t.Fatalf("MatchSite(%q, %q) ok=%v, want %v", tt.bind, tt.host, ok, tt.wantOK)
			}
			if ok && got.Site.ID != tt.wantID {
				t.Fatalf("MatchSite(%q, %q) = site %d, want %d", tt.bind, tt.host, got.Site.ID, tt.wantID)
			}
		})
	}
}

func TestRegisterSiteKeysKeepsFirstDuplicateBindHost(t *testing.T) {
	sites := make(map[string]SiteRuntime)
	registerSiteKeys(sites, testSiteRuntime(1, ":80", "example.com"))
	registerSiteKeys(sites, testSiteRuntime(2, ":80", "example.com"))

	got := sites[SiteMapKey(":80", "example.com")]
	if got.Site.ID != 1 {
		t.Fatalf("expected first site to remain registered, got %d", got.Site.ID)
	}
}

func TestRegisterSiteKeysMultiHost(t *testing.T) {
	sites := make(map[string]SiteRuntime)
	// Site with comma-separated hosts including a wildcard
	registerSiteKeys(sites, testSiteRuntime(1, ":80", "a.example.com, b.example.com, *.example.com"))

	if _, ok := sites[SiteMapKey(":80", "a.example.com")]; !ok {
		t.Fatal("expected a.example.com to be registered")
	}
	if _, ok := sites[SiteMapKey(":80", "b.example.com")]; !ok {
		t.Fatal("expected b.example.com to be registered")
	}
	if _, ok := sites[SiteMapKey(":80", "*.example.com")]; !ok {
		t.Fatal("expected *.example.com to be registered")
	}
	// All three keys should point to the same site
	if sites[SiteMapKey(":80", "a.example.com")].Site.ID != 1 {
		t.Fatal("site ID mismatch for a.example.com")
	}
}

func TestMatchSiteMultiHost(t *testing.T) {
	sites := make(map[string]SiteRuntime)
	registerSiteKeys(sites, testSiteRuntime(1, ":8800", "app.example.com, *.example.org"))
	sn := &Snapshot{Sites: sites}

	// Exact match
	if rt, ok := sn.MatchSite(":8800", "app.example.com"); !ok || rt.Site.ID != 1 {
		t.Fatal("expected exact match on app.example.com")
	}
	// Wildcard match on the second host
	if rt, ok := sn.MatchSite(":8800", "sub.example.org"); !ok || rt.Site.ID != 1 {
		t.Fatal("expected wildcard match on sub.example.org")
	}
	// No match
	if _, ok := sn.MatchSite(":8800", "other.test.com"); ok {
		t.Fatal("expected no match on other.test.com")
	}
}

func TestCompileCCRulesBuildsCompoundCustomRule(t *testing.T) {
	protection := store.ProtectionConfig{
		CCUseCustom: true,
		CCRules: `[
			{
				"name":"admin post challenge",
				"enabled":true,
				"action":"captcha",
				"conditions":[
					{"target":"url_path","operator":"prefix","value":"/admin"},
					{"target":"method","operator":"equals","value":"post"}
				],
				"window":60,
				"threshold":100,
				"duration":5
			}
		]`,
	}

	rules := compileCCRules(protection)
	if len(rules) != 1 {
		t.Fatalf("compileCCRules() returned %d rules, want 1", len(rules))
	}
	if rules[0].Phase != store.PhaseCustom {
		t.Fatalf("phase = %q, want %q", rules[0].Phase, store.PhaseCustom)
	}
	if rules[0].Action != store.ActionChallenge {
		t.Fatalf("action = %q, want %q", rules[0].Action, store.ActionChallenge)
	}
	if rules[0].Kind != "compound" {
		t.Fatalf("kind = %q, want compound", rules[0].Kind)
	}
	if !strings.Contains(rules[0].Arg, `"op":"cc_rate"`) {
		t.Fatalf("compound arg missing cc_rate op: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"threshold":100`) {
		t.Fatalf("compound arg missing threshold: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"window":60`) {
		t.Fatalf("compound arg missing window: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"op":"and"`) {
		t.Fatalf("compound arg missing and op: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"kind":"block_path"`) {
		t.Fatalf("compound arg missing path matcher: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"arg":"/admin"`) {
		t.Fatalf("compound arg missing path value: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"kind":"block_method"`) {
		t.Fatalf("compound arg missing method matcher: %s", rules[0].Arg)
	}
	if !strings.Contains(rules[0].Arg, `"arg":"POST"`) {
		t.Fatalf("compound arg missing normalized method: %s", rules[0].Arg)
	}
}

func TestCompileCCRulesDisabledWhenCustomCCOff(t *testing.T) {
	protection := store.ProtectionConfig{
		CCRules: `[
			{
				"action":"block",
				"conditions":[{"target":"url_path","operator":"contains","value":"/login"}]
			}
		]`,
	}

	if rules := compileCCRules(protection); len(rules) != 0 {
		t.Fatalf("compileCCRules() returned %d rules, want 0", len(rules))
	}
}

func TestCompileCCRulesSkipsUnsupportedConditions(t *testing.T) {
	protection := store.ProtectionConfig{
		CCUseCustom: true,
		CCRules: `[
			{
				"name":"method contains draft",
				"enabled":true,
				"action":"observe",
				"conditions":[{"target":"method","operator":"contains","value":"POST"}]
			}
		]`,
	}

	if rules := compileCCRules(protection); len(rules) != 0 {
		t.Fatalf("compileCCRules() returned %d rules, want 0", len(rules))
	}
}

func TestCompileCCRulesBuildsHeaderRule(t *testing.T) {
	protection := store.ProtectionConfig{
		CCUseCustom: true,
		CCRules: `[
			{
				"action":"block",
				"conditions":[{"target":"header","operator":"contains","value":"User-Agent:curl"}]
			}
		]`,
	}

	rules := compileCCRules(protection)
	if len(rules) != 1 {
		t.Fatalf("compileCCRules() returned %d rules, want 1", len(rules))
	}
	if rules[0].Kind != "block_header" {
		t.Fatalf("kind = %q, want block_header", rules[0].Kind)
	}
	if rules[0].Arg != "User-Agent:curl" {
		t.Fatalf("arg = %q, want User-Agent:curl", rules[0].Arg)
	}
}

func TestCompileCCRulesBuildsSinglePathRule(t *testing.T) {
	protection := store.ProtectionConfig{
		CCUseCustom: true,
		CCRules: `[
			{
				"action":"observe",
				"conditions":[{"target":"url_path","operator":"equals","value":"/login"}]
			}
		]`,
	}

	rules := compileCCRules(protection)
	if len(rules) != 1 {
		t.Fatalf("compileCCRules() returned %d rules, want 1", len(rules))
	}
	if rules[0].Kind != "block_path_exact" {
		t.Fatalf("kind = %q, want block_path_exact", rules[0].Kind)
	}
	if rules[0].Arg != "/login" {
		t.Fatalf("arg = %q, want /login", rules[0].Arg)
	}
	if rules[0].Action != store.ActionObserve {
		t.Fatalf("action = %q, want %q", rules[0].Action, store.ActionObserve)
	}
}

func TestParseUpstreamURLsSupportsJSONArray(t *testing.T) {
	got := parseUpstreamURLs(`[" http://127.0.0.1:8800 ", "", "https://example.com"]`)
	want := []string{"http://127.0.0.1:8800", "https://example.com"}
	if len(got) != len(want) {
		t.Fatalf("parseUpstreamURLs() returned %d urls, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("url[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseUpstreamURLsKeepsCommaFormat(t *testing.T) {
	got := parseUpstreamURLs(` http://127.0.0.1:8800 , https://example.com `)
	want := []string{"http://127.0.0.1:8800", "https://example.com"}
	if len(got) != len(want) {
		t.Fatalf("parseUpstreamURLs() returned %d urls, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("url[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseSiteCacheRulesSuffixNoLeadingSlash(t *testing.T) {
	raw := `[{"type":"suffix","value":"config","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	// Bare token without ".", "/", "?" is treated as a file extension → ".config"
	if len(rules) != 1 || rules[0].Path != ".config" {
		t.Fatalf("got %#v", rules)
	}
}

func TestParseSiteCacheRulesCommaSeparatedSuffixes(t *testing.T) {
	raw := `[{"type":"suffix","value":".js,.mjs","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d %#v", len(rules), rules)
	}
}

func TestParseSiteCacheRulesSuffixBareExtensions(t *testing.T) {
	raw := `[{"type":"suffix","value":"js,html,css","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d %#v", len(rules), rules)
	}
	want := map[string]bool{".js": true, ".html": true, ".css": true}
	for _, r := range rules {
		if !want[r.Path] {
			t.Fatalf("unexpected pattern %q in %#v", r.Path, rules)
		}
	}
}

func TestParseSiteCacheRulesSuffixMultiDotPreserved(t *testing.T) {
	raw := `[{"type":"suffix","value":"min.js,tar.gz","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules, got %d %#v", len(rules), rules)
	}
	got := map[string]bool{rules[0].Path: true, rules[1].Path: true}
	if !got["min.js"] || !got["tar.gz"] {
		t.Fatalf("want min.js and tar.gz unchanged, got %#v", rules)
	}
}

func TestParseSiteCacheRulesContainsNoForcedSlash(t *testing.T) {
	raw := `[{"type":"contains","value":"v=1","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 1 || rules[0].Path != "v=1" {
		t.Fatalf("got %#v", rules)
	}
}

func TestParseSiteCacheRulesRegexCompiled(t *testing.T) {
	raw := `[{"type":"regex","value":"\\.(js|css)$","ttl":10}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 1 || rules[0].Regex == nil {
		t.Fatalf("got %#v", rules)
	}
	if !rules[0].Regex.MatchString("/a/b.js") {
		t.Fatal("expected regex match")
	}
}

func TestParseSiteCacheRulesRegexCaseInsensitive(t *testing.T) {
	raw := `[{"type":"regex","value":"\\.js$","ttl":10,"case_insensitive":true}]`
	rules := parseSiteCacheRules(raw)
	if len(rules) != 1 || rules[0].Regex == nil {
		t.Fatalf("got %#v", rules)
	}
	if !rules[0].Regex.MatchString("/a/b.JS") {
		t.Fatal("expected case-insensitive regex match")
	}
}
