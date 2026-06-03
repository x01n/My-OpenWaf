package rules

import (
	"net"
	"testing"

	"My-OpenWaf/internal/store"
)

func TestParsePatternNewKinds(t *testing.T) {
	tests := []struct {
		input    string
		wantKind string
		wantArg  string
	}{
		{"block_path_exact:/admin", "block_path_exact", "/admin"},
		{"block_method:DELETE", "block_method", "DELETE"},
		{"block_content_type:application/xml", "block_content_type", "application/xml"},
		{"block_ip:10.0.0.0/8", "block_ip", "10.0.0.0/8"},
		{"unknown:foo", "", ""},
	}
	for _, tt := range tests {
		kind, arg := ParsePattern(tt.input)
		if kind != tt.wantKind || arg != tt.wantArg {
			t.Errorf("ParsePattern(%q) = (%q, %q), want (%q, %q)", tt.input, kind, arg, tt.wantKind, tt.wantArg)
		}
	}
}

func TestCompoundJSONPattern(t *testing.T) {
	// JSON compound condition: AND(block_path:/admin, block_method:POST)
	pattern := `{"op":"and","children":[{"kind":"block_path","arg":"/admin"},{"kind":"block_method","arg":"POST"}]}`
	kind, _ := ParsePattern(pattern)
	if kind != "compound" {
		t.Fatalf("expected kind=compound, got %q", kind)
	}

	rules := Compile([]store.Rule{
		{Phase: "custom", Pattern: pattern, Action: "intercept", Priority: 1, Enabled: true},
	})
	if len(rules) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(rules))
	}

	mc := MatchCtx{
		ClientIP: net.ParseIP("1.2.3.4"),
		Method:   "POST",
		Path:     "/admin/users",
		Query:    "",
		Headers:  map[string]string{},
	}
	if !rules[0].Match(mc) {
		t.Error("expected match for POST /admin/users")
	}

	mc.Method = "GET"
	if rules[0].Match(mc) {
		t.Error("expected no match for GET /admin/users")
	}

	mc.Path = "/public"
	mc.Method = "POST"
	if rules[0].Match(mc) {
		t.Error("expected no match for POST /public")
	}
}

func TestCompoundOR(t *testing.T) {
	pattern := `{"op":"or","children":[{"kind":"block_path_exact","arg":"/.env"},{"kind":"block_path_exact","arg":"/.git/config"}]}`
	rules := Compile([]store.Rule{
		{Phase: "custom", Pattern: pattern, Action: "intercept", Priority: 1, Enabled: true},
	})
	if len(rules) != 1 {
		t.Fatal("expected 1 compiled rule")
	}

	for _, path := range []string{"/.env", "/.git/config"} {
		mc := MatchCtx{Path: path}
		if !rules[0].Match(mc) {
			t.Errorf("expected match for %s", path)
		}
	}

	mc := MatchCtx{Path: "/index.html"}
	if rules[0].Match(mc) {
		t.Error("expected no match for /index.html")
	}
}

func TestCompoundNOT(t *testing.T) {
	pattern := `{"op":"not","children":[{"kind":"allow_ip","arg":"10.0.0.0/8"}]}`
	rules := Compile([]store.Rule{
		{Phase: "acl", Pattern: pattern, Action: "intercept", Priority: 1, Enabled: true},
	})
	if len(rules) != 1 {
		t.Fatal("expected 1 compiled rule")
	}

	// IP outside 10.0.0.0/8 should match (NOT whitelist = block)
	mc := MatchCtx{ClientIP: net.ParseIP("8.8.8.8"), Path: "/"}
	if !rules[0].Match(mc) {
		t.Error("expected match for IP outside 10.0.0.0/8")
	}

	// IP inside 10.0.0.0/8 should NOT match
	mc.ClientIP = net.ParseIP("10.1.2.3")
	if rules[0].Match(mc) {
		t.Error("expected no match for IP inside 10.0.0.0/8")
	}
}

func TestCompoundIfElse(t *testing.T) {
	pattern := `{"op":"if","if":{"kind":"host","arg":"admin.example.com"},"then":{"kind":"block_path","arg":"/admin"},"else":{"kind":"block_path_exact","arg":"/.env"}}`
	rules := Compile([]store.Rule{{Phase: "custom", Pattern: pattern, Action: "intercept", Priority: 1, Enabled: true}})
	if len(rules) != 1 {
		t.Fatal("expected 1 compiled rule")
	}
	if !rules[0].Match(MatchCtx{Path: "/admin/users", Headers: map[string]string{"Host": "admin.example.com:443"}}) {
		t.Fatal("expected then branch to match admin host")
	}
	if rules[0].Match(MatchCtx{Path: "/public", Headers: map[string]string{"Host": "admin.example.com"}}) {
		t.Fatal("expected then branch to reject non-admin path")
	}
	if !rules[0].Match(MatchCtx{Path: "/.env", Headers: map[string]string{"Host": "www.example.com"}}) {
		t.Fatal("expected else branch to match non-admin host")
	}
}

func TestQueryParamMatcherDecodesValues(t *testing.T) {
	rules := Compile([]store.Rule{{Phase: "custom", Pattern: "query_param:q:union select", Action: "intercept", Priority: 1, Enabled: true}})
	if len(rules) != 1 {
		t.Fatal("expected 1 compiled rule")
	}
	if !rules[0].Match(MatchCtx{Query: "q=union+select"}) {
		t.Fatal("expected decoded query parameter value to match")
	}
}

func TestQueryParamRegexMatcher(t *testing.T) {
	rules := Compile([]store.Rule{{Phase: "custom", Pattern: `query_param_regex:q:(?i)union\s+select`, Action: "intercept", Priority: 1, Enabled: true}})
	if len(rules) != 1 {
		t.Fatal("expected 1 compiled rule")
	}
	if !rules[0].Match(MatchCtx{Query: "q=UNION+SELECT"}) {
		t.Fatal("expected decoded query parameter regex to match")
	}
}

func TestPathContainsMatchers(t *testing.T) {
	contains := Compile([]store.Rule{{Phase: "custom", Pattern: "path_contains:/api/", Action: "intercept", Priority: 1, Enabled: true}})
	if !contains[0].Match(MatchCtx{Path: "/v1/api/users"}) {
		t.Fatal("expected path_contains to match")
	}
	notContains := Compile([]store.Rule{{Phase: "custom", Pattern: "path_not_contains:/health", Action: "intercept", Priority: 1, Enabled: true}})
	if !notContains[0].Match(MatchCtx{Path: "/v1/api/users"}) || notContains[0].Match(MatchCtx{Path: "/health"}) {
		t.Fatal("unexpected path_not_contains result")
	}
}

func TestExactPathMatcher(t *testing.T) {
	rules := Compile([]store.Rule{
		{Phase: "custom", Pattern: "block_path_exact:/.env", Action: "intercept", Priority: 1, Enabled: true},
	})
	if len(rules) != 1 {
		t.Fatal("expected 1 compiled rule")
	}

	mc := MatchCtx{Path: "/.env"}
	if !rules[0].Match(mc) {
		t.Error("expected match for /.env")
	}

	mc.Path = "/.environment"
	if rules[0].Match(mc) {
		t.Error("expected no match for /.environment")
	}
}

func TestMethodMatcher(t *testing.T) {
	rules := Compile([]store.Rule{
		{Phase: "custom", Pattern: "block_method:TRACE", Action: "intercept", Priority: 1, Enabled: true},
	})
	if len(rules) != 1 {
		t.Fatal("expected 1 compiled rule")
	}

	mc := MatchCtx{Method: "TRACE", Headers: map[string]string{}}
	if !rules[0].Match(mc) {
		t.Error("expected match for TRACE")
	}

	mc.Method = "GET"
	if rules[0].Match(mc) {
		t.Error("expected no match for GET")
	}
}

func TestContentTypeMatcher(t *testing.T) {
	rules := Compile([]store.Rule{
		{Phase: "custom", Pattern: "block_content_type:application/xml", Action: "intercept", Priority: 1, Enabled: true},
	})
	if len(rules) != 1 {
		t.Fatal("expected 1 compiled rule")
	}

	mc := MatchCtx{Headers: map[string]string{"Content-Type": "application/xml; charset=utf-8"}}
	if !rules[0].Match(mc) {
		t.Error("expected match for application/xml")
	}

	mc.Headers["Content-Type"] = "application/json"
	if rules[0].Match(mc) {
		t.Error("expected no match for application/json")
	}
}

func TestUserAgentMatcher(t *testing.T) {
	rules := Compile([]store.Rule{
		{Phase: "acl", Pattern: "block_user_agent:sqlmap", Action: "intercept", Priority: 1, Enabled: true},
	})
	if len(rules) != 1 {
		t.Fatal("expected 1 compiled rule")
	}

	mc := MatchCtx{Headers: map[string]string{"User-Agent": "sqlmap/1.7.8 (https://sqlmap.org)"}}
	if !rules[0].Match(mc) {
		t.Error("expected match for sqlmap User-Agent")
	}

	mc.Headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	if rules[0].Match(mc) {
		t.Error("expected no match for normal browser UA")
	}
}

func TestUserAgentRegexMatcher(t *testing.T) {
	rules := Compile([]store.Rule{
		{Phase: "acl", Pattern: `block_user_agent_regex:(?i)(sqlmap|nikto|nessus|nmap|masscan|zgrab|nuclei)`, Action: "intercept", Priority: 1, Enabled: true},
	})
	if len(rules) != 1 {
		t.Fatal("expected 1 compiled rule")
	}

	for _, ua := range []string{"sqlmap/1.7", "Nikto/2.1.6", "Nessus Agent", "masscan/1.3"} {
		mc := MatchCtx{Headers: map[string]string{"User-Agent": ua}}
		if !rules[0].Match(mc) {
			t.Errorf("expected match for scanner UA: %s", ua)
		}
	}

	mc := MatchCtx{Headers: map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"}}
	if rules[0].Match(mc) {
		t.Error("expected no match for Googlebot")
	}
}

func TestUserAgentRegexCached(t *testing.T) {
	// Compile the same regex-based rule twice; both should match identically,
	// verifying the regex cache returns the correct compiled pattern.
	pattern := `block_user_agent_regex:(?i)dirbuster`
	r1 := Compile([]store.Rule{{Phase: "acl", Pattern: pattern, Action: "intercept", Priority: 1, Enabled: true}})
	r2 := Compile([]store.Rule{{Phase: "acl", Pattern: pattern, Action: "intercept", Priority: 1, Enabled: true}})

	mc := MatchCtx{Headers: map[string]string{"User-Agent": "DirBuster-1.0"}}
	if !r1[0].Match(mc) || !r2[0].Match(mc) {
		t.Error("both rule compilations should match DirBuster")
	}
}

func TestCCRateMatcherThresholdAndHostIsolation(t *testing.T) {
	pattern := `{"op":"cc_rate","window":60,"threshold":3,"duration":5,"children":[{"kind":"block_path","arg":"/login"}]}`
	rules := Compile([]store.Rule{
		{Phase: "custom", Pattern: pattern, Action: "challenge", Priority: 1, Enabled: true},
	})
	if len(rules) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(rules))
	}

	mc := MatchCtx{ClientIP: net.ParseIP("1.2.3.4"), Path: "/login", Headers: map[string]string{"Host": "a.example"}}
	if rules[0].Match(mc) {
		t.Fatal("first matching request should stay below threshold")
	}
	if rules[0].Match(mc) {
		t.Fatal("second matching request should stay below threshold")
	}
	if !rules[0].Match(mc) {
		t.Fatal("third matching request should reach threshold")
	}
	if !rules[0].Match(mc) {
		t.Fatal("same client should remain challenged during duration")
	}

	mc.Headers["Host"] = "b.example"
	if rules[0].Match(mc) {
		t.Fatal("different host should have an independent counter")
	}
}

func TestTLSFingerprintMatchers(t *testing.T) {
	rules := Compile([]store.Rule{
		{ID: 1, Name: "ja4", PolicyID: 1, Phase: store.PhaseCustom, Pattern: "tls_ja4:t13d1516h2", Action: store.ActionIntercept, Enabled: true},
		{ID: 2, Name: "ja3-hash", PolicyID: 1, Phase: store.PhaseCustom, Pattern: "tls_ja3_hash:27a5061c22108817120d1d3870cba0e0", Action: store.ActionIntercept, Enabled: true},
		{ID: 3, Name: "header-order", PolicyID: 1, Phase: store.PhaseCustom, Pattern: "header_order_contains:user-agent,accept", Action: store.ActionIntercept, Enabled: true},
	})
	if len(rules) != 3 {
		t.Fatalf("expected 3 compiled fingerprint rules, got %d", len(rules))
	}
	mc := MatchCtx{Headers: map[string]string{
		"X-OWAF-TLS-JA4":      "t13d1516h2",
		"X-OWAF-TLS-JA3":      "771,4865-4866,0-23,29,0",
		"X-OWAF-Header-Order": "host,user-agent,accept",
	}}
	for _, rule := range rules {
		if !rule.Match(mc) {
			t.Fatalf("expected fingerprint rule %s to match", rule.Kind)
		}
	}
}
