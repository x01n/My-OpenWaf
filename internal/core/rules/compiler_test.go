package rules

import (
	"net"
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
)

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
