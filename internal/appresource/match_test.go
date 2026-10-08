package appresource

import (
	"testing"

	"My-OpenWaf/internal/store/approute"
)

func TestApplyOpBasic(t *testing.T) {
	if !Match(CompiledRule{Op: approute.AppRouteOpEq, Pattern: "GET"}, "GET") {
		t.Fatal("eq")
	}
	if Match(CompiledRule{Op: approute.AppRouteOpNe, Pattern: "GET"}, "GET") {
		t.Fatal("ne")
	}
	if !Match(CompiledRule{Op: approute.AppRouteOpContains, Pattern: "foo"}, "barfoobaz") {
		t.Fatal("contains")
	}
	if Match(CompiledRule{Op: approute.AppRouteOpNotContains, Pattern: "foo"}, "barfoobaz") {
		t.Fatal("not_contains")
	}
	if !Match(CompiledRule{Op: approute.AppRouteOpFuzzy, Pattern: "FOO"}, "xfoo") {
		t.Fatal("fuzzy")
	}
}

func TestCompileRulesRegex(t *testing.T) {
	rules := []approute.ApplicationRouteRule{
		{ID: 1, SiteID: 1, Enabled: true, Target: approute.AppRouteTargetRequestMethod, Op: approute.AppRouteOpRegex, Pattern: `GET|POST`},
	}
	out := CompileRules(rules)
	if len(out) != 1 || out[0].Regex == nil {
		t.Fatalf("compile: %#v", out)
	}
	if !Match(out[0], "GET") {
		t.Fatal("regex match")
	}
}
