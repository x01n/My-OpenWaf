package appresource

import (
	"testing"

	"My-OpenWaf/internal/store"
)

func TestApplyOpBasic(t *testing.T) {
	if !Match(CompiledRule{Op: store.AppRouteOpEq, Pattern: "GET"}, "GET") {
		t.Fatal("eq")
	}
	if Match(CompiledRule{Op: store.AppRouteOpNe, Pattern: "GET"}, "GET") {
		t.Fatal("ne")
	}
	if !Match(CompiledRule{Op: store.AppRouteOpContains, Pattern: "foo"}, "barfoobaz") {
		t.Fatal("contains")
	}
	if Match(CompiledRule{Op: store.AppRouteOpNotContains, Pattern: "foo"}, "barfoobaz") {
		t.Fatal("not_contains")
	}
	if !Match(CompiledRule{Op: store.AppRouteOpFuzzy, Pattern: "FOO"}, "xfoo") {
		t.Fatal("fuzzy")
	}
}

func TestCompileRulesRegex(t *testing.T) {
	rules := []store.ApplicationRouteRule{
		{ID: 1, SiteID: 1, Enabled: true, Target: store.AppRouteTargetRequestMethod, Op: store.AppRouteOpRegex, Pattern: `GET|POST`},
	}
	out := CompileRules(rules)
	if len(out) != 1 || out[0].Regex == nil {
		t.Fatalf("compile: %#v", out)
	}
	if !Match(out[0], "GET") {
		t.Fatal("regex match")
	}
}
