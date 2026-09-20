package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateAndCompileSiteCacheRules(t *testing.T) {
	raw := `[
		{"type":"prefix","value":"/static","ttl":0,"note":"assets","stale_if_error_seconds":30},
		{"type":"regex","value":"^/items/[0-9]{1,3}$","ttl":90,"case_insensitive":true},
		{"type":"suffix","value":"js,tar.gz","ttl":120}
	]`
	rules, err := ValidateAndCompileSiteCacheRules(raw, 60)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("compiled rule count = %d, want 4", len(rules))
	}
	var prefix, regexRule *SiteCacheRule
	for index := range rules {
		switch rules[index].Type {
		case "prefix":
			prefix = &rules[index]
		case "regex":
			regexRule = &rules[index]
		}
	}
	if prefix == nil || prefix.TTL != 60 || prefix.Note != "assets" || prefix.StaleIfError != 30 {
		t.Fatalf("prefix rule = %#v", prefix)
	}
	if regexRule == nil || regexRule.Regex == nil || !regexRule.Regex.MatchString("/ITEMS/12") {
		t.Fatalf("regex rule was not compiled as one comma-safe pattern: %#v", regexRule)
	}
}

func TestValidateAndCompileSiteCacheRulesRejectsInvalidConfig(t *testing.T) {
	manyRules := make([]SiteCacheRule, MaxSiteCacheRules+1)
	for index := range manyRules {
		manyRules[index] = SiteCacheRule{Type: "prefix", Value: "/x", TTL: 1}
	}
	manyJSON, err := json.Marshal(manyRules)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		raw        string
		defaultTTL int
	}{
		{name: "object", raw: `{}`, defaultTTL: 60},
		{name: "unknown type", raw: `[{"type":"prefex","value":"/x","ttl":1}]`, defaultTTL: 60},
		{name: "empty value", raw: `[{"type":"prefix","value":"","ttl":1}]`, defaultTTL: 60},
		{name: "invalid regex", raw: `[{"type":"regex","value":"(","ttl":1}]`, defaultTTL: 60},
		{name: "negative ttl", raw: `[{"type":"prefix","value":"/x","ttl":-1}]`, defaultTTL: 60},
		{name: "missing inherited ttl", raw: `[{"type":"prefix","value":"/x","ttl":0}]`, defaultTTL: 0},
		{name: "ttl too high", raw: `[{"type":"prefix","value":"/x","ttl":2592001}]`, defaultTTL: 60},
		{name: "stale too high", raw: `[{"type":"prefix","value":"/x","ttl":1,"stale_if_error_seconds":86401}]`, defaultTTL: 60},
		{name: "pattern too long", raw: `[{"type":"prefix","value":"` + strings.Repeat("x", MaxSiteCacheRulePatternBytes+1) + `","ttl":1}]`, defaultTTL: 60},
		{name: "too many rules", raw: string(manyJSON), defaultTTL: 60},
		{name: "json too large", raw: `[{"type":"prefix","value":"/x","ttl":1,"note":"` + strings.Repeat("n", MaxSiteCacheRulesJSONBytes) + `"}]`, defaultTTL: 60},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ValidateAndCompileSiteCacheRules(test.raw, test.defaultTTL); err == nil {
				t.Fatal("invalid cache config was accepted")
			}
		})
	}
}

func TestValidateAndCompileSiteCacheRulesOmitsDisabledRules(t *testing.T) {
	rules, err := ValidateAndCompileSiteCacheRules(`[{"type":"exact","value":"/x","ttl":1,"disabled":true}]`, 60)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("disabled rules entered runtime: %#v", rules)
	}
}
