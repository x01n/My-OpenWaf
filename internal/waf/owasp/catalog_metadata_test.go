package owasp

import (
	"strings"
	"testing"
)

func TestBuiltinRuleDefinitionsExposePerRuleRemarks(t *testing.T) {
	definitions := BuiltinRuleDefinitions()
	if len(definitions) < 300 {
		t.Fatalf("built-in definitions=%d want at least 300", len(definitions))
	}
	descriptions := make(map[string]struct{}, len(definitions))
	for i := range definitions {
		item := definitions[i]
		if strings.TrimSpace(item.RuleID) == "" || strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Description) == "" {
			t.Fatalf("incomplete metadata: %#v", item)
		}
		descriptions[item.Description] = struct{}{}
	}
	if len(descriptions) < 300 {
		t.Fatalf("distinct descriptions=%d want at least 300", len(descriptions))
	}
}

func TestBuiltinRuleDefinitionsExcludeUnemittedPathRuleAndDescribeDirectRules(t *testing.T) {
	definitions := BuiltinRuleDefinitions()
	byID := make(map[string]string, len(definitions))
	for i := range definitions {
		byID[definitions[i].RuleID] = definitions[i].Description
	}
	if _, exists := byID["owasp:path:003"]; exists {
		t.Fatal("owasp:path:003 has no detector emission path and must not remain active")
	}
	for _, ruleID := range []string{"owasp:upload:001", "owasp:proto:001", "owasp:path:001", "owasp:deser:012", "owasp:crlf:005"} {
		description := byID[ruleID]
		if !strings.Contains(description, "风险分值") {
			t.Fatalf("rule %s description=%q missing risk score remark", ruleID, description)
		}
	}
}
