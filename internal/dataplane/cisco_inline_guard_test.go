package dataplane

import (
	"testing"

	"My-OpenWaf/internal/waf/owasp"
)

func TestCiscoInlineGuardModeSemantics(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		query string
		mode  string
		want  bool
	}{
		{"scoped CSCOE portal with tgroup", "/+CSCOE+/translation-table", "tgroup=x", owasp.CiscoASAModeScoped, false},
		{"scoped CSCOE with traversal marker", "/+CSCOE+/../translation-table", "tgroup=x", owasp.CiscoASAModeScoped, true},
		{"scoped CSCOE without tgroup", "/+CSCOE+/translation-table", "", owasp.CiscoASAModeScoped, true},
		{"scoped CSCOT always blocked", "/+CSCOT+/translation-table", "tgroup=x", owasp.CiscoASAModeScoped, true},
		{"legacy CSCOE blocked", "/+CSCOE+/translation-table", "tgroup=x", owasp.CiscoASAModeLegacy, true},
		{"strict CSCOE allowed", "/+CSCOE+/translation-table", "tgroup=x", owasp.CiscoASAModeStrict, false},
		{"strict CSCOT blocked", "/+CSCOT+/translation-table", "", owasp.CiscoASAModeStrict, true},
		{"encoded CSCOT blocked", "/%2bCSCOT%2b/translation-table", "", owasp.CiscoASAModeScoped, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := owasp.CheckCiscoASAInlineGuard(tc.path, tc.query, tc.mode); got != tc.want {
				t.Fatalf("CheckCiscoASAInlineGuard(%q,%q,%q) = %v, want %v", tc.path, tc.query, tc.mode, got, tc.want)
			}
		})
	}
}
