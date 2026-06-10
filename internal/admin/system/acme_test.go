package system

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/store"
)

func TestResolveACMEEmailUsesRequestEmail(t *testing.T) {
	got, err := resolveACMEEmail("example.com", " admin@example.com ")
	if err != nil {
		t.Fatalf("resolve ACME email: %v", err)
	}
	if got != "admin@example.com" {
		t.Fatalf("email = %q, want request email", got)
	}
}

func TestResolveACMEEmailGeneratesDomainScopedEmail(t *testing.T) {
	got, err := resolveACMEEmail("Example.COM", "")
	if err != nil {
		t.Fatalf("resolve ACME email: %v", err)
	}
	if !strings.HasPrefix(got, "acme-") || !strings.HasSuffix(got, "@example.com") {
		t.Fatalf("generated email = %q, want random local part at example.com", got)
	}
}

func TestMatchACMESitesMatchesEnabledHosts(t *testing.T) {
	matches := matchACMESites([]store.Site{
		{ID: 1, Host: "example.com", Enabled: true},
		{ID: 2, Host: "api.example.com", Enabled: false},
		{ID: 3, Host: "*.example.org", Enabled: true},
	}, "api.example.org")
	if len(matches) != 1 {
		t.Fatalf("match count = %d, want 1", len(matches))
	}
	if matches[0].ID != 3 || matches[0].MatchedName != "*.example.org" {
		t.Fatalf("match = %#v, want wildcard site", matches[0])
	}
}

func TestMatchACMESitesSkipsDisabledHosts(t *testing.T) {
	matches := matchACMESites([]store.Site{
		{ID: 1, Host: "example.com", Enabled: false},
	}, "example.com")
	if len(matches) != 0 {
		t.Fatalf("match count = %d, want 0", len(matches))
	}
}
