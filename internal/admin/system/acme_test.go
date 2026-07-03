package system

import (
	"bytes"
	"encoding/json"
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

func TestLoadACMEConfigDefaultsCAAAllowedIssuers(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(store.SettingKeyACMEConfig, `{"enabled":true,"directory_url":"","auto_renew":true,"renew_before_days":30}`); err != nil {
		t.Fatalf("seed acme config: %v", err)
	}

	got := loadACMEConfig(repo)
	if got.CAAAllowedIssuers != "letsencrypt.org" {
		t.Fatalf("caa_allowed_issuers = %q, want letsencrypt.org", got.CAAAllowedIssuers)
	}
}

func TestUpdateACMEConfigRejectsCAAEnabledWithoutDNSServer(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeSystemConfigHandler(t, UpdateACMEConfig(repo), "POST", "/api/v1/certificates/acme/config", []byte(`{"caa_check_enabled":true,"caa_allowed_issuers":"letsencrypt.org"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestUpdateACMEConfigPersistsCAASettings(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeSystemConfigHandler(t, UpdateACMEConfig(repo), "POST", "/api/v1/certificates/acme/config", []byte(`{"enabled":true,"email":"admin@example.com","caa_check_enabled":true,"caa_allowed_issuers":"letsencrypt.org, pki.goog","caa_dns_server":"127.0.0.1:5353"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp ACMEConfig
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.CAACheckEnabled || resp.CAAAllowedIssuers != "letsencrypt.org, pki.goog" || resp.CAADNSServer != "127.0.0.1:5353" {
		t.Fatalf("response CAA settings = %#v, want persisted settings", resp)
	}

	stored := loadACMEConfig(repo)
	if !stored.CAACheckEnabled || stored.CAAAllowedIssuers != "letsencrypt.org, pki.goog" || stored.CAADNSServer != "127.0.0.1:5353" {
		t.Fatalf("stored CAA settings = %#v, want persisted settings", stored)
	}
}
