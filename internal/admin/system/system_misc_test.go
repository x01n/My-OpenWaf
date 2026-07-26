package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/store"
)

func TestMaskDSNHidesCredentials(t *testing.T) {
	tests := []struct {
		name     string
		dsn      string
		wantFunc func(string) bool
	}{
		{
			name:     "empty stays empty",
			dsn:      "   ",
			wantFunc: func(got string) bool { return got == "" },
		},
		{
			// url.URL.String() 会把掩码里的 '*' 百分号编码为 %2A，因此断言编码后的形态。
			name: "url credentials are masked",
			dsn:  "postgres://waf_user:sup3rs3cret@db.internal:5432/waf?sslmode=disable",
			wantFunc: func(got string) bool {
				return !strings.Contains(got, "sup3rs3cret") && strings.Contains(got, "waf_user") &&
					strings.Contains(got, "db.internal:5432") && strings.Contains(got, "%2A%2A%2A%2A%2A%2A")
			},
		},
		{
			name: "url without username masks both parts",
			dsn:  "mysql://:only-a-password@db.internal:3306/waf",
			wantFunc: func(got string) bool {
				return !strings.Contains(got, "only-a-password") &&
					strings.Count(got, "%2A%2A%2A%2A%2A%2A") == 2
			},
		},
		{
			name: "key value password is masked",
			dsn:  "host=db.internal user=waf password=pg-secret dbname=waf",
			wantFunc: func(got string) bool {
				return !strings.Contains(got, "pg-secret") && strings.Contains(got, "password=******") &&
					strings.Contains(got, "host=db.internal") && strings.Contains(got, "user=waf")
			},
		},
		{
			name: "passwd alias is masked",
			dsn:  "host=db.internal passwd=alias-secret",
			wantFunc: func(got string) bool {
				return !strings.Contains(got, "alias-secret") && strings.Contains(got, "passwd=******")
			},
		},
		{
			name: "pwd alias is masked",
			dsn:  "host=db.internal pwd=short-secret",
			wantFunc: func(got string) bool {
				return !strings.Contains(got, "short-secret") && strings.Contains(got, "pwd=******")
			},
		},
		{
			name:     "sqlite path passes through",
			dsn:      "./data/waf.db",
			wantFunc: func(got string) bool { return got == "./data/waf.db" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskDSN(tt.dsn)
			if !tt.wantFunc(got) {
				t.Fatalf("maskDSN(%q) = %q", tt.dsn, got)
			}
		})
	}
}

func TestLoadRuntimeDropEnabled(t *testing.T) {
	// nil 仓库直接回落到 fallback。
	if got := loadRuntimeDropEnabled(nil, true); !got {
		t.Fatalf("nil repo should return the fallback true")
	}
	if got := loadRuntimeDropEnabled(nil, false); got {
		t.Fatalf("nil repo should return the fallback false")
	}

	tests := []struct {
		name     string
		stored   string
		seed     bool
		fallback bool
		want     bool
	}{
		{name: "missing key falls back", seed: false, fallback: true, want: true},
		{name: "empty value falls back", seed: true, stored: "   ", fallback: true, want: true},
		{name: "invalid json falls back", seed: true, stored: "not-json", fallback: false, want: false},
		{name: "absent enabled field falls back", seed: true, stored: `{"threshold":5}`, fallback: true, want: true},
		{name: "explicit false overrides fallback", seed: true, stored: `{"enabled":false}`, fallback: true, want: false},
		{name: "explicit true overrides fallback", seed: true, stored: `{"enabled":true}`, fallback: false, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSystemSettingsRepoForTest(t)
			if tt.seed {
				if err := repo.Set("drop_policy", tt.stored); err != nil {
					t.Fatalf("seed drop_policy: %v", err)
				}
			}
			if got := loadRuntimeDropEnabled(repo, tt.fallback); got != tt.want {
				t.Fatalf("loadRuntimeDropEnabled(%q, fallback=%v) = %v, want %v", tt.stored, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestGetACMEConfigReturnsDefaultsAndStoredValues(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	defaults := invokeSystemConfigHandler(t, GetACMEConfig(repo), "GET", "/api/v1/certificates/acme/config", nil)
	if defaults.Response.StatusCode() != 200 {
		t.Fatalf("status %d: %s", defaults.Response.StatusCode(), bytes.TrimSpace(defaults.Response.Body()))
	}
	var cfg ACMEConfig
	if err := json.Unmarshal(defaults.Response.Body(), &cfg); err != nil {
		t.Fatalf("decode acme config: %v", err)
	}
	if cfg != loadACMEConfig(repo) {
		t.Fatalf("acme config = %#v, want the loader defaults %#v", cfg, loadACMEConfig(repo))
	}
	if cfg.DirectoryURL == "" {
		t.Fatalf("directory_url must default to the ACME directory")
	}

	stored, err := json.Marshal(ACMEConfig{
		Enabled:         true,
		Email:           "  ops@example.test  ",
		DirectoryURL:    "https://acme.example.test/directory",
		AutoRenew:       true,
		RenewBeforeDays: 15,
	})
	if err != nil {
		t.Fatalf("encode stored acme config: %v", err)
	}
	if err := repo.Set(store.SettingKeyACMEConfig, string(stored)); err != nil {
		t.Fatalf("seed acme config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, GetACMEConfig(repo), "GET", "/api/v1/certificates/acme/config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var got ACMEConfig
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode acme config: %v", err)
	}
	if !got.Enabled || !got.AutoRenew || got.RenewBeforeDays != 15 {
		t.Fatalf("acme config = %#v, want the stored values", got)
	}
	// 加载器会去除首尾空白。
	if got.Email != "ops@example.test" {
		t.Fatalf("email = %q, want the trimmed address", got.Email)
	}
	if got.DirectoryURL != "https://acme.example.test/directory" {
		t.Fatalf("directory_url = %q, want the stored directory", got.DirectoryURL)
	}
}

func TestRealtimeTicketHandlerIssuesUniqueTickets(t *testing.T) {
	hub := NewRealtimeHub(nil, nil, nil, nil, nil)

	seen := make(map[string]struct{}, 3)
	for i := 0; i < 3; i++ {
		ctx := invokeSystemConfigHandler(t, hub.TicketHandler(), "POST", "/api/v1/realtime/ticket", nil)
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("ticket status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		var resp struct {
			Ticket    string `json:"ticket"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
			t.Fatalf("decode ticket response: %v", err)
		}
		if len(resp.Ticket) != 64 {
			t.Fatalf("ticket length = %d, want 64 hex chars", len(resp.Ticket))
		}
		if resp.ExpiresAt == "" {
			t.Fatalf("ticket response must carry an expiry")
		}
		if _, dup := seen[resp.Ticket]; dup {
			t.Fatalf("ticket %q was issued twice", resp.Ticket)
		}
		seen[resp.Ticket] = struct{}{}
	}

	// 签发的票据必须可被一次性消费。
	for ticket := range seen {
		if !hub.consumeTicket(ticket) {
			t.Fatalf("issued ticket %q could not be consumed", ticket)
		}
		if hub.consumeTicket(ticket) {
			t.Fatalf("ticket %q must not be consumable twice", ticket)
		}
	}
}

func TestRandomTicketProducesDistinctHexStrings(t *testing.T) {
	seen := make(map[string]struct{}, 16)
	for i := 0; i < 16; i++ {
		ticket := randomTicket()
		if len(ticket) != 64 {
			t.Fatalf("ticket length = %d, want 64", len(ticket))
		}
		if strings.Trim(ticket, "0123456789abcdef") != "" {
			t.Fatalf("ticket %q is not lowercase hex", ticket)
		}
		if _, dup := seen[ticket]; dup {
			t.Fatalf("randomTicket produced a duplicate: %q", ticket)
		}
		seen[ticket] = struct{}{}
	}
}

func TestRealtimeHubHasSubscribersWithoutClients(t *testing.T) {
	hub := NewRealtimeHub(nil, nil, nil, nil, nil)
	for _, topic := range []string{"dashboard", "access_logs", "security_events"} {
		if hub.hasSubscribers(topic) {
			t.Fatalf("topic %q reports subscribers on a fresh hub", topic)
		}
	}
}

func TestGetPolicyAndCreatePolicyErrorPaths(t *testing.T) {
	repo := newPolicyRepoForTest(t)

	badID := invokePolicyHandler(t, GetPolicy(repo), "GET", "/api/v1/policies/nan", param.Params{{Key: "id", Value: "nan"}}, nil)
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	missing := invokePolicyHandler(t, GetPolicy(repo), "GET", "/api/v1/policies/9090", param.Params{{Key: "id", Value: "9090"}}, nil)
	if missing.Response.StatusCode() != 404 {
		t.Fatalf("missing policy status = %d, want 404", missing.Response.StatusCode())
	}

	malformed := invokePolicyHandler(t, CreatePolicy(repo, func() error { return nil }), "POST", "/api/v1/policies", nil, []byte(`{"name":`))
	if malformed.Response.StatusCode() != 400 {
		t.Fatalf("malformed body status = %d, want 400", malformed.Response.StatusCode())
	}

	reloadFailure := invokePolicyHandler(t, CreatePolicy(repo, func() error { return errors.New("reload boom") }),
		"POST", "/api/v1/policies", nil, []byte(`{"name":"reload-fail"}`))
	if reloadFailure.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", reloadFailure.Response.StatusCode())
	}
	if !bytes.Contains(reloadFailure.Response.Body(), []byte("reload failed")) {
		t.Fatalf("reload failure body = %s, want it to mention the failure", bytes.TrimSpace(reloadFailure.Response.Body()))
	}
}

func TestUpdatePolicyErrorPaths(t *testing.T) {
	repo := newPolicyRepoForTest(t)
	policy := &store.Policy{Name: "existing"}
	if err := repo.Create(policy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	idParams := param.Params{{Key: "id", Value: "1"}}

	badID := invokePolicyHandler(t, UpdatePolicy(repo, func() error { return nil }),
		"POST", "/api/v1/policies/nan/update", param.Params{{Key: "id", Value: "nan"}}, []byte(`{"name":"x"}`))
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}

	missing := invokePolicyHandler(t, UpdatePolicy(repo, func() error { return nil }),
		"POST", "/api/v1/policies/9090/update", param.Params{{Key: "id", Value: "9090"}}, []byte(`{"name":"x"}`))
	if missing.Response.StatusCode() != 404 {
		t.Fatalf("missing policy status = %d, want 404", missing.Response.StatusCode())
	}

	malformed := invokePolicyHandler(t, UpdatePolicy(repo, func() error { return nil }),
		"POST", "/api/v1/policies/1/update", idParams, []byte(`{"name":`))
	if malformed.Response.StatusCode() != 400 {
		t.Fatalf("malformed body status = %d, want 400", malformed.Response.StatusCode())
	}

	reloadFailure := invokePolicyHandler(t, UpdatePolicy(repo, func() error { return errors.New("reload boom") }),
		"POST", "/api/v1/policies/1/update", idParams, []byte(`{"name":"renamed"}`))
	if reloadFailure.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", reloadFailure.Response.StatusCode())
	}
	got, err := repo.Get(policy.ID)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if got.Name != "renamed" {
		t.Fatalf("name = %q, want the update to persist before the reload failure", got.Name)
	}
}
