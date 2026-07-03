package rule

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func TestValidatePersistedRuleAction(t *testing.T) {
	tests := []struct {
		name  string
		phase store.RulePhase
		in    string
		want  string
		ok    bool
	}{
		{name: "intercept", phase: store.PhaseCustom, in: "intercept", want: "intercept", ok: true},
		{name: "legacy block", phase: store.PhaseCustom, in: "block", want: "intercept", ok: true},
		{name: "legacy log only", phase: store.PhaseCustom, in: "log_only", want: "observe", ok: true},
		{name: "acl allow", phase: store.PhaseACL, in: "allow", want: "allow", ok: true},
		{name: "signature allow rejected", phase: store.PhaseSignature, in: "allow", ok: false},
		{name: "custom allow rejected", phase: store.PhaseCustom, in: "allow", ok: false},
		{name: "tag rejected", phase: store.PhaseACL, in: "tag", ok: false},
		{name: "reject invalid", phase: store.PhaseCustom, in: "destroy", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := validatePersistedRuleAction(tt.phase, store.RuleAction(tt.in))
			if ok != tt.ok || string(got) != tt.want {
				t.Fatalf("validatePersistedRuleAction(%q, %q) = (%q, %v), want (%q, %v)", tt.phase, tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestNormalizePersistedRuleConfigRejectsNonACLAllow(t *testing.T) {
	for _, phase := range []store.RulePhase{store.PhaseSignature, store.PhaseCustom} {
		item := store.Rule{
			Phase:   phase,
			Action:  store.ActionAllow,
			Pattern: "block_path:/ok",
		}
		if got := normalizePersistedRuleConfig(&item); got != "invalid action" {
			t.Fatalf("normalizePersistedRuleConfig(%q allow) = %q, want invalid action", phase, got)
		}
	}
}

func TestNormalizePersistedRuleConfigRequiresRedirectTarget(t *testing.T) {
	item := store.Rule{Phase: store.PhaseACL, Action: store.ActionRedirect, Pattern: "block_path:/blocked"}
	if got := normalizePersistedRuleConfig(&item); got != "redirect_to required" {
		t.Fatalf("normalizePersistedRuleConfig() = %q, want redirect_to required", got)
	}

	item.RedirectTo = "/blocked"
	if got := normalizePersistedRuleConfig(&item); got != "" {
		t.Fatalf("normalizePersistedRuleConfig() = %q, want empty error", got)
	}
}

func TestNormalizePersistedRuleConfigRejectsUnsupportedPhase(t *testing.T) {
	for _, phase := range []store.RulePhase{store.PhaseRateLimit, store.PhaseOWASP} {
		item := store.Rule{
			Phase:  phase,
			Action: store.ActionIntercept,
		}
		if got := normalizePersistedRuleConfig(&item); got != "unsupported phase: only acl, signature, custom are executable custom rule phases" {
			t.Fatalf("normalizePersistedRuleConfig(%q) = %q", phase, got)
		}
	}
}

func TestNormalizePersistedRuleConfigAcceptsExecutableRulePhases(t *testing.T) {
	for _, phase := range []store.RulePhase{store.PhaseACL, store.PhaseSignature, store.PhaseCustom} {
		item := store.Rule{
			Phase:   phase,
			Action:  store.ActionObserve,
			Pattern: "block_path:/ok",
		}
		if got := normalizePersistedRuleConfig(&item); got != "" {
			t.Fatalf("normalizePersistedRuleConfig(%q) = %q", phase, got)
		}
	}
}

func TestNormalizePersistedRuleConfigRejectsInvalidTLSPattern(t *testing.T) {
	item := store.Rule{
		Phase:   store.PhaseCustom,
		Action:  store.ActionObserve,
		Pattern: "tls_version:TLS 1.9",
	}
	if got := normalizePersistedRuleConfig(&item); got != "invalid pattern: tls_version requires a supported TLS version token" {
		t.Fatalf("normalizePersistedRuleConfig() = %q", got)
	}
}

func TestNormalizePersistedRuleConfigRejectsUnsupportedSSL3TLSPattern(t *testing.T) {
	item := store.Rule{
		Phase:   store.PhaseCustom,
		Action:  store.ActionObserve,
		Pattern: "tls_version:SSL3",
	}
	if got := normalizePersistedRuleConfig(&item); got != "invalid pattern: tls_version requires a supported TLS version token" {
		t.Fatalf("normalizePersistedRuleConfig() = %q", got)
	}
}

func TestNormalizePersistedRuleConfigRejectsInvalidCompoundTLSPattern(t *testing.T) {
	item := store.Rule{
		Phase:  store.PhaseCustom,
		Action: store.ActionObserve,
		Pattern: `{"op":"and","children":[` +
			`{"kind":"block_path","arg":"/admin"},` +
			`{"kind":"tls_version","arg":"TLS 1.9"}` +
			`]}`,
	}
	if got := normalizePersistedRuleConfig(&item); got != "invalid pattern: tls_version requires a supported TLS version token" {
		t.Fatalf("normalizePersistedRuleConfig() = %q", got)
	}
}

func TestNormalizePersistedRuleConfigAcceptsCompoundTLSAliases(t *testing.T) {
	item := store.Rule{
		Phase:  store.PhaseCustom,
		Action: store.ActionObserve,
		Pattern: `{"op":"and","children":[` +
			`{"kind":"tls_version","arg":"TLS 1.3"},` +
			`{"kind":"tls_cipher_suites","arg":"4865"}` +
			`]}`,
	}
	if got := normalizePersistedRuleConfig(&item); got != "" {
		t.Fatalf("normalizePersistedRuleConfig() = %q", got)
	}
}

func invokeTestRuleHandler(t *testing.T, payload []byte) *app.RequestContext {
	t.Helper()

	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/rules/test")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	TestRule()(context.Background(), ctx)
	return ctx
}

func TestTestRuleMatchesTLSVersionHeader(t *testing.T) {
	ctx := invokeTestRuleHandler(t, []byte(`{
		"pattern":"tls_version:TLS13",
		"method":"GET",
		"path":"/",
		"headers":{"X-OWAF-TLS-Version":"TLS13"}
	}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status code %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Matched bool   `json:"matched"`
		Kind    string `json:"kind"`
		Arg     string `json:"arg"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Matched {
		t.Fatalf("expected tls_version test rule to match, got %#v", resp)
	}
	if resp.Kind != "tls_version" || resp.Arg != "TLS13" {
		t.Fatalf("unexpected tls_version response %#v", resp)
	}
}

func TestTestRuleMatchesTLSCipherSuitesHeader(t *testing.T) {
	ctx := invokeTestRuleHandler(t, []byte(`{
		"pattern":"tls_cipher_suites:TLS_AES_128_GCM_SHA256",
		"method":"GET",
		"path":"/",
		"headers":{"X-OWAF-TLS-Cipher-Suites":"TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384"}
	}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status code %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Matched bool   `json:"matched"`
		Kind    string `json:"kind"`
		Arg     string `json:"arg"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Matched {
		t.Fatalf("expected tls_cipher_suites test rule to match, got %#v", resp)
	}
	if resp.Kind != "tls_cipher_suites" || resp.Arg != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("unexpected tls_cipher_suites response %#v", resp)
	}
}

func newRuleRepoForHandlerTest(t *testing.T) *repository.RuleRepo {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Policy{}, &store.Rule{}); err != nil {
		t.Fatalf("migrate rules: %v", err)
	}
	if err := db.Create(&store.Policy{
		Name:        "handler-policy",
		Description: "handler tests",
	}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	return repository.NewRuleRepo(db)
}

func invokePersistedRuleHandler(
	t *testing.T,
	handler app.HandlerFunc,
	uri string,
	payload []byte,
) *app.RequestContext {
	t.Helper()

	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI(uri)
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

func TestCreateRuleRejectsInvalidTLSPattern(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	handler := CreateRule(repo, func() error { return nil })

	ctx := invokePersistedRuleHandler(t, handler, "/api/v1/rules", []byte(`{
		"name":"invalid tls version create",
		"policy_id":1,
		"phase":"custom",
		"pattern":"tls_version:TLS 1.9",
		"action":"observe",
		"priority":10,
		"enabled":true
	}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status code %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "invalid pattern: tls_version requires a supported TLS version token" {
		t.Fatalf("error = %q", resp.Error)
	}
}

func TestImportRulesRejectsInvalidCompoundTLSPattern(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)
	handler := ImportRules(repo, func() error { return nil })

	ctx := invokePersistedRuleHandler(t, handler, "/api/v1/rules/import", []byte(`{
		"rules":[
			{
				"name":"invalid compound tls version import",
				"policy_id":1,
				"phase":"custom",
				"pattern":"{\"op\":\"and\",\"children\":[{\"kind\":\"block_path\",\"arg\":\"/admin\"},{\"kind\":\"tls_version\",\"arg\":\"TLS 1.9\"}]}",
				"action":"observe",
				"priority":11,
				"enabled":true
			}
		]
	}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status code %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var resp struct {
		Error string `json:"error"`
		Index int    `json:"index"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "invalid pattern: tls_version requires a supported TLS version token" {
		t.Fatalf("error = %q", resp.Error)
	}
	if resp.Index != 0 {
		t.Fatalf("index = %d, want 0", resp.Index)
	}
}
