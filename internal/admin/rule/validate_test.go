package rule

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/store"
)

func TestGetRuleTemplatesIncludesTLSRuleTemplates(t *testing.T) {
	ctx := app.NewContext(0)
	GetRuleTemplates()(context.Background(), ctx)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status code %d", ctx.Response.StatusCode())
	}

	var resp struct {
		Templates []RuleTemplate `json:"templates"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode templates response: %v", err)
	}

	patterns := make(map[string]bool, len(resp.Templates))
	for _, template := range resp.Templates {
		patterns[template.Pattern] = true
		if template.Phase == "" {
			t.Fatalf("template %q phase is empty", template.Name)
		}
		if template.Action == "" {
			t.Fatalf("template %q action is empty", template.Name)
		}
		item := store.Rule{
			Phase:   store.RulePhase(template.Phase),
			Pattern: template.Pattern,
			Action:  store.RuleAction(template.Action),
		}
		if got := normalizePersistedRuleConfig(&item); got != "" {
			t.Fatalf("template %q cannot be persisted: %q", template.Name, got)
		}
	}

	wantTemplateDefaults := map[string]struct {
		phase  string
		action string
	}{
		"allow_ip:10.0.0.0/8": {
			phase:  string(store.PhaseACL),
			action: string(store.ActionAllow),
		},
		"tls_ja3_hash:27a5061c22108817120d1d3870cba0e0": {
			phase:  string(store.PhaseCustom),
			action: string(store.ActionIntercept),
		},
	}
	for _, template := range resp.Templates {
		want, ok := wantTemplateDefaults[template.Pattern]
		if !ok {
			continue
		}
		if template.Phase != want.phase || template.Action != want.action {
			t.Fatalf("template %q = phase/action %q/%q, want %q/%q", template.Pattern, template.Phase, template.Action, want.phase, want.action)
		}
	}

	for _, pattern := range []string{
		"tls_ja3:771,4865-4866-4867,0-11-10-35,29-23-24,0",
		"tls_version:TLS13",
		"tls_sni:login.example.com",
		"tls_alpn:h2",
		"tls_cipher_suites:TLS_AES_128_GCM_SHA256",
	} {
		if !patterns[pattern] {
			t.Fatalf("missing TLS rule template %q in %#v", pattern, resp.Templates)
		}
	}
}

func invokeValidateRuleHandler(t *testing.T, payload []byte) *app.RequestContext {
	t.Helper()

	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/rules/validate")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ValidateRule()(context.Background(), ctx)
	return ctx
}

func TestValidateRuleAcceptsTLSPatternAliases(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		wantKind    string
		wantValid   bool
		wantArgSame bool
	}{
		{
			name:        "tls version short alias",
			pattern:     "tls_version:1.3",
			wantKind:    "tls_version",
			wantValid:   true,
			wantArgSame: true,
		},
		{
			name:        "tls version wire hex",
			pattern:     "tls_version:0x0304",
			wantKind:    "tls_version",
			wantValid:   true,
			wantArgSame: true,
		},
		{
			name:        "tls cipher suite numeric id",
			pattern:     "tls_cipher_suites:4865",
			wantKind:    "tls_cipher_suites",
			wantValid:   true,
			wantArgSame: true,
		},
		{
			name:        "tls cipher suite singular alias",
			pattern:     "tls_cipher_suite:TLS_AES_128_GCM_SHA256",
			wantKind:    "tls_cipher_suite",
			wantValid:   true,
			wantArgSame: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := invokeValidateRuleHandler(t, []byte(`{"pattern":"`+tt.pattern+`"}`))
			if ctx.Response.StatusCode() != 200 {
				t.Fatalf("unexpected status code %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
			}

			var resp ValidateRuleResponse
			if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
				t.Fatalf("decode validate response: %v", err)
			}
			if resp.Valid != tt.wantValid {
				t.Fatalf("pattern %q valid = %v, want %v, resp=%#v", tt.pattern, resp.Valid, tt.wantValid, resp)
			}
			if resp.Kind != tt.wantKind {
				t.Fatalf("pattern %q kind = %q, want %q", tt.pattern, resp.Kind, tt.wantKind)
			}
			if tt.wantArgSame && resp.Arg != tt.pattern[len(resp.Kind)+1:] {
				t.Fatalf("pattern %q arg = %q, want original arg %q", tt.pattern, resp.Arg, tt.pattern[len(resp.Kind)+1:])
			}
		})
	}
}

func TestValidateRuleRejectsInvalidTLSPatterns(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		wantError string
	}{
		{
			name:      "invalid tls version",
			pattern:   "tls_version:TLS 1.9",
			wantError: "tls_version requires a supported TLS version token",
		},
		{
			name:      "unsupported ssl3 tls version",
			pattern:   "tls_version:SSL3",
			wantError: "tls_version requires a supported TLS version token",
		},
		{
			name:      "invalid compound tls version",
			pattern:   `{"op":"and","children":[{"kind":"block_path","arg":"/admin"},{"kind":"tls_version","arg":"TLS 1.9"}]}`,
			wantError: "tls_version requires a supported TLS version token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := invokeValidateRuleHandler(t, []byte(`{"pattern":`+marshalJSONString(t, tt.pattern)+`}`))
			if ctx.Response.StatusCode() != 200 {
				t.Fatalf("unexpected status code %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
			}

			var resp ValidateRuleResponse
			if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
				t.Fatalf("decode validate response: %v", err)
			}
			if resp.Valid {
				t.Fatalf("pattern %q unexpectedly valid: %#v", tt.pattern, resp)
			}
			if len(resp.Errors) != 1 || resp.Errors[0] != tt.wantError {
				t.Fatalf("pattern %q errors = %#v, want %q", tt.pattern, resp.Errors, tt.wantError)
			}
		})
	}
}

func marshalJSONString(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json string: %v", err)
	}
	return string(data)
}
