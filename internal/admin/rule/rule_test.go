package rule

import (
	"testing"

	"My-OpenWaf/internal/store"
)

func TestValidatePersistedRuleAction(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "intercept", in: "intercept", want: "intercept", ok: true},
		{name: "legacy block", in: "block", want: "intercept", ok: true},
		{name: "legacy log only", in: "log_only", want: "observe", ok: true},
		{name: "reject invalid", in: "destroy", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := validatePersistedRuleAction(store.RuleAction(tt.in))
			if ok != tt.ok || string(got) != tt.want {
				t.Fatalf("validatePersistedRuleAction(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestNormalizePersistedRuleConfigRequiresRedirectTarget(t *testing.T) {
	item := store.Rule{Action: store.ActionRedirect}
	if got := normalizePersistedRuleConfig(&item); got != "redirect_to required" {
		t.Fatalf("normalizePersistedRuleConfig() = %q, want redirect_to required", got)
	}

	item.RedirectTo = "/blocked"
	if got := normalizePersistedRuleConfig(&item); got != "" {
		t.Fatalf("normalizePersistedRuleConfig() = %q, want empty error", got)
	}
}
