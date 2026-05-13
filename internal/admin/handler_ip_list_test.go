package admin

import (
	"testing"

	"My-OpenWaf/internal/store"
)

func TestNormalizeIPListAction(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "empty defaults intercept", in: "", want: "intercept", ok: true},
		{name: "intercept", in: "intercept", want: "intercept", ok: true},
		{name: "drop remains canonical", in: "drop", want: "drop", ok: true},
		{name: "legacy block maps drop", in: "block", want: "drop", ok: true},
		{name: "reject challenge", in: "challenge", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := normalizeIPListAction(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("normalizeIPListAction(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

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
