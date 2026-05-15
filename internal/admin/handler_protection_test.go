package admin

import (
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/store"
)

func TestProtectionConfigUnmarshalWithCCRulesArray(t *testing.T) {
	// Regression: dashboard sends cc_rules as [] while ProtectionConfig.CCRules is a string.
	raw := map[string]json.RawMessage{
		"builtin_owasp_enabled":    json.RawMessage(`true`),
		"request_ratelimit_action": json.RawMessage(`"intercept"`),
		"cc_rules":                 json.RawMessage(`[]`),
	}
	preserved := peelJSONStringBlobs(raw, protectionJSONBlobKeys())
	plainBytes, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.DefaultProtectionConfig()
	if err := json.Unmarshal(plainBytes, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s, ok := preserved["cc_rules"]; ok {
		cfg.CCRules = s
	}
	if cfg.CCRules != "[]" {
		t.Fatalf("CCRules = %q want %q", cfg.CCRules, "[]")
	}
}
