package shared

import (
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/store"
)

func TestProtectionConfigUnmarshalWithCCRulesArray(t *testing.T) {
	raw := map[string]json.RawMessage{
		"builtin_owasp_enabled":    json.RawMessage(`true`),
		"request_ratelimit_action": json.RawMessage(`"intercept"`),
		"cc_rules":                 json.RawMessage(`[]`),
	}
	preserved := PeelJSONStringBlobs(raw, ProtectionJSONBlobKeys())
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

func TestBindSiteFromRequestBody_JSONArraysBecomeStrings(t *testing.T) {
	body := []byte(`{
		"host": "a.example",
		"bind": ":80",
		"upstream_urls": ["http://127.0.0.1:9000"],
		"cache_rules": [{"type":"prefix","value":"/static","ttl":60}],
		"custom_error_pages": {"502": {"html": "<p>x</p>"}}
	}`)
	var s store.Site
	if err := BindSiteFromRequestBody(body, &s); err != nil {
		t.Fatal(err)
	}
	if s.Host != "a.example" {
		t.Fatalf("host: %q", s.Host)
	}
	if want := `["http://127.0.0.1:9000"]`; s.UpstreamURLs != want {
		t.Fatalf("upstream_urls = %q want %q", s.UpstreamURLs, want)
	}
	var rules []map[string]any
	if err := json.Unmarshal([]byte(s.CacheRules), &rules); err != nil {
		t.Fatalf("cache_rules json: %v", err)
	}
	if len(rules) != 1 || rules[0]["type"] != "prefix" {
		t.Fatalf("cache_rules: %#v", rules)
	}
}

func TestBindSiteFromRequestBodyPreservesMissingNullableOverrides(t *testing.T) {
	disabled := false
	existing := store.Site{
		Host:                 "old.example",
		BotProtectionEnabled: &disabled,
		OWASPEnabled:         &disabled,
		CacheRules:           `[{"type":"suffix","value":".js","ttl":60}]`,
	}

	body := []byte(`{"host":"new.example"}`)
	if err := BindSiteFromRequestBody(body, &existing); err != nil {
		t.Fatal(err)
	}
	if existing.Host != "new.example" {
		t.Fatalf("host = %q", existing.Host)
	}
	if existing.BotProtectionEnabled == nil || *existing.BotProtectionEnabled {
		t.Fatalf("bot override should be preserved as false, got %#v", existing.BotProtectionEnabled)
	}
	if existing.OWASPEnabled == nil || *existing.OWASPEnabled {
		t.Fatalf("owasp override should be preserved as false, got %#v", existing.OWASPEnabled)
	}
	if existing.CacheRules != `[{"type":"suffix","value":".js","ttl":60}]` {
		t.Fatalf("cache rules changed: %s", existing.CacheRules)
	}
}
func TestBindSiteFromRequestBodyPreservesMissingJSONBlobFields(t *testing.T) {
	existing := store.Site{
		Host:             "old.example",
		UpstreamURLs:     `["http://127.0.0.1:9000"]`,
		CacheRules:       `[{"type":"prefix","value":"/assets","ttl":120}]`,
		CustomErrorPages: `{"502":{"html":"<p>bad gateway</p>"}}`,
		CipherSuites:     `["TLS_AES_128_GCM_SHA256"]`,
	}

	body := []byte(`{"host":"new.example","bind":":8080"}`)
	if err := BindSiteFromRequestBody(body, &existing); err != nil {
		t.Fatal(err)
	}
	if existing.Host != "new.example" || existing.Bind != ":8080" {
		t.Fatalf("basic fields not updated: %#v", existing)
	}
	if existing.UpstreamURLs != `["http://127.0.0.1:9000"]` {
		t.Fatalf("upstream urls changed: %s", existing.UpstreamURLs)
	}
	if existing.CacheRules != `[{"type":"prefix","value":"/assets","ttl":120}]` {
		t.Fatalf("cache rules changed: %s", existing.CacheRules)
	}
	if existing.CustomErrorPages != `{"502":{"html":"<p>bad gateway</p>"}}` {
		t.Fatalf("custom error pages changed: %s", existing.CustomErrorPages)
	}
	if existing.CipherSuites != `["TLS_AES_128_GCM_SHA256"]` {
		t.Fatalf("cipher suites changed: %s", existing.CipherSuites)
	}
}
