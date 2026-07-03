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

func TestValidateSiteUpstreamURLsAcceptsSupportedSchemes(t *testing.T) {
	input := `["http://127.0.0.1:9000","https://origin.example/base","h2c://127.0.0.1:9001","h3://127.0.0.1:9443"]`
	if err := ValidateSiteUpstreamURLs(input); err != nil {
		t.Fatalf("ValidateSiteUpstreamURLs() returned error: %v", err)
	}
}

func TestValidateSiteUpstreamURLsAcceptsCommaSeparatedFormat(t *testing.T) {
	input := "http://127.0.0.1:9000, h2c://127.0.0.1:9001, h3://127.0.0.1:9443"
	if err := ValidateSiteUpstreamURLs(input); err != nil {
		t.Fatalf("ValidateSiteUpstreamURLs() returned error: %v", err)
	}
}

func TestValidateSiteUpstreamURLsRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: "upstream_urls is required"},
		{name: "invalid json array", input: `["http://127.0.0.1:9000", 1]`, want: "upstream_urls must be a string array or comma-separated string"},
		{name: "missing scheme", input: "127.0.0.1:9000", want: "upstream_urls contains invalid URL"},
		{name: "unsupported scheme", input: "ftp://127.0.0.1:21", want: "upstream_urls supports only http, https, h2c, h3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSiteUpstreamURLs(tt.input)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("ValidateSiteUpstreamURLs() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateSiteUpstreamHostAcceptsHostAndTemplate(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "host", input: "backend.example.com"},
		{name: "host with port", input: "backend.example.com:8443"},
		{name: "template", input: "{{.Host}}.internal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateSiteUpstreamHost(tt.input); err != nil {
				t.Fatalf("ValidateSiteUpstreamHost(%q) returned error: %v", tt.input, err)
			}
		})
	}
}

func TestValidateSiteUpstreamHostRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "invalid host", input: "bad host", want: "upstream_host contains invalid host"},
		{name: "invalid template", input: "{{.Missing", want: "upstream_host contains invalid template"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSiteUpstreamHost(tt.input)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("ValidateSiteUpstreamHost(%q) error = %v, want %q", tt.input, err, tt.want)
			}
		})
	}
}
