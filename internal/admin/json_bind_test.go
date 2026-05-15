package admin

import (
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/store"
)

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
