package shared

import (
	"encoding/json"
	"strings"

	"My-OpenWaf/internal/store"
)

// StringifyJSONishField normalizes JSON that is stored as a Go string but may be sent as
// an object or array from the dashboard (e.g. cc_rules: []).
func StringifyJSONishField(v json.RawMessage) string {
	s := strings.TrimSpace(string(v))
	if len(s) == 0 || s == "null" {
		return ""
	}
	if s[0] == '[' || s[0] == '{' {
		return s
	}
	if s[0] == '"' {
		var inner string
		if json.Unmarshal([]byte(s), &inner) == nil {
			return inner
		}
	}
	return s
}

// PeelJSONStringBlobs extracts the given keys from a raw JSON map, stringifies them,
// and removes them from the map.
func PeelJSONStringBlobs(raw map[string]json.RawMessage, keys []string) map[string]string {
	out := make(map[string]string)
	for _, key := range keys {
		if v, ok := raw[key]; ok {
			out[key] = StringifyJSONishField(v)
			delete(raw, key)
		}
	}
	return out
}

// ProtectionJSONBlobKeys returns the list of protection config fields that are stored
// as JSON string blobs.
func ProtectionJSONBlobKeys() []string {
	return []string{
		"cc_rules",
		"owasp_modules",
		"chain_steps",
		"escalation_steps",
		"category_sensitivity",
		"owasp_rules_config",
		"cve_rules_config",
	}
}

// SiteJSONBlobKeys returns the list of site config fields that are stored as JSON string blobs.
func SiteJSONBlobKeys() []string {
	return []string{
		"cache_rules",
		"custom_error_pages",
		"upstream_urls",
		"cipher_suites",
	}
}

// BindSiteFromRequestBody parses a site JSON body into dst after normalizing JSON-blob fields.
func BindSiteFromRequestBody(body []byte, dst *store.Site) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return err
	}
	return bindSiteFromRaw(raw, dst)
}

// bindSiteFromRaw unmarshals a site JSON object into dst after lifting JSON-blob fields that
// are stored as strings in store.Site but are often sent as arrays/objects from the UI.
func bindSiteFromRaw(raw map[string]json.RawMessage, dst *store.Site) error {
	preserved := PeelJSONStringBlobs(raw, SiteJSONBlobKeys())
	plain, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(plain, dst); err != nil {
		return err
	}
	if s, ok := preserved["cache_rules"]; ok {
		dst.CacheRules = s
	}
	if s, ok := preserved["custom_error_pages"]; ok {
		dst.CustomErrorPages = s
	}
	if s, ok := preserved["upstream_urls"]; ok {
		dst.UpstreamURLs = s
	}
	if s, ok := preserved["cipher_suites"]; ok {
		dst.CipherSuites = s
	}
	return nil
}
