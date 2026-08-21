package shared

import (
	"encoding/json"
	"errors"
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

// ValidateSkipPathByPhase rejects invalid phase-to-path-list objects before persistence.
func ValidateSkipPathByPhase(raw string) error {
	var pathsByPhase map[string][]string
	if err := json.Unmarshal([]byte(raw), &pathsByPhase); err != nil || pathsByPhase == nil {
		return errors.New("skip_path_by_phase must be a JSON object")
	}
	for phase, paths := range pathsByPhase {
		if !store.IsSkipPathPhaseKey(phase) {
			return errors.New("skip_path_by_phase contains an unsupported phase")
		}
		if len(paths) == 0 {
			return errors.New("skip_path_by_phase paths must be non-empty strings")
		}
		for _, path := range paths {
			if strings.TrimSpace(path) == "" {
				return errors.New("skip_path_by_phase paths must be non-empty strings")
			}
		}
	}
	return nil
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
		"skip_path_by_phase",
	}
}

// SiteJSONBlobKeys returns the list of site config fields that are stored as JSON string blobs.
func SiteJSONBlobKeys() []string {
	return []string{
		"cache_rules",
		"custom_error_pages",
		"upstream_urls",
		"cipher_suites",
		"dynamic_js_paths",
		"cc_rules",
		"client_ip_header_order",
		"skip_path_by_phase",
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
	skipPathRaw, skipPathPresent := raw["skip_path_by_phase"]
	skipPathNull := skipPathPresent && strings.TrimSpace(string(skipPathRaw)) == "null"
	preserved := PeelJSONStringBlobs(raw, SiteJSONBlobKeys())
	if s, ok := preserved["skip_path_by_phase"]; ok && !skipPathNull {
		if err := ValidateSkipPathByPhase(s); err != nil {
			return err
		}
	}
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
	if s, ok := preserved["dynamic_js_paths"]; ok {
		dst.DynamicJSPaths = s
	}
	if s, ok := preserved["cc_rules"]; ok {
		dst.CCRules = s
	}
	if s, ok := preserved["client_ip_header_order"]; ok {
		dst.ClientIPHeaderOrder = s
	}
	if s, ok := preserved["skip_path_by_phase"]; ok {
		if skipPathNull {
			dst.SkipPathByPhase = nil
		} else {
			dst.SkipPathByPhase = &s
		}
	}
	return nil
}
