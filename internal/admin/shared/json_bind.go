package shared

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"My-OpenWaf/internal/store"
)

// StringifyJSONishField 归一化「以 Go 字符串存储、但仪表盘可能以对象或数组下发」的 JSON
// （例如 cc_rules: []）。
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

// PeelJSONStringBlobs 从原始 JSON map 中取出指定 key，把值字符串化，并从 map 中删除这些 key。
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

// ValidateSkipPathByPhase 在持久化之前拒绝非法的「phase -> 路径列表」对象。
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

// ProtectionJSONBlobKeys 返回以 JSON 字符串 blob 形式存储的 protection 配置字段列表。
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

// SiteJSONBlobKeys 返回以 JSON 字符串 blob 形式存储的站点配置字段列表。
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

// BindSiteFromRequestBody 先归一化 JSON blob 字段，再把站点 JSON 请求体解析进 dst。
func BindSiteFromRequestBody(body []byte, dst *store.Site) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return err
	}
	return bindSiteFromRaw(raw, dst)
}

// bindSiteFromRaw 先把「在 store.Site 中以字符串存储、但前端常以数组/对象下发」的
// JSON blob 字段摘出来，再把站点 JSON 对象解析进 dst。
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
	// challenge_action / captcha_type 是独立三态标量字段：JSON null 表示
	// 「取消站点覆盖、回到继承全局」；不传时保留原值（Update 场景）。
	if v, ok := raw["challenge_action"]; ok && strings.TrimSpace(string(v)) == "null" {
		dst.ChallengeAction = nil
	}
	if v, ok := raw["captcha_type"]; ok && strings.TrimSpace(string(v)) == "null" {
		dst.SiteCaptchaType = nil
	}
	// anti_replay_cookie_mode 同为三态覆盖：JSON null 或空串 = 取消覆盖继承全局。
	if v, ok := raw["anti_replay_cookie_mode"]; ok {
		var mode string
		if err := json.Unmarshal(v, &mode); err != nil || strings.TrimSpace(mode) == "" {
			dst.AntiReplayCookieMode = nil
		} else {
			normalized, valid := ValidateAntiReplayCookieMode(mode, true)
			if !valid {
				return fmt.Errorf("invalid anti_replay_cookie_mode")
			}
			if normalized == "" {
				dst.AntiReplayCookieMode = nil
			} else {
				dst.AntiReplayCookieMode = &normalized
			}
		}
	}
	return nil
}
