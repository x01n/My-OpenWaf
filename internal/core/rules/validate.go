package rules

import (
	"encoding/json"
	"net"
	"strings"

	"My-OpenWaf/internal/tlsmeta"
)

type compoundPattern struct {
	Op              string            `json:"op"`
	Kind            string            `json:"kind"`
	Arg             string            `json:"arg"`
	Children        []compoundPattern `json:"children"`
	If              *compoundPattern  `json:"if"`
	Then            *compoundPattern  `json:"then"`
	Else            *compoundPattern  `json:"else"`
	Window          int64             `json:"window"`
	Threshold       int64             `json:"threshold"`
	Duration        int64             `json:"duration"`
	DurationUnit    string            `json:"duration_unit"`
	DurationSeconds int64             `json:"duration_seconds"`
}

// ValidatePattern performs syntax and semantic validation for a persisted rule
// pattern. It accepts both simple DSL and JSON compound conditions.
func ValidatePattern(pattern string) (kind, arg string, errs []string) {
	kind, arg = ParsePattern(pattern)
	if kind == "" {
		return "", "", []string{"规则表达式必须以合法的匹配器前缀开头，或者使用合法的复合条件 JSON"}
	}
	return kind, arg, validateParsedPattern(kind, arg)
}

func validateParsedPattern(kind, arg string) []string {
	if kind == "compound" {
		return validateCompoundPattern(arg)
	}
	if err := validateSimplePattern(kind, arg); err != "" {
		return []string{err}
	}
	return nil
}

func validateCompoundPattern(raw string) []string {
	var cond compoundPattern
	if err := json.Unmarshal([]byte(raw), &cond); err != nil {
		return []string{"复合条件 JSON 格式无效"}
	}
	return validateCompoundNode(cond)
}

func validateCompoundNode(cond compoundPattern) []string {
	op := strings.ToLower(strings.TrimSpace(cond.Op))
	switch op {
	case "and", "or":
		if len(cond.Children) == 0 {
			return []string{"复合条件至少需要一个子条件"}
		}
		return validateCompoundChildren(cond.Children)
	case "not":
		if len(cond.Children) != 1 {
			return []string{"非条件必须且只能包含一个子条件"}
		}
		return validateCompoundChildren(cond.Children)
	case "if", "if_else", "ifelse":
		if cond.If == nil || cond.Then == nil {
			return []string{"条件必须同时提供 if 和 then 分支"}
		}
		errs := append(validateCompoundNode(*cond.If), validateCompoundNode(*cond.Then)...)
		if cond.Else != nil {
			errs = append(errs, validateCompoundNode(*cond.Else)...)
		}
		return errs
	case "cc_rate":
		if len(cond.Children) != 1 {
			return []string{"cc_rate 条件必须且只能包含一个子条件"}
		}
		if cond.Window <= 0 {
			return []string{"cc_rate window 必须大于 0"}
		}
		if cond.Threshold <= 0 {
			return []string{"cc_rate threshold 必须大于 0"}
		}
		if !validCompoundDurationUnit(cond.DurationUnit) {
			return []string{"cc_rate duration_unit 必须为 seconds 或 minutes"}
		}
		if cond.Duration < 0 || cond.DurationSeconds < 0 {
			return []string{"cc_rate duration 和 duration_seconds 不能小于 0"}
		}
		return validateCompoundChildren(cond.Children)
	case "":
		if cond.Kind == "" {
			return []string{"复合条件叶子节点必须定义 kind"}
		}
		if err := validateSimplePattern(cond.Kind, cond.Arg); err != "" {
			return []string{err}
		}
		return nil
	default:
		return []string{"复合条件使用了不支持的操作符"}
	}
}

func validateCompoundChildren(children []compoundPattern) []string {
	errs := make([]string, 0)
	for _, child := range children {
		errs = append(errs, validateCompoundNode(child)...)
	}
	return errs
}

func validCompoundDurationUnit(unit string) bool {
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "", "seconds", "minutes":
		return true
	default:
		return false
	}
}

func validateSimplePattern(kind, arg string) string {
	if _, ok := knownPrefixes[kind]; !ok {
		return "复合条件叶子节点使用了不支持的 kind"
	}

	switch kind {
	case "block_path":
		if strings.TrimSpace(arg) == "" {
			return "block_path 需要非空路径前缀"
		}
	case "block_query_contains", "block_path_exact", "block_method", "block_content_type", "block_user_agent",
		"header_order_contains", "body_contains", "block_body_contains", "path_contains", "path_not_contains",
		"host", "host_full", "full_url_contains", "host_contains", "host_not_contains", "full_url_not_exact", "path_not_exact", "host_not_exact", "cookie_contains", "referer_contains",
		"tls_ja3", "tls_ja3_hash", "tls_ja4", "tls_sni", "tls_alpn", "geo_block":
		if strings.TrimSpace(arg) == "" {
			return "规则表达式不能为空"
		}
	case "allow_ip", "block_ip":
		if _, _, err := net.ParseCIDR(arg); err == nil {
			return ""
		}
		if net.ParseIP(strings.TrimSpace(arg)) == nil {
			return "IP/CIDR 匹配器要求合法的 IP 地址或 CIDR"
		}
	case "block_path_regex", "block_query_regex", "block_user_agent_regex", "header_order_regex", "full_url_regex", "host_regex":
		if strings.TrimSpace(arg) == "" {
			return "规则表达式不能为空"
		}
		if _, err := cachedCompile(arg); err != nil {
			return "规则表达式使用了非法的正则表达式"
		}
	case "block_header", "block_header_exact", "block_header_not_exact":
		name, value := splitHeaderArg(arg)
		if strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
			return "Header 匹配器需要 name:value 格式"
		}
	case "block_header_prefix":
		name, prefix := splitHeaderArg(arg)
		if strings.TrimSpace(name) == "" || strings.TrimSpace(prefix) == "" {
			return "block_header_prefix 需要 name:prefix 格式"
		}
	case "block_header_regex", "header_regex":
		name, pattern := splitHeaderArg(arg)
		if strings.TrimSpace(name) == "" || strings.TrimSpace(pattern) == "" {
			return "Header 正则需要 name:pattern 格式"
		}
		if _, err := cachedCompile(pattern); err != nil {
			return "规则表达式使用了非法的正则表达式"
		}
	case "query_param", "query_param_not_exact":
		param, value := splitHeaderArg(arg)
		if strings.TrimSpace(param) == "" || strings.TrimSpace(value) == "" {
			return "query_param 需要非空的 param:value 格式"
		}
	case "query_param_regex":
		param, pattern, ok := strings.Cut(arg, ":")
		if !ok || strings.TrimSpace(param) == "" || strings.TrimSpace(pattern) == "" {
			return "query_param_regex 需要非空的 param:regex 格式"
		}
		if _, err := cachedCompile(pattern); err != nil {
			return "规则表达式使用了非法的正则表达式"
		}
	case "body_not_exact":
		if strings.TrimSpace(arg) == "" {
			return "规则表达式不能为空"
		}
	case "block_body_regex", "body_regex":
		if strings.TrimSpace(arg) == "" {
			return "规则表达式不能为空"
		}
		if _, err := cachedCompile(arg); err != nil {
			return "规则表达式使用了非法的正则表达式"
		}
	case "block_body_json_path":
		jsonPath, pattern := splitHeaderArg(arg)
		if strings.TrimSpace(jsonPath) == "" {
			return "block_body_json_path 需要非空 JSON 路径"
		}
		if pattern != "" {
			if _, err := cachedCompile(pattern); err != nil {
				return "规则表达式使用了非法的正则表达式"
			}
		}
	case "block_multipart":
		if arg != "" {
			if _, err := cachedCompile(arg); err != nil {
				return "规则表达式使用了非法的正则表达式"
			}
		}
	case "path_wildcard", "full_url_wildcard", "host_wildcard", "body_wildcard":
		// 空模式只会匹配空目标串，等同于永不命中，必须在保存期拒绝而非留到运行期。
		if strings.TrimSpace(arg) == "" {
			return "通配符匹配器需要非空的通配符模式"
		}
		source, err := globToRegexSource(arg, false)
		if err != nil {
			return "规则表达式使用了非法的通配符模式"
		}
		if _, err := cachedCompile(source); err != nil {
			return "规则表达式使用了非法的通配符模式"
		}
	case "header_wildcard":
		name, pattern := splitHeaderArg(arg)
		if strings.TrimSpace(name) == "" {
			return "header_wildcard 需要 name:pattern 格式"
		}
		if pattern == "" {
			return "header_wildcard 需要 name:pattern 格式"
		}
		source, err := globToRegexSource(pattern, false)
		if err != nil {
			return "规则表达式使用了非法的通配符模式"
		}
		if _, err := cachedCompile(source); err != nil {
			return "规则表达式使用了非法的通配符模式"
		}
	case "tls_version":
		if tlsmeta.NormalizeRuntimeVersionToken(arg) == "" {
			return "tls_version 需要合法的 TLS 版本标识"
		}
	case "tls_cipher_suite", "tls_cipher_suites":
		values := make(map[string]struct{})
		for _, token := range strings.Split(arg, ",") {
			normalized := normalizeTLSCipherSuiteToken(token)
			if normalized == "" {
				continue
			}
			values[normalized] = struct{}{}
		}
		if len(values) == 0 {
			return "tls_cipher_suites 至少需要一个合法的密码套件标识"
		}
	}
	return ""
}
