package rules

import (
	"sort"
	"strings"
	"unicode"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
)

// Compiled 是运行时可直接使用的规则，已预构建匹配器。
type Compiled struct {
	ID          uint
	Phase       string
	Action      action.Type
	Priority    int
	Kind        string
	Arg         string
	StatusCode  int    // 自定义 HTTP 状态码（0 表示用默认值）
	RedirectTo  string // redirect 动作的目标 URL
	CaptchaType string // 规则级验证码类型；为空则继承全局防护配置
	// CaptchaMinutes 是规则级验证码通过有效期（分钟）；0 继承全局 captcha_pass_ttl。
	CaptchaMinutes int
	matcher        Matcher
	runtimeAction  action.Type
	ruleIDStr      string
	matchDesc      string
}

// Match 委托给预构建的匹配器。
func (c *Compiled) Match(ctx MatchCtx) bool {
	if c.matcher != nil {
		return c.matcher.Match(ctx)
	}
	return false
}

// Compile 把持久化的 Rule 模型转换为排序后、匹配器就绪的 Compiled 切片。
func Compile(rs []store.Rule) []Compiled {
	var out []Compiled
	for _, r := range rs {
		if !r.Enabled {
			continue
		}
		kind, arg := ParsePattern(r.Pattern)
		if kind == "" {
			continue
		}
		matcher := Matcher(&neverMatcher{})
		if len(validateParsedPattern(kind, arg)) == 0 {
			matcher = buildMatcher(kind, arg)
		}
		out = append(out, Compiled{
			ID:             r.ID,
			Phase:          string(r.Phase),
			Action:         action.Type(r.Action),
			Priority:       r.Priority,
			Kind:           kind,
			Arg:            arg,
			StatusCode:     r.StatusCode,
			RedirectTo:     r.RedirectTo,
			CaptchaType:    r.CaptchaType,
			CaptchaMinutes: r.CaptchaMinutes,
			matcher:        matcher,
			runtimeAction:  normalizeConfiguredAction(string(r.Action)),
			ruleIDStr:      "rule:" + string(r.Phase) + ":" + kind,
			matchDesc:      compiledMatchDesc(kind, arg),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func compiledMatchDesc(kind string, arg string) string {
	if kind == "compound" && len(arg) > 60 {
		return "compound:{...}"
	}
	return kind + ":" + arg
}

func ensureCompiledMetadata(rules []Compiled) []Compiled {
	if len(rules) == 0 {
		return nil
	}
	needsCopy := false
	for i := range rules {
		if rules[i].ruleIDStr == "" || rules[i].matchDesc == "" || rules[i].runtimeAction == "" {
			needsCopy = true
			break
		}
	}
	if !needsCopy {
		return rules
	}

	out := append([]Compiled(nil), rules...)
	for i := range out {
		if out[i].ruleIDStr == "" {
			out[i].ruleIDStr = "rule:" + out[i].Phase + ":" + out[i].Kind
		}
		if out[i].matchDesc == "" {
			out[i].matchDesc = compiledMatchDesc(out[i].Kind, out[i].Arg)
		}
		if out[i].runtimeAction == "" {
			out[i].runtimeAction = normalizeConfiguredAction(string(out[i].Action))
		}
	}
	return out
}

// knownPrefixes 把已知的规则 kind 前缀（不含尾部冒号）映射到自身。
// 在 init 时依据这份规范列表构建一次。
var knownPrefixes = func() map[string]struct{} {
	kinds := []string{
		"allow_ip", "block_ip", "geo_block",
		"block_path", "block_path_regex", "block_path_exact",
		"block_query_contains", "block_query_regex",
		"block_header", "block_header_exact", "block_header_prefix", "block_header_regex",
		"block_method", "block_content_type",
		"full_url_not_exact", "path_not_exact", "host_not_exact", "block_header_not_exact", "query_param_not_exact", "body_not_exact",
		"block_user_agent", "block_user_agent_regex",
		"header_regex", "body_contains", "body_regex", "block_body_contains", "block_body_regex", "block_body_json_path", "query_param", "query_param_regex",
		"path_contains", "path_not_contains",
		"path_wildcard", "full_url_wildcard", "host_wildcard", "body_wildcard", "header_wildcard",
		"host", "host_full", "host_regex", "host_contains", "host_not_contains",
		"full_url_contains", "full_url_regex",
		"cookie_contains", "referer_contains",
		"tls_ja3", "tls_ja3_hash", "tls_ja4", "tls_version", "tls_sni", "tls_alpn", "tls_cipher_suite", "tls_cipher_suites", "header_order_contains", "header_order_regex",
		"block_multipart",
	}
	m := make(map[string]struct{}, len(kinds))
	for _, k := range kinds {
		m[k] = struct{}{}
	}
	return m
}()

// ParsePattern 从 "block_ip:1.2.3.0/24" 这类 DSL 串中提取 kind 与 arg。
// 简单模式与 JSON 复合条件都支持。
func ParsePattern(p string) (kind, arg string) {
	// 前导空白属于表达式外围的排版。对通配符匹配器而言，首个冒号之后的
	// 空白是模式的一部分，不得丢弃。
	trimmed := strings.TrimLeftFunc(p, unicode.IsSpace)

	// JSON 复合条件：{"op":"and","children":[...]}
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return "compound", strings.TrimSpace(trimmed)
	}

	// 找到第一个冒号，判断前缀是否为已知 kind。
	idx := strings.IndexByte(trimmed, ':')
	if idx <= 0 {
		return "", ""
	}
	candidate := trimmed[:idx]
	if _, ok := knownPrefixes[candidate]; ok {
		arg := trimmed[idx+1:]
		if strings.HasSuffix(candidate, "_wildcard") {
			return candidate, arg
		}
		return candidate, strings.TrimSpace(arg)
	}
	return "", ""
}
