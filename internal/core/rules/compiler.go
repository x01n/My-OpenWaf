package rules

import (
	"sort"
	"strings"
	"unicode"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
)

// Compiled is a runtime-ready rule with a pre-built matcher.
type Compiled struct {
	ID            uint
	Phase         string
	Action        action.Type
	Priority      int
	Kind          string
	Arg           string
	StatusCode    int    // custom HTTP status code (0 = default)
	RedirectTo    string // URL for redirect action
	CaptchaType   string // Rule-level CAPTCHA type; empty inherits global protection config.
	matcher       Matcher
	runtimeAction action.Type
	ruleIDStr     string
	matchDesc     string
}

// Match delegates to the pre-built matcher.
func (c *Compiled) Match(ctx MatchCtx) bool {
	if c.matcher != nil {
		return c.matcher.Match(ctx)
	}
	return false
}

// Compile converts persisted Rule models into sorted, matcher-ready Compiled slices.
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
			ID:            r.ID,
			Phase:         string(r.Phase),
			Action:        action.Type(r.Action),
			Priority:      r.Priority,
			Kind:          kind,
			Arg:           arg,
			StatusCode:    r.StatusCode,
			RedirectTo:    r.RedirectTo,
			CaptchaType:   r.CaptchaType,
			matcher:       matcher,
			runtimeAction: normalizeConfiguredAction(string(r.Action)),
			ruleIDStr:     "rule:" + string(r.Phase) + ":" + kind,
			matchDesc:     compiledMatchDesc(kind, arg),
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

// knownPrefixes maps known rule-kind prefixes (without trailing colon) to
// themselves. Built once at init from the canonical list.
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

// ParsePattern extracts kind and arg from a DSL string like "block_ip:1.2.3.0/24".
// Supports both simple patterns and JSON compound conditions.
func ParsePattern(p string) (kind, arg string) {
	// Leading whitespace is formatting around the expression. For wildcard
	// matchers, whitespace after the first colon is part of the pattern and
	// must not be discarded.
	trimmed := strings.TrimLeftFunc(p, unicode.IsSpace)

	// JSON compound condition: {"op":"and","children":[...]}
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return "compound", strings.TrimSpace(trimmed)
	}

	// Find the first colon and check if the prefix is a known kind.
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
