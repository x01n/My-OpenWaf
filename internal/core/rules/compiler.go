package rules

import (
	"sort"
	"strings"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
)

// Compiled is a runtime-ready rule with a pre-built matcher.
type Compiled struct {
	ID         uint
	Phase      string
	Action     action.Type
	Priority   int
	Kind       string
	Arg        string
	StatusCode int    // custom HTTP status code (0 = default)
	RedirectTo string // URL for redirect action
	matcher    Matcher
}

// Match delegates to the pre-built matcher.
func (c *Compiled) Match(ctx MatchCtx) bool {
	return c.matcher.Match(ctx.ClientIP, ctx.Method, ctx.Path, ctx.Query, ctx.Headers, ctx.Body)
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
		out = append(out, Compiled{
			ID:         r.ID,
			Phase:      string(r.Phase),
			Action:     action.Type(r.Action),
			Priority:   r.Priority,
			Kind:       kind,
			Arg:        arg,
			StatusCode: r.StatusCode,
			RedirectTo: r.RedirectTo,
			matcher:    buildMatcher(kind, arg),
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

// ParsePattern extracts kind and arg from a DSL string like "block_ip:1.2.3.0/24".
// Supports both simple patterns and JSON compound conditions.
func ParsePattern(p string) (kind, arg string) {
	p = strings.TrimSpace(p)

	// JSON compound condition: {"op":"and","children":[...]}
	if len(p) > 0 && p[0] == '{' {
		return "compound", p
	}

	prefixes := []string{
		"allow_ip:", "block_ip:", "geo_block:",
		"block_path:", "block_path_regex:", "block_path_exact:",
		"block_query_contains:", "block_query_regex:",
		"block_header:", "block_header_regex:",
		"block_method:", "block_content_type:",
		"block_user_agent:", "block_user_agent_regex:",
		"header_regex:", "body_contains:", "body_regex:", "block_body_contains:", "block_body_regex:", "block_body_json_path:", "query_param:", "query_param_regex:",
		"path_contains:", "path_not_contains:",
		"host:", "host_full:", "host_regex:", "host_contains:", "host_not_contains:",
		"full_url_contains:", "full_url_regex:",
		"cookie_contains:", "referer_contains:",
		"tls_ja3:", "tls_ja3_hash:", "tls_ja4:", "tls_version:", "tls_sni:", "tls_alpn:", "header_order_contains:", "header_order_regex:",
		"block_multipart:",
	}
	for _, pfx := range prefixes {
		if arg, ok := strings.CutPrefix(p, pfx); ok {
			return strings.TrimSuffix(pfx, ":"), strings.TrimSpace(arg)
		}
	}
	return "", ""
}
