package rules

import (
	"sort"
	"strings"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
)

// Compiled is a runtime-ready rule with a pre-built matcher.
type Compiled struct {
	ID       uint
	Phase    string
	Action   action.Type
	Priority int
	Kind     string
	Arg      string
	matcher  Matcher
}

// Match delegates to the pre-built matcher.
func (c *Compiled) Match(ctx MatchCtx) bool {
	return c.matcher.Match(ctx.ClientIP, ctx.Path, ctx.Query, ctx.Headers)
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
			ID:       r.ID,
			Phase:    string(r.Phase),
			Action:   action.Type(r.Action),
			Priority: r.Priority,
			Kind:     kind,
			Arg:      arg,
			matcher:  buildMatcher(kind, arg),
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
		"allow_ip:", "block_ip:",
		"block_path:", "block_path_regex:", "block_path_exact:",
		"block_query_contains:", "block_query_regex:",
		"block_header:", "block_header_regex:",
		"block_method:", "block_content_type:",
	}
	for _, pfx := range prefixes {
		if strings.HasPrefix(p, pfx) {
			return strings.TrimSuffix(pfx, ":"), strings.TrimSpace(strings.TrimPrefix(p, pfx))
		}
	}
	return "", ""
}
