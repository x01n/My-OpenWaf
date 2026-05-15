package appresource

import (
	"regexp"
	"sort"
	"strings"

	"My-OpenWaf/internal/store"
)

// MaxRegexPattern limits application-route regex size at compile time.
const MaxRegexPattern = 512

// CompiledRule is a snapshot-time compiled application route rule.
type CompiledRule struct {
	ID            uint
	SiteID        uint
	Target        string
	Op            string
	Pattern       string
	HeaderKey     string
	Priority      int
	Regex         *regexp.Regexp
	NeedsResponse bool
}

// TargetNeedsResponse is true when the subject is only known after upstream responds.
func TargetNeedsResponse(target string) bool {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case store.AppRouteTargetResponseBody,
		store.AppRouteTargetResponseHeadersFull,
		store.AppRouteTargetFullHTTPResponse:
		return true
	default:
		return false
	}
}

// CompileRules turns DB rows into compiled runtime rules (invalid regex rows are skipped).
func CompileRules(rules []store.ApplicationRouteRule) []CompiledRule {
	out := make([]CompiledRule, 0, len(rules))
	for i := range rules {
		r := rules[i]
		if !r.Enabled {
			continue
		}
		t := strings.ToLower(strings.TrimSpace(r.Target))
		op := strings.ToLower(strings.TrimSpace(r.Op))
		if t == "" || op == "" {
			continue
		}
		cr := CompiledRule{
			ID:            r.ID,
			SiteID:        r.SiteID,
			Target:        t,
			Op:            op,
			Pattern:       r.Pattern,
			HeaderKey:     strings.TrimSpace(r.HeaderKey),
			Priority:      r.Priority,
			NeedsResponse: TargetNeedsResponse(t),
		}
		if op == store.AppRouteOpRegex {
			if len(r.Pattern) > MaxRegexPattern {
				continue
			}
			rx, err := regexp.Compile(r.Pattern)
			if err != nil {
				continue
			}
			cr.Regex = rx
		}
		out = append(out, cr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}
