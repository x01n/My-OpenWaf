package appresource

import (
	"regexp"
	"sort"
	"strings"

	"My-OpenWaf/internal/store/approute"
)

// MaxRegexPattern 限制应用路由正则的编译期大小。
const MaxRegexPattern = 512

// CompiledRule 是快照构建期编译好的应用路由规则。
type CompiledRule struct {
	ID             uint
	SiteID         uint
	Target         string
	Op             string
	Pattern        string
	HeaderKey      string
	HeaderKeyLower string
	Priority       int
	Regex          *regexp.Regexp
	NeedsResponse  bool
}

// TargetNeedsResponse 为真表示该匹配对象要等上游响应之后才可知。
func TargetNeedsResponse(target string) bool {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case approute.AppRouteTargetResponseBody,
		approute.AppRouteTargetResponseHeadersFull,
		approute.AppRouteTargetFullHTTPResponse:
		return true
	default:
		return false
	}
}

/**
 * CompileRules 把 DB 行转换为编译后的运行时规则。
 *
 * 正则非法的行会被跳过。返回结果按 Priority 降序、同优先级按 ID 升序排序。
 *
 * @param rules DB 中的启用状态应用路由规则。
 * @return 编译并排序后的规则列表。
 */
func CompileRules(rules []approute.ApplicationRouteRule) []CompiledRule {
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
			ID:             r.ID,
			SiteID:         r.SiteID,
			Target:         t,
			Op:             op,
			Pattern:        r.Pattern,
			HeaderKey:      strings.TrimSpace(r.HeaderKey),
			HeaderKeyLower: strings.ToLower(strings.TrimSpace(r.HeaderKey)),
			Priority:       r.Priority,
			NeedsResponse:  TargetNeedsResponse(t),
		}
		if op == approute.AppRouteOpRegex {
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
