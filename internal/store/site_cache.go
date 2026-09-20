package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	// MaxSiteCacheRulesJSONBytes limits persisted rule data parsed on every snapshot build.
	MaxSiteCacheRulesJSONBytes = 64 << 10
	// MaxSiteCacheRules bounds per-request rule matching work.
	MaxSiteCacheRules = 128
	// MaxSiteCacheRulePatternBytes bounds compiled and compared pattern data.
	MaxSiteCacheRulePatternBytes = 1024
	// MaxSiteCacheTTLSeconds bounds cached response lifetime to thirty days.
	MaxSiteCacheTTLSeconds = 30 * 24 * 60 * 60
	// MaxSiteCacheStaleIfErrorSeconds bounds stale fallback to one day.
	MaxSiteCacheStaleIfErrorSeconds = 24 * 60 * 60
)

var (
	errSiteCacheRulesArray      = errors.New("cache_rules must be a JSON array")
	errSiteCacheRulesTooLarge   = errors.New("cache_rules exceeds the maximum JSON size")
	errSiteCacheRulesTooMany    = errors.New("cache_rules contains too many rules")
	errSiteCacheRuleType        = errors.New("cache rule type must be prefix, exact, suffix, contains, or regex")
	errSiteCacheRuleValue       = errors.New("cache rule value must be non-empty")
	errSiteCacheRuleValueLength = errors.New("cache rule value is too long")
	errSiteCacheRuleTTL         = errors.New("cache rule ttl is out of range")
	errSiteCacheDefaultTTL      = errors.New("cache_default_ttl is out of range")
	errSiteCacheRuleStale       = errors.New("cache rule stale_if_error_seconds is out of range")
)

// ValidateAndCompileSiteCacheRules validates persisted cache rules and returns
// their immutable runtime representation. A rule TTL of zero inherits defaultTTL;
// paths without a matching rule remain uncacheable.
func ValidateAndCompileSiteCacheRules(raw string, defaultTTL int) ([]SiteCacheRule, error) {
	if defaultTTL < 0 || defaultTTL > MaxSiteCacheTTLSeconds {
		return nil, errSiteCacheDefaultTTL
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > MaxSiteCacheRulesJSONBytes {
		return nil, errSiteCacheRulesTooLarge
	}

	var inbound []SiteCacheRule
	if err := json.Unmarshal([]byte(raw), &inbound); err != nil || inbound == nil {
		return nil, errSiteCacheRulesArray
	}
	if len(inbound) > MaxSiteCacheRules {
		return nil, errSiteCacheRulesTooMany
	}

	compiled := make([]SiteCacheRule, 0, len(inbound))
	for index, rule := range inbound {
		rules, err := compileSiteCacheRule(rule, defaultTTL)
		if err != nil {
			return nil, fmt.Errorf("cache_rules[%d]: %w", index, err)
		}
		if len(compiled)+len(rules) > MaxSiteCacheRules {
			return nil, errSiteCacheRulesTooMany
		}
		compiled = append(compiled, rules...)
	}

	sort.SliceStable(compiled, func(i, j int) bool {
		return len(siteCacheRuleRuntimePattern(compiled[i])) > len(siteCacheRuleRuntimePattern(compiled[j]))
	})
	return compiled, nil
}

func compileSiteCacheRule(rule SiteCacheRule, defaultTTL int) ([]SiteCacheRule, error) {
	ruleType := strings.ToLower(strings.TrimSpace(rule.Type))
	value := strings.TrimSpace(rule.Value)
	legacyPath := strings.TrimSpace(rule.Path)
	if ruleType == "" {
		ruleType = "prefix"
	}
	if value == "" {
		value = legacyPath
	}
	if value == "" {
		return nil, errSiteCacheRuleValue
	}
	if len(value) > MaxSiteCacheRulePatternBytes {
		return nil, errSiteCacheRuleValueLength
	}
	if rule.TTL < 0 || rule.TTL > MaxSiteCacheTTLSeconds {
		return nil, errSiteCacheRuleTTL
	}
	if rule.TTL == 0 {
		if defaultTTL <= 0 {
			return nil, errSiteCacheDefaultTTL
		}
		rule.TTL = defaultTTL
	}
	if rule.StaleIfError < 0 || rule.StaleIfError > MaxSiteCacheStaleIfErrorSeconds {
		return nil, errSiteCacheRuleStale
	}

	switch ruleType {
	case "prefix", "exact", "suffix", "contains", "regex":
	default:
		return nil, errSiteCacheRuleType
	}
	if rule.Disabled {
		return nil, nil
	}

	values := []string{value}
	// Comma-separated suffix lists are a documented legacy format. Other rule
	// types keep commas literal so regex quantifiers and query values are intact.
	if ruleType == "suffix" && strings.Contains(value, ",") {
		values = strings.Split(value, ",")
	}
	result := make([]SiteCacheRule, 0, len(values))
	for _, rawValue := range values {
		pattern := strings.TrimSpace(rawValue)
		if pattern == "" {
			return nil, errSiteCacheRuleValue
		}
		if len(pattern) > MaxSiteCacheRulePatternBytes {
			return nil, errSiteCacheRuleValueLength
		}
		compiled := SiteCacheRule{
			Type:            ruleType,
			TTL:             rule.TTL,
			CaseInsensitive: rule.CaseInsensitive,
			IgnoreQuery:     rule.IgnoreQuery,
			Note:            rule.Note,
			StaleIfError:    rule.StaleIfError,
		}
		switch ruleType {
		case "regex":
			compiled.Value = pattern
			regexPattern := pattern
			if rule.CaseInsensitive {
				regexPattern = "(?i)" + regexPattern
			}
			re, err := regexp.Compile(regexPattern)
			if err != nil {
				return nil, fmt.Errorf("invalid cache rule regex: %w", err)
			}
			compiled.Regex = re
		case "contains":
			compiled.Path = pattern
		case "suffix":
			compiled.Path = pattern
			if !strings.Contains(pattern, ".") {
				compiled.Path = "." + pattern
			}
		default:
			if !strings.HasPrefix(pattern, "/") {
				pattern = "/" + pattern
			}
			compiled.Path = pattern
		}
		result = append(result, compiled)
	}
	return result, nil
}

func siteCacheRuleRuntimePattern(rule SiteCacheRule) string {
	if value := strings.TrimSpace(rule.Value); value != "" {
		return value
	}
	return strings.TrimSpace(rule.Path)
}
