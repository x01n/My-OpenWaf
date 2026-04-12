package rules

import (
	"net"
	"regexp"
	"strings"
)

// Matcher tests a single condition against request fields.
type Matcher interface {
	Match(ip net.IP, path, query string, headers map[string]string) bool
}

// ── concrete matchers ──

type ipCIDRMatcher struct{ cidr *net.IPNet }

func (m *ipCIDRMatcher) Match(ip net.IP, _, _ string, _ map[string]string) bool {
	return ip != nil && m.cidr.Contains(ip)
}

type pathPrefixMatcher struct{ prefix string }

func (m *pathPrefixMatcher) Match(_ net.IP, path, _ string, _ map[string]string) bool {
	return strings.HasPrefix(path, m.prefix)
}

type pathRegexMatcher struct{ re *regexp.Regexp }

func (m *pathRegexMatcher) Match(_ net.IP, path, _ string, _ map[string]string) bool {
	return m.re.MatchString(path)
}

type queryContainsMatcher struct{ substr string }

func (m *queryContainsMatcher) Match(_ net.IP, _, query string, _ map[string]string) bool {
	return strings.Contains(query, m.substr)
}

type queryRegexMatcher struct{ re *regexp.Regexp }

func (m *queryRegexMatcher) Match(_ net.IP, _, query string, _ map[string]string) bool {
	return m.re.MatchString(query)
}

type headerContainsMatcher struct{ name, substr string }

func (m *headerContainsMatcher) Match(_ net.IP, _, _ string, headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, m.name) && strings.Contains(v, m.substr) {
			return true
		}
	}
	return false
}

type headerRegexMatcher struct {
	name string
	re   *regexp.Regexp
}

func (m *headerRegexMatcher) Match(_ net.IP, _, _ string, headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, m.name) && m.re.MatchString(v) {
			return true
		}
	}
	return false
}

type alwaysMatcher struct{}

func (m *alwaysMatcher) Match(net.IP, string, string, map[string]string) bool { return true }

// buildMatcher creates a Matcher from a parsed kind:arg pattern.
func buildMatcher(kind, arg string) Matcher {
	switch kind {
	case "allow_ip", "block_ip":
		_, cidr, err := net.ParseCIDR(arg)
		if err != nil {
			ip := net.ParseIP(strings.TrimSpace(arg))
			if ip == nil {
				return &alwaysMatcher{}
			}
			if ip4 := ip.To4(); ip4 != nil {
				_, cidr, _ = net.ParseCIDR(ip.String() + "/32")
			} else {
				_, cidr, _ = net.ParseCIDR(ip.String() + "/128")
			}
		}
		if cidr == nil {
			return &alwaysMatcher{}
		}
		return &ipCIDRMatcher{cidr: cidr}

	case "block_path":
		return &pathPrefixMatcher{prefix: arg}

	case "block_path_regex":
		re, err := regexp.Compile(arg)
		if err != nil {
			return &alwaysMatcher{}
		}
		return &pathRegexMatcher{re: re}

	case "block_query_contains":
		return &queryContainsMatcher{substr: arg}

	case "block_query_regex":
		re, err := regexp.Compile(arg)
		if err != nil {
			return &alwaysMatcher{}
		}
		return &queryRegexMatcher{re: re}

	case "block_header":
		name, substr := splitHeaderArg(arg)
		return &headerContainsMatcher{name: name, substr: substr}

	case "block_header_regex":
		name, pattern := splitHeaderArg(arg)
		re, err := regexp.Compile(pattern)
		if err != nil {
			return &alwaysMatcher{}
		}
		return &headerRegexMatcher{name: name, re: re}

	default:
		return &alwaysMatcher{}
	}
}

// splitHeaderArg splits "Header-Name:value" into (name, value).
func splitHeaderArg(arg string) (string, string) {
	if i := strings.Index(arg, ":"); i > 0 {
		return arg[:i], arg[i+1:]
	}
	return arg, ""
}
