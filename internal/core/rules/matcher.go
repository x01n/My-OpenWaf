package rules

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"
	"sync"
)

// Matcher tests a single condition against request fields.
type Matcher interface {
	Match(ip net.IP, method, path, query string, headers map[string]string) bool
}

// ── compound matchers ──

type andMatcher struct{ children []Matcher }

func (m *andMatcher) Match(ip net.IP, method, path, query string, headers map[string]string) bool {
	for _, c := range m.children {
		if !c.Match(ip, method, path, query, headers) {
			return false
		}
	}
	return len(m.children) > 0
}

type orMatcher struct{ children []Matcher }

func (m *orMatcher) Match(ip net.IP, method, path, query string, headers map[string]string) bool {
	for _, c := range m.children {
		if c.Match(ip, method, path, query, headers) {
			return true
		}
	}
	return false
}

type notMatcher struct{ child Matcher }

func (m *notMatcher) Match(ip net.IP, method, path, query string, headers map[string]string) bool {
	return !m.child.Match(ip, method, path, query, headers)
}

// ── concrete matchers ──

type ipCIDRMatcher struct{ cidr *net.IPNet }

func (m *ipCIDRMatcher) Match(ip net.IP, _, _, _ string, _ map[string]string) bool {
	return ip != nil && m.cidr.Contains(ip)
}

type pathPrefixMatcher struct{ prefix string }

func (m *pathPrefixMatcher) Match(_ net.IP, _, path, _ string, _ map[string]string) bool {
	return strings.HasPrefix(path, m.prefix)
}

type pathRegexMatcher struct{ re *regexp.Regexp }

func (m *pathRegexMatcher) Match(_ net.IP, _, path, _ string, _ map[string]string) bool {
	return m.re.MatchString(path)
}

type queryContainsMatcher struct{ substr string }

func (m *queryContainsMatcher) Match(_ net.IP, _, _, query string, _ map[string]string) bool {
	return strings.Contains(query, m.substr)
}

type queryRegexMatcher struct{ re *regexp.Regexp }

func (m *queryRegexMatcher) Match(_ net.IP, _, _, query string, _ map[string]string) bool {
	return m.re.MatchString(query)
}

type headerContainsMatcher struct{ name, substr string } // name is pre-lowercased

func (m *headerContainsMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string) bool {
	for k, v := range headers {
		if strings.ToLower(k) == m.name && strings.Contains(v, m.substr) {
			return true
		}
	}
	return false
}

type headerRegexMatcher struct {
	name string // pre-lowercased
	re   *regexp.Regexp
}

func (m *headerRegexMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string) bool {
	for k, v := range headers {
		if strings.ToLower(k) == m.name && m.re.MatchString(v) {
			return true
		}
	}
	return false
}

type exactPathMatcher struct{ path string }

func (m *exactPathMatcher) Match(_ net.IP, _, path, _ string, _ map[string]string) bool {
	return path == m.path
}

type methodMatcher struct{ method string }

func (m *methodMatcher) Match(_ net.IP, method, _, _ string, _ map[string]string) bool {
	return strings.EqualFold(method, m.method)
}

type contentTypeMatcher struct{ ctype string } // ctype is pre-lowercased

func (m *contentTypeMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			return strings.Contains(strings.ToLower(v), m.ctype)
		}
	}
	return false
}

type alwaysMatcher struct{}

func (m *alwaysMatcher) Match(net.IP, string, string, string, map[string]string) bool { return true }

type neverMatcher struct{}

func (m *neverMatcher) Match(net.IP, string, string, string, map[string]string) bool { return false }

type bodyContainsMatcher struct{ substr string }

func (m *bodyContainsMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string) bool {
	// Body matching requires special handling in the engine
	// This matcher is a placeholder that always returns false here
	// The actual body check happens in the request context
	return false
}

type queryParamMatcher struct {
	param string
	value string
}

func (m *queryParamMatcher) Match(_ net.IP, _, _, query string, _ map[string]string) bool {
	if query == "" {
		return false
	}
	// Parse query string for specific parameter
	for _, pair := range strings.Split(query, "&") {
		if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
			if kv[0] == m.param {
				if m.value == "" {
					return true // Just check param exists
				}
				return strings.Contains(kv[1], m.value)
			}
		}
	}
	return false
}

// buildMatcher creates a Matcher from a parsed kind:arg pattern.
func buildMatcher(kind, arg string) Matcher {
	switch kind {
	case "allow_ip", "block_ip":
		_, cidr, err := net.ParseCIDR(arg)
		if err != nil {
			ip := net.ParseIP(strings.TrimSpace(arg))
			if ip == nil {
				return &neverMatcher{} // invalid IP/CIDR: match nothing instead of everything
			}
			if ip4 := ip.To4(); ip4 != nil {
				_, cidr, _ = net.ParseCIDR(ip.String() + "/32")
			} else {
				_, cidr, _ = net.ParseCIDR(ip.String() + "/128")
			}
		}
		if cidr == nil {
			return &neverMatcher{}
		}
		return &ipCIDRMatcher{cidr: cidr}

	case "block_path":
		return &pathPrefixMatcher{prefix: arg}

	case "block_path_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{} // invalid regex: match nothing
		}
		return &pathRegexMatcher{re: re}

	case "block_query_contains":
		return &queryContainsMatcher{substr: arg}

	case "block_query_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{} // invalid regex: match nothing
		}
		return &queryRegexMatcher{re: re}

	case "block_header":
		name, substr := splitHeaderArg(arg)
		return &headerContainsMatcher{name: strings.ToLower(name), substr: substr}

	case "block_header_regex":
		name, pattern := splitHeaderArg(arg)
		re, err := cachedCompile(pattern)
		if err != nil {
			return &neverMatcher{} // invalid regex: match nothing
		}
		return &headerRegexMatcher{name: strings.ToLower(name), re: re}

	case "block_path_exact":
		return &exactPathMatcher{path: arg}

	case "block_method":
		return &methodMatcher{method: strings.ToUpper(arg)}

	case "block_content_type":
		return &contentTypeMatcher{ctype: strings.ToLower(arg)}

	// User-Agent convenience matchers (equivalent to block_header:User-Agent:<value>).
	case "block_user_agent":
		return &headerContainsMatcher{name: "user-agent", substr: arg}

	case "block_user_agent_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &headerRegexMatcher{name: "user-agent", re: re}

	// New matcher types
	case "header_regex":
		name, pattern := splitHeaderArg(arg)
		re, err := cachedCompile(pattern)
		if err != nil {
			return &neverMatcher{}
		}
		return &headerRegexMatcher{name: strings.ToLower(name), re: re}

	case "body_contains":
		return &bodyContainsMatcher{substr: arg}

	case "query_param":
		param, value := splitHeaderArg(arg) // Reuse split logic for param:value
		return &queryParamMatcher{param: param, value: value}

	case "compound":
		return parseCompoundJSON(arg)

	default:
		return &neverMatcher{}
	}
}

// splitHeaderArg splits "Header-Name:value" into (name, value).
func splitHeaderArg(arg string) (string, string) {
	if i := strings.Index(arg, ":"); i > 0 {
		return arg[:i], arg[i+1:]
	}
	return arg, ""
}

// ── regex cache ──

var regexCache = struct {
	mu    sync.RWMutex
	cache map[string]*regexp.Regexp
}{cache: make(map[string]*regexp.Regexp)}

// cachedCompile returns a compiled regexp, reusing a cached instance if available.
func cachedCompile(pattern string) (*regexp.Regexp, error) {
	regexCache.mu.RLock()
	if re, ok := regexCache.cache[pattern]; ok {
		regexCache.mu.RUnlock()
		return re, nil
	}
	regexCache.mu.RUnlock()

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCache.mu.Lock()
	regexCache.cache[pattern] = re
	regexCache.mu.Unlock()
	return re, nil
}

// ── compound JSON condition ──

// compoundCondition represents a JSON-encoded compound rule condition.
// Format: {"op":"and|or|not","children":[...]} or {"kind":"block_ip","arg":"1.2.3.0/24"}
type compoundCondition struct {
	Op       string              `json:"op"`
	Kind     string              `json:"kind"`
	Arg      string              `json:"arg"`
	Children []compoundCondition `json:"children"`
}

func parseCompoundJSON(raw string) Matcher {
	var cond compoundCondition
	if err := json.Unmarshal([]byte(raw), &cond); err != nil {
		return &neverMatcher{}
	}
	return buildCompound(cond)
}

func buildCompound(cond compoundCondition) Matcher {
	switch cond.Op {
	case "and":
		children := make([]Matcher, 0, len(cond.Children))
		for _, ch := range cond.Children {
			children = append(children, buildCompound(ch))
		}
		return &andMatcher{children: children}
	case "or":
		children := make([]Matcher, 0, len(cond.Children))
		for _, ch := range cond.Children {
			children = append(children, buildCompound(ch))
		}
		return &orMatcher{children: children}
	case "not":
		if len(cond.Children) == 0 {
			return &neverMatcher{}
		}
		return &notMatcher{child: buildCompound(cond.Children[0])}
	default:
		if cond.Kind != "" {
			return buildMatcher(cond.Kind, cond.Arg)
		}
		return &neverMatcher{}
	}
}
