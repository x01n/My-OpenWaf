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
	Match(ip net.IP, method, path, query string, headers map[string]string, body []byte) bool
}

// ── compound matchers ──

type andMatcher struct{ children []Matcher }

func (m *andMatcher) Match(ip net.IP, method, path, query string, headers map[string]string, body []byte) bool {
	for _, c := range m.children {
		if !c.Match(ip, method, path, query, headers, body) {
			return false
		}
	}
	return len(m.children) > 0
}

type orMatcher struct{ children []Matcher }

func (m *orMatcher) Match(ip net.IP, method, path, query string, headers map[string]string, body []byte) bool {
	for _, c := range m.children {
		if c.Match(ip, method, path, query, headers, body) {
			return true
		}
	}
	return false
}

type notMatcher struct{ child Matcher }

func (m *notMatcher) Match(ip net.IP, method, path, query string, headers map[string]string, body []byte) bool {
	return !m.child.Match(ip, method, path, query, headers, body)
}

// ── concrete matchers ──

type ipCIDRMatcher struct{ cidr *net.IPNet }

func (m *ipCIDRMatcher) Match(ip net.IP, _, _, _ string, _ map[string]string, _ []byte) bool {
	return ip != nil && m.cidr.Contains(ip)
}

type pathPrefixMatcher struct{ prefix string }

func (m *pathPrefixMatcher) Match(_ net.IP, _, path, _ string, _ map[string]string, _ []byte) bool {
	return strings.HasPrefix(path, m.prefix)
}

type pathRegexMatcher struct{ re *regexp.Regexp }

func (m *pathRegexMatcher) Match(_ net.IP, _, path, _ string, _ map[string]string, _ []byte) bool {
	return m.re.MatchString(path)
}

type queryContainsMatcher struct{ substr string }

func (m *queryContainsMatcher) Match(_ net.IP, _, _, query string, _ map[string]string, _ []byte) bool {
	return strings.Contains(query, m.substr)
}

type queryRegexMatcher struct{ re *regexp.Regexp }

func (m *queryRegexMatcher) Match(_ net.IP, _, _, query string, _ map[string]string, _ []byte) bool {
	return m.re.MatchString(query)
}

type headerContainsMatcher struct{ name, substr string }

func (m *headerContainsMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	for k, v := range headers {
		if strings.ToLower(k) == m.name && strings.Contains(v, m.substr) {
			return true
		}
	}
	return false
}

type headerRegexMatcher struct {
	name string
	re   *regexp.Regexp
}

func (m *headerRegexMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	for k, v := range headers {
		if strings.ToLower(k) == m.name && m.re.MatchString(v) {
			return true
		}
	}
	return false
}

type exactPathMatcher struct{ path string }

func (m *exactPathMatcher) Match(_ net.IP, _, path, _ string, _ map[string]string, _ []byte) bool {
	return path == m.path
}

type methodMatcher struct{ method string }

func (m *methodMatcher) Match(_ net.IP, method, _, _ string, _ map[string]string, _ []byte) bool {
	return strings.EqualFold(method, m.method)
}

type contentTypeMatcher struct{ ctype string }

func (m *contentTypeMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			return strings.Contains(strings.ToLower(v), m.ctype)
		}
	}
	return false
}

type alwaysMatcher struct{}

func (m *alwaysMatcher) Match(net.IP, string, string, string, map[string]string, []byte) bool {
	return true
}

type neverMatcher struct{}

func (m *neverMatcher) Match(net.IP, string, string, string, map[string]string, []byte) bool {
	return false
}

type bodyContainsMatcher struct{ substr string }

func (m *bodyContainsMatcher) Match(_ net.IP, _, _, _ string, _ map[string]string, body []byte) bool {
	return len(body) > 0 && strings.Contains(string(body), m.substr)
}

type bodyRegexMatcher struct{ re *regexp.Regexp }

func (m *bodyRegexMatcher) Match(_ net.IP, _, _, _ string, _ map[string]string, body []byte) bool {
	return len(body) > 0 && m.re.Match(body)
}

// bodyJSONPathMatcher checks if a dot-notation JSON path exists and optionally matches a pattern.
type bodyJSONPathMatcher struct {
	jsonPath string // e.g. "$.user.role"
	pattern  *regexp.Regexp
}

func (m *bodyJSONPathMatcher) Match(_ net.IP, _, _, _ string, _ map[string]string, body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var raw map[string]any
	if json.Unmarshal(body, &raw) != nil {
		return false
	}
	// Strip leading "$." if present.
	path := m.jsonPath
	if strings.HasPrefix(path, "$.") {
		path = path[2:]
	}
	parts := strings.Split(path, ".")
	var current any = raw
	for _, part := range parts {
		obj, ok := current.(map[string]any)
		if !ok {
			return false
		}
		current, ok = obj[part]
		if !ok {
			return false
		}
	}
	// Path exists. If no pattern, just check existence.
	if m.pattern == nil {
		return true
	}
	// Convert value to string for pattern match.
	var val string
	switch v := current.(type) {
	case string:
		val = v
	default:
		b, _ := json.Marshal(v)
		val = string(b)
	}
	return m.pattern.MatchString(val)
}

// multipartMatcher checks multipart upload filenames for suspicious extensions.
type multipartMatcher struct{ re *regexp.Regexp }

func (m *multipartMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, body []byte) bool {
	if len(body) == 0 {
		return false
	}
	ct := ""
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			ct = v
			break
		}
	}
	if !strings.Contains(strings.ToLower(ct), "multipart/form-data") {
		return false
	}
	// Extract boundary and scan part headers for filenames.
	idx := strings.Index(strings.ToLower(ct), "boundary=")
	if idx < 0 {
		return false
	}
	boundary := ct[idx+len("boundary="):]
	if q := strings.IndexByte(boundary, ';'); q >= 0 {
		boundary = boundary[:q]
	}
	boundary = strings.Trim(boundary, `"' `)
	if boundary == "" {
		return false
	}
	// Scan raw body for Content-Disposition filename values.
	bodyStr := string(body)
	parts := strings.Split(bodyStr, "--"+boundary)
	for _, part := range parts {
		low := strings.ToLower(part)
		if fi := strings.Index(low, "filename="); fi >= 0 {
			fnStart := fi + len("filename=")
			if fnStart < len(part) {
				fname := part[fnStart:]
				// Trim quotes and extract until end of line.
				fname = strings.TrimLeft(fname, `"' `)
				if nl := strings.IndexAny(fname, "\r\n\""); nl >= 0 {
					fname = fname[:nl]
				}
				if m.re.MatchString(fname) {
					return true
				}
			}
		}
	}
	return false
}

// geoBlockMatcher blocks requests based on geo country code headers.
type geoBlockMatcher struct{ countries map[string]bool }

func (m *geoBlockMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	// Check common geo-country headers.
	for k, v := range headers {
		lk := strings.ToLower(k)
		if lk == "x-geo-country" || lk == "cf-ipcountry" {
			code := strings.TrimSpace(strings.ToUpper(v))
			if m.countries[code] {
				return true
			}
		}
	}
	return false
}

type queryParamMatcher struct {
	param string
	value string
}

func (m *queryParamMatcher) Match(_ net.IP, _, _, query string, _ map[string]string, _ []byte) bool {
	if query == "" {
		return false
	}
	for _, pair := range strings.Split(query, "&") {
		if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
			if kv[0] == m.param {
				if m.value == "" {
					return true
				}
				return strings.Contains(kv[1], m.value)
			}
		}
	}
	return false
}

// hostMatcher matches the Host header exactly or with wildcard prefix.
type hostMatcher struct{ pattern string }

func (m *hostMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	host := ""
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			host = strings.ToLower(v)
			break
		}
	}
	if host == "" {
		return false
	}
	// Strip port if present.
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	pat := strings.ToLower(m.pattern)
	if strings.HasPrefix(pat, "*.") {
		suffix := pat[1:] // ".example.com"
		return strings.HasSuffix(host, suffix) || host == pat[2:]
	}
	return host == pat
}

// cookieContainsMatcher checks if any cookie contains the given substring.
type cookieContainsMatcher struct{ substr string }

func (m *cookieContainsMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	for k, v := range headers {
		if strings.EqualFold(k, "Cookie") {
			return strings.Contains(v, m.substr)
		}
	}
	return false
}

// refererContainsMatcher checks if the Referer header contains a substring.
type refererContainsMatcher struct{ substr string }

func (m *refererContainsMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	for k, v := range headers {
		if strings.EqualFold(k, "Referer") {
			return strings.Contains(v, m.substr)
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
				return &neverMatcher{}
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
			return &neverMatcher{}
		}
		return &pathRegexMatcher{re: re}

	case "block_query_contains":
		return &queryContainsMatcher{substr: arg}

	case "block_query_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &queryRegexMatcher{re: re}

	case "block_header":
		name, substr := splitHeaderArg(arg)
		return &headerContainsMatcher{name: strings.ToLower(name), substr: substr}

	case "block_header_regex":
		name, pattern := splitHeaderArg(arg)
		re, err := cachedCompile(pattern)
		if err != nil {
			return &neverMatcher{}
		}
		return &headerRegexMatcher{name: strings.ToLower(name), re: re}

	case "block_path_exact":
		return &exactPathMatcher{path: arg}

	case "block_method":
		return &methodMatcher{method: strings.ToUpper(arg)}

	case "block_content_type":
		return &contentTypeMatcher{ctype: strings.ToLower(arg)}

	case "block_user_agent":
		return &headerContainsMatcher{name: "user-agent", substr: arg}

	case "block_user_agent_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &headerRegexMatcher{name: "user-agent", re: re}

	case "header_regex":
		name, pattern := splitHeaderArg(arg)
		re, err := cachedCompile(pattern)
		if err != nil {
			return &neverMatcher{}
		}
		return &headerRegexMatcher{name: strings.ToLower(name), re: re}

	case "body_contains":
		return &bodyContainsMatcher{substr: arg}

	case "body_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &bodyRegexMatcher{re: re}

	case "query_param":
		param, value := splitHeaderArg(arg)
		return &queryParamMatcher{param: param, value: value}

	case "host":
		return &hostMatcher{pattern: arg}

	case "cookie_contains":
		return &cookieContainsMatcher{substr: arg}

	case "referer_contains":
		return &refererContainsMatcher{substr: arg}

	case "block_body_json_path":
		// arg format: "$.path.to.field" or "$.path.to.field:regex_pattern"
		jsonPath, pattern := splitHeaderArg(arg)
		var re *regexp.Regexp
		if pattern != "" {
			var err error
			re, err = cachedCompile(pattern)
			if err != nil {
				return &neverMatcher{}
			}
		}
		return &bodyJSONPathMatcher{jsonPath: jsonPath, pattern: re}

	case "block_multipart":
		// arg is a regex pattern to match against uploaded filenames
		if arg == "" {
			arg = `(?i)\.(php[0-9]?|phtml|jsp|jspx|asp|aspx|exe|dll|sh|bat|cmd|cgi|pl|py|rb|war|ear)$`
		}
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &multipartMatcher{re: re}

	case "geo_block":
		// arg is comma-separated country codes, e.g. "CN,RU,KP"
		codes := strings.Split(arg, ",")
		countries := make(map[string]bool, len(codes))
		for _, c := range codes {
			c = strings.TrimSpace(strings.ToUpper(c))
			if c != "" {
				countries[c] = true
			}
		}
		return &geoBlockMatcher{countries: countries}

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
