package rules

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Matcher tests a single condition against request fields.
type Matcher interface {
	Match(ip net.IP, method, path, query string, headers map[string]string, body []byte) bool
}

type ccRateMatcher struct {
	child     Matcher
	window    int64
	threshold int64
	duration  int64
	mu        sync.Mutex
	clients   map[string]*ccRateState
	lastSweep int64
}

type ccRateState struct {
	count       int64
	windowUntil int64
	blockedTill int64
}

func (m *ccRateMatcher) Match(ip net.IP, method, path, query string, headers map[string]string, body []byte) bool {
	if m.child == nil || !m.child.Match(ip, method, path, query, headers, body) {
		return false
	}
	if m.window <= 0 || m.threshold <= 0 {
		return true
	}

	now := time.Now().Unix()
	key := ccRateKey(ip, headers)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.clients == nil {
		m.clients = make(map[string]*ccRateState)
	}
	if now-m.lastSweep >= 60 {
		for k, state := range m.clients {
			if state == nil || (state.windowUntil <= now && state.blockedTill <= now) {
				delete(m.clients, k)
			}
		}
		m.lastSweep = now
	}
	state := m.clients[key]
	if state != nil && state.blockedTill > now {
		return true
	}
	if state == nil || state.windowUntil <= now {
		state = &ccRateState{windowUntil: now + m.window}
		m.clients[key] = state
	}
	state.count++
	if state.count < m.threshold {
		return false
	}
	if m.duration > 0 {
		state.blockedTill = now + m.duration*60
	}
	return true
}

func ccRateKey(ip net.IP, headers map[string]string) string {
	client := ""
	if ip != nil {
		client = ip.String()
	}
	return client + "|" + headerValue(headers, "host")
}

func headerValue(headers map[string]string, name string) string {
	value, _ := lookupHeaderValue(headers, name)
	return value
}

func lookupHeaderValue(headers map[string]string, name string) (string, bool) {
	if value, ok := headers[name]; ok {
		return value, true
	}
	if lower := strings.ToLower(name); lower != name {
		if value, ok := headers[lower]; ok {
			return value, true
		}
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
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
	value, ok := lookupHeaderValue(headers, m.name)
	return ok && strings.Contains(value, m.substr)
}

type headerRegexMatcher struct {
	name string
	re   *regexp.Regexp
}

type headerOrderContainsMatcher struct{ substr string }

func (m *headerOrderContainsMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	return strings.Contains(headerValue(headers, "x-owaf-header-order"), m.substr)
}

type headerOrderRegexMatcher struct{ re *regexp.Regexp }

type tlsFingerprintMatcher struct {
	name  string
	value string
}

func (m *tlsFingerprintMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	value := headerValue(headers, m.name)
	if strings.EqualFold(value, m.value) {
		return true
	}
	if m.name == "x-owaf-tls-ja3-hash" && value == "" {
		ja3 := headerValue(headers, "x-owaf-tls-ja3")
		if ja3 == "" {
			return false
		}
		sum := md5.Sum([]byte(ja3))
		return strings.EqualFold(hex.EncodeToString(sum[:]), m.value)
	}
	return false
}

func (m *headerOrderRegexMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	return m.re.MatchString(headerValue(headers, "x-owaf-header-order"))
}

func (m *headerRegexMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	value, ok := lookupHeaderValue(headers, m.name)
	return ok && m.re.MatchString(value)
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

type ifElseMatcher struct {
	condition Matcher
	thenMatch Matcher
	elseMatch Matcher
}

func (m *ifElseMatcher) Match(ip net.IP, method, path, query string, headers map[string]string, body []byte) bool {
	if m.condition == nil {
		return false
	}
	if m.condition.Match(ip, method, path, query, headers, body) {
		return m.thenMatch != nil && m.thenMatch.Match(ip, method, path, query, headers, body)
	}
	return m.elseMatch != nil && m.elseMatch.Match(ip, method, path, query, headers, body)
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

type queryParamRegexMatcher struct {
	param string
	re    *regexp.Regexp
}

type pathContainsMatcher struct{ substr string }

type pathNotContainsMatcher struct{ substr string }

func rawQueryMayContainParam(query, param string) bool {
	if query == "" || param == "" {
		return false
	}
	if rawQueryContainsParamName(query, param) {
		return true
	}
	escaped := url.QueryEscape(param)
	return escaped != param && rawQueryContainsParamName(query, escaped)
}

func rawQueryContainsParamName(query, name string) bool {
	start := 0
	for {
		idx := strings.Index(query[start:], name)
		if idx < 0 {
			return false
		}
		pos := start + idx
		end := pos + len(name)
		beforeOK := pos == 0 || query[pos-1] == '&'
		afterOK := end == len(query) || query[end] == '=' || query[end] == '&'
		if beforeOK && afterOK {
			return true
		}
		start = end
	}
}

func (m *queryParamMatcher) Match(_ net.IP, _, _, query string, _ map[string]string, _ []byte) bool {
	if query == "" || !rawQueryMayContainParam(query, m.param) {
		return false
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return false
	}
	items, ok := values[m.param]
	if !ok {
		return false
	}
	if m.value == "" {
		return true
	}
	for _, item := range items {
		if strings.Contains(item, m.value) {
			return true
		}
	}
	return false
}

func (m *queryParamRegexMatcher) Match(_ net.IP, _, _, query string, _ map[string]string, _ []byte) bool {
	if query == "" || !rawQueryMayContainParam(query, m.param) {
		return false
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return false
	}
	items, ok := values[m.param]
	if !ok {
		return false
	}
	for _, item := range items {
		if m.re.MatchString(item) {
			return true
		}
	}
	return false
}

func (m *pathContainsMatcher) Match(_ net.IP, _, path, _ string, _ map[string]string, _ []byte) bool {
	return strings.Contains(path, m.substr)
}

func (m *pathNotContainsMatcher) Match(_ net.IP, _, path, _ string, _ map[string]string, _ []byte) bool {
	return !strings.Contains(path, m.substr)
}

// hostMatcher matches the Host header exactly or with wildcard prefix.
type hostMatcher struct{ pattern string }

func (m *hostMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	host, _ := splitHostPortHeader(headerValue(headers, "host"))
	if host == "" {
		return false
	}
	pat, _ := splitHostPortHeader(m.pattern)
	if strings.HasPrefix(pat, "*.") {
		suffix := pat[1:]
		return strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(pat, "*.")
	}
	return host == pat
}

func splitHostPortHeader(host string) (nameOnly, fullLower string) {
	fullLower = strings.ToLower(strings.TrimSpace(host))
	nameOnly = fullLower
	if i := strings.LastIndex(fullLower, ":"); i > 0 {
		tail := fullLower[i+1:]
		allDigits := len(tail) > 0
		for _, ch := range tail {
			if ch < '0' || ch > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			nameOnly = fullLower[:i]
		}
	}
	return nameOnly, fullLower
}

// hostFullMatcher matches Host including explicit port; wildcard applies to hostname only.
type hostFullMatcher struct{ pattern string }

func (m *hostFullMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	raw := strings.TrimSpace(headerValue(headers, "host"))
	if raw == "" {
		return false
	}
	hostName, fullLower := splitHostPortHeader(raw)
	pat := strings.TrimSpace(m.pattern)
	patLower := strings.ToLower(pat)
	if strings.HasPrefix(patLower, "*.") {
		suffix := patLower[1:]
		return strings.HasSuffix(hostName, suffix) || hostName == strings.TrimPrefix(patLower, "*.")
	}
	pl := strings.ToLower(pat)
	return fullLower == pl || hostName == pl
}

type hostRegexMatcher struct{ re *regexp.Regexp }

func (m *hostRegexMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	raw := strings.TrimSpace(headerValue(headers, "host"))
	if raw == "" {
		return false
	}
	hostName, _ := splitHostPortHeader(raw)
	return m.re.MatchString(hostName)
}

type hostContainsMatcher struct{ substr string }

func (m *hostContainsMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	raw := strings.TrimSpace(headerValue(headers, "host"))
	if raw == "" {
		return false
	}
	hostName, _ := splitHostPortHeader(raw)
	return strings.Contains(hostName, strings.ToLower(m.substr))
}

type hostNotContainsMatcher struct{ substr string }

func (m *hostNotContainsMatcher) Match(_ net.IP, _, _, _ string, headers map[string]string, _ []byte) bool {
	raw := strings.TrimSpace(headerValue(headers, "host"))
	if raw == "" {
		return true
	}
	hostName, _ := splitHostPortHeader(raw)
	return !strings.Contains(hostName, strings.ToLower(m.substr))
}

// fullURLContainsMatcher matches path + raw query (lowercased) for a substring.
type fullURLContainsMatcher struct{ substr string }

func (m *fullURLContainsMatcher) Match(_ net.IP, _, path, query string, _ map[string]string, _ []byte) bool {
	u := path
	if query != "" {
		u += "?" + query
	}
	return strings.Contains(strings.ToLower(u), strings.ToLower(m.substr))
}

// fullURLRegexMatcher matches path + raw query against a regex.
type fullURLRegexMatcher struct{ re *regexp.Regexp }

func (m *fullURLRegexMatcher) Match(_ net.IP, _, path, query string, _ map[string]string, _ []byte) bool {
	u := path
	if query != "" {
		u += "?" + query
	}
	return m.re.MatchString(u)
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

	case "tls_ja3":
		return &tlsFingerprintMatcher{name: "x-owaf-tls-ja3", value: arg}

	case "tls_ja3_hash":
		return &tlsFingerprintMatcher{name: "x-owaf-tls-ja3-hash", value: arg}

	case "tls_ja4":
		return &tlsFingerprintMatcher{name: "x-owaf-tls-ja4", value: arg}

	case "tls_version":
		return &tlsFingerprintMatcher{name: "x-owaf-tls-version", value: arg}

	case "tls_sni":
		return &tlsFingerprintMatcher{name: "x-owaf-tls-sni", value: arg}

	case "tls_alpn":
		return &tlsFingerprintMatcher{name: "x-owaf-tls-alpn", value: arg}

	case "header_order_contains":
		return &headerOrderContainsMatcher{substr: arg}

	case "header_order_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &headerOrderRegexMatcher{re: re}

	case "header_regex":
		name, pattern := splitHeaderArg(arg)
		re, err := cachedCompile(pattern)
		if err != nil {
			return &neverMatcher{}
		}
		return &headerRegexMatcher{name: strings.ToLower(name), re: re}

	case "body_contains", "block_body_contains":
		return &bodyContainsMatcher{substr: arg}

	case "body_regex", "block_body_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &bodyRegexMatcher{re: re}

	case "query_param":
		param, value := splitHeaderArg(arg)
		return &queryParamMatcher{param: param, value: value}

	case "query_param_regex":
		param, pattern, ok := strings.Cut(arg, ":")
		if !ok {
			return &neverMatcher{}
		}
		re, err := cachedCompile(pattern)
		if err != nil {
			return &neverMatcher{}
		}
		return &queryParamRegexMatcher{param: param, re: re}

	case "path_contains":
		return &pathContainsMatcher{substr: arg}

	case "path_not_contains":
		return &pathNotContainsMatcher{substr: arg}

	case "host_full":
		return &hostFullMatcher{pattern: arg}

	case "full_url_contains":
		return &fullURLContainsMatcher{substr: arg}

	case "full_url_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &fullURLRegexMatcher{re: re}

	case "host":
		return &hostMatcher{pattern: arg}

	case "host_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &hostRegexMatcher{re: re}

	case "host_contains":
		return &hostContainsMatcher{substr: arg}

	case "host_not_contains":
		return &hostNotContainsMatcher{substr: arg}

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
	Op        string              `json:"op"`
	Kind      string              `json:"kind"`
	Arg       string              `json:"arg"`
	Children  []compoundCondition `json:"children"`
	If        *compoundCondition  `json:"if"`
	Then      *compoundCondition  `json:"then"`
	Else      *compoundCondition  `json:"else"`
	Window    int64               `json:"window"`
	Threshold int64               `json:"threshold"`
	Duration  int64               `json:"duration"`
}

func parseCompoundJSON(raw string) Matcher {
	var cond compoundCondition
	if err := json.Unmarshal([]byte(raw), &cond); err != nil {
		return &neverMatcher{}
	}
	return buildCompound(cond)
}

func buildCompound(cond compoundCondition) Matcher {
	op := strings.ToLower(strings.TrimSpace(cond.Op))
	switch op {
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
	case "if", "if_else", "ifelse":
		if cond.If == nil || cond.Then == nil {
			return &neverMatcher{}
		}
		var elseMatch Matcher
		if cond.Else != nil {
			elseMatch = buildCompound(*cond.Else)
		}
		return &ifElseMatcher{condition: buildCompound(*cond.If), thenMatch: buildCompound(*cond.Then), elseMatch: elseMatch}
	case "cc_rate":
		if len(cond.Children) == 0 {
			return &neverMatcher{}
		}
		return &ccRateMatcher{
			child:     buildCompound(cond.Children[0]),
			window:    cond.Window,
			threshold: cond.Threshold,
			duration:  cond.Duration,
			clients:   make(map[string]*ccRateState),
		}
	default:
		if cond.If != nil && cond.Then != nil {
			var elseMatch Matcher
			if cond.Else != nil {
				elseMatch = buildCompound(*cond.Else)
			}
			return &ifElseMatcher{condition: buildCompound(*cond.If), thenMatch: buildCompound(*cond.Then), elseMatch: elseMatch}
		}
		if cond.Kind != "" {
			return buildMatcher(cond.Kind, cond.Arg)
		}
		return &neverMatcher{}
	}
}
