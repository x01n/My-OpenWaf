package rules

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"My-OpenWaf/internal/tlsmeta"
)

// Matcher tests a single condition against request fields.
type Matcher interface {
	Match(ctx MatchCtx) bool
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

func (m *ccRateMatcher) Match(ctx MatchCtx) bool {
	if m.child == nil || !m.child.Match(ctx) {
		return false
	}
	if m.window <= 0 || m.threshold <= 0 {
		return true
	}

	now := time.Now().Unix()
	key := ccRateKey(ctx)
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

func ccRateKey(ctx MatchCtx) string {
	client := ""
	if ctx.ClientIP != nil {
		client = ctx.ClientIP.String()
	}
	return client + "|" + hostValue(ctx)
}

func headerValue(ctx MatchCtx, name string) string {
	value, _ := lookupHeaderValueInCtx(ctx, name)
	return value
}

func lookupHeaderValueInCtx(ctx MatchCtx, name string) (string, bool) {
	if ctx.HeadersLowercase {
		if value, ok := ctx.Headers[name]; ok {
			return value, true
		}
		if lower, changed := lowerASCIIIfNeeded(name); changed {
			if value, ok := ctx.Headers[lower]; ok {
				return value, true
			}
		}
		return "", false
	}
	return lookupHeaderValue(ctx.Headers, name)
}

func lookupHeaderValue(headers map[string]string, name string) (string, bool) {
	if value, ok := headers[name]; ok {
		return value, true
	}
	if lower, changed := lowerASCIIIfNeeded(name); changed {
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

func headerOrderValue(ctx MatchCtx) string {
	if ctx.HeaderOrder != "" {
		return ctx.HeaderOrder
	}
	return headerValue(ctx, "x-owaf-header-order")
}

func tlsFingerprintValue(ctx MatchCtx, name string) string {
	if ctx.TLS == nil {
		switch name {
		case "x-owaf-tls-alpn":
			return ctx.TLSALPN
		case tlsCipherSuitesHeaderLower:
			return ctx.TLSCipherSuites
		default:
			return headerValue(ctx, name)
		}
	}
	switch name {
	case "x-owaf-tls-ja3":
		if ctx.TLS.JA3 != "" {
			return ctx.TLS.JA3
		}
	case "x-owaf-tls-ja3-hash":
		if ctx.TLS.JA3Hash != "" {
			return ctx.TLS.JA3Hash
		}
	case "x-owaf-tls-ja4":
		if ctx.TLS.JA4 != "" {
			return ctx.TLS.JA4
		}
	case "x-owaf-tls-version":
		if ctx.TLS.TLSVersion != "" {
			return ctx.TLS.TLSVersion
		}
	case "x-owaf-tls-sni":
		if ctx.TLS.SNI != "" {
			return ctx.TLS.SNI
		}
	case "x-owaf-tls-alpn":
		if ctx.TLSALPN != "" {
			return ctx.TLSALPN
		}
	case tlsCipherSuitesHeaderLower:
		if ctx.TLSCipherSuites != "" {
			return ctx.TLSCipherSuites
		}
	}
	return headerValue(ctx, name)
}

func tlsCipherSuitesValue(ctx MatchCtx) string {
	if ctx.TLSCipherSuites != "" {
		return ctx.TLSCipherSuites
	}
	return headerValue(ctx, tlsCipherSuitesHeaderLower)
}

func lowerASCIIIfNeeded(raw string) (string, bool) {
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if 'A' <= b && b <= 'Z' {
			return strings.ToLower(raw), true
		}
	}
	return raw, false
}

func asciiLowerByte(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func containsFoldASCII(s, substr string) bool {
	n := len(substr)
	if n == 0 {
		return true
	}
	if n > len(s) {
		return false
	}
	first := asciiLowerByte(substr[0])
	last := len(s) - n
	for i := 0; i <= last; i++ {
		if asciiLowerByte(s[i]) != first {
			continue
		}
		match := true
		for j := 1; j < n; j++ {
			if asciiLowerByte(s[i+j]) != asciiLowerByte(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ── compound matchers ──

type andMatcher struct{ children []Matcher }

func (m *andMatcher) Match(ctx MatchCtx) bool {
	for _, c := range m.children {
		if !c.Match(ctx) {
			return false
		}
	}
	return len(m.children) > 0
}

type orMatcher struct{ children []Matcher }

func (m *orMatcher) Match(ctx MatchCtx) bool {
	for _, c := range m.children {
		if c.Match(ctx) {
			return true
		}
	}
	return false
}

type notMatcher struct{ child Matcher }

func (m *notMatcher) Match(ctx MatchCtx) bool {
	return !m.child.Match(ctx)
}

// ── concrete matchers ──

type ipCIDRMatcher struct{ cidr *net.IPNet }

func (m *ipCIDRMatcher) Match(ctx MatchCtx) bool {
	return ctx.ClientIP != nil && m.cidr.Contains(ctx.ClientIP)
}

type pathPrefixMatcher struct{ prefix string }

func (m *pathPrefixMatcher) Match(ctx MatchCtx) bool {
	return strings.HasPrefix(ctx.Path, m.prefix)
}

type pathRegexMatcher struct{ re *regexp.Regexp }

func (m *pathRegexMatcher) Match(ctx MatchCtx) bool {
	return m.re.MatchString(ctx.Path)
}

type queryContainsMatcher struct{ substr string }

func (m *queryContainsMatcher) Match(ctx MatchCtx) bool {
	return strings.Contains(ctx.Query, m.substr)
}

type queryRegexMatcher struct{ re *regexp.Regexp }

func (m *queryRegexMatcher) Match(ctx MatchCtx) bool {
	return m.re.MatchString(ctx.Query)
}

type headerContainsMatcher struct{ name, substr string }

func (m *headerContainsMatcher) Match(ctx MatchCtx) bool {
	value, ok := lookupHeaderValueInCtx(ctx, m.name)
	return ok && strings.Contains(value, m.substr)
}

type headerRegexMatcher struct {
	name string
	re   *regexp.Regexp
}

type headerOrderContainsMatcher struct{ substr string }

func (m *headerOrderContainsMatcher) Match(ctx MatchCtx) bool {
	return strings.Contains(headerOrderValue(ctx), m.substr)
}

type headerOrderRegexMatcher struct{ re *regexp.Regexp }

type tlsFingerprintMatcher struct {
	name  string
	value string
}

type tlsCipherSuitesMatcher struct {
	values map[string]struct{}
}

func (m *tlsFingerprintMatcher) Match(ctx MatchCtx) bool {
	value := tlsFingerprintValue(ctx, m.name)
	if value != "" {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), m.value) {
				return true
			}
		}
	}
	if m.name == "x-owaf-tls-ja3-hash" && value == "" {
		ja3 := tlsFingerprintValue(ctx, "x-owaf-tls-ja3")
		if ja3 == "" {
			return false
		}
		sum := md5.Sum([]byte(ja3))
		return strings.EqualFold(hex.EncodeToString(sum[:]), m.value)
	}
	return false
}

func (m *tlsCipherSuitesMatcher) Match(ctx MatchCtx) bool {
	if len(m.values) == 0 {
		return false
	}
	value := tlsCipherSuitesValue(ctx)
	if value == "" {
		return false
	}
	for _, token := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(token)
		if _, ok := m.values[trimmed]; ok {
			return true
		}
		normalized := normalizeTLSCipherSuiteToken(trimmed)
		if normalized != "" && normalized != trimmed {
			if _, ok := m.values[normalized]; ok {
				return true
			}
		}
	}
	return false
}

func (m *headerOrderRegexMatcher) Match(ctx MatchCtx) bool {
	return m.re.MatchString(headerOrderValue(ctx))
}

func (m *headerRegexMatcher) Match(ctx MatchCtx) bool {
	value, ok := lookupHeaderValueInCtx(ctx, m.name)
	return ok && m.re.MatchString(value)
}

type exactPathMatcher struct{ path string }

func (m *exactPathMatcher) Match(ctx MatchCtx) bool {
	return ctx.Path == m.path
}

type methodMatcher struct{ method string }

func (m *methodMatcher) Match(ctx MatchCtx) bool {
	return strings.EqualFold(ctx.Method, m.method)
}

type contentTypeMatcher struct{ ctype string }

func (m *contentTypeMatcher) Match(ctx MatchCtx) bool {
	value, ok := lookupHeaderValueInCtx(ctx, "content-type")
	return ok && containsFoldASCII(value, m.ctype)
}

type alwaysMatcher struct{}

func (m *alwaysMatcher) Match(MatchCtx) bool {
	return true
}

type ifElseMatcher struct {
	condition Matcher
	thenMatch Matcher
	elseMatch Matcher
}

func (m *ifElseMatcher) Match(ctx MatchCtx) bool {
	if m.condition == nil {
		return false
	}
	if m.condition.Match(ctx) {
		return m.thenMatch != nil && m.thenMatch.Match(ctx)
	}
	return m.elseMatch != nil && m.elseMatch.Match(ctx)
}

type neverMatcher struct{}

func (m *neverMatcher) Match(MatchCtx) bool {
	return false
}

type bodyContainsMatcher struct{ substr []byte }

func (m *bodyContainsMatcher) Match(ctx MatchCtx) bool {
	return len(ctx.Body) > 0 && bytes.Contains(ctx.Body, m.substr)
}

type bodyRegexMatcher struct{ re *regexp.Regexp }

func (m *bodyRegexMatcher) Match(ctx MatchCtx) bool {
	return len(ctx.Body) > 0 && m.re.Match(ctx.Body)
}

// bodyJSONPathMatcher checks if a dot-notation JSON path exists and optionally matches a pattern.
type bodyJSONPathMatcher struct {
	jsonPath string // e.g. "$.user.role"
	pattern  *regexp.Regexp
}

func (m *bodyJSONPathMatcher) Match(ctx MatchCtx) bool {
	if len(ctx.Body) == 0 {
		return false
	}
	var raw map[string]any
	if json.Unmarshal(ctx.Body, &raw) != nil {
		return false
	}
	// Strip leading "$." if present.
	path := strings.TrimPrefix(m.jsonPath, "$.")
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

func (m *multipartMatcher) Match(ctx MatchCtx) bool {
	if len(ctx.Body) == 0 {
		return false
	}
	ct := headerValue(ctx, "content-type")
	if !containsFoldASCII(ct, "multipart/form-data") {
		return false
	}
	// Extract boundary and scan part headers for filenames.
	if lower, changed := lowerASCIIIfNeeded(ct); changed {
		ct = lower
	}
	idx := strings.Index(ct, "boundary=")
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
	bodyStr := string(ctx.Body)
	parts := strings.Split(bodyStr, "--"+boundary)
	for _, part := range parts {
		low := part
		if lowered, changed := lowerASCIIIfNeeded(part); changed {
			low = lowered
		}
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

func (m *geoBlockMatcher) Match(ctx MatchCtx) bool {
	if value, ok := lookupHeaderValueInCtx(ctx, "x-geo-country"); ok {
		code := strings.TrimSpace(strings.ToUpper(value))
		if m.countries[code] {
			return true
		}
	}
	value, ok := lookupHeaderValueInCtx(ctx, "cf-ipcountry")
	if !ok {
		return false
	}
	code := strings.TrimSpace(strings.ToUpper(value))
	return m.countries[code]
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

func (m *queryParamMatcher) Match(ctx MatchCtx) bool {
	if ctx.Query == "" || !rawQueryMayContainParam(ctx.Query, m.param) {
		return false
	}
	values, err := url.ParseQuery(ctx.Query)
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

func (m *queryParamRegexMatcher) Match(ctx MatchCtx) bool {
	if ctx.Query == "" || !rawQueryMayContainParam(ctx.Query, m.param) {
		return false
	}
	values, err := url.ParseQuery(ctx.Query)
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

func (m *pathContainsMatcher) Match(ctx MatchCtx) bool {
	return strings.Contains(ctx.Path, m.substr)
}

func (m *pathNotContainsMatcher) Match(ctx MatchCtx) bool {
	return !strings.Contains(ctx.Path, m.substr)
}

// hostMatcher matches the Host header exactly or with wildcard prefix.
type hostMatcher struct{ pattern string }

func hostValue(ctx MatchCtx) string {
	if ctx.Host != "" {
		return ctx.Host
	}
	return headerValue(ctx, "host")
}

func (m *hostMatcher) Match(ctx MatchCtx) bool {
	host, _ := splitHostPortHeader(hostValue(ctx))
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
	fullLower = strings.TrimSpace(host)
	if lower, changed := lowerASCIIIfNeeded(fullLower); changed {
		fullLower = lower
	}
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

func (m *hostFullMatcher) Match(ctx MatchCtx) bool {
	raw := strings.TrimSpace(hostValue(ctx))
	if raw == "" {
		return false
	}
	hostName, fullLower := splitHostPortHeader(raw)
	pat := strings.TrimSpace(m.pattern)
	if lower, changed := lowerASCIIIfNeeded(pat); changed {
		pat = lower
	}
	if strings.HasPrefix(pat, "*.") {
		suffix := pat[1:]
		return strings.HasSuffix(hostName, suffix) || hostName == strings.TrimPrefix(pat, "*.")
	}
	return fullLower == pat || hostName == pat
}

type hostRegexMatcher struct{ re *regexp.Regexp }

func (m *hostRegexMatcher) Match(ctx MatchCtx) bool {
	raw := strings.TrimSpace(hostValue(ctx))
	if raw == "" {
		return false
	}
	hostName, _ := splitHostPortHeader(raw)
	return m.re.MatchString(hostName)
}

type hostContainsMatcher struct{ substr string }

func (m *hostContainsMatcher) Match(ctx MatchCtx) bool {
	raw := strings.TrimSpace(hostValue(ctx))
	if raw == "" {
		return false
	}
	hostName, _ := splitHostPortHeader(raw)
	return strings.Contains(hostName, m.substr)
}

type hostNotContainsMatcher struct{ substr string }

func (m *hostNotContainsMatcher) Match(ctx MatchCtx) bool {
	raw := strings.TrimSpace(hostValue(ctx))
	if raw == "" {
		return true
	}
	hostName, _ := splitHostPortHeader(raw)
	return !strings.Contains(hostName, m.substr)
}

// fullURLContainsMatcher matches path + raw query (lowercased) for a substring.
type fullURLContainsMatcher struct{ substr string }

func (m *fullURLContainsMatcher) Match(ctx MatchCtx) bool {
	u := ctx.Path
	if ctx.Query != "" {
		u += "?" + ctx.Query
	}
	return containsFoldASCII(u, m.substr)
}

// fullURLRegexMatcher matches path + raw query against a regex.
type fullURLRegexMatcher struct{ re *regexp.Regexp }

func (m *fullURLRegexMatcher) Match(ctx MatchCtx) bool {
	u := ctx.Path
	if ctx.Query != "" {
		u += "?" + ctx.Query
	}
	return m.re.MatchString(u)
}

// cookieContainsMatcher checks if any cookie contains the given substring.
type cookieContainsMatcher struct{ substr string }

func (m *cookieContainsMatcher) Match(ctx MatchCtx) bool {
	value, ok := lookupHeaderValueInCtx(ctx, "cookie")
	return ok && strings.Contains(value, m.substr)
}

// refererContainsMatcher checks if the Referer header contains a substring.
type refererContainsMatcher struct{ substr string }

func (m *refererContainsMatcher) Match(ctx MatchCtx) bool {
	value, ok := lookupHeaderValueInCtx(ctx, "referer")
	return ok && strings.Contains(value, m.substr)
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
		normalized := tlsmeta.NormalizeRuntimeVersionToken(arg)
		if normalized == "" {
			return &neverMatcher{}
		}
		return &tlsFingerprintMatcher{name: "x-owaf-tls-version", value: normalized}

	case "tls_sni":
		return &tlsFingerprintMatcher{name: "x-owaf-tls-sni", value: arg}

	case "tls_alpn":
		return &tlsFingerprintMatcher{name: "x-owaf-tls-alpn", value: arg}

	case "tls_cipher_suite", "tls_cipher_suites":
		values := make(map[string]struct{})
		for _, token := range strings.Split(arg, ",") {
			normalized := normalizeTLSCipherSuiteToken(token)
			if normalized == "" {
				continue
			}
			values[normalized] = struct{}{}
		}
		if len(values) == 0 {
			return &neverMatcher{}
		}
		return &tlsCipherSuitesMatcher{values: values}

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
		return &bodyContainsMatcher{substr: []byte(arg)}

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
		return &hostFullMatcher{pattern: strings.ToLower(arg)}

	case "full_url_contains":
		return &fullURLContainsMatcher{substr: strings.ToLower(arg)}

	case "full_url_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &fullURLRegexMatcher{re: re}

	case "host":
		return &hostMatcher{pattern: strings.ToLower(arg)}

	case "host_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &hostRegexMatcher{re: re}

	case "host_contains":
		return &hostContainsMatcher{substr: strings.ToLower(arg)}

	case "host_not_contains":
		return &hostNotContainsMatcher{substr: strings.ToLower(arg)}

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
