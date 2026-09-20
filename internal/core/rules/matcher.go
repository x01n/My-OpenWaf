package rules

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	state     *ccRateSharedState
}

type ccRateSharedState struct {
	mu        sync.Mutex
	clients   map[string]*ccRateState
	lastSweep int64
}

type ccRateState struct {
	count       int64
	windowUntil int64
	blockedTill int64
}

var ccRateStates sync.Map

func (m *ccRateMatcher) Match(ctx MatchCtx) bool {
	if m.child == nil || !m.child.Match(ctx) {
		return false
	}
	if m.window <= 0 || m.threshold <= 0 {
		return true
	}

	now := time.Now().Unix()
	stateStore := m.state
	if stateStore == nil {
		stateStore = newCCRateSharedState()
		m.state = stateStore
	}
	key := ccRateKey(ctx)
	stateStore.mu.Lock()
	defer stateStore.mu.Unlock()
	if stateStore.clients == nil {
		stateStore.clients = make(map[string]*ccRateState)
	}
	if now-stateStore.lastSweep >= 60 {
		for k, state := range stateStore.clients {
			if state == nil || (state.windowUntil <= now && state.blockedTill <= now) {
				delete(stateStore.clients, k)
			}
		}
		stateStore.lastSweep = now
	}
	state := stateStore.clients[key]
	if state != nil && state.blockedTill > now {
		return true
	}
	if state == nil || state.windowUntil <= now {
		state = &ccRateState{windowUntil: now + m.window}
		stateStore.clients[key] = state
	}
	state.count++
	if state.count < m.threshold {
		return false
	}
	if m.duration > 0 {
		state.blockedTill = now + m.duration
	}
	return true
}

func newCCRateSharedState() *ccRateSharedState {
	return &ccRateSharedState{clients: make(map[string]*ccRateState)}
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

// containsFoldASCIIBytes performs case-insensitive substring search on []byte
// without allocating a string copy.
func containsFoldASCIIBytes(s []byte, substr string) bool {
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

// exactNotMatcher negates an exact matcher without changing the exact side's semantics.
// It is used by the UI `ne` mappings so `ne` is not implemented as not-contains.
type exactNotMatcher struct{ child Matcher }

func (m *exactNotMatcher) Match(ctx MatchCtx) bool {
	return !m.child.Match(ctx)
}

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

type headerExactMatcher struct{ name, value string }

func (m *headerExactMatcher) Match(ctx MatchCtx) bool {
	value, ok := lookupHeaderValueInCtx(ctx, m.name)
	return ok && value == m.value
}

type headerPrefixMatcher struct{ name, prefix string }

func (m *headerPrefixMatcher) Match(ctx MatchCtx) bool {
	value, ok := lookupHeaderValueInCtx(ctx, m.name)
	return ok && strings.HasPrefix(value, m.prefix)
}

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
		for value != "" {
			token := value
			if i := strings.IndexByte(value, ','); i >= 0 {
				token = value[:i]
				value = value[i+1:]
			} else {
				value = ""
			}
			if strings.EqualFold(strings.TrimSpace(token), m.value) {
				return true
			}
		}
		return false
	}
	if m.name == "x-owaf-tls-ja3-hash" {
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
	for value != "" {
		token := value
		if i := strings.IndexByte(value, ','); i >= 0 {
			token = value[:i]
			value = value[i+1:]
		} else {
			value = ""
		}
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

type fullURLExactMatcher struct{ value string }

func (m *fullURLExactMatcher) Match(ctx MatchCtx) bool {
	return requestURLValue(ctx) == m.value
}

type bodyExactMatcher struct{ value []byte }

func (m *bodyExactMatcher) Match(ctx MatchCtx) bool {
	return len(ctx.Body) > 0 && bytes.Equal(ctx.Body, m.value)
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

type queryParamExactMatcher struct {
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

func (m *queryParamExactMatcher) Match(ctx MatchCtx) bool {
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
		if item == m.value {
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
	if fullLower == "" {
		return nameOnly, fullLower
	}

	// A bare IPv6 literal contains colons but no port separator. Check it
	// before the hostname:port fallback so the final numeric hextet is kept.
	if net.ParseIP(fullLower) != nil {
		return fullLower, fullLower
	}

	// Normalize bracketed IPv6 literals to the same hostname form as bare
	// literals. Only a numeric suffix is treated as a port, preserving the
	// existing behavior for non-numeric port-like text.
	if strings.HasPrefix(fullLower, "[") {
		if close := strings.IndexByte(fullLower, ']'); close > 0 {
			literal := fullLower[1:close]
			if net.ParseIP(literal) == nil || !strings.Contains(literal, ":") {
				return nameOnly, fullLower
			}
			if close == len(fullLower)-1 {
				return literal, fullLower
			}
			if close+1 < len(fullLower) && fullLower[close+1] == ':' && isNumericHostPort(fullLower[close+2:]) {
				return literal, fullLower
			}
			return nameOnly, fullLower
		}
	}

	if i := strings.LastIndex(fullLower, ":"); i > 0 && isNumericHostPort(fullLower[i+1:]) {
		nameOnly = fullLower[:i]
	}
	return nameOnly, fullLower
}

func isNumericHostPort(port string) bool {
	if port == "" {
		return false
	}
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func hostPortHeaderPort(host string) (string, bool) {
	raw := strings.TrimSpace(host)
	if raw == "" {
		return "", false
	}
	if strings.HasPrefix(raw, "[") {
		if close := strings.IndexByte(raw, ']'); close > 0 {
			literal := raw[1:close]
			if net.ParseIP(literal) != nil && strings.Contains(literal, ":") && close+1 < len(raw) && raw[close+1] == ':' && isNumericHostPort(raw[close+2:]) {
				return raw[close+2:], true
			}
		}
		return "", false
	}
	if net.ParseIP(raw) != nil {
		return "", false
	}
	if i := strings.LastIndex(raw, ":"); i > 0 && isNumericHostPort(raw[i+1:]) {
		return raw[i+1:], true
	}
	return "", false
}

// hostFullMatcher matches Host including explicit port; wildcard applies to hostname only.
type hostFullMatcher struct{ pattern string }

func (m *hostFullMatcher) Match(ctx MatchCtx) bool {
	hostName, fullLower := splitHostPortHeader(hostValue(ctx))
	if hostName == "" {
		return false
	}
	patName, patFull := splitHostPortHeader(m.pattern)
	if patName == "" {
		return false
	}

	if strings.HasPrefix(patName, "*.") {
		suffix := patName[1:]
		if !(strings.HasSuffix(hostName, suffix) || hostName == strings.TrimPrefix(patName, "*.")) {
			return false
		}
		patPort, hasPatPort := hostPortHeaderPort(patFull)
		if !hasPatPort {
			return true
		}
		hostPort, hasHostPort := hostPortHeaderPort(fullLower)
		return hasHostPort && hostPort == patPort
	}

	if hostName != patName {
		return fullLower == patFull
	}
	patPort, hasPatPort := hostPortHeaderPort(patFull)
	if !hasPatPort {
		// Keep the existing compatibility behavior: a portless pattern
		// matches the same hostname whether the request supplies a port.
		return true
	}
	hostPort, hasHostPort := hostPortHeaderPort(fullLower)
	return hasHostPort && hostPort == patPort
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

func requestURLValue(ctx MatchCtx) string {
	u := ctx.Path
	if ctx.Query != "" {
		u += "?" + ctx.Query
	}
	return u
}

// fullURLContainsMatcher matches path + raw query (lowercased) for a substring.
type fullURLContainsMatcher struct{ substr string }

func (m *fullURLContainsMatcher) Match(ctx MatchCtx) bool {
	return containsFoldASCII(requestURLValue(ctx), m.substr)
}

// fullURLRegexMatcher matches path + raw query against a regex.
type fullURLRegexMatcher struct{ re *regexp.Regexp }

func (m *fullURLRegexMatcher) Match(ctx MatchCtx) bool {
	return m.re.MatchString(requestURLValue(ctx))
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

// errBadWildcard 表示通配符模式本身语法非法（字符类未闭合、转义符悬空等）。
var errBadWildcard = errors.New("syntax error in wildcard pattern")

const maxUnescapedWildcardStars = 8

// countUnescapedWildcardStars 只统计类外、未转义的通配星号。
func countUnescapedWildcardStars(pattern string) int {
	count := 0
	inClass := false
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			if i+1 < len(pattern) {
				i++
			}
		case '[':
			if !inClass {
				inClass = true
			}
		case ']':
			inClass = false
		case '*':
			if !inClass {
				count++
			}
		}
	}
	return count
}

/**
 * globToRegexSource 把通配符模式翻译为锚定的正则源码。
 *
 * 语义是**有意**偏离 path.Match / filepath.Match 的：本实现中 `*` 匹配任意字符
 * 序列，包含 `/` 与换行。标准库把 `*` 限制在单个路径段内是为文件系统遍历设计的，
 * 而 WAF 的匹配目标（header 值如 "Mozilla/5.0"、请求体、含 query 的完整 URL）
 * 天然含 `/`，沿用段边界语义会让 `*bot*` 之类的规则静默永不命中——与本包历史上
 * neverMatcher 那类"配了但不生效"的缺陷同源。
 *
 * 支持 `?`（任意单字符）、`[...]`/`[^...]`/`[!...]`（字符类，两种取反写法均可）、
 * `\` 转义。翻译结果交给 cachedCompile 走全局正则缓存，因此热路径上不存在
 * 每请求重复解析模式串的开销，且 RE2 的线性时间保证使恶意模式无法放大成回溯爆炸。
 *
 * @param pattern         通配符模式
 * @param caseInsensitive 是否大小写不敏感（由各 kind 依既有同类匹配器惯例决定）
 * @return 正则源码；模式非法时返回 errBadWildcard
 */
func globToRegexSource(pattern string, caseInsensitive bool) (string, error) {
	parsed, err := parseGlob(pattern)
	if err != nil {
		return "", err
	}
	return parsed.regexSource(caseInsensitive), nil
}

// parsedGlob 是通配符模式的一次性解析结果，同时携带正则源码与结构信息，
// 供上层选择字符串快路径或回落 RE2。
type parsedGlob struct {
	body     string // 去掉首尾通配星号后的正则片段
	literal  string // body 为纯字面量时的原文；否则为空
	isConcat bool   // body 是否为纯字面量（无 `*`/`?`/字符类）
	starHead bool   // 模式以未转义的 `*` 开头
	starTail bool   // 模式以未转义的 `*` 结尾
}

/**
 * regexSource 拼出可交给 cachedCompile 的正则源码。
 *
 * 首尾的 `*` 不再翻译成 `\A.*` / `.*\z`，而是直接省掉对应锚点：`MatchString`
 * 本就是非锚定搜索，二者语义等价，但省掉前导 `.*` 才能让 RE2 用上字面量
 * 预扫描（memchr）优化。实测 2 KiB 请求体上该改动把 24µs/op 降到亚微秒级。
 */
func (p parsedGlob) regexSource(caseInsensitive bool) string {
	var sb strings.Builder
	sb.Grow(len(p.body) + 12)
	// (?s) 让 `.` 覆盖换行，避免攻击载荷靠插入换行绕过 `*`。
	sb.WriteString("(?s)")
	if caseInsensitive {
		sb.WriteString("(?i)")
	}
	if !p.starHead {
		sb.WriteString(`\A`)
	}
	sb.WriteString(p.body)
	if !p.starTail {
		sb.WriteString(`\z`)
	}
	return sb.String()
}

/**
 * parseGlob 单趟解析通配符模式，产出正则片段与结构信息。
 *
 * 空模式只会匹配空目标串，等同于永不命中，在此统一拒绝，使保存期校验与
 * 运行期编译对"什么算不可用模式"的判断天然一致，不会一边放行一边拒绝。
 */
func parseGlob(pattern string) (parsedGlob, error) {
	if strings.TrimSpace(pattern) == "" || !utf8.ValidString(pattern) || countUnescapedWildcardStars(pattern) > maxUnescapedWildcardStars {
		return parsedGlob{}, errBadWildcard
	}
	// 星号数量必须在归并前统计，连续的未转义星号也占用规则复杂度预算。
	pattern = collapseGlobStars(pattern)

	var sb strings.Builder
	sb.Grow(len(pattern) + 8)
	var lit strings.Builder
	lit.Grow(len(pattern))

	out := parsedGlob{isConcat: true}
	// 首尾星号单独剥离，因此需要知道每个星号处于什么位置。
	for i := 0; i < len(pattern); {
		switch ch := pattern[i]; ch {
		case '*':
			if i == 0 {
				out.starHead = true
				i++
				continue
			}
			if i == len(pattern)-1 {
				out.starTail = true
				i++
				continue
			}
			sb.WriteString(".*")
			out.isConcat = false
			i++
		case '?':
			sb.WriteString(".")
			out.isConcat = false
			i++
		case '\\':
			// 悬空转义符视为非法，与 path.Match 对 `/a\` 的处理一致。
			if i+1 >= len(pattern) {
				return parsedGlob{}, errBadWildcard
			}
			_, size := utf8.DecodeRuneInString(pattern[i+1:])
			escaped := pattern[i+1 : i+1+size]
			sb.WriteString(regexp.QuoteMeta(escaped))
			lit.WriteString(escaped)
			i += 1 + size
		case '[':
			consumed, err := appendGlobCharClass(&sb, pattern[i:])
			if err != nil {
				return parsedGlob{}, err
			}
			out.isConcat = false
			i += consumed
		default:
			_, size := utf8.DecodeRuneInString(pattern[i:])
			literal := pattern[i : i+size]
			sb.WriteString(regexp.QuoteMeta(literal))
			lit.WriteString(literal)
			i += size
		}
	}

	out.body = sb.String()
	if out.isConcat {
		out.literal = lit.String()
	}
	return out, nil
}

/**
 * appendGlobCharClass 翻译一个 `[...]` 字符类并写入 sb。
 *
 * 类内 `-` 原样保留以维持区间语义，其余字节一律按正则类内元字符转义，
 * 因此 `[[:alpha:]]` 这类 POSIX 类名会退化为字面字符集合（glob 本就不支持它）。
 * 字面 `]` 必须写作 `\]`；紧跟在 `[` 或取反标记后的裸 `]` 判为空类并报错。
 *
 * @param sb  输出缓冲
 * @param s   以 `[` 开头的剩余模式串
 * @return 消耗的字节数；未闭合或空类时返回 errBadWildcard
 */
func appendGlobCharClass(sb *strings.Builder, s string) (int, error) {
	i := 1 // 跳过 '['
	sb.WriteByte('[')
	if i < len(s) && (s[i] == '^' || s[i] == '!') {
		sb.WriteByte('^')
		i++
	}
	empty := true
	for {
		if i >= len(s) {
			return 0, errBadWildcard
		}
		ch, size := utf8.DecodeRuneInString(s[i:])
		if ch == ']' {
			if empty {
				return 0, errBadWildcard
			}
			sb.WriteByte(']')
			return i + 1, nil
		}
		if ch == '\\' {
			if i+size >= len(s) {
				return 0, errBadWildcard
			}
			escaped, escapedSize := utf8.DecodeRuneInString(s[i+size:])
			sb.WriteString(escapeCharClassByte(escaped))
			i += size + escapedSize
			empty = false
			continue
		}
		if ch == '-' {
			sb.WriteByte('-')
		} else {
			sb.WriteString(escapeCharClassByte(ch))
		}
		i += size
		empty = false
	}
}

/**
 * collapseGlobStars 把连续的未转义星号归并为一个。
 *
 * 转义对（`\x`）整体原样保留，因此 `a\**` 中的字面星号不会与后面的通配星号
 * 归并。字符类内部不含通配星号语义，无需特殊处理：类内的 `*` 是普通字符，
 * 而本函数只在类外归并——为此需跳过整个 `[...]` 块。
 */
func collapseGlobStars(pattern string) string {
	if !strings.Contains(pattern, "**") {
		return pattern
	}
	var sb strings.Builder
	sb.Grow(len(pattern))
	for i := 0; i < len(pattern); {
		switch ch := pattern[i]; ch {
		case '\\':
			sb.WriteByte(ch)
			if i+1 < len(pattern) {
				sb.WriteByte(pattern[i+1])
				i += 2
				continue
			}
			i++
		case '[':
			// 类内原样复制到闭合处，避免把类内的 `*` 当通配符归并。
			j := i + 1
			if j < len(pattern) && (pattern[j] == '^' || pattern[j] == '!') {
				j++
			}
			for j < len(pattern) && pattern[j] != ']' {
				if pattern[j] == '\\' {
					j++
				}
				j++
			}
			if j < len(pattern) {
				j++ // 含闭合的 ']'
			}
			sb.WriteString(pattern[i:j])
			i = j
		case '*':
			sb.WriteByte('*')
			for i < len(pattern) && pattern[i] == '*' {
				i++
			}
		default:
			sb.WriteByte(ch)
			i++
		}
	}
	return sb.String()
}

// escapeCharClassByte 转义正则字符类内部有特殊含义的字节。
func escapeCharClassByte(ch rune) string {
	switch ch {
	case '\\', ']', '^', '[', '-':
		return `\` + string(ch)
	default:
		return regexp.QuoteMeta(string(ch))
	}
}

// wildcardShape 是通配符模式的形态，决定走哪条匹配实现。
type wildcardShape uint8

const (
	wcRegex    wildcardShape = iota // 一般形态，交给 RE2
	wcAny                           // 纯星号，恒真
	wcExact                         // "abc"
	wcContains                      // "*abc*"
	wcPrefix                        // "abc*"
	wcSuffix                        // "*abc"
)

/**
 * wildcardTester 是编译后的通配符测试器。
 *
 * 绝大多数真实规则是 `*foo*` / `foo*` / `*foo` / `foo` 四种纯字面量形态，
 * 这些形态退化为 strings/bytes 的子串与前后缀比较，避免进 RE2；其余形态
 * （含 `?`、字符类、中缀星号）才编译成正则。这样做的依据是实测数据：未加
 * 快路径时 2 KiB 请求体上 `*<script>*` 为 24µs/op，加快路径后进入亚微秒级。
 */
type wildcardTester struct {
	shape wildcardShape
	lit   string
	litB  []byte
	fold  bool
	re    *regexp.Regexp
}

/**
 * compileWildcard 把通配符模式编译为测试器。
 *
 * 失败方向为 fail-closed（调用方回落 neverMatcher）：非法模式在保存期已被
 * ValidatePattern 拒绝，运行期还能走到这里只可能是绕过 Admin 直改数据库，
 * 此时宁可该规则不生效，也不能让一条语法错误的规则拦下全部流量。这与
 * 本包既有全部 *_regex kind 的处理方向一致。
 *
 * @param caseInsensitive 大小写不敏感。仅 `*foo*` 形态用 ASCII 折叠比较复用
 *                        containsFoldASCII，其余形态回落正则的 (?i)，避免在
 *                        本包内引入第二套折叠语义。
 */
func compileWildcard(pattern string, caseInsensitive bool) (*wildcardTester, error) {
	parsed, err := parseGlob(pattern)
	if err != nil {
		return nil, err
	}

	if parsed.isConcat {
		lit := parsed.literal
		if caseInsensitive {
			// containsFoldASCII 两侧都折叠，此处小写化只为与 full_url_contains
			// 传入小写 arg 的既有写法保持一致。
			lit = strings.ToLower(lit)
		}
		shape := wcRegex
		switch {
		case lit == "":
			shape = wcAny
		case parsed.starHead && parsed.starTail:
			shape = wcContains
		case !caseInsensitive && !parsed.starHead && !parsed.starTail:
			shape = wcExact
		case !caseInsensitive && parsed.starTail:
			shape = wcPrefix
		case !caseInsensitive && parsed.starHead:
			shape = wcSuffix
		}
		if shape != wcRegex {
			return &wildcardTester{shape: shape, lit: lit, litB: []byte(lit), fold: caseInsensitive}, nil
		}
	}

	re, err := cachedCompile(parsed.regexSource(caseInsensitive))
	if err != nil {
		return nil, err
	}
	return &wildcardTester{shape: wcRegex, re: re}, nil
}

// matchString 对字符串目标求值。
func (w *wildcardTester) matchString(s string) bool {
	switch w.shape {
	case wcAny:
		return true
	case wcExact:
		return s == w.lit
	case wcContains:
		if w.fold {
			return containsFoldASCII(s, w.lit)
		}
		return strings.Contains(s, w.lit)
	case wcPrefix:
		return strings.HasPrefix(s, w.lit)
	case wcSuffix:
		return strings.HasSuffix(s, w.lit)
	default:
		return w.re.MatchString(s)
	}
}

// matchBytes 对字节目标求值，避免请求体的 []byte→string 拷贝。
func (w *wildcardTester) matchBytes(b []byte) bool {
	switch w.shape {
	case wcAny:
		return true
	case wcExact:
		return bytes.Equal(b, w.litB)
	case wcContains:
		if w.fold {
			return containsFoldASCIIBytes(b, w.lit)
		}
		return bytes.Contains(b, w.litB)
	case wcPrefix:
		return bytes.HasPrefix(b, w.litB)
	case wcSuffix:
		return bytes.HasSuffix(b, w.litB)
	default:
		return w.re.Match(b)
	}
}

// pathWildcardMatcher 对原始请求路径做通配符匹配（大小写敏感，与 path_contains 一致）。
type pathWildcardMatcher struct{ w *wildcardTester }

func (m *pathWildcardMatcher) Match(ctx MatchCtx) bool {
	return m.w.matchString(ctx.Path)
}

// fullURLWildcardMatcher 对 路径 + "?" + 原始 query 做通配符匹配
// （大小写不敏感，与 full_url_contains 一致）。
type fullURLWildcardMatcher struct{ w *wildcardTester }

func (m *fullURLWildcardMatcher) Match(ctx MatchCtx) bool {
	u := ctx.Path
	if ctx.Query != "" {
		u += "?" + ctx.Query
	}
	return m.w.matchString(u)
}

// hostWildcardMatcher 对去端口后的 Host 做通配符匹配。
// 模式与 Host 两侧在构造/取值时均已小写，因此无需再做折叠。
type hostWildcardMatcher struct{ w *wildcardTester }

func (m *hostWildcardMatcher) Match(ctx MatchCtx) bool {
	raw := strings.TrimSpace(hostValue(ctx))
	if raw == "" {
		return false
	}
	hostName, _ := splitHostPortHeader(raw)
	return m.w.matchString(hostName)
}

// bodyWildcardMatcher 对请求体做通配符匹配（大小写敏感，与 body_contains 一致）。
type bodyWildcardMatcher struct{ w *wildcardTester }

func (m *bodyWildcardMatcher) Match(ctx MatchCtx) bool {
	return len(ctx.Body) > 0 && m.w.matchBytes(ctx.Body)
}

// headerWildcardMatcher 对指定请求头的值做通配符匹配
// （头名小写查找、值大小写敏感，与 headerContainsMatcher / headerRegexMatcher 一致）。
type headerWildcardMatcher struct {
	name string
	w    *wildcardTester
}

func (m *headerWildcardMatcher) Match(ctx MatchCtx) bool {
	value, ok := lookupHeaderValueInCtx(ctx, m.name)
	return ok && m.w.matchString(value)
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

	case "block_header_exact":
		name, value := splitHeaderArg(arg)
		return &headerExactMatcher{name: strings.ToLower(name), value: value}

	case "block_header_not_exact":
		name, value := splitHeaderArg(arg)
		return &exactNotMatcher{child: &headerExactMatcher{name: strings.ToLower(name), value: value}}

	case "block_header_prefix":
		name, prefix := splitHeaderArg(arg)
		return &headerPrefixMatcher{name: strings.ToLower(name), prefix: prefix}

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

	case "path_not_exact":
		return &exactNotMatcher{child: &exactPathMatcher{path: arg}}

	case "full_url_not_exact":
		return &exactNotMatcher{child: &fullURLExactMatcher{value: arg}}

	case "host_not_exact":
		return &exactNotMatcher{child: &hostMatcher{pattern: strings.ToLower(arg)}}

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

	case "body_not_exact":
		return &exactNotMatcher{child: &bodyExactMatcher{value: []byte(arg)}}

	case "body_regex", "block_body_regex":
		re, err := cachedCompile(arg)
		if err != nil {
			return &neverMatcher{}
		}
		return &bodyRegexMatcher{re: re}

	case "query_param":
		param, value := splitHeaderArg(arg)
		return &queryParamMatcher{param: param, value: value}

	case "query_param_not_exact":
		param, value := splitHeaderArg(arg)
		return &exactNotMatcher{child: &queryParamExactMatcher{param: param, value: value}}

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

	case "path_wildcard":
		w, err := compileWildcard(arg, false)
		if err != nil {
			return &neverMatcher{}
		}
		return &pathWildcardMatcher{w: w}

	case "full_url_wildcard":
		w, err := compileWildcard(arg, true)
		if err != nil {
			return &neverMatcher{}
		}
		return &fullURLWildcardMatcher{w: w}

	case "host_wildcard":
		// 模式在此小写、Host 取值经 splitHostPortHeader 也已小写，
		// 故按大小写敏感编译即可，顺带用上字面量快路径。
		w, err := compileWildcard(strings.ToLower(arg), false)
		if err != nil {
			return &neverMatcher{}
		}
		return &hostWildcardMatcher{w: w}

	case "body_wildcard":
		w, err := compileWildcard(arg, false)
		if err != nil {
			return &neverMatcher{}
		}
		return &bodyWildcardMatcher{w: w}

	case "header_wildcard":
		name, pattern := splitHeaderArg(arg)
		if pattern == "" {
			return &neverMatcher{}
		}
		w, err := compileWildcard(pattern, false)
		if err != nil {
			return &neverMatcher{}
		}
		return &headerWildcardMatcher{name: strings.ToLower(name), w: w}

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

type compoundCondition struct {
	Op              string              `json:"op"`
	Kind            string              `json:"kind"`
	Arg             string              `json:"arg"`
	Children        []compoundCondition `json:"children"`
	If              *compoundCondition  `json:"if"`
	Then            *compoundCondition  `json:"then"`
	Else            *compoundCondition  `json:"else"`
	Window          int64               `json:"window"`
	Threshold       int64               `json:"threshold"`
	Duration        int64               `json:"duration"`
	DurationUnit    string              `json:"duration_unit"`
	DurationSeconds int64               `json:"duration_seconds"`
}

func parseCompoundJSON(raw string) Matcher {
	var cond compoundCondition
	if err := json.Unmarshal([]byte(raw), &cond); err != nil {
		return &neverMatcher{}
	}
	var validation compoundPattern
	if err := json.Unmarshal([]byte(raw), &validation); err != nil || len(validateCompoundNode(validation)) != 0 {
		return &neverMatcher{}
	}
	return buildCompound(cond)
}

func ccRateDurationSeconds(cond compoundCondition) int64 {
	if cond.DurationSeconds > 0 {
		return cond.DurationSeconds
	}
	return ccDurationSeconds(cond.Duration, cond.DurationUnit)
}

func ccDurationSeconds(duration int64, unit string) int64 {
	if duration <= 0 {
		return 0
	}
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "seconds", "second", "sec", "s":
		return duration
	case "", "minutes", "minute", "min", "m":
		return duration * 60
	default:
		return duration * 60
	}
}

func ccRateStateKey(cond compoundCondition) string {
	keyData := struct {
		Child           compoundCondition `json:"child"`
		Window          int64             `json:"window"`
		Threshold       int64             `json:"threshold"`
		DurationSeconds int64             `json:"duration_seconds"`
	}{
		Child:           cond.Children[0],
		Window:          cond.Window,
		Threshold:       cond.Threshold,
		DurationSeconds: ccRateDurationSeconds(cond),
	}
	raw, err := json.Marshal(keyData)
	if err != nil {
		raw = []byte(cond.Op)
	}
	sum := md5.Sum(raw)
	return "cc_rate:" + hex.EncodeToString(sum[:])
}

func buildCompound(cond compoundCondition) Matcher {
	op := strings.ToLower(strings.TrimSpace(cond.Op))
	switch op {
	case "and", "or":
		if len(cond.Children) == 0 {
			return &neverMatcher{}
		}
		children := make([]Matcher, 0, len(cond.Children))
		for _, ch := range cond.Children {
			children = append(children, buildCompound(ch))
		}
		if op == "and" {
			return &andMatcher{children: children}
		}
		return &orMatcher{children: children}
	case "not":
		if len(cond.Children) != 1 {
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
		if len(cond.Children) != 1 || cond.Window <= 0 || cond.Threshold <= 0 || cond.Duration < 0 || cond.DurationSeconds < 0 || !validCompoundDurationUnit(cond.DurationUnit) {
			return &neverMatcher{}
		}
		stateKey := ccRateStateKey(cond)
		state, _ := ccRateStates.LoadOrStore(stateKey, newCCRateSharedState())
		return &ccRateMatcher{
			child:     buildCompound(cond.Children[0]),
			window:    cond.Window,
			threshold: cond.Threshold,
			duration:  ccRateDurationSeconds(cond),
			state:     state.(*ccRateSharedState),
		}
	case "":
		if cond.Kind != "" {
			return buildMatcher(cond.Kind, cond.Arg)
		}
		return &neverMatcher{}
	default:
		return &neverMatcher{}
	}
}
