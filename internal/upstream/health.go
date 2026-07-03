package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	defaultHTTPProbeTCPKeepAlive        = 30 * time.Second
	defaultHTTPProbeIdleConnTimeout     = 90 * time.Second
	defaultHTTPProbeTLSHandshakeTimeout = 10 * time.Second
	defaultHTTPProbeExpectContinue      = time.Second
	defaultHTTPProbeQUICHandshakeIdle   = 5 * time.Second
	defaultHTTPProbeQUICMaxIdle         = 90 * time.Second
)

const (
	probeFailureInvalidRequest = "invalid_request"
	probeFailureRequestTimeout = "request_timeout"
	probeFailureTLS            = "tls_failure"
	probeFailureProtocol       = "protocol_mismatch"
	probeFailureHTTP3          = "http3_request_failed"
	probeFailureConnection     = "connection_failed"
	probeFailureRequest        = "request_failed"
)

type State struct {
	Healthy          bool
	CheckedAt        time.Time
	LastSuccessAt    time.Time
	LastHTTPProtocol string
	LastFailureKind  string
	FailCount        int
	LastError        string
	LastLatencyMs    int64
	AverageLatencyMs int64
	LatencySamples   int64
}

type Pool struct {
	mu     sync.RWMutex
	states map[upstreamStateKey]State
}

type ProbeFunc func(context.Context, string) error

type ProbeResult struct {
	Err          error
	HTTPProtocol string
	FailureKind  string
}

type ProbeResultFunc func(context.Context, string) ProbeResult

type probeFailureError struct {
	kind string
	err  error
}

func (e *probeFailureError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *probeFailureError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

type upstreamURLInfo struct {
	raw    string
	url    *url.URL
	scheme string
}

type upstreamStateKey struct {
	raw       string
	scheme    upstreamStateScheme
	authority string
}

func (k upstreamStateKey) String() string {
	if k.raw != "" {
		return k.raw
	}
	if k.authority == "" {
		return ""
	}
	switch k.scheme {
	case upstreamStateSchemeHTTP:
		return "http://" + k.authority
	case upstreamStateSchemeHTTPS:
		return "https://" + k.authority
	case upstreamStateSchemeH2C:
		return "h2c://" + k.authority
	case upstreamStateSchemeH3:
		return "h3://" + k.authority
	default:
		return ""
	}
}

type upstreamStateScheme uint8

const (
	upstreamStateSchemeInvalid upstreamStateScheme = iota
	upstreamStateSchemeHTTP
	upstreamStateSchemeHTTPS
	upstreamStateSchemeH2C
	upstreamStateSchemeH3
)

func parseUpstreamURL(raw string) upstreamURLInfo {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return upstreamURLInfo{}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return upstreamURLInfo{raw: raw}
	}
	return upstreamURLInfo{
		raw:    raw,
		url:    u,
		scheme: strings.ToLower(u.Scheme),
	}
}

func (i upstreamURLInfo) valid() bool {
	return i.url != nil
}

func (i upstreamURLInfo) normalized() string {
	return normalizeUpstreamBase(i.raw)
}

func (i upstreamURLInfo) configuredProtocol() string {
	if !i.valid() {
		return ""
	}
	switch i.scheme {
	case "h3":
		return "h3"
	case "h2c":
		return "h2c"
	case "https":
		return "https"
	case "http":
		return "http"
	default:
		return i.scheme
	}
}

func (i upstreamURLInfo) isHTTPS() bool {
	return i.valid() && i.scheme == "https"
}

func (i upstreamURLInfo) isExplicitH2C() bool {
	return i.valid() && i.scheme == "h2c"
}

func (i upstreamURLInfo) isExplicitH3() bool {
	return i.valid() && i.scheme == "h3"
}

func (i upstreamURLInfo) probeTarget() string {
	if !i.valid() {
		return i.raw
	}
	u := *i.url
	switch i.scheme {
	case "h2c":
		u.Scheme = "http"
	case "h3":
		u.Scheme = "https"
	}
	return u.String()
}

func NewPool() *Pool {
	return &Pool{states: make(map[upstreamStateKey]State)}
}

func (p *Pool) Pick(urls []string, next func(uint32) uint32) (string, bool) {
	if len(urls) == 0 {
		return "", false
	}
	start := 0
	if next != nil {
		start = int(next(uint32(len(urls))))
	}
	if selected, ok := pickAvailableUpstream(urls, p, start); ok {
		return selected, true
	}
	return urls[start], true
}

// GroupURLsByProtocolPreference splits upstream URLs into protocol-preference
// groups, ordered from highest to lowest protocol version.
func GroupURLsByProtocolPreference(urls []string) [][]string {
	groups := make([][]string, 4)
	for _, raw := range urls {
		switch protocolPreference(raw) {
		case 3:
			groups[0] = append(groups[0], raw)
		case 2:
			groups[1] = append(groups[1], raw)
		case 1:
			groups[2] = append(groups[2], raw)
		default:
			groups[3] = append(groups[3], raw)
		}
	}
	return groups
}

// PickByProtocolPreference selects an upstream URL by preferring explicit
// HTTP/3, then h2c, then HTTPS, then other upstreams.
func PickByProtocolPreference(urls []string, pool *Pool, next func(uint32) uint32) (string, bool) {
	if len(urls) == 0 {
		return "", false
	}
	start := 0
	if next != nil {
		start = int(next(uint32(len(urls))))
	}
	if pool == nil {
		return pickByProtocolPreferenceWithoutPool(urls, start)
	}
	return pickByProtocolPreferenceWithPool(urls, pool, start)
}

func pickByProtocolPreferenceWithoutPool(urls []string, start int) (string, bool) {
	var h3 string
	var h2c string
	var https string
	var other string
	var haveH3 bool
	var haveH2C bool
	var haveHTTPS bool
	var haveOther bool
	for offset := range urls {
		raw := urls[(start+offset)%len(urls)]
		switch protocolPreference(raw) {
		case 3:
			if !haveH3 {
				h3 = raw
				haveH3 = true
			}
		case 2:
			if !haveH2C {
				h2c = raw
				haveH2C = true
			}
		case 1:
			if !haveHTTPS {
				https = raw
				haveHTTPS = true
			}
		default:
			if !haveOther {
				other = raw
				haveOther = true
			}
		}
	}
	switch {
	case haveH3:
		return h3, true
	case haveH2C:
		return h2c, true
	case haveHTTPS:
		return https, true
	case haveOther:
		return other, true
	default:
		return "", false
	}
}

func pickByProtocolPreferenceWithPool(urls []string, pool *Pool, start int) (string, bool) {
	if pool == nil {
		return "", false
	}
	var first [4]string
	var best [4]string
	var bestLatency [4]int64
	var haveFirst [4]bool
	var haveBest [4]bool
	var allHaveLatency [4]bool
	for i := range allHaveLatency {
		allHaveLatency[i] = true
	}

	pool.mu.RLock()
	defer pool.mu.RUnlock()

	for offset := range urls {
		raw := urls[(start+offset)%len(urls)]
		tier := protocolPreference(raw)
		st, known := pool.states[parseUpstreamStateKey(raw)]
		if known && !st.Healthy {
			continue
		}
		if !haveFirst[tier] {
			first[tier] = raw
			haveFirst[tier] = true
		}
		if !known || st.LatencySamples <= 0 || st.AverageLatencyMs <= 0 {
			allHaveLatency[tier] = false
			continue
		}
		if !haveBest[tier] || st.AverageLatencyMs < bestLatency[tier] {
			best[tier] = raw
			bestLatency[tier] = st.AverageLatencyMs
			haveBest[tier] = true
		}
	}

	for tier := 3; tier >= 0; tier-- {
		if !haveFirst[tier] {
			continue
		}
		if allHaveLatency[tier] && haveBest[tier] {
			return best[tier], true
		}
		return first[tier], true
	}
	return "", false
}

func protocolPreference(raw string) int {
	raw = strings.TrimSpace(raw)
	switch {
	case hasSchemePrefixFold(raw, "h3://"):
		return 3
	case hasSchemePrefixFold(raw, "h2c://"):
		return 2
	case hasSchemePrefixFold(raw, "https://"):
		return 1
	default:
		return 0
	}
}

func pickAvailableUpstream(urls []string, pool *Pool, start int) (string, bool) {
	if len(urls) == 0 {
		return "", false
	}
	if pool != nil {
		if raw, ok := pool.pickFastestKnownAvailable(urls, start); ok {
			return raw, true
		}
		return "", false
	}
	for offset := range urls {
		idx := (start + offset) % len(urls)
		return urls[idx], true
	}
	return "", false
}

func (p *Pool) pickFastestKnownAvailable(urls []string, start int) (string, bool) {
	if p == nil || len(urls) == 0 {
		return "", false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	first := ""
	best := ""
	var bestLatency int64
	allHaveLatency := true
	for offset := range urls {
		idx := (start + offset) % len(urls)
		raw := urls[idx]
		st, known := p.states[parseUpstreamStateKey(raw)]
		if known && !st.Healthy {
			continue
		}
		if first == "" {
			first = raw
		}
		if !known || st.LatencySamples <= 0 || st.AverageLatencyMs <= 0 {
			allHaveLatency = false
			continue
		}
		if best == "" || st.AverageLatencyMs < bestLatency {
			best = raw
			bestLatency = st.AverageLatencyMs
		}
	}
	if first == "" {
		return "", false
	}
	if allHaveLatency && best != "" {
		return best, true
	}
	return first, true
}

func (p *Pool) IsAvailable(raw string) bool {
	if p == nil {
		return true
	}
	p.mu.RLock()
	st, ok := p.states[parseUpstreamStateKey(raw)]
	p.mu.RUnlock()
	return !ok || st.Healthy
}

func (p *Pool) Mark(raw string, err error) {
	p.MarkResult(raw, err, 0)
}

func (p *Pool) MarkResult(raw string, err error, latency time.Duration) {
	p.MarkProbeResult(raw, ProbeResult{Err: err}, latency)
}

func (p *Pool) MarkProbeResult(raw string, result ProbeResult, latency time.Duration) {
	p.markProbeResult(parseUpstreamStateKey(raw), result, latency)
}

func (p *Pool) markProbeResult(key upstreamStateKey, result ProbeResult, latency time.Duration) {
	if p == nil || key == (upstreamStateKey{}) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.states[key]
	err := result.Err
	st.CheckedAt = time.Now()
	if latency > 0 {
		latencyMs := latencyMilliseconds(latency)
		st.LastLatencyMs = latencyMs
		st.AverageLatencyMs = ((st.AverageLatencyMs * st.LatencySamples) + latencyMs) / (st.LatencySamples + 1)
		st.LatencySamples++
	}
	if err == nil {
		st.Healthy = true
		st.FailCount = 0
		st.LastError = ""
		st.LastFailureKind = ""
		st.LastSuccessAt = st.CheckedAt
		if proto := strings.TrimSpace(result.HTTPProtocol); proto != "" {
			st.LastHTTPProtocol = proto
		}
	} else {
		st.FailCount++
		st.Healthy = st.FailCount < 2
		st.LastError = truncateStateError(err.Error())
		st.LastFailureKind = probeFailureKind(result.FailureKind, err)
	}
	p.states[key] = st
}

func truncateStateError(raw string) string {
	raw = strings.Join(strings.Fields(raw), " ")
	const maxLen = 512
	if len(raw) <= maxLen {
		return raw
	}
	return raw[:maxLen] + "..."
}

func latencyMilliseconds(latency time.Duration) int64 {
	if latency <= 0 {
		return 0
	}
	ms := latency.Milliseconds()
	if ms == 0 {
		return 1
	}
	return ms
}

func (p *Pool) Snapshot() map[string]State {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]State, len(p.states))
	for k, v := range p.states {
		out[k.String()] = v
	}
	return out
}

func (p *Pool) Probe(ctx context.Context, urls []string, probe ProbeFunc) {
	if probe == nil {
		return
	}
	p.ProbeWithResult(ctx, urls, func(ctx context.Context, raw string) ProbeResult {
		return ProbeResult{Err: probe(ctx, raw)}
	})
}

func (p *Pool) ProbeWithResult(ctx context.Context, urls []string, probe ProbeResultFunc) {
	if p == nil || probe == nil {
		return
	}
	seen := make(map[upstreamStateKey]struct{}, len(urls))
	for _, raw := range urls {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		key := parseUpstreamStateKey(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		start := time.Now()
		result := probe(ctx, trimmed)
		p.markProbeResult(key, result, time.Since(start))
	}
}

func (p *Pool) Start(ctx context.Context, urls func() []string, interval time.Duration, probe ProbeFunc) {
	if probe == nil {
		return
	}
	p.StartWithResult(ctx, urls, interval, func(ctx context.Context, raw string) ProbeResult {
		return ProbeResult{Err: probe(ctx, raw)}
	})
}

func (p *Pool) StartWithResult(ctx context.Context, urls func() []string, interval time.Duration, probe ProbeResultFunc) {
	if p == nil || urls == nil || probe == nil {
		return
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	p.ProbeWithResult(ctx, urls(), probe)
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.ProbeWithResult(ctx, urls(), probe)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func HTTPProbe(timeout time.Duration) ProbeFunc {
	probe := HTTPProbeWithResult(timeout)
	return func(ctx context.Context, raw string) error {
		return probe(ctx, raw).Err
	}
}

func HTTPProbeWithResult(timeout time.Duration) ProbeResultFunc {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	client := newHTTPProbeClient(timeout)
	var h2cOnce sync.Once
	var h2cClient *http.Client
	var h3Once sync.Once
	var h3Client *http.Client
	return func(ctx context.Context, raw string) ProbeResult {
		info := parseUpstreamURL(raw)
		target := info.normalized()
		probeClient := client
		expectedProto := ""
		switch {
		case info.isExplicitH2C():
			target = info.probeTarget()
			h2cOnce.Do(func() {
				h2cClient = newHTTPProbeH2CClient(timeout)
			})
			probeClient = h2cClient
			expectedProto = "HTTP/2.0"
		case info.isExplicitH3():
			target = info.probeTarget()
			h3Once.Do(func() {
				h3Client = newHTTPProbeHTTP3Client(timeout)
			})
			probeClient = h3Client
			expectedProto = "HTTP/3.0"
		}
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		resp, err := doProbeRequest(probeClient, reqCtx, http.MethodHead, target, expectedProto)
		if err != nil {
			return ProbeResult{Err: err, FailureKind: probeFailureKind("", err)}
		}
		proto := resp.Proto
		resp.Body.Close()
		if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
			return getProbeWithResult(probeClient, reqCtx, target, expectedProto)
		}
		return ProbeResult{HTTPProtocol: proto}
	}
}

func newHTTPProbeH2CClient(timeout time.Duration) *http.Client {
	transport := newHTTPProbeTransport(timeout)
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetUnencryptedHTTP2(true)
	return &http.Client{Timeout: timeout, Transport: transport}
}

func newHTTPProbeTransport(timeout time.Duration) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: defaultHTTPProbeTCPKeepAlive,
	}
	return &http.Transport{
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		DialContext:           dialer.DialContext,
		IdleConnTimeout:       defaultHTTPProbeIdleConnTimeout,
		TLSHandshakeTimeout:   defaultHTTPProbeTLSHandshakeTimeout,
		ExpectContinueTimeout: defaultHTTPProbeExpectContinue,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
	}
}

func newHTTPProbeHTTP3Client(timeout time.Duration) *http.Client {
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: defaultHTTPProbeQUICHandshakeIdle,
			MaxIdleTimeout:       defaultHTTPProbeQUICMaxIdle,
		},
		DisableCompression: true,
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func newHTTPProbeClient(timeout time.Duration) *http.Client {
	defaultTransport := newHTTPProbeTransport(timeout)
	defaultTransport.Proxy = http.ProxyFromEnvironment
	defaultTransport.TLSClientConfig = HTTPSClientTLSConfig("", false)
	return &http.Client{Timeout: timeout, Transport: defaultTransport}
}

func doProbeRequest(client *http.Client, ctx context.Context, method string, raw string, expectedProto string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, raw, nil)
	if err != nil {
		return nil, withProbeFailureKind(probeFailureInvalidRequest, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, withProbeFailureKind(classifyProbeRequestError(err, expectedProto), err)
	}
	if err := validateProbeProtocol(resp, expectedProto); err != nil {
		if resp.Body != nil {
			resp.Body.Close()
		}
		return nil, err
	}
	return resp, nil
}

func validateProbeProtocol(resp *http.Response, expectedProto string) error {
	if resp == nil || expectedProto == "" {
		return nil
	}
	if resp.Proto != expectedProto {
		return withProbeFailureKind(probeFailureProtocol, fmt.Errorf("unexpected upstream protocol: got %s, want %s", resp.Proto, expectedProto))
	}
	return nil
}

func withProbeFailureKind(kind string, err error) error {
	if err == nil {
		return nil
	}
	if kind == "" {
		kind = probeFailureRequest
	}
	return &probeFailureError{kind: kind, err: err}
}

func probeFailureKind(explicit string, err error) string {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		return explicit
	}
	if err == nil {
		return ""
	}
	var classified *probeFailureError
	if errors.As(err, &classified) && classified.kind != "" {
		return classified.kind
	}
	return classifyProbeRequestError(err, "")
}

func classifyProbeRequestError(err error, expectedProto string) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return probeFailureRequestTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return probeFailureRequestTimeout
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return probeFailureTLS
	}
	var certVerifyErr *tls.CertificateVerificationError
	if errors.As(err, &certVerifyErr) {
		return probeFailureTLS
	}
	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return probeFailureTLS
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return probeFailureTLS
	}
	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return probeFailureTLS
	}
	var systemRootsErr x509.SystemRootsError
	if errors.As(err, &systemRootsErr) {
		return probeFailureTLS
	}
	if expectedProto == "HTTP/3.0" {
		return probeFailureHTTP3
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return probeFailureConnection
	}
	return probeFailureRequest
}

func getProbeWithResult(client *http.Client, ctx context.Context, raw string, expectedProto string) ProbeResult {
	resp, err := doProbeRequest(client, ctx, http.MethodGet, raw, expectedProto)
	if err != nil {
		return ProbeResult{Err: err, FailureKind: probeFailureKind("", err)}
	}
	proto := resp.Proto
	resp.Body.Close()
	return ProbeResult{HTTPProtocol: proto}
}

func Normalize(raw string) string {
	return normalizeUpstreamBase(raw)
}

func parseUpstreamStateKey(raw string) upstreamStateKey {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return upstreamStateKey{}
	}
	if i := strings.Index(raw, "://"); i > 0 {
		if scheme := parseUpstreamStateScheme(raw[:i]); scheme != upstreamStateSchemeInvalid {
			authorityStart := i + len("://")
			if authorityStart < len(raw) {
				authorityEnd := len(raw)
				for j := authorityStart; j < len(raw); j++ {
					switch raw[j] {
					case '/', '?', '#':
						authorityEnd = j
						j = len(raw)
					}
				}
				if authorityEnd > authorityStart {
					authority := raw[authorityStart:authorityEnd]
					if !containsInvalidUpstreamAuthority(authority) {
						return upstreamStateKey{scheme: scheme, authority: authority}
					}
				}
			}
		}
	}
	return upstreamStateKey{raw: raw}
}

func parseUpstreamStateScheme(raw string) upstreamStateScheme {
	switch {
	case asciiEqualFoldAnyString(raw, "http"):
		return upstreamStateSchemeHTTP
	case asciiEqualFoldAnyString(raw, "https"):
		return upstreamStateSchemeHTTPS
	case asciiEqualFoldAnyString(raw, "h2c"):
		return upstreamStateSchemeH2C
	case asciiEqualFoldAnyString(raw, "h3"):
		return upstreamStateSchemeH3
	default:
		return upstreamStateSchemeInvalid
	}
}

func ConfiguredProtocol(raw string) string {
	return parseUpstreamURL(raw).configuredProtocol()
}

func isExplicitH2CUpstream(raw string) bool {
	return parseUpstreamURL(raw).isExplicitH2C()
}

func isExplicitH3Upstream(raw string) bool {
	return parseUpstreamURL(raw).isExplicitH3()
}

func normalizeUpstreamBase(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd <= 0 {
		return raw
	}
	scheme := raw[:schemeEnd]
	if !isValidUpstreamScheme(scheme) {
		return raw
	}
	authorityStart := schemeEnd + len("://")
	if authorityStart >= len(raw) {
		return raw
	}
	authorityEnd := len(raw)
	for i := authorityStart; i < len(raw); i++ {
		switch raw[i] {
		case '/', '?', '#':
			authorityEnd = i
			i = len(raw)
		}
	}
	if authorityEnd == authorityStart {
		return raw
	}
	authority := raw[authorityStart:authorityEnd]
	if containsInvalidUpstreamAuthority(authority) {
		return raw
	}
	schemeHasUpper := containsUpperASCII(scheme)
	if authorityEnd == len(raw) && !schemeHasUpper {
		return raw
	}
	if authorityEnd < len(raw) && !schemeHasUpper {
		return raw[:authorityEnd]
	}

	var b strings.Builder
	b.Grow(authorityEnd)
	for i := 0; i < len(scheme); i++ {
		ch := scheme[i]
		if 'A' <= ch && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		_ = b.WriteByte(ch)
	}
	b.WriteString("://")
	b.WriteString(authority)
	return b.String()
}

func isValidUpstreamScheme(scheme string) bool {
	if scheme == "" || !isASCIIAlpha(scheme[0]) {
		return false
	}
	for i := 1; i < len(scheme); i++ {
		ch := scheme[i]
		switch {
		case isASCIIAlpha(ch), isASCIIDigit(ch), ch == '+', ch == '-', ch == '.':
		default:
			return false
		}
	}
	return true
}

func containsInvalidUpstreamAuthority(authority string) bool {
	for i := 0; i < len(authority); i++ {
		ch := authority[i]
		if ch <= 0x20 || ch == 0x7f || ch == '\\' {
			return true
		}
	}
	return false
}

func containsUpperASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

func asciiEqualFoldAnyString(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := 0; i < len(got); i++ {
		if asciiLowerAnyByte(got[i]) != asciiLowerAnyByte(want[i]) {
			return false
		}
	}
	return true
}

func asciiLowerAnyByte(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func isASCIIAlpha(ch byte) bool {
	return ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z')
}

func isASCIIDigit(ch byte) bool {
	return '0' <= ch && ch <= '9'
}
