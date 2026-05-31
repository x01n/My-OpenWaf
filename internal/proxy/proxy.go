package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

// transportKey identifies a unique upstream TLS configuration.
type transportKey struct {
	tlsServerName string
	tlsSkipVerify bool
	isHTTPS       bool
}

var (
	transportMu   sync.RWMutex
	transportPool = make(map[transportKey]*http.Transport)
)

// SharedTransport returns a cached http.Transport for the given site runtime.
// Transports are keyed by TLS config so connections are reused across requests.
func SharedTransport(rt snapshot.SiteRuntime) *http.Transport {
	base := ""
	if len(rt.UpstreamURLs) > 0 {
		base = rt.UpstreamURLs[0]
	}
	return SharedTransportForUpstream(rt, base)
}

// SharedTransportForUpstream keys the pool by the selected upstream scheme.
func SharedTransportForUpstream(rt snapshot.SiteRuntime, base string) *http.Transport {
	isHTTPS := strings.HasPrefix(strings.ToLower(base), "https://")
	key := transportKey{
		tlsServerName: rt.Site.UpstreamTLSServerName,
		tlsSkipVerify: rt.Site.UpstreamTLSSkipVerify,
		isHTTPS:       isHTTPS,
	}

	transportMu.RLock()
	if tr, ok := transportPool[key]; ok {
		transportMu.RUnlock()
		return tr
	}
	transportMu.RUnlock()

	tr := &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	if isHTTPS {
		tr.TLSClientConfig = &tls.Config{
			ServerName:         rt.Site.UpstreamTLSServerName,
			InsecureSkipVerify: rt.Site.UpstreamTLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
	}

	transportMu.Lock()
	if existing, ok := transportPool[key]; ok {
		transportMu.Unlock()
		return existing
	}
	transportPool[key] = tr
	transportMu.Unlock()
	return tr
}

// clientPool caches http.Client instances keyed by transport to avoid repeated allocation.
var (
	clientPoolMu sync.RWMutex
	clientCache  = make(map[*http.Transport]*http.Client)
)

func sharedClient(tr *http.Transport) *http.Client {
	clientPoolMu.RLock()
	if hc, ok := clientCache[tr]; ok {
		clientPoolMu.RUnlock()
		return hc
	}
	clientPoolMu.RUnlock()

	hc := &http.Client{Transport: tr, Timeout: 60 * time.Second}
	clientPoolMu.Lock()
	if existing, ok := clientCache[tr]; ok {
		clientPoolMu.Unlock()
		return existing
	}
	clientCache[tr] = hc
	clientPoolMu.Unlock()
	return hc
}

// HTTPResponse is a buffered upstream response used by the cache path.
type HTTPResponse struct {
	StatusCode  int
	ContentType string
	Body        []byte
	Header      http.Header
}

func requestPath(c *app.RequestContext) string {
	if rawPath := c.Request.URI().PathOriginal(); len(rawPath) > 0 {
		return string(rawPath)
	}
	path := string(c.Path())
	if path == "" {
		return "/"
	}
	return path
}

func inboundProto(c *app.RequestContext) string {
	if v := strings.TrimSpace(string(c.GetHeader("X-Forwarded-Proto"))); v != "" {
		return strings.ToLower(v)
	}
	if bytes.EqualFold(c.Request.Header.Peek("Upgrade"), []byte("websocket")) {
		if bytes.HasPrefix(bytes.ToLower(c.Request.Header.Peek("Origin")), []byte("https://")) {
			return "https"
		}
		return "http"
	}
	if string(c.Request.Scheme()) == "https" {
		return "https"
	}
	return "http"
}

func buildUpstreamRequest(ctx context.Context, c *app.RequestContext, base string, clientIP net.IP, origHost string, preserveOriginalHost bool) (*http.Request, error) {
	full := strings.TrimRight(base, "/") + requestPath(c)
	if q := c.URI().QueryString(); len(q) > 0 {
		full += "?" + string(q)
	}

	body := c.Request.Body()
	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, string(c.Method()), full, rdr)
	if err != nil {
		return nil, err
	}

	c.Request.Header.VisitAll(func(k, v []byte) {
		key := strings.ToLower(string(k))
		if _, skip := hopByHopHeaders[key]; skip {
			return
		}
		req.Header.Add(string(k), string(v))
	})

	security.ApplyOutboundForwarding(req, clientIP, origHost, preserveOriginalHost, inboundProto(c))
	return req, nil
}

func copyResponseHeaders(dst *app.RequestContext, src http.Header) {
	debugEnabled := slog.Default().Enabled(context.Background(), slog.LevelDebug)
	var removed []string
	for k, vv := range src {
		if isHopByHop(k) {
			if debugEnabled {
				removed = append(removed, k)
			}
			continue
		}
		for _, v := range vv {
			dst.Response.Header.Add(k, v)
		}
	}
	if src.Get("Server") == "" {
		dst.Response.Header.Del("Server")
	}
	if len(removed) > 0 {
		slog.Debug("upstream hop-by-hop response headers stripped", slog.Any("headers", removed))
	}
}

// FetchHTTP performs the upstream request and returns a buffered response.
func FetchHTTP(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) (*HTTPResponse, error) {
	req, err := buildUpstreamRequest(ctx, c, base, clientIP, origHost, rt.PreserveOriginalHost)
	if err != nil {
		return nil, err
	}

	tr := SharedTransportForUpstream(rt, base)
	hc := sharedClient(tr)
	start := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		slog.Warn("upstream buffered request failed",
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
			slog.String("host", origHost),
			slog.Any("err", err),
		)
		return nil, err
	}
	defer resp.Body.Close()
	slog.Debug("upstream buffered response received",
		slog.String("method", req.Method),
		slog.String("url", req.URL.String()),
		slog.String("host", origHost),
		slog.Int("status", resp.StatusCode),
		slog.String("proto", resp.Proto),
		slog.Duration("latency", time.Since(start)),
	)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &HTTPResponse{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        respBody,
		Header:      resp.Header.Clone(),
	}, nil
}

func ForwardBufferedResponse(c *app.RequestContext, resp *HTTPResponse) {
	if resp == nil {
		return
	}
	if resp.Header != nil {
		copyResponseHeaders(c, resp.Header)
	}
	if resp.ContentType != "" && (resp.Header == nil || resp.Header.Get("Content-Type") == "") {
		c.SetContentType(resp.ContentType)
	}
	c.Status(resp.StatusCode)
	c.Response.SetBodyRaw(resp.Body)
}

// SanitizeHeadersForEdgeCache strips hop-by-hop headers and Content-Length before persisting
// upstream metadata with the body. Keeps Content-Encoding (e.g. br) so cache hits decode correctly.
func SanitizeHeadersForEdgeCache(src http.Header) http.Header {
	if src == nil {
		return nil
	}
	dst := src.Clone()
	for k := range dst {
		if isHopByHop(k) {
			dst.Del(k)
		}
	}
	dst.Del("Content-Length")
	if len(dst) == 0 {
		return nil
	}
	return dst
}

// WriteCachedResponse replays a cache.ResponseEntry, including stored headers when present.
func WriteCachedResponse(c *app.RequestContext, method string, e *cache.ResponseEntry) {
	if e == nil {
		return
	}
	if strings.EqualFold(strings.TrimSpace(method), "HEAD") {
		if e.ContentType != "" {
			c.SetContentType(e.ContentType)
		}
		c.Status(e.StatusCode)
		if len(e.Body) > 0 {
			c.Response.Header.Set("Content-Length", strconv.Itoa(len(e.Body)))
		}
		c.Response.SetBodyRaw(nil)
		return
	}
	if e.Header != nil && len(e.Header) > 0 {
		copyResponseHeaders(c, e.Header)
	}
	if e.ContentType != "" {
		c.SetContentType(e.ContentType)
	}
	c.Status(e.StatusCode)
	c.Response.SetBodyRaw(e.Body)
}

func ShouldCacheResponse(method string, statusCode int, body []byte) bool {
	return strings.EqualFold(method, "GET") && statusCode == 200 && len(body) > 0
}

// varyDisallowsCaching reports true when Vary implies dimensions we do not key on.
// Many origins send only "Accept-Encoding"; Go's http.Client already decodes gzip bodies,
// so a single buffered variant is safe for our in-process cache.
func varyDisallowsCaching(vary string) bool {
	vary = strings.TrimSpace(vary)
	if vary == "" {
		return false
	}
	for _, p := range strings.Split(vary, ",") {
		t := strings.ToLower(strings.TrimSpace(p))
		if t == "" {
			continue
		}
		if t != "accept-encoding" {
			return true
		}
	}
	return false
}

// ShouldCacheHTTPResponse decides whether to store the upstream response in the edge cache.
// When ignoreUpstreamCacheControl is true (path matched an explicit site cache rule), upstream
// Cache-Control private/no-store is ignored so CDNs/framework defaults do not disable caching;
// Set-Cookie and unsafe Vary are still respected.
func ShouldCacheHTTPResponse(method string, resp *HTTPResponse, ignoreUpstreamCacheControl bool) bool {
	if resp == nil || !ShouldCacheResponse(method, resp.StatusCode, resp.Body) {
		return false
	}
	if resp.Header.Get("Set-Cookie") != "" {
		return false
	}
	if !ignoreUpstreamCacheControl {
		cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))
		if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "private") {
			return false
		}
	}
	if varyDisallowsCaching(resp.Header.Get("Vary")) {
		return false
	}
	return true
}

// SiteCacheTTL returns the configured TTL in seconds for the given rule match key (path with optional "?query").
func SiteCacheTTL(rt snapshot.SiteRuntime, matchKey string) int64 {
	ttl, _ := SiteCacheTTLDetails(rt, matchKey)
	return ttl
}

// siteCacheFirstMatch returns the first matching cache rule's TTL and key-shaping flags.
func siteCacheFirstMatch(rt snapshot.SiteRuntime, matchKey string) (ttl int64, stripQueryKey bool, lowerPathKey bool, matched bool) {
	if !rt.CacheEnabled {
		return 0, false, false, false
	}
	for _, rule := range rt.CacheRules {
		pat := cacheRulePattern(rule)
		if pat == "" {
			continue
		}
		ruleType := strings.ToLower(strings.TrimSpace(rule.Type))
		if ruleType == "" {
			ruleType = "prefix"
		}
		keyFor := matchKey
		if rule.IgnoreQuery {
			keyFor = pathOnlyFromRuleMatchKey(matchKey)
		}
		var matches bool
		switch ruleType {
		case "regex":
			if rule.Regex != nil {
				matches = rule.Regex.MatchString(keyFor)
			}
		default:
			keyCmp, patCmp := keyFor, pat
			if rule.CaseInsensitive {
				keyCmp = strings.ToLower(keyCmp)
				patCmp = strings.ToLower(patCmp)
			}
			switch ruleType {
			case "exact":
				matches = keyCmp == patCmp
			case "suffix":
				matches = cacheSuffixPatternMatch(keyCmp, patCmp)
			case "contains":
				matches = strings.Contains(keyCmp, patCmp)
			default:
				matches = strings.HasPrefix(keyCmp, patCmp)
			}
		}
		if !matches {
			continue
		}
		t := int64(rule.TTL)
		if t <= 0 {
			t = int64(rt.CacheDefaultTTL)
		}
		if t > 0 {
			return t, rule.IgnoreQuery, rule.CaseInsensitive, true
		}
	}
	return 0, false, false, false
}

// SiteCacheTTLDetails returns TTL and whether a cache_rules row matched (pattern hit).
// cache_default_ttl is applied only as the TTL for a matching rule whose own ttl is <= 0;
// it does not enable caching for paths that do not match any rule.
func SiteCacheTTLDetails(rt snapshot.SiteRuntime, matchKey string) (ttl int64, matchedExplicitRule bool) {
	t, _, _, ok := siteCacheFirstMatch(rt, matchKey)
	return t, ok
}

// RuleMatchKey is path plus optional raw query string, used to evaluate cache path rules.
func RuleMatchKey(c *app.RequestContext) string {
	p := requestPath(c)
	qs := strings.TrimSpace(string(c.URI().QueryString()))
	if qs == "" {
		return p
	}
	return p + "?" + qs
}

func cacheRulePattern(r store.SiteCacheRule) string {
	v := strings.TrimSpace(r.Value)
	if v != "" {
		return v
	}
	return strings.TrimSpace(r.Path)
}

func pathOnlyFromRuleMatchKey(matchKey string) string {
	if i := strings.IndexByte(matchKey, '?'); i >= 0 {
		return matchKey[:i]
	}
	return matchKey
}

// cacheSuffixPatternMatch matches suffix rules without mid-token false positives, e.g. pattern
// "ig" must not match ".../config". File extensions (".js") and explicit path tails ("a/b.js")
// keep standard suffix semantics.
func cacheSuffixPatternMatch(matchKey, pat string) bool {
	if pat == "" {
		return false
	}
	if strings.Contains(pat, "?") {
		return strings.HasSuffix(matchKey, pat)
	}
	pathOnly := pathOnlyFromRuleMatchKey(matchKey)
	if !strings.HasSuffix(pathOnly, pat) {
		return false
	}
	if strings.HasPrefix(pat, ".") || strings.Contains(pat, "/") {
		return true
	}
	idx := len(pathOnly) - len(pat)
	if idx < 0 {
		return false
	}
	if idx == 0 {
		return true
	}
	switch pathOnly[idx-1] {
	case '/', '.', '_', '-':
		return true
	default:
		return false
	}
}

// BuildSiteCacheStorageKey builds the in-process cache key; stripQuery drops the query from the key,
// lowerPath lowercases only the path segment (not the host key) when case-insensitive rules matched.
func BuildSiteCacheStorageKey(rt snapshot.SiteRuntime, c *app.RequestContext, stripQuery, lowerPath bool) string {
	method := string(c.Method())
	if strings.EqualFold(method, "HEAD") {
		method = "GET"
	}
	p := requestPath(c)
	if lowerPath {
		p = strings.ToLower(p)
	}
	q := string(c.URI().QueryString())
	if stripQuery {
		q = ""
	}
	hostKey := strings.TrimSpace(rt.Bind) + "|" + strconv.FormatUint(uint64(rt.Site.ID), 10) + "|" + snapshot.NormalizeMatchHost(string(c.Host()))
	return cache.CacheKey(method, hostKey, p, q)
}

// SiteCacheKey builds the default cache key (full query, original path casing).
func SiteCacheKey(rt snapshot.SiteRuntime, c *app.RequestContext) string {
	return BuildSiteCacheStorageKey(rt, c, false, false)
}

// SiteCacheEligible reports whether this request may use the edge response cache.
// The third return is true when a cache_rules row matched: upstream Cache-Control private/no-store
// may be ignored for storing (still never caches Set-Cookie responses).
func SiteCacheEligible(rt snapshot.SiteRuntime, c *app.RequestContext) (key string, ttl int64, ignoreUpstreamCacheControl bool) {
	if !rt.CacheEnabled {
		return "", 0, false
	}
	m := string(c.Method())
	if !strings.EqualFold(m, "GET") && !strings.EqualFold(m, "HEAD") {
		return "", 0, false
	}
	if c.Request.Header.Get("Authorization") != "" {
		return "", 0, false
	}
	// Do not disable edge caching based on the client's Cache-Control/Pragma. Browsers and
	// devtools often send no-cache while operators still want stale shielding when upstream
	// is down. Storage eligibility remains governed by ShouldCacheHTTPResponse (upstream CC,
	// Set-Cookie, Vary, etc.).
	full := RuleMatchKey(c)
	ttlVal, stripQ, lowerP, ok := siteCacheFirstMatch(rt, full)
	if !ok || ttlVal <= 0 {
		return "", 0, false
	}
	return BuildSiteCacheStorageKey(rt, c, stripQ, lowerP), ttlVal, true
}

// ForwardHTTP copies the incoming request to upstream and streams the response.
func ForwardHTTP(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) error {
	req, err := buildUpstreamRequest(ctx, c, base, clientIP, origHost, rt.PreserveOriginalHost)
	if err != nil {
		return err
	}

	tr := SharedTransportForUpstream(rt, base)
	hc := sharedClient(tr)
	start := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		slog.Warn("upstream streaming request failed",
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
			slog.String("host", origHost),
			slog.Any("err", err),
		)
		return err
	}
	defer resp.Body.Close()
	slog.Debug("upstream streaming response received",
		slog.String("method", req.Method),
		slog.String("url", req.URL.String()),
		slog.String("host", origHost),
		slog.Int("status", resp.StatusCode),
		slog.String("proto", resp.Proto),
		slog.Duration("latency", time.Since(start)),
	)

	copyResponseHeaders(c, resp.Header)
	c.Status(resp.StatusCode)
	_, err = io.Copy(c.Response.BodyWriter(), resp.Body)
	return err
}

var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"proxy-connection":    {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
}

func isHopByHop(name string) bool {
	_, ok := hopByHopHeaders[strings.ToLower(name)]
	return ok
}

// IsHopByHop returns whether the given header name is a hop-by-hop header
// that should be stripped when forwarding responses.
func IsHopByHop(name string) bool { return isHopByHop(name) }
