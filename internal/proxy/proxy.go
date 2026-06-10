package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

type byteSliceReadCloser struct {
	data []byte
	pos  int
}

func (r *byteSliceReadCloser) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *byteSliceReadCloser) Close() error {
	return nil
}

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
	isHTTPS := isHTTPSUpstreamBase(base)
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
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 128,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
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

func isHTTPSUpstreamBase(base string) bool {
	const scheme = "https://"
	if len(base) < len(scheme) {
		return false
	}
	for i := 0; i < len(scheme); i++ {
		b := base[i]
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != scheme[i] {
			return false
		}
	}
	return true
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

var upstreamErrorLogCounter atomic.Uint64

// shouldLogUpstreamErrorCount keeps initial evidence and samples repeated failures.
func shouldLogUpstreamErrorCount(count uint64) bool {
	return count <= 16 || count%1024 == 0
}

func upstreamErrorReason(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err.Error()
	}
	return err.Error()
}

func upstreamLogPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	const limit = 160
	if len(path) <= limit {
		return path
	}
	return path[:limit] + "..."
}

func logUpstreamRequestError(ctx context.Context, mode string, req *http.Request, origHost string, err error) {
	logger := slog.Default()
	if !logger.Enabled(ctx, slog.LevelWarn) {
		return
	}
	count := upstreamErrorLogCounter.Add(1)
	if !shouldLogUpstreamErrorCount(count) {
		return
	}

	method := ""
	scheme := ""
	upstreamHost := ""
	queryLen := 0
	if req != nil {
		method = req.Method
		if req.URL != nil {
			scheme = req.URL.Scheme
			upstreamHost = req.URL.Host
			queryLen = len(req.URL.RawQuery)
		}
	}
	logger.LogAttrs(ctx, slog.LevelWarn, "upstream "+mode+" request failed",
		slog.String("method", method),
		slog.String("scheme", scheme),
		slog.String("upstream_host", upstreamHost),
		slog.String("path", upstreamLogPath(req)),
		slog.Int("query_len", queryLen),
		slog.String("host", origHost),
		slog.Uint64("failure_count", count),
		slog.String("err", upstreamErrorReason(err)),
	)
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

func upstreamRequestURL(c *app.RequestContext, base string) string {
	path := c.Request.URI().PathOriginal()
	if len(path) == 0 {
		path = c.Path()
	}
	pathLen := len(path)
	if pathLen == 0 {
		pathLen = 1
	}
	q := c.URI().QueryString()
	baseLen := len(base)
	for baseLen > 0 && base[baseLen-1] == '/' {
		baseLen--
	}

	var b strings.Builder
	b.Grow(baseLen + pathLen + querySuffixLen(q))
	b.WriteString(base[:baseLen])
	if len(path) > 0 {
		b.Write(path)
	} else {
		b.WriteByte('/')
	}
	if len(q) > 0 {
		b.WriteByte('?')
		b.Write(q)
	}
	return b.String()
}

func querySuffixLen(q []byte) int {
	if len(q) == 0 {
		return 0
	}
	return 1 + len(q)
}

func requestMethod(c *app.RequestContext) string {
	method := c.Method()
	switch len(method) {
	case len("GET"):
		if bytes.Equal(method, []byte("GET")) {
			return "GET"
		}
		if bytes.Equal(method, []byte("PUT")) {
			return "PUT"
		}
	case len("POST"):
		if bytes.Equal(method, []byte("POST")) {
			return "POST"
		}
		if bytes.Equal(method, []byte("HEAD")) {
			return "HEAD"
		}
	case len("PATCH"):
		if bytes.Equal(method, []byte("PATCH")) {
			return "PATCH"
		}
		if bytes.Equal(method, []byte("TRACE")) {
			return "TRACE"
		}
	case len("DELETE"):
		if bytes.Equal(method, []byte("DELETE")) {
			return "DELETE"
		}
	case len("OPTIONS"):
		if bytes.Equal(method, []byte("OPTIONS")) {
			return "OPTIONS"
		}
		if bytes.Equal(method, []byte("CONNECT")) {
			return "CONNECT"
		}
	}
	return string(method)
}

func inboundProto(c *app.RequestContext) string {
	if v := forwardedProtoFromHeader(c.GetHeader("X-Forwarded-Proto")); v != "" {
		return v
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
	full := upstreamRequestURL(c, base)

	body := c.Request.Body()
	var rdr io.Reader
	if len(body) > 0 {
		rdr = &byteSliceReadCloser{data: body}
	}

	req, err := http.NewRequestWithContext(ctx, requestMethod(c), full, rdr)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return &byteSliceReadCloser{data: body}, nil
		}
	}

	c.Request.Header.VisitAll(func(k, v []byte) {
		if isHopByHopBytes(k) {
			return
		}
		addUpstreamHeader(req.Header, k, v)
	})

	security.ApplyOutboundForwarding(req, clientIP, origHost, preserveOriginalHost, inboundProto(c))
	return req, nil
}

func addUpstreamHeader(header http.Header, key, value []byte) {
	switch len(key) {
	case len("Accept"):
		if bytes.Equal(key, []byte("Accept")) {
			header["Accept"] = append(header["Accept"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Origin")) {
			header["Origin"] = append(header["Origin"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Pragma")) {
			header["Pragma"] = append(header["Pragma"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Cookie")) {
			header["Cookie"] = append(header["Cookie"], string(value))
			return
		}
	case len("Referer"):
		if bytes.Equal(key, []byte("Referer")) {
			header["Referer"] = append(header["Referer"], string(value))
			return
		}
	case len("Sec-Ch-Ua"):
		if bytes.Equal(key, []byte("Sec-Ch-Ua")) {
			header["Sec-Ch-Ua"] = append(header["Sec-Ch-Ua"], string(value))
			return
		}
	case len("User-Agent"):
		if bytes.Equal(key, []byte("User-Agent")) {
			header["User-Agent"] = append(header["User-Agent"], string(value))
			return
		}
	case len("Content-Type"):
		if bytes.Equal(key, []byte("Content-Type")) {
			header["Content-Type"] = append(header["Content-Type"], string(value))
			return
		}
		if bytes.Equal(key, []byte("X-Tingyun-Id")) {
			header["X-Tingyun-Id"] = append(header["X-Tingyun-Id"], string(value))
			return
		}
	case len("Cache-Control"):
		if bytes.Equal(key, []byte("Cache-Control")) {
			header["Cache-Control"] = append(header["Cache-Control"], string(value))
			return
		}
		if bytes.Equal(key, []byte("X-Client-Data")) {
			header["X-Client-Data"] = append(header["X-Client-Data"], string(value))
			return
		}
	case len("Content-Length"):
		if bytes.Equal(key, []byte("Content-Length")) {
			header["Content-Length"] = append(header["Content-Length"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Sec-Fetch-Site")) {
			header["Sec-Fetch-Site"] = append(header["Sec-Fetch-Site"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Sec-Fetch-Mode")) {
			header["Sec-Fetch-Mode"] = append(header["Sec-Fetch-Mode"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Sec-Fetch-Dest")) {
			header["Sec-Fetch-Dest"] = append(header["Sec-Fetch-Dest"], string(value))
			return
		}
	case len("Accept-Encoding"):
		if bytes.Equal(key, []byte("Accept-Encoding")) {
			header["Accept-Encoding"] = append(header["Accept-Encoding"], string(value))
			return
		}
		if bytes.Equal(key, []byte("Accept-Language")) {
			header["Accept-Language"] = append(header["Accept-Language"], string(value))
			return
		}
	case len("Sec-Ch-Ua-Mobile"):
		if bytes.Equal(key, []byte("Sec-Ch-Ua-Mobile")) {
			header["Sec-Ch-Ua-Mobile"] = append(header["Sec-Ch-Ua-Mobile"], string(value))
			return
		}
		if bytes.Equal(key, []byte("X-Requested-With")) {
			header["X-Requested-With"] = append(header["X-Requested-With"], string(value))
			return
		}
	case len("If-Modified-Since"):
		if bytes.Equal(key, []byte("If-Modified-Since")) {
			header["If-Modified-Since"] = append(header["If-Modified-Since"], string(value))
			return
		}
	case len("Sec-Ch-Ua-Platform"):
		if bytes.Equal(key, []byte("Sec-Ch-Ua-Platform")) {
			header["Sec-Ch-Ua-Platform"] = append(header["Sec-Ch-Ua-Platform"], string(value))
			return
		}
	case len("Upgrade-Insecure-Requests"):
		if bytes.Equal(key, []byte("Upgrade-Insecure-Requests")) {
			header["Upgrade-Insecure-Requests"] = append(header["Upgrade-Insecure-Requests"], string(value))
			return
		}
	}
	header.Add(string(key), string(value))
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
	debugEnabled := slog.Default().Enabled(ctx, slog.LevelDebug)
	var start time.Time
	if debugEnabled {
		start = time.Now()
	}
	resp, err := hc.Do(req)
	if err != nil {
		logUpstreamRequestError(ctx, "buffered", req, origHost, err)
		return nil, err
	}
	defer resp.Body.Close()
	if debugEnabled {
		slog.Debug("upstream buffered response received",
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
			slog.String("host", origHost),
			slog.Int("status", resp.StatusCode),
			slog.String("proto", resp.Proto),
			slog.Duration("latency", time.Since(start)),
		)
	}

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
	return ruleMatchKeyFromPathQuery(requestPath(c), c.URI().QueryString())
}

func ruleMatchKeyFromPathQuery(path string, query []byte) string {
	qs := strings.TrimSpace(string(query))
	if qs == "" {
		return path
	}
	return path + "?" + qs
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
	return buildSiteCacheStorageKeyFromParts(rt, c, requestPath(c), c.URI().QueryString(), stripQuery, lowerPath)
}

func buildSiteCacheStorageKeyFromParts(rt snapshot.SiteRuntime, c *app.RequestContext, path string, query []byte, stripQuery, lowerPath bool) string {
	method := string(c.Method())
	if strings.EqualFold(method, "HEAD") {
		method = "GET"
	}
	p := path
	if lowerPath {
		p = strings.ToLower(p)
	}
	q := string(query)
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
	if !isCacheableRequestMethod(c.Method()) {
		return "", 0, false
	}
	if c.Request.Header.Get("Authorization") != "" {
		return "", 0, false
	}
	// Do not disable edge caching based on the client's Cache-Control/Pragma. Browsers and
	// devtools often send no-cache while operators still want stale shielding when upstream
	// is down. Storage eligibility remains governed by ShouldCacheHTTPResponse (upstream CC,
	// Set-Cookie, Vary, etc.).
	path := requestPath(c)
	query := c.URI().QueryString()
	full := ruleMatchKeyFromPathQuery(path, query)
	ttlVal, stripQ, lowerP, ok := siteCacheFirstMatch(rt, full)
	if !ok || ttlVal <= 0 {
		return "", 0, false
	}
	return buildSiteCacheStorageKeyFromParts(rt, c, path, query, stripQ, lowerP), ttlVal, true
}

func isCacheableRequestMethod(method []byte) bool {
	switch len(method) {
	case len("GET"):
		return asciiEqualFoldBytes(method, "get")
	case len("HEAD"):
		return asciiEqualFoldBytes(method, "head")
	}
	return false
}

// ForwardHTTP copies the incoming request to upstream and streams the response.
func ForwardHTTP(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) error {
	req, err := buildUpstreamRequest(ctx, c, base, clientIP, origHost, rt.PreserveOriginalHost)
	if err != nil {
		return err
	}

	tr := SharedTransportForUpstream(rt, base)
	hc := sharedClient(tr)
	debugEnabled := slog.Default().Enabled(ctx, slog.LevelDebug)
	var start time.Time
	if debugEnabled {
		start = time.Now()
	}
	resp, err := hc.Do(req)
	if err != nil {
		logUpstreamRequestError(ctx, "streaming", req, origHost, err)
		return err
	}
	defer resp.Body.Close()
	if debugEnabled {
		slog.Debug("upstream streaming response received",
			slog.String("method", req.Method),
			slog.String("url", req.URL.String()),
			slog.String("host", origHost),
			slog.Int("status", resp.StatusCode),
			slog.String("proto", resp.Proto),
			slog.Duration("latency", time.Since(start)),
		)
	}

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

func forwardedProtoFromHeader(raw []byte) string {
	start := 0
	end := len(raw)
	for start < end && isASCIISpace(raw[start]) {
		start++
	}
	for end > start && isASCIISpace(raw[end-1]) {
		end--
	}
	if start == end {
		return ""
	}
	trimmed := raw[start:end]
	switch len(trimmed) {
	case len("h3"):
		if asciiEqualFoldBytes(trimmed, "h3") {
			return "h3"
		}
	case len("http"):
		if asciiEqualFoldBytes(trimmed, "http") {
			return "http"
		}
	case len("https"):
		if asciiEqualFoldBytes(trimmed, "https") {
			return "https"
		}
	}
	return strings.ToLower(string(trimmed))
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

func isHopByHopBytes(name []byte) bool {
	switch len(name) {
	case len("te"):
		return asciiEqualFoldBytes(name, "te")
	case len("trailer"):
		return asciiEqualFoldBytes(name, "trailer") || asciiEqualFoldBytes(name, "upgrade")
	case len("connection"):
		return asciiEqualFoldBytes(name, "connection") || asciiEqualFoldBytes(name, "keep-alive")
	case len("proxy-connection"):
		return asciiEqualFoldBytes(name, "proxy-connection")
	case len("transfer-encoding"):
		return asciiEqualFoldBytes(name, "transfer-encoding")
	case len("proxy-authenticate"):
		return asciiEqualFoldBytes(name, "proxy-authenticate")
	case len("proxy-authorization"):
		return asciiEqualFoldBytes(name, "proxy-authorization")
	}
	return false
}

func asciiEqualFoldBytes(got []byte, want string) bool {
	if len(got) != len(want) {
		return false
	}
	for i, b := range got {
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != want[i] {
			return false
		}
	}
	return true
}

func isHopByHop(name string) bool {
	_, ok := hopByHopHeaders[strings.ToLower(name)]
	return ok
}

// IsHopByHop returns whether the given header name is a hop-by-hop header
// that should be stripped when forwarding responses.
func IsHopByHop(name string) bool { return isHopByHop(name) }
