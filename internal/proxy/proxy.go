package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
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

	security.ApplyOutboundForwarding(req, clientIP, origHost, preserveOriginalHost)
	return req, nil
}

func copyResponseHeaders(dst *app.RequestContext, src http.Header) {
	for k, vv := range src {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vv {
			dst.Response.Header.Add(k, v)
		}
	}
	if src.Get("Server") == "" {
		dst.Response.Header.Del("Server")
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
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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

func ForwardCachedResponse(c *app.RequestContext, entryStatus int, contentType string, body []byte) {
	if contentType != "" {
		c.SetContentType(contentType)
	}
	c.Status(entryStatus)
	c.Response.SetBodyRaw(body)
}

func ShouldCacheResponse(method string, statusCode int, body []byte) bool {
	return strings.EqualFold(method, "GET") && statusCode == 200 && len(body) > 0
}

func ShouldCacheHTTPResponse(method string, resp *HTTPResponse) bool {
	if resp == nil || !ShouldCacheResponse(method, resp.StatusCode, resp.Body) {
		return false
	}
	if resp.Header.Get("Set-Cookie") != "" {
		return false
	}
	cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))
	if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "private") {
		return false
	}
	if resp.Header.Get("Vary") != "" {
		return false
	}
	return true
}

func SiteCacheTTL(rt snapshot.SiteRuntime, path string) int64 {
	if !rt.CacheEnabled {
		return 0
	}
	for _, rule := range rt.CacheRules {
		ruleType := strings.ToLower(strings.TrimSpace(rule.Type))
		if ruleType == "" {
			ruleType = "prefix"
		}
		switch ruleType {
		case "exact":
			if path == rule.Value {
				return int64(rule.TTL)
			}
		case "suffix":
			if strings.HasSuffix(path, rule.Value) {
				return int64(rule.TTL)
			}
		default:
			if strings.HasPrefix(path, rule.Value) {
				return int64(rule.TTL)
			}
		}
	}
	if rt.CacheDefaultTTL > 0 {
		return int64(rt.CacheDefaultTTL)
	}
	return 0
}

func SiteCacheKey(rt snapshot.SiteRuntime, c *app.RequestContext) string {
	hostKey := strings.TrimSpace(rt.Bind) + "|" + strconv.FormatUint(uint64(rt.Site.ID), 10) + "|" + string(c.Host())
	return cache.CacheKey(string(c.Method()), hostKey, requestPath(c), string(c.URI().QueryString()))
}

func SiteCacheEligible(rt snapshot.SiteRuntime, c *app.RequestContext) (string, int64) {
	if !rt.CacheEnabled || !strings.EqualFold(string(c.Method()), "GET") {
		return "", 0
	}
	if c.Request.Header.Get("Authorization") != "" {
		return "", 0
	}
	cacheControl := strings.ToLower(string(c.Request.Header.Peek("Cache-Control")))
	if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "no-cache") {
		return "", 0
	}
	ttl := SiteCacheTTL(rt, requestPath(c))
	if ttl <= 0 {
		return "", 0
	}
	return SiteCacheKey(rt, c), ttl
}

// ForwardHTTP copies the incoming request to upstream and streams the response.
func ForwardHTTP(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) error {
	req, err := buildUpstreamRequest(ctx, c, base, clientIP, origHost, rt.PreserveOriginalHost)
	if err != nil {
		return err
	}

	tr := SharedTransportForUpstream(rt, base)
	hc := sharedClient(tr)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

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
