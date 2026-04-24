package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

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
	isHTTPS := len(rt.UpstreamURLs) > 0 && strings.HasPrefix(rt.UpstreamURLs[0], "https://")
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

// ForwardHTTP copies the incoming request to upstream and streams the response.
func ForwardHTTP(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) error {
	path := string(c.Path())
	if path == "" {
		path = "/"
	}
	q := c.URI().QueryString()
	full := strings.TrimRight(base, "/") + path
	if len(q) > 0 {
		full += "?" + string(q)
	}

	body := c.Request.Body()
	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, string(c.Method()), full, rdr)
	if err != nil {
		return err
	}

	c.Request.Header.VisitAll(func(k, v []byte) {
		key := strings.ToLower(string(k))
		if _, skip := hopByHopHeaders[key]; skip {
			return
		}
		req.Header.Add(string(k), string(v))
	})

	security.ApplyOutboundForwarding(req, clientIP, origHost, rt.PreserveOriginalHost)

	tr := SharedTransport(rt)
	hc := sharedClient(tr)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Strip hop-by-hop headers from upstream response before forwarding to client.
	for k, vv := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vv {
			c.Response.Header.Add(k, v)
		}
	}
	// Remove any Server header added by the framework — let upstream's header stand.
	if resp.Header.Get("Server") == "" {
		c.Response.Header.Del("Server")
	}
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
