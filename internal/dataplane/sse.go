package dataplane

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
)

// ForwardSSE streams a text/event-stream response from upstream to the client.
func ForwardSSE(ctx context.Context, c *app.RequestContext, rt snapshot.SiteRuntime, base string, clientIP net.IP, origHost string) error {
	transport, normalizedBase := proxy.UpstreamRoundTripperForBase(rt, base)
	rawPath := string(c.Request.URI().RequestURI())
	full := strings.TrimRight(normalizedBase, "/") + rawPath

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
		switch key {
		case "connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "host":
			return
		}
		if isInternalHTTP3Header(key) {
			return
		}
		req.Header.Add(string(k), string(v))
	})
	security.ApplyOutboundForwarding(req, clientIP, origHost, rt.PreserveOriginalHost, rt.Site.UpstreamHost, inboundProto(c, rt.Site.TLSEnabled))

	hc := &http.Client{Transport: transport, Timeout: 0}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	proxy.SetUpstreamHTTPProtocol(c, resp.Proto)

	connTokens := parseConnectionTokens(resp.Header.Get("Connection"))
	for k, vv := range resp.Header {
		if proxy.IsHopByHop(k) || connTokens[strings.ToLower(k)] {
			continue
		}
		for _, v := range vv {
			c.Response.Header.Add(k, v)
		}
	}
	if resp.Header.Get("Server") == "" {
		c.Response.Header.Del("Server")
	}
	c.SetStatusCode(resp.StatusCode)

	c.Response.Header.Set("Cache-Control", "no-cache")
	c.Response.Header.Del("Connection")
	c.Response.Header.Del("Content-Length")
	c.Response.ImmediateHeaderFlush = true
	c.Response.SetBodyStream(&sseBodyStream{rc: resp.Body, resp: resp, hertzCtx: c}, -1)

	return nil
}

func inboundProto(c *app.RequestContext, tlsEnabled bool) string {
	if v := strings.TrimSpace(string(c.GetHeader("X-Forwarded-Proto"))); v != "" {
		return strings.ToLower(v)
	}
	if tlsEnabled {
		return "https"
	}
	return "http"
}

func parseConnectionTokens(conn string) map[string]bool {
	if conn == "" {
		return nil
	}
	tokens := make(map[string]bool)
	for _, tok := range strings.Split(conn, ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			tokens[strings.ToLower(tok)] = true
		}
	}
	return tokens
}

func isInternalHTTP3Header(key string) bool {
	return strings.HasPrefix(key, "x-openwaf-internal-")
}

type autoCloseReader struct {
	rc     io.ReadCloser
	closed bool
}

func (r *autoCloseReader) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	if err != nil && !r.closed {
		r.closed = true
		_ = r.rc.Close()
	}
	return n, err
}

func (r *autoCloseReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.rc.Close()
}

type sseBodyStream struct {
	rc       io.ReadCloser
	resp     *http.Response
	hertzCtx *app.RequestContext
	closed   bool
}

func (r *sseBodyStream) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	if err != nil && !r.closed {
		r.closed = true
		_ = r.rc.Close()
		copySSETrailers(r.hertzCtx, r.resp.Trailer)
	}
	return n, err
}

func (r *sseBodyStream) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	copySSETrailers(r.hertzCtx, r.resp.Trailer)
	return r.rc.Close()
}

func copySSETrailers(c *app.RequestContext, trailers http.Header) {
	for k, vv := range trailers {
		lk := strings.ToLower(k)
		if proxy.IsHopByHop(lk) || lk == "content-encoding" || lk == "content-length" || lk == "content-range" || lk == "content-type" {
			continue
		}
		for _, v := range vv {
			c.Response.Header.Trailer().Set(k, v)
		}
	}
}

// IsSSERequest checks if the client expects a text/event-stream response.
func IsSSERequest(c *app.RequestContext) bool {
	accept := strings.ToLower(string(c.GetHeader("Accept")))
	idx := strings.Index(accept, "text/event-stream")
	if idx < 0 {
		return false
	}
	end := idx + len("text/event-stream")
	if end < len(accept) {
		next := accept[end]
		if next != ';' && next != ',' && next != ' ' && next != '\t' {
			return false
		}
	}
	return true
}
