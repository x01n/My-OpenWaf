package dataplane

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

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

	upstreamCtx, cancelUpstream := context.WithCancel(ctx)
	upstreamConn := &proxy.UpstreamRequestConn{}
	req, err := http.NewRequestWithContext(proxy.TraceUpstreamRequestConn(upstreamCtx, upstreamConn), string(c.Method()), full, rdr)
	if err != nil {
		cancelUpstream()
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
		cancelUpstream()
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
	if len(resp.Trailer) > 0 {
		proxy.AddResponseTrailerHeaders(c, resp.Trailer)
	}
	if resp.Header.Get("Server") == "" {
		c.Response.Header.Del("Server")
	}
	c.SetStatusCode(resp.StatusCode)

	c.Response.Header.Set("Cache-Control", "no-cache")
	c.Response.Header.Del("Connection")
	c.Response.Header.Del("Content-Length")
	c.Response.Header.SetContentLength(-1)
	c.Response.ImmediateHeaderFlush = true
	if resp.ProtoMajor != 1 {
		upstreamConn = nil
	}
	stream := newSSEBodyStream(ctx, resp.Body, resp, c, cancelUpstream, upstreamConn)
	if proxy.StreamResponseViaHijack(ctx, c, stream, func() { _ = stream.cleanup() }) {
		return nil
	}
	c.Response.SetBodyStream(stream, -1)

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
	rc           io.ReadCloser
	resp         *http.Response
	hertzCtx     *app.RequestContext
	cancel       context.CancelFunc
	upstreamConn *proxy.UpstreamRequestConn
	done         chan struct{}
	mu           sync.Mutex
	closed       bool
}

func newSSEBodyStream(ctx context.Context, rc io.ReadCloser, resp *http.Response, hertzCtx *app.RequestContext, cancel context.CancelFunc, upstreamConn *proxy.UpstreamRequestConn) *sseBodyStream {
	stream := &sseBodyStream{
		rc:           rc,
		resp:         resp,
		hertzCtx:     hertzCtx,
		cancel:       cancel,
		upstreamConn: upstreamConn,
		done:         make(chan struct{}),
	}
	go func() {
		select {
		case <-ctx.Done():
			stream.cleanup()
		case <-stream.done:
		}
	}()
	return stream
}

func (r *sseBodyStream) cleanup() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	close(r.done)
	r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
	}
	var closeErr error
	if r.upstreamConn != nil {
		closeErr = errors.Join(closeErr, r.upstreamConn.Close())
	}
	copySSETrailers(r.hertzCtx, r.resp.Trailer)
	closeErr = errors.Join(closeErr, r.rc.Close())
	return closeErr
}

func (r *sseBodyStream) Read(p []byte) (int, error) {
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return 0, io.EOF
	}
	n, err := r.rc.Read(p)
	if err != nil {
		_ = r.cleanup()
	}
	return n, err
}

func (r *sseBodyStream) Close() error {
	return r.cleanup()
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
