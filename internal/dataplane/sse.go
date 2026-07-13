package dataplane

import (
	"bytes"
	"context"
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
	req, err := http.NewRequestWithContext(upstreamCtx, string(c.Method()), full, rdr)
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
	stream := newSSEBodyStream(ctx, resp.Body, resp, c, cancelUpstream)
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
	rc            io.ReadCloser
	resp          *http.Response
	hertzCtx      *app.RequestContext
	cancel        context.CancelFunc
	done          chan struct{}
	mu            sync.Mutex
	cond          *sync.Cond
	activeReaders int
	closing       bool
	closed        bool
	closeErr      error
}

func newSSEBodyStream(ctx context.Context, rc io.ReadCloser, resp *http.Response, hertzCtx *app.RequestContext, cancel context.CancelFunc) *sseBodyStream {
	stream := &sseBodyStream{
		rc:       rc,
		resp:     resp,
		hertzCtx: hertzCtx,
		cancel:   cancel,
		done:     make(chan struct{}),
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
		err := r.closeErr
		r.mu.Unlock()
		return err
	}
	if r.closing {
		r.initCondLocked()
		for !r.closed {
			r.cond.Wait()
		}
		err := r.closeErr
		r.mu.Unlock()
		return err
	}
	r.closing = true
	close(r.done)
	cancel := r.cancel
	r.cancel = nil
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	r.mu.Lock()
	r.initCondLocked()
	for r.activeReaders > 0 {
		r.cond.Wait()
	}
	r.mu.Unlock()

	copySSETrailers(r.hertzCtx, r.resp.Trailer)
	closeErr := r.rc.Close()

	r.mu.Lock()
	r.closeErr = closeErr
	r.closed = true
	r.cond.Broadcast()
	r.mu.Unlock()
	return closeErr
}

func (r *sseBodyStream) Read(p []byte) (int, error) {
	r.mu.Lock()
	if r.closing || r.closed {
		r.mu.Unlock()
		return 0, io.EOF
	}
	r.activeReaders++
	r.mu.Unlock()

	n, err := r.rc.Read(p)

	r.mu.Lock()
	r.activeReaders--
	if r.activeReaders == 0 && r.cond != nil {
		r.cond.Broadcast()
	}
	r.mu.Unlock()
	if err != nil {
		_ = r.cleanup()
	}
	return n, err
}

func (r *sseBodyStream) Close() error {
	return r.cleanup()
}

func (r *sseBodyStream) initCondLocked() {
	if r.cond == nil {
		r.cond = sync.NewCond(&r.mu)
	}
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
