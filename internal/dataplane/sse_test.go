package dataplane

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/quic-go/quic-go/http3"

	"My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

var benchmarkSSERequestSink bool

func TestForwardSSEUsesUnifiedUpstreamRequestSemantics(t *testing.T) {
	type upstreamObservation struct {
		method          string
		path            string
		rawQuery        string
		hostHeader      string
		requestHost     string
		forwardedFor    string
		forwardedHost   string
		forwardedProto  string
		internalProto   string
		internalVersion string
		te              string
		trailer         string
		connection      string
		body            string
	}

	seen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream request body: %v", err)
		}
		seen <- upstreamObservation{
			method:          r.Method,
			path:            r.URL.EscapedPath(),
			rawQuery:        r.URL.RawQuery,
			hostHeader:      r.Header.Get("Host"),
			requestHost:     r.Host,
			forwardedFor:    r.Header.Get("X-Forwarded-For"),
			forwardedHost:   r.Header.Get("X-Forwarded-Host"),
			forwardedProto:  r.Header.Get("X-Forwarded-Proto"),
			internalProto:   r.Header.Get(InternalHTTP3ProtoHeader),
			internalVersion: r.Header.Get(InternalHTTP3TLSVersionHeader),
			te:              r.Header.Get("TE"),
			trailer:         r.Header.Get("Trailer"),
			connection:      r.Header.Get("Connection"),
			body:            string(body),
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", "12")
		w.Header().Set("Connection", "keep-alive, X-SSE-Hop")
		w.Header().Set("X-SSE-Hop", "drop")
		w.Header().Set("X-SSE-End-To-End", "kept")
		_, _ = io.WriteString(w, "data: ok\n\n")
	}))
	t.Cleanup(upstream.Close)

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.SetRequestURI("/sse/%E4%B8%AD/events?stream=1")
	ctx.Request.Header.SetHost("client.example")
	ctx.Request.Header.Set("Accept", "text/event-stream")
	ctx.Request.Header.Set("Host", "client.example")
	ctx.Request.Header.Set("Connection", "keep-alive")
	ctx.Request.Header.Set("TE", "gzip")
	ctx.Request.Header.Set("Trailer", "X-Late")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSVersionHeader, "TLS13")
	ctx.Request.SetBody([]byte("payload"))

	rt := snapshot.SiteRuntime{
		Site:                 store.Site{PreserveOriginalHost: true},
		PreserveOriginalHost: true,
	}
	err := ForwardSSE(context.Background(), ctx, rt, upstream.URL, net.ParseIP("203.0.113.10"), "client.example")
	if err != nil {
		t.Fatalf("ForwardSSE returned error: %v", err)
	}
	if got := ctx.Response.Header.ContentLength(); got != -1 {
		t.Fatalf("SSE Content-Length = %d, want -1", got)
	}
	if got := string(ctx.Response.Header.Peek("Connection")); got != "" {
		t.Fatalf("SSE Connection response header = %q, want empty", got)
	}
	if got := string(ctx.Response.Header.Peek("X-SSE-Hop")); got != "" {
		t.Fatalf("SSE Connection token response header = %q, want empty", got)
	}
	if got := string(ctx.Response.Header.Peek("X-SSE-End-To-End")); got != "kept" {
		t.Fatalf("SSE end-to-end response header = %q, want kept", got)
	}

	got := <-seen
	if got.method != http.MethodPost {
		t.Fatalf("upstream method = %q, want %q", got.method, http.MethodPost)
	}
	if got.path != "/sse/%E4%B8%AD/events" {
		t.Fatalf("upstream escaped path = %q", got.path)
	}
	if got.rawQuery != "stream=1" {
		t.Fatalf("upstream raw query = %q", got.rawQuery)
	}
	if got.hostHeader != "" {
		t.Fatalf("upstream ordinary Host header = %q, want empty", got.hostHeader)
	}
	if got.requestHost != "client.example" {
		t.Fatalf("upstream Request.Host = %q, want client.example", got.requestHost)
	}
	if got.forwardedFor != "203.0.113.10" {
		t.Fatalf("upstream X-Forwarded-For = %q", got.forwardedFor)
	}
	if got.forwardedHost != "client.example" {
		t.Fatalf("upstream X-Forwarded-Host = %q", got.forwardedHost)
	}
	if got.forwardedProto != "h3" {
		t.Fatalf("upstream X-Forwarded-Proto = %q, want h3", got.forwardedProto)
	}
	if got.internalProto != "" || got.internalVersion != "" {
		t.Fatalf("upstream leaked internal HTTP/3 headers: proto=%q version=%q", got.internalProto, got.internalVersion)
	}
	if got.te != "" || got.trailer != "" || got.connection != "" {
		t.Fatalf("upstream hop-by-hop headers leaked: TE=%q Trailer=%q Connection=%q", got.te, got.trailer, got.connection)
	}
	if got.body != "payload" {
		t.Fatalf("upstream body = %q", got.body)
	}
}

func TestForwardSSEUsesConfiguredUpstreamHost(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Host
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: ok\n\n")
	}))
	t.Cleanup(upstream.Close)

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/events")
	ctx.Request.Header.SetHost("client.example")
	ctx.Request.Header.Set("Accept", "text/event-stream")

	rt := snapshot.SiteRuntime{Site: store.Site{UpstreamHost: "backend.example.com"}}
	err := ForwardSSE(context.Background(), ctx, rt, upstream.URL, net.ParseIP("203.0.113.10"), "client.example")
	if err != nil {
		t.Fatalf("ForwardSSE returned error: %v", err)
	}
	if got := <-seen; got != "backend.example.com" {
		t.Fatalf("upstream Host = %q, want backend.example.com", got)
	}
}

func TestForwardSSEUsesExplicitUpstreamProtocols(t *testing.T) {
	assertSSEStream := func(t *testing.T, ctx *app.RequestContext, wantBody string, wantEndToEnd string, wantTrailer string) {
		t.Helper()
		if got := ctx.Response.StatusCode(); got != http.StatusOK {
			t.Fatalf("SSE status = %d, want %d", got, http.StatusOK)
		}
		if !ctx.Response.ImmediateHeaderFlush {
			t.Fatal("SSE response should flush headers immediately")
		}
		if got := ctx.Response.Header.ContentLength(); got != -1 {
			t.Fatalf("SSE Content-Length = %d, want -1", got)
		}
		if got := string(ctx.Response.Header.Peek("Connection")); got != "" {
			t.Fatalf("SSE Connection response header = %q, want empty", got)
		}
		if got := string(ctx.Response.Header.Peek("Cache-Control")); got != "no-cache" {
			t.Fatalf("SSE Cache-Control = %q, want no-cache", got)
		}
		if got := string(ctx.Response.Header.Peek("Content-Type")); got != "text/event-stream" {
			t.Fatalf("SSE Content-Type = %q, want text/event-stream", got)
		}
		if got := string(ctx.Response.Header.Peek("X-SSE-End-To-End")); got != wantEndToEnd {
			t.Fatalf("SSE end-to-end response header = %q, want %q", got, wantEndToEnd)
		}
		body, err := io.ReadAll(ctx.Response.BodyStream())
		if err != nil {
			t.Fatalf("read SSE body stream: %v", err)
		}
		if err := ctx.Response.CloseBodyStream(); err != nil {
			t.Fatalf("close SSE body stream: %v", err)
		}
		if string(body) != wantBody {
			t.Fatalf("SSE body = %q, want %q", string(body), wantBody)
		}
		if got := ctx.Response.Header.Trailer().Get("X-SSE-Trailer"); got != wantTrailer {
			t.Fatalf("SSE response trailer X-SSE-Trailer = %q, want %q", got, wantTrailer)
		}
		for _, name := range []string{"Connection", "Content-Encoding", "Content-Length", "Content-Range", "Content-Type", "Keep-Alive", "Transfer-Encoding"} {
			if got := ctx.Response.Header.Trailer().Get(name); got != "" {
				t.Fatalf("SSE response trailer %s = %q, want empty", name, got)
			}
		}
	}

	t.Run("h2c", func(t *testing.T) {
		upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Proto != "HTTP/2.0" {
				t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Header().Set("Content-Length", "11")
			w.Header().Set("X-SSE-End-To-End", "kept-h2c")
			w.Header().Set("Trailer", "X-SSE-Trailer")
			_, _ = io.WriteString(w, "data: h2c\n\n")
			w.Header().Set("X-SSE-Trailer", "done-h2c")
		}))
		upstream.Config.Protocols = new(http.Protocols)
		upstream.Config.Protocols.SetHTTP1(true)
		upstream.Config.Protocols.SetUnencryptedHTTP2(true)
		upstream.Start()
		defer upstream.Close()

		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod(http.MethodGet)
		ctx.Request.SetRequestURI("/events")
		ctx.Request.Header.SetHost("client.example")
		ctx.Request.Header.Set("Accept", "text/event-stream")

		base := strings.Replace(upstream.URL, "http://", "h2c://", 1)
		err := ForwardSSE(context.Background(), ctx, snapshot.SiteRuntime{}, base, net.ParseIP("203.0.113.10"), "client.example")
		if err != nil {
			t.Fatalf("ForwardSSE returned error: %v", err)
		}
		assertSSEStream(t, ctx, "data: h2c\n\n", "kept-h2c", "done-h2c")
	})

	t.Run("h3", func(t *testing.T) {
		base := startSSETestHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Proto != "HTTP/3.0" {
				t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Header().Set("Content-Length", "10")
			w.Header().Set("X-SSE-End-To-End", "kept-h3")
			w.Header().Set("Trailer", "X-SSE-Trailer")
			_, _ = io.WriteString(w, "data: h3\n\n")
			w.Header().Set("X-SSE-Trailer", "done-h3")
		}))

		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod(http.MethodGet)
		ctx.Request.SetRequestURI("/events")
		ctx.Request.Header.SetHost("client.example")
		ctx.Request.Header.Set("Accept", "text/event-stream")

		rt := snapshot.SiteRuntime{
			Site: store.Site{
				UpstreamTLSSkipVerify: true,
			},
		}
		err := ForwardSSE(context.Background(), ctx, rt, base, net.ParseIP("203.0.113.10"), "client.example")
		if err != nil {
			t.Fatalf("ForwardSSE returned error: %v", err)
		}
		assertSSEStream(t, ctx, "data: h3\n\n", "kept-h3", "done-h3")
	})
}

func TestForwardSSECancelClosesExplicitUpstreamBodyStreams(t *testing.T) {
	assertCanceled := func(t *testing.T, base string, rt snapshot.SiteRuntime, upstreamDone <-chan struct{}) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		reqCtx := app.NewContext(0)
		reqCtx.Request.Header.SetMethod(http.MethodGet)
		reqCtx.Request.SetRequestURI("/events")
		reqCtx.Request.Header.SetHost("client.example")
		reqCtx.Request.Header.Set("Accept", "text/event-stream")

		err := ForwardSSE(ctx, reqCtx, rt, base, net.ParseIP("203.0.113.10"), "client.example")
		if err != nil {
			t.Fatalf("ForwardSSE returned error: %v", err)
		}

		cancel()
		select {
		case <-upstreamDone:
		case <-time.After(2 * time.Second):
			_ = reqCtx.Response.CloseBodyStream()
			t.Fatalf("upstream SSE body stream was not closed after request cancellation")
		}
		if err := reqCtx.Response.CloseBodyStream(); err != nil {
			t.Fatalf("close SSE body stream: %v", err)
		}
	}

	t.Run("h2c", func(t *testing.T) {
		upstreamDone := make(chan struct{})
		upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Proto != "HTTP/2.0" {
				t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
			}
			writeSSEOpenChunkAndWaitForCancel(t, w, r, upstreamDone)
		}))
		upstream.Config.Protocols = new(http.Protocols)
		upstream.Config.Protocols.SetHTTP1(true)
		upstream.Config.Protocols.SetUnencryptedHTTP2(true)
		upstream.Start()
		defer upstream.Close()

		base := strings.Replace(upstream.URL, "http://", "h2c://", 1)
		assertCanceled(t, base, snapshot.SiteRuntime{}, upstreamDone)
	})

	t.Run("h3", func(t *testing.T) {
		upstreamDone := make(chan struct{})
		base := startSSETestHTTP3UpstreamServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Proto != "HTTP/3.0" {
				t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/3.0")
			}
			writeSSEOpenChunkAndWaitForCancel(t, w, r, upstreamDone)
		}))

		rt := snapshot.SiteRuntime{
			Site: store.Site{
				UpstreamTLSSkipVerify: true,
			},
		}
		assertCanceled(t, base, rt, upstreamDone)
	})
}

func TestIsSSERequestUsesCaseInsensitiveAcceptToken(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("Accept", "application/json, Text/Event-Stream; charset=utf-8")
	if !IsSSERequest(ctx) {
		t.Fatal("expected mixed-case text/event-stream Accept token to be detected")
	}

	ctx.Request.Header.Set("Accept", "application/json, text/event-streaming")
	if IsSSERequest(ctx) {
		t.Fatal("text/event-streaming must not be treated as a SSE Accept token")
	}
}

func writeSSEOpenChunkAndWaitForCancel(t *testing.T, w http.ResponseWriter, r *http.Request, done chan<- struct{}) {
	t.Helper()
	w.Header().Set("Content-Type", "text/event-stream")
	_, _ = io.WriteString(w, "data: opened\n\n")
	flusher, ok := w.(http.Flusher)
	if !ok {
		t.Fatalf("SSE upstream response writer does not implement http.Flusher")
	}
	flusher.Flush()
	<-r.Context().Done()
	close(done)
}

func BenchmarkIsSSERequestAcceptToken(b *testing.B) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("Accept", "application/json, application/problem+json;q=0.8, text/event-stream; charset=utf-8")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkSSERequestSink = IsSSERequest(ctx)
	}
}

func startSSETestHTTP3UpstreamServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	cert, err := acme.GenerateSelfSigned("127.0.0.1:0")
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	server := &http3.Server{
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h3"},
		},
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(pc)
	}()
	t.Cleanup(func() {
		if err := server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("close http3 server: %v", err)
		}
		select {
		case serveErr := <-errCh:
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !strings.Contains(serveErr.Error(), "closed network connection") {
				t.Fatalf("http3 serve returned error: %v", serveErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("http3 server did not stop in time")
		}
	})

	return "h3://" + pc.LocalAddr().String()
}
