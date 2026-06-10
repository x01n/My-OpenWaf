package dataplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/network"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/bot"
)

func TestBuildWebSocketHandshakeHeadersAppliesForwarding(t *testing.T) {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetHost("client.example")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "abc")
	req.Header.Set("X-Custom", "yes")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)

	rt := snapshot.SiteRuntime{Site: store.Site{PreserveOriginalHost: true}, PreserveOriginalHost: true}
	got := buildWebSocketHandshakeHeaders(ctx, "/ws?token=1", "upstream.internal:8080", "wss", rt, net.ParseIP("203.0.113.10"))

	for _, want := range []string{
		"GET /ws?token=1 HTTP/1.1\r\n",
		"Host: client.example\r\n",
		"X-Forwarded-For: 203.0.113.10\r\n",
		"X-Forwarded-Host: client.example\r\n",
		"X-Forwarded-Proto: https\r\n",
		"Sec-Websocket-Key: abc\r\n",
		"Connection: Upgrade\r\n",
		"X-Custom: yes\r\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("handshake headers missing %q in %q", want, got)
		}
	}
	if strings.Count(strings.ToLower(got), "connection: upgrade\r\n") != 1 {
		t.Fatalf("Connection upgrade header should be rebuilt exactly once, got %q", got)
	}
}

func TestBuildWebSocketHandshakeHeadersUsesUpstreamHostByDefault(t *testing.T) {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetHost("client.example")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)

	rt := snapshot.SiteRuntime{Site: store.Site{PreserveOriginalHost: false}}
	got := buildWebSocketHandshakeHeaders(ctx, "/ws", "upstream.internal:8080", "ws", rt, nil)

	if !strings.Contains(got, "Host: upstream.internal:8080\r\n") {
		t.Fatalf("expected upstream Host header, got %q", got)
	}
	if !strings.Contains(got, "X-Forwarded-Proto: http\r\n") {
		t.Fatalf("expected http forwarded proto, got %q", got)
	}
	if strings.Contains(got, "X-Forwarded-Host:") || strings.Contains(got, "X-Forwarded-For:") {
		t.Fatalf("unexpected forwarded headers, got %q", got)
	}
}

type testHertzConn struct {
	net.Conn
}

func (c *testHertzConn) Peek(n int) ([]byte, error) { return nil, io.EOF }
func (c *testHertzConn) Skip(n int) error           { return nil }
func (c *testHertzConn) Release() error             { return nil }
func (c *testHertzConn) Len() int                   { return 0 }
func (c *testHertzConn) ReadByte() (byte, error)    { return 0, io.EOF }
func (c *testHertzConn) ReadBinary(n int) ([]byte, error) {
	return nil, io.EOF
}
func (c *testHertzConn) Malloc(n int) ([]byte, error) { return make([]byte, n), nil }
func (c *testHertzConn) WriteBinary(b []byte) (int, error) {
	return c.Write(b)
}
func (c *testHertzConn) Flush() error { return nil }
func (c *testHertzConn) SetReadTimeout(t time.Duration) error {
	return c.SetReadDeadline(time.Now().Add(t))
}
func (c *testHertzConn) SetWriteTimeout(t time.Duration) error {
	return c.SetWriteDeadline(time.Now().Add(t))
}

func (c *testHertzConn) NetConn() net.Conn { return c.Conn }

func TestReadWSFrameLargePayloadPreservesRawFrame(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), wsInspectFrameLimit+512)
	maskKey := [4]byte{1, 2, 3, 4}

	raw := []byte{0x82, 0x80 | 126, 0, 0}
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(payload)))
	raw = append(raw, maskKey[:]...)
	maskedPayload := append([]byte(nil), payload...)
	for i := range maskedPayload {
		maskedPayload[i] ^= maskKey[i%4]
	}
	raw = append(raw, maskedPayload...)

	frame, err := readWSFrame(bytes.NewReader(raw), wsInspectFrameLimit)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if !bytes.Equal(frame.Raw, raw) {
		t.Fatalf("raw frame should be preserved, got %d bytes want %d", len(frame.Raw), len(raw))
	}
	if len(frame.Payload) != wsInspectFrameLimit {
		t.Fatalf("decoded inspection payload should be capped to %d, got %d", wsInspectFrameLimit, len(frame.Payload))
	}
	if !bytes.Equal(frame.Payload, payload[:wsInspectFrameLimit]) {
		t.Fatal("decoded inspection payload does not match payload prefix")
	}
}

func TestReadWSFrameLarge127PayloadPreservesRawFrame(t *testing.T) {
	payload := bytes.Repeat([]byte("b"), 66000)
	raw := []byte{0x82, 127, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(raw[2:10], uint64(len(payload)))
	raw = append(raw, payload...)

	frame, err := readWSFrame(bytes.NewReader(raw), wsInspectFrameLimit)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if !bytes.Equal(frame.Raw, raw) {
		t.Fatalf("raw frame should be preserved, got %d bytes want %d", len(frame.Raw), len(raw))
	}
	if len(frame.Payload) != wsInspectFrameLimit {
		t.Fatalf("decoded inspection payload should be capped to %d, got %d", wsInspectFrameLimit, len(frame.Payload))
	}
}

func TestBuildAccessLogEntryDoesNotRecordProxyTLSFingerprintForHTTP3(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{
		TLSVersion: "TLS13",
		JA3Hash:    "proxy-ja3",
		JA4:        "proxy-ja4",
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("X-OpenWaf-Internal-Proto", "h3")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.SetConn(&testHertzConn{Conn: wrapped})

	entry := buildAccessLogEntry(ctx, accessLogInfo{SiteID: 1})
	if entry.HTTPProtocol != "h3" {
		t.Fatalf("expected h3 protocol, got %q", entry.HTTPProtocol)
	}
	if entry.TLSJA3Hash != "" || entry.TLSJA4 != "" || entry.TLSVersion != "" {
		t.Fatalf("HTTP/3 proxy TLS fingerprint should not be logged as client fingerprint: %+v", entry)
	}
}

func TestRequestProtocolPrefersTLSOverSpoofedForwardedProto(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{TLSVersion: "TLS13", JA3Hash: "real"})
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.SetConn(&testHertzConn{Conn: wrapped})

	if got := requestProtocol(ctx); got != "https" {
		t.Fatalf("expected real TLS connection to win over spoofed forwarded proto, got %q", got)
	}
}

func TestRequestProtocolIgnoresSpoofedInternalHTTP3Header(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{TLSVersion: "TLS13", JA3Hash: "real"})
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("X-OpenWaf-Internal-Proto", "h3")
	ctx.SetConn(&testHertzConn{Conn: wrapped})

	entry := buildAccessLogEntry(ctx, accessLogInfo{SiteID: 1})
	if entry.HTTPProtocol != "https" {
		t.Fatalf("expected spoofed internal h3 header to be ignored on TLS request, got %q", entry.HTTPProtocol)
	}
	if entry.TLSJA3Hash != "real" {
		t.Fatalf("expected TLS fingerprint to be retained, got %+v", entry)
	}
}

func TestTLSFingerprintCarrierPreservesHandshakeUpdates(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := &peekConn{Conn: server, fingerprint: bot.TLSClientFingerprint{JA3Hash: "ja3"}}
	wrapped := bot.WrapFingerprintConn(pc, pc.fingerprint)
	pc.SetTLSHandshakeInfo("TLS13", "client.example", "h2")

	fp, ok := bot.TLSFingerprintFromConn(wrapped)
	if !ok {
		t.Fatal("expected fingerprint from wrapped connection")
	}
	if fp.JA3Hash != "ja3" || fp.TLSVersion != "TLS13" || fp.SNI != "client.example" || len(fp.ALPN) != 1 || fp.ALPN[0] != "h2" {
		t.Fatalf("unexpected fingerprint after handshake update: %+v", fp)
	}
}

func TestBuildAccessLogEntryMergesHandshakeTLSMetadata(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Set(tlsFingerprintContextKey, bot.TLSClientFingerprint{
		TLSVersion: "TLS13",
		SNI:        "client.example",
		ALPN:       []string{"h2"},
	})

	entry := buildAccessLogEntry(ctx, accessLogInfo{
		SiteID:       1,
		HTTPProtocol: "https",
		TLSFingerprint: bot.TLSClientFingerprint{
			JA3Hash: "ja3",
			JA4:     "ja4",
		},
	})
	if entry.TLSJA3Hash != "ja3" || entry.TLSJA4 != "ja4" {
		t.Fatalf("expected parsed JA3/JA4 to be retained, got %+v", entry)
	}
	if entry.TLSVersion != "TLS13" || entry.TLSSNI != "client.example" || entry.TLSALPN != "h2" {
		t.Fatalf("expected handshake TLS metadata to be merged, got %+v", entry)
	}
}

func TestFixURIConnForwardsTLSFingerprint(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{TLSVersion: "TLS13", JA3Hash: "real"})
	fixed := &FixURIConn{Conn: wrapped}
	fp, ok := bot.TLSFingerprintFromConn(fixed)
	if !ok || fp.TLSVersion != "TLS13" || fp.JA3Hash != "real" {
		t.Fatalf("expected FixURIConn to forward TLS fingerprint, got ok=%v fp=%+v", ok, fp)
	}
}

func TestFixURIWrappersForwardHandshakeInfoThroughNetConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	parsed := bot.TLSClientFingerprint{
		JA3Hash:    "ja3",
		JA4:        "ja4",
		TLSVersion: "TLS13",
		SNI:        "client.example",
		ALPN:       []string{"h2", "http/1.1"},
	}
	pc := &peekConn{Conn: server, fingerprint: parsed}
	tlsLike := &testNetConnUnwrapper{Conn: server, inner: pc}
	fixed := &FixURIConn{Conn: tlsLike}
	hertzConn := newFixURIHertzConn(fixed)

	hertzConn.SetTLSHandshakeInfo("TLS12", "client.example", "http/1.1")

	fp, ok := pc.TLSFingerprint()
	if !ok {
		t.Fatal("expected fingerprint after handshake update")
	}
	if fp.JA3Hash != "ja3" || fp.JA4 != "ja4" {
		t.Fatalf("expected parsed JA3/JA4 to be retained, got %+v", fp)
	}
	if fp.TLSVersion != "TLS12" || fp.SNI != "client.example" || len(fp.ALPN) != 1 || fp.ALPN[0] != "http/1.1" {
		t.Fatalf("expected final handshake metadata to reach peekConn, got %+v", fp)
	}
	got, ok := bot.TLSFingerprintFromConn(hertzConn)
	if !ok {
		t.Fatal("expected Hertz connection to expose TLS fingerprint")
	}
	if got.TLSVersion != "TLS12" || got.SNI != "client.example" || len(got.ALPN) != 1 || got.ALPN[0] != "http/1.1" {
		t.Fatalf("expected Hertz connection to expose final TLS metadata, got %+v", got)
	}
}

func TestContextWithTLSHandshakeInfoPreservesParsedFingerprint(t *testing.T) {
	ctx := ContextWithTLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		JA3Hash: "ja3",
		JA4:     "ja4",
		SNI:     "client.example",
		ALPN:    []string{"http/1.1"},
	})

	ctx = ContextWithTLSHandshakeInfo(ctx, "TLS13", "client.example", "h2")

	fp, ok := tlsFingerprintFromContext(ctx)
	if !ok {
		t.Fatal("expected TLS fingerprint in context")
	}
	if fp.JA3Hash != "ja3" || fp.JA4 != "ja4" || fp.SNI != "client.example" || fp.TLSVersion != "TLS13" {
		t.Fatalf("unexpected merged TLS fingerprint: %+v", fp)
	}
	if len(fp.ALPN) != 1 || fp.ALPN[0] != "h2" {
		t.Fatalf("unexpected merged ALPN: %+v", fp.ALPN)
	}
}

func TestTLSFingerprintFromRequestContextUsesCachedValue(t *testing.T) {
	ctx := app.NewContext(0)
	want := bot.TLSClientFingerprint{JA3Hash: "cached-ja3", JA4: "cached-ja4", TLSVersion: "TLS13"}
	ctx.Set(tlsFingerprintContextKey, want)

	got, ok := tlsFingerprintFromRequestContext(ctx)
	if !ok {
		t.Fatal("expected cached TLS fingerprint")
	}
	if got.JA3Hash != want.JA3Hash || got.JA4 != want.JA4 || got.TLSVersion != want.TLSVersion {
		t.Fatalf("unexpected cached fingerprint: %+v", got)
	}
}

func TestTLSFingerprintFromRequestContextFallsBackToConnectionCarrier(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	want := bot.TLSClientFingerprint{JA3Hash: "conn-ja3", JA4: "conn-ja4", TLSVersion: "TLS13"}
	ctx := app.NewContext(0)
	ctx.SetConn(&testHertzConn{Conn: bot.WrapFingerprintConn(server, want)})

	got, ok := tlsFingerprintFromRequestContext(ctx)
	if !ok {
		t.Fatal("expected connection TLS fingerprint")
	}
	if got.JA3Hash != want.JA3Hash || got.JA4 != want.JA4 || got.TLSVersion != want.TLSVersion {
		t.Fatalf("unexpected connection fingerprint: %+v", got)
	}
	cached, exists := ctx.Get(tlsFingerprintContextKey)
	if !exists {
		t.Fatal("expected connection fingerprint to be cached in request context")
	}
	if cachedFP, ok := cached.(bot.TLSClientFingerprint); !ok || cachedFP.JA3Hash != want.JA3Hash {
		t.Fatalf("unexpected cached connection fingerprint: %+v", cached)
	}
}

type singleConnListener struct {
	conn net.Conn
	used bool
}

type testNetConnUnwrapper struct {
	net.Conn
	inner net.Conn
}

func (c *testNetConnUnwrapper) NetConn() net.Conn { return c.inner }

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.used {
		return nil, net.ErrClosed
	}
	l.used = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	if l.conn == nil {
		return nil
	}
	return l.conn.Close()
}

func (l *singleConnListener) Addr() net.Addr { return testAddr("single-conn") }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func TestFixURITLSTransportOnConnectRunsAfterHandshake(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	cert, err := acme.GenerateSelfSigned("localhost")
	if err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}

	stateCh := make(chan tls.ConnectionState, 1)
	handlerCh := make(chan struct{}, 1)
	errCh := make(chan error, 1)

	transport := &fixURITLSTransport{
		ln: &singleConnListener{conn: serverConn},
		tls: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2"},
		},
		OnConnect: func(ctx context.Context, conn network.Conn) context.Context {
			stateProvider, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
			if !ok {
				t.Fatal("expected connection state provider")
			}
			stateCh <- stateProvider.ConnectionState()
			return ctx
		},
	}

	go func() {
		errCh <- transport.ListenAndServe(func(ctx context.Context, conn interface{}) error {
			handlerCh <- struct{}{}
			if closer, ok := conn.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
			return nil
		})
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2"},
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	select {
	case state := <-stateCh:
		if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" || state.ServerName != "localhost" {
			t.Fatalf("unexpected TLS state in OnConnect: version=%#x alpn=%q sni=%q", state.Version, state.NegotiatedProtocol, state.ServerName)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for OnConnect")
	}

	select {
	case <-handlerCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for handler")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("transport returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for transport shutdown")
	}
}
