package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/network"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/upstream"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/bot"
)

func TestForwardWebSocketUsesTLS10ConfigForWSSUpstream(t *testing.T) {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/ws")
	req.SetHost("client.example")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)

	rt := snapshot.SiteRuntime{Site: store.Site{
		UpstreamTLSServerName: "origin.example.test",
		UpstreamTLSSkipVerify: true,
	}}
	called := false
	originalDial := tlsDialWebSocketUpstream
	tlsDialWebSocketUpstream = func(dialer *net.Dialer, host string, gotRT snapshot.SiteRuntime) (net.Conn, error) {
		called = true
		if dialer == nil || dialer.Timeout != 10*time.Second {
			t.Fatalf("websocket dialer timeout = %#v", dialer)
		}
		if host != "127.0.0.1:9443" {
			t.Fatalf("websocket upstream host = %q, want %q", host, "127.0.0.1:9443")
		}
		if gotRT.Site.UpstreamTLSServerName != "origin.example.test" {
			t.Fatalf("upstream TLS server name = %q", gotRT.Site.UpstreamTLSServerName)
		}
		if !gotRT.Site.UpstreamTLSSkipVerify {
			t.Fatal("upstream TLS skip verify setting was not preserved")
		}
		cfg := upstream.HTTPSClientTLSConfig(gotRT.Site.UpstreamTLSServerName, gotRT.Site.UpstreamTLSSkipVerify)
		if cfg.MinVersion != tls.VersionTLS10 {
			t.Fatalf("wss upstream TLS MinVersion = %#x, want %#x", cfg.MinVersion, tls.VersionTLS10)
		}
		return nil, errors.New("stop after tls config check")
	}
	t.Cleanup(func() { tlsDialWebSocketUpstream = originalDial })

	err := ForwardWebSocket(ctx, rt, "https://127.0.0.1:9443", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "stop after tls config check") {
		t.Fatalf("ForwardWebSocket error = %v", err)
	}
	if !called {
		t.Fatal("expected wss upstream TLS dial path")
	}
}

func TestIsWebSocketUpgradeUsesConnectionToken(t *testing.T) {
	tests := []struct {
		name       string
		upgrade    string
		connection string
		want       bool
	}{
		{name: "upgrade_token", upgrade: "websocket", connection: "keep-alive, Upgrade", want: true},
		{name: "mixed_case", upgrade: "WebSocket", connection: "uPgRaDe", want: true},
		{name: "substring_rejected", upgrade: "websocket", connection: "notupgrade", want: false},
		{name: "missing_upgrade_header", upgrade: "", connection: "Upgrade", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			if tt.upgrade != "" {
				ctx.Request.Header.Set("Upgrade", tt.upgrade)
			}
			if tt.connection != "" {
				ctx.Request.Header.Set("Connection", tt.connection)
			}
			if got := IsWebSocketUpgrade(ctx); got != tt.want {
				t.Fatalf("IsWebSocketUpgrade() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildWebSocketHandshakeHeadersAppliesForwarding(t *testing.T) {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetHost("client.example")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade, X-Hop")
	req.Header.Set("Sec-WebSocket-Key", "abc")
	req.Header.Set("X-Custom", "yes")
	req.Header.Set("X-Hop", "drop")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)

	rt := snapshot.SiteRuntime{Site: store.Site{PreserveOriginalHost: true}, PreserveOriginalHost: true}
	got, err := buildWebSocketHandshakeHeaders(ctx, "/ws?token=1", "upstream.internal:8080", "wss", rt, net.ParseIP("203.0.113.10"))
	if err != nil {
		t.Fatalf("buildWebSocketHandshakeHeaders returned error: %v", err)
	}

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
	if strings.Contains(got, "X-Hop:") {
		t.Fatalf("dynamic Connection token header leaked into upstream handshake: %q", got)
	}
}

func TestBuildWebSocketHandshakeHeadersPreservesRepeatedForwardedForValues(t *testing.T) {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetHost("client.example")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Add("X-Forwarded-For", " 198.51.100.7 ")
	req.Header.Add("X-Forwarded-For", "")
	req.Header.Add("X-Forwarded-For", " 198.51.100.8, 198.51.100.9 ")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)

	got, err := buildWebSocketHandshakeHeaders(ctx, "/ws", "upstream.internal:8080", "ws", snapshot.SiteRuntime{}, net.ParseIP("203.0.113.10"))
	if err != nil {
		t.Fatalf("buildWebSocketHandshakeHeaders returned error: %v", err)
	}
	want := "X-Forwarded-For: 198.51.100.7, 198.51.100.8, 198.51.100.9, 203.0.113.10\r\n"
	if !strings.Contains(got, want) {
		t.Fatalf("handshake headers missing preserved X-Forwarded-For chain %q in %q", want, got)
	}
	if strings.Count(got, "X-Forwarded-For:") != 1 {
		t.Fatalf("X-Forwarded-For should be rebuilt exactly once, got %q", got)
	}
}

func TestBuildWebSocketHandshakeHeadersUsesUpstreamHostByDefault(t *testing.T) {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetHost("client.example")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)

	rt := snapshot.SiteRuntime{Site: store.Site{PreserveOriginalHost: false}}
	got, err := buildWebSocketHandshakeHeaders(ctx, "/ws", "upstream.internal:8080", "ws", rt, nil)
	if err != nil {
		t.Fatalf("buildWebSocketHandshakeHeaders returned error: %v", err)
	}

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

func TestBuildWebSocketHandshakeHeadersUsesConfiguredUpstreamHost(t *testing.T) {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetHost("client.example")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)

	rt := snapshot.SiteRuntime{Site: store.Site{UpstreamHost: "backend.example.com"}}
	got, err := buildWebSocketHandshakeHeaders(ctx, "/ws", "upstream.internal:8080", "ws", rt, nil)
	if err != nil {
		t.Fatalf("buildWebSocketHandshakeHeaders returned error: %v", err)
	}

	if !strings.Contains(got, "Host: backend.example.com\r\n") {
		t.Fatalf("expected configured upstream Host header, got %q", got)
	}
}

func TestBuildWebSocketHandshakeHeadersInfersHTTPSForwardedProtoFromOrigin(t *testing.T) {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetHost("client.example")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Origin", "HTTPS://client.example/app")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)

	got, err := buildWebSocketHandshakeHeaders(ctx, "/ws", "upstream.internal:8080", "ws", snapshot.SiteRuntime{}, nil)
	if err != nil {
		t.Fatalf("buildWebSocketHandshakeHeaders returned error: %v", err)
	}
	if !strings.Contains(got, "X-Forwarded-Proto: https\r\n") {
		t.Fatalf("expected HTTPS forwarded proto inferred from websocket Origin, got %q", got)
	}
	if strings.Contains(got, "X-Forwarded-Proto: http\r\n") {
		t.Fatalf("websocket HTTPS Origin must not be downgraded to http, got %q", got)
	}
}

func TestBuildWebSocketHandshakeHeadersPreservesRepeatedSubprotocolValues(t *testing.T) {
	var req protocol.Request
	req.SetMethod("GET")
	req.SetHost("client.example")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Add("Sec-WebSocket-Protocol", "chat")
	req.Header.Add("Sec-WebSocket-Protocol", "superchat")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)

	got, err := buildWebSocketHandshakeHeaders(ctx, "/ws", "upstream.internal:8080", "ws", snapshot.SiteRuntime{}, nil)
	if err != nil {
		t.Fatalf("buildWebSocketHandshakeHeaders returned error: %v", err)
	}
	if !strings.Contains(got, "Sec-Websocket-Protocol: chat\r\n") ||
		!strings.Contains(got, "Sec-Websocket-Protocol: superchat\r\n") {
		t.Fatalf("websocket subprotocol headers were not fully preserved, got %q", got)
	}
	if strings.Count(got, "Sec-Websocket-Protocol:") != 2 {
		t.Fatalf("expected two subprotocol header lines, got %q", got)
	}
}

func TestForwardWebSocketReturnsWhenClientClosesAfterHandshake(t *testing.T) {
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstreamListener.Close()

	upstreamDone := make(chan error, 1)
	go func() {
		conn, err := upstreamListener.Accept()
		if err != nil {
			upstreamDone <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			upstreamDone <- err
			return
		}
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				upstreamDone <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			upstreamDone <- err
			return
		}
		var b [1]byte
		_, err = reader.Read(b[:])
		if err == nil {
			upstreamDone <- errors.New("expected upstream connection to close after client disconnect")
			return
		}
		upstreamDone <- nil
	}()

	client, server := net.Pipe()
	for _, conn := range []net.Conn{client, server} {
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/ws")
	ctx.Request.SetHost("client.example")
	ctx.Request.Header.Set("Upgrade", "websocket")
	ctx.Request.Header.Set("Connection", "Upgrade")
	ctx.SetConn(&testHertzConn{Conn: server})

	forwardDone := make(chan error, 1)
	go func() {
		forwardDone <- ForwardWebSocket(ctx, snapshot.SiteRuntime{}, "http://"+upstreamListener.Addr().String(), nil, nil)
	}()

	clientReader := bufio.NewReader(client)
	statusLine, err := clientReader.ReadString('\n')
	if err != nil {
		t.Fatalf("read websocket handshake status: %v", err)
	}
	if statusLine != "HTTP/1.1 101 Switching Protocols\r\n" {
		t.Fatalf("status line = %q", statusLine)
	}
	for {
		line, err := clientReader.ReadString('\n')
		if err != nil {
			t.Fatalf("read websocket handshake header: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}

	select {
	case err := <-forwardDone:
		if err != nil && !isNetClosed(err) && !errors.Is(err, io.EOF) {
			t.Fatalf("ForwardWebSocket returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ForwardWebSocket did not return after client close")
	}
	select {
	case err := <-upstreamDone:
		if err != nil && !isNetClosed(err) && !errors.Is(err, io.EOF) {
			t.Fatalf("upstream connection did not observe close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe close after client close")
	}
}

func TestForwardWebSocketReturnsWhenWAFInterceptsClientFrame(t *testing.T) {
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstreamListener.Close()

	upstreamDone := make(chan error, 1)
	go func() {
		conn, err := upstreamListener.Accept()
		if err != nil {
			upstreamDone <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			upstreamDone <- err
			return
		}
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				upstreamDone <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			upstreamDone <- err
			return
		}
		var b [1]byte
		_, err = reader.Read(b[:])
		if err == nil {
			upstreamDone <- errors.New("expected upstream connection to close after WAF terminal action")
			return
		}
		upstreamDone <- nil
	}()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "client.example",
			Bind: ":80",
		},
		Bind:     ":80",
		PolicyID: 1,
		Rules: []snapshot.CompiledRule{
			{
				ID:       12,
				Phase:    store.PhaseCustom,
				Kind:     "body_contains",
				Arg:      "blocked-ws-payload",
				Action:   store.ActionIntercept,
				Priority: 1,
			},
		},
		EffectiveProtection: &protection,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "client.example"): rt,
		},
	})
	eng := engine.New(holder, nil, nil, nil)

	client, server := net.Pipe()
	for _, conn := range []net.Conn{client, server} {
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/ws")
	ctx.Request.SetHost("client.example")
	ctx.Request.Header.Set("Upgrade", "websocket")
	ctx.Request.Header.Set("Connection", "Upgrade")
	ctx.SetConn(&testHertzConn{Conn: server})

	forwardDone := make(chan error, 1)
	go func() {
		forwardDone <- ForwardWebSocket(ctx, rt, "http://"+upstreamListener.Addr().String(), nil, eng)
	}()

	clientReader := bufio.NewReader(client)
	statusLine, err := clientReader.ReadString('\n')
	if err != nil {
		t.Fatalf("read websocket handshake status: %v", err)
	}
	if statusLine != "HTTP/1.1 101 Switching Protocols\r\n" {
		t.Fatalf("status line = %q", statusLine)
	}
	for {
		line, err := clientReader.ReadString('\n')
		if err != nil {
			t.Fatalf("read websocket handshake header: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := client.Write(maskedTextFrameForTest([]byte("blocked-ws-payload"))); err != nil {
		t.Fatalf("write websocket frame: %v", err)
	}

	select {
	case err := <-forwardDone:
		if err != nil && !isNetClosed(err) && !errors.Is(err, io.EOF) {
			t.Fatalf("ForwardWebSocket returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ForwardWebSocket did not return after WAF terminal action")
	}
	select {
	case err := <-upstreamDone:
		if err != nil && !isNetClosed(err) && !errors.Is(err, io.EOF) {
			t.Fatalf("upstream connection did not observe close after WAF terminal action: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe close after WAF terminal action")
	}
}

type testHertzConn struct {
	net.Conn
}

type loopbackHertzConn struct {
	Conn       *testHertzConn
	localAddr  net.Addr
	remoteAddr net.Addr
}

type failingWriteConn struct {
	net.Conn
	err error
}

func maskedTextFrameForTest(payload []byte) []byte {
	maskKey := [4]byte{1, 2, 3, 4}
	raw := []byte{0x81, 0x80 | byte(len(payload))}
	raw = append(raw, maskKey[:]...)
	for i, b := range payload {
		raw = append(raw, b^maskKey[i%len(maskKey)])
	}
	return raw
}

func (c *failingWriteConn) Write([]byte) (int, error) {
	return 0, c.err
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
func (c *loopbackHertzConn) Read(p []byte) (int, error) {
	return c.Conn.Read(p)
}
func (c *loopbackHertzConn) Write(p []byte) (int, error) {
	return c.Conn.Write(p)
}
func (c *loopbackHertzConn) Close() error {
	return c.Conn.Close()
}
func (c *loopbackHertzConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}
func (c *loopbackHertzConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}
func (c *loopbackHertzConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
func (c *loopbackHertzConn) Peek(n int) ([]byte, error) { return c.Conn.Peek(n) }
func (c *loopbackHertzConn) Skip(n int) error           { return c.Conn.Skip(n) }
func (c *loopbackHertzConn) Release() error             { return c.Conn.Release() }
func (c *loopbackHertzConn) Len() int                   { return c.Conn.Len() }
func (c *loopbackHertzConn) ReadByte() (byte, error)    { return c.Conn.ReadByte() }
func (c *loopbackHertzConn) ReadBinary(n int) ([]byte, error) {
	return c.Conn.ReadBinary(n)
}
func (c *loopbackHertzConn) Malloc(n int) ([]byte, error) { return c.Conn.Malloc(n) }
func (c *loopbackHertzConn) WriteBinary(b []byte) (int, error) {
	return c.Conn.WriteBinary(b)
}
func (c *loopbackHertzConn) Flush() error { return c.Conn.Flush() }
func (c *loopbackHertzConn) SetReadTimeout(t time.Duration) error {
	return c.Conn.SetReadTimeout(t)
}
func (c *loopbackHertzConn) SetWriteTimeout(t time.Duration) error {
	return c.Conn.SetWriteTimeout(t)
}
func (c *loopbackHertzConn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return c.Conn.LocalAddr()
}
func (c *loopbackHertzConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.Conn.RemoteAddr()
}
func (c *loopbackHertzConn) NetConn() net.Conn {
	return c.Conn.NetConn()
}

func TestReadWSFrameLargePayloadBuffersPayloadPrefix(t *testing.T) {
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

	reader := bytes.NewReader(raw)
	frame, err := readWSFrame(reader, wsInspectFrameLimit)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	wantRawLen := 2 + 2 + len(maskKey) + wsInspectFrameLimit
	if !bytes.Equal(frame.Raw, raw[:wantRawLen]) {
		t.Fatalf("buffered raw frame prefix mismatch, got %d bytes want %d", len(frame.Raw), wantRawLen)
	}
	if reader.Len() != len(payload)-wsInspectFrameLimit {
		t.Fatalf("remaining reader payload = %d, want %d", reader.Len(), len(payload)-wsInspectFrameLimit)
	}
	if frame.PayloadLen != uint64(len(payload)) {
		t.Fatalf("payload length = %d, want %d", frame.PayloadLen, len(payload))
	}
	if frame.BufferedPayloadLen != uint64(wsInspectFrameLimit) {
		t.Fatalf("buffered payload length = %d, want %d", frame.BufferedPayloadLen, wsInspectFrameLimit)
	}
	if len(frame.Payload) != wsInspectFrameLimit {
		t.Fatalf("decoded inspection payload should be capped to %d, got %d", wsInspectFrameLimit, len(frame.Payload))
	}
	if !bytes.Equal(frame.Payload, payload[:wsInspectFrameLimit]) {
		t.Fatal("decoded inspection payload does not match payload prefix")
	}
}

func TestReadWSFrameLarge127PayloadBuffersPayloadPrefix(t *testing.T) {
	payload := bytes.Repeat([]byte("b"), 66000)
	raw := []byte{0x82, 127, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(raw[2:10], uint64(len(payload)))
	raw = append(raw, payload...)

	reader := bytes.NewReader(raw)
	frame, err := readWSFrame(reader, wsInspectFrameLimit)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	wantRawLen := 10 + wsInspectFrameLimit
	if !bytes.Equal(frame.Raw, raw[:wantRawLen]) {
		t.Fatalf("buffered raw frame prefix mismatch, got %d bytes want %d", len(frame.Raw), wantRawLen)
	}
	if reader.Len() != len(payload)-wsInspectFrameLimit {
		t.Fatalf("remaining reader payload = %d, want %d", reader.Len(), len(payload)-wsInspectFrameLimit)
	}
	if frame.PayloadLen != uint64(len(payload)) {
		t.Fatalf("payload length = %d, want %d", frame.PayloadLen, len(payload))
	}
	if frame.BufferedPayloadLen != uint64(wsInspectFrameLimit) {
		t.Fatalf("buffered payload length = %d, want %d", frame.BufferedPayloadLen, wsInspectFrameLimit)
	}
	if len(frame.Payload) != wsInspectFrameLimit {
		t.Fatalf("decoded inspection payload should be capped to %d, got %d", wsInspectFrameLimit, len(frame.Payload))
	}
	if !bytes.Equal(frame.Payload, payload[:wsInspectFrameLimit]) {
		t.Fatal("decoded inspection payload does not match payload prefix")
	}
}

func BenchmarkReadWSFrameLargePayloadPrefix(b *testing.B) {
	payload := bytes.Repeat([]byte("a"), 1<<20)
	maskKey := [4]byte{1, 2, 3, 4}
	raw := []byte{0x82, 0x80 | 127, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(raw[2:10], uint64(len(payload)))
	raw = append(raw, maskKey[:]...)
	maskedPayload := append([]byte(nil), payload...)
	for i := range maskedPayload {
		maskedPayload[i] ^= maskKey[i%4]
	}
	raw = append(raw, maskedPayload...)

	b.SetBytes(int64(wsInspectFrameLimit))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(raw)
		frame, err := readWSFrame(reader, wsInspectFrameLimit)
		if err != nil {
			b.Fatal(err)
		}
		if frame.BufferedPayloadLen != uint64(wsInspectFrameLimit) || len(frame.Payload) != wsInspectFrameLimit {
			b.Fatalf("buffered payload = %d/%d, want %d", frame.BufferedPayloadLen, len(frame.Payload), wsInspectFrameLimit)
		}
		if reader.Len() != len(payload)-wsInspectFrameLimit {
			b.Fatalf("remaining payload = %d, want %d", reader.Len(), len(payload)-wsInspectFrameLimit)
		}
	}
}

func TestInspectWebSocketClientFramesStreamsRemainingPayload(t *testing.T) {
	payload := bytes.Repeat([]byte("c"), wsInspectFrameLimit+8192)
	maskKey := [4]byte{5, 6, 7, 8}
	raw := []byte{0x82, 0x80 | 126, 0, 0}
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(payload)))
	raw = append(raw, maskKey[:]...)
	maskedPayload := append([]byte(nil), payload...)
	for i := range maskedPayload {
		maskedPayload[i] ^= maskKey[i%4]
	}
	raw = append(raw, maskedPayload...)

	clientConn, proxyClientConn := net.Pipe()
	proxyUpstreamConn, upstreamConn := net.Pipe()
	for _, conn := range []net.Conn{clientConn, proxyClientConn, proxyUpstreamConn, upstreamConn} {
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}

	done := make(chan error, 2)
	ctx := app.NewContext(0)
	go inspectWebSocketClientFrames(proxyClientConn, proxyUpstreamConn, ctx, snapshot.SiteRuntime{}, nil, done)

	writeErr := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(raw)
		_ = clientConn.Close()
		writeErr <- err
	}()

	got := make([]byte, len(raw))
	if _, err := io.ReadFull(upstreamConn, got); err != nil {
		t.Fatalf("read forwarded frame: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("forwarded frame does not match original raw frame")
	}
	select {
	case err := <-writeErr:
		if err != nil {
			t.Fatalf("write raw frame: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client writer")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("inspectWebSocketClientFrames returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for frame inspector")
	}
}

func TestInspectWebSocketClientFramesSendsSingleError(t *testing.T) {
	payload := []byte("x")
	maskKey := [4]byte{9, 10, 11, 12}
	raw := []byte{0x82, 0x80 | byte(len(payload))}
	raw = append(raw, maskKey[:]...)
	maskedPayload := append([]byte(nil), payload...)
	for i := range maskedPayload {
		maskedPayload[i] ^= maskKey[i%4]
	}
	raw = append(raw, maskedPayload...)

	clientConn, proxyClientConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClientConn.Close()
	for _, conn := range []net.Conn{clientConn, proxyClientConn} {
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}

	writeErr := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(raw)
		_ = clientConn.Close()
		writeErr <- err
	}()

	wantErr := errors.New("upstream write failed")
	done := make(chan error, 2)
	inspectWebSocketClientFrames(proxyClientConn, &failingWriteConn{err: wantErr}, app.NewContext(0), snapshot.SiteRuntime{}, nil, done)

	got := <-done
	if !errors.Is(got, wantErr) {
		t.Fatalf("inspectWebSocketClientFrames error = %v, want %v", got, wantErr)
	}
	select {
	case extra := <-done:
		t.Fatalf("inspectWebSocketClientFrames sent extra result: %v", extra)
	default:
	}
	select {
	case err := <-writeErr:
		if err != nil {
			t.Fatalf("write raw frame: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client writer")
	}
}

func TestReadHTTPResponseHeadReadsNormalHeaders(t *testing.T) {
	head := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	status, headers, err := readHTTPResponseHead(bufio.NewReader(strings.NewReader(head)))
	if err != nil {
		t.Fatalf("readHTTPResponseHead returned error: %v", err)
	}
	if status != "HTTP/1.1 101 Switching Protocols\r\n" {
		t.Fatalf("status line = %q", status)
	}
	if headers != "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n" {
		t.Fatalf("headers = %q", headers)
	}
}

func TestReadHTTPResponseHeadRejectsNonSwitchingStatus(t *testing.T) {
	head := "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
	_, _, err := readHTTPResponseHead(bufio.NewReader(strings.NewReader(head)))
	if err == nil || !strings.Contains(err.Error(), "websocket upstream handshake failed with status 400") {
		t.Fatalf("readHTTPResponseHead error = %v", err)
	}
}

func TestReadHTTPResponseHeadRejectsInvalidStatusLine(t *testing.T) {
	head := "HTTP/1.1 Bad\r\nContent-Length: 0\r\n\r\n"
	_, _, err := readHTTPResponseHead(bufio.NewReader(strings.NewReader(head)))
	if err == nil || !strings.Contains(err.Error(), "websocket upstream handshake failed with status 0") {
		t.Fatalf("readHTTPResponseHead error = %v", err)
	}
}

func TestSanitizeWebSocketUpgradeResponseHeadersStripsConnectionTokenHeaders(t *testing.T) {
	headers := "Upgrade: websocket\r\nConnection: Upgrade, X-Hop\r\nKeep-Alive: timeout=5\r\nX-Hop: drop\r\nX-Keep: kept\r\n\r\n"
	got, err := sanitizeWebSocketUpgradeResponseHeaders(headers)
	if err != nil {
		t.Fatalf("sanitizeWebSocketUpgradeResponseHeaders returned error: %v", err)
	}

	for _, want := range []string{
		"Upgrade: websocket\r\n",
		"X-Keep: kept\r\n",
		"Connection: Upgrade\r\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("sanitized websocket response headers missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "X-Hop:") {
		t.Fatalf("dynamic Connection token response header leaked: %q", got)
	}
	if strings.Contains(got, "Keep-Alive:") {
		t.Fatalf("fixed hop-by-hop response header leaked: %q", got)
	}
	if strings.Contains(got, "Connection: Upgrade, X-Hop") {
		t.Fatalf("unsanitized Connection response header leaked: %q", got)
	}
	if strings.Count(strings.ToLower(got), "connection: upgrade\r\n") != 1 {
		t.Fatalf("Connection upgrade header should be rebuilt exactly once, got %q", got)
	}
}

func TestSanitizeWebSocketUpgradeResponseHeadersRejectsMissingWebSocketUpgradeHeader(t *testing.T) {
	headers := "Connection: Upgrade\r\nX-Keep: kept\r\n\r\n"
	got, err := sanitizeWebSocketUpgradeResponseHeaders(headers)
	if err == nil || !strings.Contains(err.Error(), "websocket upstream handshake missing Upgrade: websocket") {
		t.Fatalf("sanitizeWebSocketUpgradeResponseHeaders error = %v, got %q", err, got)
	}
	if got != "" {
		t.Fatalf("missing websocket Upgrade header must not emit response headers, got %q", got)
	}
}

func TestSanitizeWebSocketUpgradeResponseHeadersRejectsWrongUpgradeHeader(t *testing.T) {
	headers := "Upgrade: h2c\r\nConnection: Upgrade\r\n\r\n"
	got, err := sanitizeWebSocketUpgradeResponseHeaders(headers)
	if err == nil || !strings.Contains(err.Error(), "websocket upstream handshake missing Upgrade: websocket") {
		t.Fatalf("sanitizeWebSocketUpgradeResponseHeaders error = %v, got %q", err, got)
	}
	if got != "" {
		t.Fatalf("wrong websocket Upgrade header must not emit response headers, got %q", got)
	}
}

func TestSanitizeWebSocketUpgradeResponseHeadersRejectsMissingConnectionUpgradeHeader(t *testing.T) {
	headers := "Upgrade: websocket\r\nConnection: keep-alive\r\nX-Keep: kept\r\n\r\n"
	got, err := sanitizeWebSocketUpgradeResponseHeaders(headers)
	if err == nil || !strings.Contains(err.Error(), "websocket upstream handshake missing Connection: Upgrade") {
		t.Fatalf("sanitizeWebSocketUpgradeResponseHeaders error = %v, got %q", err, got)
	}
	if got != "" {
		t.Fatalf("missing websocket Connection upgrade header must not emit response headers, got %q", got)
	}
}

func TestReadHTTPResponseHeadRejectsOversizedStatusLine(t *testing.T) {
	raw := strings.Repeat("H", websocketUpstreamResponseHeaderLimit) + "\n"
	_, _, err := readHTTPResponseHead(bufio.NewReader(strings.NewReader(raw)))
	if err == nil || !strings.Contains(err.Error(), "websocket upstream response headers too large") {
		t.Fatalf("readHTTPResponseHead error = %v", err)
	}
}

func TestReadHTTPResponseHeadRejectsOversizedHeaders(t *testing.T) {
	status := "HTTP/1.1 101 Switching Protocols\r\n"
	raw := status + strings.Repeat("X", websocketUpstreamResponseHeaderLimit-len(status)) + "\n"
	_, _, err := readHTTPResponseHead(bufio.NewReader(strings.NewReader(raw)))
	if err == nil || !strings.Contains(err.Error(), "websocket upstream response headers too large") {
		t.Fatalf("readHTTPResponseHead error = %v", err)
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
	ctx.SetConn(&loopbackHertzConn{
		Conn:       &testHertzConn{Conn: wrapped},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	entry := buildAccessLogEntry(ctx, accessLogInfo{SiteID: 1})
	if entry.HTTPProtocol != "h3" {
		t.Fatalf("expected h3 protocol, got %q", entry.HTTPProtocol)
	}
	if entry.TLSJA3Hash != "" || entry.TLSJA4 != "" || entry.TLSVersion != "" {
		t.Fatalf("HTTP/3 proxy TLS fingerprint should not be logged as client fingerprint: %+v", entry)
	}
}

func TestBuildAccessLogEntryUsesCachedTLSFingerprintForHTTP3(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.Set(internalHTTP3ContextKey, true)
	ctx.Set(tlsFingerprintContextKey, bot.TLSClientFingerprint{
		JA3:        "771,4865-4866,0-16-43,29,0",
		JA3Hash:    "0123456789abcdef0123456789abcdef",
		JA4:        "q13d0511h3_fea09b2e4d67_1234567890ab",
		TLSVersion: "TLS13",
		SNI:        "client.example",
		ALPN:       []string{"h3"},
	})

	entry := buildAccessLogEntry(ctx, accessLogInfo{SiteID: 1})
	if entry.HTTPProtocol != "h3" {
		t.Fatalf("expected h3 protocol, got %q", entry.HTTPProtocol)
	}
	if entry.TLSVersion != "TLS13" || entry.TLSSNI != "client.example" || entry.TLSALPN != "h3" {
		t.Fatalf("expected cached HTTP/3 TLS metadata to be logged, got %+v", entry)
	}
	if entry.TLSJA3 != "771,4865-4866,0-16-43,29,0" || entry.TLSJA3Hash != "0123456789abcdef0123456789abcdef" || entry.TLSJA4 != "q13d0511h3_fea09b2e4d67_1234567890ab" {
		t.Fatalf("expected cached HTTP/3 JA3/JA4 metadata to be logged, got %+v", entry)
	}
}

func TestBuildAccessLogEntryPrefersCachedHTTP3TLSFingerprintOverProxyTLS(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.Set(internalHTTP3ContextKey, true)
	ctx.Set(tlsFingerprintContextKey, bot.TLSClientFingerprint{
		JA3:          "771,4865-4866,0-16-43,29,0",
		JA3Hash:      "0123456789abcdef0123456789abcdef",
		JA4:          "q13d0511h3_fea09b2e4d67_1234567890ab",
		TLSVersion:   "TLS13",
		SNI:          "client.example",
		ALPN:         []string{"h3"},
		CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
	})

	entry := buildAccessLogEntry(ctx, accessLogInfo{
		SiteID: 1,
		TLSFingerprint: bot.TLSClientFingerprint{
			JA3:          "proxy-ja3",
			JA3Hash:      "proxy-ja3-hash",
			JA4:          "t13i2511h2_b78ed14e2fd0_ab7e3b40a677",
			TLSVersion:   "TLS13",
			SNI:          "client.example",
			ALPN:         []string{"h2"},
			CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
		},
	})
	if entry.HTTPProtocol != "h3" {
		t.Fatalf("expected h3 protocol, got %q", entry.HTTPProtocol)
	}
	if entry.TLSJA3 != "771,4865-4866,0-16-43,29,0" || entry.TLSJA3Hash != "0123456789abcdef0123456789abcdef" || entry.TLSJA4 != "q13d0511h3_fea09b2e4d67_1234567890ab" {
		t.Fatalf("expected cached HTTP/3 JA3/JA4 metadata to override proxy TLS, got %+v", entry)
	}
	if entry.TLSALPN != "h3" {
		t.Fatalf("expected cached HTTP/3 ALPN to override proxy TLS, got %+v", entry)
	}
	if entry.TLSCipherSuites != "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384" {
		t.Fatalf("expected cached HTTP/3 cipher suites to override proxy TLS, got %+v", entry)
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

func TestRequestProtocolPrefersNegotiatedALPNOverSpoofedForwardedProto(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{
		TLSVersion: "TLS13",
		JA3Hash:    "real",
		ALPN:       []string{"h2"},
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.SetConn(&testHertzConn{Conn: wrapped})

	if got := requestProtocol(ctx); got != "h2" {
		t.Fatalf("expected negotiated ALPN to win over spoofed forwarded proto, got %q", got)
	}
}

func TestRequestProtocolFallsBackToRequestHeaderProtocol(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.SetProtocol("HTTP/2.0")

	if got := requestProtocol(ctx); got != "h2" {
		t.Fatalf("expected request header protocol, got %q", got)
	}
}

func TestRequestProtocolPrefersRequestHeaderProtocolOverTLSFingerprint(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{
		TLSVersion: "TLS13",
		JA3Hash:    "real",
		ALPN:       []string{"h2"},
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.SetProtocol("HTTP/1.1")
	ctx.SetConn(&testHertzConn{Conn: wrapped})

	if got := requestProtocol(ctx); got != "http/1.1" {
		t.Fatalf("expected request header protocol to win over TLS fingerprint ALPN, got %q", got)
	}
}

func TestRequestProtocolReturnsHTTPSWhenTLSHasNoALPN(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{TLSVersion: "TLS13", JA3Hash: "real"})
	ctx := app.NewContext(0)
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
		HTTPProtocol: "h2",
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

func TestInspectWebSocketPayloadAppliesSiteAntiReplayTTLToNonceHeaderPhase(t *testing.T) {
	holder := &snapshot.Holder{}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: store.DefaultProtectionConfig(),
		Sites:      make(map[string]snapshot.SiteRuntime),
	}
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:            1,
			Host:          "ws-ttl.example.com",
			Bind:          ":80",
			AntiReplayTTL: 1,
		},
		Bind:              ":80",
		AntiReplayEnabled: true,
	}
	sn.Sites[snapshot.SiteMapKey(":80", "ws-ttl.example.com")] = rt
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	mgr := antireplay.NewAntiReplayManager("websocket-anti-replay-ttl", nil, 5*time.Minute)
	eng.SetAntiReplayManager(mgr)

	nonce := mgr.GenerateNonce("")
	time.Sleep(1100 * time.Millisecond)

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/ws")
	ctx.Request.Header.SetHost("ws-ttl.example.com")
	ctx.Request.Header.Set("X-Nonce", nonce)

	got := inspectWebSocketPayload(ctx, rt, eng, []byte("hello"))
	if got.Type != action.Intercept {
		t.Fatalf("inspectWebSocketPayload action = %#v, want intercept", got)
	}
	if got.Phase != "anti_replay" {
		t.Fatalf("inspectWebSocketPayload phase = %q, want %q", got.Phase, "anti_replay")
	}
}

func TestInspectWebSocketPayloadUsesCachedTLSHandshakeMetadata(t *testing.T) {
	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:         1,
			Host:       "ws-tls.example.com",
			Bind:       ":443",
			TLSEnabled: true,
		},
		Bind:     ":443",
		PolicyID: 1,
		Rules: []snapshot.CompiledRule{
			{
				ID:       11,
				Phase:    store.PhaseCustom,
				Kind:     "tls_sni",
				Arg:      "client.example",
				Action:   store.ActionIntercept,
				Priority: 1,
			},
		},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshot.SiteRuntime{
			snapshot.SiteMapKey(":443", "ws-tls.example.com"): rt,
		},
	}
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/ws")
	ctx.Request.Header.SetHost("ws-tls.example.com")
	ctx.Set(tlsFingerprintContextKey, bot.TLSClientFingerprint{
		TLSVersion: "TLS13",
		SNI:        "client.example",
		ALPN:       []string{"h2"},
	})

	got := inspectWebSocketPayload(ctx, rt, eng, []byte("hello"))
	if got.Type != action.Intercept {
		t.Fatalf("inspectWebSocketPayload action = %#v, want intercept", got)
	}
	if got.RuleID != 11 {
		t.Fatalf("inspectWebSocketPayload rule id = %d, want 11", got.RuleID)
	}
	if got.Phase != "custom" {
		t.Fatalf("inspectWebSocketPayload phase = %q, want %q", got.Phase, "custom")
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

func TestContextWithTLSHandshakeInfoClearsOfferedALPNWhenNegotiatedEmpty(t *testing.T) {
	ctx := ContextWithTLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		JA3Hash: "ja3",
		JA4:     "ja4",
		SNI:     "client.example",
		ALPN:    []string{"h2", "http/1.1"},
	})

	ctx = ContextWithTLSHandshakeInfo(ctx, "TLS11", "client.example", "")

	fp, ok := tlsFingerprintFromContext(ctx)
	if !ok {
		t.Fatal("expected TLS fingerprint in context")
	}
	if fp.JA3Hash != "ja3" || fp.JA4 != "ja4" || fp.SNI != "client.example" || fp.TLSVersion != "TLS11" {
		t.Fatalf("unexpected merged TLS fingerprint: %+v", fp)
	}
	if len(fp.ALPN) != 0 {
		t.Fatalf("ALPN = %+v, want empty negotiated ALPN", fp.ALPN)
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
