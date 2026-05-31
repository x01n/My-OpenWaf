package dataplane

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

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
	pc.SetTLSHandshakeInfo("TLS13", "h2")

	fp, ok := bot.TLSFingerprintFromConn(wrapped)
	if !ok {
		t.Fatal("expected fingerprint from wrapped connection")
	}
	if fp.JA3Hash != "ja3" || fp.TLSVersion != "TLS13" || len(fp.ALPN) != 1 || fp.ALPN[0] != "h2" {
		t.Fatalf("unexpected fingerprint after handshake update: %+v", fp)
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
