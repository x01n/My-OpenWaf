package dataplane

import (
	"net"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
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
	ctx.Request = req

	rt := snapshot.SiteRuntime{Site: store.Site{PreserveOriginalHost: true}, PreserveOriginalHost: true}
	got := buildWebSocketHandshakeHeaders(ctx, "/ws?token=1", "upstream.internal:8080", rt, net.ParseIP("203.0.113.10"))

	for _, want := range []string{
		"GET /ws?token=1 HTTP/1.1\r\n",
		"Host: client.example\r\n",
		"X-Forwarded-For: 203.0.113.10\r\n",
		"X-Forwarded-Host: client.example\r\n",
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
	ctx.Request = req

	rt := snapshot.SiteRuntime{Site: store.Site{PreserveOriginalHost: false}}
	got := buildWebSocketHandshakeHeaders(ctx, "/ws", "upstream.internal:8080", rt, nil)

	if !strings.Contains(got, "Host: upstream.internal:8080\r\n") {
		t.Fatalf("expected upstream Host header, got %q", got)
	}
	if strings.Contains(got, "X-Forwarded-Host:") || strings.Contains(got, "X-Forwarded-For:") {
		t.Fatalf("unexpected forwarded headers, got %q", got)
	}
}
