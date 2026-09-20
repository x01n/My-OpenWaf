package admin

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	hertzmock "github.com/cloudwego/hertz/pkg/common/test/mock"
)

type adminProtocolTestConn struct {
	*hertzmock.Conn
	remoteAddr net.Addr
	tlsState   tls.ConnectionState
}

func (c *adminProtocolTestConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *adminProtocolTestConn) ConnectionState() tls.ConnectionState {
	return c.tlsState
}

func setAdminProtocolTestConn(c *app.RequestContext, remoteIP string, tlsVersion uint16) {
	c.SetConn(&adminProtocolTestConn{
		Conn:       hertzmock.NewConn(""),
		remoteAddr: &net.TCPAddr{IP: net.ParseIP(remoteIP), Port: 443},
		tlsState:   tls.ConnectionState{Version: tlsVersion},
	})
}

// TestAdminRequestProtocolOnlyTrustsLoopbackForwardedProto 验证外部请求不能伪造 HTTPS 协议。
func TestAdminRequestProtocolOnlyTrustsLoopbackForwardedProto(t *testing.T) {
	untrusted := newMiddlewareCtx("http://example.test/api/v1/auth/login", map[string]string{"X-Forwarded-Proto": "https"})
	setAdminProtocolTestConn(untrusted, "198.51.100.10", 0)
	if got := adminRequestProtocol(untrusted); got != "http" {
		t.Fatalf("untrusted forwarded protocol = %q, want http", got)
	}

	loopback := newMiddlewareCtx("http://example.test/api/v1/auth/login", map[string]string{"X-Forwarded-Proto": "HTTPS"})
	setAdminProtocolTestConn(loopback, "127.0.0.1", 0)
	if got := adminRequestProtocol(loopback); got != "https" {
		t.Fatalf("loopback forwarded protocol = %q, want https", got)
	}

	directTLS := newMiddlewareCtx("http://example.test/api/v1/auth/login", map[string]string{"X-Forwarded-Proto": "http"})
	setAdminProtocolTestConn(directTLS, "198.51.100.10", tls.VersionTLS13)
	if got := adminRequestProtocol(directTLS); got != "https" {
		t.Fatalf("direct TLS protocol = %q, want https", got)
	}
}

// TestRefreshCookieSecureUsesTrustedProtocol 验证 Secure 仅由可信 HTTPS 连接或回环反代启用。
func TestRefreshCookieSecureUsesTrustedProtocol(t *testing.T) {
	tests := []struct {
		name       string
		remoteIP   string
		forwarded  string
		tlsVersion uint16
		wantSecure bool
	}{
		{name: "untrusted spoof", remoteIP: "198.51.100.10", forwarded: "https", wantSecure: false},
		{name: "loopback proxy", remoteIP: "127.0.0.1", forwarded: "https", wantSecure: true},
		{name: "direct tls", remoteIP: "198.51.100.10", forwarded: "http", tlsVersion: tls.VersionTLS13, wantSecure: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMiddlewareCtx("http://example.test/api/v1/auth/login", map[string]string{"X-Forwarded-Proto": tt.forwarded})
			setAdminProtocolTestConn(ctx, tt.remoteIP, tt.tlsVersion)
			setRefreshCookie(ctx, "jti:raw", time.Hour)
			raw := string(ctx.Response.Header.Peek("Set-Cookie"))
			gotSecure := strings.Contains(strings.ToLower(raw), "; secure")
			if gotSecure != tt.wantSecure {
				t.Fatalf("Set-Cookie = %q, Secure=%t want %t", raw, gotSecure, tt.wantSecure)
			}
		})
	}
}
