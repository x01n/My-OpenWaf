package security

import (
	"net"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	hertzmock "github.com/cloudwego/hertz/pkg/common/test/mock"

	"My-OpenWaf/internal/store"
)

type testRemoteAddrConn struct {
	*hertzmock.Conn
	remoteAddr net.Addr
}

func (c *testRemoteAddrConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func newResolveClientIPContext(remote string) *app.RequestContext {
	ctx := app.NewContext(0)
	ctx.SetConn(&testRemoteAddrConn{
		Conn:       hertzmock.NewConn(""),
		remoteAddr: &net.TCPAddr{IP: net.ParseIP(remote), Port: 443},
	})
	return ctx
}

func TestResolveClientIPStripIgnoresForwardedFor(t *testing.T) {
	ctx := newResolveClientIPContext("192.0.2.10")
	ctx.Request.Header.Set("X-Forwarded-For", "203.0.113.10")

	got := ResolveClientIP(ctx, store.XFFModeStrip, "192.0.2.0/24")
	if !got.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("ResolveClientIP strip = %s, want 192.0.2.10", got)
	}
}

func TestResolveClientIPTrustOuterRequiresTrustedRemote(t *testing.T) {
	ctx := newResolveClientIPContext("198.51.100.10")
	ctx.Request.Header.Set("X-Forwarded-For", "203.0.113.10")

	got := ResolveClientIP(ctx, store.XFFModeTrustOuter, "192.0.2.0/24")
	if !got.Equal(net.ParseIP("198.51.100.10")) {
		t.Fatalf("ResolveClientIP untrusted remote = %s, want 198.51.100.10", got)
	}
}

func TestResolveClientIPTrustOuterUsesFirstValidForwardedFor(t *testing.T) {
	ctx := newResolveClientIPContext("192.0.2.10")
	ctx.Request.Header.Set("X-Forwarded-For", "bad, 203.0.113.10, 198.51.100.20")

	got := ResolveClientIP(ctx, store.XFFModeTrustOuter, "192.0.2.0/24")
	if !got.Equal(net.ParseIP("203.0.113.10")) {
		t.Fatalf("ResolveClientIP trusted remote = %s, want 203.0.113.10", got)
	}
}

func TestResolveClientIPTrustOuterPreservesRepeatedForwardedForValues(t *testing.T) {
	ctx := newResolveClientIPContext("192.0.2.10")
	ctx.Request.Header.Add("X-Forwarded-For", "bad")
	ctx.Request.Header.Add("X-Forwarded-For", "")
	ctx.Request.Header.Add("X-Forwarded-For", " 203.0.113.10, 198.51.100.20 ")

	got := ResolveClientIP(ctx, store.XFFModeTrustOuter, "192.0.2.0/24")
	if !got.Equal(net.ParseIP("203.0.113.10")) {
		t.Fatalf("ResolveClientIP repeated XFF = %s, want 203.0.113.10", got)
	}
}

func BenchmarkResolveClientIPTrustOuterRepeatedForwardedFor(b *testing.B) {
	ctx := newResolveClientIPContext("192.0.2.10")
	ctx.Request.Header.Add("X-Forwarded-For", "bad")
	ctx.Request.Header.Add("X-Forwarded-For", "")
	ctx.Request.Header.Add("X-Forwarded-For", " 203.0.113.10, 198.51.100.20 ")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if ResolveClientIP(ctx, store.XFFModeTrustOuter, "192.0.2.0/24") == nil {
			b.Fatal("empty client ip")
		}
	}
}

func BenchmarkResolveClientIPTrustOuterRepeatedForwardedForPreviousStringForTest(b *testing.B) {
	ctx := newResolveClientIPContext("192.0.2.10")
	ctx.Request.Header.Add("X-Forwarded-For", "bad")
	ctx.Request.Header.Add("X-Forwarded-For", "")
	ctx.Request.Header.Add("X-Forwarded-For", " 203.0.113.10, 198.51.100.20 ")

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if resolveClientIPTrustOuterPreviousStringForTest(ctx, "192.0.2.0/24") == nil {
			b.Fatal("empty client ip")
		}
	}
}

func resolveClientIPTrustOuterPreviousStringForTest(ctx *app.RequestContext, trustedCIDR string) net.IP {
	remoteHost, _, err := net.SplitHostPort(ctx.RemoteAddr().String())
	if err != nil {
		remoteHost = ctx.RemoteAddr().String()
	}
	direct := net.ParseIP(remoteHost)
	if direct == nil {
		return nil
	}
	if !remoteInTrustedCIDR(direct, trustedCIDR) {
		return direct
	}
	xff := ForwardedForHeaderValueBytes(ctx.Request.Header.PeekAll("X-Forwarded-For"))
	if xff == "" {
		return direct
	}
	parts := strings.Split(xff, ",")
	for _, p := range parts {
		ip := net.ParseIP(strings.TrimSpace(p))
		if ip != nil {
			return ip
		}
	}
	return direct
}
