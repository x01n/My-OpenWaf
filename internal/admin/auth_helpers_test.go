package admin

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
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
			setRefreshCookie(ctx, "jti.raw", time.Hour)
			raw := string(ctx.Response.Header.Peek("Set-Cookie"))
			gotSecure := strings.Contains(strings.ToLower(raw), "; secure")
			if gotSecure != tt.wantSecure {
				t.Fatalf("Set-Cookie = %q, Secure=%t want %t", raw, gotSecure, tt.wantSecure)
			}
		})
	}
}

// readCookieLikeHertz 按 hertz 的真实读回语义解析 cookie：RequestContext.Cookie
// 最终落到 RequestHeader.Cookie → parseRequestCookies，只做扫描切片、不做
// percent 解码。这里刻意用真实的协议栈读回，而不是自己 split 字符串。
func readCookieLikeHertz(t *testing.T, setCookie string) *app.RequestContext {
	t.Helper()
	ctx := newMiddlewareCtx("/api/v1/auth/refresh", map[string]string{"Cookie": setCookie})
	return ctx
}

// readBackThroughRequestLine 把 Set-Cookie 值放进一条真实构造的请求行，
// 用 net/http 的解析器读回，再走包内 splitRefreshCookie 解析。这条路径撮合
// 了「写侧的线格式」与「读侧拿到的字节」，两端的任何转义/裁剪不一致都会失败。
func readBackThroughRequestLine(t *testing.T, setName, value string) (jti, raw string, ok bool) {
	t.Helper()
	rawReq := "POST /api/v1/auth/refresh HTTP/1.1\r\nHost: admin.example.test\r\n" +
		"Cookie: " + setName + "=" + value + "\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(rawReq)))
	if err != nil {
		t.Fatalf("解析构造的请求行失败: %v", err)
	}
	defer func() { _ = req.Body.Close() }()
	c, err := req.Cookie(setName)
	if err != nil {
		t.Fatalf("请求行中读不到 %s: %v", setName, err)
	}
	return splitRefreshCookie(c.Value)
}

// TestRefreshCookieSurvivesHertzSetCookieEncoding 是这次缺陷的回归测试：
// 缺陷能溜过去，是因为没有一条测试走完「写 Set-Cookie → 按 hertz 读回语义
// 读回 → splitRefreshCookie 解析」这条链。同时把 hertz「写侧 QueryEscape、
// 读侧不解码」这一不对称行为钉成测试事实：换框架或升级 hertz 时会立刻失败。
func TestRefreshCookieSurvivesHertzSetCookieEncoding(t *testing.T) {
	// hertz 会对值做 url.QueryEscape；冒号会被写成 %3A。先把这个行为固化。
	probe := newMiddlewareCtx("/api/v1/auth/login", nil)
	setRefreshCookie(probe, "jti:raw", time.Hour)
	probeHeader := string(probe.Response.Header.Peek("Set-Cookie"))
	if !strings.Contains(probeHeader, "jti%3Araw") {
		t.Fatalf("hertz 不再对 cookie 值做 percent 编码，本测试的假设已失效: %q", probeHeader)
	}
	if strings.Contains(probeHeader, "%253A") {
		t.Fatalf("hertz 对已含 %% 的值发生二次转义，旧格式兼容分支将失效: %q", probeHeader)
	}
	if got := string(readCookieLikeHertz(t, probeHeader).Cookie(refreshCookieName)); got != "jti%3Araw" {
		t.Fatalf("hertz 读回值 = %q，期望字面量 jti%%3Araw（读侧不解码）", got)
	}
	// 旧格式正是靠这一条解析路径恢复既有会话：jti 与 raw 必须逐字节解出。
	legacyJTI, legacyRaw, ok := splitRefreshCookie("jti%3Araw")
	if !ok || legacyJTI != "jti" || legacyRaw != "raw" {
		t.Fatalf("旧 %%3A 分支解析 = (%q, %q, %v)，期望 (jti, raw, true)", legacyJTI, legacyRaw, ok)
	}

	// 生产分隔符必须逐字节往返。
	ctx := newMiddlewareCtx("/api/v1/auth/refresh", nil)
	const wantJTI = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	const wantRaw = "ab12cd34ef56ab78cd90ef12ab34cd56ef78ab90cd12ef34ab56cd78ef90ab12"
	setRefreshCookie(ctx, wantJTI+string(refreshCookieSeparator)+wantRaw, time.Hour)
	header := string(ctx.Response.Header.Peek("Set-Cookie"))

	wire := refreshCookieValue(t, header)
	if strings.ContainsAny(wire, "%:") {
		t.Fatalf("refresh cookie 值仍含需转义/不合法的字节: %q", wire)
	}
	if wire != wantJTI+"."+wantRaw {
		t.Fatalf("网络值与写入值不一致: %q", wire)
	}
	// 经真实请求行读回（独立于 hertz 写侧的解析器），再解析。
	jti, raw, ok := readBackThroughRequestLine(t, refreshCookieName, wire)
	if !ok {
		t.Fatalf("经请求行读回后解析失败: %q", wire)
	}
	if jti != wantJTI || raw != wantRaw {
		t.Fatalf("经请求行解析结果 = (%q, %q)，期望 (%q, %q)", jti, raw, wantJTI, wantRaw)
	}
	// hertz 自身的读回路径也必须给出同一结果。
	readBack := string(readCookieLikeHertz(t, header).Cookie(refreshCookieName))
	if readBack != wire {
		t.Fatalf("hertz 读回值 %q 与网络值 %q 不一致", readBack, wire)
	}
}

// TestLegacyEscapedCookieReadsBackUnescaped 固化旧格式恢复会话所依赖的框架事实：
// 写侧把冒号转义成 %3A，读侧原样返回，不做二次转义也不解码。若将来升级 hertz
// 变成写侧转义 + 读侧解码（对称），旧 cookie 会解出字面冒号并落入新格式分支，
// 恢复能力随之失效——这条测试会先失败。
func TestLegacyEscapedCookieReadsBackUnescaped(t *testing.T) {
	ctx := newMiddlewareCtx("/api/v1/auth/login", nil)
	const legacyJTI = "8b046b0fa4d3cded750f8c5747c131ba"
	const legacyRaw = "5b06fd70134f973252a3b0ac725ea0ab3217f6c3d0eb56c9247916e8a9edf040"
	setRefreshCookie(ctx, legacyJTI+":"+legacyRaw, time.Hour)
	header := string(ctx.Response.Header.Peek("Set-Cookie"))

	wire := refreshCookieValue(t, header)
	if wire != legacyJTI+"%3A"+legacyRaw {
		t.Fatalf("旧格式网络值 = %q，期望 %q", wire, legacyJTI+"%3A"+legacyRaw)
	}
	got := string(readCookieLikeHertz(t, header).Cookie(refreshCookieName))
	if got != wire {
		t.Fatalf("读侧解码了旧格式（%q -> %q），恢复既有会话的前提不再成立", wire, got)
	}
	jti, raw, ok := splitRefreshCookie(got)
	if !ok || jti != legacyJTI || raw != legacyRaw {
		t.Fatalf("旧格式解析 = (%q, %q, %v)，期望 (%q, %q, true)", jti, raw, ok, legacyJTI, legacyRaw)
	}
}
