package dataplane

import (
	"net"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
)

// newHTTP3LoopbackTestContext 构造一个「h3 回环请求」的请求上下文。
//
// 内部头只有在同时满足「Proto=h3」「X-Forwarded-Proto=h3」「来源是本机回环」
// 三个条件时才会被 applyInternalHTTP3RequestMetadata 采信，因此测试必须真的
// 挂一个回环 Conn，否则断言会退化成「头被清除」而不是「0-RTT 被识别」。
func newHTTP3LoopbackTestContext(t *testing.T) *app.RequestContext {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.SetConn(&loopbackHertzConn{
		Conn:       &testHertzConn{Conn: server},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})
	return ctx
}

/**
 * TestApplyInternalHTTP3RequestMetadataMarksZeroRTT 锁定 h3 回环的 0-RTT 标记。
 *
 * 0-RTT 只能由本机 h3 转发按真实连接状态写入；元数据消费后必须把标记
 * 放进 context，供访问日志与策略判定读取。
 */
func TestApplyInternalHTTP3RequestMetadataMarksZeroRTT(t *testing.T) {
	ctx := newHTTP3LoopbackTestContext(t)
	ctx.Request.Header.Set(InternalHTTP3ZeroRTTHeader, "1")

	applyInternalHTTP3RequestMetadata(ctx)

	if !isInternalHTTP3Request(ctx) {
		t.Fatal("expected request to be marked as internal HTTP/3")
	}
	if !isInternalHTTP3ZeroRTT(ctx) {
		t.Fatal("expected request to be marked as 0-RTT")
	}
	if got := string(ctx.GetHeader(InternalHTTP3ZeroRTTHeader)); got != "" {
		t.Fatalf("internal 0-RTT header should be stripped after consumption, got %q", got)
	}
}

/**
 * TestApplyInternalHTTP3RequestMetadataIgnoresZeroRTTHeaderWithoutH3
 * 锁定 0-RTT 头不能由外部请求伪造。
 *
 * 普通 TCP 客户端可以随意发同名请求头，但缺少 h3 内部标记时整个元数据块
 * 都不得被采信，标记必须被清除且不会写入 context。
 */
func TestApplyInternalHTTP3RequestMetadataIgnoresZeroRTTHeaderWithoutH3(t *testing.T) {
	client, server := net.Pipe()
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()
	ctx := app.NewContext(0)
	ctx.Request.Header.Set(InternalHTTP3ZeroRTTHeader, "1")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.SetConn(&loopbackHertzConn{
		Conn:       &testHertzConn{Conn: server},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	applyInternalHTTP3RequestMetadata(ctx)

	if isInternalHTTP3Request(ctx) {
		t.Fatal("request without the h3 internal proto header must not be treated as internal HTTP/3")
	}
	if isInternalHTTP3ZeroRTT(ctx) {
		t.Fatal("forged 0-RTT header must not mark the request as 0-RTT")
	}
	if got := string(ctx.GetHeader(InternalHTTP3ZeroRTTHeader)); got != "" {
		t.Fatalf("forged 0-RTT header should be stripped, got %q", got)
	}
}

/**
 * TestApplyInternalHTTP3RequestMetadataIgnoresZeroRTTHeaderFromNonLoopback
 * 锁定 0-RTT 标记只在回环来源上生效。
 *
 * h3 监听的数据面通过本机 TCP 回环转发，因此可信来源必然是回环地址；
 * 任何非回环来源即使持有 h3 内部头也必须被清除。这是防止内部头泄漏到
 * 公网后被重新注入的最后一道关口。
 */
func TestApplyInternalHTTP3RequestMetadataIgnoresZeroRTTHeaderFromNonLoopback(t *testing.T) {
	client, server := net.Pipe()
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()
	ctx := app.NewContext(0)
	ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.Request.Header.Set(InternalHTTP3ZeroRTTHeader, "1")
	ctx.SetConn(&loopbackHertzConn{
		Conn:       &testHertzConn{Conn: server},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 43111},
	})

	applyInternalHTTP3RequestMetadata(ctx)

	if isInternalHTTP3Request(ctx) {
		t.Fatal("non-loopback request must not be treated as internal HTTP/3")
	}
	if isInternalHTTP3ZeroRTT(ctx) {
		t.Fatal("non-loopback request must not be marked as 0-RTT")
	}
}
