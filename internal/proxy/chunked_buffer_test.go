package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

// newChunkedUpstream 启动一个强制使用 chunked 编码的上游服务。
//
// httptest 的 ResponseWriter 会把小响应缓冲成 Content-Length，这里通过
// 显式 Flush 让响应头先行下发，从而稳定构造 Transfer-Encoding: chunked。
func newChunkedUpstream(t *testing.T, contentType string, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		w.(http.Flusher).Flush()
	}))
}

// forwardOnce 以最小上下文调用 ForwardHTTP，返回可断言的响应上下文。
func forwardOnce(t *testing.T, base string) *app.RequestContext {
	t.Helper()
	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/resource")
	ctx.Request.Header.SetHost("proxy.example.com")
	rt := snapshot.SiteRuntime{Site: store.Site{}}
	if err := ForwardHTTP(context.Background(), ctx, rt, base, nil, "proxy.example.com"); err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	return ctx
}

// TestForwardHTTP_ChunkedSmallBodyUsesContentLength 锁定未知长度的小响应
// 会被整流成 Content-Length 一次性写出，避免 hertz 逐 chunk 触发 syscall。
func TestForwardHTTP_ChunkedSmallBodyUsesContentLength(t *testing.T) {
	upstream := newChunkedUpstream(t, "text/plain", []byte("OK"))
	defer upstream.Close()

	ctx := forwardOnce(t, upstream.URL)
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != "2" {
		t.Fatalf("Content-Length = %q, want %q", got, "2")
	}
	if got := string(ctx.Response.Body()); got != "OK" {
		t.Fatalf("body = %q, want %q", got, "OK")
	}
	if ctx.Response.ImmediateHeaderFlush {
		t.Fatal("小响应已整流为 Content-Length，不应再启用流式立即下发")
	}
}

// TestForwardHTTP_ChunkedLargeBodyKeepsAllBytes 锁定超过探测缓冲的响应会
// 回退流式转发，且前缀与剩余流拼接后字节完整。
func TestForwardHTTP_ChunkedLargeBodyKeepsAllBytes(t *testing.T) {
	body := []byte(strings.Repeat("chunked-buffer-probe-", 8192)) // 160 KiB
	upstream := newChunkedUpstream(t, "text/plain", body)
	defer upstream.Close()

	ctx := forwardOnce(t, upstream.URL)
	got, err := io.ReadAll(ctx.Response.BodyStream())
	if err != nil {
		t.Fatalf("read body stream: %v", err)
	}
	if len(got) != len(body) {
		t.Fatalf("body length = %d, want %d", len(got), len(body))
	}
	if string(got) != string(body) {
		t.Fatal("body content mismatch")
	}
}

// TestForwardHTTP_FixedLengthSmallBodyIsBuffered 锁定定长小响应会被整体缓冲为
// 内存实体：Hertz 侧 BodyStream 为 nil，头部与响应体合并成一次 Flush。
func TestForwardHTTP_FixedLengthSmallBodyIsBuffered(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "11")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello-world"))
	}))
	defer upstream.Close()

	ctx := forwardOnce(t, upstream.URL)
	if ctx.Response.BodyStream() != protocol.NoResponseBody {
		t.Fatal("定长小响应应缓冲为内存实体，不应保留 BodyStream")
	}
	if got := string(ctx.Response.Body()); got != "hello-world" {
		t.Fatalf("body = %q, want %q", got, "hello-world")
	}
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != "11" {
		t.Fatalf("Content-Length = %q, want %q", got, "11")
	}
	if ctx.Response.ImmediateHeaderFlush {
		t.Fatal("缓冲后的定长响应不应再启用流式立即下发")
	}
}

// TestForwardHTTP_FixedLengthEmptyBody 锁定 Content-Length: 0 的响应不会被
// 误判为流式，也不会写出多余字节。
func TestForwardHTTP_FixedLengthEmptyBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	ctx := forwardOnce(t, upstream.URL)
	if ctx.Response.BodyStream() != protocol.NoResponseBody {
		t.Fatal("空响应体不应保留 BodyStream")
	}
	if got := len(ctx.Response.Body()); got != 0 {
		t.Fatalf("body length = %d, want 0", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != "0" {
		t.Fatalf("Content-Length = %q, want %q", got, "0")
	}
}

// TestForwardHTTP_FixedLengthLargeBodyStaysStreamed 锁定超过缓冲上限的定长
// 响应继续流式转发，且字节完整。
func TestForwardHTTP_FixedLengthLargeBodyStaysStreamed(t *testing.T) {
	body := []byte(strings.Repeat("fixed-length-stream-", 16384)) // 320 KiB
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	ctx := forwardOnce(t, upstream.URL)
	if ctx.Response.BodyStream() == protocol.NoResponseBody {
		t.Fatal("超过上限的定长响应应保持流式转发")
	}
	got, err := io.ReadAll(ctx.Response.BodyStream())
	if err != nil {
		t.Fatalf("read body stream: %v", err)
	}
	if len(got) != len(body) || string(got) != string(body) {
		t.Fatalf("body length = %d, want %d", len(got), len(body))
	}
}

// TestForwardHTTP_EventStreamNotBuffered 锁定 SSE 语义响应不会被缓冲：
// 必须保持流式（BodyStream 非空）且立即下发头部。
func TestForwardHTTP_EventStreamNotBuffered(t *testing.T) {
	upstream := newChunkedUpstream(t, "text/event-stream", []byte("data: hello\n\n"))
	defer upstream.Close()

	ctx := forwardOnce(t, upstream.URL)
	if ctx.Response.BodyStream() == protocol.NoResponseBody {
		t.Fatal("SSE 响应应保持流式，不应被缓冲为 Content-Length")
	}
	if !ctx.Response.ImmediateHeaderFlush {
		t.Fatal("SSE 响应应立即下发头部")
	}
	got, err := io.ReadAll(ctx.Response.BodyStream())
	if err != nil {
		t.Fatalf("read body stream: %v", err)
	}
	if string(got) != "data: hello\n\n" {
		t.Fatalf("body = %q", got)
	}
}
