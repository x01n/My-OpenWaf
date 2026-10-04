package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
)

/**
 * grpcWebDataFrame 构造一个 gRPC-Web DATA 帧。
 *
 * 帧体为 1 字节帧标志（0x00 表示数据、0x80 表示 trailer）、4 字节大端 payload
 * 长度、payload 本身。消息 payload 内部的长度前缀由 grpcMessagePayload 补上。
 *
 * @param flag 帧标志。
 * @param payload 帧负载。
 * @return 完整帧字节。
 */
func grpcWebDataFrame(flag byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

/**
 * grpcMessagePayload 为 unary 消息加上 gRPC 长度前缀。
 *
 * 前缀依次为 1 字节压缩标志、4 字节大端消息长度，之后是消息本身。
 *
 * @param payload 消息字节。
 * @return 带长度前缀的消息帧。
 */
func grpcMessagePayload(payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

/**
 * grpcWebTrailersFrame 构造 gRPC-Web 的 Envoy 服务端形态的体内 trailers 帧。
 *
 * 帧体为标志 0x80、payload "grpc-status:<code>"，其后可选 "grpc-message:<message>"
 * 以及任意 "key:value" 条目。该形态下 grpc-status 从不走 HTTP Trailer 段。
 *
 * @param status grpc-status 码。
 * @param message 可选的 grpc-message。
 * @param extra 额外的 trailer 键值对。
 * @return 完整 trailers 帧字节。
 */
func grpcWebTrailersFrame(status int, message string, extra map[string]string) []byte {
	payload := fmt.Sprintf("grpc-status:%d", status)
	if message != "" {
		payload += "\r\ngrpc-message:" + message
	}
	for key, value := range extra {
		payload += "\r\n" + key + ":" + value
	}
	return grpcWebDataFrame(0x80, []byte(payload))
}

/**
 * h2GRPCWebUnaryUpstream 以 HTTP/2 起一路测试上游，返回一个消息帧加一个体内 trailers 帧。
 *
 * 响应 content type 为 application/grpc-web+proto。
 *
 * @param t 测试上下文。
 * @return 已启动的测试上游。
 */
func h2GRPCWebUnaryUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/grpc.web.Echo/Echo" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		_, _ = w.Write(grpcWebDataFrame(0, grpcMessagePayload([]byte("payload-web-unary"))))
		_, _ = w.Write(grpcWebTrailersFrame(0, "", nil))
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	return upstream
}

/**
 * compressionRT 返回压缩阈值为 1 字节的运行时开关。
 *
 * 阈值取 1，使任何可压缩响应都够格被重新编码。
 *
 * @return 站点运行时。
 */
func compressionRT() snapshot.SiteRuntime {
	return snapshot.SiteRuntime{
		ResponseCompressionConfigured:  true,
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: true,
		ResponseCompressionMinBytes:    1,
	}
}

/**
 * TestForwardHTTPSkipsCompressionForGRPCWebAndGRPCJSONFamilies 覆盖流式 ForwardHTTP 路径。
 *
 * 对每种 grpc 家族 content type 断言不施加 Content-Encoding，而同一份运行时
 * 开关下可压缩的 text/plain 对照响应必须被 gzip 编码。
 *
 * @param t 测试上下文。
 */
func TestForwardHTTPSkipsCompressionForGRPCWebAndGRPCJSONFamilies(t *testing.T) {
	grpcTypes := []string{
		"application/grpc",
		"application/grpc+proto",
		"application/grpc+json",
		"application/grpc-web",
		"application/grpc-web+proto",
		"application/grpc-web+json",
	}
	payload := strings.Repeat("grpc-compression-border-", 64)
	for _, contentType := range grpcTypes {
		t.Run(contentType, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentType)
				_, _ = io.WriteString(w, payload)
			}))
			defer upstream.Close()

			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI("/grpc-compression-border")
			ctx.Request.Header.SetHost("proxy.example.com")
			ctx.Request.Header.Set("Accept-Encoding", "gzip, br")
			if err := ForwardHTTP(context.Background(), ctx, compressionRT(), upstream.URL, nil, "proxy.example.com"); err != nil {
				t.Fatalf("ForwardHTTP returned error: %v", err)
			}
			if got := ctx.Response.Header.Peek("Content-Encoding"); len(got) != 0 {
				t.Fatalf("Content-Encoding = %q, want empty for %s", got, contentType)
			}
			if got := ctx.Response.Body(); !bytes.Equal(got, []byte(payload)) {
				t.Fatalf("body mismatch for %s: got %d bytes, want %d", contentType, len(got), len(payload))
			}
		})
	}

	// 对照：同一份运行时必须仍然压缩普通文本响应。
	t.Run("control-text-plain", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, payload)
		}))
		defer upstream.Close()

		ctx := app.NewContext(0)
		ctx.Request.SetMethod("GET")
		ctx.Request.SetRequestURI("/control-text-plain")
		ctx.Request.Header.SetHost("proxy.example.com")
		ctx.Request.Header.Set("Accept-Encoding", "gzip")
		if err := ForwardHTTP(context.Background(), ctx, compressionRT(), upstream.URL, nil, "proxy.example.com"); err != nil {
			t.Fatalf("ForwardHTTP returned error: %v", err)
		}
		if got := ctx.Response.Header.Peek("Content-Encoding"); !bytes.Equal(got, []byte("gzip")) {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		setRaw := ctx.Response.Body()
		reader, err := gzip.NewReader(bytes.NewReader(setRaw))
		if err != nil {
			t.Fatalf("create gzip reader: %v", err)
		}
		decoded, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil || !bytes.Equal(decoded, []byte(payload)) {
			t.Fatalf("control decoded body mismatch: err=%v len=%d", err, len(decoded))
		}
	})
}

/**
 * TestForwardBufferedResponseSkipsCompressionForGRPCWebFamilies 覆盖缓存与 app-route 捕获所用的缓冲转发路径。
 *
 * @param t 测试上下文。
 */
func TestForwardBufferedResponseSkipsCompressionForGRPCWebFamilies(t *testing.T) {
	payload := strings.Repeat("buffered-grpc-border-", 64)
	for _, contentType := range []string{"application/grpc", "application/grpc+json", "application/grpc-web", "application/grpc-web+proto", "application/grpc-web+json"} {
		t.Run(contentType, func(t *testing.T) {
			resp := &HTTPResponse{
				StatusCode:  http.StatusOK,
				ContentType: contentType,
				Body:        []byte(payload),
				Header:      http.Header{"Content-Type": []string{contentType}},
			}
			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI("/buffered-grpc-border")
			ctx.Request.Header.SetHost("proxy.example.com")
			ctx.Request.Header.Set("Accept-Encoding", "gzip")
			ForwardBufferedResponseForSiteWithClientIP(ctx, resp, compressionRT(), nil)
			if got := ctx.Response.Header.Peek("Content-Encoding"); len(got) != 0 {
				t.Fatalf("Content-Encoding = %q, want empty for %s", got, contentType)
			}
			if got := ctx.Response.Body(); !bytes.Equal(got, []byte(payload)) {
				t.Fatalf("body mismatch for %s: got %d bytes, want %d", contentType, len(got), len(payload))
			}
		})
	}
}

/**
 * TestForwardHTTPSkipsCompressionForGRPCWebTrailerBody 转发 Envoy 形态的 gRPC-Web 响应体。
 *
 * 该形态为消息帧加带 grpc-status 的体内 trailers 帧；断言帧字节逐字节一致
 * 且不带 Content-Encoding。
 *
 * @param t 测试上下文。
 */
func TestForwardHTTPSkipsCompressionForGRPCWebTrailerBody(t *testing.T) {
	payload := []byte(strings.Repeat("zx-body-payload", 512))
	messageFrame := grpcWebDataFrame(0, grpcMessagePayload(payload))
	trailersFrame := grpcWebTrailersFrame(0, "", nil)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		_, _ = w.Write(messageFrame)
		_, _ = w.Write(trailersFrame)
	}))
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/grpc.web.Echo/Echo")
	ctx.Request.Header.SetHost("proxy.example.com")
	ctx.Request.Header.Set("Accept-Encoding", "gzip")
	if err := ForwardHTTP(context.Background(), ctx, compressionRT(), upstream.URL, nil, "proxy.example.com"); err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.Header.Peek("Content-Encoding"); len(got) != 0 {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	want := append(append([]byte{}, messageFrame...), trailersFrame...)
	if got := ctx.Response.Body(); !bytes.Equal(got, want) {
		t.Fatalf("grpc-web body mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

/**
 * TestShouldCacheHTTPResponseRejectsGRPCFamilies 验证共享边缘缓存永不存储 RPC 响应流。
 *
 * 无论上游缓存指令如何，application/grpc 家族（grpc、grpc+proto、grpc-web、
 * grpc-web+proto）一律排除：把一个调用方的流回放给另一个会破坏 RPC 语义
 * （逐调用的 trailer、状态与 payload 连续性）。
 *
 * @param t 测试上下文。
 */
func TestShouldCacheHTTPResponseRejectsGRPCFamilies(t *testing.T) {
	for _, contentType := range []string{"application/grpc", "application/grpc+proto", "application/grpc-web", "application/grpc-web+proto", "application/grpc+json"} {
		t.Run(contentType, func(t *testing.T) {
			resp := &HTTPResponse{
				StatusCode:  http.StatusOK,
				ContentType: contentType,
				Header: http.Header{
					"Content-Type":  []string{contentType},
					"Cache-Control": []string{"public, max-age=60"},
				},
				Body: grpcWebDataFrame(0, grpcMessagePayload([]byte("cache-border-payload"))),
			}
			if ShouldCacheHTTPResponse(http.MethodGet, resp) {
				t.Fatalf("ShouldCacheHTTPResponse = true, gRPC family %s must stay uncacheable", contentType)
			}
		})
	}
}

/**
 * TestForwardHTTPWritesH2CGRPCTrailerFrame 验证 h2c gRPC classic 语义在流式路径上成立。
 *
 * 消息体帧与 grpc-status 响应 trailer 都必须完整穿过代理。
 *
 * @param t 测试上下文。
 */
func TestForwardHTTPWritesH2CGRPCTrailerFrame(t *testing.T) {
	messageFrame := grpcWebDataFrame(0, grpcMessagePayload([]byte("h2c-grpc-echo")))
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Fatalf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		w.Header().Set("Content-Type", "application/grpc+proto")
		w.Header().Add("Trailer", "grpc-status")
		_, _ = w.Write(messageFrame)
		w.Header().Set("grpc-status", "0")
	}))
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetHTTP1(true)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	defer upstream.Close()

	ctx := app.NewContext(0)
	ctx.Request.SetMethod("GET")
	ctx.Request.SetRequestURI("/grpc.Echo/Echo")
	ctx.Request.Header.SetHost("proxy.example.com")
	base := strings.Replace(upstream.URL, "http://", "h2c://", 1)
	if err := ForwardHTTP(context.Background(), ctx, snapshot.SiteRuntime{}, base, nil, "proxy.example.com"); err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := ctx.Response.Body(); !bytes.Equal(got, messageFrame) {
		t.Fatalf("body mismatch: got %d bytes, want %d", len(got), len(messageFrame))
	}
	if got := ctx.Response.Header.Trailer().Get("grpc-status"); got != "0" {
		t.Fatalf("grpc-status trailer = %q, want %q", got, "0")
	}
}
