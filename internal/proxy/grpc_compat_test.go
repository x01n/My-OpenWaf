package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
)

// grpcCompatFrameWithFlag 构造 gRPC 帧(压缩标志 + 4 字节大端长度 + 消息)，
// 与 grpcTestFrame 的区别是允许非零压缩标志位。
func grpcCompatFrameWithFlag(flag byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// grpcCompatGzipBytes 对给定字节做确定性 gzip 压缩，仅用于测试上游构造。
func grpcCompatGzipBytes(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatalf("create gzip writer: %v", err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// grpcCompatForward 经 ForwardHTTP 转发自定义方法/内容类型/请求头的请求，
// 返回 (响应体字节, 下游 trailer, HTTP 状态码, 响应头)。
func grpcCompatForward(t *testing.T, base, path, method, contentType string, headers map[string]string, reqBody []byte, rt snapshot.SiteRuntime) ([]byte, http.Header, int, http.Header) {
	t.Helper()
	c := app.NewContext(0)
	c.Request.SetMethod(method)
	c.Request.SetRequestURI(path)
	if contentType != "" {
		c.Request.Header.SetContentTypeBytes([]byte(contentType))
	}
	c.Request.Header.SetHost("proxy.example.com")
	for key, value := range headers {
		c.Request.Header.Set(key, value)
	}
	if reqBody != nil {
		c.Request.SetBody(reqBody)
	}
	if err := ForwardHTTP(context.Background(), c, rt, base, nil, "proxy.example.com"); err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	var body []byte
	if c.Response.IsBodyStream() {
		b, err := io.ReadAll(c.Response.BodyStream())
		if err != nil {
			t.Fatalf("read hertz body stream: %v", err)
		}
		_ = c.Response.CloseBodyStream()
		body = b
	} else {
		body = append([]byte(nil), c.Response.Body()...)
	}
	trailer := http.Header{}
	c.Response.Header.Trailer().VisitAll(func(k, v []byte) {
		trailer.Add(string(k), string(v))
	})
	headerOut := http.Header{}
	c.Response.Header.VisitAll(func(k, v []byte) {
		headerOut.Add(string(k), string(v))
	})
	return body, trailer, c.Response.StatusCode(), headerOut
}

// grpcCompatH2CUpstream 以 h2c 启动一路上游并返回其 base；handler 校验
// 上游请求必须走 HTTP/2。
func grpcCompatH2CUpstream(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Errorf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		handler(w, r)
	}))
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetHTTP1(true)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	t.Cleanup(upstream.Close)
	return "h2c://" + upstream.Listener.Addr().String()
}

// TestGRPCCompatWebTextBase64FramesSurvive 覆盖 grpc-web-text 家族的三种
// 变体：上游把每个帧整体(base64 标志+长度+payload)base64 编码后拼接，
// 代理必须逐字节透传（不解 base64、不重编码、不压缩）。
func TestGRPCCompatWebTextBase64FramesSurvive(t *testing.T) {
	payload := []byte(strings.Repeat("web-text-payload-", 128))
	for _, contentType := range []string{
		"application/grpc-web-text",
		"application/grpc-web-text+proto",
		"application/grpc-web-text+json",
	} {
		t.Run(contentType, func(t *testing.T) {
			msgFrame := grpcWebDataFrame(0, grpcMessagePayload(payload))
			trailerFrame := grpcWebTrailersFrame(0, "", nil)
			want := base64.StdEncoding.EncodeToString(msgFrame) + base64.StdEncoding.EncodeToString(trailerFrame)
			base := grpcCompatH2CUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentType)
				_, _ = w.Write([]byte(want))
			})

			body, _, status, headerOut := grpcCompatForward(t, base, "/grpc.web.Echo/Echo", http.MethodPost,
				"application/grpc-web-text", map[string]string{"Accept-Encoding": "gzip"}, nil, compressionRT())
			if status != http.StatusOK {
				t.Fatalf("status = %d, want %d", status, http.StatusOK)
			}
			if got := headerOut.Get("Content-Encoding"); got != "" {
				t.Fatalf("Content-Encoding = %q, want empty for %s", got, contentType)
			}
			if string(body) != want {
				t.Fatalf("web-text body mismatch: got %d bytes, want %d (base64 frames must pass through unchanged)", len(body), len(want))
			}
		})
	}
}

// TestGRPCCompatDeadlineExceededAndTimeoutSurvive 覆盖 grpc-timeout 请求头
// 透传与 grpc-status=4 错误路径：上游必须收到未修改的 grpc-timeout，
// deadline-exceeded 响应（HTTP 200 + 错误 trailer）必须原样到达，
// 代理不得合成 502 或重试。
func TestGRPCCompatDeadlineExceededAndTimeoutSurvive(t *testing.T) {
	const path = "/grpc.Echo/Expire"
	msgFrame := grpcTestFrame([]byte("expired-call-body"))
	base := grpcCompatH2CUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Grpc-Timeout"); got != "100m" {
			t.Errorf("upstream grpc-timeout = %q, want %q", got, "100m")
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "grpc-status, grpc-message")
		_, _ = w.Write(msgFrame)
		w.Header().Set("grpc-status", "4")
		w.Header().Set("grpc-message", "deadline exceeded")
	})

	body, trailer, status, headerOut := grpcCompatForward(t, base, path, http.MethodPost, "application/grpc",
		map[string]string{"Grpc-Timeout": "100m"}, grpcTestFrame([]byte("expire-me")), snapshot.SiteRuntime{})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d (grpc-status carries the RPC error, HTTP must stay 200)", status, http.StatusOK)
	}
	if !bytes.Equal(body, msgFrame) {
		t.Fatalf("body mismatch on deadline-exceeded path: got %d bytes, want %d", len(body), len(msgFrame))
	}
	if got := trailer.Get("Grpc-Status"); got != "4" {
		t.Fatalf("trailer grpc-status = %q, want %q", got, "4")
	}
	if got := trailer.Get("Grpc-Message"); got != "deadline exceeded" {
		t.Fatalf("trailer grpc-message = %q, want %q", got, "deadline exceeded")
	}
	if got := headerOut.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty on error path", got)
	}
}

// TestGRPCCompatGRPCEncodingCompressedFramesPassthrough 覆盖 grpc-encoding
// 头与压缩帧体：上游带 grpc-encoding: gzip 且帧压缩标志为 1，代理必须
// 原样透传 gzip 字节与 grpc-encoding 头，不得解压、不得重复压缩、不得
// 注入 Content-Encoding。
func TestGRPCCompatGRPCEncodingCompressedFramesPassthrough(t *testing.T) {
	part1 := []byte(strings.Repeat("compressed-part-1-", 512))
	part2 := []byte(strings.Repeat("compressed-part-2-", 512))
	frame1 := grpcCompatFrameWithFlag(1, grpcCompatGzipBytes(t, part1))
	frame2 := grpcCompatFrameWithFlag(1, grpcCompatGzipBytes(t, part2))
	want := append(append([]byte{}, frame1...), frame2...)
	base := grpcCompatH2CUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("grpc-encoding", "gzip")
		w.Header().Set("Trailer", "grpc-status")
		_, _ = w.Write(frame1)
		_, _ = w.Write(frame2)
		w.Header().Set("grpc-status", "0")
	})

	body, trailer, status, headerOut := grpcCompatForward(t, base, "/grpc.Echo/Compressed", http.MethodPost, "application/grpc",
		map[string]string{"Accept-Encoding": "gzip"}, grpcTestFrame([]byte("compressed-call")), compressionRT())
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if got := headerOut.Get("Grpc-Encoding"); got != "gzip" {
		t.Fatalf("grpc-encoding header = %q, want %q", got, "gzip")
	}
	if got := headerOut.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty (proxy must not recompress grpc frames)", got)
	}
	if !bytes.Equal(body, want) {
		t.Fatalf("compressed frames mismatch: got %d bytes, want %d", len(body), len(want))
	}
	if got := trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("trailer grpc-status = %q, want %q", got, "0")
	}
}

// TestGRPCCompatTrailersOnlyResponse 覆盖 Trailers-Only 形态：上游不写任何
// 消息帧，grpc-status 仅经 trailer 到达。代理必须保真 trailer、保持 body
// 为空、正确结束流（END_STREAM）。
func TestGRPCCompatTrailersOnlyResponse(t *testing.T) {
	const path = "/grpc.Echo/TrailersOnly"
	base := grpcCompatH2CUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "grpc-status, grpc-message")
		// Trailers-Only：不写 body，status/message 只走 trailer 声明。
		w.Header().Set("grpc-status", "0")
		w.Header().Set("grpc-message", "")
	})

	body, trailer, status, _ := grpcCompatForward(t, base, path, http.MethodPost, "application/grpc",
		nil, grpcTestFrame([]byte("trailers-only-call")), snapshot.SiteRuntime{})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if len(body) != 0 {
		t.Fatalf("trailers-only body carries %d bytes, want 0", len(body))
	}
	if got := trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("trailers-only grpc-status = %q, want %q (trailer must survive an empty body)", got, "0")
	}
	if _, ok := trailer["Grpc-Message"]; !ok {
		t.Fatalf("trailers-only grpc-message missing, trailer = %v", trailer)
	}
}

// TestGRPCCompatLargeMessageFraming 覆盖大消息帧在传输层与帧级的分片：
// 单帧 4MiB 遍历、单帧 4MiB 上游拆两半写、64KiB 帧体拆两个 gRPC 消息帧、
// 以及 4MiB 到 640KiB 的双向大消息全双工往返（客户端写完整个两帧请求后
// 再读上游的连续应答帧，任何全双工损伤都会使应答长度不匹配）。
func TestGRPCCompatLargeMessageFraming(t *testing.T) {
	const chunkPattern = "large-chunk-pattern-"
	chunk := []byte(strings.Repeat(chunkPattern, 4096)) // 81920 字节/块
	makePayload := func(blocks int) []byte {
		payload := make([]byte, 0, len(chunk)*blocks)
		for i := 0; i < blocks; i++ {
			payload = append(payload, chunk...)
		}
		return payload
	}

	t.Run("single-4MiB-message", func(t *testing.T) {
		payload := makePayload(52) // 52 * 81920 = 4260 减出精确 4MiB
		payload = payload[:4<<20]
		want := grpcTestFrame(payload)
		base := grpcCompatH2CUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "grpc-status")
			_, _ = w.Write(want)
			w.Header().Set("grpc-status", "0")
		})
		body, trailer, status, _ := grpcCompatForward(t, base, "/grpc.Echo/Large1", http.MethodPost, "application/grpc",
			nil, grpcTestFrame([]byte("large-1-call")), snapshot.SiteRuntime{})
		if status != http.StatusOK || !bytes.Equal(body, want) {
			t.Fatalf("4MiB frame mismatch: status=%d got=%d want=%d", status, len(body), len(want))
		}
		if got := trailer.Get("Grpc-Status"); got != "0" {
			t.Fatalf("trailer grpc-status = %q, want %q", got, "0")
		}
	})

	t.Run("64KiB-frame-as-two-grpc-messages", func(t *testing.T) {
		half1 := makePayload(4)[:32<<10]
		half2 := makePayload(4)[:32<<10]
		want := append(append([]byte{}, grpcTestFrame(half1)...), grpcTestFrame(half2)...)
		base := grpcCompatH2CUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "grpc-status")
			_, _ = w.Write(want)
			w.Header().Set("grpc-status", "0")
		})
		body, _, status, _ := grpcCompatForward(t, base, "/grpc.Echo/Large2", http.MethodPost, "application/grpc",
			nil, nil, snapshot.SiteRuntime{})
		if status != http.StatusOK || !bytes.Equal(body, want) {
			t.Fatalf("two-32KiB-frame mismatch: status=%d got=%d want=%d", status, len(body), len(want))
		}
	})

	t.Run("upstream-splits-one-frame-in-two-writes", func(t *testing.T) {
		payload := makePayload(1)[:64<<10]
		frame := grpcTestFrame(payload)
		half := len(frame) / 2
		base := grpcCompatH2CUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "grpc-status")
			_, _ = w.Write(frame[:half])
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			_, _ = w.Write(frame[half:])
			w.Header().Set("grpc-status", "0")
		})
		body, _, status, _ := grpcCompatForward(t, base, "/grpc.Echo/Large3", http.MethodPost, "application/grpc",
			nil, nil, snapshot.SiteRuntime{})
		if status != http.StatusOK || !bytes.Equal(body, frame) {
			t.Fatalf("split-write frame mismatch: status=%d got=%d want=%d", status, len(body), len(frame))
		}
	})

	t.Run("4MiB-bidi-round", func(t *testing.T) {
		reqPayload := makePayload(52)[:4<<20]
		replyBlob := []byte(strings.Repeat("reply-bidi-large-", 40960)) // 655360 字节/轮片
		reqFrameA := grpcTestFrame(reqPayload[:2<<20])
		reqFrameB := grpcTestFrame(reqPayload[2<<20:])
		var replyFrames []byte
		for i := 0; i < 2; i++ {
			replyFrames = append(replyFrames, grpcTestFrame(replyBlob)...)
		}
		base := grpcCompatH2CUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "grpc-status")
			stream, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read 4MiB bidi ingress: %v", err)
				return
			}
			wantIn := append(append([]byte{}, reqFrameA...), reqFrameB...)
			if !bytes.Equal(stream, wantIn) {
				t.Errorf("4MiB bidi ingress mismatch: got %d bytes, want %d", len(stream), len(wantIn))
				return
			}
			// 应答帧拆六个分块写出并逐块 flush。
			flusher, _ := w.(http.Flusher)
			const block = 256 << 10
			for off := 0; off < len(replyFrames); off += block {
				end := off + block
				if end > len(replyFrames) {
					end = len(replyFrames)
				}
				if _, err := w.Write(replyFrames[off:end]); err != nil {
					t.Errorf("write 4MiB bidi chunk: %v", err)
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			w.Header().Set("grpc-status", "0")
		})
		stream := append(append([]byte{}, reqFrameA...), reqFrameB...)
		body, trailer, status, _ := grpcCompatForward(t, base, "/grpc.Echo/BidiLarge", http.MethodPost, "application/grpc",
			nil, stream, snapshot.SiteRuntime{})
		if status != http.StatusOK || !bytes.Equal(body, replyFrames) {
			t.Fatalf("4MiB bidi reply mismatch: status=%d got=%d want=%d", status, len(body), len(replyFrames))
		}
		if got := trailer.Get("Grpc-Status"); got != "0" {
			t.Fatalf("trailer grpc-status = %q, want %q", got, "0")
		}
	})
}

// TestGRPCCompatContentTypeParameterVariantsStayInFamily 覆盖大小写/带参数
// 的 content-type 变体：判定必须仍落在 grpc 家族（压缩排除 + 缓存排除），
// 而 text/plain 对照在同一压缩 runtime 下必须被压缩。
func TestGRPCCompatContentTypeParameterVariantsStayInFamily(t *testing.T) {
	variants := []string{
		"application/grpc; charset=utf-8",
		"APPLICATION/GRPC+PROTO",
		"Application/Grpc-Web ",
		"application/grpc-web-text; proto=x",
		"Application/Grpc-Web-Text+JSON",
	}
	payload := strings.Repeat("variant-border-payload-", 64)

	t.Run("compression-exclusion", func(t *testing.T) {
		for _, contentType := range variants {
			t.Run(contentType, func(t *testing.T) {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", contentType)
					_, _ = io.WriteString(w, payload)
				}))
				defer upstream.Close()

				c := app.NewContext(0)
				c.Request.SetMethod("GET")
				c.Request.SetRequestURI("/grpc-variant-border")
				c.Request.Header.SetHost("proxy.example.com")
				c.Request.Header.Set("Accept-Encoding", "gzip")
				if err := ForwardHTTP(context.Background(), c, compressionRT(), upstream.URL, nil, "proxy.example.com"); err != nil {
					t.Fatalf("ForwardHTTP returned error: %v", err)
				}
				if got := c.Response.Header.Peek("Content-Encoding"); len(got) != 0 {
					t.Fatalf("Content-Encoding = %q, want empty for %s", got, contentType)
				}
				if got := c.Response.Body(); !bytes.Equal(got, []byte(payload)) {
					t.Fatalf("body mismatch for %s: got %d bytes, want %d", contentType, len(got), len(payload))
				}
			})
		}
	})

	t.Run("cache-exclusion", func(t *testing.T) {
		for _, contentType := range variants {
			t.Run(contentType, func(t *testing.T) {
				resp := &HTTPResponse{
					StatusCode:  http.StatusOK,
					ContentType: contentType,
					Header: http.Header{
						"Content-Type":  []string{contentType},
						"Cache-Control": []string{"public, max-age=60"},
					},
					Body: grpcWebDataFrame(0, grpcMessagePayload([]byte("variant-cache-payload"))),
				}
				if ShouldCacheHTTPResponse(http.MethodGet, resp) {
					t.Fatalf("ShouldCacheHTTPResponse = true, %s must stay in the grpc family and uncacheable", contentType)
				}
			})
		}
	})

	t.Run("text-plain-control", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, payload)
		}))
		defer upstream.Close()

		c := app.NewContext(0)
		c.Request.SetMethod("GET")
		c.Request.SetRequestURI("/grpc-variant-control")
		c.Request.Header.SetHost("proxy.example.com")
		c.Request.Header.Set("Accept-Encoding", "gzip")
		if err := ForwardHTTP(context.Background(), c, compressionRT(), upstream.URL, nil, "proxy.example.com"); err != nil {
			t.Fatalf("ForwardHTTP returned error: %v", err)
		}
		if got := c.Response.Header.Peek("Content-Encoding"); !bytes.Equal(got, []byte("gzip")) {
			t.Fatalf("control Content-Encoding = %q, want gzip", got)
		}
	})
}
