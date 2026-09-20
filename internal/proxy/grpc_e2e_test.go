package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/snapshot"
)

// grpcTestFrame 构造标准 gRPC 帧：1 字节压缩标志(0) + 4 字节大端长度 + protobuf 消息。
func grpcTestFrame(msg []byte) []byte {
	out := make([]byte, 5+len(msg))
	copy(out[5:], msg)
	binary.BigEndian.PutUint32(out[1:5], uint32(len(msg)))
	return out
}

// grpcTestReadFrame 从字节流头部读取一帧，返回 (消息, 剩余字节)。
func grpcTestReadFrame(t *testing.T, buf []byte) ([]byte, []byte) {
	t.Helper()
	if len(buf) < 5 {
		t.Fatalf("grpc stream truncated: %d bytes remain for frame header", len(buf))
	}
	if buf[0] != 0 {
		t.Fatalf("grpc frame compression flag = %d, want 0", buf[0])
	}
	n := binary.BigEndian.Uint32(buf[1:5])
	if uint64(n) > uint64(len(buf)-5) {
		t.Fatalf("grpc frame declares %d bytes but only %d remain", n, len(buf)-5)
	}
	return append([]byte(nil), buf[5:5+n]...), buf[5+n:]
}

// grpcTestFrames 拼装多帧为连续字节流。
func grpcTestFrames(msgs ...string) []byte {
	var out []byte
	for _, msg := range msgs {
		out = append(out, grpcTestFrame([]byte(msg))...)
	}
	return out
}

// grpcTestEchoUpstream 以 h2c 启动 gRPC echo 上游，handler 自行决定 RPC 形态。
func grpcTestEchoUpstream(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	upstream := httptest.NewUnstartedServer(handler)
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetHTTP1(true)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	t.Cleanup(upstream.Close)
	return "h2c://" + upstream.Listener.Addr().String()
}

// grpcTestForward 经 ForwardHTTP 转发请求并返回 (响应体字节, 下游 trailer 表)。
func grpcTestForward(t *testing.T, base, path string, reqBody []byte, rt snapshot.SiteRuntime) ([]byte, http.Header) {
	t.Helper()
	c := app.NewContext(0)
	c.Request.SetMethod("POST")
	c.Request.SetRequestURI(path)
	c.Request.Header.Set("Content-Type", "application/grpc")
	c.Request.Header.SetHost("proxy.example.com")
	c.Request.SetBody(reqBody)
	if err := ForwardHTTP(context.Background(), c, rt, base, nil, "proxy.example.com"); err != nil {
		t.Fatalf("ForwardHTTP returned error: %v", err)
	}
	if c.Response.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want %d", c.Response.StatusCode(), http.StatusOK)
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
	return body, trailer
}

// grpcTestRequireFrames 断言响应字节流逐帧等于期望消息序列且无多余字节。
func grpcTestRequireFrames(t *testing.T, got []byte, want ...string) {
	t.Helper()
	for _, wantMsg := range want {
		var msg []byte
		msg, got = grpcTestReadFrame(t, got)
		if string(msg) != wantMsg {
			t.Fatalf("grpc frame = %q, want %q", msg, wantMsg)
		}
	}
	if len(got) != 0 {
		t.Fatalf("grpc stream carries %d trailing bytes: %x", len(got), got)
	}
}

// TestGRPCUnaryOverH2C 验证 unary：单请求帧、单响应帧、grpc-status trailer 原样到达。
func TestGRPCUnaryOverH2C(t *testing.T) {
	const path = "/grpc.Echo/Unary"
	base := grpcTestEchoUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Errorf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/grpc" {
			t.Errorf("upstream content-type = %q, want %q", ct, "application/grpc")
		}
		stream, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read inbound grpc stream: %v", err)
			return
		}
		msg, rest := grpcTestReadFrame(t, stream)
		if string(msg) != "ping-unary-body" {
			t.Errorf("unary ingress = %q, want %q", msg, "ping-unary-body")
		}
		if len(rest) != 0 {
			t.Errorf("unary ingress carries %d trailing bytes", len(rest))
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "grpc-status, grpc-message")
		_, _ = w.Write(grpcTestFrame([]byte("unary-reply")))
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "")
	})

	gotBody, gotTrailer := grpcTestForward(t, base, path, grpcTestFrame([]byte("ping-unary-body")), snapshot.SiteRuntime{})
	grpcTestRequireFrames(t, gotBody, "unary-reply")
	if got := gotTrailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("trailer grpc-status = %q, want %q", got, "0")
	}
	if _, ok := gotTrailer["Grpc-Message"]; !ok {
		t.Fatalf("trailer grpc-message missing, trailer = %v", gotTrailer)
	}
}

// TestGRPCServerStreamOverH2C 验证 server-stream：多次写帧 + EOF 结束流，
// 每帧单独 flush；第二帧写入前强制间隔，若数据面把 EOF 边界判早，
// 上游第二次 Write/Flush 会拿到流结束错误。
func TestGRPCServerStreamOverH2C(t *testing.T) {
	const path = "/grpc.Echo/ServerStream"
	base := grpcTestEchoUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Errorf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		stream, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read inbound grpc stream: %v", err)
			return
		}
		msg, rest := grpcTestReadFrame(t, stream)
		if string(msg) != "ping-server-stream" || len(rest) != 0 {
			t.Errorf("server-stream ingress = %q (+%d bytes), want %q", msg, len(rest), "ping-server-stream")
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "grpc-status")
		flusher, _ := w.(http.Flusher)
		if _, err := w.Write(grpcTestFrame([]byte("server-stream-part-1"))); err != nil {
			t.Errorf("write stream frame 1: %v", err)
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		// 给数据面流式转发留出消费窗口：若其把未知长度响应误判为提前 EOF，
		// 这里 sleep 后继续写会撞上已被关闭的 h2 流。
		time.Sleep(150 * time.Millisecond)
		if _, err := w.Write(grpcTestFrame([]byte("server-stream-part-2"))); err != nil {
			t.Errorf("write stream frame 2 after flush gap: %v", err)
			return
		}
		if _, err := w.Write(grpcTestFrame([]byte("server-stream-part-3"))); err != nil {
			t.Errorf("write stream frame 3: %v", err)
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		w.Header().Set("Grpc-Status", "0")
	})

	gotBody, gotTrailer := grpcTestForward(t, base, path, grpcTestFrame([]byte("ping-server-stream")), snapshot.SiteRuntime{})
	grpcTestRequireFrames(t, gotBody, "server-stream-part-1", "server-stream-part-2", "server-stream-part-3")
	if got := gotTrailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("trailer grpc-status = %q, want %q", got, "0")
	}
}

// TestGRPCClientStreamOverH2C 验证 client-stream：上游读取多个入站帧后回传一帧。
func TestGRPCClientStreamOverH2C(t *testing.T) {
	const path = "/grpc.Echo/ClientStream"
	base := grpcTestEchoUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Errorf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		stream, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read inbound grpc stream: %v", err)
			return
		}
		var seen []string
		for len(stream) > 0 {
			var msg []byte
			msg, stream = grpcTestReadFrame(t, stream)
			seen = append(seen, string(msg))
		}
		if want := "client-part-a,client-part-b,client-part-c"; joinGRPCStrings(seen) != want {
			t.Errorf("client-stream ingress frames = %q, want %q", seen, want)
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "grpc-status")
		_, _ = w.Write(grpcTestFrame([]byte("client-ack")))
		w.Header().Set("Grpc-Status", "0")
	})

	gotBody, gotTrailer := grpcTestForward(t, base, path, grpcTestFrames("client-part-a", "client-part-b", "client-part-c"), snapshot.SiteRuntime{})
	grpcTestRequireFrames(t, gotBody, "client-ack")
	if got := gotTrailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("trailer grpc-status = %q, want %q", got, "0")
	}
}

// TestGRPCBidiStreamOverH2C 验证 bidi：上游边读边写，四轮读帧/回帧全部完整。
func TestGRPCBidiStreamOverH2C(t *testing.T) {
	const path = "/grpc.Echo/Bidi"
	want := []string{"bidi-ack-0", "bidi-ack-1", "bidi-ack-2", "bidi-ack-3"}
	base := grpcTestEchoUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Proto != "HTTP/2.0" {
			t.Errorf("upstream request proto = %q, want %q", r.Proto, "HTTP/2.0")
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "grpc-status")
		head := make([]byte, 5)
		for i := range want {
			if _, err := io.ReadFull(r.Body, head); err != nil {
				t.Errorf("read bidi frame head %d: %v", i, err)
				return
			}
			if head[0] != 0 {
				t.Errorf("bidi frame %d compression flag = %d, want 0", i, head[0])
			}
			msg := make([]byte, binary.BigEndian.Uint32(head[1:5]))
			if _, err := io.ReadFull(r.Body, msg); err != nil {
				t.Errorf("read bidi frame body %d: %v", i, err)
				return
			}
			if string(msg) != "bidi-ping-"+string(rune('0'+i)) {
				t.Errorf("bidi ingress %d = %q, want %q", i, msg, "bidi-ping-"+string(rune('0'+i)))
			}
			if _, err := w.Write(grpcTestFrame([]byte(want[i]))); err != nil {
				t.Errorf("write bidi reply %d: %v", i, err)
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		w.Header().Set("Grpc-Status", "0")
	})

	var stream []byte
	for i := range want {
		stream = append(stream, grpcTestFrame([]byte("bidi-ping-"+string(rune('0'+i))))...)
	}
	gotBody, gotTrailer := grpcTestForward(t, base, path, stream, snapshot.SiteRuntime{})
	grpcTestRequireFrames(t, gotBody, want...)
	if got := gotTrailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("trailer grpc-status = %q, want %q", got, "0")
	}
}

// joinGRPCStrings 用逗号拼接消息列表，仅用于测试诊断输出。
func joinGRPCStrings(items []string) string {
	out := ""
	for i, item := range items {
		if i > 0 {
			out += ","
		}
		out += item
	}
	return out
}
