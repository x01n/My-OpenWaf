package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/hertz-contrib/http2/hpack"
)

// TestIsH2ExtendedWebSocketConnect 验证扩展 CONNECT 识别只看
// CONNECT 方法与 ":protocol" 伪头，不依赖 Upgrade/Connection 残留。
func TestIsH2ExtendedWebSocketConnect(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		protocol string
		upgrade  string
		want     bool
	}{
		{name: "connect_with_protocol", method: "CONNECT", protocol: "websocket", upgrade: "websocket", want: true},
		{name: "connect_without_protocol", method: "CONNECT", protocol: "", upgrade: "websocket", want: false},
		{name: "get_with_protocol", method: "GET", protocol: "websocket", upgrade: "", want: false},
		{name: "connect_other_protocol", method: "CONNECT", protocol: "coap", upgrade: "coap", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := app.NewContext(0)
			c.Request.SetMethod(tt.method)
			if tt.protocol != "" {
				c.Request.Header.Set(":protocol", tt.protocol)
			}
			if tt.upgrade != "" {
				c.Request.Header.Set("Upgrade", tt.upgrade)
			}
			if got := IsH2ExtendedWebSocketConnect(c); got != tt.want {
				t.Fatalf("IsH2ExtendedWebSocketConnect() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsH2WebSocketDirectUpstream 验证 h2c/grpc 上游直通判定。
func TestIsH2WebSocketDirectUpstream(t *testing.T) {
	tests := []struct {
		base string
		want bool
	}{
		{base: "h2c://127.0.0.1:18080", want: true},
		{base: "grpc://127.0.0.1:18080", want: true},
		{base: "http://127.0.0.1:18080", want: false},
		{base: "https://127.0.0.1:18443", want: false},
		{base: "grpcs://127.0.0.1:18443", want: false},
		{base: "tls://127.0.0.1:18443", want: false},
		{base: "ws://127.0.0.1:18080", want: false},
	}
	for _, tt := range tests {
		if got := IsH2WebSocketDirectUpstream(tt.base); got != tt.want {
			t.Errorf("IsH2WebSocketDirectUpstream(%q) = %v, want %v", tt.base, got, tt.want)
		}
	}
}

// TestH2DirectUpstreamTarget 验证 h2c 上游拨号地址与 CONNECT 目标构造。
func TestH2DirectUpstreamTarget(t *testing.T) {
	host, target, err := h2DirectUpstreamTarget("h2c://192.0.2.7:18080/a/b", "/socket", "keep=1")
	if err != nil {
		t.Fatalf("h2DirectUpstreamTarget: %v", err)
	}
	if host != "192.0.2.7:18080" {
		t.Fatalf("host = %q, want %q", host, "192.0.2.7:18080")
	}
	if target != "http://192.0.2.7:18080/socket?keep=1" {
		t.Fatalf("target = %q, want path/query preserved", target)
	}

	host, target, err = h2DirectUpstreamTarget("h2c://192.0.2.7", "/socket", "")
	if err != nil {
		t.Fatalf("h2DirectUpstreamTarget default port: %v", err)
	}
	if host != "192.0.2.7:80" {
		t.Fatalf("host = %q, want default :80", host)
	}
	if target != "http://192.0.2.7:80/socket" {
		t.Fatalf("target = %q, want default-port target", target)
	}
}

// TestSanitizeWebSocketUpgradeResponseHeadersKeepsSecHeaders 验证畸形握手
// 净化：hop-by-hop 被剔除、Sec-* 保留。
func TestSanitizeWebSocketUpgradeResponseHeadersKeepsSecHeaders(t *testing.T) {
	raw := "Sec-WebSocket-Accept: abc\r\n" +
		"Sec-WebSocket-Protocol: chat\r\n" +
		// X-Evil-Hop 列入 Connection 名单：它是连接属主声明的 hop 头，
		// 与既有 h1 回归（websocket_test.go TestSanitizeWebSocketUpgradeResponseHeadersStripsConnectionTokenHeaders）
		// 锚定的语义一致——进入剔除名单；Sec-* 与 Upgrade 端到端头保留。
		"Connection: keep-alive, Upgrade, X-Evil-Hop\r\n" +
		"Upgrade: websocket\r\n" +
		"X-Evil-Hop: 1\r\n" +
		"\r\n"
	_ = raw
	got, err := sanitizeWebSocketUpgradeResponseHeaders(raw)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if !strings.Contains(got, "Sec-WebSocket-Accept: abc") {
		t.Fatalf("missing accept header: %q", got)
	}
	if !strings.Contains(got, "Sec-WebSocket-Protocol: chat") {
		t.Fatalf("missing protocol header: %q", got)
	}
	if strings.Contains(strings.ToLower(got), "x-evil-hop") {
		t.Fatalf("hop-by-hop header survived sanitize: %q", got)
	}
}

// TestDialH2CExtendedConnectHandshakeAndBidirectionalData 在 dataplane 层
// 直接驱动 h2c 直通帧流：mock 上游负责 SETTINGS 与响应头，验证握手与
// 双向 DATA 字节一致。
func TestDialH2CExtendedConnectHandshakeAndBidirectionalData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock h2c upstream: %v", err)
	}
	defer ln.Close()
	upstreamAddr := ln.Addr().String()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := dialH2CExtendedConnect(ctx, upstreamAddr, "http://"+upstreamAddr+"/ws", "websocket", nil)
	if err != nil {
		t.Fatalf("dialH2CExtendedConnect: %v", err)
	}
	defer stream.Close()

	upConn := <-accepted
	defer upConn.Close()
	br := bufio.NewReader(upConn)

	// 1) 读客户端连接前缀。
	preface := make([]byte, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	if _, err := io.ReadFull(br, preface); err != nil {
		t.Fatalf("read preface: %v", err)
	}

	// 2) 客户端空 SETTINGS 与扩展 CONNECT HEADERS。
	ftype, _, streamID, payload, err := h2WSReadTestFrame(br)
	if err != nil {
		t.Fatalf("read client SETTINGS: %v", err)
	}
	if ftype != h2FrameSettings || streamID != 0 {
		t.Fatalf("client frame1 = type %d stream %d, want SETTINGS/0", ftype, streamID)
	}
	ftype, _, streamID, payload, err = h2WSReadTestFrame(br)
	if err != nil {
		t.Fatalf("read client HEADERS: %v", err)
	}
	if ftype != h2FrameHeaders || streamID != 1 {
		t.Fatalf("client frame2 = type %d stream %d, want HEADERS/1", ftype, streamID)
	}
	if !h2WSHeadersContainTest(payload, ":protocol", "websocket") {
		t.Fatalf("client HEADERS missing :protocol websocket")
	}
	if !h2WSHeadersContainTest(payload, ":method", "CONNECT") {
		t.Fatalf("client HEADERS missing :method CONNECT")
	}

	// 3) 上游回 SETTINGS（INITIAL_WINDOW_SIZE 4095）+ 响应 HEADERS(200)。
	var out bytes.Buffer
	settingsPayload := []byte{0x00, 0x04, 0x00, 0x00, 0x0f, 0xff}
	writeH2RawFrame(&out, h2FrameSettings, 0, 0, settingsPayload)
	out.Write(h2WSEncodeTestHeaders([][2]string{{":status", "200"}}))
	if _, err := upConn.Write(out.Bytes()); err != nil {
		t.Fatalf("write upstream SETTINGS+HEADERS: %v", err)
	}

	select {
	case <-stream.HandshakeDone():
	case <-time.After(3 * time.Second):
		t.Fatal("handshake not completed")
	}
	if stream.ResponseStatus() != 200 {
		t.Fatalf("response status = %d, want 200", stream.ResponseStatus())
	}

	// 4) 客户端 -> 上游 DATA（先读掉客户端对 SETTINGS 的 ACK）。
	wantUp := []byte("client-to-upstream")
	if _, err := stream.Write(wantUp); err != nil {
		t.Fatalf("stream.Write: %v", err)
	}
	var (
		gotFtype   uint8
		gotFlags   uint8
		gotStream  uint32
		gotPayload []byte
	)
	for i := 0; i < 4; i++ {
		gotFtype, gotFlags, gotStream, gotPayload, err = h2WSReadTestFrame(br)
		if err != nil {
			t.Fatalf("read client DATA: %v", err)
		}
		if gotFtype == h2FrameSettings {
			continue
		}
		break
	}
	if gotFtype != h2FrameData || gotStream != 1 || !bytes.Equal(gotPayload, wantUp) {
		t.Fatalf("client DATA = type %d flags %d stream %d payload %q, want %q", gotFtype, gotFlags, gotStream, gotPayload, wantUp)
	}

	// 5) 上游 -> 客户端 DATA。
	wantDown := []byte("upstream-to-client")
	writeH2RawFrame(upConn, h2FrameData, 0, 1, wantDown)
	buf := make([]byte, len(wantDown)+2)
	n, rerr := stream.Read(buf)
	if rerr != nil {
		t.Fatalf("stream.Read: %v", rerr)
	}
	if !bytes.Equal(buf[:n], wantDown) {
		t.Fatalf("stream.Read = %q, want %q", buf[:n], wantDown)
	}

	// 6) 上游 END_STREAM 后读侧 EOF。
	writeH2RawFrame(upConn, h2FrameData, h2FlagEndStream, 1, nil)
	readCh := make(chan error, 1)
	go func() {
		_, rerr2 := stream.Read(buf)
		readCh <- rerr2
	}()
	select {
	case rerr2 := <-readCh:
		if !errors.Is(rerr2, io.EOF) {
			t.Fatalf("stream.Read after END_STREAM = %v, want EOF", rerr2)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for EOF after END_STREAM")
	}
	_ = ctx
}

// h2WSReadTestFrame 读一个完整 h2 帧（头 + 净荷）。
func h2WSReadTestFrame(br *bufio.Reader) (uint8, uint8, uint32, []byte, error) {
	header := make([]byte, 9)
	if _, err := io.ReadFull(br, header); err != nil {
		return 0, 0, 0, nil, err
	}
	length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(br, payload); err != nil {
			return 0, 0, 0, nil, err
		}
	}
	return header[3], header[4], binary.BigEndian.Uint32(header[5:9]) & 0x7fffffff, payload, nil
}

// h2WSHeadersContainTest 解码头块并检查指定字段。
func h2WSHeadersContainTest(payload []byte, name string, value string) bool {
	found := false
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == name && f.Value == value {
			found = true
		}
	})
	if _, err := dec.Write(payload); err != nil {
		return false
	}
	_ = dec.Close()
	return found
}

// h2WSEncodeTestHeaders 编码 HEADERS 帧（stream 1，END_HEADERS）。
func h2WSEncodeTestHeaders(fields [][2]string) []byte {
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range fields {
		_ = enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]})
	}
	payload := hb.Bytes()
	frame := make([]byte, 9+len(payload))
	n := len(payload)
	frame[0] = byte(n >> 16)
	frame[1] = byte(n >> 8)
	frame[2] = byte(n)
	frame[3] = h2FrameHeaders
	frame[4] = h2FlagEndHeaders
	binary.BigEndian.PutUint32(frame[5:9], 1)
	copy(frame[9:], payload)
	return frame
}
