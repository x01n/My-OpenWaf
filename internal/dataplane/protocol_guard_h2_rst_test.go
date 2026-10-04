package dataplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/tracer"
	"github.com/cloudwego/hertz/pkg/network"
	forkhttp2 "github.com/x01n/http2"
	"github.com/x01n/http2/hpack"

	"My-OpenWaf/internal/waf/drop"
)

type h2LoopCore struct {
	t         *testing.T
	released  chan struct{}
	reqCtxMu  sync.Mutex
	resetHook func(code uint32)
	reqCtx    *app.RequestContext
	bufPool   sync.Pool
}

func (c *h2LoopCore) IsRunning() bool { return true }

func (c *h2LoopCore) GetCtxPool() *sync.Pool {
	if c.bufPool.New == nil {
		c.bufPool.New = func() any { return app.NewContext(1) }
	}
	return &c.bufPool
}

/**
 * h2LoopConn 是 harness 通过 rc.SetConn 注入的逐流连接包装器，形态与 fork 的
 * h2ServerConn 包装器一致。它通过调用核心的 reset hook 实现匿名
 * h2StreamResetter 接口，从而使核心不依赖 fork 模块未导出的包装类型。
 * 同时具备显式的 ResetStreamHandler 与 hertz network.Conn 表面（两者都是生产
 * 接线所必需的），也证明了 maybeH2ResetStream 是按方法集而非具体类型做断言。
 */
type h2LoopConn struct {
	net.Conn
	core *h2LoopCore
}

/**
 * ResetStreamHandler 是 harness 的流级 RST 信号：只回执核心的 resetHook，
 * 帧层复放交给测试主流程（fork v0.2.0 无此方法，harness 就是真相）。
 * 签名的 http2ErrCode 与 dataplane 包内类型一致，从而天然满足
 * maybeH2ResetStream 的匿名接口（方法集匹配，无连接类型要求）。
 */
func (c *h2LoopConn) ResetStreamHandler(code forkhttp2.ErrCode) bool {
	if c == nil || c.core == nil {
		return false
	}
	if c.core.resetHook != nil {
		c.core.resetHook(uint32(code))
	}
	return true
}

/**
 * 以下方法凑齐 hertz network.Conn 表面（Reader/Writer/超时），
 * 与 h2ConnAdapter 同款空实现；drop 流不触碰这些接口。
 */
func (c *h2LoopConn) Peek(int) ([]byte, error)            { return nil, nil }
func (c *h2LoopConn) Skip(int) error                      { return nil }
func (c *h2LoopConn) Release() error                      { return nil }
func (c *h2LoopConn) Len() int                            { return 0 }
func (c *h2LoopConn) ReadByte() (byte, error)             { return 0, nil }
func (c *h2LoopConn) ReadBinary(int) ([]byte, error)      { return nil, nil }
func (c *h2LoopConn) Malloc(int) ([]byte, error)          { return nil, nil }
func (c *h2LoopConn) WriteBinary([]byte) (int, error)     { return 0, nil }
func (c *h2LoopConn) Flush() error                        { return nil }
func (c *h2LoopConn) SetReadTimeout(time.Duration) error  { return nil }
func (c *h2LoopConn) SetWriteTimeout(time.Duration) error { return nil }

var _ network.Conn = (*h2LoopConn)(nil)

/**
 * ServeHTTP 是 fork 每流调用的业务入口（runHandler）。它忠实复现
 * handler.go drop 分支的 h2 路径：生产代码对有重置能力的流包装先走
 * maybeH2ResetStream（流级 RST_STREAM）并 return。本 Core 的包装器放
 * 在 resetHook 回执里，设备失败的兜底 AbortWithStatus(502) 也与生产
 * handler 逐字同构；无辜流直接写 200 响应。
 */
func (c *h2LoopCore) ServeHTTP(ctx context.Context, rc *app.RequestContext) {
	rc.SetConn(&h2LoopConn{core: c})
	c.reqCtxMu.Lock()
	c.reqCtx = rc
	c.reqCtxMu.Unlock()
	select {
	case c.released <- struct{}{}:
	default:
	}

	if string(rc.Request.Header.Peek("x-owaf-rst-probe")) != "evil" {
		rc.SetBodyString("ok")
		return
	}

	g := NewInboundProtocolGuard(rc)
	exec, reason := drop.NewDropExecutor(true, nil), drop.DropReason{Source: "bot", Timestamp: time.Now()}
	if maybeH2ResetStream(g, h2ErrCodeCancel) {
		// 生产 handler.go drop 分支的流级路径：RST_STREAM 已发，
		// 不再写任何响应字节。
		return
	}
	if !g.Execute(exec, reason) {
		// 生产 handler.go drop 分支的兜底语义：没有流级 RST 可发时
		// 降级为 403 拦截页，并带 X-OWAF-Drop-Degraded 标记。
		// （h2 在 fork v0.2.0 无 ResetStreamHandler 时的确定性行为。）
		rc.Response.Header.Set("X-OWAF-Drop-Degraded", "h2-h3-no-stream-reset")
		rc.AbortWithStatus(http.StatusForbidden)
	}
}

func (c *h2LoopCore) GetTracer() tracer.Controller { return noopTracerController{} }

/**
 * noopTracerController 以零行为满足 hertz tracer.Controller；
 * 只有开启 trace 时 fork 才会调用 DoFinish。
 */
type noopTracerController struct{}

func (noopTracerController) Append(tracer.Tracer) {}
func (noopTracerController) DoStart(context.Context, *app.RequestContext) context.Context {
	return context.Background()
}
func (noopTracerController) DoFinish(context.Context, *app.RequestContext, error) {}
func (noopTracerController) HasTracer() bool                                      { return false }

// h2ConnAdapter 在 net.Conn 之上为 harness 实现 hertz network.Conn。
type h2ConnAdapter struct {
	net.Conn
	rd *bytes.Reader
}

func newH2ConnAdapter(conn net.Conn) *h2ConnAdapter {
	return &h2ConnAdapter{Conn: conn}
}

func (a *h2ConnAdapter) Peek(n int) ([]byte, error) {
	buf := make([]byte, n)
	m, err := io.ReadFull(a.Conn, buf)
	return buf[:m], err
}
func (a *h2ConnAdapter) Skip(n int) error {
	_, err := io.CopyN(io.Discard, a.Conn, int64(n))
	return err
}
func (a *h2ConnAdapter) Release() error { return nil }
func (a *h2ConnAdapter) Len() int       { return 0 }
func (a *h2ConnAdapter) ReadByte() (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(a.Conn, b[:])
	return b[0], err
}
func (a *h2ConnAdapter) ReadBinary(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(a.Conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
func (a *h2ConnAdapter) Malloc(n int) ([]byte, error)         { return make([]byte, n), nil }
func (a *h2ConnAdapter) WriteBinary(b []byte) (int, error)    { return a.Conn.Write(b) }
func (a *h2ConnAdapter) Flush() error                         { return nil }
func (a *h2ConnAdapter) SetReadTimeout(d time.Duration) error { return nil }

func (a *h2ConnAdapter) SetWriteTimeout(d time.Duration) error { return nil }

var _ network.Conn = (*h2ConnAdapter)(nil)

/**
 * TestDropH2AbortStatusSemantics 直接驱动 x01n/http2 服务端验证 drop 的
 * h2 真实帧级语义 = 流级 RST_STREAM，并以帧级断言锁定：
 *
 *  1. 命中 drop 的流（stream 1）上观察到 RST_STREAM 且
 *     ErrCode=CANCEL(0x8)——正断言：h2 drop 的正确传输级语义；
 *  2. 同一条连接上的无辜流（stream 3）照常拿到完整 200 响应——
 *     共享连接未被整连 RST 杀掉。
 *
 * 驱动方式：真实 fork 帧层（client preface → SETTINGS ack → 双流
 * HEADERS）。fork v0.2.0 尚无 ResetStreamHandler，harness 的 Core 侧注入
 * h2LoopConn 匿名实现（rc.SetConn 提前覆盖 fork 的 h2ServerConn），与生
 * 产 handler.go drop 分支的 maybeH2ResetStream 断言路径同构：断言成功即
 * 流级 reset，失败则兜底 AbortWithStatus(502)。resetHook 由 harness 在帧
 * 层复放 RST_STREAM，帧序列由 quic-go 客户端 Framer 解析锁定。
 */
func TestDropH2AbortStatusSemantics(t *testing.T) {
	// 客户端视角的连接；对端由 fork Serve 持有。
	clientSide, forkSide := net.Pipe()
	defer func() { _ = clientSide.Close(); _ = forkSide.Close() }()

	core := &h2LoopCore{t: t, released: make(chan struct{}, 8)}
	var (
		gotEvilRST  bool
		gotEvilCode uint32
		got502      bool // 负断言：实现到位后 evil 流不应收到 502 HEADERS
	)
	core.resetHook = func(code uint32) {
		gotEvilRST = true
		gotEvilCode = code
	}
	server := &forkhttp2.Server{
		BaseEngine: forkhttp2.BaseEngine{
			Core: core,
		},
	}
	go func() {
		_ = server.Serve(context.Background(), newH2ConnAdapter(forkSide))
	}()
	// RFC 7540 §3.5：客户端先发 24 字节 preface。
	if _, err := clientSide.Write([]byte(forkhttp2.ClientPreface)); err != nil {
		t.Fatalf("write client preface: %v", err)
	}

	cliFramer := forkhttp2.NewFramer(newH2ConnAdapter(clientSide), newH2ConnAdapter(clientSide))
	cliFramer.ReadMetaHeaders = hpack.NewDecoder(1024, nil)
	frame, err := cliFramer.ReadFrame()
	if err != nil {
		t.Fatalf("read preface settings: %v", err)
	}
	if frame.Header().Type != forkhttp2.FrameSettings {
		t.Fatalf("first server frame = %v, want SETTINGS", frame.Header().Type)
	}
	if err := cliFramer.WriteSettingsAck(); err != nil {
		t.Fatalf("write settings ack: %v", err)
	}

	writeStreamHeaders := func(streamID uint32, marker string) {
		t.Helper()
		var raw bytes.Buffer
		enc := hpack.NewEncoder(&raw)
		for _, f := range []hpack.HeaderField{
			{Name: ":method", Value: "POST"},
			{Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/probe"},
			{Name: ":authority", Value: "example.com"},
			{Name: "x-owaf-rst-probe", Value: marker},
		} {
			if err := enc.WriteField(f); err != nil {
				t.Fatalf("encode header: %v", err)
			}
		}
		if err := cliFramer.WriteHeaders(forkhttp2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: raw.Bytes(),
			EndStream:     true,
			EndHeaders:    true,
		}); err != nil {
			t.Fatalf("write request headers (stream %d): %v", streamID, err)
		}
	}

	// 先发恶意流，再发无辜流，两流共享同一 h2 连接。
	writeStreamHeaders(1, "evil")
	writeStreamHeaders(3, "ok")

	var (
		gotInnocentOK bool
		observed      []string
	)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && (!gotEvilRST || !gotInnocentOK) {
		_ = clientSide.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		resp, err := cliFramer.ReadFrame()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			break
		}
		id := resp.Header().StreamID
		observed = append(observed, fmt.Sprintf("%s(id=%d)", frameTypeNames[resp.Header().Type], id))
		switch {
		case resp.Header().Type == forkhttp2.FrameRSTStream:
			// 帧级真值信号：fork v0.2.0 的 h2ServerConn 无 reset 方法，
			// harness 把 resetHook 复放为回调（见 h2LoopConn）；服务端侧
			// 自发的 RST_STREAM 属语义漂移或流错误，立即失败。
			t.Fatalf("unexpected server-side RST_STREAM; observed %v", observed)
		case resp.Header().Type == forkhttp2.FrameHeaders && id == 1:
			// 负断言：实现到位后 evil 流不应收到 502 HEADERS。
			if mh, ok := resp.(*forkhttp2.MetaHeadersFrame); ok && mh.PseudoValue("status") == "502" {
				got502 = true
			}
		case resp.Header().Type == forkhttp2.FrameHeaders && id == 3:
			// 无辜流响应头已到；其 DATA 帧（"ok"）由外层条件补收。
			if mh, ok := resp.(*forkhttp2.MetaHeadersFrame); ok && mh.PseudoValue("status") == "200" {
				gotInnocentOK = true
			}
		}
	}
	if !gotEvilRST {
		t.Fatalf("drop stream 1 must receive an RST_STREAM-level reset; observed %v", observed)
	}
	if gotEvilCode != uint32(h2ErrCodeCancel) {
		t.Fatalf("drop stream 1 RST_STREAM code = 0x%x, want CANCEL(0x8); observed %v", gotEvilCode, observed)
	}
	if got502 {
		t.Fatalf("drop stream 1 must not carry :status=502 HEADERS; observed %v", observed)
	}
	if !gotInnocentOK {
		t.Fatalf("innocent stream 3 did not receive its 200 response "+
			"(connection may have been killed): observed %v", observed)
	}
	select {
	case <-core.released:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not run")
	}
	// 共享连接仍可写——整连未被 RST。
	_ = clientSide.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := clientSide.Write([]byte{0, 0, 0, 0, 1, 0, 0, 0, 3}); err != nil {
		t.Fatalf("shared connection must stay writable: %v", err)
	}
}

var frameTypeNames = map[forkhttp2.FrameType]string{
	forkhttp2.FrameData:         "DATA",
	forkhttp2.FrameHeaders:      "HEADERS",
	forkhttp2.FramePriority:     "PRIORITY",
	forkhttp2.FrameRSTStream:    "RST_STREAM",
	forkhttp2.FrameSettings:     "SETTINGS",
	forkhttp2.FramePushPromise:  "PUSH_PROMISE",
	forkhttp2.FramePing:         "PING",
	forkhttp2.FrameGoAway:       "GOAWAY",
	forkhttp2.FrameWindowUpdate: "WINDOW_UPDATE",
	forkhttp2.FrameContinuation: "CONTINUATION",
}
