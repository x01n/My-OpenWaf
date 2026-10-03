package dataplane

import (
	"log/slog"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/waf/drop"
)

// dropExecutorForTest 返回与生产同构的启用态 DropExecutor。
func dropExecutorForTest() *drop.DropExecutor {
	return drop.NewDropExecutor(true, slog.Default())
}

// dropReasonForTest 返回一个足量的 DropReason，避免各测试重复构造。
func dropReasonForTest(source string) drop.DropReason {
	return drop.DropReason{Source: source, RuleID: "test-rule", Timestamp: time.Now()}
}

// testRawTCPConn 建立一对回环 TCP 连接：server 端模拟 WAF 服务端持有的
// 连接（即 drop 要 RST 的一侧），client 端模拟浏览器侧，用于观察对端
// 是否收到 RST/关闭。t.Cleanup 负责回收。
func testRawTCPConn(t *testing.T) (server *net.TCPConn, client *net.TCPConn, ln net.Listener) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr == nil {
			accepted <- conn.(*net.TCPConn)
		}
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("dial: %v", err)
	}
	client = dialed.(*net.TCPConn)
	server = <-accepted
	t.Cleanup(func() {
		client.Close()
		server.Close()
		ln.Close()
	})
	return server, client, ln
}

// fakeTCPConn 是 *net.TCPConn 的测试替身，Close 可观察，不占用内核资源。
// 用于「形状不符即拒绝」类断言：包裹链末端的非 *net.TCPConn 叶子必须
// 让解析器返回 nil。
type fakeTCPConn struct{ closed bool }

func (f *fakeTCPConn) Read(b []byte) (int, error)  { return 0, nil }
func (f *fakeTCPConn) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeTCPConn) Close() error                { f.closed = true; return nil }
func (f *fakeTCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
}
func (f *fakeTCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2}
}
func (f *fakeTCPConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeTCPConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeTCPConn) SetWriteDeadline(t time.Time) error { return nil }

// fakeTCPConn 必须满足 net.Conn，否则形状断言失真。
var _ net.Conn = (*fakeTCPConn)(nil)

// h2ServerConnShape mirrors x01n/http2's h2ServerConn field layout: embedded
// exported net.Conn first, unwalkable unexported pointer after. The resolver
// is allowed to find the embedded conn (same as upstream's NetConn), but the
// guard's protocol check must still forbid an RST on this shape.
type h2ServerConnShape struct {
	net.Conn
	rw any
}

// h1GuardCtx 构造带 h1 包裹链（fixURIHertzConn → TCP）的请求上下文。
func h1GuardCtx(t *testing.T, protocol string, wafConn net.Conn) (*app.RequestContext, *fakeTCPConn) {
	t.Helper()
	raw := &fakeTCPConn{}
	c := &app.RequestContext{}
	c.Request.Header.SetProtocol(protocol)
	c.SetConn(&fixURIHertzConn{Conn: wafConn})
	return c, raw
}

func TestRawTCPConnForRSTDisallowsOpaqueLeaf(t *testing.T) {
	// 包裹链内层指向非 *net.TCPConn 叶子（fakeTCPConn），必须解析失败。
	if got := rawTCPConnForRST(&fixURIHertzConn{Conn: &fakeTCPConn{}}); got != nil {
		t.Fatalf("opaque leaf must not resolve, got %T", got)
	}
}

// TestProtocolGuardOnlyTCPLeafDropsWithExecutor 恶意 h1 请求命中 drop 时，
// 守卫必须解析到真实 TCP 连接并关闭它（对端观察到连接关闭）。
func TestProtocolGuardOnlyTCPLeafDropsWithExecutor(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	_ = client
	c := &app.RequestContext{}
	c.Request.Header.SetProtocol("HTTP/1.1")
	c.SetConn(&fixURIHertzConn{Conn: server})
	g := NewInboundProtocolGuard(c)
	if got := g.ProtocolName(); got != "http/1.1" {
		t.Fatalf("ProtocolName = %q, want http/1.1", got)
	}
	if g.tcpDropTarget() == nil {
		t.Fatalf("h1 guard must resolve a TCP drop target")
	}
	if !g.CloseForDrop() {
		t.Fatalf("h1 drop should apply")
	}
	// 对端必须感知连接关闭。
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Errorf("peer should observe connection reset after h1 drop")
	}
}

// TestProtocolGuardH2NoConnectionRST 是「错误 reset」的核心回归：h2 请求
// 命中 drop 时绝不整连 RST，连接保持可写（无辜流不受影响）。
func TestProtocolGuardH2NoConnectionRST(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	_ = client
	g := &InboundProtocolGuard{
		protocol: "http/2.0",
		conn:     &h2ServerConnShape{Conn: server},
	}
	if !g.IsStreamMultiplexed() {
		t.Fatalf("h2 guard must be stream-multiplexed")
	}
	if g.tcpDropTarget() != nil {
		t.Fatalf("h2 guard must not resolve a TCP drop target")
	}
	if g.CloseForDrop() || g.Execute(dropExecutorForTest(), dropReasonForTest("bot")) {
		t.Fatalf("h2 drop must not apply connection-level RST")
	}
	if _, err := server.Write([]byte("stream-alive")); err != nil {
		t.Errorf("h2 drop must not close the shared connection: %v", err)
	}
}

// TestProtocolGuardH3NoConnectionRST 镜像 h3 场景（无 TCP 连接可 RST）：
// 守卫拒绝执行，连接不受影响。
func TestProtocolGuardH3NoConnectionRST(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	_ = client
	c := &app.RequestContext{}
	c.Request.Header.SetProtocol("H3")
	c.SetConn(&fixURIHertzConn{Conn: server})
	g := NewInboundProtocolGuard(c)
	if g.tcpDropTarget() != nil {
		t.Fatalf("h3 guard must not resolve a TCP drop target")
	}
	if g.CloseForDrop() {
		t.Fatalf("h3 drop must not apply connection-level RST")
	}
}

// TestProtocolGuardH2CNoConnectionRST 覆盖明文 h2c：同样禁止整连 RST。
func TestProtocolGuardH2CNoConnectionRST(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	_ = client
	g := &InboundProtocolGuard{protocol: "h2c", conn: server}
	if !g.IsStreamMultiplexed() {
		t.Fatalf("h2c guard must be stream-multiplexed")
	}
	if g.tcpDropTarget() != nil || g.CloseForDrop() {
		t.Fatalf("h2c drop must not apply connection-level RST")
	}
}

// TestProtocolGuardNilContextNeverRSTs 覆盖 NewInboundProtocolGuard(nil) 与
// 空守卫：绝不产生连接级副作用。
func TestProtocolGuardNilContextNeverRSTs(t *testing.T) {
	g := NewInboundProtocolGuard(nil)
	if g.ProtocolName() != "" {
		t.Fatalf("nil-context protocol = %q, want empty", g.ProtocolName())
	}
	if g.tcpDropTarget() != nil || g.CloseForDrop() {
		t.Fatalf("nil context must never apply a connection close")
	}
}

// TestProtocolGuardUnknownProtocolNeverRSTs 覆盖未知/缺失协议值：宁可放弃
// RST，也不闭错连接。
func TestProtocolGuardUnknownProtocolNeverRSTs(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	_ = client
	c := &app.RequestContext{}
	c.Request.Header.SetProtocol("")
	c.SetConn(&fixURIHertzConn{Conn: server})
	g := NewInboundProtocolGuard(c)
	if g.tcpDropTarget() != nil || g.CloseForDrop() {
		t.Fatalf("unknown protocol must not apply connection-level RST")
	}
}

// TestRawTCPConnForRSTUnwrapsStandardConn 验证 hertz standard.Conn 的
// 未导出 c 字段形态（单 net.Conn 字段 + 缓冲字段）能被 reflect 兜底解析。
// standardConnShape 必须像生产 standard.Conn 一样整个满足 net.Conn
// （方法转发到 c），才能让解析器走到字段扫描路径。
type standardConnShape struct {
	c       net.Conn
	buf     [8]byte
	ignored int64
}

func (s *standardConnShape) Read(b []byte) (int, error)    { return s.c.Read(b) }
func (s *standardConnShape) Write(b []byte) (int, error)   { return s.c.Write(b) }
func (s *standardConnShape) Close() error                  { return s.c.Close() }
func (s *standardConnShape) LocalAddr() net.Addr           { return s.c.LocalAddr() }
func (s *standardConnShape) RemoteAddr() net.Addr          { return s.c.RemoteAddr() }
func (s *standardConnShape) SetDeadline(t time.Time) error { return s.c.SetDeadline(t) }
func (s *standardConnShape) SetReadDeadline(t time.Time) error {
	return s.c.SetReadDeadline(t)
}
func (s *standardConnShape) SetWriteDeadline(t time.Time) error {
	return s.c.SetWriteDeadline(t)
}

var _ net.Conn = (*standardConnShape)(nil)

func TestRawTCPConnForRSTUnwrapsStandardConn(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	_ = client
	if got := rawTCPConnForRST(&standardConnShape{c: server}); got != server {
		t.Fatalf("unexported-standard-conn shape resolves to %T, want *net.TCPConn", got)
	}
	// fake 叶子仍然拒绝。
	if got := rawTCPConnForRST(&standardConnShape{c: &fakeTCPConn{}}); got != nil {
		t.Fatalf("unexported-standard-conn with opaque leaf must not resolve, got %T", got)
	}
}

// TestRawTCPConnForRSTWalksFixURIChain 覆盖 h1 生产包裹链的完整展开：
// fixURIHertzConn → tls.Conn → TCP。
func TestRawTCPConnForRSTWalksFixURIChain(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	_ = client
	chain := &fixURIHertzConn{Conn: &FixURIConn{Conn: server}}
	if got := rawTCPConnForRST(chain); got != server {
		t.Fatalf("fixURI chain resolves to %T, want *net.TCPConn", got)
	}
	// 直达 *net.TCPConn。
	if got := rawTCPConnForRST(server); got != server {
		t.Fatalf("direct *net.TCPConn must resolve to itself, got %T", got)
	}
}

// TestProtocolGuardH2ShapeHasNoExportablePatterns 固化 h2 形状契约：
// h2ServerConnShape 必须与 x01n 原型一致（嵌入 net.Conn + 一个不可导出字段）。
func TestProtocolGuardH2ShapeHasNoExportablePatterns(t *testing.T) {
	if n := reflect.TypeOf(h2ServerConnShape{}).NumField(); n != 2 {
		t.Fatalf("h2ServerConnShape fields = %d, want 2 (embedded net.Conn + rw)", n)
	}
}

// TestProtocolGuardDisabledExecutorStillRSTs 对应 handler 的 else 分支：
// drop 策略禁用时守卫仍直接关闭 h1 连接（维持旧 conn.Close 语义）。
func TestProtocolGuardDisabledExecutorStillRSTs(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	_ = client
	c := &app.RequestContext{}
	c.Request.Header.SetProtocol("HTTP/1.1")
	c.SetConn(&fixURIHertzConn{Conn: server})
	g := NewInboundProtocolGuard(c)
	disabled := dropExecutorForTest()
	disabled.Reconfigure(false)
	if disabled.Enabled() {
		t.Fatalf("executor should be disabled")
	}
	// Execute 在 executor 禁用时仍执行 h1 RST（旧行为：直接 conn.Close）。
	if !g.Execute(disabled, dropReasonForTest("bot")) {
		t.Fatalf("disabled path must still RST h1 conn")
	}
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Errorf("peer should observe connection reset")
	}
}

/**
 * TestProtocolGuardNilExecuteEqualsMockConnClose 锁定惰性 guard 的语义契约:
 * nil guard + enabled executor 等价旧版「dropExec.Enabled 时对 mock 连接
 * Close 空操作」;对真实 *net.TCPConn 则 1.1 语义输出(Close 幂等)。
 */
func TestProtocolGuardNilExecuteEqualsMockConnClose(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	if _, err := server.Write([]byte("k")); err != nil {
		t.Fatalf("warm write: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err != nil {
		t.Fatalf("warm read: %v", err)
	}
	// httptest 两端的 *net.TCPConn:旧语义 = 直接 Close,新 nil 语义 = 无操作,
	// 对端仍应读到后续写入。验证方式：nil guard Execute 之后 server 再写
	// 一字节给 client，client 能读到即证明连接未被 closed。
	guard := (*InboundProtocolGuard)(nil)
	if !guard.Execute(dropExecutorForTest(), dropReasonForTest("bot")) {
		t.Fatalf("nil guard with executor must report true (connections-only allocation offline)")
	}
	if _, err := server.Write([]byte("o")); err != nil {
		t.Fatalf("nil guard must leave server conn writable: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err != nil {
		t.Fatalf("nil guard must not close peer conn: %v", err)
	}
}
