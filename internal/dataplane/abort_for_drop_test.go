package dataplane

import (
	"net"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	forkhttp2 "github.com/x01n/http2"
)

/**
 * h2ResettableTCPConn 同时具备真实 TCP 叶子与 ResetStreamHandler，
 * 用于验证 AbortForDrop 在流级复位可用时绝不关共享连接。
 */
type h2ResettableTCPConn struct {
	*net.TCPConn
	probe *h2ResetProbeConn
}

func (c *h2ResettableTCPConn) ResetStreamHandler(code forkhttp2.ErrCode) bool {
	return c.probe.ResetStreamHandler(code)
}

/**
 * TestAbortForDropH2PrefersStreamReset 锁定 h2 的终止优先级：
 * RST_STREAM 成功时返回 true，且共享 TCP 连接保持可用。
 */
func TestAbortForDropH2PrefersStreamReset(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	probe := &h2ResetProbeConn{}
	g := &InboundProtocolGuard{
		protocol: "h2",
		conn:     &h2ResettableTCPConn{TCPConn: server, probe: probe},
	}
	if !g.AbortForDrop(nil, dropExecutorForTest(), dropReasonForTest("bot")) {
		t.Fatal("h2 with ResetStreamHandler must report a protocol-level abort")
	}
	if !probe.called || probe.code != h2ErrCodeCancel {
		t.Fatalf("h2 abort must send RST_STREAM(CANCEL), called=%v code=0x%x", probe.called, uint32(probe.code))
	}
	if _, err := server.Write([]byte("stream-alive")); err != nil {
		t.Errorf("h2 stream reset must not close the shared connection: %v", err)
	}
	_ = client.Close()
}

/**
 * TestAbortForDropH2FallsBackToConnectionClose 锁定 h2 流级复位失败后的
 * 兜底：关闭底层 TCP，绝不再回写 403/502。
 */
func TestAbortForDropH2FallsBackToConnectionClose(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	g := &InboundProtocolGuard{
		protocol: "h2",
		conn:     &h2ServerConnShape{Conn: server},
	}
	if !g.AbortForDrop(nil, dropExecutorForTest(), dropReasonForTest("bot")) {
		t.Fatal("h2 without stream reset must fall back to closing the connection")
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer should observe connection close when h2 stream reset is unavailable")
	}
}

/**
 * TestAbortForDropH3ExecutesResetToken 验证 h3 优先执行流级取消闭包，
 * 且不触碰回环连接。
 */
func TestAbortForDropH3ExecutesResetToken(t *testing.T) {
	c := app.NewContext(0)
	c.Request.Header.SetProtocol("H3")
	executed := false
	c.Set(InternalHTTP3ResetTokenHeader, func() { executed = true })
	g := &InboundProtocolGuard{protocol: "h3"}
	if !g.AbortForDrop(c, dropExecutorForTest(), dropReasonForTest("bot")) {
		t.Fatal("h3 with a reset token must report a protocol-level abort")
	}
	if !executed {
		t.Fatal("h3 reset token closure was not executed")
	}
}

/**
 * TestAbortForDropH3WithoutTokenClosesLoopback 验证 h3 流级闭包缺失时
 * 关闭本机回环连接，由 h3 服务侧的取消链路终止 QUIC 流。
 */
func TestAbortForDropH3WithoutTokenClosesLoopback(t *testing.T) {
	server, client, _ := testRawTCPConn(t)
	c := app.NewContext(0)
	c.Request.Header.SetProtocol("H3")
	g := &InboundProtocolGuard{
		protocol: "h3",
		conn:     &fixURIHertzConn{Conn: server},
	}
	if !g.AbortForDrop(c, dropExecutorForTest(), dropReasonForTest("bot")) {
		t.Fatal("h3 without a reset token must fall back to closing the loopback connection")
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer should observe loopback connection close")
	}
}

/**
 * TestAbortForDropNilReportsFalse 锁定 nil 守卫的返回值：没有连接就
 * 没有任何协议级手段可用，但调用方仍不得回写拦截页。
 */
func TestAbortForDropNilReportsFalse(t *testing.T) {
	var g *InboundProtocolGuard
	if g.AbortForDrop(nil, dropExecutorForTest(), dropReasonForTest("bot")) {
		t.Fatal("nil guard must not report a successful abort")
	}
}
