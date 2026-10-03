package drop

import (
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"
)

// errCloseConn 是所有 Close 都返回错误的假连接：验证 Execute 的失败路径不
// 登记统计、不冒烟，且错误原样返回（调用方守卫已兜底，不重试不降级）。
type errCloseConn struct{ closed bool }

func (m *errCloseConn) Read(b []byte) (int, error)  { return 0, nil }
func (m *errCloseConn) Write(b []byte) (int, error) { return len(b), nil }
func (m *errCloseConn) Close() error                { m.closed = true; return errors.New("owned elsewhere") }
func (m *errCloseConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
}
func (m *errCloseConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2}
}
func (m *errCloseConn) SetDeadline(t time.Time) error      { return nil }
func (m *errCloseConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *errCloseConn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*errCloseConn)(nil)

// TestDropExecutorExecuteCloseErrorSkipsStats 失败关闭不登记 drop 统计。
func TestDropExecutorExecuteCloseErrorSkipsStats(t *testing.T) {
	executor := NewDropExecutor(true, slog.Default())
	conn := &errCloseConn{}
	err := executor.Execute(conn, DropReason{Source: "bot", Timestamp: time.Now()})
	if err == nil {
		t.Fatalf("Execute must return the close error")
	}
	if !conn.closed {
		t.Fatalf("connection close must be attempted")
	}
	stats := executor.GetStats()
	if stats.TotalDropped.Load() != 0 {
		t.Errorf("failed close must not count as drop, TotalDropped = %d", stats.TotalDropped.Load())
	}
}
