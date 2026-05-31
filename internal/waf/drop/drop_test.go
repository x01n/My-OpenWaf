package drop

import (
	"log/slog"
	"net"
	"testing"
	"time"
)

type mockConn struct{ closed bool }

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestDropExecutor_Execute(t *testing.T) {
	executor := NewDropExecutor(true, slog.Default())
	conn := &mockConn{}
	reason := DropReason{Source: "bot", RuleID: "test-rule-1", Detail: "bot detected", ClientIP: "1.2.3.4", Host: "example.com", Path: "/api/data", Timestamp: time.Now()}
	err := executor.Execute(conn, reason)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !conn.closed {
		t.Error("connection should be closed after Execute")
	}
}

func TestDropExecutor_ExecuteNilConn(t *testing.T) {
	executor := NewDropExecutor(true, slog.Default())
	reason := DropReason{Source: "cve", Timestamp: time.Now()}
	err := executor.Execute(nil, reason)
	if err != nil {
		t.Fatalf("Execute(nil) returned error: %v", err)
	}
}

func TestDropExecutor_Stats(t *testing.T) {
	executor := NewDropExecutor(true, slog.Default())
	now := time.Now()
	reasons := []DropReason{{Source: "bot", Timestamp: now}, {Source: "bot", Timestamp: now}, {Source: "cve", Timestamp: now}, {Source: "rule", Timestamp: now}, {Source: "ip_reputation", Timestamp: now}}
	for _, r := range reasons {
		conn := &mockConn{}
		executor.Execute(conn, r)
	}
	stats := executor.GetStats()
	if stats.TotalDropped.Load() != 5 {
		t.Errorf("TotalDropped = %d, want 5", stats.TotalDropped.Load())
	}
	if stats.DroppedByBot.Load() != 2 {
		t.Errorf("DroppedByBot = %d, want 2", stats.DroppedByBot.Load())
	}
	if stats.DroppedByCVE.Load() != 1 {
		t.Errorf("DroppedByCVE = %d, want 1", stats.DroppedByCVE.Load())
	}
	if stats.DroppedByRule.Load() != 2 {
		t.Errorf("DroppedByRule = %d, want 2", stats.DroppedByRule.Load())
	}
}

func TestDropExecutor_ResetStats(t *testing.T) {
	executor := NewDropExecutor(true, slog.Default())
	conn := &mockConn{}
	executor.Execute(conn, DropReason{Source: "bot", Timestamp: time.Now()})
	stats := executor.GetStats()
	if stats.TotalDropped.Load() != 1 {
		t.Fatalf("expected 1 drop before reset")
	}
	executor.ResetStats()
	stats = executor.GetStats()
	if stats.TotalDropped.Load() != 0 {
		t.Errorf("TotalDropped after reset = %d, want 0", stats.TotalDropped.Load())
	}
}

func TestDropExecutor_Enabled(t *testing.T) {
	executor := NewDropExecutor(false, slog.Default())
	if executor.Enabled() {
		t.Error("expected disabled")
	}
	executor.SetEnabled(true)
	if !executor.Enabled() {
		t.Error("expected enabled after SetEnabled(true)")
	}
}
