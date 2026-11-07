package dataplane

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// readerFromConn 是「底层连接实现 io.ReaderFrom」的桩：记录转发调用与收到的
// 字节，用于确认 FixURIConn.ReadFrom 直接委托而不自行缓冲。
type readerFromConn struct {
	fakeReadConn
	reads    int
	received []byte
}

func (c *readerFromConn) ReadFrom(r io.Reader) (int64, error) {
	c.reads++
	b, err := io.ReadAll(r)
	c.received = append(c.received, b...)
	return int64(len(b)), err
}

// writeOnlyConn 是「底层连接未实现 io.ReaderFrom」的桩：只记录 Write 收到的
// 字节，用于确认回退路径仍然完整转发。
type writeOnlyConn struct {
	fakeReadConn
	written []byte
}

func (c *writeOnlyConn) Write(b []byte) (int, error) {
	c.written = append(c.written, b...)
	return len(b), nil
}

// TestFixURIConnReadFromDelegates 钉住底层连接支持 ReadFrom 时走委托路径。
func TestFixURIConnReadFromDelegates(t *testing.T) {
	raw := &readerFromConn{}
	conn := &FixURIConn{Conn: raw}

	n, err := conn.ReadFrom(strings.NewReader("hello-body"))
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if n != 10 || string(raw.received) != "hello-body" {
		t.Fatalf("delegated n=%d received=%q, want 10 and %q", n, raw.received, "hello-body")
	}
	if raw.reads != 1 {
		t.Fatalf("underlying ReadFrom calls = %d, want 1", raw.reads)
	}
}

// TestFixURIConnReadFromFallsBackToWrite 钉住底层不支持 ReadFrom 时的回退路径。
func TestFixURIConnReadFromFallsBackToWrite(t *testing.T) {
	raw := &writeOnlyConn{}
	conn := &FixURIConn{Conn: raw}

	const body = "fallback-body"
	n, err := conn.ReadFrom(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if n != int64(len(body)) || !bytes.Equal(raw.written, []byte(body)) {
		t.Fatalf("fallback n=%d written=%q, want %d and %q", n, raw.written, len(body), body)
	}
}

// TestFixURIConnIsReaderFrom 在编译期钉住标准库快速路径依赖的接口实现。
func TestFixURIConnIsReaderFrom(t *testing.T) {
	var _ io.ReaderFrom = (*FixURIConn)(nil)
}
