package stream

import (
	"io"
	"net"
	"time"
)

// testHertzConn / loopbackHertzConn mirror the dataplane package fixtures used
// by the CloseNotify binding tests. The tests moved here with the runtime, so
// the fixtures are reproduced locally per the package's own test scope.
type testHertzConn struct {
	net.Conn
}

type loopbackHertzConn struct {
	Conn       *testHertzConn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *testHertzConn) Peek(n int) ([]byte, error) { return nil, io.EOF }
func (c *testHertzConn) Skip(n int) error           { return nil }
func (c *testHertzConn) Release() error             { return nil }
func (c *testHertzConn) Len() int                   { return 0 }
func (c *testHertzConn) ReadByte() (byte, error)    { return 0, io.EOF }
func (c *testHertzConn) ReadBinary(n int) ([]byte, error) {
	return nil, io.EOF
}
func (c *testHertzConn) Malloc(n int) ([]byte, error) { return make([]byte, n), nil }
func (c *testHertzConn) WriteBinary(b []byte) (int, error) {
	return c.Write(b)
}
func (c *testHertzConn) Flush() error { return nil }
func (c *testHertzConn) SetReadTimeout(t time.Duration) error {
	return c.SetReadDeadline(time.Now().Add(t))
}
func (c *testHertzConn) SetWriteTimeout(t time.Duration) error {
	return c.SetWriteDeadline(time.Now().Add(t))
}

func (c *testHertzConn) NetConn() net.Conn { return c.Conn }
func (c *loopbackHertzConn) Read(p []byte) (int, error) {
	return c.Conn.Read(p)
}
func (c *loopbackHertzConn) Write(p []byte) (int, error) {
	return c.Conn.Write(p)
}
func (c *loopbackHertzConn) Close() error {
	return c.Conn.Close()
}
func (c *loopbackHertzConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}
func (c *loopbackHertzConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}
func (c *loopbackHertzConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
func (c *loopbackHertzConn) Peek(n int) ([]byte, error) { return c.Conn.Peek(n) }
func (c *loopbackHertzConn) Skip(n int) error           { return c.Conn.Skip(n) }
func (c *loopbackHertzConn) Release() error             { return c.Conn.Release() }
func (c *loopbackHertzConn) Len() int                   { return c.Conn.Len() }
func (c *loopbackHertzConn) ReadByte() (byte, error)    { return c.Conn.ReadByte() }
func (c *loopbackHertzConn) ReadBinary(n int) ([]byte, error) {
	return c.Conn.ReadBinary(n)
}
func (c *loopbackHertzConn) Malloc(n int) ([]byte, error) { return c.Conn.Malloc(n) }
func (c *loopbackHertzConn) WriteBinary(b []byte) (int, error) {
	return c.Conn.WriteBinary(b)
}
func (c *loopbackHertzConn) Flush() error { return c.Conn.Flush() }
func (c *loopbackHertzConn) SetReadTimeout(t time.Duration) error {
	return c.Conn.SetReadTimeout(t)
}
func (c *loopbackHertzConn) SetWriteTimeout(t time.Duration) error {
	return c.Conn.SetWriteTimeout(t)
}
func (c *loopbackHertzConn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return c.Conn.LocalAddr()
}
func (c *loopbackHertzConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.Conn.RemoteAddr()
}
func (c *loopbackHertzConn) NetConn() net.Conn {
	return c.Conn.NetConn()
}
