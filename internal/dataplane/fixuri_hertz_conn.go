package dataplane

import (
	"bytes"
	"crypto/tls"
	"net"
	"time"
)

type fixURIHertzConn struct {
	net.Conn
	readBuf []byte
	write   bytes.Buffer
}

func newFixURIHertzConn(conn net.Conn) *fixURIHertzConn {
	return &fixURIHertzConn{Conn: conn}
}

func (c *fixURIHertzConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *fixURIHertzConn) Write(b []byte) (int, error) {
	if err := c.Flush(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *fixURIHertzConn) SetReadTimeout(t time.Duration) error {
	if t <= 0 {
		return c.SetReadDeadline(time.Time{})
	}
	return c.SetReadDeadline(time.Now().Add(t))
}

func (c *fixURIHertzConn) SetWriteTimeout(t time.Duration) error {
	if t <= 0 {
		return c.SetWriteDeadline(time.Time{})
	}
	return c.SetWriteDeadline(time.Now().Add(t))
}

func (c *fixURIHertzConn) Peek(n int) ([]byte, error) {
	for len(c.readBuf) < n {
		buf := make([]byte, max(4096, n-len(c.readBuf)))
		read, err := c.Conn.Read(buf)
		if read > 0 {
			c.readBuf = append(c.readBuf, buf[:read]...)
		}
		if err != nil {
			if len(c.readBuf) >= n {
				break
			}
			return c.readBuf, err
		}
	}
	return c.readBuf[:n], nil
}

func (c *fixURIHertzConn) Skip(n int) error {
	if len(c.readBuf) < n {
		if _, err := c.Peek(n); err != nil {
			return err
		}
	}
	c.readBuf = c.readBuf[n:]
	return nil
}

func (c *fixURIHertzConn) Release() error {
	return nil
}

func (c *fixURIHertzConn) Len() int {
	return len(c.readBuf)
}

func (c *fixURIHertzConn) ReadByte() (byte, error) {
	if len(c.readBuf) == 0 {
		if _, err := c.Peek(1); err != nil {
			return 0, err
		}
	}
	b := c.readBuf[0]
	c.readBuf = c.readBuf[1:]
	return b, nil
}

func (c *fixURIHertzConn) ReadBinary(n int) ([]byte, error) {
	if len(c.readBuf) < n {
		if _, err := c.Peek(n); err != nil {
			return nil, err
		}
	}
	buf := append([]byte(nil), c.readBuf[:n]...)
	c.readBuf = c.readBuf[n:]
	return buf, nil
}

func (c *fixURIHertzConn) Malloc(n int) ([]byte, error) {
	pos := c.write.Len()
	c.write.Grow(n)
	_, _ = c.write.Write(make([]byte, n))
	return c.write.Bytes()[pos : pos+n], nil
}

func (c *fixURIHertzConn) WriteBinary(b []byte) (int, error) {
	return c.write.Write(b)
}

func (c *fixURIHertzConn) Flush() error {
	for c.write.Len() > 0 {
		n, err := c.Conn.Write(c.write.Bytes())
		if err != nil {
			return err
		}
		c.write.Next(n)
	}
	return nil
}

func (c *fixURIHertzConn) Handshake() error {
	if tlsConn, ok := c.Conn.(interface{ Handshake() error }); ok {
		return tlsConn.Handshake()
	}
	return nil
}

func (c *fixURIHertzConn) ConnectionState() tls.ConnectionState {
	if tlsConn, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return tlsConn.ConnectionState()
	}
	return tls.ConnectionState{}
}
