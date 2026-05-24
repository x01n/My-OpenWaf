package dataplane

import (
	"bytes"
	"net"
)

type fixURIListener struct {
	net.Listener
}

func NewFixURIListener(ln net.Listener) net.Listener {
	return &fixURIListener{Listener: ln}
}

func (l *fixURIListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &fixURIConn{Conn: c}, nil
}

type fixURIConn struct {
	net.Conn
	checked bool
	prefix  []byte
}

func (c *fixURIConn) Read(b []byte) (int, error) {
	if c.checked {
		if len(c.prefix) > 0 {
			n := copy(b, c.prefix)
			c.prefix = c.prefix[n:]
			return n, nil
		}
		return c.Conn.Read(b)
	}
	c.checked = true

	n, err := c.Conn.Read(b)
	if n == 0 {
		return n, err
	}

	data := b[:n]
	sp := bytes.IndexByte(data, ' ')
	if sp < 0 || sp+1 >= n || data[sp+1] == '/' || data[sp+1] == '*' {
		return n, err
	}

	fixed := make([]byte, n+1)
	copy(fixed, data[:sp+1])
	fixed[sp+1] = '/'
	copy(fixed[sp+2:], data[sp+1:n])

	written := copy(b, fixed)
	if written < len(fixed) {
		c.prefix = append([]byte(nil), fixed[written:]...)
	}
	return written, err
}
