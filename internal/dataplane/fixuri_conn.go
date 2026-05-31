package dataplane

import (
	"bytes"
	"crypto/tls"
	"net"

	"My-OpenWaf/internal/waf/bot"
)

type FixURIConn struct {
	net.Conn
	checked bool
	prefix  []byte
}

func NewFixURIConn(conn net.Conn) net.Conn {
	return &FixURIConn{Conn: conn}
}

func (c *FixURIConn) NetConn() net.Conn {
	return c.Conn
}

func (c *FixURIConn) Handshake() error {
	if tlsConn, ok := c.Conn.(interface{ Handshake() error }); ok {
		return tlsConn.Handshake()
	}
	return nil
}

func (c *FixURIConn) ConnectionState() tls.ConnectionState {
	if tlsConn, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return tlsConn.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (c *FixURIConn) TLSFingerprint() (bot.TLSClientFingerprint, bool) {
	if carrier, ok := c.Conn.(interface {
		TLSFingerprint() (bot.TLSClientFingerprint, bool)
	}); ok {
		return carrier.TLSFingerprint()
	}
	return bot.TLSClientFingerprint{}, false
}

func (c *FixURIConn) SetTLSHandshakeInfo(version string, alpn string) {
	if setter, ok := c.Conn.(interface{ SetTLSHandshakeInfo(string, string) }); ok {
		setter.SetTLSHandshakeInfo(version, alpn)
	}
}

func (c *FixURIConn) Read(b []byte) (int, error) {
	if c.checked {
		if len(c.prefix) > 0 {
			n := copy(b, c.prefix)
			c.prefix = c.prefix[n:]
			return n, nil
		}
		return c.Conn.Read(b)
	}
	c.checked = true

	if stateProvider, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		if stateProvider.ConnectionState().NegotiatedProtocol == "h2" {
			return c.Conn.Read(b)
		}
	}

	n, err := c.Conn.Read(b)
	if n == 0 {
		return n, err
	}

	data := b[:n]
	if len(data) > 0 && data[0] == 0x16 {
		return n, err
	}
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
