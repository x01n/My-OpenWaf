package dataplane

import (
	"bufio"
	"io"
	"net"
	"sync"

	"My-OpenWaf/internal/waf/bot"
)

const maxClientHelloRecord = 16 * 1024

type TLSFingerprintListener struct {
	net.Listener
}

func NewTLSFingerprintListener(ln net.Listener) net.Listener {
	return &TLSFingerprintListener{Listener: ln}
}

func (l *TLSFingerprintListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newTLSFingerprintConn(conn), nil
}

func newTLSFingerprintConn(conn net.Conn) net.Conn {
	br := bufio.NewReader(conn)
	fp := peekTLSFingerprint(br)
	pc := &peekConn{Conn: conn, reader: br, fingerprint: fp}
	return bot.WrapFingerprintConn(pc, fp)
}

type peekConn struct {
	net.Conn
	reader      *bufio.Reader
	fingerprint bot.TLSClientFingerprint
	mu          sync.RWMutex
}

func (c *peekConn) NetConn() net.Conn {
	return c.Conn
}

func (c *peekConn) Read(p []byte) (int, error) {
	if c.reader != nil && c.reader.Buffered() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

func (c *peekConn) SetTLSHandshakeInfo(version string, alpn string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fingerprint.TLSVersion = version
	if alpn != "" {
		c.fingerprint.ALPN = []string{alpn}
	}
}

func (c *peekConn) TLSFingerprint() (bot.TLSClientFingerprint, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.fingerprint, c.fingerprint.HasValue()
}

func peekTLSFingerprint(r *bufio.Reader) bot.TLSClientFingerprint {
	header, err := r.Peek(5)
	if err != nil || len(header) < 5 || header[0] != 0x16 {
		return bot.TLSClientFingerprint{}
	}
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen <= 0 || recordLen+5 > maxClientHelloRecord {
		return bot.TLSClientFingerprint{}
	}
	record, err := r.Peek(recordLen + 5)
	if err != nil && err != io.EOF {
		return bot.TLSClientFingerprint{}
	}
	fp, err := bot.ParseTLSClientHello(record)
	if err != nil {
		return bot.TLSClientFingerprint{}
	}
	return fp
}
