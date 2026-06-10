package dataplane

import (
	"io"
	"net"
	"sync"

	"My-OpenWaf/internal/waf/bot"
)

// maxClientHelloRecord is the TLS record payload limit; the 5-byte header is read separately.
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
	return &peekConn{Conn: conn}
}

type peekConn struct {
	net.Conn
	prefix      []byte
	fingerprint bot.TLSClientFingerprint
	parsed      bool
	readMu      sync.Mutex
	mu          sync.RWMutex
}

func (c *peekConn) NetConn() net.Conn {
	return c.Conn
}

func (c *peekConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if !c.parsed {
		prefix, fp := readTLSFingerprintPrefix(c.Conn)
		c.prefix = prefix
		c.parsed = true
		if fp.HasValue() {
			c.mu.Lock()
			if fp.JA3 != "" {
				c.fingerprint.JA3 = fp.JA3
			}
			if fp.JA3Hash != "" {
				c.fingerprint.JA3Hash = fp.JA3Hash
			}
			if fp.JA4 != "" {
				c.fingerprint.JA4 = fp.JA4
			}
			if c.fingerprint.TLSVersion == "" {
				c.fingerprint.TLSVersion = fp.TLSVersion
			}
			if c.fingerprint.SNI == "" {
				c.fingerprint.SNI = fp.SNI
			}
			if len(c.fingerprint.ALPN) == 0 {
				c.fingerprint.ALPN = fp.ALPN
			}
			if len(c.fingerprint.CipherSuites) == 0 {
				c.fingerprint.CipherSuites = fp.CipherSuites
			}
			if len(c.fingerprint.Extensions) == 0 {
				c.fingerprint.Extensions = fp.Extensions
			}
			if len(c.fingerprint.Curves) == 0 {
				c.fingerprint.Curves = fp.Curves
			}
			if len(c.fingerprint.PointFormats) == 0 {
				c.fingerprint.PointFormats = fp.PointFormats
			}
			c.mu.Unlock()
		}
	}
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *peekConn) SetTLSHandshakeInfo(version string, sni string, alpn string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if version != "" {
		c.fingerprint.TLSVersion = version
	}
	if sni != "" {
		c.fingerprint.SNI = sni
	}
	if alpn != "" {
		c.fingerprint.ALPN = []string{alpn}
	}
}

func (c *peekConn) TLSFingerprint() (bot.TLSClientFingerprint, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.fingerprint, c.fingerprint.HasValue()
}

func setTLSHandshakeInfoOnConn(conn net.Conn, version string, sni string, alpn string) {
	for conn != nil {
		if setter, ok := conn.(interface{ SetTLSHandshakeInfo(string, string, string) }); ok {
			setter.SetTLSHandshakeInfo(version, sni, alpn)
			return
		}
		unwrapper, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		next := unwrapper.NetConn()
		if next == nil || next == conn {
			break
		}
		conn = next
	}
}

func readTLSFingerprintPrefix(conn net.Conn) ([]byte, bot.TLSClientFingerprint) {
	var header [5]byte
	n, err := io.ReadFull(conn, header[:])
	if err != nil {
		prefix := make([]byte, n)
		copy(prefix, header[:n])
		return prefix, bot.TLSClientFingerprint{}
	}
	if header[0] != 0x16 {
		prefix := make([]byte, len(header))
		copy(prefix, header[:])
		return prefix, bot.TLSClientFingerprint{}
	}
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen <= 0 || recordLen > maxClientHelloRecord {
		prefix := make([]byte, len(header))
		copy(prefix, header[:])
		return prefix, bot.TLSClientFingerprint{}
	}

	prefix := make([]byte, len(header), len(header)+recordLen)
	copy(prefix, header[:])
	var body []byte
	prefix, body, n, err = readFullIntoPrefix(conn, prefix, recordLen)
	if err != nil {
		return prefix, bot.TLSClientFingerprint{}
	}

	parseRecord, prefix, ok := readCompleteClientHelloRecord(conn, prefix, body)
	if !ok {
		return prefix, bot.TLSClientFingerprint{}
	}
	fp, err := bot.ParseTLSClientHello(parseRecord)
	if err != nil {
		return prefix, bot.TLSClientFingerprint{}
	}
	return prefix, fp
}

func readCompleteClientHelloRecord(conn net.Conn, prefix []byte, firstBody []byte) ([]byte, []byte, bool) {
	if len(firstBody) == 0 || firstBody[0] != 0x01 {
		return prefix, prefix, true
	}

	var need int
	var parseRecord []byte
	copied := 0
	if len(firstBody) >= 4 {
		helloLen := int(firstBody[1])<<16 | int(firstBody[2])<<8 | int(firstBody[3])
		if helloLen <= 0 || helloLen+4 > maxClientHelloRecord {
			return prefix, prefix, false
		}
		need = 4 + helloLen
		if len(firstBody) == need {
			return prefix, prefix, true
		}
		if len(firstBody) > need {
			parseRecord := make([]byte, 5+need)
			copy(parseRecord[:5], prefix[:5])
			parseRecord[3] = byte(need >> 8)
			parseRecord[4] = byte(need)
			copy(parseRecord[5:], firstBody[:need])
			return parseRecord, prefix, true
		}
		parseRecord = make([]byte, 5+need)
		copy(parseRecord[:5], prefix[:5])
		parseRecord[3] = byte(need >> 8)
		parseRecord[4] = byte(need)
		copied = copy(parseRecord[5:], firstBody)
	} else {
		copied = len(firstBody)
	}

	var handshakeHeader [4]byte
	if copied > 0 && len(firstBody) < 4 {
		copy(handshakeHeader[:], firstBody)
	}
	for {
		if need > 0 && copied >= need {
			break
		}

		var header [5]byte
		n, err := io.ReadFull(conn, header[:])
		prefix = append(prefix, header[:n]...)
		if err != nil {
			return prefix, prefix, false
		}
		if header[0] != 0x16 {
			return prefix, prefix, false
		}
		recordLen := int(header[3])<<8 | int(header[4])
		if recordLen <= 0 || recordLen > maxClientHelloRecord {
			return prefix, prefix, false
		}
		var body []byte
		prefix, body, n, err = readFullIntoPrefix(conn, prefix, recordLen)
		if need == 0 {
			headerNeed := 4 - copied
			if headerNeed > n {
				headerNeed = n
			}
			copy(handshakeHeader[copied:], body[:headerNeed])
			copied += headerNeed
			if copied >= 4 {
				helloLen := int(handshakeHeader[1])<<16 | int(handshakeHeader[2])<<8 | int(handshakeHeader[3])
				if helloLen <= 0 || helloLen+4 > maxClientHelloRecord {
					return prefix, prefix, false
				}
				need = 4 + helloLen
				parseRecord = make([]byte, 5+need)
				copy(parseRecord[:5], prefix[:5])
				parseRecord[3] = byte(need >> 8)
				parseRecord[4] = byte(need)
				copy(parseRecord[5:], handshakeHeader[:])
				if headerNeed < n {
					copied += copy(parseRecord[5+copied:], body[headerNeed:n])
				}
			}
		} else {
			copied += copy(parseRecord[5+copied:], body[:n])
		}
		if err != nil {
			return prefix, prefix, false
		}
		if copied > maxClientHelloRecord {
			return prefix, prefix, false
		}
	}
	return parseRecord, prefix, true
}

func readFullIntoPrefix(conn net.Conn, prefix []byte, size int) ([]byte, []byte, int, error) {
	start := len(prefix)
	end := start + size
	if cap(prefix) < end {
		next := make([]byte, end)
		copy(next, prefix)
		prefix = next
	} else {
		prefix = prefix[:end]
	}

	buf := prefix[start:end]
	n, err := io.ReadFull(conn, buf)
	if n < size {
		prefix = prefix[:start+n]
		buf = prefix[start:]
	}
	return prefix, buf, n, err
}
