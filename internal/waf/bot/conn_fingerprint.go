package bot

import "net"

type FingerprintCarrier interface {
	TLSFingerprint() (TLSClientFingerprint, bool)
}

type FingerprintConn struct {
	net.Conn
	carrier FingerprintCarrier
}

func (c *FingerprintConn) NetConn() net.Conn {
	return c.Conn
}

func WrapFingerprintConn(conn net.Conn, fp TLSClientFingerprint) net.Conn {
	if carrier, ok := conn.(FingerprintCarrier); ok {
		return &FingerprintConn{Conn: conn, carrier: carrier}
	}
	if !fp.HasValue() {
		return conn
	}
	return &FingerprintConn{Conn: conn, carrier: staticFingerprint{fingerprint: fp}}
}

type staticFingerprint struct {
	fingerprint TLSClientFingerprint
}

func (s staticFingerprint) TLSFingerprint() (TLSClientFingerprint, bool) {
	return s.fingerprint, s.fingerprint.HasValue()
}

func (c *FingerprintConn) TLSFingerprint() (TLSClientFingerprint, bool) {
	return c.carrier.TLSFingerprint()
}

func TLSFingerprintFromConn(conn net.Conn) (TLSClientFingerprint, bool) {
	for conn != nil {
		if carrier, ok := conn.(FingerprintCarrier); ok {
			return carrier.TLSFingerprint()
		}
		if unwrapper, ok := conn.(interface{ NetConn() net.Conn }); ok {
			conn = unwrapper.NetConn()
			continue
		}
		break
	}
	return TLSClientFingerprint{}, false
}

func (f TLSClientFingerprint) HasValue() bool {
	return f.JA3 != "" || f.JA3Hash != "" || f.JA4 != "" || f.TLSVersion != "" || f.SNI != "" || len(f.ALPN) > 0
}
