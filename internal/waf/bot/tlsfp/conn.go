package tlsfp

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
	return f.JA3 != "" || f.JA3Hash != "" || f.JA4 != "" || f.TLSVersion != "" || f.SNI != "" ||
		len(f.ALPN) > 0 || len(f.ALPNRaw) > 0
}

// NegotiatedALPN 返回握手实际协商出的单个协议；ALPN 为空时回退到声明列表首项。
func (f TLSClientFingerprint) NegotiatedALPN() string {
	if len(f.ALPN) > 0 {
		return f.ALPN[0]
	}
	if len(f.ALPNRaw) > 0 {
		return f.ALPNRaw[0]
	}
	return ""
}

// DeclaredALPN 返回 ClientHello 声明的 ALPN 列表（原始顺序）。
// ALPNRaw 尚未填充时回退到 ALPN，保证调用方总能看到声明列表。
func (f TLSClientFingerprint) DeclaredALPN() []string {
	if len(f.ALPNRaw) > 0 {
		return f.ALPNRaw
	}
	return f.ALPN
}

// SetNegotiatedALPN 记录握手协商出的单个协议，只写 ALPN，不触碰 ALPNRaw。
//
// 当 ALPNRaw 为空（该连接未走 ClientHello 前缀窃读，例如
// MY_OPENWAF_H2WS_PEEKER_OFF=1 的豁免路径）时，先用覆写前的 ALPN 回填
// ALPNRaw，使声明列表始终有可读值。
func (f *TLSClientFingerprint) SetNegotiatedALPN(alpn string) {
	if len(f.ALPNRaw) == 0 && len(f.ALPN) > 0 {
		f.ALPNRaw = append([]string(nil), f.ALPN...)
	}
	f.ALPN = nil
	if alpn != "" {
		f.ALPN = []string{alpn}
	}
}
