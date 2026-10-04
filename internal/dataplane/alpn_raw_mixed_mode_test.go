package dataplane

import (
	"My-OpenWaf/internal/waf/bot/tlsfp"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"reflect"
	"testing"
)

/**
 * TestPeekConnALPNRawSurvivesNegotiatedH1 是 TCP/TLS 监听路径上混合模式 ALPN
 * 契约的端到端守门测试：ClientHello 声明 "h2,http/1.1"，握手随后协商出
 * http/1.1，而 ALPNRaw 之后仍必须报告 h2。
 */
func TestPeekConnALPNRawSurvivesNegotiatedH1(t *testing.T) {
	record := clientHelloRecordForDataplaneTest(t, &tls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h2", "http/1.1"},
	})

	conn := &bytesConnForBenchmark{}
	conn.Reset(record)
	wrapped := newTLSFingerprintConn(conn)

	buf := make([]byte, len(record))
	if _, err := io.ReadFull(wrapped, buf); err != nil {
		t.Fatalf("read wrapped record: %v", err)
	}
	if !bytes.Equal(buf, record) {
		t.Fatal("prefix read altered the payload")
	}

	fp, ok := tlsfp.TLSFingerprintFromConn(wrapped)
	if !ok {
		t.Fatal("fingerprint missing after first read")
	}
	if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(fp.ALPNRaw, want) {
		t.Fatalf("ALPNRaw after parse = %+v, want %+v", fp.ALPNRaw, want)
	}

	// 服务端协商出 http/1.1（例如最高 TLS 版本低于 1.2 会剥掉 h2）。
	setTLSHandshakeInfoOnConn(wrapped, "TLS13", "example.com", "http/1.1")

	after, ok := tlsfp.TLSFingerprintFromConn(wrapped)
	if !ok {
		t.Fatal("fingerprint missing after handshake info")
	}
	if want := []string{"http/1.1"}; !reflect.DeepEqual(after.ALPN, want) {
		t.Fatalf("ALPN after negotiation = %+v, want %+v", after.ALPN, want)
	}
	if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(after.ALPNRaw, want) {
		t.Fatalf("ALPNRaw was overwritten by negotiation: %+v, want %+v", after.ALPNRaw, want)
	}
	if got := after.NegotiatedALPN(); got != "http/1.1" {
		t.Fatalf("NegotiatedALPN() = %q, want http/1.1", got)
	}
	if got := after.DeclaredALPN(); !reflect.DeepEqual(got, []string{"h2", "http/1.1"}) {
		t.Fatalf("DeclaredALPN() = %+v, want [h2 http/1.1]", got)
	}
}

/**
 * TestFixURIConnALPNRawSurvivesNegotiation 覆盖那个永远看不到 ClientHello 的
 * 豁免包装器：SetTLSHandshakeInfo 仍不得破坏已存在的声明列表。
 */
func TestFixURIConnALPNRawSurvivesNegotiation(t *testing.T) {
	inner := &bytesConnForBenchmark{}
	conn := NewFixURIConn(inner).(*FixURIConn)
	conn.fingerprint = tlsfp.TLSClientFingerprint{
		TLSVersion: "TLS12",
		SNI:        "example.com",
		ALPN:       []string{"h2", "http/1.1"},
		ALPNRaw:    []string{"h2", "http/1.1"},
	}

	setTLSHandshakeInfoOnConn(conn, "TLS13", "example.com", "http/1.1")

	fp, ok := tlsfp.TLSFingerprintFromConn(conn)
	if !ok {
		t.Fatal("fingerprint missing")
	}
	if got := fp.ALPN; !reflect.DeepEqual(got, []string{"http/1.1"}) {
		t.Fatalf("ALPN = %+v, want [http/1.1]", got)
	}
	if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(fp.ALPNRaw, want) {
		t.Fatalf("ALPNRaw = %+v, want %+v", fp.ALPNRaw, want)
	}
	if fp.TLSVersion != "TLS13" || fp.SNI != "example.com" {
		t.Fatalf("version/SNI not updated: %+v", fp)
	}
}

/**
 * TestFixURIConnALPNRawBackfilledWhenAbsent 覆盖这样的顺序：在任何 ClientHello
 * 解析之前，只有协商值已知；此时覆写必须把它保留进 ALPNRaw，而不是丢弃。
 */
func TestFixURIConnALPNRawBackfilledWhenAbsent(t *testing.T) {
	inner := &bytesConnForBenchmark{}
	conn := NewFixURIConn(inner).(*FixURIConn)
	conn.fingerprint = tlsfp.TLSClientFingerprint{TLSVersion: "TLS12", ALPN: []string{"h2"}}

	setTLSHandshakeInfoOnConn(conn, "", "", "h2")

	fp, _ := tlsfp.TLSFingerprintFromConn(conn)
	if want := []string{"h2"}; !reflect.DeepEqual(fp.ALPNRaw, want) {
		t.Fatalf("ALPNRaw = %+v, want %+v", fp.ALPNRaw, want)
	}
}

/**
 * TestContextWithTLSHandshakeInfoKeepsALPNRaw 覆盖 handler 侧的覆写点：
 * 当握手报告了不同的协商协议时，上下文携带的指纹必须保留原声明列表。
 */
func TestContextWithTLSHandshakeInfoKeepsALPNRaw(t *testing.T) {
	base := tlsfp.TLSClientFingerprint{
		JA3Hash: "a1f6c4ad2b63a0149a2e61e4bcc30c8c",
		JA4:     "t13d1312h2_f57a46bbacb6_f50d94e863eb",
		ALPN:    []string{"h2", "http/1.1"},
		ALPNRaw: []string{"h2", "http/1.1"},
	}
	ctx := ContextWithTLSFingerprint(context.Background(), base)

	ctx = ContextWithTLSHandshakeInfo(ctx, "TLS13", "example.com", "http/1.1")

	fp, ok := tlsFingerprintFromContext(ctx)
	if !ok {
		t.Fatal("fingerprint missing from context")
	}
	if got := fp.ALPN; !reflect.DeepEqual(got, []string{"http/1.1"}) {
		t.Fatalf("ALPN = %+v, want [http/1.1]", got)
	}
	if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(fp.ALPNRaw, want) {
		t.Fatalf("ALPNRaw = %+v, want %+v", fp.ALPNRaw, want)
	}
	if fp.TLSVersion != "TLS13" || fp.SNI != "example.com" {
		t.Fatalf("version/SNI not applied: %+v", fp)
	}
}

// fakeBytesConnForALPNTest 让辅助声明保持可读。
var _ net.Conn = (*bytesConnForBenchmark)(nil)
