package dataplane

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"My-OpenWaf/internal/waf/bot"
)

func TestTLSFingerprintListenerParsesLargeClientHello(t *testing.T) {
	protos := largeALPNProtocolsForTest()
	record := clientHelloRecordForDataplaneTest(t, &tls.Config{
		ServerName: "example.com",
		NextProtos: protos,
	})
	if len(record) <= 4096 {
		t.Fatalf("client hello record length = %d, want > 4096", len(record))
	}

	conn := connWithInitialBytesForTest(t, record)
	defer conn.Close()

	wrapped := newTLSFingerprintConn(conn)
	if _, ok := bot.TLSFingerprintFromConn(wrapped); ok {
		t.Fatal("fingerprint should be empty before the first read")
	}

	got := make([]byte, len(record))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("read wrapped record: %v", err)
	}
	if !bytes.Equal(got, record) {
		t.Fatal("wrapped connection did not replay the complete client hello record")
	}

	fp, ok := bot.TLSFingerprintFromConn(wrapped)
	if !ok {
		t.Fatal("expected parsed TLS fingerprint after the first read")
	}
	if !reflect.DeepEqual(fp.ALPN, protos) {
		t.Fatalf("ALPN = %+v, want %+v", fp.ALPN, protos)
	}
	if fp.SNI != "example.com" {
		t.Fatalf("SNI = %q, want %q", fp.SNI, "example.com")
	}
	if fp.JA3 == "" || fp.JA3Hash == "" || fp.JA4 == "" {
		t.Fatalf("expected JA3, JA3 hash and JA4, got %+v", fp)
	}
}

func TestTLSFingerprintListenerParsesMaxPayloadClientHello(t *testing.T) {
	record := maxPayloadClientHelloRecordForDataplaneTest(t)
	recordLen := int(record[3])<<8 | int(record[4])
	if recordLen != maxClientHelloRecord {
		t.Fatalf("TLS record payload length = %d, want %d", recordLen, maxClientHelloRecord)
	}
	if _, err := bot.ParseTLSClientHello(record); err != nil {
		t.Fatalf("test ClientHello must be parseable: %v", err)
	}

	conn := connWithInitialBytesForTest(t, record)
	defer conn.Close()

	wrapped := newTLSFingerprintConn(conn)
	got := make([]byte, len(record))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("read wrapped record: %v", err)
	}
	if !bytes.Equal(got, record) {
		t.Fatal("wrapped connection did not replay the max payload client hello record")
	}

	fp, ok := bot.TLSFingerprintFromConn(wrapped)
	if !ok {
		t.Fatal("expected parsed TLS fingerprint for max payload ClientHello")
	}
	if fp.JA3 == "" || fp.JA3Hash == "" || fp.JA4 == "" {
		t.Fatalf("expected JA3, JA3 hash and JA4, got %+v", fp)
	}
}

func TestTLSFingerprintListenerParsesFragmentedClientHello(t *testing.T) {
	record := clientHelloRecordForDataplaneTest(t, &tls.Config{
		ServerName: "fragmented.example",
		NextProtos: []string{"h2", "http/1.1"},
	})
	want, err := bot.ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("test ClientHello must be parseable: %v", err)
	}
	fragmented := fragmentTLSClientHelloRecordForDataplaneTest(t, record, 2)
	if bytes.Equal(fragmented, record) {
		t.Fatal("fragmented record should differ from the original record")
	}

	conn := connWithInitialBytesForTest(t, fragmented)
	defer conn.Close()

	wrapped := newTLSFingerprintConn(conn)
	got := make([]byte, len(fragmented))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("read wrapped fragmented record: %v", err)
	}
	if !bytes.Equal(got, fragmented) {
		t.Fatal("wrapped connection did not replay the complete fragmented client hello")
	}

	fp, ok := bot.TLSFingerprintFromConn(wrapped)
	if !ok {
		t.Fatal("expected parsed TLS fingerprint for fragmented ClientHello")
	}
	if fp.JA3 != want.JA3 || fp.JA3Hash != want.JA3Hash || fp.JA4 != want.JA4 {
		t.Fatalf("fingerprint = %+v, want JA3=%q JA3Hash=%q JA4=%q", fp, want.JA3, want.JA3Hash, want.JA4)
	}
	if fp.SNI != "fragmented.example" {
		t.Fatalf("SNI = %q, want %q", fp.SNI, "fragmented.example")
	}
	if !reflect.DeepEqual(fp.ALPN, []string{"h2", "http/1.1"}) {
		t.Fatalf("ALPN = %+v, want [h2 http/1.1]", fp.ALPN)
	}
}

func TestTLSFingerprintListenerParsesClientHelloHeaderSplitAcrossRecords(t *testing.T) {
	record := clientHelloRecordForDataplaneTest(t, &tls.Config{
		ServerName: "split-header.example",
		NextProtos: []string{"h2", "http/1.1"},
	})
	want, err := bot.ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("test ClientHello must be parseable: %v", err)
	}

	for _, firstPayloadLen := range []int{1, 2, 3} {
		firstPayloadLen := firstPayloadLen
		t.Run(fmt.Sprintf("first_payload_%d", firstPayloadLen), func(t *testing.T) {
			fragmented := fragmentTLSClientHelloRecordForDataplaneTest(t, record, firstPayloadLen)
			conn := connWithInitialBytesForTest(t, fragmented)
			defer conn.Close()

			wrapped := newTLSFingerprintConn(conn)
			got := make([]byte, len(fragmented))
			if _, err := io.ReadFull(wrapped, got); err != nil {
				t.Fatalf("read wrapped split ClientHello header: %v", err)
			}
			if !bytes.Equal(got, fragmented) {
				t.Fatal("wrapped connection did not replay the split ClientHello header")
			}

			fp, ok := bot.TLSFingerprintFromConn(wrapped)
			if !ok {
				t.Fatal("expected parsed TLS fingerprint for split ClientHello header")
			}
			if fp.JA3 != want.JA3 || fp.JA3Hash != want.JA3Hash || fp.JA4 != want.JA4 {
				t.Fatalf("fingerprint = %+v, want JA3=%q JA3Hash=%q JA4=%q", fp, want.JA3, want.JA3Hash, want.JA4)
			}
			if fp.SNI != "split-header.example" {
				t.Fatalf("SNI = %q, want %q", fp.SNI, "split-header.example")
			}
			if !reflect.DeepEqual(fp.ALPN, []string{"h2", "http/1.1"}) {
				t.Fatalf("ALPN = %+v, want [h2 http/1.1]", fp.ALPN)
			}
		})
	}
}

func TestTLSFingerprintListenerParsesClientHelloWithTrailingHandshakeBytes(t *testing.T) {
	record := clientHelloRecordForDataplaneTest(t, &tls.Config{
		ServerName: "trailing.example",
		NextProtos: []string{"http/1.1"},
	})
	want, err := bot.ParseTLSClientHello(record)
	if err != nil {
		t.Fatalf("test ClientHello must be parseable: %v", err)
	}

	recordLen := int(record[3])<<8 | int(record[4])
	trailing := []byte{0x00, 0x00, 0x00, 0x00}
	combined := make([]byte, 0, len(record)+len(trailing))
	combined = append(combined, record...)
	combined[3] = byte((recordLen + len(trailing)) >> 8)
	combined[4] = byte(recordLen + len(trailing))
	combined = append(combined, trailing...)

	conn := connWithInitialBytesForTest(t, combined)
	defer conn.Close()

	wrapped := newTLSFingerprintConn(conn)
	got := make([]byte, len(combined))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("read wrapped record with trailing handshake bytes: %v", err)
	}
	if !bytes.Equal(got, combined) {
		t.Fatal("wrapped connection did not replay trailing handshake bytes")
	}

	fp, ok := bot.TLSFingerprintFromConn(wrapped)
	if !ok {
		t.Fatal("expected parsed TLS fingerprint for ClientHello with trailing handshake bytes")
	}
	if fp.JA3 != want.JA3 || fp.JA3Hash != want.JA3Hash || fp.JA4 != want.JA4 {
		t.Fatalf("fingerprint = %+v, want JA3=%q JA3Hash=%q JA4=%q", fp, want.JA3, want.JA3Hash, want.JA4)
	}
	if fp.SNI != "trailing.example" {
		t.Fatalf("SNI = %q, want %q", fp.SNI, "trailing.example")
	}
	if !reflect.DeepEqual(fp.ALPN, []string{"http/1.1"}) {
		t.Fatalf("ALPN = %+v, want [http/1.1]", fp.ALPN)
	}
}

func TestTLSFingerprintListenerReplaysNonTLSPrefix(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	conn := connWithInitialBytesForTest(t, payload)
	defer conn.Close()

	wrapped := newTLSFingerprintConn(conn)
	if _, ok := bot.TLSFingerprintFromConn(wrapped); ok {
		t.Fatal("non-TLS payload should not produce a TLS fingerprint before read")
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(wrapped, got); err != nil {
		t.Fatalf("read wrapped payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("wrapped payload = %q, want %q", got, payload)
	}
	if _, ok := bot.TLSFingerprintFromConn(wrapped); ok {
		t.Fatal("non-TLS payload should not produce a TLS fingerprint after read")
	}
}

func TestTLSFingerprintListenerAcceptDoesNotReadClientHello(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	ln := NewTLSFingerprintListener(&singleConnListener{conn: server})
	defer ln.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()

	select {
	case res := <-accepted:
		if res.err != nil {
			t.Fatalf("Accept returned error: %v", res.err)
		}
		if res.conn == nil {
			t.Fatal("Accept returned nil connection")
		}
		defer res.conn.Close()
		if _, ok := bot.TLSFingerprintFromConn(res.conn); ok {
			t.Fatal("fingerprint should be empty before the first read")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Accept blocked waiting for ClientHello bytes")
	}
}

func BenchmarkTLSFingerprintConnSmallClientHello(b *testing.B) {
	record := clientHelloRecordForDataplaneTest(b, &tls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h2", "http/1.1"},
	})
	benchmarkTLSFingerprintConn(b, record)
}

func BenchmarkTLSFingerprintConnLargeClientHello(b *testing.B) {
	record := clientHelloRecordForDataplaneTest(b, &tls.Config{
		ServerName: "example.com",
		NextProtos: largeALPNProtocolsForTest(),
	})
	if len(record) <= 4096 {
		b.Fatalf("client hello record length = %d, want > 4096", len(record))
	}
	benchmarkTLSFingerprintConn(b, record)
}

func BenchmarkTLSFingerprintConnFragmentedClientHello(b *testing.B) {
	record := clientHelloRecordForDataplaneTest(b, &tls.Config{
		ServerName: "fragmented.example",
		NextProtos: []string{"h2", "http/1.1"},
	})
	fragmented := fragmentTLSClientHelloRecordForDataplaneTest(b, record, 2)
	benchmarkTLSFingerprintConn(b, fragmented)
}

func benchmarkTLSFingerprintConn(b *testing.B, record []byte) {
	b.Helper()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		conn := &bytesConnForBenchmark{Reader: bytes.NewReader(record)}
		wrapped := newTLSFingerprintConn(conn)
		buf := make([]byte, len(record))
		if _, err := io.ReadFull(wrapped, buf); err != nil {
			b.Fatalf("read wrapped record: %v", err)
		}
		fp, ok := bot.TLSFingerprintFromConn(wrapped)
		if !ok || fp.JA3 == "" || fp.JA3Hash == "" || fp.JA4 == "" {
			b.Fatalf("unexpected fingerprint: %+v, ok=%v", fp, ok)
		}
	}
}

func largeALPNProtocolsForTest() []string {
	protos := make([]string, 0, 48)
	for i := 0; i < 48; i++ {
		protos = append(protos, fmt.Sprintf("proto-%02d-%s", i, strings.Repeat("x", 96)))
	}
	return protos
}

func clientHelloRecordForDataplaneTest(tb testing.TB, config *tls.Config) []byte {
	tb.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	tlsConfig := &tls.Config{}
	if config != nil {
		tlsConfig = config.Clone()
	}
	tlsConfig.InsecureSkipVerify = true
	go func() {
		defer client.Close()
		tlsClient := tls.Client(client, tlsConfig)
		done <- tlsClient.Handshake()
	}()

	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		server.Close()
		tb.Fatalf("read TLS record header: %v", err)
	}
	if header[0] != 0x16 {
		server.Close()
		tb.Fatalf("record content type = %d, want 22", header[0])
	}
	recordLen := int(header[3])<<8 | int(header[4])
	body := make([]byte, recordLen)
	if _, err := io.ReadFull(server, body); err != nil {
		server.Close()
		tb.Fatalf("read TLS record body: %v", err)
	}
	server.Close()
	<-done

	record := make([]byte, 0, len(header)+len(body))
	record = append(record, header...)
	record = append(record, body...)
	return record
}

func maxPayloadClientHelloRecordForDataplaneTest(tb testing.TB) []byte {
	tb.Helper()
	const paddingExtensionID = 21

	payloadLen := maxClientHelloRecord
	helloLen := payloadLen - 4
	hello := make([]byte, 43)
	hello[0] = 0x03
	hello[1] = 0x03
	hello[34] = 0
	hello[35] = 0
	hello[36] = 2
	hello[37] = 0x13
	hello[38] = 0x01
	hello[39] = 1
	hello[40] = 0

	extensionsLen := helloLen - len(hello)
	if extensionsLen < 4 {
		tb.Fatalf("extensions length = %d, want at least 4", extensionsLen)
	}
	hello[41] = byte(extensionsLen >> 8)
	hello[42] = byte(extensionsLen)

	paddingLen := extensionsLen - 4
	hello = append(hello,
		byte(paddingExtensionID>>8), byte(paddingExtensionID),
		byte(paddingLen>>8), byte(paddingLen),
	)
	hello = append(hello, make([]byte, paddingLen)...)
	if len(hello) != helloLen {
		tb.Fatalf("ClientHello body length = %d, want %d", len(hello), helloLen)
	}

	handshake := make([]byte, 4+len(hello))
	handshake[0] = 0x01
	handshake[1] = byte(len(hello) >> 16)
	handshake[2] = byte(len(hello) >> 8)
	handshake[3] = byte(len(hello))
	copy(handshake[4:], hello)
	if len(handshake) != payloadLen {
		tb.Fatalf("TLS record payload length = %d, want %d", len(handshake), payloadLen)
	}

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	record[3] = byte(len(handshake) >> 8)
	record[4] = byte(len(handshake))
	copy(record[5:], handshake)
	return record
}

func fragmentTLSClientHelloRecordForDataplaneTest(tb testing.TB, record []byte, firstPayloadLen int) []byte {
	tb.Helper()
	if len(record) < 9 {
		tb.Fatalf("tls record is too short: %d", len(record))
	}
	if record[0] != 0x16 {
		tb.Fatalf("record content type = %d, want 22", record[0])
	}
	recordLen := int(record[3])<<8 | int(record[4])
	if len(record) < 5+recordLen {
		tb.Fatalf("tls record length %d exceeds record size %d", recordLen, len(record))
	}
	if firstPayloadLen <= 0 || firstPayloadLen >= recordLen {
		tb.Fatalf("first payload length = %d, want 1..%d", firstPayloadLen, recordLen-1)
	}

	first := record[5 : 5+firstPayloadLen]
	second := record[5+firstPayloadLen : 5+recordLen]
	fragmented := make([]byte, 0, len(record)+5)
	fragmented = append(fragmented, record[0], record[1], record[2], byte(len(first)>>8), byte(len(first)))
	fragmented = append(fragmented, first...)
	fragmented = append(fragmented, record[0], record[1], record[2], byte(len(second)>>8), byte(len(second)))
	fragmented = append(fragmented, second...)
	return fragmented
}

func connWithInitialBytesForTest(tb testing.TB, payload []byte) net.Conn {
	tb.Helper()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		client.Close()
		done <- err
	}()
	tb.Cleanup(func() {
		<-done
	})
	return server
}

type bytesConnForBenchmark struct {
	*bytes.Reader
}

func (c *bytesConnForBenchmark) Write(p []byte) (int, error) { return len(p), nil }
func (c *bytesConnForBenchmark) Close() error                { return nil }
func (c *bytesConnForBenchmark) LocalAddr() net.Addr         { return nil }
func (c *bytesConnForBenchmark) RemoteAddr() net.Addr        { return nil }
func (c *bytesConnForBenchmark) SetDeadline(time.Time) error { return nil }
func (c *bytesConnForBenchmark) SetReadDeadline(time.Time) error {
	return nil
}
func (c *bytesConnForBenchmark) SetWriteDeadline(time.Time) error {
	return nil
}
