// Package tlsfptest 导出 dataplane 连接窃读层的测试夹具。
// 与 dataplane/tlsfp 同名但独立：夹具只在测试构建中参与编译，
// 不污染 tlsfp 生产包的依赖图。
package tlsfptest

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
)

// BuildClientHelloRecord 用给定 tls.Config 走一次真实握手，抓取 ClientHello 记录
// （5 字节 record 头 + 载荷）。供需要构造真实 ClientHello 字节的测试使用。
func BuildClientHelloRecord(tb testing.TB, config *tls.Config) []byte {
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
