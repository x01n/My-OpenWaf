package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// benchListener 启动一个回环 TCP 监听，返回 listen 地址与关闭函数。
//
// 不用 net.Pipe：它是无缓冲同步管道，TLS1.3 服务端在握手结束后写
// NewSessionTicket 会先阻塞，双方互等导致基准死锁。
func benchListener(tb testing.TB, serverCfg *tls.Config) (string, func()) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				sc := tls.Server(c, serverCfg)
				_ = sc.Handshake()
				buf := make([]byte, 1)
				if _, err := io.ReadFull(sc, buf); err == nil {
					_, _ = sc.Write([]byte("a"))
				}
				_ = sc.Close()
			}(raw)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

// driveHandshake 在真实回环连接上完成一次握手并消费服务端 NewSessionTicket，
// 使客户端会话缓存真正写入（否则 TLS1.3 的票据不会被读取）。
func driveHandshake(tb testing.TB, addr string, clientCfg *tls.Config) {
	tb.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	client := tls.Client(raw, clientCfg)
	defer client.Close()
	if err := client.Handshake(); err != nil {
		tb.Fatalf("client handshake: %v", err)
	}
	if _, err := client.Write([]byte("q")); err != nil {
		tb.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(client, buf); err != nil {
		tb.Fatalf("client read: %v", err)
	}
}

// benchCert 依据私钥类型签发一张回环测试证书。
func benchCert(tb testing.TB, key any) tls.Certificate {
	tb.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bench.example.test"},
		DNSNames:     []string{"bench.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, publicKeyOf(key), key)
	if err != nil {
		tb.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func publicKeyOf(key any) any {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	}
	return nil
}

func benchServerConfig(tb testing.TB, cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
}

func benchClientConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "bench.example.test",
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}
}

// 下列两组基准量化「证书私钥类型」对握手成本的影响：
// RSA-2048 每次完整握手都要做一次私钥签名，远贵于 ECDSA P-256。
func BenchmarkTLSHandshakeFullECDSA(b *testing.B) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}
	serverCfg := benchServerConfig(b, benchCert(b, key))
	addr, stop := benchListener(b, serverCfg)
	defer stop()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		driveHandshake(b, addr, benchClientConfig())
	}
}

func BenchmarkTLSHandshakeFullRSA(b *testing.B) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}
	serverCfg := benchServerConfig(b, benchCert(b, key))
	addr, stop := benchListener(b, serverCfg)
	defer stop()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		driveHandshake(b, addr, benchClientConfig())
	}
}

// 会话复用基准：客户端复用同一 ClientSessionCache，完整握手一次之后
// 后续都应命中 TLS1.3 PSK，跳过证书签名与密钥交换。
func BenchmarkTLSHandshakeResumedECDSA(b *testing.B) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}
	serverCfg := benchServerConfig(b, benchCert(b, key))
	addr, stop := benchListener(b, serverCfg)
	defer stop()
	clientCfg := benchClientConfig()
	clientCfg.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	driveHandshake(b, addr, clientCfg)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		driveHandshake(b, addr, clientCfg)
	}
}
