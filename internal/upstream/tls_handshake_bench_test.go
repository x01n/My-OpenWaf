package upstream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

/**
 * benchServerCertificate 为本地基准监听器生成一张一次性自签名证书。
 *
 * @param b 基准测试对象，用于标记 helper 与报告失败。
 * @return 供本地 TLS 监听器使用的一次性自签名证书。
 */
func benchServerCertificate(b *testing.B) tls.Certificate {
	b.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bench.upstream.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"bench.upstream.test"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		b.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		b.Fatalf("marshal key: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		b.Fatalf("load key pair: %v", err)
	}
	return cert
}

/**
 * benchTLSEchoServer 启动一个完成握手后即关闭的 TLS 监听器。
 *
 * 这样基准测得的只有握手开销，不含应用层往返。
 *
 * @param b 基准测试对象，用于标记 helper 与报告失败。
 * @return addr 监听地址；stop 关闭监听并等待所有连接 goroutine 退出。
 */
func benchTLSEchoServer(b *testing.B) (addr string, stop func()) {
	b.Helper()
	cert := benchServerCertificate(b)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		b.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				if tc, ok := c.(*tls.Conn); ok {
					if err := tc.Handshake(); err == nil {
						// 握手后写入一次会冲刷出 TLS 1.3 的
						// NewSessionTicket 消息，这正是后续
						// 能够恢复会话的前提。
						_, _ = c.Write([]byte{0})
						var buf [1]byte
						_, _ = c.Read(buf[:])
					}
				}
				_ = c.Close()
			}(conn)
		}
	}()

	return ln.Addr().String(), func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	}
}

func benchDialHandshake(b *testing.B, addr string, cfg *tls.Config) bool {
	b.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		b.Fatalf("handshake: %v", err)
	}
	resumed := conn.ConnectionState().DidResume
	// 读一次让客户端处理服务端的 NewSessionTicket 并填充
	// ClientSessionCache；不读则 TLS 1.3 永远无法恢复会话。
	var buf [1]byte
	_, _ = conn.Read(buf[:])
	_, _ = conn.Write([]byte{0})
	_ = conn.Close()
	return resumed
}

/**
 * BenchmarkUpstreamTLSHandshakeFreshConfig 复现当前的 WebSocket 上游路径。
 *
 * TLSDialWithDialer 对每条连接都调用一次 HTTPSClientTLSConfig，因此每次拨号
 * 都拿到全新的 tls.Config、没有 ClientSessionCache，每一次握手都是完整握手。
 */
func BenchmarkUpstreamTLSHandshakeFreshConfig(b *testing.B) {
	addr, stop := benchTLSEchoServer(b)
	defer stop()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg := HTTPSClientTLSConfig("bench.upstream.test", true)
		benchDialHandshake(b, addr, cfg)
	}
}

/**
 * BenchmarkUpstreamTLSHandshakeSharedConfig 以一份复用的 tls.Config 模拟同样的拨号。
 *
 * 该配置带 ClientSessionCache，因此除首次以外的握手都能恢复会话，
 * 而不必重做非对称密钥交换。
 */
func BenchmarkUpstreamTLSHandshakeSharedConfig(b *testing.B) {
	addr, stop := benchTLSEchoServer(b)
	defer stop()

	cfg := HTTPSClientTLSConfig("bench.upstream.test", true)
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(32)
	// 先预热缓存，让计时循环走的是会话恢复路径。
	benchDialHandshake(b, addr, cfg)
	benchDialHandshake(b, addr, cfg)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchDialHandshake(b, addr, cfg)
	}
}

/**
 * BenchmarkUpstreamTLSHandshakeSharedConfigResumeRate 是一道守卫。
 *
 * 若会话恢复实际并未发生，它会显式失败，避免上面那对基准的读数被误读。
 */
func BenchmarkUpstreamTLSHandshakeSharedConfigResumeRate(b *testing.B) {
	addr, stop := benchTLSEchoServer(b)
	defer stop()

	cfg := HTTPSClientTLSConfig("bench.upstream.test", true)
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(32)
	benchDialHandshake(b, addr, cfg)
	benchDialHandshake(b, addr, cfg)

	resumed := 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if benchDialHandshake(b, addr, cfg) {
			resumed++
		}
	}
	b.StopTimer()
	if b.N > 10 && resumed == 0 {
		b.Fatalf("no handshake resumed across %d dials; resumption premise is wrong", b.N)
	}
	b.ReportMetric(float64(resumed)/float64(b.N)*100, "%resumed")
}

/**
 * BenchmarkUpstreamTLSHandshakeSharedDialConfig 实测改动后的生产路径。
 *
 * TLSDialWithDialer 现在经 sharedDialTLSConfig 取到复用配置，因此这里按上面
 * 那对基准同样的方式实测，而不是假设它的行为与之一致。
 */
func BenchmarkUpstreamTLSHandshakeSharedDialConfig(b *testing.B) {
	addr, stop := benchTLSEchoServer(b)
	defer stop()

	cfg := sharedDialTLSConfig("bench.upstream.test", true)
	benchDialHandshake(b, addr, cfg)
	benchDialHandshake(b, addr, cfg)

	resumed := 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if benchDialHandshake(b, addr, sharedDialTLSConfig("bench.upstream.test", true)) {
			resumed++
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(resumed)/float64(b.N)*100, "%resumed")
}

/**
 * BenchmarkHTTPSClientTLSConfigAlloc 只测量每次调用的配置构造开销。
 *
 * 其中包含 cipher suite 切片的复制。
 */
func BenchmarkHTTPSClientTLSConfigAlloc(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg := HTTPSClientTLSConfig("bench.upstream.test", false)
		if cfg == nil {
			b.Fatal("nil config")
		}
	}
}
