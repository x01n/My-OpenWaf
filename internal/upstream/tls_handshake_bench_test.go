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

// benchServerCertificate generates a throwaway self-signed certificate for the
// local benchmark listener.
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

// benchTLSEchoServer starts a TLS listener that completes the handshake and
// closes, so benchmarks measure handshake cost only.
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
						// Writing after the handshake flushes the TLS 1.3
						// NewSessionTicket message, which is what makes a later
						// resumption possible at all.
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
	// Reading once lets the client process the server's NewSessionTicket and
	// populate ClientSessionCache; without it TLS 1.3 can never resume.
	var buf [1]byte
	_, _ = conn.Read(buf[:])
	_, _ = conn.Write([]byte{0})
	_ = conn.Close()
	return resumed
}

// BenchmarkUpstreamTLSHandshakeFreshConfig reproduces the current WebSocket
// upstream path: TLSDialWithDialer calls HTTPSClientTLSConfig per connection, so
// every dial gets a brand new tls.Config with no ClientSessionCache and every
// handshake is a full one.
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

// BenchmarkUpstreamTLSHandshakeSharedConfig models the same dials against one
// reused tls.Config carrying a ClientSessionCache, so handshakes after the first
// can resume instead of redoing the asymmetric key exchange.
func BenchmarkUpstreamTLSHandshakeSharedConfig(b *testing.B) {
	addr, stop := benchTLSEchoServer(b)
	defer stop()

	cfg := HTTPSClientTLSConfig("bench.upstream.test", true)
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(32)
	// Prime the cache so the measured loop exercises the resumption path.
	benchDialHandshake(b, addr, cfg)
	benchDialHandshake(b, addr, cfg)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchDialHandshake(b, addr, cfg)
	}
}

// BenchmarkUpstreamTLSHandshakeSharedConfigResumeRate is a guard: it fails the
// premise loudly if resumption is not actually happening, so the paired numbers
// above cannot be misread.
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

// BenchmarkUpstreamTLSHandshakeSharedDialConfig exercises the production path
// after the change: TLSDialWithDialer now resolves a reused config through
// sharedDialTLSConfig, so it is measured the same way as the paired benchmarks
// above rather than being assumed to behave like them.
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

// BenchmarkHTTPSClientTLSConfigAlloc measures just the per-call config
// construction, including the cipher suite slice copy.
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
