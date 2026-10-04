package app

import (
	"context"
	"crypto/tls"
	"log/slog"
	"strings"
	"testing"
	"time"

	acmepkg "My-OpenWaf/internal/acme"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

// benchListenerTLSFixture 构建握手路径基准测试所用的单监听 TLS 配置。
// 配置本身每个基准只构建一次，这样被测量的就只有每次握手的回调开销。
func benchListenerTLSFixture(b *testing.B) *tls.Config {
	b.Helper()
	certPEM, keyPEM, err := acmepkg.GenerateSelfSignedPEM("bench.example.test", []string{"bench.example.test"}, nil, time.Hour)
	if err != nil {
		b.Fatalf("generate certificate: %v", err)
	}
	rt := snapshotpkg.SiteRuntime{
		Bind: "127.0.0.1:8443",
		Site: store.Site{
			ID:         1,
			Host:       "bench.example.test",
			Bind:       "127.0.0.1:8443",
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		Certificate: &store.Certificate{
			Name:    "bench",
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		},
		NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:     snapshotpkg.DefaultTLSDefaults(),
	}
	sn := &snapshotpkg.Snapshot{
		Sites: map[string]*snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey("127.0.0.1:8443", "bench.example.test"): &rt,
		},
		SiteTLSCertBySNI: map[string]tls.Certificate{},
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		b.Fatalf("parse key pair: %v", err)
	}
	sn.SiteTLSCertBySNI["sni:127.0.0.1:8443\x00bench.example.test"] = cert

	cfg := buildListenerTLS(rt, sn)
	if cfg == nil || cfg.GetCertificate == nil || cfg.GetConfigForClient == nil {
		b.Fatalf("expected TLS config with handshake callbacks, got %#v", cfg)
	}
	return cfg
}

// benchClientHello 模拟现代浏览器的 ClientHello：支持 TLS 1.3、
// ALPN 为 h2/http-1.1、带 SNI。
func benchClientHello(serverName string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        serverName,
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

func BenchmarkListenerGetCertificateSNIMatch(b *testing.B) {
	cfg := benchListenerTLSFixture(b)
	hello := benchClientHello("bench.example.test")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cert, err := cfg.GetCertificate(hello)
		if err != nil || cert == nil {
			b.Fatalf("GetCertificate() = %v, %v", cert, err)
		}
	}
}

func BenchmarkListenerGetCertificateEmptySNI(b *testing.B) {
	cfg := benchListenerTLSFixture(b)
	hello := benchClientHello("")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cert, err := cfg.GetCertificate(hello)
		if err != nil || cert == nil {
			b.Fatalf("GetCertificate() = %v, %v", cert, err)
		}
	}
}

func BenchmarkListenerGetCertificateUnknownSNI(b *testing.B) {
	cfg := benchListenerTLSFixture(b)
	hello := benchClientHello("scanner.unknown.test")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cert, err := cfg.GetCertificate(hello)
		if err != nil || cert == nil {
			b.Fatalf("GetCertificate() = %v, %v", cert, err)
		}
	}
}

func BenchmarkListenerGetConfigForClient(b *testing.B) {
	cfg := benchListenerTLSFixture(b)
	hello := benchClientHello("bench.example.test")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cfg.GetConfigForClient(hello); err != nil {
			b.Fatalf("GetConfigForClient() error: %v", err)
		}
	}
}

// emitUnguardedHandshakeDebugLog 复现优化前 buildListenerTLS 的 GetCertificate
// 回调里那次日志调用：无论当前日志级别如何，每次握手都会构造 slog 属性。
// 下面的配对基准在同一次运行里隔离这一处差异，避免分次运行被机器负载漂移污染。
func emitUnguardedHandshakeDebugLog(bind string, hello *tls.ClientHelloInfo) {
	sni := strings.ToLower(strings.TrimSpace(hello.ServerName))
	clientTLSMin := uint16(0)
	if len(hello.SupportedVersions) > 0 {
		clientTLSMin = hello.SupportedVersions[0]
	}
	slog.Debug("TLS ClientHello received",
		slog.String("bind", bind),
		slog.String("sni", sni),
		slog.Any("client_alpn", hello.SupportedProtos),
		slog.Int("client_tls_first", int(clientTLSMin)),
	)
}

func BenchmarkListenerGetCertificateSNIMatchUnguardedDebugLog(b *testing.B) {
	cfg := benchListenerTLSFixture(b)
	hello := benchClientHello("bench.example.test")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		emitUnguardedHandshakeDebugLog("127.0.0.1:8443", hello)
		cert, err := cfg.GetCertificate(hello)
		if err != nil || cert == nil {
			b.Fatalf("GetCertificate() = %v, %v", cert, err)
		}
	}
}

// benchUnknownSNISnapshot 构建陌生 SNI 路径要走的快照形态：
// 该 bind 上只有一个已知站点，因此查找会依次错过精确、通配符与 catch-all
// 三类键，最后返回未命中。
func benchUnknownSNISnapshot() *snapshotpkg.Snapshot {
	rt := snapshotpkg.SiteRuntime{
		Bind: "127.0.0.1:8443",
		Site: store.Site{ID: 1, Host: "bench.example.test", Bind: "127.0.0.1:8443", TLSEnabled: true},
	}
	return &snapshotpkg.Snapshot{
		Sites: map[string]*snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey("127.0.0.1:8443", "bench.example.test"): &rt,
		},
	}
}

// 下列两个基准对比 MatchSite 按值返回 SiteRuntime（1472 字节）
// 与握手回调现用的指针版本之间的开销差异。
// 放在同一次运行里配对测量，避免负载漂移影响对比结论。
func BenchmarkUnknownSNIMatchSiteByValue(b *testing.B) {
	sn := benchUnknownSNISnapshot()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, found := sn.MatchSite("127.0.0.1:8443", "scanner.unknown.test"); found {
			b.Fatal("unexpected site match")
		}
	}
}

func BenchmarkUnknownSNIMatchSitePtr(b *testing.B) {
	sn := benchUnknownSNISnapshot()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, found := sn.MatchSitePtr("127.0.0.1:8443", "scanner.unknown.test"); found {
			b.Fatal("unexpected site match")
		}
	}
}

// BenchmarkHandshakeDebugLogGuardOnly 只测那层守卫本身，
// 便于报告里说明保留的日志级别检查每次握手要花多少。
func BenchmarkHandshakeDebugLogGuardOnly(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			b.Fatal("debug level unexpectedly enabled in benchmark")
		}
	}
}
