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

// benchListenerTLSFixture builds the per-listener TLS config used by the
// handshake-path benchmarks. The config itself is built once per benchmark so
// that only the per-handshake callbacks are measured.
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

// benchClientHello mirrors a modern browser ClientHello: TLS 1.3 capable,
// h2/http-1.1 ALPN, SNI present.
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

// emitUnguardedHandshakeDebugLog reproduces the pre-optimization logging call in
// buildListenerTLS's GetCertificate callback: slog attributes were constructed
// on every handshake regardless of the active log level. The paired benchmarks
// below isolate that single difference in one benchmark run so the comparison is
// not polluted by machine load drift between separate runs.
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

// benchUnknownSNISnapshot builds the snapshot shape the unknown-SNI path walks:
// one known site on the bind, so the lookup misses exact, wildcard, and
// catch-all keys before returning not-found.
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

// The next two benchmarks isolate the cost of MatchSite's by-value SiteRuntime
// return (1472 bytes) against the pointer variant now used by the handshake
// callback. Paired in one run so load drift cannot skew the comparison.
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

// BenchmarkHandshakeDebugLogGuardOnly measures the guard itself, so the report
// can state what the retained level check costs per handshake.
func BenchmarkHandshakeDebugLogGuardOnly(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			b.Fatal("debug level unexpectedly enabled in benchmark")
		}
	}
}
