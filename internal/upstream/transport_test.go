package upstream

import (
	"crypto/tls"
	"testing"
)

func TestHTTPSClientTLSConfigSupportsTLS10Upstream(t *testing.T) {
	cfg := HTTPSClientTLSConfig("origin.example.test", true)
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if cfg.MinVersion != tls.VersionTLS10 {
		t.Fatalf("MinVersion = %#x, want %#x", cfg.MinVersion, tls.VersionTLS10)
	}
	if cfg.ServerName != "origin.example.test" {
		t.Fatalf("ServerName = %q, want %q", cfg.ServerName, "origin.example.test")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should preserve upstream setting")
	}
	if len(cfg.CipherSuites) == 0 {
		t.Fatal("CipherSuites should include TLS 1.0-1.2 upstream suites")
	}
	hasTLS10Suite := false
	for _, suite := range cfg.CipherSuites {
		switch suite {
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
			hasTLS10Suite = true
		case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256:
			t.Fatalf("CipherSuites contains TLS 1.3-only suite %#x", suite)
		}
	}
	if !hasTLS10Suite {
		t.Fatalf("CipherSuites = %#v, want TLS 1.0-compatible ECDHE CBC suite", cfg.CipherSuites)
	}
}

func TestHTTPSClientTLSConfigReturnsIndependentCipherSuiteSlice(t *testing.T) {
	cfg := HTTPSClientTLSConfig("origin.example.test", false)
	if cfg == nil || len(cfg.CipherSuites) == 0 {
		t.Fatal("expected TLS config with cipher suites")
	}
	firstSuite := cfg.CipherSuites[0]
	cfg.CipherSuites[0] = 0

	next := HTTPSClientTLSConfig("origin.example.test", false)
	if next == nil || len(next.CipherSuites) == 0 {
		t.Fatal("expected next TLS config with cipher suites")
	}
	if next.CipherSuites[0] != firstSuite {
		t.Fatalf("CipherSuites[0] = %#x, want independent cached copy %#x", next.CipherSuites[0], firstSuite)
	}
}

func BenchmarkHTTPSClientTLSConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cfg := HTTPSClientTLSConfig("origin.example.test", false)
		if cfg == nil || cfg.MinVersion != tls.VersionTLS10 {
			b.Fatal("invalid HTTPS upstream TLS config")
		}
	}
}
