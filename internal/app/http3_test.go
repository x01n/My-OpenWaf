package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	acmepkg "My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/dataplane"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/bot"

	"github.com/andybalholm/brotli"
	"github.com/quic-go/quic-go/http3"
)

type testHTTP3NetAddr string

func (a testHTTP3NetAddr) Network() string { return "udp" }
func (a testHTTP3NetAddr) String() string  { return string(a) }

type testHTTP3ClientHelloConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *testHTTP3ClientHelloConn) Read(_ []byte) (int, error)         { return 0, nil }
func (c *testHTTP3ClientHelloConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *testHTTP3ClientHelloConn) Close() error                       { return nil }
func (c *testHTTP3ClientHelloConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *testHTTP3ClientHelloConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *testHTTP3ClientHelloConn) SetDeadline(_ time.Time) error      { return nil }
func (c *testHTTP3ClientHelloConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *testHTTP3ClientHelloConn) SetWriteDeadline(_ time.Time) error { return nil }

func mustHTTP3TestCertificate(t *testing.T, host string) (string, string, tls.Certificate) {
	t.Helper()
	certPEM, keyPEM, err := acmepkg.GenerateSelfSignedPEM(host, []string{host}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate for %s: %v", host, err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("parse certificate for %s: %v", host, err)
	}
	return certPEM, keyPEM, cert
}

func TestHTTP3RouteTableResolvesWildcardWithExactPrecedence(t *testing.T) {
	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{
		{
			Bind: "127.0.0.1:8443",
			Site: store.Site{
				ID:   1,
				Host: "*.example.test",
			},
		},
		{
			Bind: "127.0.0.1:9443",
			Site: store.Site{
				ID:   2,
				Host: "api.example.test",
			},
		},
	})

	if got, ok := routeTable.Resolve("www.example.test"); !ok || got != "127.0.0.1:8443" {
		t.Fatalf("wildcard route = %q, %v, want %q, true", got, ok, "127.0.0.1:8443")
	}
	if got, ok := routeTable.Resolve("api.example.test"); !ok || got != "127.0.0.1:9443" {
		t.Fatalf("exact route = %q, %v, want %q, true", got, ok, "127.0.0.1:9443")
	}
	if got, ok := routeTable.Resolve("unknown.other.test"); ok {
		t.Fatalf("unknown route = %q, %v, want no route", got, ok)
	}
}

func TestHTTP3RouteTableDropsConflictingHostsAcrossBinds(t *testing.T) {
	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{
		{
			Bind: "127.0.0.1:8443",
			Site: store.Site{
				ID:   1,
				Host: "same.example.test,*.conflict.test,stable-a.example.test",
			},
		},
		{
			Bind: "127.0.0.1:9443",
			Site: store.Site{
				ID:   2,
				Host: "same.example.test,*.conflict.test,stable-b.example.test",
			},
		},
	})

	if got, ok := routeTable.Resolve("same.example.test"); ok {
		t.Fatalf("conflicting exact route = %q, %v, want no route", got, ok)
	}
	if got, ok := routeTable.Resolve("www.conflict.test"); ok {
		t.Fatalf("conflicting wildcard route = %q, %v, want no route", got, ok)
	}
	if got, ok := routeTable.Resolve("stable-a.example.test"); !ok || got != "127.0.0.1:8443" {
		t.Fatalf("stable A route = %q, %v, want %q, true", got, ok, "127.0.0.1:8443")
	}
	if got, ok := routeTable.Resolve("stable-b.example.test"); !ok || got != "127.0.0.1:9443" {
		t.Fatalf("stable B route = %q, %v, want %q, true", got, ok, "127.0.0.1:9443")
	}
	if got := strings.Join(routeTable.exactConflicts, ","); got != "same.example.test" {
		t.Fatalf("exact conflicts = %q, want same.example.test", got)
	}
	if got := strings.Join(routeTable.wildcardConflicts, ","); got != "*.conflict.test" {
		t.Fatalf("wildcard conflicts = %q, want *.conflict.test", got)
	}
}

func TestHTTP3RouteTableConflictDiagnosticsAreStableCopies(t *testing.T) {
	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{
		{
			Bind: "127.0.0.1:8443",
			Site: store.Site{
				ID:   1,
				Host: "same.example.test,*.conflict.test",
			},
		},
		{
			Bind: "127.0.0.1:9443",
			Site: store.Site{
				ID:   2,
				Host: "same.example.test,*.conflict.test",
			},
		},
	})

	diagnostics := routeTable.conflictDiagnostics(" 127.0.0.1:18443 ")
	if diagnostics.UDPBind != "127.0.0.1:18443" {
		t.Fatalf("diagnostic udp bind = %q, want trimmed bind", diagnostics.UDPBind)
	}
	if !diagnostics.HasConflicts() {
		t.Fatal("expected route conflict diagnostics")
	}
	if got := diagnostics.Summary(); got != "exact=same.example.test;wildcard=*.conflict.test" {
		t.Fatalf("diagnostic summary = %q", got)
	}
	diagnostics.ExactHosts[0] = "mutated.example.test"
	if got := strings.Join(routeTable.exactConflicts, ","); got != "same.example.test" {
		t.Fatalf("route table exact conflicts mutated to %q", got)
	}
}

func TestHTTP3RouteConflictDiagnosticsEmptySummary(t *testing.T) {
	diagnostics := http3RouteConflictDiagnostics{}
	if diagnostics.HasConflicts() {
		t.Fatal("empty diagnostics should not report conflicts")
	}
	if got := diagnostics.Summary(); got != "" {
		t.Fatalf("empty diagnostics summary = %q, want empty", got)
	}
}

func TestHTTP3AltSvcAdvertisementFollowsRouteTable(t *testing.T) {
	networkDefaults := snapshotpkg.NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      "127.0.0.1:18443",
		DefaultALPN:    "h2,h3,http/1.1",
		DefaultNetwork: "tcp",
	}
	tlsDefaults := snapshotpkg.DefaultTLSDefaults()
	rtA := snapshotpkg.SiteRuntime{
		Bind: "127.0.0.1:10443",
		Site: store.Site{
			ID:         1,
			Bind:       "127.0.0.1:10443",
			Host:       "same.example.test,*.conflict.test,stable-a.example.test",
			TLSEnabled: true,
			ALPN:       "h2,h3,http/1.1",
		},
		NetworkDefaults: networkDefaults,
		TLSDefaults:     tlsDefaults,
	}
	rtB := snapshotpkg.SiteRuntime{
		Bind: "127.0.0.1:11443",
		Site: store.Site{
			ID:         2,
			Bind:       "127.0.0.1:11443",
			Host:       "same.example.test,*.conflict.test,stable-b.example.test",
			TLSEnabled: true,
			ALPN:       "h2,h3,http/1.1",
		},
		NetworkDefaults: networkDefaults,
		TLSDefaults:     tlsDefaults,
	}
	sn := &snapshotpkg.Snapshot{
		TLSDefaults: tlsDefaults,
		Sites: map[string]snapshotpkg.SiteRuntime{
			"a": rtA,
			"b": rtB,
		},
	}

	advertisementA, ok := buildHTTP3AltSvcAdvertisement(rtA, sn)
	if !ok {
		t.Fatal("expected HTTP/3 Alt-Svc advertisement for site A")
	}
	wantAltSvc := `h3=":18443"; ma=86400`
	if got, ok := advertisementA.valueForHost("stable-a.example.test"); !ok || got != wantAltSvc {
		t.Fatalf("stable A Alt-Svc = %q, %v, want %q, true", got, ok, wantAltSvc)
	}
	if got, ok := advertisementA.valueForHost("same.example.test"); ok {
		t.Fatalf("conflicting exact host Alt-Svc = %q, %v, want no advertisement", got, ok)
	}
	if got, ok := advertisementA.valueForHost("www.conflict.test"); ok {
		t.Fatalf("conflicting wildcard host Alt-Svc = %q, %v, want no advertisement", got, ok)
	}
	if got, ok := advertisementA.valueForHost("stable-b.example.test"); ok {
		t.Fatalf("other TCP bind Alt-Svc = %q, %v, want no advertisement", got, ok)
	}

	advertisementB, ok := buildHTTP3AltSvcAdvertisement(rtB, sn)
	if !ok {
		t.Fatal("expected HTTP/3 Alt-Svc advertisement for site B")
	}
	if got, ok := advertisementB.valueForHost("stable-b.example.test"); !ok || got != wantAltSvc {
		t.Fatalf("stable B Alt-Svc = %q, %v, want %q, true", got, ok, wantAltSvc)
	}
}

func TestHTTP3AltSvcAdvertisementUsesProvidedPlans(t *testing.T) {
	rt := snapshotpkg.SiteRuntime{
		Bind: "127.0.0.1:10443",
		Site: store.Site{
			ID:         1,
			Bind:       "127.0.0.1:10443",
			Host:       "cached.example.test",
			TLSEnabled: true,
			ALPN:       "h2,h3,http/1.1",
		},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      "127.0.0.1:18443",
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
	}
	plans := map[string]http3ServerPlan{
		http3ListenerName("127.0.0.1:18443"): {
			Bind: "127.0.0.1:18443",
			RouteTable: http3RouteTable{
				exact: map[string]string{
					"cached.example.test": "127.0.0.1:10443",
				},
			},
		},
	}

	advertisement, ok := buildHTTP3AltSvcAdvertisementWithPlans(rt, nil, plans)
	if !ok {
		t.Fatal("expected HTTP/3 Alt-Svc advertisement from provided plans")
	}
	if got, ok := advertisement.valueForHost("cached.example.test"); !ok || got != `h3=":18443"; ma=86400` {
		t.Fatalf("Alt-Svc = %q, %v, want provided plan value", got, ok)
	}
}

func TestHTTP3AltSvcAdvertisementRequiresTLSHTTP3Plan(t *testing.T) {
	rt := snapshotpkg.SiteRuntime{
		Bind: "127.0.0.1:10443",
		Site: store.Site{
			ID:         1,
			Bind:       "127.0.0.1:10443",
			Host:       "plain.example.test",
			TLSEnabled: false,
			ALPN:       "h3,http/1.1",
		},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      "127.0.0.1:18443",
			DefaultALPN:    "h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
	}
	sn := &snapshotpkg.Snapshot{
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			"plain": rt,
		},
	}

	if _, ok := buildHTTP3AltSvcAdvertisement(rt, sn); ok {
		t.Fatal("plain HTTP site should not advertise HTTP/3 Alt-Svc")
	}
}

func TestNewHTTP3ServerDoesNotAdvertiseAltSvcWithoutRoute(t *testing.T) {
	srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       "127.0.0.1:8443",
		RouteTable: http3RouteTable{},
		TLSConfig:  &tls.Config{MinVersion: tls.VersionTLS13},
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://missing.example.test/", nil)
	req.Host = "missing.example.test"

	srv.server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("HTTP/3 status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if got := rec.Header().Get("Alt-Svc"); got != "" {
		t.Fatalf("HTTP/3 response Alt-Svc = %q, want empty for missing route", got)
	}
}

func TestHTTP3ServerReturnsBadGatewayWithoutRouteOverQUIC(t *testing.T) {
	const host = "missing-h3-route.example.test"

	certPEM, keyPEM, err := acmepkg.GenerateSelfSignedPEM(host, []string{host}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate HTTP/3 certificate: %v", err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("parse HTTP/3 certificate: %v", err)
	}

	udpBind := reserveUDPBind(t)
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: http3RouteTable{},
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		},
		Log: slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/no-route", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 no-route request: %v", err)
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 no-route request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 no-route response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("no-route response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 no-route TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 no-route TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 no-route negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("HTTP/3 no-route status = %d, want %d; body=%q", resp.StatusCode, http.StatusBadGateway, string(body))
	}
	if got := resp.Header.Get("Alt-Svc"); got != "" {
		t.Fatalf("HTTP/3 no-route Alt-Svc = %q, want empty", got)
	}
	if !strings.Contains(string(body), "no HTTP/3 route target") {
		t.Fatalf("HTTP/3 no-route body = %q, want route target error", string(body))
	}
}

func TestHTTP3ServerShutdownIsIdempotent(t *testing.T) {
	srv := &HTTP3Server{
		server:   &http3.Server{},
		stopChan: make(chan struct{}),
	}

	for i := 0; i < 2; i++ {
		func(call int) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("Shutdown panicked on call %d: %v", call, recovered)
				}
			}()
			_ = srv.Shutdown(context.Background())
		}(i + 1)
	}
}

func TestNewHTTP3ServerForcesTLS13AndH3ALPN(t *testing.T) {
	srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind: "127.0.0.1:8443",
		RouteTable: http3RouteTable{
			exact: map[string]string{
				"tls-h3.example.test": "127.0.0.1:9443",
			},
		},
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		},
	})
	if srv == nil || srv.server == nil || srv.server.TLSConfig == nil {
		t.Fatalf("expected HTTP/3 server TLS config, got %#v", srv)
	}
	cfg := srv.server.TLSConfig
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 MinVersion = %#x, want TLS 1.3", cfg.MinVersion)
	}
	if cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 MaxVersion = %#x, want TLS 1.3", cfg.MaxVersion)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h3" {
		t.Fatalf("HTTP/3 NextProtos = %#v, want [h3]", cfg.NextProtos)
	}
}

func TestNewHTTP3ServerLoopbackTransportSupportsLegacyTLSRange(t *testing.T) {
	srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind: "127.0.0.1:8443",
		RouteTable: http3RouteTable{
			exact: map[string]string{
				"loopback-tls.example.test": "127.0.0.1:9443",
			},
		},
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	})
	if srv == nil || srv.proxyTransport == nil || srv.proxyTransport.TLSClientConfig == nil {
		t.Fatalf("expected HTTP/3 loopback transport TLS config, got %#v", srv)
	}
	if !srv.proxyTransport.ForceAttemptHTTP2 {
		t.Fatal("HTTP/3 loopback transport should attempt HTTP/2 to the TCP data-plane")
	}
	if !srv.proxyTransport.DisableCompression {
		t.Fatal("HTTP/3 loopback transport should keep response compression explicit")
	}
	if srv.proxyTransport.TLSHandshakeTimeout != http3LoopbackTLSHandshakeTimeout {
		t.Fatalf("HTTP/3 loopback TLS handshake timeout = %s, want %s", srv.proxyTransport.TLSHandshakeTimeout, http3LoopbackTLSHandshakeTimeout)
	}
	if srv.proxyTransport.ExpectContinueTimeout != http3LoopbackExpectContinueTimeout {
		t.Fatalf("HTTP/3 loopback expect-continue timeout = %s, want %s", srv.proxyTransport.ExpectContinueTimeout, http3LoopbackExpectContinueTimeout)
	}
	if srv.proxyTransport.IdleConnTimeout != http3LoopbackIdleConnTimeout {
		t.Fatalf("HTTP/3 loopback idle timeout = %s, want %s", srv.proxyTransport.IdleConnTimeout, http3LoopbackIdleConnTimeout)
	}
	cfg := srv.proxyTransport.TLSClientConfig
	if cfg.MinVersion != tls.VersionTLS10 {
		t.Fatalf("HTTP/3 loopback MinVersion = %#x, want TLS 1.0", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Fatal("HTTP/3 loopback CipherSuites is empty")
	}
	hasCBCSuite := false
	for _, suite := range cfg.CipherSuites {
		if suite == tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA {
			hasCBCSuite = true
			break
		}
	}
	if !hasCBCSuite {
		t.Fatalf("HTTP/3 loopback CipherSuites = %#v, want TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", cfg.CipherSuites)
	}
}

func TestHTTP3LoopbackTLSCipherSuitesExcludeTLS13Suites(t *testing.T) {
	suites := http3LoopbackTLSCipherSuites()
	if len(suites) == 0 {
		t.Fatal("HTTP/3 loopback cipher suites is empty")
	}
	hasTLS10Suite := false
	hasTLS12Suite := false
	for _, suite := range suites {
		switch suite {
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
			hasTLS10Suite = true
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			hasTLS12Suite = true
		case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256:
			t.Fatalf("HTTP/3 loopback cipher suites includes TLS 1.3-only suite %#x", suite)
		}
	}
	if !hasTLS10Suite {
		t.Fatalf("HTTP/3 loopback cipher suites = %#v, want TLS1.0-compatible ECDSA CBC suite", suites)
	}
	if !hasTLS12Suite {
		t.Fatalf("HTTP/3 loopback cipher suites = %#v, want TLS1.2-compatible ECDSA GCM suite", suites)
	}
}

func TestHTTP3LoopbackTransportNegotiatesLegacyTLSAndALPN(t *testing.T) {
	tests := []struct {
		name         string
		minVersion   uint16
		maxVersion   uint16
		nextProtos   []string
		cipherSuites []uint16
		wantALPN     string
		wantCipher   uint16
	}{
		{
			name:         "tls10_http11",
			minVersion:   tls.VersionTLS10,
			maxVersion:   tls.VersionTLS10,
			nextProtos:   []string{"http/1.1"},
			cipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			wantALPN:     "http/1.1",
			wantCipher:   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
		{
			name:         "tls11_http11",
			minVersion:   tls.VersionTLS11,
			maxVersion:   tls.VersionTLS11,
			nextProtos:   []string{"http/1.1"},
			cipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			wantALPN:     "http/1.1",
			wantCipher:   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
		{
			name:         "tls12_h2",
			minVersion:   tls.VersionTLS12,
			maxVersion:   tls.VersionTLS12,
			nextProtos:   []string{"h2", "http/1.1"},
			cipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			wantALPN:     "h2",
			wantCipher:   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateCh := make(chan tls.ConnectionState, 1)
			loopback := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil {
					t.Fatal("loopback request has no TLS state")
				}
				select {
				case stateCh <- *r.TLS:
				default:
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = io.WriteString(w, "loopback tls response")
			}))
			loopback.TLS = &tls.Config{
				MinVersion:   tt.minVersion,
				MaxVersion:   tt.maxVersion,
				NextProtos:   tt.nextProtos,
				CipherSuites: tt.cipherSuites,
			}
			loopback.StartTLS()
			t.Cleanup(loopback.Close)

			srv := NewHTTP3Server(HTTP3ServerConfig{
				Bind: "127.0.0.1:8443",
				RouteTable: http3RouteTable{
					exact: map[string]string{
						"loopback-negotiation.example.test": loopback.Listener.Addr().String(),
					},
				},
				TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
			})
			if srv == nil || srv.proxyTransport == nil {
				t.Fatalf("expected HTTP/3 loopback transport, got %#v", srv)
			}
			t.Cleanup(func() {
				srv.proxyTransport.CloseIdleConnections()
			})

			req, err := http.NewRequest(http.MethodGet, loopback.URL, nil)
			if err != nil {
				t.Fatalf("build loopback request: %v", err)
			}
			req.Host = "loopback-negotiation.example.test"
			resp, err := srv.proxyTransport.RoundTrip(req)
			if err != nil {
				t.Fatalf("send loopback request: %v", err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatalf("read loopback response: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("loopback response status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
			}
			if string(body) != "loopback tls response" {
				t.Fatalf("loopback response body = %q", string(body))
			}

			select {
			case state := <-stateCh:
				if state.Version != tt.maxVersion {
					t.Fatalf("loopback TLS version = %#x, want %#x", state.Version, tt.maxVersion)
				}
				if state.NegotiatedProtocol != tt.wantALPN {
					t.Fatalf("loopback ALPN = %q, want %q", state.NegotiatedProtocol, tt.wantALPN)
				}
				if state.CipherSuite != tt.wantCipher {
					t.Fatalf("loopback cipher suite = %#x, want %#x", state.CipherSuite, tt.wantCipher)
				}
			default:
				t.Fatal("loopback server did not observe TLS state")
			}
		})
	}
}

func TestHTTP3ServerSetsForwardedHeadersForLoopback(t *testing.T) {
	const host = "h3-forwarded.example.test"

	type observedForwarding struct {
		host              string
		path              string
		escapedPath       string
		rawQuery          string
		xForwardedFor     string
		xForwardedHost    string
		xForwardedProto   string
		internalProtoMark string
	}

	observed := make(chan observedForwarding, 1)
	loopback := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- observedForwarding{
			host:              r.Host,
			path:              r.URL.Path,
			escapedPath:       r.URL.EscapedPath(),
			rawQuery:          r.URL.RawQuery,
			xForwardedFor:     r.Header.Get("X-Forwarded-For"),
			xForwardedHost:    r.Header.Get("X-Forwarded-Host"),
			xForwardedProto:   r.Header.Get("X-Forwarded-Proto"),
			internalProtoMark: r.Header.Get(dataplane.InternalHTTP3ProtoHeader),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "loopback forwarded headers")
	}))
	t.Cleanup(loopback.Close)

	certPEM, keyPEM, err := acmepkg.GenerateSelfSignedPEM(host, []string{host}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate HTTP/3 certificate: %v", err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("parse HTTP/3 certificate: %v", err)
	}

	udpBind := reserveUDPBind(t)
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind: udpBind,
		RouteTable: http3RouteTable{
			exact: map[string]string{
				host: loopback.Listener.Addr().String(),
			},
		},
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		},
		Log: slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-forwarded/a%2Fb?keep=1;semi=2&encoded=a%2Fb", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 request: %v", err)
	}
	req.Host = host
	req.Header.Set("X-Forwarded-For", "198.51.100.77")
	req.Header.Set("X-Forwarded-Host", "spoofed-forwarded-host.example.test")
	req.Header.Set("X-Forwarded-Proto", "http")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
	}
	if got := string(body); got != "loopback forwarded headers" {
		t.Fatalf("HTTP/3 response body = %q", got)
	}

	select {
	case got := <-observed:
		if got.host != host {
			t.Fatalf("loopback Host = %q, want %q", got.host, host)
		}
		if got.path != "/h3-forwarded/a/b" {
			t.Fatalf("loopback path = %q, want %q", got.path, "/h3-forwarded/a/b")
		}
		if got.escapedPath != "/h3-forwarded/a%2Fb" {
			t.Fatalf("loopback escaped path = %q, want %q", got.escapedPath, "/h3-forwarded/a%2Fb")
		}
		if got.rawQuery != "keep=1;semi=2&encoded=a%2Fb" {
			t.Fatalf("loopback raw query = %q, want %q", got.rawQuery, "keep=1;semi=2&encoded=a%2Fb")
		}
		if got.xForwardedFor != "127.0.0.1" {
			t.Fatalf("loopback X-Forwarded-For = %q, want %q", got.xForwardedFor, "127.0.0.1")
		}
		if got.xForwardedHost != host {
			t.Fatalf("loopback X-Forwarded-Host = %q, want %q", got.xForwardedHost, host)
		}
		if got.xForwardedProto != "h3" {
			t.Fatalf("loopback X-Forwarded-Proto = %q, want %q", got.xForwardedProto, "h3")
		}
		if got.internalProtoMark != "h3" {
			t.Fatalf("loopback %s = %q, want %q", dataplane.InternalHTTP3ProtoHeader, got.internalProtoMark, "h3")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("loopback server did not observe HTTP/3 forwarded headers")
	}
}

func TestHTTP3ServerCompletesQUICHandshakeAndProxiesResponse(t *testing.T) {
	type upstreamObservation struct {
		path        string
		escapedPath string
		rawQuery    string
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSeen <- upstreamObservation{
			path:        r.URL.Path,
			escapedPath: r.URL.EscapedPath(),
			rawQuery:    r.URL.RawQuery,
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "http3 quic response")
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-response.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-response/a%2Fb?keep=1;semi=2&encoded=a%2Fb", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 request: %v", err)
	}
	req.Host = rt.Site.Host

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
	}
	if got := string(body); got != "http3 quic response" {
		t.Fatalf("HTTP/3 response body = %q", got)
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 Alt-Svc response header")
	}
	select {
	case got := <-upstreamSeen:
		if got.path != "/h3-response/a/b" {
			t.Fatalf("upstream path = %q, want %q", got.path, "/h3-response/a/b")
		}
		if got.escapedPath != "/h3-response/a%2Fb" {
			t.Fatalf("upstream escaped path = %q, want %q", got.escapedPath, "/h3-response/a%2Fb")
		}
		if got.rawQuery != "keep=1;semi=2&encoded=a%2Fb" {
			t.Fatalf("upstream raw query = %q, want %q", got.rawQuery, "keep=1;semi=2&encoded=a%2Fb")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 path/query request")
	}
}

func TestHTTP3ServerProxiesHEADWithoutResponseBody(t *testing.T) {
	type upstreamObservation struct {
		method      string
		path        string
		escapedPath string
		rawQuery    string
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSeen <- upstreamObservation{
			method:      r.Method,
			path:        r.URL.Path,
			escapedPath: r.URL.EscapedPath(),
			rawQuery:    r.URL.RawQuery,
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Head-Upstream", "seen")
		_, _ = io.WriteString(w, "head response body must not reach client")
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-head.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodHead, "https://"+udpBind+"/h3-head/a%2Fb?keep=1;semi=2&encoded=a%2Fb", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 HEAD request: %v", err)
	}
	req.Host = rt.Site.Host

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 HEAD request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 HEAD response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HEAD response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 HEAD TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 HEAD TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 HEAD negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 HEAD status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
	}
	if got := resp.Header.Get("X-Head-Upstream"); got != "seen" {
		t.Fatalf("HTTP/3 HEAD response header X-Head-Upstream = %q, want %q", got, "seen")
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 HEAD Alt-Svc response header")
	}
	if len(body) != 0 {
		t.Fatalf("HTTP/3 HEAD response body length = %d, want 0; body=%q", len(body), string(body))
	}

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodHead {
			t.Fatalf("upstream method = %q, want %q", got.method, http.MethodHead)
		}
		if got.path != "/h3-head/a/b" {
			t.Fatalf("upstream path = %q, want %q", got.path, "/h3-head/a/b")
		}
		if got.escapedPath != "/h3-head/a%2Fb" {
			t.Fatalf("upstream escaped path = %q, want %q", got.escapedPath, "/h3-head/a%2Fb")
		}
		if got.rawQuery != "keep=1;semi=2&encoded=a%2Fb" {
			t.Fatalf("upstream raw query = %q, want %q", got.rawQuery, "keep=1;semi=2&encoded=a%2Fb")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 HEAD request")
	}
}

func TestHTTP3ServerProxiesPOSTBodyAndNoContentResponse(t *testing.T) {
	requestBody := bytes.Repeat([]byte(`{"h3":"post-body","chunk":"data"}`), 512)
	type upstreamObservation struct {
		method        string
		path          string
		escapedPath   string
		rawQuery      string
		contentLength int64
		body          []byte
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		upstreamSeen <- upstreamObservation{
			method:        r.Method,
			path:          r.URL.Path,
			escapedPath:   r.URL.EscapedPath(),
			rawQuery:      r.URL.RawQuery,
			contentLength: r.ContentLength,
			body:          body,
		}
		w.Header().Set("X-Post-Upstream", "seen")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-post.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+udpBind+"/h3-post/a%2Fb?keep=1;semi=2&encoded=a%2Fb", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("build HTTP/3 POST request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(requestBody))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 POST request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 POST response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("POST response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 POST TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 POST TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 POST negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("HTTP/3 POST status = %d, want %d; body=%q", resp.StatusCode, http.StatusNoContent, string(body))
	}
	if got := resp.Header.Get("X-Post-Upstream"); got != "seen" {
		t.Fatalf("HTTP/3 POST response header X-Post-Upstream = %q, want %q", got, "seen")
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 POST Alt-Svc response header")
	}
	if len(body) != 0 {
		t.Fatalf("HTTP/3 POST 204 response body length = %d, want 0; body=%q", len(body), string(body))
	}

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodPost {
			t.Fatalf("upstream method = %q, want %q", got.method, http.MethodPost)
		}
		if got.path != "/h3-post/a/b" {
			t.Fatalf("upstream path = %q, want %q", got.path, "/h3-post/a/b")
		}
		if got.escapedPath != "/h3-post/a%2Fb" {
			t.Fatalf("upstream escaped path = %q, want %q", got.escapedPath, "/h3-post/a%2Fb")
		}
		if got.rawQuery != "keep=1;semi=2&encoded=a%2Fb" {
			t.Fatalf("upstream raw query = %q, want %q", got.rawQuery, "keep=1;semi=2&encoded=a%2Fb")
		}
		if got.contentLength != int64(len(requestBody)) {
			t.Fatalf("upstream ContentLength = %d, want %d", got.contentLength, len(requestBody))
		}
		if !bytes.Equal(got.body, requestBody) {
			t.Fatalf("upstream body mismatch: got %d bytes want %d bytes", len(got.body), len(requestBody))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 POST request")
	}
}

func TestHTTP3ServerProxiesPATCHBodyAndResponse(t *testing.T) {
	requestBody := bytes.Repeat([]byte(`{"h3":"patch-body","chunk":"data"}`), 256)
	type upstreamObservation struct {
		method        string
		path          string
		escapedPath   string
		rawQuery      string
		contentType   string
		contentLength int64
		body          []byte
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read PATCH body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		upstreamSeen <- upstreamObservation{
			method:        r.Method,
			path:          r.URL.Path,
			escapedPath:   r.URL.EscapedPath(),
			rawQuery:      r.URL.RawQuery,
			contentType:   r.Header.Get("Content-Type"),
			contentLength: r.ContentLength,
			body:          body,
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Patch-Upstream", "seen")
		_, _ = io.WriteString(w, "patch upstream ok")
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-patch.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodPatch, "https://"+udpBind+"/h3-patch/a%2Fb?keep=1;semi=2&encoded=a%2Fb", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("build HTTP/3 PATCH request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Content-Type", "application/merge-patch+json")
	req.ContentLength = int64(len(requestBody))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 PATCH request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 PATCH response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("PATCH response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 PATCH TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 PATCH TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 PATCH negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 PATCH status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
	}
	if got := resp.Header.Get("X-Patch-Upstream"); got != "seen" {
		t.Fatalf("HTTP/3 PATCH response header X-Patch-Upstream = %q, want %q", got, "seen")
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 PATCH Alt-Svc response header")
	}
	if got := string(body); got != "patch upstream ok" {
		t.Fatalf("HTTP/3 PATCH response body = %q, want %q", got, "patch upstream ok")
	}

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodPatch {
			t.Fatalf("upstream method = %q, want %q", got.method, http.MethodPatch)
		}
		if got.path != "/h3-patch/a/b" {
			t.Fatalf("upstream path = %q, want %q", got.path, "/h3-patch/a/b")
		}
		if got.escapedPath != "/h3-patch/a%2Fb" {
			t.Fatalf("upstream escaped path = %q, want %q", got.escapedPath, "/h3-patch/a%2Fb")
		}
		if got.rawQuery != "keep=1;semi=2&encoded=a%2Fb" {
			t.Fatalf("upstream raw query = %q, want %q", got.rawQuery, "keep=1;semi=2&encoded=a%2Fb")
		}
		if got.contentType != "application/merge-patch+json" {
			t.Fatalf("upstream Content-Type = %q, want %q", got.contentType, "application/merge-patch+json")
		}
		if got.contentLength != int64(len(requestBody)) {
			t.Fatalf("upstream ContentLength = %d, want %d", got.contentLength, len(requestBody))
		}
		if !bytes.Equal(got.body, requestBody) {
			t.Fatalf("upstream body mismatch: got %d bytes want %d bytes", len(got.body), len(requestBody))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 PATCH request")
	}
}

func TestHTTP3ServerProxiesPUTStreamingBodyAndResponse(t *testing.T) {
	requestBody := bytes.Repeat([]byte("http3-put-stream-payload-"), 4096)
	firstSegmentSize := len(requestBody) / 3
	type upstreamObservation struct {
		method        string
		path          string
		escapedPath   string
		rawQuery      string
		contentType   string
		contentLength int64
		body          []byte
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read PUT body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		upstreamSeen <- upstreamObservation{
			method:        r.Method,
			path:          r.URL.Path,
			escapedPath:   r.URL.EscapedPath(),
			rawQuery:      r.URL.RawQuery,
			contentType:   r.Header.Get("Content-Type"),
			contentLength: r.ContentLength,
			body:          body,
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Put-Upstream", "seen")
		_, _ = io.WriteString(w, "put upstream ok")
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-put.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}

	bodyReader, bodyWriter := io.Pipe()
	writeErrCh := make(chan error, 1)
	go func() {
		if _, err := bodyWriter.Write(requestBody[:firstSegmentSize]); err != nil {
			_ = bodyWriter.CloseWithError(err)
			writeErrCh <- err
			return
		}
		if _, err := bodyWriter.Write(requestBody[firstSegmentSize:]); err != nil {
			_ = bodyWriter.CloseWithError(err)
			writeErrCh <- err
			return
		}
		writeErrCh <- bodyWriter.Close()
	}()

	req, err := http.NewRequest(http.MethodPut, "https://"+udpBind+"/h3-put/a%2Fb?stream=1&encoded=a%2Fb", bodyReader)
	if err != nil {
		t.Fatalf("build HTTP/3 PUT request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = -1

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 PUT request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 PUT response body: %v", err)
	}
	select {
	case err := <-writeErrCh:
		if err != nil {
			t.Fatalf("write HTTP/3 PUT streaming body: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP/3 PUT streaming body writer")
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("PUT response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 PUT TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 PUT TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 PUT negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 PUT status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
	}
	if got := resp.Header.Get("X-Put-Upstream"); got != "seen" {
		t.Fatalf("HTTP/3 PUT response header X-Put-Upstream = %q, want %q", got, "seen")
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 PUT Alt-Svc response header")
	}
	if got := string(body); got != "put upstream ok" {
		t.Fatalf("HTTP/3 PUT response body = %q, want %q", got, "put upstream ok")
	}

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodPut {
			t.Fatalf("upstream method = %q, want %q", got.method, http.MethodPut)
		}
		if got.path != "/h3-put/a/b" {
			t.Fatalf("upstream path = %q, want %q", got.path, "/h3-put/a/b")
		}
		if got.escapedPath != "/h3-put/a%2Fb" {
			t.Fatalf("upstream escaped path = %q, want %q", got.escapedPath, "/h3-put/a%2Fb")
		}
		if got.rawQuery != "stream=1&encoded=a%2Fb" {
			t.Fatalf("upstream raw query = %q, want %q", got.rawQuery, "stream=1&encoded=a%2Fb")
		}
		if got.contentType != "application/octet-stream" {
			t.Fatalf("upstream Content-Type = %q, want %q", got.contentType, "application/octet-stream")
		}
		if got.contentLength != -1 {
			t.Fatalf("upstream ContentLength = %d, want -1 for streaming body", got.contentLength)
		}
		if !bytes.Equal(got.body, requestBody) {
			t.Fatalf("upstream PUT body mismatch: got %d bytes want %d bytes", len(got.body), len(requestBody))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 PUT request")
	}
}

func TestHTTP3ServerCancelsUpstreamRequestBodyWhenClientCancelsUpload(t *testing.T) {
	firstSegment := bytes.Repeat([]byte("http3-request-cancel-prefix-"), 4096)
	const wantPrefixBytes = 50 * 1024

	type upstreamObservation struct {
		method        string
		path          string
		rawQuery      string
		contentType   string
		contentLength int64
		forwarded     string
		protoMark     string
	}
	type upstreamResult struct {
		upstreamObservation
		bytesRead  int
		readErr    error
		contextErr error
	}
	type clientResult struct {
		resp *http.Response
		err  error
	}

	upstreamPartial := make(chan upstreamObservation, 1)
	upstreamFinished := make(chan upstreamResult, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-upload-cancel/body" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3 upload cancel ready")
			return
		}

		obs := upstreamObservation{
			method:        r.Method,
			path:          r.URL.Path,
			rawQuery:      r.URL.RawQuery,
			contentType:   r.Header.Get("Content-Type"),
			contentLength: r.ContentLength,
			forwarded:     r.Header.Get("X-Forwarded-Proto"),
			protoMark:     r.Header.Get(dataplane.InternalHTTP3ProtoHeader),
		}
		buf := make([]byte, 8192)
		total := 0
		partialSent := false
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				total += n
				if total >= wantPrefixBytes && !partialSent {
					upstreamPartial <- obs
					partialSent = true
				}
			}
			if err != nil {
				upstreamFinished <- upstreamResult{
					upstreamObservation: obs,
					bytesRead:           total,
					readErr:             err,
					contextErr:          r.Context().Err(),
				}
				return
			}
		}
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-upload-cancel.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
		DisableCompression: true,
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}

	bodyReader, bodyWriter := io.Pipe()
	ctx, cancelReq := context.WithCancel(context.Background())
	defer cancelReq()
	t.Cleanup(func() {
		_ = bodyWriter.CloseWithError(context.Canceled)
	})

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := bodyWriter.Write(firstSegment)
		writeErrCh <- err
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://"+udpBind+"/h3-upload-cancel/body?stream=1", bodyReader)
	if err != nil {
		t.Fatalf("build HTTP/3 upload cancel request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = -1

	clientDone := make(chan clientResult, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		clientDone <- clientResult{resp: resp, err: err}
	}()

	select {
	case got := <-upstreamPartial:
		if got.method != http.MethodPut {
			t.Fatalf("upstream HTTP/3 upload cancel method = %q, want %q", got.method, http.MethodPut)
		}
		if got.path != "/h3-upload-cancel/body" {
			t.Fatalf("upstream HTTP/3 upload cancel path = %q, want %q", got.path, "/h3-upload-cancel/body")
		}
		if got.rawQuery != "stream=1" {
			t.Fatalf("upstream HTTP/3 upload cancel raw query = %q, want %q", got.rawQuery, "stream=1")
		}
		if got.contentType != "application/octet-stream" {
			t.Fatalf("upstream HTTP/3 upload cancel Content-Type = %q, want %q", got.contentType, "application/octet-stream")
		}
		if got.contentLength != -1 {
			t.Fatalf("upstream HTTP/3 upload cancel ContentLength = %d, want -1", got.contentLength)
		}
		if got.forwarded != "h3" {
			t.Fatalf("upstream HTTP/3 upload cancel X-Forwarded-Proto = %q, want %q", got.forwarded, "h3")
		}
		if got.protoMark != "" {
			t.Fatalf("upstream HTTP/3 upload cancel leaked %s = %q, want empty", dataplane.InternalHTTP3ProtoHeader, got.protoMark)
		}
	case <-time.After(2 * time.Second):
		cancelReq()
		_ = bodyWriter.CloseWithError(context.Canceled)
		t.Fatal("upstream did not receive HTTP/3 upload cancel prefix")
	}

	cancelReq()
	_ = bodyWriter.CloseWithError(context.Canceled)

	select {
	case <-writeErrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP/3 upload cancel body writer")
	}

	select {
	case got := <-upstreamFinished:
		if got.bytesRead < wantPrefixBytes {
			t.Fatalf("upstream HTTP/3 upload cancel bytes read = %d, want at least %d", got.bytesRead, wantPrefixBytes)
		}
		if got.readErr == nil {
			t.Fatal("upstream HTTP/3 upload cancel read error is nil, want cancellation error")
		}
		if !errors.Is(got.contextErr, context.Canceled) {
			t.Fatalf("upstream HTTP/3 upload cancel context error = %v, want context canceled; readErr=%v", got.contextErr, got.readErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream HTTP/3 upload body did not stop after client cancellation")
	}

	select {
	case got := <-clientDone:
		if got.err == nil {
			t.Fatal("HTTP/3 upload cancel client request succeeded, want cancellation error")
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Fatalf("HTTP/3 upload cancel client error = %v, want context canceled", got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP/3 upload cancel client result")
	}

	readyReq, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-upload-cancel-ready", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 upload cancel ready request: %v", err)
	}
	readyReq.Host = rt.Site.Host
	readyResp, err := client.Do(readyReq)
	if err != nil {
		t.Fatalf("send HTTP/3 upload cancel ready request after stream cancel: %v", err)
	}
	defer readyResp.Body.Close()
	readyBody, err := io.ReadAll(readyResp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 upload cancel ready response: %v", err)
	}
	if readyResp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 upload cancel ready protocol major = %d, want 3", readyResp.ProtoMajor)
	}
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 upload cancel ready status = %d, want %d; body=%q", readyResp.StatusCode, http.StatusOK, string(readyBody))
	}
	if got := string(readyBody); got != "h3 upload cancel ready" {
		t.Fatalf("HTTP/3 upload cancel ready body = %q, want %q", got, "h3 upload cancel ready")
	}
}

func TestHTTP3ServerProxiesDELETEBodyAndResponse(t *testing.T) {
	requestBody := []byte(`{"delete":"http3-body","reason":"cleanup"}`)
	type upstreamObservation struct {
		method        string
		path          string
		escapedPath   string
		rawQuery      string
		contentType   string
		contentLength int64
		body          []byte
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read DELETE body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		upstreamSeen <- upstreamObservation{
			method:        r.Method,
			path:          r.URL.Path,
			escapedPath:   r.URL.EscapedPath(),
			rawQuery:      r.URL.RawQuery,
			contentType:   r.Header.Get("Content-Type"),
			contentLength: r.ContentLength,
			body:          body,
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Delete-Upstream", "seen")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "delete upstream accepted")
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-delete.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodDelete, "https://"+udpBind+"/h3-delete/a%2Fb?confirm=1&encoded=a%2Fb", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatalf("build HTTP/3 DELETE request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(requestBody))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 DELETE request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 DELETE response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("DELETE response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 DELETE TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 DELETE TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 DELETE negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("HTTP/3 DELETE status = %d, want %d; body=%q", resp.StatusCode, http.StatusAccepted, string(body))
	}
	if got := resp.Header.Get("X-Delete-Upstream"); got != "seen" {
		t.Fatalf("HTTP/3 DELETE response header X-Delete-Upstream = %q, want %q", got, "seen")
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 DELETE Alt-Svc response header")
	}
	if got := string(body); got != "delete upstream accepted" {
		t.Fatalf("HTTP/3 DELETE response body = %q, want %q", got, "delete upstream accepted")
	}

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodDelete {
			t.Fatalf("upstream method = %q, want %q", got.method, http.MethodDelete)
		}
		if got.path != "/h3-delete/a/b" {
			t.Fatalf("upstream path = %q, want %q", got.path, "/h3-delete/a/b")
		}
		if got.escapedPath != "/h3-delete/a%2Fb" {
			t.Fatalf("upstream escaped path = %q, want %q", got.escapedPath, "/h3-delete/a%2Fb")
		}
		if got.rawQuery != "confirm=1&encoded=a%2Fb" {
			t.Fatalf("upstream raw query = %q, want %q", got.rawQuery, "confirm=1&encoded=a%2Fb")
		}
		if got.contentType != "application/json" {
			t.Fatalf("upstream Content-Type = %q, want %q", got.contentType, "application/json")
		}
		if got.contentLength != int64(len(requestBody)) {
			t.Fatalf("upstream ContentLength = %d, want %d", got.contentLength, len(requestBody))
		}
		if !bytes.Equal(got.body, requestBody) {
			t.Fatalf("upstream DELETE body mismatch: got %d bytes want %d bytes", len(got.body), len(requestBody))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 DELETE request")
	}
}

func TestHTTP3ServerProxiesOPTIONSPreflightHeadersAndResponse(t *testing.T) {
	type upstreamObservation struct {
		method                     string
		path                       string
		escapedPath                string
		rawQuery                   string
		origin                     string
		accessControlRequestMethod string
		accessControlRequestHeader string
		body                       []byte
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read OPTIONS body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		upstreamSeen <- upstreamObservation{
			method:                     r.Method,
			path:                       r.URL.Path,
			escapedPath:                r.URL.EscapedPath(),
			rawQuery:                   r.URL.RawQuery,
			origin:                     r.Header.Get("Origin"),
			accessControlRequestMethod: r.Header.Get("Access-Control-Request-Method"),
			accessControlRequestHeader: r.Header.Get("Access-Control-Request-Headers"),
			body:                       body,
		}
		w.Header().Set("Allow", "GET, POST, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Origin", "https://client.example.test")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "X-Trace-Token, Content-Type")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-options.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodOptions, "https://"+udpBind+"/h3-options/a%2Fb?preflight=1&encoded=a%2Fb", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 OPTIONS request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Origin", "https://client.example.test")
	req.Header.Set("Access-Control-Request-Method", "PATCH")
	req.Header.Set("Access-Control-Request-Headers", "X-Trace-Token, Content-Type")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 OPTIONS request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 OPTIONS response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("OPTIONS response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 OPTIONS TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 OPTIONS TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 OPTIONS negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("HTTP/3 OPTIONS status = %d, want %d; body=%q", resp.StatusCode, http.StatusNoContent, string(body))
	}
	if got := resp.Header.Get("Allow"); got != "GET, POST, PATCH, OPTIONS" {
		t.Fatalf("HTTP/3 OPTIONS Allow = %q, want %q", got, "GET, POST, PATCH, OPTIONS")
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://client.example.test" {
		t.Fatalf("HTTP/3 OPTIONS Access-Control-Allow-Origin = %q, want %q", got, "https://client.example.test")
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "GET, POST, PATCH, OPTIONS" {
		t.Fatalf("HTTP/3 OPTIONS Access-Control-Allow-Methods = %q, want %q", got, "GET, POST, PATCH, OPTIONS")
	}
	if got := resp.Header.Get("Access-Control-Allow-Headers"); got != "X-Trace-Token, Content-Type" {
		t.Fatalf("HTTP/3 OPTIONS Access-Control-Allow-Headers = %q, want %q", got, "X-Trace-Token, Content-Type")
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 OPTIONS Alt-Svc response header")
	}
	if len(body) != 0 {
		t.Fatalf("HTTP/3 OPTIONS response body length = %d, want 0; body=%q", len(body), string(body))
	}

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodOptions {
			t.Fatalf("upstream method = %q, want %q", got.method, http.MethodOptions)
		}
		if got.path != "/h3-options/a/b" {
			t.Fatalf("upstream path = %q, want %q", got.path, "/h3-options/a/b")
		}
		if got.escapedPath != "/h3-options/a%2Fb" {
			t.Fatalf("upstream escaped path = %q, want %q", got.escapedPath, "/h3-options/a%2Fb")
		}
		if got.rawQuery != "preflight=1&encoded=a%2Fb" {
			t.Fatalf("upstream raw query = %q, want %q", got.rawQuery, "preflight=1&encoded=a%2Fb")
		}
		if got.origin != "https://client.example.test" {
			t.Fatalf("upstream Origin = %q, want %q", got.origin, "https://client.example.test")
		}
		if got.accessControlRequestMethod != "PATCH" {
			t.Fatalf("upstream Access-Control-Request-Method = %q, want %q", got.accessControlRequestMethod, "PATCH")
		}
		if got.accessControlRequestHeader != "X-Trace-Token, Content-Type" {
			t.Fatalf("upstream Access-Control-Request-Headers = %q, want %q", got.accessControlRequestHeader, "X-Trace-Token, Content-Type")
		}
		if len(got.body) != 0 {
			t.Fatalf("upstream OPTIONS body length = %d, want 0; body=%q", len(got.body), string(got.body))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 OPTIONS request")
	}
}

func TestHTTP3ServerProxiesResponseTrailers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Trailer", "X-Upstream-Trailer")
		_, _ = io.WriteString(w, "http3 trailer response")
		w.Header().Set("X-Upstream-Trailer", "done")
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-trailers.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-trailers", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 request: %v", err)
	}
	req.Host = rt.Site.Host

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
	}
	if got := string(body); got != "http3 trailer response" {
		t.Fatalf("HTTP/3 response body = %q", got)
	}
	if got := resp.Trailer.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("HTTP/3 response trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
}

func TestHTTP3ServerProxiesSSEResponseStream(t *testing.T) {
	type upstreamObservation struct {
		method     string
		path       string
		rawQuery   string
		accept     string
		forwarded  string
		protoMark  string
		writeError error
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obs := upstreamObservation{
			method:    r.Method,
			path:      r.URL.Path,
			rawQuery:  r.URL.RawQuery,
			accept:    r.Header.Get("Accept"),
			forwarded: r.Header.Get("X-Forwarded-Proto"),
			protoMark: r.Header.Get(dataplane.InternalHTTP3ProtoHeader),
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		if _, err := io.WriteString(w, "data: one\n\n"); err != nil {
			obs.writeError = err
			upstreamSeen <- obs
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(20 * time.Millisecond)
		if _, err := io.WriteString(w, "data: two\n\n"); err != nil {
			obs.writeError = err
			upstreamSeen <- obs
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		upstreamSeen <- obs
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-sse.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-sse/events?stream=1", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 SSE request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Accept", "text/event-stream")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 SSE request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 SSE response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("SSE response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 SSE TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 SSE TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 SSE negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 SSE status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("HTTP/3 SSE Content-Type = %q, want %q", got, "text/event-stream")
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("HTTP/3 SSE Cache-Control = %q, want %q", got, "no-cache")
	}
	if got := resp.Header.Get("Content-Length"); got != "" {
		t.Fatalf("HTTP/3 SSE Content-Length = %q, want empty", got)
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 SSE Alt-Svc response header")
	}
	if got := string(body); got != "data: one\n\ndata: two\n\n" {
		t.Fatalf("HTTP/3 SSE body = %q, want %q", got, "data: one\\n\\ndata: two\\n\\n")
	}

	select {
	case got := <-upstreamSeen:
		if got.writeError != nil {
			t.Fatalf("upstream SSE write error: %v", got.writeError)
		}
		if got.method != http.MethodGet {
			t.Fatalf("upstream SSE method = %q, want %q", got.method, http.MethodGet)
		}
		if got.path != "/h3-sse/events" {
			t.Fatalf("upstream SSE path = %q, want %q", got.path, "/h3-sse/events")
		}
		if got.rawQuery != "stream=1" {
			t.Fatalf("upstream SSE raw query = %q, want %q", got.rawQuery, "stream=1")
		}
		if got.accept != "text/event-stream" {
			t.Fatalf("upstream SSE Accept = %q, want %q", got.accept, "text/event-stream")
		}
		if got.forwarded != "h3" {
			t.Fatalf("upstream SSE X-Forwarded-Proto = %q, want %q", got.forwarded, "h3")
		}
		if got.protoMark != "" {
			t.Fatalf("upstream SSE leaked %s = %q, want empty", dataplane.InternalHTTP3ProtoHeader, got.protoMark)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 SSE request")
	}
}

func TestHTTP3ServerCancelsUpstreamSSEWhenClientClosesResponseBody(t *testing.T) {
	type upstreamObservation struct {
		method    string
		path      string
		rawQuery  string
		accept    string
		forwarded string
		protoMark string
	}

	upstreamStarted := make(chan upstreamObservation, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-sse-cancel/events" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "h3 sse cancel ready")
			return
		}

		upstreamStarted <- upstreamObservation{
			method:    r.Method,
			path:      r.URL.Path,
			rawQuery:  r.URL.RawQuery,
			accept:    r.Header.Get("Accept"),
			forwarded: r.Header.Get("X-Forwarded-Proto"),
			protoMark: r.Header.Get(dataplane.InternalHTTP3ProtoHeader),
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "upstream flusher unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, "data: h3-sse-cancel\n\n"); err != nil {
			return
		}
		flusher.Flush()

		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("HTTP/3 upstream SSE context was not canceled in time")
		}
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-sse-cancel.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
		DisableCompression: true,
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-sse-cancel/events?stream=1", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 SSE cancel request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 SSE cancel request: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 SSE cancel response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 SSE cancel TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 SSE cancel TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 SSE cancel negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 SSE cancel status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("HTTP/3 SSE cancel Content-Type = %q, want %q", got, "text/event-stream")
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("HTTP/3 SSE cancel Cache-Control = %q, want %q", got, "no-cache")
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 SSE cancel Alt-Svc response header")
	}

	buf := make([]byte, len("data: h3-sse-cancel\n\n"))
	n, err := io.ReadFull(resp.Body, buf)
	if err != nil {
		_ = resp.Body.Close()
		t.Fatalf("read HTTP/3 SSE cancel first event: n=%d err=%v", n, err)
	}
	if got := string(buf); got != "data: h3-sse-cancel\n\n" {
		_ = resp.Body.Close()
		t.Fatalf("HTTP/3 SSE cancel first event = %q, want %q", got, "data: h3-sse-cancel\\n\\n")
	}

	select {
	case got := <-upstreamStarted:
		if got.method != http.MethodGet {
			t.Fatalf("upstream HTTP/3 SSE cancel method = %q, want %q", got.method, http.MethodGet)
		}
		if got.path != "/h3-sse-cancel/events" {
			t.Fatalf("upstream HTTP/3 SSE cancel path = %q, want %q", got.path, "/h3-sse-cancel/events")
		}
		if got.rawQuery != "stream=1" {
			t.Fatalf("upstream HTTP/3 SSE cancel raw query = %q, want %q", got.rawQuery, "stream=1")
		}
		if got.accept != "text/event-stream" {
			t.Fatalf("upstream HTTP/3 SSE cancel Accept = %q, want %q", got.accept, "text/event-stream")
		}
		if got.forwarded != "h3" {
			t.Fatalf("upstream HTTP/3 SSE cancel X-Forwarded-Proto = %q, want %q", got.forwarded, "h3")
		}
		if got.protoMark != "" {
			t.Fatalf("upstream HTTP/3 SSE cancel leaked %s = %q, want empty", dataplane.InternalHTTP3ProtoHeader, got.protoMark)
		}
	case <-time.After(2 * time.Second):
		_ = resp.Body.Close()
		t.Fatal("upstream did not observe HTTP/3 SSE cancel request")
	}

	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close HTTP/3 SSE cancel response body: %v", err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HTTP/3 upstream SSE cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/3 upstream SSE was not canceled after client closed response body")
	}

	readyReq, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-sse-cancel-ready", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 SSE cancel ready request: %v", err)
	}
	readyReq.Host = rt.Site.Host
	readyResp, err := client.Do(readyReq)
	if err != nil {
		t.Fatalf("send HTTP/3 SSE cancel ready request after stream cancel: %v", err)
	}
	defer readyResp.Body.Close()
	readyBody, err := io.ReadAll(readyResp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 SSE cancel ready response: %v", err)
	}
	if readyResp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 SSE cancel ready protocol major = %d, want 3", readyResp.ProtoMajor)
	}
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 SSE cancel ready status = %d, want %d; body=%q", readyResp.StatusCode, http.StatusOK, string(readyBody))
	}
	if got := string(readyBody); got != "h3 sse cancel ready" {
		t.Fatalf("HTTP/3 SSE cancel ready body = %q, want %q", got, "h3 sse cancel ready")
	}
}

func TestHTTP3ServerCancelsUpstreamStreamingResponseWhenClientClosesResponseBody(t *testing.T) {
	type upstreamObservation struct {
		method    string
		path      string
		rawQuery  string
		forwarded string
		protoMark string
	}

	const firstChunk = "h3 streaming cancel first chunk\n"

	upstreamStarted := make(chan upstreamObservation, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-stream-cancel/response" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3 stream cancel ready")
			return
		}

		upstreamStarted <- upstreamObservation{
			method:    r.Method,
			path:      r.URL.Path,
			rawQuery:  r.URL.RawQuery,
			forwarded: r.Header.Get("X-Forwarded-Proto"),
			protoMark: r.Header.Get(dataplane.InternalHTTP3ProtoHeader),
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "upstream flusher unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, firstChunk); err != nil {
			return
		}
		flusher.Flush()

		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("HTTP/3 upstream streaming response context was not canceled in time")
		}
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-stream-cancel.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
		DisableCompression: true,
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-stream-cancel/response?stream=1", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 streaming cancel request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 streaming cancel request: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 streaming cancel response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 streaming cancel TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 streaming cancel TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 streaming cancel negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 streaming cancel status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("HTTP/3 streaming cancel Content-Type = %q, want %q", got, "text/plain; charset=utf-8")
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("HTTP/3 streaming cancel Cache-Control = %q, want %q", got, "no-cache")
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 streaming cancel Alt-Svc response header")
	}

	buf := make([]byte, len(firstChunk))
	n, err := io.ReadFull(resp.Body, buf)
	if err != nil {
		_ = resp.Body.Close()
		t.Fatalf("read HTTP/3 streaming cancel first chunk: n=%d err=%v", n, err)
	}
	if got := string(buf); got != firstChunk {
		_ = resp.Body.Close()
		t.Fatalf("HTTP/3 streaming cancel first chunk = %q, want %q", got, firstChunk)
	}

	select {
	case got := <-upstreamStarted:
		if got.method != http.MethodGet {
			t.Fatalf("upstream HTTP/3 streaming cancel method = %q, want %q", got.method, http.MethodGet)
		}
		if got.path != "/h3-stream-cancel/response" {
			t.Fatalf("upstream HTTP/3 streaming cancel path = %q, want %q", got.path, "/h3-stream-cancel/response")
		}
		if got.rawQuery != "stream=1" {
			t.Fatalf("upstream HTTP/3 streaming cancel raw query = %q, want %q", got.rawQuery, "stream=1")
		}
		if got.forwarded != "h3" {
			t.Fatalf("upstream HTTP/3 streaming cancel X-Forwarded-Proto = %q, want %q", got.forwarded, "h3")
		}
		if got.protoMark != "" {
			t.Fatalf("upstream HTTP/3 streaming cancel leaked %s = %q, want empty", dataplane.InternalHTTP3ProtoHeader, got.protoMark)
		}
	case <-time.After(2 * time.Second):
		_ = resp.Body.Close()
		t.Fatal("upstream did not observe HTTP/3 streaming cancel request")
	}

	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close HTTP/3 streaming cancel response body: %v", err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HTTP/3 upstream streaming cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/3 upstream streaming response was not canceled after client closed response body")
	}

	readyReq, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-stream-cancel-ready", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 streaming cancel ready request: %v", err)
	}
	readyReq.Host = rt.Site.Host
	readyResp, err := client.Do(readyReq)
	if err != nil {
		t.Fatalf("send HTTP/3 streaming cancel ready request after stream cancel: %v", err)
	}
	defer readyResp.Body.Close()
	readyBody, err := io.ReadAll(readyResp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 streaming cancel ready response: %v", err)
	}
	if readyResp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 streaming cancel ready protocol major = %d, want 3", readyResp.ProtoMajor)
	}
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 streaming cancel ready status = %d, want %d; body=%q", readyResp.StatusCode, http.StatusOK, string(readyBody))
	}
	if got := string(readyBody); got != "h3 stream cancel ready" {
		t.Fatalf("HTTP/3 streaming cancel ready body = %q, want %q", got, "h3 stream cancel ready")
	}
}

func TestHTTP3ServerShutdownClosesActiveStreamAndCancelsUpstream(t *testing.T) {
	type upstreamObservation struct {
		method    string
		path      string
		rawQuery  string
		forwarded string
		protoMark string
	}

	const firstChunk = "h3 shutdown active stream first chunk\n"

	upstreamStarted := make(chan upstreamObservation, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/h3-shutdown/stream" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "h3 shutdown ready")
			return
		}

		upstreamStarted <- upstreamObservation{
			method:    r.Method,
			path:      r.URL.Path,
			rawQuery:  r.URL.RawQuery,
			forwarded: r.Header.Get("X-Forwarded-Proto"),
			protoMark: r.Header.Get(dataplane.InternalHTTP3ProtoHeader),
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "upstream flusher unavailable", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		if _, err := io.WriteString(w, firstChunk); err != nil {
			return
		}
		flusher.Flush()

		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("HTTP/3 upstream active stream context was not canceled during shutdown")
		}
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-shutdown.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
		DisableCompression: true,
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-shutdown/stream?stream=1", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 shutdown stream request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 shutdown stream request: %v", err)
	}
	t.Cleanup(func() {
		_ = resp.Body.Close()
	})
	if resp.ProtoMajor != 3 {
		t.Fatalf("HTTP/3 shutdown stream response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 shutdown stream TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 shutdown stream TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 shutdown stream negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 shutdown stream status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("HTTP/3 shutdown stream Content-Type = %q, want %q", got, "text/plain; charset=utf-8")
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("HTTP/3 shutdown stream Cache-Control = %q, want %q", got, "no-cache")
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 shutdown stream Alt-Svc response header")
	}

	buf := make([]byte, len(firstChunk))
	n, err := io.ReadFull(resp.Body, buf)
	if err != nil {
		t.Fatalf("read HTTP/3 shutdown stream first chunk: n=%d err=%v", n, err)
	}
	if got := string(buf); got != firstChunk {
		t.Fatalf("HTTP/3 shutdown stream first chunk = %q, want %q", got, firstChunk)
	}

	select {
	case got := <-upstreamStarted:
		if got.method != http.MethodGet {
			t.Fatalf("upstream HTTP/3 shutdown stream method = %q, want %q", got.method, http.MethodGet)
		}
		if got.path != "/h3-shutdown/stream" {
			t.Fatalf("upstream HTTP/3 shutdown stream path = %q, want %q", got.path, "/h3-shutdown/stream")
		}
		if got.rawQuery != "stream=1" {
			t.Fatalf("upstream HTTP/3 shutdown stream raw query = %q, want %q", got.rawQuery, "stream=1")
		}
		if got.forwarded != "h3" {
			t.Fatalf("upstream HTTP/3 shutdown stream X-Forwarded-Proto = %q, want %q", got.forwarded, "h3")
		}
		if got.protoMark != "" {
			t.Fatalf("upstream HTTP/3 shutdown stream leaked %s = %q, want empty", dataplane.InternalHTTP3ProtoHeader, got.protoMark)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 shutdown stream request")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	if err := h3Srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("HTTP/3 shutdown active stream error: %v", err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("HTTP/3 upstream active stream shutdown error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/3 upstream active stream was not canceled after shutdown deadline")
	}
}

func TestHTTP3ServerCompressesResponseForGzipClient(t *testing.T) {
	responseBody := []byte(strings.Repeat("http3 gzip response body ", 160))
	type upstreamObservation struct {
		method         string
		path           string
		rawQuery       string
		acceptEncoding string
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSeen <- upstreamObservation{
			method:         r.Method,
			path:           r.URL.Path,
			rawQuery:       r.URL.RawQuery,
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
		_, _ = w.Write(responseBody)
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-gzip.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:                       1,
		Protection:                     protection,
		HTTP2Config:                    snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults:                    snapshotpkg.DefaultTLSDefaults(),
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: true,
		ResponseCompressionMinBytes:    snapshotpkg.DefaultResponseCompressionMinBytes,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
		DisableCompression: true,
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-gzip/a%2Fb?keep=1;semi=2&encoded=a%2Fb", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 gzip request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 gzip request: %v", err)
	}
	defer resp.Body.Close()
	compressedBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 gzip response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("gzip response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 gzip TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 gzip TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 gzip negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 gzip status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(compressedBody))
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("HTTP/3 gzip Content-Encoding = %q, want %q", got, "gzip")
	}
	if got := resp.Header.Get("Vary"); got != "Accept-Encoding" {
		t.Fatalf("HTTP/3 gzip Vary = %q, want %q", got, "Accept-Encoding")
	}
	if got := resp.Header.Get("Content-Length"); got != "" {
		t.Fatalf("HTTP/3 gzip Content-Length = %q, want empty", got)
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 gzip Alt-Svc response header")
	}
	if len(compressedBody) >= len(responseBody) {
		t.Fatalf("HTTP/3 gzip body length = %d, want smaller than %d", len(compressedBody), len(responseBody))
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(compressedBody))
	if err != nil {
		t.Fatalf("open HTTP/3 gzip response body: %v", err)
	}
	decodedBody, err := io.ReadAll(gzipReader)
	closeErr := gzipReader.Close()
	if err != nil {
		t.Fatalf("decode HTTP/3 gzip response body: %v", err)
	}
	if closeErr != nil {
		t.Fatalf("close HTTP/3 gzip response body: %v", closeErr)
	}
	if !bytes.Equal(decodedBody, responseBody) {
		t.Fatalf("HTTP/3 gzip decoded body mismatch: got %d bytes want %d bytes", len(decodedBody), len(responseBody))
	}

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodGet {
			t.Fatalf("upstream gzip method = %q, want %q", got.method, http.MethodGet)
		}
		if got.path != "/h3-gzip/a/b" {
			t.Fatalf("upstream gzip path = %q, want %q", got.path, "/h3-gzip/a/b")
		}
		if got.rawQuery != "keep=1;semi=2&encoded=a%2Fb" {
			t.Fatalf("upstream gzip raw query = %q, want %q", got.rawQuery, "keep=1;semi=2&encoded=a%2Fb")
		}
		if got.acceptEncoding != "gzip" {
			t.Fatalf("upstream gzip Accept-Encoding = %q, want %q", got.acceptEncoding, "gzip")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 gzip request")
	}
}

func TestHTTP3ServerDoesNotInjectAcceptEncodingWhenClientOmitsIt(t *testing.T) {
	responseBody := []byte(strings.Repeat("http3 plain response body ", 160))
	type upstreamObservation struct {
		method         string
		path           string
		rawQuery       string
		acceptEncoding string
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSeen <- upstreamObservation{
			method:         r.Method,
			path:           r.URL.Path,
			rawQuery:       r.URL.RawQuery,
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
		_, _ = w.Write(responseBody)
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-no-accept-encoding.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:                       1,
		Protection:                     protection,
		HTTP2Config:                    snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults:                    snapshotpkg.DefaultTLSDefaults(),
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: true,
		ResponseCompressionMinBytes:    snapshotpkg.DefaultResponseCompressionMinBytes,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
		DisableCompression: true,
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-no-ae/a%2Fb?keep=1;semi=2&encoded=a%2Fb", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 no Accept-Encoding request: %v", err)
	}
	req.Host = rt.Site.Host

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 no Accept-Encoding request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 no Accept-Encoding response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("no Accept-Encoding response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 no Accept-Encoding TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 no Accept-Encoding TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 no Accept-Encoding negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 no Accept-Encoding status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("HTTP/3 no Accept-Encoding Content-Encoding = %q, want empty", got)
	}
	if got := resp.Header.Get("Vary"); got != "" {
		t.Fatalf("HTTP/3 no Accept-Encoding Vary = %q, want empty", got)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(responseBody)) {
		t.Fatalf("HTTP/3 no Accept-Encoding Content-Length = %q, want %q", got, strconv.Itoa(len(responseBody)))
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 no Accept-Encoding Alt-Svc response header")
	}
	if !bytes.Equal(body, responseBody) {
		t.Fatalf("HTTP/3 no Accept-Encoding body mismatch: got %d bytes want %d bytes", len(body), len(responseBody))
	}

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodGet {
			t.Fatalf("upstream no Accept-Encoding method = %q, want %q", got.method, http.MethodGet)
		}
		if got.path != "/h3-no-ae/a/b" {
			t.Fatalf("upstream no Accept-Encoding path = %q, want %q", got.path, "/h3-no-ae/a/b")
		}
		if got.rawQuery != "keep=1;semi=2&encoded=a%2Fb" {
			t.Fatalf("upstream no Accept-Encoding raw query = %q, want %q", got.rawQuery, "keep=1;semi=2&encoded=a%2Fb")
		}
		if got.acceptEncoding != "" {
			t.Fatalf("upstream no Accept-Encoding header = %q, want empty", got.acceptEncoding)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 no Accept-Encoding request")
	}
}

func TestHTTP3ServerCompressesResponseForBrotliClient(t *testing.T) {
	responseBody := []byte(strings.Repeat("http3 brotli response body ", 180))
	type upstreamObservation struct {
		method         string
		path           string
		rawQuery       string
		acceptEncoding string
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSeen <- upstreamObservation{
			method:         r.Method,
			path:           r.URL.Path,
			rawQuery:       r.URL.RawQuery,
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
		_, _ = w.Write(responseBody)
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-brotli.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:                       1,
		Protection:                     protection,
		HTTP2Config:                    snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults:                    snapshotpkg.DefaultTLSDefaults(),
		BrotliEnabled:                  true,
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: true,
		ResponseCompressionMinBytes:    snapshotpkg.DefaultResponseCompressionMinBytes,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
		DisableCompression: true,
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-brotli/a%2Fb?keep=1;semi=2&encoded=a%2Fb", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 brotli request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Accept-Encoding", "br, gzip")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 brotli request: %v", err)
	}
	defer resp.Body.Close()
	compressedBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 brotli response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("brotli response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 brotli TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 brotli TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 brotli negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 brotli status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(compressedBody))
	}
	if got := resp.Header.Get("Content-Encoding"); got != "br" {
		t.Fatalf("HTTP/3 brotli Content-Encoding = %q, want %q", got, "br")
	}
	if got := resp.Header.Get("Vary"); got != "Accept-Encoding" {
		t.Fatalf("HTTP/3 brotli Vary = %q, want %q", got, "Accept-Encoding")
	}
	if got := resp.Header.Get("Content-Length"); got != "" {
		t.Fatalf("HTTP/3 brotli Content-Length = %q, want empty", got)
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 brotli Alt-Svc response header")
	}
	if len(compressedBody) >= len(responseBody) {
		t.Fatalf("HTTP/3 brotli body length = %d, want smaller than %d", len(compressedBody), len(responseBody))
	}
	decodedBody, err := io.ReadAll(brotli.NewReader(bytes.NewReader(compressedBody)))
	if err != nil {
		t.Fatalf("decode HTTP/3 brotli response body: %v", err)
	}
	if !bytes.Equal(decodedBody, responseBody) {
		t.Fatalf("HTTP/3 brotli decoded body mismatch: got %d bytes want %d bytes", len(decodedBody), len(responseBody))
	}

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodGet {
			t.Fatalf("upstream brotli method = %q, want %q", got.method, http.MethodGet)
		}
		if got.path != "/h3-brotli/a/b" {
			t.Fatalf("upstream brotli path = %q, want %q", got.path, "/h3-brotli/a/b")
		}
		if got.rawQuery != "keep=1;semi=2&encoded=a%2Fb" {
			t.Fatalf("upstream brotli raw query = %q, want %q", got.rawQuery, "keep=1;semi=2&encoded=a%2Fb")
		}
		if got.acceptEncoding != "br, gzip" {
			t.Fatalf("upstream brotli Accept-Encoding = %q, want %q", got.acceptEncoding, "br, gzip")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 brotli request")
	}
}

func TestHTTP3ServerSkipsGzipCompressionForNoTransformResponse(t *testing.T) {
	responseBody := []byte(strings.Repeat("http3 no-transform response body ", 160))
	type upstreamObservation struct {
		method         string
		path           string
		rawQuery       string
		acceptEncoding string
	}

	upstreamSeen := make(chan upstreamObservation, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSeen <- upstreamObservation{
			method:         r.Method,
			path:           r.URL.Path,
			rawQuery:       r.URL.RawQuery,
			acceptEncoding: r.Header.Get("Accept-Encoding"),
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "private, no-transform")
		w.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
		_, _ = w.Write(responseBody)
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-no-transform.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:                       1,
		Protection:                     protection,
		HTTP2Config:                    snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults:                    snapshotpkg.DefaultTLSDefaults(),
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: true,
		ResponseCompressionMinBytes:    snapshotpkg.DefaultResponseCompressionMinBytes,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
		DisableCompression: true,
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+udpBind+"/h3-no-transform/a%2Fb?keep=1;semi=2&encoded=a%2Fb", nil)
	if err != nil {
		t.Fatalf("build HTTP/3 no-transform request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 no-transform request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 no-transform response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("no-transform response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected HTTP/3 no-transform TLS connection state")
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("HTTP/3 no-transform TLS version = %#x, want TLS 1.3", resp.TLS.Version)
	}
	if resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("HTTP/3 no-transform negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h3")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 no-transform status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("HTTP/3 no-transform Content-Encoding = %q, want empty", got)
	}
	if got := resp.Header.Get("Vary"); got != "" {
		t.Fatalf("HTTP/3 no-transform Vary = %q, want empty", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "private, no-transform" {
		t.Fatalf("HTTP/3 no-transform Cache-Control = %q, want %q", got, "private, no-transform")
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(responseBody)) {
		t.Fatalf("HTTP/3 no-transform Content-Length = %q, want %q", got, strconv.Itoa(len(responseBody)))
	}
	if got := resp.Header.Get("Alt-Svc"); got == "" {
		t.Fatal("expected HTTP/3 no-transform Alt-Svc response header")
	}
	if !bytes.Equal(body, responseBody) {
		t.Fatalf("HTTP/3 no-transform body mismatch: got %d bytes want %d bytes", len(body), len(responseBody))
	}

	select {
	case got := <-upstreamSeen:
		if got.method != http.MethodGet {
			t.Fatalf("upstream no-transform method = %q, want %q", got.method, http.MethodGet)
		}
		if got.path != "/h3-no-transform/a/b" {
			t.Fatalf("upstream no-transform path = %q, want %q", got.path, "/h3-no-transform/a/b")
		}
		if got.rawQuery != "keep=1;semi=2&encoded=a%2Fb" {
			t.Fatalf("upstream no-transform raw query = %q, want %q", got.rawQuery, "keep=1;semi=2&encoded=a%2Fb")
		}
		if got.acceptEncoding != "gzip" {
			t.Fatalf("upstream no-transform Accept-Encoding = %q, want %q", got.acceptEncoding, "gzip")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 no-transform request")
	}
}

func TestHTTP3ServerProxiesRequestTrailersToUpstream(t *testing.T) {
	upstreamResult := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			upstreamResult <- "read upstream request body: " + err.Error()
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		if got := string(body); got != "http3 request trailer payload" {
			upstreamResult <- "upstream request body = " + got
			http.Error(w, "unexpected body", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Te"); got != "trailers" {
			upstreamResult <- "upstream request Te = " + got
			http.Error(w, "unexpected TE", http.StatusBadRequest)
			return
		}
		if got := r.Trailer.Get("X-Trace"); got != "done" {
			upstreamResult <- "upstream request trailer X-Trace = " + got
			http.Error(w, "unexpected trailer", http.StatusBadRequest)
			return
		}

		upstreamResult <- ""
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "http3 request trailer upstream ok")
	}))
	defer upstream.Close()

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve TCP bind: %v", err)
	}
	tcpBind := tcpLn.Addr().String()
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("release TCP bind: %v", err)
	}
	udpBind := reserveUDPBind(t)

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: tcpBind,
		Site: store.Site{
			ID:         1,
			Host:       "h3-request-trailers.example.test",
			Bind:       tcpBind,
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		UpstreamURLs: []string{upstream.URL},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			IPv6Enabled:    false,
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      udpBind,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(tcpBind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	dataSrv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   tcpBind,
	})
	if dataSrv == nil {
		t.Fatal("expected data server")
	}
	go dataSrv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !dataSrv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dataSrv.Shutdown(ctx)
	})

	routeTable := buildHTTP3RouteTable([]snapshotpkg.SiteRuntime{rt})
	h3Srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind:       udpBind,
		RouteTable: routeTable,
		TLSConfig:  buildHTTP3ServerTLSConfig(udpBind, []snapshotpkg.SiteRuntime{rt}, sn),
		Log:        slog.Default(),
	})
	if h3Srv == nil {
		t.Fatal("expected HTTP/3 server")
	}
	go h3Srv.Spin()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = h3Srv.Shutdown(ctx)
	})

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         rt.Site.Host,
		},
	}
	t.Cleanup(func() {
		_ = tr.Close()
	})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+udpBind+"/h3-request-trailers", io.NopCloser(bytes.NewBufferString("http3 request trailer payload")))
	if err != nil {
		t.Fatalf("build HTTP/3 request: %v", err)
	}
	req.Host = rt.Site.Host
	req.ContentLength = -1
	req.Trailer = http.Header{
		"X-Trace": []string{"done"},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send HTTP/3 request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read HTTP/3 response body: %v", err)
	}
	if resp.ProtoMajor != 3 {
		t.Fatalf("response protocol major = %d, want 3", resp.ProtoMajor)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/3 status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
	}
	if got := string(body); got != "http3 request trailer upstream ok" {
		t.Fatalf("HTTP/3 response body = %q", got)
	}
	select {
	case result := <-upstreamResult:
		if result != "" {
			t.Fatal(result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not observe HTTP/3 request trailers")
	}
}

func TestInstrumentHTTP3TLSConfigStoresClientHelloFingerprint(t *testing.T) {
	store := newHTTP3HandshakeFingerprintStore()
	cfg := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &tls.Certificate{}, nil
		},
	}
	instrumentHTTP3TLSConfig(cfg, store)

	hello := &tls.ClientHelloInfo{
		Conn: &testHTTP3ClientHelloConn{
			localAddr:  testHTTP3NetAddr("127.0.0.1:443"),
			remoteAddr: testHTTP3NetAddr("203.0.113.10:12345"),
		},
		CipherSuites:     []uint16{0x0a0a, 4865, 4866},
		ServerName:       "client.example",
		SupportedCurves:  []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:  []uint8{0},
		SignatureSchemes: []tls.SignatureScheme{tls.PSSWithSHA256},
		SupportedProtos:  []string{"h3", "h2"},
		SupportedVersions: []uint16{
			0x0a0a,
			tls.VersionTLS13,
			tls.VersionTLS12,
		},
		Extensions: []uint16{0x0a0a, 0, 16, 10, 11, 13, 43, 45, 51},
	}

	if _, err := cfg.GetCertificate(hello); err != nil {
		t.Fatalf("GetCertificate() error: %v", err)
	}

	fp, ok := store.Take(hello.Conn.LocalAddr(), hello.Conn.RemoteAddr())
	if !ok {
		t.Fatal("expected stored HTTP/3 client hello fingerprint")
	}
	if fp.JA3 == "" || fp.JA3Hash == "" || fp.JA4 == "" {
		t.Fatalf("expected complete fingerprint, got %+v", fp)
	}
	if fp.TLSVersion != "TLS13" {
		t.Fatalf("TLSVersion = %q, want %q", fp.TLSVersion, "TLS13")
	}
	if fp.SNI != "client.example" {
		t.Fatalf("SNI = %q, want %q", fp.SNI, "client.example")
	}
	if len(fp.ALPN) != 2 || fp.ALPN[0] != "h3" || fp.ALPN[1] != "h2" {
		t.Fatalf("ALPN = %+v", fp.ALPN)
	}
	if len(fp.CipherSuites) != 3 || fp.CipherSuites[1] != 4865 || fp.CipherSuites[2] != 4866 {
		t.Fatalf("CipherSuites = %+v", fp.CipherSuites)
	}
	if fp.JA4[0] != 'q' {
		t.Fatalf("JA4 = %q, want QUIC-prefixed fingerprint", fp.JA4)
	}
}

func TestInstrumentHTTP3TLSConfigStoresClientHelloFingerprintWithoutExistingHooks(t *testing.T) {
	store := newHTTP3HandshakeFingerprintStore()
	cfg := &tls.Config{}
	instrumentHTTP3TLSConfig(cfg, store)

	if cfg.GetConfigForClient == nil {
		t.Fatal("expected HTTP/3 ClientHello hook on TLS config without existing hooks")
	}
	if cfg.GetCertificate != nil {
		t.Fatal("instrumentation should not create a certificate selector")
	}

	hello := &tls.ClientHelloInfo{
		Conn: &testHTTP3ClientHelloConn{
			localAddr:  testHTTP3NetAddr("127.0.0.1:443"),
			remoteAddr: testHTTP3NetAddr("203.0.113.20:23456"),
		},
		CipherSuites:      []uint16{4865, 4866},
		ServerName:        "hookless.example",
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SignatureSchemes:  []tls.SignatureScheme{tls.PSSWithSHA256},
		SupportedProtos:   []string{"h3"},
		SupportedVersions: []uint16{tls.VersionTLS13},
		Extensions:        []uint16{0, 16, 10, 11, 13, 43, 45, 51},
	}

	next, err := cfg.GetConfigForClient(hello)
	if err != nil {
		t.Fatalf("GetConfigForClient() error: %v", err)
	}
	if next != nil {
		t.Fatalf("GetConfigForClient() returned config %#v, want nil", next)
	}

	fp, ok := store.Take(hello.Conn.LocalAddr(), hello.Conn.RemoteAddr())
	if !ok {
		t.Fatal("expected stored HTTP/3 ClientHello fingerprint")
	}
	if fp.SNI != "hookless.example" {
		t.Fatalf("SNI = %q, want %q", fp.SNI, "hookless.example")
	}
	if fp.JA3 == "" || fp.JA3Hash == "" || fp.JA4 == "" {
		t.Fatalf("expected JA3, JA3 hash and JA4, got %+v", fp)
	}
	if fp.JA4[0] != 'q' {
		t.Fatalf("JA4 = %q, want QUIC-prefixed fingerprint", fp.JA4)
	}
}

func TestApplyHTTP3ProxyTLSHeadersUsesContextFingerprint(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.com/resource", nil)
	req = req.WithContext(contextWithHTTP3TLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		JA3:          "771,4865-4866,0-16-43,29,0",
		JA3Hash:      "0123456789abcdef0123456789abcdef",
		JA4:          "q13d0511h3_fea09b2e4d67_1234567890ab",
		TLSVersion:   "TLS13",
		SNI:          "client.example",
		ALPN:         []string{"h3", "h2"},
		CipherSuites: []uint16{4865, 4866},
		Extensions:   []uint16{0, 16, 43},
		Curves:       []uint16{29, 23},
		PointFormats: []uint8{0},
	}))
	req.TLS = &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		ServerName:         "client.example",
		NegotiatedProtocol: "h3",
	}
	req.Header.Set(dataplane.InternalHTTP3TLSJA3Header, "stale")

	clearInternalHTTP3TLSHeaders(req.Header)
	applyHTTP3ProxyTLSHeaders(req)

	if got := req.Header.Get(dataplane.InternalHTTP3TLSVersionHeader); got != "TLS13" {
		t.Fatalf("TLS version header = %q, want %q", got, "TLS13")
	}
	if got := req.Header.Get(dataplane.InternalHTTP3TLSSNIHeader); got != "client.example" {
		t.Fatalf("TLS SNI header = %q, want %q", got, "client.example")
	}
	if got := req.Header.Get(dataplane.InternalHTTP3TLSALPNHeader); got != "h3" {
		t.Fatalf("TLS ALPN header = %q, want %q", got, "h3")
	}
	if got := req.Header.Get(dataplane.InternalHTTP3TLSJA3Header); got != "771,4865-4866,0-16-43,29,0" {
		t.Fatalf("TLS JA3 header = %q", got)
	}
	if got := req.Header.Get(dataplane.InternalHTTP3TLSJA3HashHeader); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("TLS JA3 hash header = %q", got)
	}
	if got := req.Header.Get(dataplane.InternalHTTP3TLSJA4Header); got != "q13d0511h3_fea09b2e4d67_1234567890ab" {
		t.Fatalf("TLS JA4 header = %q", got)
	}
	if got := req.Header.Get(dataplane.InternalHTTP3TLSCipherSuitesHeader); got != "4865,4866" {
		t.Fatalf("TLS cipher suites header = %q", got)
	}
	if got := req.Header.Get(dataplane.InternalHTTP3TLSExtensionsHeader); got != "0,16,43" {
		t.Fatalf("TLS extensions header = %q", got)
	}
	if got := req.Header.Get(dataplane.InternalHTTP3TLSCurvesHeader); got != "29,23" {
		t.Fatalf("TLS curves header = %q", got)
	}
	if got := req.Header.Get(dataplane.InternalHTTP3TLSPointFormatsHeader); got != "0" {
		t.Fatalf("TLS point formats header = %q", got)
	}
}

func TestBuildHTTP3ServerTLSConfigReturnsOCSPStapledCertificate(t *testing.T) {
	certPEM, keyPEM, err := acmepkg.GenerateSelfSignedPEM("h3-ocsp.example.test", []string{"h3-ocsp.example.test"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	ocspDER := []byte{0x30, 0x03, 0x0a, 0x01, 0x00}
	rt := snapshotpkg.SiteRuntime{
		Bind: "127.0.0.1:8443",
		Site: store.Site{
			ID:         1,
			Host:       "h3-ocsp.example.test",
			Bind:       "127.0.0.1:8443",
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		Certificate: &store.Certificate{
			Name:          "h3-ocsp",
			CertPEM:       certPEM,
			KeyPEM:        keyPEM,
			OCSPStaplePEM: string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: ocspDER})),
		},
		NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:     snapshotpkg.DefaultTLSDefaults(),
	}
	sn := &snapshotpkg.Snapshot{
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(rt.Bind, rt.Site.Host): rt,
		},
	}

	cfg := buildHTTP3ServerTLSConfig("127.0.0.1:8443", []snapshotpkg.SiteRuntime{rt}, sn)
	if cfg == nil || cfg.GetCertificate == nil {
		t.Fatalf("expected HTTP/3 TLS config with GetCertificate, got %#v", cfg)
	}
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "h3-ocsp.example.test"})
	if err != nil {
		t.Fatalf("GetCertificate() error: %v", err)
	}
	if cert == nil || !bytes.Equal(cert.OCSPStaple, ocspDER) {
		t.Fatalf("OCSP staple = %x, want %x", cert.OCSPStaple, ocspDER)
	}
}

func TestBuildHTTP3ServerTLSConfigUsesRouteBindCertificate(t *testing.T) {
	const (
		udpBind = "127.0.0.1:18443"
		bindA   = "127.0.0.1:10443"
		bindB   = "127.0.0.1:11443"
		hostA   = "h3-cert-a.example.test"
		hostB   = "h3-cert-b.example.test"
	)
	certAPEM, keyAPEM, certA := mustHTTP3TestCertificate(t, hostA)
	certBPEM, keyBPEM, certB := mustHTTP3TestCertificate(t, hostB)
	tlsDefaults := snapshotpkg.DefaultTLSDefaults()
	networkDefaults := snapshotpkg.NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      udpBind,
		DefaultALPN:    "h2,h3,http/1.1",
		DefaultNetwork: "tcp",
	}
	rtA := snapshotpkg.SiteRuntime{
		Bind: bindA,
		Site: store.Site{
			ID:         1,
			Host:       hostA,
			Bind:       bindA,
			TLSEnabled: true,
			ALPN:       "h2,h3,http/1.1",
		},
		Certificate: &store.Certificate{Name: "h3-cert-a", CertPEM: certAPEM, KeyPEM: keyAPEM},
		TLSDefaults: tlsDefaults, NetworkDefaults: networkDefaults,
	}
	rtB := snapshotpkg.SiteRuntime{
		Bind: bindB,
		Site: store.Site{
			ID:         2,
			Host:       hostB,
			Bind:       bindB,
			TLSEnabled: true,
			ALPN:       "h2,h3,http/1.1",
		},
		Certificate: &store.Certificate{Name: "h3-cert-b", CertPEM: certBPEM, KeyPEM: keyBPEM},
		TLSDefaults: tlsDefaults, NetworkDefaults: networkDefaults,
	}
	runtimes := []snapshotpkg.SiteRuntime{rtA, rtB}
	sn := &snapshotpkg.Snapshot{
		TLSDefaults: tlsDefaults,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bindA, hostA): rtA,
			snapshotpkg.SiteMapKey(bindB, hostB): rtB,
		},
		SiteTLSCertBySNI: map[string]tls.Certificate{
			snapshotpkg.SNICertKey(bindA, hostA): certA,
			snapshotpkg.SNICertKey(bindB, hostB): certB,
		},
	}

	cfg := buildHTTP3ServerTLSConfig(udpBind, runtimes, sn)
	if cfg == nil || cfg.GetCertificate == nil {
		t.Fatalf("expected HTTP/3 TLS config with GetCertificate, got %#v", cfg)
	}
	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: hostB})
	if err != nil {
		t.Fatalf("GetCertificate() error: %v", err)
	}
	if got == nil || !bytes.Equal(got.Certificate[0], certB.Certificate[0]) {
		t.Fatalf("HTTP/3 SNI %s certificate did not match bind B certificate", hostB)
	}
}

func TestBuildHTTP3ServerTLSConfigUsesSelfSignedForConflictingSNI(t *testing.T) {
	const (
		udpBind      = "127.0.0.1:18443"
		bindA        = "127.0.0.1:10443"
		bindB        = "127.0.0.1:11443"
		conflictHost = "h3-conflict.example.test"
	)
	certAPEM, keyAPEM, certA := mustHTTP3TestCertificate(t, conflictHost)
	tlsDefaults := snapshotpkg.DefaultTLSDefaults()
	networkDefaults := snapshotpkg.NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      udpBind,
		DefaultALPN:    "h2,h3,http/1.1",
		DefaultNetwork: "tcp",
	}
	rtA := snapshotpkg.SiteRuntime{
		Bind: bindA,
		Site: store.Site{
			ID:         1,
			Host:       conflictHost,
			Bind:       bindA,
			TLSEnabled: true,
			ALPN:       "h2,h3,http/1.1",
		},
		Certificate: &store.Certificate{Name: "h3-conflict-a", CertPEM: certAPEM, KeyPEM: keyAPEM},
		TLSDefaults: tlsDefaults, NetworkDefaults: networkDefaults,
	}
	rtB := snapshotpkg.SiteRuntime{
		Bind: bindB,
		Site: store.Site{
			ID:         2,
			Host:       conflictHost,
			Bind:       bindB,
			TLSEnabled: true,
			ALPN:       "h2,h3,http/1.1",
		},
		TLSDefaults: tlsDefaults, NetworkDefaults: networkDefaults,
	}
	runtimes := []snapshotpkg.SiteRuntime{rtA, rtB}
	sn := &snapshotpkg.Snapshot{
		TLSDefaults: tlsDefaults,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bindA, conflictHost): rtA,
			snapshotpkg.SiteMapKey(bindB, conflictHost): rtB,
		},
		SiteTLSCertBySNI: map[string]tls.Certificate{
			snapshotpkg.SNICertKey(bindA, conflictHost): certA,
		},
	}

	cfg := buildHTTP3ServerTLSConfig(udpBind, runtimes, sn)
	if cfg == nil || cfg.GetCertificate == nil {
		t.Fatalf("expected HTTP/3 TLS config with GetCertificate, got %#v", cfg)
	}
	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: conflictHost})
	if err != nil {
		t.Fatalf("GetCertificate() error: %v", err)
	}
	if got == nil {
		t.Fatal("expected self-signed certificate for conflicting HTTP/3 SNI")
	}
	if bytes.Equal(got.Certificate[0], certA.Certificate[0]) {
		t.Fatal("conflicting HTTP/3 SNI returned a route-conflicted site certificate")
	}
}

func TestBuildHTTP3ServerTLSConfigAppliesSessionTicketSwitch(t *testing.T) {
	tlsDefaults := snapshotpkg.DefaultTLSDefaults()
	tlsDefaults.SessionTicketsEnabled = false
	rt := snapshotpkg.SiteRuntime{
		Bind: "127.0.0.1:8443",
		Site: store.Site{
			ID:         1,
			Host:       "h3-ticket.example.test",
			Bind:       "127.0.0.1:8443",
			TLSEnabled: true,
			ALPN:       "h3,h2,http/1.1",
		},
		NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:     tlsDefaults,
	}
	sn := &snapshotpkg.Snapshot{
		TLSDefaults: tlsDefaults,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(rt.Bind, rt.Site.Host): rt,
		},
	}

	cfg := buildHTTP3ServerTLSConfig("127.0.0.1:8443", []snapshotpkg.SiteRuntime{rt}, sn)
	if cfg == nil {
		t.Fatal("expected HTTP/3 TLS config")
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("session_tickets_enabled=false should set SessionTicketsDisabled=true")
	}
}

func TestHTTP3ListenerFingerprintIncludesSessionTicketSwitch(t *testing.T) {
	buildSnapshot := func(sessionTicketsEnabled bool) (*snapshotpkg.Snapshot, []snapshotpkg.SiteRuntime, http3RouteTable) {
		tlsDefaults := snapshotpkg.DefaultTLSDefaults()
		tlsDefaults.SessionTicketsEnabled = sessionTicketsEnabled
		rt := snapshotpkg.SiteRuntime{
			Bind: "127.0.0.1:8443",
			Site: store.Site{
				ID:         1,
				Host:       "h3-ticket.example.test",
				Bind:       "127.0.0.1:8443",
				TLSEnabled: true,
				ALPN:       "h3,h2,http/1.1",
			},
			NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
			TLSDefaults:     tlsDefaults,
		}
		runtimes := []snapshotpkg.SiteRuntime{rt}
		return &snapshotpkg.Snapshot{
			TLSDefaults: tlsDefaults,
			Sites: map[string]snapshotpkg.SiteRuntime{
				snapshotpkg.SiteMapKey(rt.Bind, rt.Site.Host): rt,
			},
		}, runtimes, buildHTTP3RouteTable(runtimes)
	}

	baseSN, baseRuntimes, baseRouteTable := buildSnapshot(true)
	changedSN, changedRuntimes, changedRouteTable := buildSnapshot(false)
	base := http3ListenerFingerprint("127.0.0.1:8443", baseRuntimes, baseRouteTable, baseSN)
	changed := http3ListenerFingerprint("127.0.0.1:8443", changedRuntimes, changedRouteTable, changedSN)

	if base == changed {
		t.Fatal("changing tls_default_config.session_tickets_enabled should change HTTP/3 listener fingerprint")
	}
}

func TestHTTP3ListenerFingerprintIncludesOCSPStapleMaterial(t *testing.T) {
	certPEM, keyPEM, err := acmepkg.GenerateSelfSignedPEM("h3-ocsp-fingerprint.example.test", []string{"h3-ocsp-fingerprint.example.test"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}

	buildSnapshot := func(ocspDER []byte) (*snapshotpkg.Snapshot, []snapshotpkg.SiteRuntime, http3RouteTable) {
		tlsDefaults := snapshotpkg.DefaultTLSDefaults()
		rt := snapshotpkg.SiteRuntime{
			Bind: "127.0.0.1:8443",
			Site: store.Site{
				ID:         1,
				Host:       "h3-ocsp-fingerprint.example.test",
				Bind:       "127.0.0.1:8443",
				TLSEnabled: true,
				ALPN:       "h3,h2,http/1.1",
			},
			Certificate: &store.Certificate{
				CertPEM:       certPEM,
				KeyPEM:        keyPEM,
				OCSPStaplePEM: string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: ocspDER})),
			},
			NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
			TLSDefaults:     tlsDefaults,
		}
		runtimes := []snapshotpkg.SiteRuntime{rt}
		return &snapshotpkg.Snapshot{
			TLSDefaults: tlsDefaults,
			Sites: map[string]snapshotpkg.SiteRuntime{
				snapshotpkg.SiteMapKey(rt.Bind, rt.Site.Host): rt,
			},
		}, runtimes, buildHTTP3RouteTable(runtimes)
	}

	baseSN, baseRuntimes, baseRouteTable := buildSnapshot([]byte{0x30, 0x03, 0x0a, 0x01, 0x00})
	changedSN, changedRuntimes, changedRouteTable := buildSnapshot([]byte{0x30, 0x03, 0x0a, 0x01, 0x01})
	base := http3ListenerFingerprint("127.0.0.1:8443", baseRuntimes, baseRouteTable, baseSN)
	changed := http3ListenerFingerprint("127.0.0.1:8443", changedRuntimes, changedRouteTable, changedSN)

	if base == changed {
		t.Fatal("changing HTTP/3 certificate OCSP staple material should change listener fingerprint")
	}
}

func reserveUDPBind(t *testing.T) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve UDP bind: %v", err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatalf("release UDP bind: %v", err)
	}
	return addr
}
