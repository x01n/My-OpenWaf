package app

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	acmepkg "My-OpenWaf/internal/acme"
	adminsystem "My-OpenWaf/internal/admin/system"
	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/core"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/dataplane"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	happ "github.com/cloudwego/hertz/pkg/app"
	hserver "github.com/cloudwego/hertz/pkg/app/server"
	"github.com/glebarez/sqlite"
	shconfig "github.com/hertz-contrib/http2/config"
	shfactory "github.com/hertz-contrib/http2/factory"
	goredis "github.com/redis/go-redis/v9"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"gorm.io/gorm"
)

func TestSnapshotUpstreamsDeduplicatesTrimsAndSorts(t *testing.T) {
	sn := &snapshotpkg.Snapshot{Sites: map[string]snapshotpkg.SiteRuntime{
		"a": {UpstreamURLs: []string{" http://b ", "http://a"}},
		"b": {UpstreamURLs: []string{"http://a", ""}},
	}}
	got := snapshotUpstreams(sn)
	if len(got) != 2 || got[0] != "http://a" || got[1] != "http://b" {
		t.Fatalf("unexpected upstream list: %#v", got)
	}
}

func TestSnapshotUpstreamSetChangedIgnoresOrderDuplicatesAndWhitespace(t *testing.T) {
	previous := &snapshotpkg.Snapshot{Sites: map[string]snapshotpkg.SiteRuntime{
		"a": {UpstreamURLs: []string{" http://b ", "http://a"}},
		"b": {UpstreamURLs: []string{"http://a"}},
	}}
	current := &snapshotpkg.Snapshot{Sites: map[string]snapshotpkg.SiteRuntime{
		"c": {UpstreamURLs: []string{"http://a", "http://b"}},
	}}
	if snapshotUpstreamSetChanged(previous, current) {
		t.Fatal("snapshotUpstreamSetChanged should ignore order, duplicates, and surrounding whitespace")
	}
}

func TestSnapshotUpstreamSetChangedDetectsEndpointChange(t *testing.T) {
	previous := &snapshotpkg.Snapshot{Sites: map[string]snapshotpkg.SiteRuntime{
		"a": {UpstreamURLs: []string{"http://a", "h3://b"}},
	}}
	current := &snapshotpkg.Snapshot{Sites: map[string]snapshotpkg.SiteRuntime{
		"a": {UpstreamURLs: []string{"http://a", "h3://c"}},
	}}
	if !snapshotUpstreamSetChanged(previous, current) {
		t.Fatal("snapshotUpstreamSetChanged should detect changed upstream endpoints")
	}
}

func TestListenerRuntimesByBindDeduplicatesBindAndPrefersTLS(t *testing.T) {
	sn := &snapshotpkg.Snapshot{Sites: map[string]snapshotpkg.SiteRuntime{
		"a": {Bind: ":443", Site: store.Site{ID: 1, Bind: ":443", TLSEnabled: false}},
		"b": {Bind: ":443", Site: store.Site{ID: 2, Bind: ":443", TLSEnabled: true}},
		"c": {Bind: ":80", Site: store.Site{ID: 3, Bind: ":80", TLSEnabled: false}},
	}}

	got := listenerRuntimesByBind(sn)
	if len(got) != 2 {
		t.Fatalf("expected one listener per bind, got %d", len(got))
	}

	byBind := make(map[string]snapshotpkg.SiteRuntime)
	for _, rt := range got {
		byBind[rt.Bind] = rt
	}
	if !byBind[":443"].Site.TLSEnabled || byBind[":443"].Site.ID != 2 {
		t.Fatalf("expected TLS runtime to represent :443 listener, got %+v", byBind[":443"])
	}
	if byBind[":80"].Site.ID != 3 {
		t.Fatalf("expected :80 runtime to remain available, got %+v", byBind[":80"].Site)
	}
}

func TestParseALPNProtocolsDefaultsAndDeduplicates(t *testing.T) {
	got := parseALPNProtocols("")
	if len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
		t.Fatalf("unexpected default ALPN list: %#v", got)
	}

	got = parseALPNProtocols(" h2 , http/1.1 , h2 , h3 ")
	want := []string{"h2", "http/1.1", "h3"}
	if len(got) != len(want) {
		t.Fatalf("unexpected ALPN length: got=%#v want=%#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected ALPN order: got=%#v want=%#v", got, want)
		}
	}

	got = parseALPNProtocols(" H2 , HTTP/1.1 , h2 , H3 ")
	want = []string{"h2", "http/1.1", "h3"}
	if len(got) != len(want) {
		t.Fatalf("unexpected mixed-case ALPN length: got=%#v want=%#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected mixed-case ALPN order: got=%#v want=%#v", got, want)
		}
	}
}

func TestTCPTLSALPNProtocolsFiltersHTTP3(t *testing.T) {
	got := tcpTLSALPNProtocols("h2,h3,http/1.1", snapshotpkg.DefaultNetworkDefaults())
	want := []string{"h2", "http/1.1"}
	if len(got) != len(want) {
		t.Fatalf("unexpected TCP ALPN list: got=%#v want=%#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected TCP ALPN list: got=%#v want=%#v", got, want)
		}
	}

	got = tcpTLSALPNProtocols("H2,H3,HTTP/1.1", snapshotpkg.DefaultNetworkDefaults())
	want = []string{"h2", "http/1.1"}
	if len(got) != len(want) {
		t.Fatalf("unexpected mixed-case TCP ALPN list: got=%#v want=%#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected mixed-case TCP ALPN list: got=%#v want=%#v", got, want)
		}
	}
}

func TestTCPTLSALPNProtocolsPromotesHTTP2WhenHTTP3Only(t *testing.T) {
	got := tcpTLSALPNProtocols("h3,http/1.1", snapshotpkg.NetworkDefaults{HTTP2Enabled: true, HTTP3Enabled: true})
	want := []string{"h2", "http/1.1"}
	if len(got) != len(want) {
		t.Fatalf("unexpected TCP ALPN list: got=%#v want=%#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected TCP ALPN list: got=%#v want=%#v", got, want)
		}
	}
}

func TestTCPTLSConfigForClientHelloRemovesHTTP2BelowTLS12(t *testing.T) {
	base := &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	cfg := tcpTLSConfigForClientHello(base, &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS11, tls.VersionTLS10},
	})
	if cfg == nil {
		t.Fatal("expected legacy TLS client config")
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("legacy TLS NextProtos = %#v, want [http/1.1]", cfg.NextProtos)
	}
	if len(base.NextProtos) != 2 || base.NextProtos[0] != "h2" || base.NextProtos[1] != "http/1.1" {
		t.Fatalf("base NextProtos mutated: %#v", base.NextProtos)
	}

	if got := tcpTLSConfigForClientHello(&tls.Config{MaxVersion: tls.VersionTLS11, NextProtos: []string{"h2", "http/1.1"}}, &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	}); got == nil {
		t.Fatal("expected legacy server TLS config")
	} else if len(got.NextProtos) != 1 || got.NextProtos[0] != "http/1.1" {
		t.Fatalf("legacy server NextProtos = %#v, want [http/1.1]", got.NextProtos)
	}

	if got := tcpTLSConfigForClientHello(base, &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12, tls.VersionTLS11},
	}); got != nil {
		t.Fatalf("TLS 1.2 capable client config = %#v, want nil", got)
	}
}

func TestTCPTLSConfigForClientHelloRejectsLegacyHTTP2OnlyALPN(t *testing.T) {
	base := &tls.Config{NextProtos: []string{"h2"}}
	cfg := tcpTLSConfigForClientHello(base, &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS11, tls.VersionTLS10},
	})
	if cfg == nil {
		t.Fatal("expected legacy TLS client config")
	}
	if len(cfg.NextProtos) != 0 {
		t.Fatalf("legacy TLS h2-only NextProtos = %#v, want empty", cfg.NextProtos)
	}
	if len(base.NextProtos) != 1 || base.NextProtos[0] != "h2" {
		t.Fatalf("base NextProtos mutated: %#v", base.NextProtos)
	}
}

func TestShouldEnableHTTP3(t *testing.T) {
	if !shouldEnableHTTP3("") {
		t.Fatal("empty ALPN should use defaults and enable HTTP/3")
	}
	if !shouldEnableHTTP3("h2, h3, http/1.1") {
		t.Fatal("expected h3 ALPN to enable HTTP/3")
	}
	if !shouldEnableHTTP3("H2, H3, HTTP/1.1") {
		t.Fatal("mixed-case h3 ALPN should enable HTTP/3")
	}
	if shouldEnableHTTP3("h2,http/1.1") {
		t.Fatal("ALPN without h3 should not enable HTTP/3")
	}
	if shouldEnableHTTP3("h3", snapshotpkg.NetworkDefaults{HTTP3Enabled: false}) {
		t.Fatal("network_config.http3_enabled=false should disable HTTP/3")
	}
	if !shouldEnableHTTP3("h3", snapshotpkg.NetworkDefaults{HTTP3Enabled: true}) {
		t.Fatal("network_config.http3_enabled=true should allow HTTP/3")
	}
}

func TestEffectiveHTTP3EnabledUsesInheritedTLSDefaultALPN(t *testing.T) {
	rt := snapshotpkg.SiteRuntime{
		Bind: ":443",
		Site: store.Site{
			TLSEnabled: true,
			ALPN:       "",
		},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			HTTP3Bind:      ":8443",
			DefaultALPN:    "http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults: snapshotpkg.TLSDefaults{
			DefaultALPN:            "h2,h3,http/1.1",
			HasExplicitDefaultALPN: true,
		},
	}

	if !effectiveHTTP3Enabled(rt) {
		t.Fatal("explicit tls_default_config.default_alpn should enable HTTP/3")
	}
}

func TestDataServerHTTP2EnabledUsesEffectiveTLSALPN(t *testing.T) {
	t.Run("defaults_enable_h2_without_site_override", func(t *testing.T) {
		rt := snapshotpkg.SiteRuntime{
			Bind: ":443",
			Site: store.Site{
				TLSEnabled: true,
			},
			NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
			TLSDefaults:     snapshotpkg.DefaultTLSDefaults(),
		}
		tlsCfg := buildListenerTLS(rt, &snapshotpkg.Snapshot{})
		if tlsCfg == nil {
			t.Fatal("expected TLS config")
		}
		if !dataServerHTTP2Enabled(rt, tlsCfg) {
			t.Fatal("empty site ALPN should still enable h2 when defaults include h2")
		}
	})

	t.Run("network_config_can_disable_h2", func(t *testing.T) {
		rt := snapshotpkg.SiteRuntime{
			Bind: ":443",
			Site: store.Site{
				TLSEnabled: true,
			},
			NetworkDefaults: snapshotpkg.NetworkDefaults{
				HTTP2Enabled:   false,
				HTTP3Enabled:   true,
				HTTP3Bind:      ":443",
				DefaultALPN:    "h2,h3,http/1.1",
				DefaultNetwork: "tcp",
			},
			TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
		}
		tlsCfg := buildListenerTLS(rt, &snapshotpkg.Snapshot{})
		if tlsCfg == nil {
			t.Fatal("expected TLS config")
		}
		if dataServerHTTP2Enabled(rt, tlsCfg) {
			t.Fatal("HTTP2Enabled=false should prevent h2 protocol registration")
		}
	})
}

func TestBuildListenerTLSReturnsOCSPStapledCertificate(t *testing.T) {
	certPEM, keyPEM, err := acmepkg.GenerateSelfSignedPEM("ocsp.example.test", []string{"ocsp.example.test"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	ocspDER := []byte{0x30, 0x03, 0x0a, 0x01, 0x00}
	rt := snapshotpkg.SiteRuntime{
		Bind: ":443",
		Site: store.Site{
			ID:         1,
			Host:       "ocsp.example.test",
			Bind:       ":443",
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		Certificate: &store.Certificate{
			Name:          "ocsp",
			CertPEM:       certPEM,
			KeyPEM:        keyPEM,
			OCSPStaplePEM: string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: ocspDER})),
		},
		NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:     snapshotpkg.DefaultTLSDefaults(),
	}
	sn := &snapshotpkg.Snapshot{
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(":443", "ocsp.example.test"): rt,
		},
	}

	cfg := buildListenerTLS(rt, sn)
	if cfg == nil || cfg.GetCertificate == nil {
		t.Fatalf("expected TLS config with GetCertificate, got %#v", cfg)
	}
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "ocsp.example.test"})
	if err != nil {
		t.Fatalf("GetCertificate() error: %v", err)
	}
	if cert == nil || !bytes.Equal(cert.OCSPStaple, ocspDER) {
		t.Fatalf("OCSP staple = %x, want %x", cert.OCSPStaple, ocspDER)
	}
}

func TestBuildDataServerNegotiatesHTTP2WithEffectiveTLSALPN(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "http2.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
			ForceAttemptHTTP2: true,
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+bind+"/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = rt.Site.Host

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Fatalf("response protocol major = %d, want 2", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected TLS connection state on response")
	}
	if resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated protocol = %q, want %q", resp.TLS.NegotiatedProtocol, "h2")
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}

func TestBuildDataServerHTTP2PermitProhibitedCipherSuitesControlsTLS12CBC(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "http2 prohibited cipher upstream")
	}))
	defer upstream.Close()

	tests := []struct {
		name   string
		permit bool
	}{
		{name: "rejects_when_disabled", permit: false},
		{name: "serves_when_enabled", permit: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("reserve test bind: %v", err)
			}
			bind := ln.Addr().String()
			if err := ln.Close(); err != nil {
				t.Fatalf("release reserved bind: %v", err)
			}

			protection := store.DefaultProtectionConfig()
			protection.BotDetectionEnabled = false
			holder := &snapshotpkg.Holder{}
			rt := snapshotpkg.SiteRuntime{
				Bind: bind,
				Site: store.Site{
					ID:            1,
					Host:          "http2-prohibited-cipher.example.test",
					Bind:          bind,
					TLSEnabled:    true,
					MinTLSVersion: "TLS12",
					MaxTLSVersion: "TLS12",
					CipherSuites:  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
					ALPN:          "h2,http/1.1",
				},
				UpstreamURLs:        []string{upstream.URL},
				NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
				TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
				EffectiveProtection: &protection,
			}
			http2Config := snapshotpkg.DefaultHTTP2Config()
			http2Config.PermitProhibitedCipherSuites = tt.permit
			sn := &snapshotpkg.Snapshot{
				Revision:    1,
				Protection:  protection,
				HTTP2Config: http2Config,
				Sites: map[string]snapshotpkg.SiteRuntime{
					snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
				},
			}
			holder.Store(sn)

			srv := buildDataServer(rt, sn, dataplane.Options{
				Holder: holder,
				Engine: engine.New(holder, nil, nil, nil),
				Log:    slog.Default(),
				Bind:   bind,
			})
			if srv == nil {
				t.Fatal("expected data server")
			}

			go srv.Spin()
			deadline := time.Now().Add(2 * time.Second)
			for !srv.IsRunning() {
				if time.Now().After(deadline) {
					t.Fatal("data server did not start")
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = srv.Shutdown(ctx)
			})

			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
					MaxVersion:         tls.VersionTLS12,
					NextProtos:         []string{"h2"},
					CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
				},
				ForceAttemptHTTP2: true,
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{
				Timeout:   5 * time.Second,
				Transport: transport,
			}
			req, err := http.NewRequest(http.MethodGet, "https://"+bind+"/http2-prohibited-cipher", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Host = rt.Site.Host

			resp, err := client.Do(req)
			if !tt.permit {
				if err == nil {
					defer resp.Body.Close()
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatalf("read rejected response body: %v", readErr)
					}
					t.Fatalf("HTTP/2 prohibited cipher request unexpectedly succeeded: proto=%s status=%d body=%q", resp.Proto, resp.StatusCode, string(body))
				}
				return
			}
			if err != nil {
				t.Fatalf("send permitted prohibited cipher request: %v", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read permitted response body: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("permitted response status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
			}
			if got := string(body); got != "http2 prohibited cipher upstream" {
				t.Fatalf("permitted response body = %q, want %q", got, "http2 prohibited cipher upstream")
			}
			if resp.ProtoMajor != 2 {
				t.Fatalf("permitted response protocol major = %d, want 2", resp.ProtoMajor)
			}
			if resp.TLS == nil {
				t.Fatal("permitted response missing TLS state")
			}
			if resp.TLS.Version != tls.VersionTLS12 {
				t.Fatalf("permitted TLS version = %#x, want %#x", resp.TLS.Version, tls.VersionTLS12)
			}
			if resp.TLS.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA {
				t.Fatalf("permitted TLS cipher suite = %#x, want %#x", resp.TLS.CipherSuite, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
			}
			if resp.TLS.NegotiatedProtocol != "h2" {
				t.Fatalf("permitted ALPN = %q, want h2", resp.TLS.NegotiatedProtocol)
			}
		})
	}
}

func TestBuildDataServerServesConfiguredTLSVersionsWithHTTP11Response(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "configured tls version response")
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:            1,
			Host:          "tls-versions.example.test",
			Bind:          bind,
			TLSEnabled:    true,
			MinTLSVersion: "TLS10",
			MaxTLSVersion: "TLS13",
			CipherSuites:  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			ALPN:          "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	tests := []struct {
		name         string
		version      uint16
		cipherSuites []uint16
	}{
		{
			name:         "TLS10",
			version:      tls.VersionTLS10,
			cipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		},
		{
			name:         "TLS11",
			version:      tls.VersionTLS11,
			cipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		},
		{
			name:         "TLS12",
			version:      tls.VersionTLS12,
			cipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		},
		{
			name:    "TLS13",
			version: tls.VersionTLS13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tt.version,
					MaxVersion:         tt.version,
					NextProtos:         []string{"http/1.1"},
					CipherSuites:       tt.cipherSuites,
				},
			}
			defer transport.CloseIdleConnections()

			client := &http.Client{
				Timeout:   5 * time.Second,
				Transport: transport,
			}
			req, err := http.NewRequest(http.MethodGet, "https://"+bind+"/tls-version-response", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Host = rt.Site.Host

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("send %s request: %v", tt.name, err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read %s response body: %v", tt.name, err)
			}
			if got := string(body); got != "configured tls version response" {
				t.Fatalf("%s response body = %q, want %q", tt.name, got, "configured tls version response")
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s status = %d, want %d", tt.name, resp.StatusCode, http.StatusOK)
			}
			if resp.ProtoMajor != 1 {
				t.Fatalf("%s response protocol major = %d, want 1", tt.name, resp.ProtoMajor)
			}
			if resp.TLS == nil {
				t.Fatalf("%s response missing TLS state", tt.name)
			}
			if resp.TLS.Version != tt.version {
				t.Fatalf("%s negotiated TLS version = %#x, want %#x", tt.name, resp.TLS.Version, tt.version)
			}
			if resp.TLS.NegotiatedProtocol != "http/1.1" {
				t.Fatalf("%s negotiated ALPN = %q, want %q", tt.name, resp.TLS.NegotiatedProtocol, "http/1.1")
			}
		})
	}

	legacyALPNTests := []struct {
		name         string
		version      uint16
		cipherSuites []uint16
	}{
		{
			name:         "TLS10OffersH2",
			version:      tls.VersionTLS10,
			cipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		},
		{
			name:         "TLS11OffersH2",
			version:      tls.VersionTLS11,
			cipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		},
	}

	for _, tt := range legacyALPNTests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					MinVersion:         tt.version,
					MaxVersion:         tt.version,
					NextProtos:         []string{"h2", "http/1.1"},
					CipherSuites:       tt.cipherSuites,
				},
			}
			defer transport.CloseIdleConnections()

			client := &http.Client{
				Timeout:   5 * time.Second,
				Transport: transport,
			}
			req, err := http.NewRequest(http.MethodGet, "https://"+bind+"/tls-version-response", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Host = rt.Site.Host

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("send %s request: %v", tt.name, err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read %s response body: %v", tt.name, err)
			}
			if got := string(body); got != "configured tls version response" {
				t.Fatalf("%s response body = %q, want %q", tt.name, got, "configured tls version response")
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s status = %d, want %d", tt.name, resp.StatusCode, http.StatusOK)
			}
			if resp.ProtoMajor != 1 {
				t.Fatalf("%s response protocol major = %d, want 1", tt.name, resp.ProtoMajor)
			}
			if resp.TLS == nil {
				t.Fatalf("%s response missing TLS state", tt.name)
			}
			if resp.TLS.Version != tt.version {
				t.Fatalf("%s negotiated TLS version = %#x, want %#x", tt.name, resp.TLS.Version, tt.version)
			}
			if resp.TLS.NegotiatedProtocol != "http/1.1" {
				t.Fatalf("%s negotiated ALPN = %q, want %q", tt.name, resp.TLS.NegotiatedProtocol, "http/1.1")
			}
		})
	}

	const versionSSL30 = 0x0300
	_, err = tls.Dial("tcp", bind, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         versionSSL30,
		MaxVersion:         versionSSL30,
	})
	if err == nil {
		t.Fatal("SSL3 handshake unexpectedly succeeded")
	}
}

func TestBuildDataServerDoesNotNegotiateHTTP2BelowTLS12WhenALPNIsH2Only(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "legacy h2-only fallback response")
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:            1,
			Host:          "legacy-h2-only.example.test",
			Bind:          bind,
			TLSEnabled:    true,
			MinTLSVersion: "TLS10",
			MaxTLSVersion: "TLS11",
			CipherSuites:  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			ALPN:          "h2",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS11,
			MaxVersion:         tls.VersionTLS11,
			NextProtos:         []string{"h2", "http/1.1"},
			CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+bind+"/legacy-h2-only", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = rt.Site.Host

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send legacy h2-only request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", resp.StatusCode, http.StatusOK, string(body))
	}
	if got := string(body); got != "legacy h2-only fallback response" {
		t.Fatalf("response body = %q", got)
	}
	if resp.ProtoMajor != 1 {
		t.Fatalf("response protocol major = %d, want 1", resp.ProtoMajor)
	}
	if resp.TLS == nil {
		t.Fatal("expected TLS connection state on response")
	}
	if resp.TLS.Version != tls.VersionTLS11 {
		t.Fatalf("negotiated TLS version = %#x, want %#x", resp.TLS.Version, tls.VersionTLS11)
	}
	if resp.TLS.NegotiatedProtocol == "h2" {
		t.Fatalf("legacy TLS negotiated ALPN = %q, want non-h2", resp.TLS.NegotiatedProtocol)
	}
}

func TestBuildDataServerRejectsTooManyRequestHeadersOverHTTP2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "http2-headers.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxHeaderFields = 3
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
			ForceAttemptHTTP2: true,
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+bind+"/too-many-headers", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = rt.Site.Host
	for i := 0; i < 6; i++ {
		req.Header.Set(fmt.Sprintf("X-Header-%d", i), "v")
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Fatalf("response protocol major = %d, want 2", resp.ProtoMajor)
	}
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	got := string(body)
	if !strings.Contains(got, "HTTP Error 431") || !strings.Contains(got, "Request Header Field(s) Too Large") {
		t.Fatalf("body = %q, want 431 header-too-large page", got)
	}
}

func TestBuildDataServerRejectsRawHTTP2CookieCrumbBurstOverHeaderFieldLimit(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "cookie-crumbs.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxHeaderFields = 4
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const rejectedStreamID uint32 = 1
	writeRawHTTP2HeadersWithFields(t, fr, rejectedStreamID, rt.Site.Host, "/cookie-crumbs", []hpack.HeaderField{
		{Name: "cookie", Value: "a=b"},
		{Name: "cookie", Value: "c=d"},
		{Name: "cookie", Value: "e=f"},
		{Name: "cookie", Value: "g=h"},
	})
	readRawHTTP2ResponseStatus(t, conn, fr, rejectedStreamID, "431")

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after cookie crumb burst: %q", path)
	case <-time.After(200 * time.Millisecond):
	}

	const okStreamID uint32 = 3
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after cookie crumb rejection")
	}
}

func TestBuildDataServerRejectsRawHTTP2HPACKHeaderBombOverHeaderListBudget(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "hpack-bomb.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxHeaderBytes = 2048
	http2cfg.MaxHeaderFields = 8
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr, settings := newRawHTTP2ClientConnWithServerSettings(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	maxHeaderListSize, ok := settings[http2.SettingMaxHeaderListSize]
	if !ok {
		t.Fatal("server settings missing MAX_HEADER_LIST_SIZE")
	}

	cookieValue := strings.Repeat("x", 1024)
	cookieHeaderCost := len("cookie") + len(cookieValue) + 32
	totalCookieHeaderCost := cookieHeaderCost * 3
	if totalCookieHeaderCost <= int(maxHeaderListSize) {
		t.Fatalf("test setup invalid: cookie header cost %d must exceed advertised max header list size %d", totalCookieHeaderCost, maxHeaderListSize)
	}

	var headerBlock bytes.Buffer
	encoder := hpack.NewEncoder(&headerBlock)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodGet},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: rt.Site.Host},
		{Name: ":path", Value: "/hpack-bomb"},
		{Name: "cookie", Value: cookieValue},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatalf("encode initial hpack field %q: %v", field.Name, err)
		}
	}

	const rejectedStreamID uint32 = 1
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      rejectedStreamID,
		BlockFragment: append([]byte(nil), headerBlock.Bytes()...),
		EndStream:     true,
		EndHeaders:    false,
	}); err != nil {
		t.Fatalf("WriteHeaders() error = %v", err)
	}

	for i := 0; i < 2; i++ {
		headerBlock.Reset()
		if err := encoder.WriteField(hpack.HeaderField{Name: "cookie", Value: cookieValue}); err != nil {
			t.Fatalf("encode repeated hpack cookie %d: %v", i, err)
		}
		compressedContinuation := append([]byte(nil), headerBlock.Bytes()...)
		if len(compressedContinuation) >= len(cookieValue) {
			t.Fatalf("compressed continuation len = %d, want smaller than raw cookie len %d", len(compressedContinuation), len(cookieValue))
		}
		if err := fr.WriteContinuation(rejectedStreamID, i == 1, compressedContinuation); err != nil {
			t.Fatalf("WriteContinuation(index=%d) error = %v", i, err)
		}
	}

	readRawHTTP2ResponseStatus(t, conn, fr, rejectedStreamID, "431")

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after HPACK header bomb rejection: %q", path)
	case <-time.After(200 * time.Millisecond):
	}

	const okStreamID uint32 = 3
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after HPACK header bomb rejection")
	}
}

func TestBuildDataServerRejectsRawHTTP2HPACKHeaderBombWithManyContinuationFragments(t *testing.T) {
	const continuationCount = 12

	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "hpack-bomb-many-fragments.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxHeaderBytes = 256
	http2cfg.MaxHeaderFields = 32
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr, settings := newRawHTTP2ClientConnWithServerSettings(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	maxHeaderListSize, ok := settings[http2.SettingMaxHeaderListSize]
	if !ok {
		t.Fatal("server settings missing MAX_HEADER_LIST_SIZE")
	}

	cookieValue := strings.Repeat("m", 512)
	cookieHeaderCost := len("cookie") + len(cookieValue) + 32
	totalCookieHeaderCost := cookieHeaderCost * (continuationCount + 1)
	if totalCookieHeaderCost <= int(maxHeaderListSize) {
		t.Fatalf("test setup invalid: cookie header cost %d must exceed advertised max header list size %d", totalCookieHeaderCost, maxHeaderListSize)
	}
	if continuationCount+5 >= http2cfg.MaxHeaderFields {
		t.Fatalf("test setup invalid: continuation count %d exceeds header field budget %d", continuationCount, http2cfg.MaxHeaderFields)
	}

	var headerBlock bytes.Buffer
	encoder := hpack.NewEncoder(&headerBlock)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodGet},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: rt.Site.Host},
		{Name: ":path", Value: "/hpack-bomb-many-fragments"},
		{Name: "cookie", Value: cookieValue},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatalf("encode initial hpack field %q: %v", field.Name, err)
		}
	}

	const rejectedStreamID uint32 = 1
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      rejectedStreamID,
		BlockFragment: append([]byte(nil), headerBlock.Bytes()...),
		EndStream:     true,
		EndHeaders:    false,
	}); err != nil {
		t.Fatalf("WriteHeaders() error = %v", err)
	}

	totalCompressedContinuationBytes := 0
	for i := 0; i < continuationCount; i++ {
		headerBlock.Reset()
		if err := encoder.WriteField(hpack.HeaderField{Name: "cookie", Value: cookieValue}); err != nil {
			t.Fatalf("encode repeated hpack cookie %d: %v", i, err)
		}
		compressedContinuation := append([]byte(nil), headerBlock.Bytes()...)
		if len(compressedContinuation) == 0 {
			t.Fatalf("compressed continuation %d is empty", i)
		}
		if len(compressedContinuation) >= len(cookieValue) {
			t.Fatalf("compressed continuation len = %d, want smaller than raw cookie len %d", len(compressedContinuation), len(cookieValue))
		}
		totalCompressedContinuationBytes += len(compressedContinuation)
		if err := fr.WriteContinuation(rejectedStreamID, i == continuationCount-1, compressedContinuation); err != nil {
			t.Fatalf("WriteContinuation(index=%d) error = %v", i, err)
		}
	}
	if totalCompressedContinuationBytes >= continuationCount*len(cookieValue) {
		t.Fatalf("compressed continuation bytes = %d, want smaller than raw bytes %d", totalCompressedContinuationBytes, continuationCount*len(cookieValue))
	}

	readRawHTTP2ResponseStatus(t, conn, fr, rejectedStreamID, "431")

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after multi-fragment HPACK header bomb rejection: %q", path)
	case <-time.After(200 * time.Millisecond):
	}

	const okStreamID uint32 = 3
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after multi-fragment HPACK header bomb rejection")
	}
}

func TestBuildDataServerRejectsRepeatedRawHTTP2HPACKHeaderBombsAcrossStreamsOnSameConnection(t *testing.T) {
	const (
		rejectedStreamCount        = 3
		repeatedCookiesPerStream   = 4
		repeatedContinuationsCount = repeatedCookiesPerStream - 1
	)

	upstreamStarted := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "hpack-bomb-across-streams.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxHeaderBytes = 256
	http2cfg.MaxHeaderFields = 32
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr, settings := newRawHTTP2ClientConnWithServerSettings(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	maxHeaderListSize, ok := settings[http2.SettingMaxHeaderListSize]
	if !ok {
		t.Fatal("server settings missing MAX_HEADER_LIST_SIZE")
	}

	cookieValue := strings.Repeat("s", 512)
	cookieHeaderCost := len("cookie") + len(cookieValue) + 32
	totalCookieHeaderCost := cookieHeaderCost * repeatedCookiesPerStream
	if totalCookieHeaderCost <= int(maxHeaderListSize) {
		t.Fatalf("test setup invalid: cookie header cost %d must exceed advertised max header list size %d", totalCookieHeaderCost, maxHeaderListSize)
	}
	if repeatedCookiesPerStream+4 >= http2cfg.MaxHeaderFields {
		t.Fatalf("test setup invalid: repeated cookies %d exceed header field budget %d", repeatedCookiesPerStream, http2cfg.MaxHeaderFields)
	}

	var headerBlock bytes.Buffer
	encoder := hpack.NewEncoder(&headerBlock)

	headerBlock.Reset()
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodGet},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: rt.Site.Host},
		{Name: ":path", Value: "/prime-dynamic-table"},
		{Name: "cookie", Value: cookieValue},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatalf("encode prime hpack field %q: %v", field.Name, err)
		}
	}

	const primeStreamID uint32 = 1
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      primeStreamID,
		BlockFragment: append([]byte(nil), headerBlock.Bytes()...),
		EndStream:     true,
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("WriteHeaders(prime) error = %v", err)
	}
	readRawHTTP2ResponseStatus(t, conn, fr, primeStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/prime-dynamic-table" {
			t.Fatalf("prime upstream path = %q, want %q", path, "/prime-dynamic-table")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prime request did not reach upstream")
	}

	wantRejectedStatuses := make(map[uint32]string, rejectedStreamCount)
	totalCompressedContinuationBytes := 0
	for i := 0; i < rejectedStreamCount; i++ {
		streamID := uint32(i*2 + 3)
		path := fmt.Sprintf("/hpack-cross-stream/%d", i)

		headerBlock.Reset()
		for _, field := range []hpack.HeaderField{
			{Name: ":method", Value: http.MethodGet},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: rt.Site.Host},
			{Name: ":path", Value: path},
			{Name: "cookie", Value: cookieValue},
		} {
			if err := encoder.WriteField(field); err != nil {
				t.Fatalf("encode rejected stream %d field %q: %v", streamID, field.Name, err)
			}
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: append([]byte(nil), headerBlock.Bytes()...),
			EndStream:     true,
			EndHeaders:    false,
		}); err != nil {
			t.Fatalf("WriteHeaders(stream=%d) error = %v", streamID, err)
		}

		for j := 0; j < repeatedContinuationsCount; j++ {
			headerBlock.Reset()
			if err := encoder.WriteField(hpack.HeaderField{Name: "cookie", Value: cookieValue}); err != nil {
				t.Fatalf("encode rejected stream %d continuation %d: %v", streamID, j, err)
			}
			compressedContinuation := append([]byte(nil), headerBlock.Bytes()...)
			if len(compressedContinuation) == 0 {
				t.Fatalf("compressed continuation empty: stream=%d continuation=%d", streamID, j)
			}
			if len(compressedContinuation) >= len(cookieValue) {
				t.Fatalf("compressed continuation len = %d, want smaller than raw cookie len %d, stream=%d", len(compressedContinuation), len(cookieValue), streamID)
			}
			totalCompressedContinuationBytes += len(compressedContinuation)
			if err := fr.WriteContinuation(streamID, j == repeatedContinuationsCount-1, compressedContinuation); err != nil {
				t.Fatalf("WriteContinuation(stream=%d,index=%d) error = %v", streamID, j, err)
			}
		}

		wantRejectedStatuses[streamID] = "431"
	}
	if totalCompressedContinuationBytes >= rejectedStreamCount*repeatedContinuationsCount*len(cookieValue) {
		t.Fatalf("compressed continuation bytes = %d, want smaller than raw bytes %d", totalCompressedContinuationBytes, rejectedStreamCount*repeatedContinuationsCount*len(cookieValue))
	}

	readRawHTTP2ResponseStatuses(t, conn, fr, wantRejectedStatuses)

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after repeated cross-stream HPACK bombs: %q", path)
	case <-time.After(200 * time.Millisecond):
	}

	const okStreamID uint32 = 9
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after repeated cross-stream HPACK bombs")
	}
}

func TestBuildDataServerRejectsBurstOfRawHTTP2HPACKHeaderBombsAcrossManyStreamsOnSameConnection(t *testing.T) {
	const (
		rejectedStreamCount        = 12
		repeatedCookiesPerStream   = 4
		repeatedContinuationsCount = repeatedCookiesPerStream - 1
	)

	upstreamStarted := make(chan string, rejectedStreamCount+2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "hpack-bomb-burst.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxHeaderBytes = 256
	http2cfg.MaxHeaderFields = 32
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr, settings := newRawHTTP2ClientConnWithServerSettings(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	maxHeaderListSize, ok := settings[http2.SettingMaxHeaderListSize]
	if !ok {
		t.Fatal("server settings missing MAX_HEADER_LIST_SIZE")
	}

	cookieValue := strings.Repeat("b", 512)
	cookieHeaderCost := len("cookie") + len(cookieValue) + 32
	totalCookieHeaderCost := cookieHeaderCost * repeatedCookiesPerStream
	if totalCookieHeaderCost <= int(maxHeaderListSize) {
		t.Fatalf("test setup invalid: cookie header cost %d must exceed advertised max header list size %d", totalCookieHeaderCost, maxHeaderListSize)
	}
	if repeatedCookiesPerStream+4 >= http2cfg.MaxHeaderFields {
		t.Fatalf("test setup invalid: repeated cookies %d exceed header field budget %d", repeatedCookiesPerStream, http2cfg.MaxHeaderFields)
	}

	var headerBlock bytes.Buffer
	encoder := hpack.NewEncoder(&headerBlock)

	headerBlock.Reset()
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodGet},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: rt.Site.Host},
		{Name: ":path", Value: "/prime-dynamic-table"},
		{Name: "cookie", Value: cookieValue},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatalf("encode prime hpack field %q: %v", field.Name, err)
		}
	}

	const primeStreamID uint32 = 1
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      primeStreamID,
		BlockFragment: append([]byte(nil), headerBlock.Bytes()...),
		EndStream:     true,
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("WriteHeaders(prime) error = %v", err)
	}
	readRawHTTP2ResponseStatus(t, conn, fr, primeStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/prime-dynamic-table" {
			t.Fatalf("prime upstream path = %q, want %q", path, "/prime-dynamic-table")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prime request did not reach upstream")
	}

	wantRejectedStatuses := make(map[uint32]string, rejectedStreamCount)
	totalCompressedContinuationBytes := 0
	for i := 0; i < rejectedStreamCount; i++ {
		streamID := uint32(i*2 + 3)
		path := fmt.Sprintf("/hpack-burst/%d", i)

		headerBlock.Reset()
		for _, field := range []hpack.HeaderField{
			{Name: ":method", Value: http.MethodGet},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: rt.Site.Host},
			{Name: ":path", Value: path},
			{Name: "cookie", Value: cookieValue},
		} {
			if err := encoder.WriteField(field); err != nil {
				t.Fatalf("encode rejected stream %d field %q: %v", streamID, field.Name, err)
			}
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: append([]byte(nil), headerBlock.Bytes()...),
			EndStream:     true,
			EndHeaders:    false,
		}); err != nil {
			t.Fatalf("WriteHeaders(stream=%d) error = %v", streamID, err)
		}

		for j := 0; j < repeatedContinuationsCount; j++ {
			headerBlock.Reset()
			if err := encoder.WriteField(hpack.HeaderField{Name: "cookie", Value: cookieValue}); err != nil {
				t.Fatalf("encode rejected stream %d continuation %d: %v", streamID, j, err)
			}
			compressedContinuation := append([]byte(nil), headerBlock.Bytes()...)
			if len(compressedContinuation) == 0 {
				t.Fatalf("compressed continuation empty: stream=%d continuation=%d", streamID, j)
			}
			if len(compressedContinuation) >= len(cookieValue) {
				t.Fatalf("compressed continuation len = %d, want smaller than raw cookie len %d, stream=%d", len(compressedContinuation), len(cookieValue), streamID)
			}
			totalCompressedContinuationBytes += len(compressedContinuation)
			if err := fr.WriteContinuation(streamID, j == repeatedContinuationsCount-1, compressedContinuation); err != nil {
				t.Fatalf("WriteContinuation(stream=%d,index=%d) error = %v", streamID, j, err)
			}
		}

		wantRejectedStatuses[streamID] = "431"
	}
	if totalCompressedContinuationBytes >= rejectedStreamCount*repeatedContinuationsCount*len(cookieValue) {
		t.Fatalf("compressed continuation bytes = %d, want smaller than raw bytes %d", totalCompressedContinuationBytes, rejectedStreamCount*repeatedContinuationsCount*len(cookieValue))
	}

	readRawHTTP2ResponseStatuses(t, conn, fr, wantRejectedStatuses)

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after HPACK bomb burst rejection: %q", path)
	case <-time.After(200 * time.Millisecond):
	}

	const okStreamID uint32 = 27
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after HPACK bomb burst rejection")
	}
}

func TestBuildDataServerInterleavesHealthyAndRawHTTP2HPACKBombStreamsOnSameConnection(t *testing.T) {
	const (
		normalStreamCount          = 6
		rejectedStreamCount        = 6
		repeatedCookiesPerStream   = 4
		repeatedContinuationsCount = repeatedCookiesPerStream - 1
	)

	upstreamStarted := make(chan string, normalStreamCount+3)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "hpack-bomb-mixed.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxHeaderBytes = 256
	http2cfg.MaxHeaderFields = 32
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr, settings := newRawHTTP2ClientConnWithServerSettings(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	maxHeaderListSize, ok := settings[http2.SettingMaxHeaderListSize]
	if !ok {
		t.Fatal("server settings missing MAX_HEADER_LIST_SIZE")
	}

	cookieValue := strings.Repeat("i", 512)
	cookieHeaderCost := len("cookie") + len(cookieValue) + 32
	totalCookieHeaderCost := cookieHeaderCost * repeatedCookiesPerStream
	if totalCookieHeaderCost <= int(maxHeaderListSize) {
		t.Fatalf("test setup invalid: cookie header cost %d must exceed advertised max header list size %d", totalCookieHeaderCost, maxHeaderListSize)
	}
	if repeatedCookiesPerStream+4 >= http2cfg.MaxHeaderFields {
		t.Fatalf("test setup invalid: repeated cookies %d exceed header field budget %d", repeatedCookiesPerStream, http2cfg.MaxHeaderFields)
	}

	var headerBlock bytes.Buffer
	encoder := hpack.NewEncoder(&headerBlock)

	writeEncodedHeaders := func(streamID uint32, path string) {
		t.Helper()
		headerBlock.Reset()
		for _, field := range []hpack.HeaderField{
			{Name: ":method", Value: http.MethodGet},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: rt.Site.Host},
			{Name: ":path", Value: path},
		} {
			if err := encoder.WriteField(field); err != nil {
				t.Fatalf("encode stream %d field %q: %v", streamID, field.Name, err)
			}
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: append([]byte(nil), headerBlock.Bytes()...),
			EndStream:     true,
			EndHeaders:    true,
		}); err != nil {
			t.Fatalf("WriteHeaders(stream=%d,path=%q) error = %v", streamID, path, err)
		}
	}

	writeEncodedHeadersWithSingleCookie := func(streamID uint32, path string) {
		t.Helper()
		headerBlock.Reset()
		for _, field := range []hpack.HeaderField{
			{Name: ":method", Value: http.MethodGet},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: rt.Site.Host},
			{Name: ":path", Value: path},
			{Name: "cookie", Value: cookieValue},
		} {
			if err := encoder.WriteField(field); err != nil {
				t.Fatalf("encode prime stream %d field %q: %v", streamID, field.Name, err)
			}
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: append([]byte(nil), headerBlock.Bytes()...),
			EndStream:     true,
			EndHeaders:    true,
		}); err != nil {
			t.Fatalf("WriteHeaders(stream=%d,path=%q) error = %v", streamID, path, err)
		}
	}

	writeEncodedHeadersWithCookieBomb := func(streamID uint32, path string) {
		t.Helper()
		headerBlock.Reset()
		for _, field := range []hpack.HeaderField{
			{Name: ":method", Value: http.MethodGet},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: rt.Site.Host},
			{Name: ":path", Value: path},
			{Name: "cookie", Value: cookieValue},
		} {
			if err := encoder.WriteField(field); err != nil {
				t.Fatalf("encode attack stream %d field %q: %v", streamID, field.Name, err)
			}
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: append([]byte(nil), headerBlock.Bytes()...),
			EndStream:     true,
			EndHeaders:    false,
		}); err != nil {
			t.Fatalf("WriteHeaders(stream=%d,path=%q) error = %v", streamID, path, err)
		}
		for i := 0; i < repeatedContinuationsCount; i++ {
			headerBlock.Reset()
			if err := encoder.WriteField(hpack.HeaderField{Name: "cookie", Value: cookieValue}); err != nil {
				t.Fatalf("encode attack stream %d continuation %d: %v", streamID, i, err)
			}
			compressedContinuation := append([]byte(nil), headerBlock.Bytes()...)
			if len(compressedContinuation) == 0 {
				t.Fatalf("compressed continuation empty: stream=%d continuation=%d", streamID, i)
			}
			if len(compressedContinuation) >= len(cookieValue) {
				t.Fatalf("compressed continuation len = %d, want smaller than raw cookie len %d, stream=%d", len(compressedContinuation), len(cookieValue), streamID)
			}
			if err := fr.WriteContinuation(streamID, i == repeatedContinuationsCount-1, compressedContinuation); err != nil {
				t.Fatalf("WriteContinuation(stream=%d,index=%d) error = %v", streamID, i, err)
			}
		}
	}

	writeEncodedHeadersWithSingleCookie(1, "/prime-dynamic-table")
	readRawHTTP2ResponseStatus(t, conn, fr, 1, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/prime-dynamic-table" {
			t.Fatalf("prime upstream path = %q, want %q", path, "/prime-dynamic-table")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prime request did not reach upstream")
	}

	wantStatuses := make(map[uint32]string, normalStreamCount+rejectedStreamCount)
	const healthyPath = "/mixed-ok"
	const attackPath = "/mixed-attack"
	for i := 0; i < normalStreamCount; i++ {
		healthyStreamID := uint32(i*4 + 3)
		attackStreamID := uint32(i*4 + 5)

		writeEncodedHeaders(healthyStreamID, healthyPath)
		wantStatuses[healthyStreamID] = "204"

		writeEncodedHeadersWithCookieBomb(attackStreamID, attackPath)
		wantStatuses[attackStreamID] = "431"
	}

	readRawHTTP2ResponseStatuses(t, conn, fr, wantStatuses)

	primeCount := 1
	healthyCount := 0
	for healthyCount < normalStreamCount {
		select {
		case path := <-upstreamStarted:
			switch path {
			case "/prime-dynamic-table":
				primeCount++
			case healthyPath:
				healthyCount++
			default:
				t.Fatalf("unexpected upstream path during mixed sequence: %q", path)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("observed upstream paths incomplete: prime=%d healthy=%d", primeCount, healthyCount)
		}
	}
	if primeCount != 1 {
		t.Fatalf("prime upstream count = %d, want 1", primeCount)
	}
	if healthyCount != normalStreamCount {
		t.Fatalf("healthy upstream count = %d, want %d", healthyCount, normalStreamCount)
	}

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected extra upstream path after mixed sequence: %q", path)
	case <-time.After(200 * time.Millisecond):
	}

	const okStreamID uint32 = 27
	writeEncodedHeaders(okStreamID, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after mixed HPACK bomb sequence")
	}
}

func TestBuildDataServerHonorsHTTP2MaxConcurrentStreams(t *testing.T) {
	upstreamStarted := make(chan string, 2)
	releaseFirst := make(chan struct{})
	releaseSecond := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch r.URL.Path {
		case "/first":
			<-releaseFirst
		case "/second":
			<-releaseSecond
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "streams.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxConcurrentStreams = 1
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	baseTransport := &http.Transport{
		MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	http2Transport, err := http2.ConfigureTransports(baseTransport)
	if err != nil {
		t.Fatalf("ConfigureTransports() error = %v", err)
	}
	http2Transport.StrictMaxConcurrentStreams = true
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: baseTransport,
	}

	doRequest := func(path string) error {
		req, err := http.NewRequest(http.MethodGet, "https://"+bind+path, nil)
		if err != nil {
			return err
		}
		req.Host = rt.Site.Host
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.ProtoMajor != 2 {
			return fmt.Errorf("response protocol major = %d, want 2", resp.ProtoMajor)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if string(body) != "ok" {
			return fmt.Errorf("body = %q, want %q", string(body), "ok")
		}
		return nil
	}

	firstErrCh := make(chan error, 1)
	go func() {
		firstErrCh <- doRequest("/first")
	}()

	select {
	case path := <-upstreamStarted:
		if path != "/first" {
			t.Fatalf("first upstream path = %q, want %q", path, "/first")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not reach upstream")
	}

	secondErrCh := make(chan error, 1)
	go func() {
		secondErrCh <- doRequest("/second")
	}()

	select {
	case path := <-upstreamStarted:
		t.Fatalf("second request reached upstream before first completed: %q", path)
	case <-time.After(200 * time.Millisecond):
	}

	close(releaseFirst)

	select {
	case err := <-firstErrCh:
		if err != nil {
			t.Fatalf("first request failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not complete")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/second" {
			t.Fatalf("second upstream path = %q, want %q", path, "/second")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second request did not reach upstream after first completed")
	}

	close(releaseSecond)

	select {
	case err := <-secondErrCh:
		if err != nil {
			t.Fatalf("second request failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second request did not complete")
	}
}

func TestBuildDataServerCancelsUpstreamWhenHTTP2ClientCancelsStream(t *testing.T) {
	upstreamStarted := make(chan string, 2)
	upstreamCanceled := make(chan error, 1)
	releaseCanceledUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch r.URL.Path {
		case "/cancel":
			select {
			case <-r.Context().Done():
				upstreamCanceled <- r.Context().Err()
			case <-releaseCanceledUpstream:
			}
			return
		case "/after":
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
	}))
	defer upstream.Close()
	t.Cleanup(func() {
		close(releaseCanceledUpstream)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "cancel.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxConcurrentStreams = 1
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	baseTransport := &http.Transport{
		MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	http2Transport, err := http2.ConfigureTransports(baseTransport)
	if err != nil {
		t.Fatalf("ConfigureTransports() error = %v", err)
	}
	http2Transport.StrictMaxConcurrentStreams = true
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: baseTransport,
	}

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()

	firstReq, err := http.NewRequestWithContext(firstCtx, http.MethodGet, "https://"+bind+"/cancel", nil)
	if err != nil {
		t.Fatalf("build first request: %v", err)
	}
	firstReq.Host = rt.Site.Host

	firstErrCh := make(chan error, 1)
	go func() {
		resp, err := client.Do(firstReq)
		if resp != nil {
			resp.Body.Close()
		}
		firstErrCh <- err
	}()

	select {
	case path := <-upstreamStarted:
		if path != "/cancel" {
			t.Fatalf("first upstream path = %q, want %q", path, "/cancel")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancel request did not reach upstream")
	}

	cancelFirst()

	select {
	case err := <-firstErrCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first request error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first canceled request did not return")
	}

	secondReq, err := http.NewRequest(http.MethodGet, "https://"+bind+"/after", nil)
	if err != nil {
		t.Fatalf("build second request: %v", err)
	}
	secondReq.Host = rt.Site.Host

	secondResp, err := client.Do(secondReq)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	defer secondResp.Body.Close()
	if secondResp.ProtoMajor != 2 {
		t.Fatalf("second response protocol major = %d, want 2", secondResp.ProtoMajor)
	}
	if secondResp.StatusCode != http.StatusNoContent {
		t.Fatalf("second response status = %d, want %d", secondResp.StatusCode, http.StatusNoContent)
	}

	select {
	case path := <-upstreamStarted:
		if path != "/after" {
			t.Fatalf("second upstream path = %q, want %q", path, "/after")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second request did not reach upstream")
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("upstream request was not canceled after downstream HTTP/2 stream reset")
	}
}

func TestBuildDataServerSurvivesHTTP2CanceledStreamBurst(t *testing.T) {
	const burstSize = 12

	upstreamStarted := make(chan string, burstSize+1)
	upstreamCanceled := make(chan string, burstSize)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch {
		case strings.HasPrefix(r.URL.Path, "/cancel/"):
			<-r.Context().Done()
			upstreamCanceled <- r.URL.Path
			return
		case r.URL.Path == "/ok":
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}

	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "burst.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxConcurrentStreams = burstSize + 4
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	baseTransport := &http.Transport{
		MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	http2Transport, err := http2.ConfigureTransports(baseTransport)
	if err != nil {
		t.Fatalf("ConfigureTransports() error = %v", err)
	}
	http2Transport.StrictMaxConcurrentStreams = true
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: baseTransport,
	}

	cancelFns := make([]context.CancelFunc, 0, burstSize)
	burstErrCh := make(chan error, burstSize)
	expectedPaths := make(map[string]struct{}, burstSize)
	for i := 0; i < burstSize; i++ {
		path := fmt.Sprintf("/cancel/%d", i)
		expectedPaths[path] = struct{}{}
		reqCtx, cancel := context.WithCancel(context.Background())
		cancelFns = append(cancelFns, cancel)

		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://"+bind+path, nil)
		if err != nil {
			t.Fatalf("build burst request %d: %v", i, err)
		}
		req.Host = rt.Site.Host

		go func(req *http.Request) {
			resp, err := client.Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			burstErrCh <- err
		}(req)
	}

	startedPaths := make(map[string]struct{}, burstSize)
	for len(startedPaths) < burstSize {
		select {
		case path := <-upstreamStarted:
			if _, ok := expectedPaths[path]; !ok {
				t.Fatalf("unexpected burst upstream path: %q", path)
			}
			startedPaths[path] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatalf("burst requests started = %d, want %d", len(startedPaths), burstSize)
		}
	}

	for _, cancel := range cancelFns {
		cancel()
	}

	for i := 0; i < burstSize; i++ {
		select {
		case err := <-burstErrCh:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("burst request error = %v, want context canceled", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("burst canceled request %d did not return", i)
		}
	}

	canceledPaths := make(map[string]struct{}, burstSize)
	for len(canceledPaths) < burstSize {
		select {
		case path := <-upstreamCanceled:
			if _, ok := expectedPaths[path]; !ok {
				t.Fatalf("unexpected canceled upstream path: %q", path)
			}
			canceledPaths[path] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatalf("upstream canceled paths = %d, want %d", len(canceledPaths), burstSize)
		}
	}

	okReq, err := http.NewRequest(http.MethodGet, "https://"+bind+"/ok", nil)
	if err != nil {
		t.Fatalf("build healthy request: %v", err)
	}
	okReq.Host = rt.Site.Host

	okResp, err := client.Do(okReq)
	if err != nil {
		t.Fatalf("healthy request after burst failed: %v", err)
	}
	defer okResp.Body.Close()
	if okResp.ProtoMajor != 2 {
		t.Fatalf("healthy response protocol major = %d, want 2", okResp.ProtoMajor)
	}
	if okResp.StatusCode != http.StatusNoContent {
		t.Fatalf("healthy response status = %d, want %d", okResp.StatusCode, http.StatusNoContent)
	}

	select {
	case path := <-upstreamStarted:
		if path != "/ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after canceled burst")
	}
}

func TestBuildDataServerSurvivesRawHTTP2RSTStreamBurst(t *testing.T) {
	const burstSize = 8

	upstreamStarted := make(chan string, burstSize+1)
	upstreamCanceled := make(chan string, burstSize)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch {
		case strings.HasPrefix(r.URL.Path, "/raw-cancel/"):
			<-r.Context().Done()
			upstreamCanceled <- r.URL.Path
			return
		case r.URL.Path == "/raw-ok":
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}

	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "raw-rst.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxConcurrentStreams = burstSize + 4
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	streamIDs := make([]uint32, 0, burstSize)
	expectedPaths := make(map[string]struct{}, burstSize)
	for i := 0; i < burstSize; i++ {
		streamID := uint32(i*2 + 1)
		streamIDs = append(streamIDs, streamID)
		path := fmt.Sprintf("/raw-cancel/%d", i)
		expectedPaths[path] = struct{}{}
		writeRawHTTP2Headers(t, fr, streamID, rt.Site.Host, path)
	}

	startedPaths := make(map[string]struct{}, burstSize)
	for len(startedPaths) < burstSize {
		select {
		case path := <-upstreamStarted:
			if _, ok := expectedPaths[path]; !ok {
				t.Fatalf("unexpected raw burst upstream path: %q", path)
			}
			startedPaths[path] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatalf("raw burst requests started = %d, want %d", len(startedPaths), burstSize)
		}
	}

	for _, streamID := range streamIDs {
		if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
			t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
		}
	}

	canceledPaths := make(map[string]struct{}, burstSize)
	for len(canceledPaths) < burstSize {
		select {
		case path := <-upstreamCanceled:
			if _, ok := expectedPaths[path]; !ok {
				t.Fatalf("unexpected raw canceled upstream path: %q", path)
			}
			canceledPaths[path] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatalf("raw upstream canceled paths = %d, want %d", len(canceledPaths), burstSize)
		}
	}

	okStreamID := uint32(burstSize*2 + 1)
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("raw healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raw healthy request did not reach upstream after RST burst")
	}
}

func TestBuildDataServerCancelsUpstreamWhenRawHTTP2ZeroIncrementWindowUpdateBurstTriggersServerReset(t *testing.T) {
	const burstSize = 8

	upstreamStarted := make(chan string, burstSize+1)
	upstreamCanceled := make(chan string, burstSize)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch {
		case strings.HasPrefix(r.URL.Path, "/proto-reset/"):
			<-r.Context().Done()
			upstreamCanceled <- r.URL.Path
			return
		case r.URL.Path == "/raw-ok":
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "server-reset.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxConcurrentStreams = burstSize + 4
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	streamIDs := make([]uint32, 0, burstSize)
	expectedPaths := make(map[string]struct{}, burstSize)
	expectedRST := make(map[uint32]http2.ErrCode, burstSize)
	for i := 0; i < burstSize; i++ {
		streamID := uint32(i*2 + 1)
		streamIDs = append(streamIDs, streamID)
		path := fmt.Sprintf("/proto-reset/%d", i)
		expectedPaths[path] = struct{}{}
		expectedRST[streamID] = http2.ErrCodeProtocol
		writeRawHTTP2Headers(t, fr, streamID, rt.Site.Host, path)
	}

	startedPaths := make(map[string]struct{}, burstSize)
	for len(startedPaths) < burstSize {
		select {
		case path := <-upstreamStarted:
			if _, ok := expectedPaths[path]; !ok {
				t.Fatalf("unexpected protocol reset upstream path: %q", path)
			}
			startedPaths[path] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatalf("protocol reset requests started = %d, want %d", len(startedPaths), burstSize)
		}
	}

	for _, streamID := range streamIDs {
		writeRawHTTP2WindowUpdate(t, fr, streamID, 0)
	}

	readRawHTTP2RSTStreams(t, conn, fr, expectedRST)

	canceledPaths := make(map[string]struct{}, burstSize)
	for len(canceledPaths) < burstSize {
		select {
		case path := <-upstreamCanceled:
			if _, ok := expectedPaths[path]; !ok {
				t.Fatalf("unexpected protocol reset canceled upstream path: %q", path)
			}
			canceledPaths[path] = struct{}{}
		case <-time.After(2 * time.Second):
			t.Fatalf("protocol reset upstream canceled paths = %d, want %d", len(canceledPaths), burstSize)
		}
	}

	okStreamID := uint32(burstSize*2 + 1)
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("protocol reset healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raw healthy request did not reach upstream after protocol reset burst")
	}
}

func TestBuildDataServerRejectsRawHTTP2WindowUpdateOnIdleStream(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "idle-window-update.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	writeRawHTTP2WindowUpdate(t, fr, 3, 1)
	readRawHTTP2GoAway(t, conn, fr, http2.ErrCodeProtocol)

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after idle stream WINDOW_UPDATE: %q", path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBuildDataServerCancelsUpstreamWhenRawHTTP2ClientSendsDataAfterEndStream(t *testing.T) {
	upstreamStarted := make(chan string, 2)
	upstreamCanceled := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch r.URL.Path {
		case "/extra-data":
			<-r.Context().Done()
			upstreamCanceled <- r.URL.Path
			return
		case "/raw-ok":
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "extra-data.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const brokenStreamID uint32 = 1
	writeRawHTTP2Headers(t, fr, brokenStreamID, rt.Site.Host, "/extra-data")

	select {
	case path := <-upstreamStarted:
		if path != "/extra-data" {
			t.Fatalf("upstream path = %q, want %q", path, "/extra-data")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("extra-data request did not reach upstream")
	}

	writeRawHTTP2Data(t, fr, brokenStreamID, false, []byte("boom"))
	readRawHTTP2RSTStreams(t, conn, fr, map[uint32]http2.ErrCode{
		brokenStreamID: http2.ErrCodeStreamClosed,
	})

	select {
	case path := <-upstreamCanceled:
		if path != "/extra-data" {
			t.Fatalf("canceled upstream path = %q, want %q", path, "/extra-data")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request was not canceled after DATA arrived on end-stream request")
	}

	const okStreamID uint32 = 3
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after end-stream DATA error")
	}
}

func TestBuildDataServerRejectsRawHTTP2ContinuationOnWrongStream(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "continuation.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	writeRawHTTP2HeadersFrame(t, fr, 1, rt.Site.Host, "/broken-continuation", false, false)
	writeRawHTTP2Continuation(t, fr, 3, true, nil)
	readRawHTTP2GoAway(t, conn, fr, http2.ErrCodeProtocol)

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after illegal CONTINUATION: %q", path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBuildDataServerTimesOutStalledRawHTTP2HeaderBlock(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stalled-header.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.ReadTimeoutSeconds = 1
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	writeRawHTTP2HeadersFrame(t, fr, 1, rt.Site.Host, "/stalled-header", false, false)
	readRawHTTP2GoAway(t, conn, fr, http2.ErrCodeProtocol)

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after stalled header timeout: %q", path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBuildDataServerTimesOutStalledRawHTTP2RequestBody(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stalled-body.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.ReadTimeoutSeconds = 1
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const brokenStreamID uint32 = 1
	writeRawHTTP2HeadersFrameWithMethod(t, fr, brokenStreamID, http.MethodPost, rt.Site.Host, "/stalled-body", false, true)
	writeRawHTTP2Data(t, fr, brokenStreamID, false, []byte("ping"))

	readRawHTTP2GoAway(t, conn, fr, http2.ErrCodeProtocol)

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after request body timeout: %q", path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBuildDataServerRecoversAfterRawHTTP2StalledRequestBodyBurstTimesOut(t *testing.T) {
	const burstSize = 6

	upstreamStarted := make(chan string, burstSize+1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stalled-body-burst.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.ReadTimeoutSeconds = 1
	http2cfg.MaxConcurrentStreams = burstSize + 2
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	for i := 0; i < burstSize; i++ {
		streamID := uint32(i*2 + 1)
		path := fmt.Sprintf("/stalled-burst/%d", i)
		writeRawHTTP2HeadersFrameWithMethod(t, fr, streamID, http.MethodPost, rt.Site.Host, path, false, true)
		writeRawHTTP2Data(t, fr, streamID, false, []byte("ping"))
	}

	readRawHTTP2GoAway(t, conn, fr, http2.ErrCodeProtocol)

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after stalled request body burst timeout: %q", path)
	case <-time.After(200 * time.Millisecond):
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
			ForceAttemptHTTP2: true,
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+bind+"/ok", nil)
	if err != nil {
		t.Fatalf("build healthy request: %v", err)
	}
	req.Host = rt.Site.Host

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("healthy request after stalled body burst failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Fatalf("healthy response protocol major = %d, want 2", resp.ProtoMajor)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("healthy response status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	select {
	case path := <-upstreamStarted:
		if path != "/ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after stalled request body burst timeout")
	}
}

func TestBuildDataServerRejectsRawHTTP2DataOverPerStreamFlowControlWindow(t *testing.T) {
	const (
		streamWindow = 16 << 10
		frameSize    = 32 << 10
	)

	upstreamStarted := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "flow-control-stream.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxUploadBufferPerConnection = 128 << 10
	http2cfg.MaxUploadBufferPerStream = streamWindow
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const brokenStreamID uint32 = 1
	writeRawHTTP2HeadersFrameWithMethod(t, fr, brokenStreamID, http.MethodPost, rt.Site.Host, "/flow-stream", false, true)
	writeRawHTTP2Data(t, fr, brokenStreamID, false, bytes.Repeat([]byte("s"), frameSize))
	readRawHTTP2RSTStreams(t, conn, fr, map[uint32]http2.ErrCode{
		brokenStreamID: http2.ErrCodeFlowControl,
	})

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after per-stream flow control violation: %q", path)
	case <-time.After(200 * time.Millisecond):
	}

	const okStreamID uint32 = 3
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after per-stream flow control violation")
	}
}

func TestBuildDataServerKeepsHealthyRawHTTP2DataStreamAliveWhenSiblingStreamExceedsPerStreamFlowControlWindow(t *testing.T) {
	const (
		streamWindow      = 16 << 10
		brokenFrameSize   = 32 << 10
		healthyPrefixSize = 8 << 10
		healthyBodySize   = 12 << 10
	)

	healthyBody := bytes.Repeat([]byte("h"), healthyBodySize)
	healthyPrefixRead := make(chan []byte, 1)
	healthyResult := make(chan error, 1)
	releaseHealthy := make(chan struct{})
	var releaseHealthyOnce sync.Once
	releaseHealthyNow := func() {
		releaseHealthyOnce.Do(func() {
			close(releaseHealthy)
		})
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "flow-control-siblings.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:     snapshotpkg.DefaultTLSDefaults(),
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxUploadBufferPerConnection = 128 << 10
	http2cfg.MaxUploadBufferPerStream = streamWindow
	http2cfg.MaxConcurrentStreams = 4
	sn := &snapshotpkg.Snapshot{
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	tlsCfg := buildListenerTLS(rt, sn)
	if tlsCfg == nil {
		t.Fatal("expected TLS config")
	}

	srv := hserver.New(
		hserver.WithHostPorts(bind),
		hserver.WithTLS(tlsCfg),
		hserver.WithALPN(true),
	)
	if srv == nil {
		t.Fatal("expected data server")
	}
	srv.AddProtocol("h2", shfactory.NewServerFactory(http2ServerFactoryOptions(http2cfg)...))
	srv.Any("/*any", func(ctx context.Context, c *happ.RequestContext) {
		switch string(c.Path()) {
		case "/healthy-flow":
			prefix := make([]byte, healthyPrefixSize)
			if _, err := io.ReadFull(c.Request.BodyStream(), prefix); err != nil {
				healthyResult <- fmt.Errorf("read healthy handler prefix: %w", err)
				c.Response.SetStatusCode(http.StatusInternalServerError)
				return
			}
			healthyPrefixRead <- append([]byte(nil), prefix...)
			<-releaseHealthy
			rest, err := io.ReadAll(c.Request.BodyStream())
			if err != nil {
				healthyResult <- fmt.Errorf("read healthy handler body tail: %w", err)
				c.Response.SetStatusCode(http.StatusInternalServerError)
				return
			}
			got := append(prefix, rest...)
			if !bytes.Equal(got, healthyBody) {
				healthyResult <- fmt.Errorf("healthy handler body mismatch: got=%d want=%d", len(got), len(healthyBody))
				c.Response.SetStatusCode(http.StatusInternalServerError)
				return
			}
			healthyResult <- nil
			c.Response.SetStatusCode(http.StatusNoContent)
		case "/broken-flow":
			_, _ = io.Copy(io.Discard, c.Request.BodyStream())
			return
		case "/raw-ok":
			c.Response.SetStatusCode(http.StatusNoContent)
		default:
			c.Response.SetStatusCode(http.StatusInternalServerError)
		}
	})

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		releaseHealthyNow()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const healthyStreamID uint32 = 1
	writeRawHTTP2HeadersFrameWithMethod(t, fr, healthyStreamID, http.MethodPost, rt.Site.Host, "/healthy-flow", false, true)
	writeRawHTTP2Data(t, fr, healthyStreamID, false, healthyBody[:healthyPrefixSize])

	select {
	case got := <-healthyPrefixRead:
		if !bytes.Equal(got, healthyBody[:len(got)]) {
			t.Fatalf("healthy handler prefix mismatch: got=%d want=%d", len(got), len(healthyBody[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy stream did not reach handler before sibling flow control violation")
	}

	const brokenStreamID uint32 = 3
	writeRawHTTP2HeadersFrameWithMethod(t, fr, brokenStreamID, http.MethodPost, rt.Site.Host, "/broken-flow", false, true)
	writeRawHTTP2Data(t, fr, brokenStreamID, false, bytes.Repeat([]byte("b"), brokenFrameSize))
	readRawHTTP2RSTStreams(t, conn, fr, map[uint32]http2.ErrCode{
		brokenStreamID: http2.ErrCodeFlowControl,
	})

	select {
	case err := <-healthyResult:
		t.Fatalf("unexpected healthy handler result before stream completed: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	writeRawHTTP2Data(t, fr, healthyStreamID, true, healthyBody[healthyPrefixSize:])
	releaseHealthyNow()
	readRawHTTP2ResponseStatus(t, conn, fr, healthyStreamID, "204")

	select {
	case err := <-healthyResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for healthy handler body verification after sibling flow control violation")
	}

	const okStreamID uint32 = 5
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")
}

func TestBuildDataServerKeepsHealthyRawHTTP2ResponseStreamAliveWhenSiblingResponseStreamIsFlowControlled(t *testing.T) {
	const slowBodySize = 32 << 10

	slowBody := bytes.Repeat([]byte("r"), slowBodySize)
	upstreamStarted := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch r.URL.Path {
		case "/slow-response":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(slowBody)
		case "/raw-ok":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
		}
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "response-flow-control.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatalf("WriteSettings(INITIAL_WINDOW_SIZE=0) error = %v", err)
	}
	readRawHTTP2SettingsAck(t, conn, fr)

	const blockedStreamID uint32 = 1
	writeRawHTTP2Headers(t, fr, blockedStreamID, rt.Site.Host, "/slow-response")
	if ended := readRawHTTP2ResponseHeadersStatus(t, conn, fr, blockedStreamID, "200"); ended {
		t.Fatal("slow response unexpectedly ended before any flow-control quota was granted")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/slow-response" {
			t.Fatalf("blocked upstream path = %q, want %q", path, "/slow-response")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked response request did not reach upstream")
	}

	const okStreamID uint32 = 3
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy response request did not reach upstream while sibling response stream was flow-controlled")
	}

	writeRawHTTP2WindowUpdate(t, fr, blockedStreamID, uint32(len(slowBody)))
	readRawHTTP2StreamCompletion(t, conn, fr, blockedStreamID)
}

func TestBuildDataServerRejectsRawHTTP2DataOverConnectionFlowControlWindow(t *testing.T) {
	const (
		connWindow      = 65535
		streamWindow    = 128 << 10
		firstFrameSize  = 40 << 10
		secondFrameSize = 32 << 10
	)

	requestStarted := make(chan string, 3)
	releaseBlockedHandlers := make(chan struct{})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "flow-control-connection.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:     snapshotpkg.DefaultTLSDefaults(),
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxUploadBufferPerConnection = connWindow
	http2cfg.MaxUploadBufferPerStream = streamWindow
	sn := &snapshotpkg.Snapshot{
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	tlsCfg := buildListenerTLS(rt, sn)
	if tlsCfg == nil {
		t.Fatal("expected TLS config")
	}

	srv := hserver.New(
		hserver.WithHostPorts(bind),
		hserver.WithTLS(tlsCfg),
		hserver.WithALPN(true),
	)
	srv.AddProtocol("h2", shfactory.NewServerFactory(http2ServerFactoryOptions(http2cfg)...))
	srv.Any("/*any", func(ctx context.Context, c *happ.RequestContext) {
		path := string(c.Path())
		requestStarted <- path
		if string(c.Method()) == http.MethodPost && strings.HasPrefix(path, "/flow-conn/") {
			<-releaseBlockedHandlers
			return
		}
		c.Response.SetStatusCode(http.StatusNoContent)
	})

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		close(releaseBlockedHandlers)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const firstStreamID uint32 = 1
	writeRawHTTP2HeadersFrameWithMethod(t, fr, firstStreamID, http.MethodPost, rt.Site.Host, "/flow-conn/first", false, true)
	select {
	case path := <-requestStarted:
		if path != "/flow-conn/first" {
			t.Fatalf("first blocked handler path = %q, want %q", path, "/flow-conn/first")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first blocked request did not reach handler")
	}
	writeRawHTTP2Data(t, fr, firstStreamID, false, bytes.Repeat([]byte("a"), firstFrameSize))

	const brokenStreamID uint32 = 3
	writeRawHTTP2HeadersFrameWithMethod(t, fr, brokenStreamID, http.MethodPost, rt.Site.Host, "/flow-conn/second", false, true)
	select {
	case path := <-requestStarted:
		if path != "/flow-conn/second" {
			t.Fatalf("second blocked handler path = %q, want %q", path, "/flow-conn/second")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second blocked request did not reach handler")
	}
	writeRawHTTP2Data(t, fr, brokenStreamID, false, bytes.Repeat([]byte("b"), secondFrameSize))
	readRawHTTP2RSTStreams(t, conn, fr, map[uint32]http2.ErrCode{
		brokenStreamID: http2.ErrCodeFlowControl,
	})

	const okStreamID uint32 = 5
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-requestStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy handler path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach handler after connection flow control violation")
	}
}

func TestBuildDataServerRejectsRawHTTP2PingOnNonZeroStream(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "ping-invalid.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	writeRawHTTP2PingFrame(t, fr, 1, false, [8]byte{'b', 'a', 'd', '-', 'p', 'i', 'n', 'g'})
	readRawHTTP2GoAway(t, conn, fr, http2.ErrCodeProtocol)

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after illegal PING: %q", path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBuildDataServerRejectsRawHTTP2ConnectionWindowUpdateOverflow(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "window-overflow.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	writeRawHTTP2WindowUpdate(t, fr, 0, 2147483647)
	readRawHTTP2GoAway(t, conn, fr, http2.ErrCodeFlowControl)

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after connection WINDOW_UPDATE overflow: %q", path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBuildDataServerCancelsUpstreamWhenRawHTTP2StreamWindowUpdateOverflows(t *testing.T) {
	upstreamStarted := make(chan string, 2)
	upstreamCanceled := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch r.URL.Path {
		case "/stream-window-overflow":
			<-r.Context().Done()
			upstreamCanceled <- r.URL.Path
			return
		case "/raw-ok":
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-window-overflow.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const brokenStreamID uint32 = 1
	writeRawHTTP2Headers(t, fr, brokenStreamID, rt.Site.Host, "/stream-window-overflow")

	select {
	case path := <-upstreamStarted:
		if path != "/stream-window-overflow" {
			t.Fatalf("upstream path = %q, want %q", path, "/stream-window-overflow")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stream window overflow request did not reach upstream")
	}

	writeRawHTTP2WindowUpdate(t, fr, brokenStreamID, 2147483647)
	readRawHTTP2RSTStreams(t, conn, fr, map[uint32]http2.ErrCode{
		brokenStreamID: http2.ErrCodeFlowControl,
	})

	select {
	case path := <-upstreamCanceled:
		if path != "/stream-window-overflow" {
			t.Fatalf("canceled upstream path = %q, want %q", path, "/stream-window-overflow")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request was not canceled after stream WINDOW_UPDATE overflow")
	}

	const okStreamID uint32 = 3
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after stream WINDOW_UPDATE overflow")
	}
}

func TestBuildDataServerCompletesActiveStreamAfterRawHTTP2ConnectionGoAway(t *testing.T) {
	upstreamStarted := make(chan string, 2)
	releaseSlow := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch r.URL.Path {
		case "/goaway-ok":
			<-releaseSlow
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
			return
		}
	}))
	defer upstream.Close()
	t.Cleanup(func() {
		select {
		case <-releaseSlow:
		default:
			close(releaseSlow)
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "goaway-active.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const slowStreamID uint32 = 1
	writeRawHTTP2Headers(t, fr, slowStreamID, rt.Site.Host, "/goaway-ok")

	select {
	case path := <-upstreamStarted:
		if path != "/goaway-ok" {
			t.Fatalf("upstream path = %q, want %q", path, "/goaway-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow request did not reach upstream")
	}

	writeRawHTTP2PingFrame(t, fr, 1, false, [8]byte{'g', 'o', 'a', 'w', 'a', 'y', '!', '!'})
	readRawHTTP2GoAway(t, conn, fr, http2.ErrCodeProtocol)

	const afterGoAwayStreamID uint32 = 3
	writeRawHTTP2Headers(t, fr, afterGoAwayStreamID, rt.Site.Host, "/after-goaway")
	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path after GOAWAY: %q", path)
	case <-time.After(200 * time.Millisecond):
	}

	close(releaseSlow)
	readRawHTTP2ResponseStatus(t, conn, fr, slowStreamID, "204")
}

func TestLoadDropPolicyPreservesFallbackForMissingBoolFields(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	repo := repository.NewSystemSettingsRepo(db)
	if err := repo.Set("drop_policy", `{"enabled":false,"bot_score_threshold":90}`); err != nil {
		t.Fatalf("seed drop policy: %v", err)
	}

	got := loadDropPolicy(repo, core.DefaultDropConfig())
	if got.Enabled {
		t.Fatalf("expected explicit enabled=false to be preserved, got %#v", got)
	}
	if got.BotScoreThreshold != 90 {
		t.Fatalf("expected bot threshold to be loaded, got %#v", got)
	}
	if !got.CVEAutoDropCritical || !got.CVEAutoDropHigh {
		t.Fatalf("expected missing CVE auto-drop fields to keep fallback true, got %#v", got)
	}
}

func TestAdminPasswordMinLengthUsesProtectionConfig(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	repo := repository.NewSystemSettingsRepo(db)

	if got, want := adminPasswordMinLength(repo), store.DefaultProtectionConfig().LoginMinPasswordLength; got != want {
		t.Fatalf("default min password length = %d, want %d", got, want)
	}

	cfg := store.DefaultProtectionConfig()
	cfg.LoginMinPasswordLength = 14
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal protection: %v", err)
	}
	if err := repo.Set("protection", string(data)); err != nil {
		t.Fatalf("seed protection: %v", err)
	}
	if got := adminPasswordMinLength(repo); got != 14 {
		t.Fatalf("configured min password length = %d, want 14", got)
	}

	cfg.LoginMinPasswordLength = 0
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal protection fallback: %v", err)
	}
	if err := repo.Set("protection", string(data)); err != nil {
		t.Fatalf("seed fallback protection: %v", err)
	}
	if got, want := adminPasswordMinLength(repo), store.DefaultProtectionConfig().LoginMinPasswordLength; got != want {
		t.Fatalf("fallback min password length = %d, want %d", got, want)
	}
}

func TestParseCipherSuitesRecognizesNames(t *testing.T) {
	got := parseCipherSuites("49199,0xc030,TLS_AES_128_GCM_SHA256,ECDHE_RSA_WITH_AES_256_GCM_SHA384")
	if len(got) != 2 {
		t.Fatalf("expected 2 cipher suites, got %#v", got)
	}
	if got[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("unexpected first cipher suite: %v", got[0])
	}
	if got[1] != tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 {
		t.Fatalf("unexpected second cipher suite: %v", got[1])
	}
}

func TestBuildListenerTLSAppliesALPNAndBounds(t *testing.T) {
	sn := &snapshotpkg.Snapshot{}
	rt := snapshotpkg.SiteRuntime{
		Bind: ":443",
		Site: store.Site{
			TLSEnabled:    true,
			MinTLSVersion: "1.2",
			MaxTLSVersion: "1.3",
			ALPN:          "h2,h3,http/1.1",
		},
	}

	cfg := buildListenerTLS(rt, sn)
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("unexpected TLS bounds: min=%v max=%v", cfg.MinVersion, cfg.MaxVersion)
	}
	want := []string{"h2", "http/1.1"}
	if len(cfg.NextProtos) != len(want) {
		t.Fatalf("unexpected ALPN list: %#v", cfg.NextProtos)
	}
	for i := range want {
		if cfg.NextProtos[i] != want[i] {
			t.Fatalf("unexpected ALPN list: got=%#v want=%#v", cfg.NextProtos, want)
		}
	}
	if cfg.GetCertificate == nil {
		t.Fatal("expected dynamic certificate selector")
	}
}

func TestBuildListenerTLSPromotesHTTP2ForHTTP3OnlyALPN(t *testing.T) {
	sn := &snapshotpkg.Snapshot{}
	rt := snapshotpkg.SiteRuntime{
		Bind: ":443",
		Site: store.Site{
			TLSEnabled: true,
			ALPN:       "h3,http/1.1",
		},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			HTTP2Enabled:   true,
			HTTP3Enabled:   true,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
	}

	cfg := buildListenerTLS(rt, sn)
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	want := []string{"h2", "http/1.1"}
	if len(cfg.NextProtos) != len(want) {
		t.Fatalf("unexpected ALPN list: %#v", cfg.NextProtos)
	}
	for i := range want {
		if cfg.NextProtos[i] != want[i] {
			t.Fatalf("unexpected ALPN list: got=%#v want=%#v", cfg.NextProtos, want)
		}
	}
}

func TestBuildListenerTLSRemovesHTTP2WhenMaxTLSBelowTLS12(t *testing.T) {
	sn := &snapshotpkg.Snapshot{}
	rt := snapshotpkg.SiteRuntime{
		Bind: ":443",
		Site: store.Site{
			TLSEnabled:    true,
			MaxTLSVersion: "TLS11",
			ALPN:          "h2,http/1.1",
		},
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
	}

	cfg := buildListenerTLS(rt, sn)
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if cfg.MaxVersion != tls.VersionTLS11 {
		t.Fatalf("TLS max version = %#x, want %#x", cfg.MaxVersion, tls.VersionTLS11)
	}
	want := []string{"http/1.1"}
	if len(cfg.NextProtos) != len(want) {
		t.Fatalf("unexpected ALPN list: %#v", cfg.NextProtos)
	}
	for i := range want {
		if cfg.NextProtos[i] != want[i] {
			t.Fatalf("unexpected ALPN list: got=%#v want=%#v", cfg.NextProtos, want)
		}
	}
}

func TestBuildListenerTLSHonorsNetworkProtocolSwitches(t *testing.T) {
	sn := &snapshotpkg.Snapshot{}
	rt := snapshotpkg.SiteRuntime{
		Bind: ":443",
		Site: store.Site{
			TLSEnabled: true,
		},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			HTTP2Enabled:   false,
			HTTP3Enabled:   false,
			DefaultALPN:    "h2,h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
	}

	cfg := buildListenerTLS(rt, sn)
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	want := []string{"http/1.1"}
	if len(cfg.NextProtos) != len(want) {
		t.Fatalf("unexpected ALPN list: %#v", cfg.NextProtos)
	}
	for i := range want {
		if cfg.NextProtos[i] != want[i] {
			t.Fatalf("unexpected ALPN list: got=%#v want=%#v", cfg.NextProtos, want)
		}
	}
}

func TestBuildListenerTLSAppliesSessionTicketSwitch(t *testing.T) {
	sn := &snapshotpkg.Snapshot{}
	tlsDefaults := snapshotpkg.DefaultTLSDefaults()
	tlsDefaults.SessionTicketsEnabled = false
	rt := snapshotpkg.SiteRuntime{
		Bind: ":443",
		Site: store.Site{
			TLSEnabled: true,
		},
		NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:     tlsDefaults,
	}

	cfg := buildListenerTLS(rt, sn)
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if !cfg.SessionTicketsDisabled {
		t.Fatal("session_tickets_enabled=false should set SessionTicketsDisabled=true")
	}
}

func TestSiteListenerFingerprintIncludesTLSDefaultsThatAffectListenerTLS(t *testing.T) {
	buildSnapshot := func(curves string, preferServerCipherSuites bool, sessionTicketsEnabled bool) *snapshotpkg.Snapshot {
		return &snapshotpkg.Snapshot{
			Sites: map[string]snapshotpkg.SiteRuntime{
				"site": {
					Bind: ":443",
					Site: store.Site{
						ID:         1,
						Bind:       ":443",
						Host:       "example.com",
						TLSEnabled: true,
					},
					NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
					TLSDefaults: snapshotpkg.TLSDefaults{
						MinVersion:               "TLS10",
						MaxVersion:               "TLS13",
						DefaultALPN:              "h2,h3,http/1.1",
						CurvePreferences:         curves,
						PreferServerCipherSuites: preferServerCipherSuites,
						SessionTicketsEnabled:    sessionTicketsEnabled,
						SelfSignedOnIP:           true,
					},
				},
			},
		}
	}

	base := siteListenerFingerprint(":443", buildSnapshot("X25519,CurveP256", true, true))
	curveChanged := siteListenerFingerprint(":443", buildSnapshot("CurveP384", true, true))
	preferChanged := siteListenerFingerprint(":443", buildSnapshot("X25519,CurveP256", false, true))
	sessionTicketsChanged := siteListenerFingerprint(":443", buildSnapshot("X25519,CurveP256", true, false))

	if base == curveChanged {
		t.Fatal("changing tls_default_config.curve_preferences should change listener fingerprint")
	}
	if base == preferChanged {
		t.Fatal("changing tls_default_config.prefer_server_cipher_suites should change listener fingerprint")
	}
	if base == sessionTicketsChanged {
		t.Fatal("changing tls_default_config.session_tickets_enabled should change listener fingerprint")
	}
}

func TestSiteListenerFingerprintIncludesOCSPStapleMaterial(t *testing.T) {
	certPEM, keyPEM, err := acmepkg.GenerateSelfSignedPEM("ocsp-fingerprint.example.test", []string{"ocsp-fingerprint.example.test"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}

	buildSnapshot := func(ocspDER []byte) *snapshotpkg.Snapshot {
		tlsDefaults := snapshotpkg.DefaultTLSDefaults()
		rt := snapshotpkg.SiteRuntime{
			Bind: ":443",
			Site: store.Site{
				ID:         1,
				Bind:       ":443",
				Host:       "ocsp-fingerprint.example.test",
				TLSEnabled: true,
			},
			Certificate: &store.Certificate{
				CertPEM:       certPEM,
				KeyPEM:        keyPEM,
				OCSPStaplePEM: string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: ocspDER})),
			},
			NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
			TLSDefaults:     tlsDefaults,
		}
		return &snapshotpkg.Snapshot{
			TLSDefaults: tlsDefaults,
			Sites: map[string]snapshotpkg.SiteRuntime{
				snapshotpkg.SiteMapKey(rt.Bind, rt.Site.Host): rt,
			},
		}
	}

	base := siteListenerFingerprint(":443", buildSnapshot([]byte{0x30, 0x03, 0x0a, 0x01, 0x00}))
	changed := siteListenerFingerprint(":443", buildSnapshot([]byte{0x30, 0x03, 0x0a, 0x01, 0x01}))
	if base == changed {
		t.Fatal("changing certificate OCSP staple material should change listener fingerprint")
	}
}

func TestSiteListenerFingerprintChangesWhenHTTP3BindChanges(t *testing.T) {
	buildSnapshot := func(http3Bind string) *snapshotpkg.Snapshot {
		return &snapshotpkg.Snapshot{
			Sites: map[string]snapshotpkg.SiteRuntime{
				"site": {
					Bind: ":443",
					Site: store.Site{
						ID:         1,
						Bind:       ":443",
						Host:       "example.com",
						TLSEnabled: true,
					},
					NetworkDefaults: snapshotpkg.NetworkDefaults{
						HTTP2Enabled:   true,
						HTTP3Enabled:   true,
						HTTP3Bind:      http3Bind,
						DefaultALPN:    "h2,h3,http/1.1",
						DefaultNetwork: "tcp",
					},
					TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
				},
			},
		}
	}

	base := siteListenerFingerprint(":443", buildSnapshot(":443"))
	changed := siteListenerFingerprint(":443", buildSnapshot(":8443"))

	if base == changed {
		t.Fatal("changing network_config.http3_bind should change listener fingerprint")
	}
}

func TestSiteListenerFingerprintChangesWhenHTTP2ConfigChanges(t *testing.T) {
	buildSnapshot := func(maxConcurrentStreams uint32) *snapshotpkg.Snapshot {
		http2cfg := snapshotpkg.DefaultHTTP2Config()
		http2cfg.MaxConcurrentStreams = maxConcurrentStreams
		return &snapshotpkg.Snapshot{
			Sites: map[string]snapshotpkg.SiteRuntime{
				"site": {
					Bind: ":443",
					Site: store.Site{
						ID:         1,
						Bind:       ":443",
						Host:       "example.com",
						TLSEnabled: true,
					},
					NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
					TLSDefaults:     snapshotpkg.DefaultTLSDefaults(),
				},
			},
			HTTP2Config: http2cfg,
		}
	}

	base := siteListenerFingerprint(":443", buildSnapshot(100))
	changed := siteListenerFingerprint(":443", buildSnapshot(200))

	if base == changed {
		t.Fatal("changing http2_config.max_concurrent_streams should change listener fingerprint")
	}
}

func TestSiteListenerFingerprintChangesWhenHTTP2HeaderBytesChange(t *testing.T) {
	buildSnapshot := func(maxHeaderBytes int) *snapshotpkg.Snapshot {
		http2cfg := snapshotpkg.DefaultHTTP2Config()
		http2cfg.MaxHeaderBytes = maxHeaderBytes
		return &snapshotpkg.Snapshot{
			Sites: map[string]snapshotpkg.SiteRuntime{
				"site": {
					Bind: ":443",
					Site: store.Site{
						ID:         1,
						Bind:       ":443",
						Host:       "example.com",
						TLSEnabled: true,
					},
					NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
					TLSDefaults:     snapshotpkg.DefaultTLSDefaults(),
				},
			},
			HTTP2Config: http2cfg,
		}
	}

	base := siteListenerFingerprint(":443", buildSnapshot(1<<20))
	changed := siteListenerFingerprint(":443", buildSnapshot(256<<10))

	if base == changed {
		t.Fatal("changing http2_config.max_header_bytes should change listener fingerprint")
	}
}

func TestSiteListenerFingerprintChangesWhenHTTP2HeaderFieldLimitChanges(t *testing.T) {
	buildSnapshot := func(maxHeaderFields int) *snapshotpkg.Snapshot {
		http2cfg := snapshotpkg.DefaultHTTP2Config()
		http2cfg.MaxHeaderFields = maxHeaderFields
		return &snapshotpkg.Snapshot{
			Sites: map[string]snapshotpkg.SiteRuntime{
				"site": {
					Bind: ":443",
					Site: store.Site{
						ID:         1,
						Bind:       ":443",
						Host:       "example.com",
						TLSEnabled: true,
					},
					NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
					TLSDefaults:     snapshotpkg.DefaultTLSDefaults(),
				},
			},
			HTTP2Config: http2cfg,
		}
	}

	base := siteListenerFingerprint(":443", buildSnapshot(100))
	changed := siteListenerFingerprint(":443", buildSnapshot(80))

	if base == changed {
		t.Fatal("changing http2_config.max_header_fields should change listener fingerprint")
	}
}

func TestSiteListenerFingerprintChangesWhenHTTP2MaxHandlersChanges(t *testing.T) {
	buildSnapshot := func(maxHandlers int) *snapshotpkg.Snapshot {
		http2cfg := snapshotpkg.DefaultHTTP2Config()
		http2cfg.MaxHandlers = maxHandlers
		return &snapshotpkg.Snapshot{
			Sites: map[string]snapshotpkg.SiteRuntime{
				"site": {
					Bind: ":443",
					Site: store.Site{
						ID:         1,
						Bind:       ":443",
						Host:       "example.com",
						TLSEnabled: true,
					},
					NetworkDefaults: snapshotpkg.DefaultNetworkDefaults(),
					TLSDefaults:     snapshotpkg.DefaultTLSDefaults(),
				},
			},
			HTTP2Config: http2cfg,
		}
	}

	base := siteListenerFingerprint(":443", buildSnapshot(0))
	changed := siteListenerFingerprint(":443", buildSnapshot(32))

	if base == changed {
		t.Fatal("changing http2_config.max_handlers should change listener fingerprint")
	}
}

func TestBuildHTTP3ServerPlansGroupsSitesByHTTP3Bind(t *testing.T) {
	sn := &snapshotpkg.Snapshot{
		Sites: map[string]snapshotpkg.SiteRuntime{
			"a": {
				Bind: ":443",
				Site: store.Site{
					ID:         1,
					Bind:       ":443",
					Host:       "a.example.com",
					TLSEnabled: true,
					ALPN:       "h2,h3,http/1.1",
				},
				NetworkDefaults: snapshotpkg.NetworkDefaults{
					HTTP2Enabled:   true,
					HTTP3Enabled:   true,
					HTTP3Bind:      ":8443",
					DefaultALPN:    "h2,h3,http/1.1",
					DefaultNetwork: "tcp",
				},
				TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
			},
			"b": {
				Bind: ":444",
				Site: store.Site{
					ID:         2,
					Bind:       ":444",
					Host:       "b.example.com",
					TLSEnabled: true,
					ALPN:       "h2,h3,http/1.1",
				},
				NetworkDefaults: snapshotpkg.NetworkDefaults{
					HTTP2Enabled:   true,
					HTTP3Enabled:   true,
					HTTP3Bind:      ":8443",
					DefaultALPN:    "h2,h3,http/1.1",
					DefaultNetwork: "tcp",
				},
				TLSDefaults: snapshotpkg.DefaultTLSDefaults(),
			},
		},
	}

	plans := buildHTTP3ServerPlans(sn)
	plan, ok := plans["h3::8443"]
	if !ok {
		t.Fatalf("expected HTTP/3 plan for :8443, got %#v", plans)
	}
	if len(plans) != 1 {
		t.Fatalf("expected one grouped HTTP/3 plan, got %d", len(plans))
	}
	if plan.Bind != ":8443" {
		t.Fatalf("plan bind = %q, want :8443", plan.Bind)
	}
	if got, ok := plan.RouteTable.Resolve("a.example.com"); !ok || got != ":443" {
		t.Fatalf("route for a.example.com = %q, %v", got, ok)
	}
	if got, ok := plan.RouteTable.Resolve("b.example.com"); !ok || got != ":444" {
		t.Fatalf("route for b.example.com = %q, %v", got, ok)
	}
}

func TestBuildHTTP3ServerPlansUsesInheritedTLSDefaultALPN(t *testing.T) {
	sn := &snapshotpkg.Snapshot{
		Sites: map[string]snapshotpkg.SiteRuntime{
			"a": {
				Bind: ":443",
				Site: store.Site{
					ID:         1,
					Bind:       ":443",
					Host:       "a.example.com",
					TLSEnabled: true,
					ALPN:       "",
				},
				NetworkDefaults: snapshotpkg.NetworkDefaults{
					HTTP2Enabled:   true,
					HTTP3Enabled:   true,
					HTTP3Bind:      ":8443",
					DefaultALPN:    "http/1.1",
					DefaultNetwork: "tcp",
				},
				TLSDefaults: snapshotpkg.TLSDefaults{
					DefaultALPN:            "h2,h3,http/1.1",
					HasExplicitDefaultALPN: true,
				},
			},
		},
	}

	plans := buildHTTP3ServerPlans(sn)
	plan, ok := plans["h3::8443"]
	if !ok {
		t.Fatalf("expected HTTP/3 plan for inherited TLS default ALPN, got %#v", plans)
	}
	if plan.Bind != ":8443" {
		t.Fatalf("plan bind = %q, want :8443", plan.Bind)
	}
}

func TestBuildListenerTLSClientHelloOnlySeedsSNI(t *testing.T) {
	sn := &snapshotpkg.Snapshot{}
	rt := snapshotpkg.SiteRuntime{
		Bind: ":443",
		Site: store.Site{
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
	}

	cfg := buildListenerTLS(rt, sn)
	if cfg == nil || cfg.GetConfigForClient == nil {
		t.Fatal("expected TLS config with ClientHello hook")
	}
	rec := &testTLSHandshakeInfoConn{}
	if _, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{
		Conn:              rec,
		ServerName:        "client.example",
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SupportedProtos:   []string{"h2", "http/1.1"},
	}); err != nil {
		t.Fatalf("GetConfigForClient returned error: %v", err)
	}
	if rec.sni != "client.example" {
		t.Fatalf("SNI = %q, want %q", rec.sni, "client.example")
	}
	if rec.version != "" || rec.alpn != "" {
		t.Fatalf("ClientHello hook should not record unnegotiated version/alpn, got version=%q alpn=%q", rec.version, rec.alpn)
	}
}

func TestHTTP2ServerFactoryOptions(t *testing.T) {
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxReadFrameSize = snapshotpkg.MaxHTTP2ReadFrameSize
	cfg := shconfig.NewConfig(http2ServerFactoryOptions(http2cfg)...)

	if cfg.MaxConcurrentStreams != http2cfg.MaxConcurrentStreams {
		t.Fatalf("MaxConcurrentStreams = %d, want %d", cfg.MaxConcurrentStreams, http2cfg.MaxConcurrentStreams)
	}
	if cfg.MaxReadFrameSize != http2cfg.MaxReadFrameSize {
		t.Fatalf("MaxReadFrameSize = %d, want %d", cfg.MaxReadFrameSize, http2cfg.MaxReadFrameSize)
	}
	if cfg.IdleTimeout != time.Duration(http2cfg.IdleTimeoutSeconds)*time.Second {
		t.Fatalf("IdleTimeout = %s, want %s", cfg.IdleTimeout, time.Duration(http2cfg.IdleTimeoutSeconds)*time.Second)
	}
	if cfg.MaxUploadBufferPerConnection != http2cfg.MaxUploadBufferPerConnection {
		t.Fatalf("MaxUploadBufferPerConnection = %d, want %d", cfg.MaxUploadBufferPerConnection, http2cfg.MaxUploadBufferPerConnection)
	}
	if cfg.MaxUploadBufferPerStream != http2cfg.MaxUploadBufferPerStream {
		t.Fatalf("MaxUploadBufferPerStream = %d, want %d", cfg.MaxUploadBufferPerStream, http2cfg.MaxUploadBufferPerStream)
	}
	if cfg.ReadTimeout != time.Duration(http2cfg.ReadTimeoutSeconds)*time.Second {
		t.Fatalf("ReadTimeout = %s, want %s", cfg.ReadTimeout, time.Duration(http2cfg.ReadTimeoutSeconds)*time.Second)
	}
	if cfg.DisableKeepalive != http2cfg.DisableKeepalive {
		t.Fatalf("DisableKeepalive = %v, want %v", cfg.DisableKeepalive, http2cfg.DisableKeepalive)
	}
	if cfg.PermitProhibitedCipherSuites != http2cfg.PermitProhibitedCipherSuites {
		t.Fatalf("PermitProhibitedCipherSuites = %v, want %v", cfg.PermitProhibitedCipherSuites, http2cfg.PermitProhibitedCipherSuites)
	}
}

func TestBuildDataServerAdvertisesConfiguredHTTP2MaxHeaderListSize(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "settings.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxHeaderBytes = 2048
	http2cfg.MaxHeaderFields = 7
	http2cfg.MaxConcurrentStreams = 13
	http2cfg.MaxReadFrameSize = snapshotpkg.MaxHTTP2ReadFrameSize
	http2cfg.MaxUploadBufferPerStream = 96 << 10
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, _, settings := newRawHTTP2ClientConnWithServerSettings(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	got, ok := settings[http2.SettingMaxHeaderListSize]
	if !ok {
		t.Fatal("server settings missing MAX_HEADER_LIST_SIZE")
	}
	want := uint32(http2cfg.MaxHeaderBytes + http2cfg.MaxHeaderFields*32)
	if got != want {
		t.Fatalf("SETTINGS_MAX_HEADER_LIST_SIZE = %d, want %d", got, want)
	}
	if gotFrameSize, ok := settings[http2.SettingMaxFrameSize]; !ok || gotFrameSize != http2cfg.MaxReadFrameSize {
		t.Fatalf("SETTINGS_MAX_FRAME_SIZE = %d, ok=%v, want %d", gotFrameSize, ok, http2cfg.MaxReadFrameSize)
	}
	if gotConcurrentStreams, ok := settings[http2.SettingMaxConcurrentStreams]; !ok || gotConcurrentStreams != http2cfg.MaxConcurrentStreams {
		t.Fatalf("SETTINGS_MAX_CONCURRENT_STREAMS = %d, ok=%v, want %d", gotConcurrentStreams, ok, http2cfg.MaxConcurrentStreams)
	}
	if gotInitialWindow, ok := settings[http2.SettingInitialWindowSize]; !ok || gotInitialWindow != uint32(http2cfg.MaxUploadBufferPerStream) {
		t.Fatalf("SETTINGS_INITIAL_WINDOW_SIZE = %d, ok=%v, want %d", gotInitialWindow, ok, http2cfg.MaxUploadBufferPerStream)
	}
}

func TestBuildDataServerAcceptsConfiguredLargeHTTP2ReadFrame(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "large-frame.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	http2cfg := snapshotpkg.DefaultHTTP2Config()
	http2cfg.MaxReadFrameSize = (1 << 20) + 1
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: http2cfg,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr, settings := newRawHTTP2ClientConnWithServerSettings(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})
	if gotFrameSize, ok := settings[http2.SettingMaxFrameSize]; !ok || gotFrameSize != http2cfg.MaxReadFrameSize {
		t.Fatalf("SETTINGS_MAX_FRAME_SIZE = %d, ok=%v, want %d", gotFrameSize, ok, http2cfg.MaxReadFrameSize)
	}

	if err := fr.WriteRawFrame(http2.FrameType(0xff), 0, 0, make([]byte, int(http2cfg.MaxReadFrameSize))); err != nil {
		t.Fatalf("WriteRawFrame(unknown,len=%d) error = %v", http2cfg.MaxReadFrameSize, err)
	}

	const okStreamID uint32 = 1
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/after-large-frame")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/after-large-frame" {
			t.Fatalf("upstream path = %q, want %q", path, "/after-large-frame")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after configured large HTTP/2 frame")
	}
}

func TestBuildDataServerEnablesStreamRequestBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-body.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}
	if !srv.GetOptions().StreamRequestBody {
		t.Fatal("expected buildDataServer to enable StreamRequestBody")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
}

func TestBuildDataServerStreamsHTTPRequestBodyToUpstreamBeforeClientFinishes(t *testing.T) {
	const (
		firstChunkSize   = 32 * 1024
		firstSegmentSize = 50 * 1024
	)

	body := bytes.Repeat([]byte("stream-body-"), 5462)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamPrefixRead := make(chan []byte, 1)
	upstreamResult := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			upstreamResult <- fmt.Errorf("upstream method = %s, want %s", r.Method, http.MethodPost)
			http.Error(w, "bad method", http.StatusBadRequest)
			return
		}
		prefix := make([]byte, firstChunkSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamResult <- fmt.Errorf("read upstream prefix: %w", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)

		rest, err := io.ReadAll(r.Body)
		if err != nil {
			upstreamResult <- fmt.Errorf("read upstream body tail: %w", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		got := append(prefix, rest...)
		if !bytes.Equal(got, body) {
			upstreamResult <- fmt.Errorf("upstream body mismatch: got=%d want=%d", len(got), len(body))
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}

		upstreamResult <- nil
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:   1,
			Host: "stream-upstream.example.test",
			Bind: bind,
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatalf("dial data server: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	reader := bufio.NewReader(conn)

	if _, err := io.WriteString(conn, "POST /stream-upload HTTP/1.1\r\n"); err != nil {
		t.Fatalf("write request line: %v", err)
	}
	if _, err := io.WriteString(conn, "Host: "+rt.Site.Host+"\r\n"); err != nil {
		t.Fatalf("write host header: %v", err)
	}
	if _, err := io.WriteString(conn, "Transfer-Encoding: chunked\r\n"); err != nil {
		t.Fatalf("write transfer-encoding header: %v", err)
	}
	if _, err := io.WriteString(conn, "Content-Type: application/octet-stream\r\n\r\n"); err != nil {
		t.Fatalf("write request headers: %v", err)
	}
	if err := writeHTTPChunk(conn, body[:firstSegmentSize]); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, body[:len(got)]) {
			t.Fatalf("upstream prefix mismatch: got=%d want=%d", len(got), len(body[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive streamed body before client finished sending request")
	}

	if err := writeHTTPChunk(conn, body[firstSegmentSize:]); err != nil {
		t.Fatalf("write remaining chunk: %v", err)
	}
	if _, err := io.WriteString(conn, "0\r\n\r\n"); err != nil {
		t.Fatalf("write final chunk: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://"+rt.Site.Host+"/stream-upload", nil)
	if err != nil {
		t.Fatalf("build response parser request: %v", err)
	}
	resp, err := readHTTPFinalResponse(reader, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	select {
	case err := <-upstreamResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream body verification")
	}
}

func TestBuildDataServerStreamsHTTP2RequestBodyToUpstreamBeforeClientFinishes(t *testing.T) {
	const (
		firstChunkSize   = 32 * 1024
		firstSegmentSize = 50 * 1024
	)

	body := bytes.Repeat([]byte("stream-body-h2-"), 4096)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamPrefixRead := make(chan []byte, 1)
	upstreamResult := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			upstreamResult <- fmt.Errorf("upstream method = %s, want %s", r.Method, http.MethodPost)
			http.Error(w, "bad method", http.StatusBadRequest)
			return
		}
		prefix := make([]byte, firstChunkSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamResult <- fmt.Errorf("read upstream prefix: %w", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)

		rest, err := io.ReadAll(r.Body)
		if err != nil {
			upstreamResult <- fmt.Errorf("read upstream body tail: %w", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		got := append(prefix, rest...)
		if !bytes.Equal(got, body) {
			upstreamResult <- fmt.Errorf("upstream body mismatch: got=%d want=%d", len(got), len(body))
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}

		upstreamResult <- nil
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-h2-upstream.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	baseTransport := &http.Transport{
		MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	http2Transport, err := http2.ConfigureTransports(baseTransport)
	if err != nil {
		t.Fatalf("ConfigureTransports() error = %v", err)
	}
	http2Transport.StrictMaxConcurrentStreams = true
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: baseTransport,
	}

	pipeReader, pipeWriter := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, "https://"+bind+"/stream-upload-h2", pipeReader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = rt.Site.Host
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/octet-stream")

	type responseResult struct {
		resp *http.Response
		err  error
	}
	respCh := make(chan responseResult, 1)
	go func() {
		resp, err := client.Do(req)
		respCh <- responseResult{resp: resp, err: err}
	}()

	if _, err := pipeWriter.Write(body[:firstSegmentSize]); err != nil {
		t.Fatalf("write first segment: %v", err)
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, body[:len(got)]) {
			t.Fatalf("upstream prefix mismatch: got=%d want=%d", len(got), len(body[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive streamed HTTP/2 body before client finished sending request")
	}

	if _, err := pipeWriter.Write(body[firstSegmentSize:]); err != nil {
		t.Fatalf("write remaining segment: %v", err)
	}
	if err := pipeWriter.Close(); err != nil {
		t.Fatalf("close request body writer: %v", err)
	}

	select {
	case result := <-respCh:
		if result.err != nil {
			t.Fatalf("client.Do() error = %v", result.err)
		}
		defer result.resp.Body.Close()
		if result.resp.ProtoMajor != 2 {
			t.Fatalf("response protocol major = %d, want 2", result.resp.ProtoMajor)
		}
		if result.resp.TLS == nil {
			t.Fatal("expected TLS connection state on HTTP/2 response")
		}
		if result.resp.TLS.NegotiatedProtocol != "h2" {
			t.Fatalf("negotiated protocol = %q, want %q", result.resp.TLS.NegotiatedProtocol, "h2")
		}
		if result.resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", result.resp.StatusCode, http.StatusNoContent)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP/2 response")
	}

	select {
	case err := <-upstreamResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream HTTP/2 body verification")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingHTTP2RequestBodyWhenRawClientSendsRSTStreamAfterPartialUpload(t *testing.T) {
	const (
		firstPrefixSize  = 32 * 1024
		firstSegmentSize = 50 * 1024
	)

	body := bytes.Repeat([]byte("request-stream-rst-"), 4096)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamStarted := make(chan string, 2)
	upstreamPrefixRead := make(chan []byte, 1)
	upstreamBodyReadErr := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch r.URL.Path {
		case "/stream-upload-rst":
			prefix := make([]byte, firstPrefixSize)
			if _, err := io.ReadFull(r.Body, prefix); err != nil {
				upstreamBodyReadErr <- fmt.Errorf("read upstream request prefix: %w", err)
				return
			}
			upstreamPrefixRead <- append([]byte(nil), prefix...)
			_, err := io.Copy(io.Discard, r.Body)
			upstreamBodyReadErr <- err
		case "/raw-ok":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
		}
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-request-rst.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2HeadersFrameWithMethodAndFields(t, fr, streamID, http.MethodPost, rt.Site.Host, "/stream-upload-rst", []hpack.HeaderField{
		{Name: "content-type", Value: "application/octet-stream"},
		{Name: "content-length", Value: strconv.Itoa(len(body))},
	}, false, true)
	writeRawHTTP2Data(t, fr, streamID, false, body[:firstSegmentSize])

	select {
	case path := <-upstreamStarted:
		if path != "/stream-upload-rst" {
			t.Fatalf("upstream path = %q, want %q", path, "/stream-upload-rst")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("streaming request did not reach upstream before reset")
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, body[:len(got)]) {
			t.Fatalf("upstream request prefix mismatch: got=%d want=%d", len(got), len(body[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive request body prefix before client reset")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamBodyReadErr:
		if err == nil {
			t.Fatal("expected upstream request body read to stop with an error after downstream RST_STREAM")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request body read did not stop after downstream RST_STREAM")
	}

	const okStreamID uint32 = 3
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after request-body reset")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingHTTP2RequestBodyWhenRawClientClosesConnectionAfterPartialUpload(t *testing.T) {
	const (
		firstPrefixSize  = 32 * 1024
		firstSegmentSize = 50 * 1024
	)

	body := bytes.Repeat([]byte("request-stream-close-"), 4096)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamStarted := make(chan string, 1)
	upstreamPrefixRead := make(chan []byte, 1)
	upstreamBodyReadErr := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		prefix := make([]byte, firstPrefixSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamBodyReadErr <- fmt.Errorf("read upstream request prefix: %w", err)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)
		_, err := io.Copy(io.Discard, r.Body)
		upstreamBodyReadErr <- err
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-request-close.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)

	const streamID uint32 = 1
	writeRawHTTP2HeadersFrameWithMethodAndFields(t, fr, streamID, http.MethodPost, rt.Site.Host, "/stream-upload-close", []hpack.HeaderField{
		{Name: "content-type", Value: "application/octet-stream"},
		{Name: "content-length", Value: strconv.Itoa(len(body))},
	}, false, true)
	writeRawHTTP2Data(t, fr, streamID, false, body[:firstSegmentSize])

	select {
	case path := <-upstreamStarted:
		if path != "/stream-upload-close" {
			_ = conn.Close()
			t.Fatalf("upstream path = %q, want %q", path, "/stream-upload-close")
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("streaming request did not reach upstream before connection close")
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, body[:len(got)]) {
			_ = conn.Close()
			t.Fatalf("upstream request prefix mismatch: got=%d want=%d", len(got), len(body[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("upstream did not receive request body prefix before connection close")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close raw h2 client connection: %v", err)
	}

	select {
	case err := <-upstreamBodyReadErr:
		if err == nil {
			t.Fatal("expected upstream request body read to stop with an error after downstream connection close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request body read did not stop after downstream connection close")
	}
}

func TestBuildDataServerCancelsUpstreamDecodedStreamingHTTP2RequestBodyWhenRawClientSendsRSTStreamAfterPartialUpload(t *testing.T) {
	const (
		firstPrefixSize         = 16 * 1024
		firstCompressedReadSize = 64 * 1024
	)

	originalBody := make([]byte, 128*1024)
	seed := uint32(1)
	for i := range originalBody {
		seed = seed*1664525 + 1013904223
		originalBody[i] = byte(seed >> 24)
	}

	var compressed bytes.Buffer
	gzWriter := gzip.NewWriter(&compressed)
	if _, err := gzWriter.Write(originalBody); err != nil {
		t.Fatalf("write gzip request body: %v", err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatalf("close gzip request body: %v", err)
	}
	compressedBody := compressed.Bytes()
	firstCompressedSegmentSize := len(compressedBody) * 3 / 4
	if firstCompressedSegmentSize <= 0 || firstCompressedSegmentSize >= len(compressedBody) {
		t.Fatalf("compressed request body segment size = %d, total = %d, want 0 < segment < total", firstCompressedSegmentSize, len(compressedBody))
	}

	upstreamStarted := make(chan string, 1)
	upstreamPrefixRead := make(chan []byte, 1)
	upstreamBodyReadErr := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		prefix := make([]byte, firstPrefixSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamBodyReadErr <- fmt.Errorf("read decoded upstream request prefix: %w", err)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)
		_, err := io.Copy(io.Discard, r.Body)
		upstreamBodyReadErr <- err
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-request-decoded-rst.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2HeadersFrameWithMethodAndFields(t, fr, streamID, http.MethodPost, rt.Site.Host, "/stream-upload-decoded-rst", []hpack.HeaderField{
		{Name: "content-type", Value: "application/octet-stream"},
		{Name: "content-encoding", Value: "gzip"},
		{Name: "content-length", Value: strconv.Itoa(len(compressedBody))},
	}, false, true)
	writeRawHTTP2Data(t, fr, streamID, false, compressedBody[:firstCompressedReadSize])

	select {
	case path := <-upstreamStarted:
		if path != "/stream-upload-decoded-rst" {
			t.Fatalf("upstream path = %q, want %q", path, "/stream-upload-decoded-rst")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("decoded streaming request did not reach upstream before reset")
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, originalBody[:len(got)]) {
			t.Fatalf("decoded upstream request prefix mismatch: got=%d want=%d", len(got), len(originalBody[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive decoded request body prefix before client reset")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamBodyReadErr:
		if err == nil {
			t.Fatal("expected decoded upstream request body read to stop with an error after downstream RST_STREAM")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("decoded upstream request body read did not stop after downstream RST_STREAM")
	}
}

func TestBuildDataServerStreamsHTTP2RequestBodyWithTrailersToUpstreamBeforeClientFinishes(t *testing.T) {
	const (
		firstPrefixSize  = 32 * 1024
		firstSegmentSize = 50 * 1024
	)

	body := bytes.Repeat([]byte("stream-trailer-body-h2-"), 4096)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamPrefixRead := make(chan []byte, 1)
	upstreamResult := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			upstreamResult <- fmt.Errorf("upstream method = %s, want %s", r.Method, http.MethodPost)
			http.Error(w, "bad method", http.StatusBadRequest)
			return
		}
		prefix := make([]byte, firstPrefixSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamResult <- fmt.Errorf("read upstream prefix: %w", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)

		rest, err := io.ReadAll(r.Body)
		if err != nil {
			upstreamResult <- fmt.Errorf("read upstream body tail: %w", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		got := append(prefix, rest...)
		if !bytes.Equal(got, body) {
			upstreamResult <- fmt.Errorf("upstream body mismatch: got=%d want=%d", len(got), len(body))
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if gotTrailer := r.Trailer.Get("X-Trace"); gotTrailer != "done" {
			upstreamResult <- fmt.Errorf("upstream trailer X-Trace = %q, want %q", gotTrailer, "done")
			http.Error(w, "bad trailer", http.StatusBadRequest)
			return
		}
		if gotTE := r.Header.Get("Te"); gotTE != "trailers" {
			upstreamResult <- fmt.Errorf("upstream Te = %q, want %q", gotTE, "trailers")
			http.Error(w, "bad te", http.StatusBadRequest)
			return
		}

		upstreamResult <- nil
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-request-trailers-h2.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2HeadersFrameWithMethodAndFields(t, fr, streamID, http.MethodPost, rt.Site.Host, "/stream-upload-h2-trailers", []hpack.HeaderField{
		{Name: "content-type", Value: "application/octet-stream"},
		{Name: "te", Value: "trailers"},
		{Name: "trailer", Value: "x-trace"},
	}, false, true)
	writeRawHTTP2Data(t, fr, streamID, false, body[:firstSegmentSize])

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, body[:len(got)]) {
			t.Fatalf("upstream prefix mismatch: got=%d want=%d", len(got), len(body[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive streamed HTTP/2 trailer body before client finished sending request")
	}

	writeRawHTTP2Data(t, fr, streamID, false, body[firstSegmentSize:])
	writeRawHTTP2HeaderFieldsFrame(t, fr, streamID, []hpack.HeaderField{
		{Name: "x-trace", Value: "done"},
	}, true, true)

	readRawHTTP2ResponseStatus(t, conn, fr, streamID, "204")

	select {
	case err := <-upstreamResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream HTTP/2 trailer streaming verification")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingHTTP2RequestBodyWithTrailersWhenRawClientSendsRSTStreamAfterPartialUpload(t *testing.T) {
	const (
		firstPrefixSize  = 32 * 1024
		firstSegmentSize = 50 * 1024
	)

	body := bytes.Repeat([]byte("request-stream-trailer-rst-h2-"), 4096)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamStarted := make(chan string, 2)
	upstreamPrefixRead := make(chan []byte, 1)
	upstreamBodyReadErr := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch r.URL.Path {
		case "/stream-upload-h2-trailers-rst":
			prefix := make([]byte, firstPrefixSize)
			if _, err := io.ReadFull(r.Body, prefix); err != nil {
				upstreamBodyReadErr <- fmt.Errorf("read upstream request prefix: %w", err)
				return
			}
			upstreamPrefixRead <- append([]byte(nil), prefix...)
			_, err := io.Copy(io.Discard, r.Body)
			upstreamBodyReadErr <- err
		case "/raw-ok":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
		}
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-request-trailers-rst-h2.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2HeadersFrameWithMethodAndFields(t, fr, streamID, http.MethodPost, rt.Site.Host, "/stream-upload-h2-trailers-rst", []hpack.HeaderField{
		{Name: "content-type", Value: "application/octet-stream"},
		{Name: "te", Value: "trailers"},
		{Name: "trailer", Value: "x-trace"},
	}, false, true)
	writeRawHTTP2Data(t, fr, streamID, false, body[:firstSegmentSize])

	select {
	case path := <-upstreamStarted:
		if path != "/stream-upload-h2-trailers-rst" {
			t.Fatalf("upstream path = %q, want %q", path, "/stream-upload-h2-trailers-rst")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("streaming trailer request did not reach upstream before reset")
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, body[:len(got)]) {
			t.Fatalf("upstream request prefix mismatch: got=%d want=%d", len(got), len(body[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive trailer request body prefix before client reset")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamBodyReadErr:
		if err == nil {
			t.Fatal("expected upstream trailer request body read to stop with an error after downstream RST_STREAM")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream trailer request body read did not stop after downstream RST_STREAM")
	}

	const okStreamID uint32 = 3
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after trailer request reset")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingHTTP2RequestBodyWithTrailersWhenRawClientClosesConnectionAfterPartialUpload(t *testing.T) {
	const (
		firstPrefixSize  = 32 * 1024
		firstSegmentSize = 50 * 1024
	)

	body := bytes.Repeat([]byte("request-stream-trailer-close-h2-"), 4096)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamStarted := make(chan string, 1)
	upstreamPrefixRead := make(chan []byte, 1)
	upstreamBodyReadErr := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		prefix := make([]byte, firstPrefixSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamBodyReadErr <- fmt.Errorf("read upstream request prefix: %w", err)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)
		_, err := io.Copy(io.Discard, r.Body)
		upstreamBodyReadErr <- err
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-request-trailers-close-h2.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)

	const streamID uint32 = 1
	writeRawHTTP2HeadersFrameWithMethodAndFields(t, fr, streamID, http.MethodPost, rt.Site.Host, "/stream-upload-h2-trailers-close", []hpack.HeaderField{
		{Name: "content-type", Value: "application/octet-stream"},
		{Name: "te", Value: "trailers"},
		{Name: "trailer", Value: "x-trace"},
	}, false, true)
	writeRawHTTP2Data(t, fr, streamID, false, body[:firstSegmentSize])

	select {
	case path := <-upstreamStarted:
		if path != "/stream-upload-h2-trailers-close" {
			_ = conn.Close()
			t.Fatalf("upstream path = %q, want %q", path, "/stream-upload-h2-trailers-close")
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("streaming trailer request did not reach upstream before connection close")
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, body[:len(got)]) {
			_ = conn.Close()
			t.Fatalf("upstream request prefix mismatch: got=%d want=%d", len(got), len(body[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("upstream did not receive trailer request body prefix before connection close")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close raw h2 client connection: %v", err)
	}

	select {
	case err := <-upstreamBodyReadErr:
		if err == nil {
			t.Fatal("expected upstream trailer request body read to stop with an error after downstream connection close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream trailer request body read did not stop after downstream connection close")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingHTTPRequestBodyWhenRawClientClosesConnectionAfterPartialUpload(t *testing.T) {
	const (
		firstPrefixSize  = 32 * 1024
		firstSegmentSize = 50 * 1024
	)

	body := bytes.Repeat([]byte("request-stream-http1-close-"), 4096)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamStarted := make(chan string, 1)
	upstreamPrefixRead := make(chan []byte, 1)
	upstreamBodyReadErr := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		prefix := make([]byte, firstPrefixSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamBodyReadErr <- fmt.Errorf("read upstream request prefix: %w", err)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)
		_, err := io.Copy(io.Discard, r.Body)
		upstreamBodyReadErr <- err
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:   1,
			Host: "stream-request-http1-close.example.test",
			Bind: bind,
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatalf("dial data server: %v", err)
	}

	if _, err := io.WriteString(conn, "POST /stream-upload-http1-close HTTP/1.1\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write request line: %v", err)
	}
	if _, err := io.WriteString(conn, "Host: "+rt.Site.Host+"\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write host header: %v", err)
	}
	if _, err := io.WriteString(conn, "Transfer-Encoding: chunked\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write transfer-encoding header: %v", err)
	}
	if _, err := io.WriteString(conn, "Content-Type: application/octet-stream\r\n\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write request headers: %v", err)
	}
	if err := writeHTTPChunk(conn, body[:firstSegmentSize]); err != nil {
		_ = conn.Close()
		t.Fatalf("write first chunk: %v", err)
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-upload-http1-close" {
			_ = conn.Close()
			t.Fatalf("upstream path = %q, want %q", path, "/stream-upload-http1-close")
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("streaming request did not reach upstream before connection close")
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, body[:len(got)]) {
			_ = conn.Close()
			t.Fatalf("upstream request prefix mismatch: got=%d want=%d", len(got), len(body[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("upstream did not receive request body prefix before connection close")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close raw http/1.1 client connection: %v", err)
	}

	select {
	case err := <-upstreamBodyReadErr:
		if err == nil {
			t.Fatal("expected upstream request body read to stop with an error after downstream connection close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream request body read did not stop after downstream connection close")
	}
}

func TestBuildDataServerDoesNotStartUpstreamStreamingHTTPRequestWhenRawClientClosesConnectionBeforePrefetchThreshold(t *testing.T) {
	const firstSegmentSize = 8 * 1024

	body := bytes.Repeat([]byte("request-stream-early-close-"), 512)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		http.Error(w, "unexpected upstream start", http.StatusInternalServerError)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:   1,
			Host: "stream-request-early-close.example.test",
			Bind: bind,
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatalf("dial data server: %v", err)
	}

	if _, err := io.WriteString(conn, "POST /stream-upload-early-close HTTP/1.1\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write request line: %v", err)
	}
	if _, err := io.WriteString(conn, "Host: "+rt.Site.Host+"\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write host header: %v", err)
	}
	if _, err := io.WriteString(conn, "Transfer-Encoding: chunked\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write transfer-encoding header: %v", err)
	}
	if _, err := io.WriteString(conn, "Content-Type: application/octet-stream\r\n\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write request headers: %v", err)
	}
	if err := writeHTTPChunk(conn, body[:firstSegmentSize]); err != nil {
		_ = conn.Close()
		t.Fatalf("write first chunk: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close raw http/1.1 client connection: %v", err)
	}

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path before prefetch threshold was satisfied: %q", path)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestBuildDataServerDoesNotStartUpstreamStreamingHTTP2RequestWhenRawClientSendsRSTStreamBeforePrefetchThreshold(t *testing.T) {
	const firstSegmentSize = 8 * 1024

	body := bytes.Repeat([]byte("request-stream-h2-early-rst-"), 512)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamStarted := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		switch r.URL.Path {
		case "/raw-ok":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected upstream start", http.StatusInternalServerError)
		}
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-request-h2-early-rst.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshotpkg.DefaultHTTP2Config(),
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2HeadersFrameWithMethodAndFields(t, fr, streamID, http.MethodPost, rt.Site.Host, "/stream-upload-h2-early-rst", []hpack.HeaderField{
		{Name: "content-type", Value: "application/octet-stream"},
		{Name: "content-length", Value: strconv.Itoa(len(body))},
	}, false, true)
	writeRawHTTP2Data(t, fr, streamID, false, body[:firstSegmentSize])
	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case path := <-upstreamStarted:
		t.Fatalf("unexpected upstream path before prefetch threshold was satisfied: %q", path)
	case <-time.After(300 * time.Millisecond):
	}

	const okStreamID uint32 = 3
	writeRawHTTP2Headers(t, fr, okStreamID, rt.Site.Host, "/raw-ok")
	readRawHTTP2ResponseStatus(t, conn, fr, okStreamID, "204")

	select {
	case path := <-upstreamStarted:
		if path != "/raw-ok" {
			t.Fatalf("healthy upstream path = %q, want %q", path, "/raw-ok")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy request did not reach upstream after prefetch-threshold reset")
	}
}

func TestBuildDataServerCancelsUpstreamDecodedStreamingHTTPRequestBodyWhenRawClientClosesConnectionAfterPartialUpload(t *testing.T) {
	const (
		firstPrefixSize         = 16 * 1024
		firstCompressedReadSize = 64 * 1024
	)

	originalBody := make([]byte, 128*1024)
	seed := uint32(1)
	for i := range originalBody {
		seed = seed*1664525 + 1013904223
		originalBody[i] = byte(seed >> 24)
	}

	var compressed bytes.Buffer
	gzWriter := gzip.NewWriter(&compressed)
	if _, err := gzWriter.Write(originalBody); err != nil {
		t.Fatalf("write gzip request body: %v", err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatalf("close gzip request body: %v", err)
	}
	compressedBody := compressed.Bytes()
	if firstCompressedReadSize >= len(compressedBody) {
		t.Fatalf("compressed request body length = %d, want > %d", len(compressedBody), firstCompressedReadSize)
	}

	upstreamStarted := make(chan string, 1)
	upstreamPrefixRead := make(chan []byte, 1)
	upstreamBodyReadErr := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		prefix := make([]byte, firstPrefixSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamBodyReadErr <- fmt.Errorf("read decoded upstream request prefix: %w", err)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)
		_, err := io.Copy(io.Discard, r.Body)
		upstreamBodyReadErr <- err
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:   1,
			Host: "stream-request-http1-decoded-close.example.test",
			Bind: bind,
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatalf("dial data server: %v", err)
	}

	if _, err := io.WriteString(conn, "POST /stream-upload-http1-decoded-close HTTP/1.1\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write request line: %v", err)
	}
	if _, err := io.WriteString(conn, "Host: "+rt.Site.Host+"\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write host header: %v", err)
	}
	if _, err := io.WriteString(conn, "Transfer-Encoding: chunked\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write transfer-encoding header: %v", err)
	}
	if _, err := io.WriteString(conn, "Content-Type: application/octet-stream\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write content type header: %v", err)
	}
	if _, err := io.WriteString(conn, "Content-Encoding: gzip\r\n\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write request headers: %v", err)
	}
	if err := writeHTTPChunk(conn, compressedBody[:firstCompressedReadSize]); err != nil {
		_ = conn.Close()
		t.Fatalf("write first compressed chunk: %v", err)
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-upload-http1-decoded-close" {
			_ = conn.Close()
			t.Fatalf("upstream path = %q, want %q", path, "/stream-upload-http1-decoded-close")
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("decoded streaming request did not reach upstream before connection close")
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, originalBody[:len(got)]) {
			_ = conn.Close()
			t.Fatalf("decoded upstream request prefix mismatch: got=%d want=%d", len(got), len(originalBody[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("upstream did not receive decoded request body prefix before connection close")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close raw http/1.1 client connection: %v", err)
	}

	select {
	case err := <-upstreamBodyReadErr:
		if err == nil {
			t.Fatal("expected decoded upstream request body read to stop with an error after downstream connection close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("decoded upstream request body read did not stop after downstream connection close")
	}
}

func TestBuildDataServerForwardsExpectContinueBeforeSendingBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw upstream: %v", err)
	}
	defer ln.Close()

	type observation struct {
		expectHeader      string
		bodyReceivedEarly bool
		headerReadErr     error
		earlyBodyProbeErr error
	}
	resultCh := make(chan observation, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resultCh <- observation{headerReadErr: err}
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		var headerLines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				resultCh <- observation{headerReadErr: err}
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			headerLines = append(headerLines, line)
		}

		expectHeader := ""
		for _, line := range headerLines {
			if strings.HasPrefix(strings.ToLower(line), "expect:") {
				expectHeader = strings.TrimSpace(line[len("expect:"):])
				break
			}
		}

		bodyReceivedEarly := reader.Buffered() > 0
		var probeErr error
		if !bodyReceivedEarly {
			if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
				resultCh <- observation{expectHeader: expectHeader, headerReadErr: err}
				return
			}
			_, err := reader.Peek(1)
			if err == nil {
				bodyReceivedEarly = true
			} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				probeErr = err
			}
			_ = conn.SetReadDeadline(time.Time{})
		}

		_, writeErr := io.WriteString(conn, "HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		if writeErr != nil {
			resultCh <- observation{
				expectHeader:      expectHeader,
				bodyReceivedEarly: bodyReceivedEarly,
				headerReadErr:     writeErr,
				earlyBodyProbeErr: probeErr,
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
		resultCh <- observation{
			expectHeader:      expectHeader,
			bodyReceivedEarly: bodyReceivedEarly,
			earlyBodyProbeErr: probeErr,
		}
	}()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:   1,
			Host: "expect.example.test",
			Bind: bind,
		},
		UpstreamURLs:        []string{"http://" + ln.Addr().String()},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	body := []byte(strings.Repeat("expect-continue-body-", 512))
	conn, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatalf("dial data server: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	reader := bufio.NewReader(conn)

	if _, err := io.WriteString(conn, "POST /expect HTTP/1.1\r\n"); err != nil {
		t.Fatalf("write request line: %v", err)
	}
	if _, err := io.WriteString(conn, "Host: "+rt.Site.Host+"\r\n"); err != nil {
		t.Fatalf("write host header: %v", err)
	}
	if _, err := io.WriteString(conn, "Content-Type: application/octet-stream\r\n"); err != nil {
		t.Fatalf("write content-type header: %v", err)
	}
	if _, err := io.WriteString(conn, "Content-Length: "+strconv.Itoa(len(body))+"\r\n"); err != nil {
		t.Fatalf("write content-length header: %v", err)
	}
	if _, err := io.WriteString(conn, "Expect: 100-continue\r\n\r\n"); err != nil {
		t.Fatalf("write expect header: %v", err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatalf("write request body: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://"+rt.Site.Host+"/expect", nil)
	if err != nil {
		t.Fatalf("build response parser request: %v", err)
	}
	resp, err := readHTTPFinalResponse(reader, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusExpectationFailed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusExpectationFailed)
	}

	result := <-resultCh
	if result.headerReadErr != nil {
		t.Fatalf("raw upstream observation error: %v", result.headerReadErr)
	}
	if result.earlyBodyProbeErr != nil {
		t.Fatalf("raw upstream early body probe error: %v", result.earlyBodyProbeErr)
	}
	if result.expectHeader != "100-continue" {
		t.Fatalf("Expect header = %q, want %q", result.expectHeader, "100-continue")
	}
	if result.bodyReceivedEarly {
		t.Fatal("request body was sent upstream before upstream accepted Expect: 100-continue")
	}
}

func TestBuildDataServerForwardsRequestTrailers(t *testing.T) {
	upstreamReceived := make(chan error, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw upstream: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			upstreamReceived <- err
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			upstreamReceived <- fmt.Errorf("read upstream request: %w", err)
			return
		}
		defer req.Body.Close()

		body, err := io.ReadAll(req.Body)
		if err != nil {
			upstreamReceived <- fmt.Errorf("read upstream body: %w", err)
			return
		}
		if string(body) != `{"ok":true}` {
			upstreamReceived <- fmt.Errorf("upstream body = %q, want %q", string(body), `{"ok":true}`)
			return
		}
		if got := req.Header.Get("Te"); got != "trailers" {
			upstreamReceived <- fmt.Errorf("upstream Te = %q, want %q", got, "trailers")
			return
		}
		if got := req.Trailer.Get("X-Trace"); got != "done" {
			upstreamReceived <- fmt.Errorf("upstream trailer X-Trace = %q, want %q", got, "done")
			return
		}

		if _, err := io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); err != nil {
			upstreamReceived <- fmt.Errorf("write upstream response: %w", err)
			return
		}
		upstreamReceived <- nil
	}()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:   1,
			Host: "trailers.example.test",
			Bind: bind,
		},
		UpstreamURLs:        []string{"http://" + ln.Addr().String()},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatalf("dial data server: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	reader := bufio.NewReader(conn)

	if _, err := io.WriteString(conn, "POST /trailers HTTP/1.1\r\n"); err != nil {
		t.Fatalf("write request line: %v", err)
	}
	if _, err := io.WriteString(conn, "Host: "+rt.Site.Host+"\r\n"); err != nil {
		t.Fatalf("write host header: %v", err)
	}
	if _, err := io.WriteString(conn, "Transfer-Encoding: chunked\r\n"); err != nil {
		t.Fatalf("write transfer-encoding header: %v", err)
	}
	if _, err := io.WriteString(conn, "TE: trailers\r\n"); err != nil {
		t.Fatalf("write TE header: %v", err)
	}
	if _, err := io.WriteString(conn, "Trailer: X-Trace\r\n"); err != nil {
		t.Fatalf("write Trailer header: %v", err)
	}
	if _, err := io.WriteString(conn, "Content-Type: application/json\r\n\r\n"); err != nil {
		t.Fatalf("write request headers: %v", err)
	}
	if err := writeHTTPChunk(conn, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("write body chunk: %v", err)
	}
	if _, err := io.WriteString(conn, "0\r\nX-Trace: done\r\n\r\n"); err != nil {
		t.Fatalf("write final chunk and trailer: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://"+rt.Site.Host+"/trailers", nil)
	if err != nil {
		t.Fatalf("build response parser request: %v", err)
	}
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	select {
	case err := <-upstreamReceived:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream trailer verification")
	}
}

func TestBuildDataServerStreamsHTTPRequestBodyWithTrailersToUpstreamBeforeClientFinishes(t *testing.T) {
	const (
		firstPrefixSize  = 32 * 1024
		firstSegmentSize = 50 * 1024
	)

	body := bytes.Repeat([]byte("stream-trailer-body-"), 4096)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamPrefixRead := make(chan []byte, 1)
	upstreamResult := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			upstreamResult <- fmt.Errorf("upstream method = %s, want %s", r.Method, http.MethodPost)
			http.Error(w, "bad method", http.StatusBadRequest)
			return
		}
		prefix := make([]byte, firstPrefixSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamResult <- fmt.Errorf("read upstream prefix: %w", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)

		rest, err := io.ReadAll(r.Body)
		if err != nil {
			upstreamResult <- fmt.Errorf("read upstream body tail: %w", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		got := append(prefix, rest...)
		if !bytes.Equal(got, body) {
			upstreamResult <- fmt.Errorf("upstream body mismatch: got=%d want=%d", len(got), len(body))
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if gotTrailer := r.Trailer.Get("X-Trace"); gotTrailer != "done" {
			upstreamResult <- fmt.Errorf("upstream trailer X-Trace = %q, want %q", gotTrailer, "done")
			http.Error(w, "bad trailer", http.StatusBadRequest)
			return
		}
		if gotTE := r.Header.Get("Te"); gotTE != "trailers" {
			upstreamResult <- fmt.Errorf("upstream Te = %q, want %q", gotTE, "trailers")
			http.Error(w, "bad te", http.StatusBadRequest)
			return
		}

		upstreamResult <- nil
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:   1,
			Host: "stream-request-trailers.example.test",
			Bind: bind,
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatalf("dial data server: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	reader := bufio.NewReader(conn)

	if _, err := io.WriteString(conn, "POST /stream-trailers HTTP/1.1\r\n"); err != nil {
		t.Fatalf("write request line: %v", err)
	}
	if _, err := io.WriteString(conn, "Host: "+rt.Site.Host+"\r\n"); err != nil {
		t.Fatalf("write host header: %v", err)
	}
	if _, err := io.WriteString(conn, "Transfer-Encoding: chunked\r\n"); err != nil {
		t.Fatalf("write transfer-encoding header: %v", err)
	}
	if _, err := io.WriteString(conn, "TE: trailers\r\n"); err != nil {
		t.Fatalf("write TE header: %v", err)
	}
	if _, err := io.WriteString(conn, "Trailer: X-Trace\r\n"); err != nil {
		t.Fatalf("write Trailer header: %v", err)
	}
	if _, err := io.WriteString(conn, "Content-Type: application/octet-stream\r\n\r\n"); err != nil {
		t.Fatalf("write request headers: %v", err)
	}
	if err := writeHTTPChunk(conn, body[:firstSegmentSize]); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, body[:len(got)]) {
			t.Fatalf("upstream prefix mismatch: got=%d want=%d", len(got), len(body[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive streamed trailer body before client finished sending request")
	}

	if err := writeHTTPChunk(conn, body[firstSegmentSize:]); err != nil {
		t.Fatalf("write remaining chunk: %v", err)
	}
	if _, err := io.WriteString(conn, "0\r\nX-Trace: done\r\n\r\n"); err != nil {
		t.Fatalf("write final chunk and trailer: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://"+rt.Site.Host+"/stream-trailers", nil)
	if err != nil {
		t.Fatalf("build response parser request: %v", err)
	}
	resp, err := readHTTPFinalResponse(reader, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	select {
	case err := <-upstreamResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream trailer streaming verification")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingHTTPRequestBodyWithTrailersWhenRawClientClosesConnectionAfterPartialUpload(t *testing.T) {
	const (
		firstPrefixSize  = 32 * 1024
		firstSegmentSize = 50 * 1024
	)

	body := bytes.Repeat([]byte("request-stream-trailer-close-"), 4096)
	if len(body) <= firstSegmentSize {
		t.Fatalf("test body length = %d, want > %d", len(body), firstSegmentSize)
	}

	upstreamStarted := make(chan string, 1)
	upstreamPrefixRead := make(chan []byte, 1)
	upstreamBodyReadErr := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		prefix := make([]byte, firstPrefixSize)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			upstreamBodyReadErr <- fmt.Errorf("read upstream request prefix: %w", err)
			return
		}
		upstreamPrefixRead <- append([]byte(nil), prefix...)
		_, err := io.Copy(io.Discard, r.Body)
		upstreamBodyReadErr <- err
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:   1,
			Host: "stream-request-trailer-close.example.test",
			Bind: bind,
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatalf("dial data server: %v", err)
	}

	if _, err := io.WriteString(conn, "POST /stream-trailer-close HTTP/1.1\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write request line: %v", err)
	}
	if _, err := io.WriteString(conn, "Host: "+rt.Site.Host+"\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write host header: %v", err)
	}
	if _, err := io.WriteString(conn, "Transfer-Encoding: chunked\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write transfer-encoding header: %v", err)
	}
	if _, err := io.WriteString(conn, "TE: trailers\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write TE header: %v", err)
	}
	if _, err := io.WriteString(conn, "Trailer: X-Trace\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write Trailer header: %v", err)
	}
	if _, err := io.WriteString(conn, "Content-Type: application/octet-stream\r\n\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write request headers: %v", err)
	}
	if err := writeHTTPChunk(conn, body[:firstSegmentSize]); err != nil {
		_ = conn.Close()
		t.Fatalf("write first chunk: %v", err)
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-trailer-close" {
			_ = conn.Close()
			t.Fatalf("upstream path = %q, want %q", path, "/stream-trailer-close")
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("streaming trailer request did not reach upstream before connection close")
	}

	select {
	case got := <-upstreamPrefixRead:
		if !bytes.Equal(got, body[:len(got)]) {
			_ = conn.Close()
			t.Fatalf("upstream request prefix mismatch: got=%d want=%d", len(got), len(body[:len(got)]))
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("upstream did not receive trailer request body prefix before connection close")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close raw http/1.1 client connection: %v", err)
	}

	select {
	case err := <-upstreamBodyReadErr:
		if err == nil {
			t.Fatal("expected upstream trailer request body read to stop with an error after downstream connection close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream trailer request body read did not stop after downstream connection close")
	}
}

func TestBuildDataServerForwardsResponseTrailers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw upstream: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = req.Body.Close()

		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n")
		_, _ = io.WriteString(conn, "Content-Type: text/plain; charset=utf-8\r\n")
		_, _ = io.WriteString(conn, "Transfer-Encoding: chunked\r\n")
		_, _ = io.WriteString(conn, "Trailer: X-Upstream-Trailer\r\n")
		_, _ = io.WriteString(conn, "Connection: close\r\n\r\n")
		if err := writeHTTPChunk(conn, []byte("streamed trailer payload")); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "0\r\nX-Upstream-Trailer: done\r\n\r\n")
	}()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:   1,
			Host: "response-trailers.example.test",
			Bind: bind,
		},
		UpstreamURLs:        []string{"http://" + ln.Addr().String()},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, err := net.Dial("tcp", bind)
	if err != nil {
		t.Fatalf("dial data server: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	reader := bufio.NewReader(conn)

	if _, err := io.WriteString(conn, "GET /response-trailers HTTP/1.1\r\n"); err != nil {
		t.Fatalf("write request line: %v", err)
	}
	if _, err := io.WriteString(conn, "Host: "+rt.Site.Host+"\r\n"); err != nil {
		t.Fatalf("write host header: %v", err)
	}
	if _, err := io.WriteString(conn, "TE: trailers\r\n\r\n"); err != nil {
		t.Fatalf("write TE header: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://"+rt.Site.Host+"/response-trailers", nil)
	if err != nil {
		t.Fatalf("build response parser request: %v", err)
	}
	resp, err := readHTTPFinalResponse(reader, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "streamed trailer payload" {
		t.Fatalf("response body = %q, want %q", string(body), "streamed trailer payload")
	}
	if got := resp.Trailer.Get("X-Upstream-Trailer"); got != "done" {
		t.Fatalf("response trailer X-Upstream-Trailer = %q, want %q", got, "done")
	}
}

func TestBuildDataServerStreamsSSEResponseAfterHandlerReturns(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw upstream: %v", err)
	}
	defer ln.Close()

	upstreamServed := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = req.Body.Close()
		upstreamServed <- req.URL.Path

		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n")
		_, _ = io.WriteString(conn, "Content-Type: text/event-stream\r\n")
		_, _ = io.WriteString(conn, "Cache-Control: no-cache\r\n")
		_, _ = io.WriteString(conn, "Connection: close\r\n\r\n")
		_, _ = io.WriteString(conn, "data: one\n\n")
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(conn, "data: two\n\n")
	}()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "sse-stream.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{"http://" + ln.Addr().String()},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	baseTransport := &http.Transport{
		MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	http2Transport, err := http2.ConfigureTransports(baseTransport)
	if err != nil {
		t.Fatalf("ConfigureTransports() error = %v", err)
	}
	http2Transport.StrictMaxConcurrentStreams = true
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: baseTransport,
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+bind+"/events", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Accept", "text/event-stream")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Fatalf("response protocol major = %d, want 2", resp.ProtoMajor)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want %q", got, "text/event-stream")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read sse response body: %v", err)
	}
	if got := string(body); got != "data: one\n\ndata: two\n\n" {
		t.Fatalf("sse response body = %q, want %q", got, "data: one\\n\\ndata: two\\n\\n")
	}

	select {
	case path := <-upstreamServed:
		if path != "/events" {
			t.Fatalf("upstream path = %q, want %q", path, "/events")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sse request did not reach upstream")
	}
}

func TestBuildDataServerCancelsUpstreamSSEWhenClientClosesStream(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("upstream SSE context was not canceled in time")
		}
	}))
	defer upstream.Close()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "sse-cancel.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	baseTransport := &http.Transport{
		MaxConnsPerHost: 1,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
	}
	http2Transport, err := http2.ConfigureTransports(baseTransport)
	if err != nil {
		t.Fatalf("ConfigureTransports() error = %v", err)
	}
	http2Transport.StrictMaxConcurrentStreams = true
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: baseTransport,
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+bind+"/events-close", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = rt.Site.Host
	req.Header.Set("Accept", "text/event-stream")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}

	if resp.ProtoMajor != 2 {
		_ = resp.Body.Close()
		t.Fatalf("response protocol major = %d, want 2", resp.ProtoMajor)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		_ = resp.Body.Close()
		t.Fatalf("Content-Type = %q, want %q", got, "text/event-stream")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/events-close" {
			_ = resp.Body.Close()
			t.Fatalf("upstream path = %q, want %q", path, "/events-close")
		}
	case <-time.After(2 * time.Second):
		_ = resp.Body.Close()
		t.Fatal("sse cancel request did not reach upstream")
	}

	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close response body: %v", err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream SSE request was not canceled after client closed stream")
	}
}

func TestBuildDataServerCancelsUpstreamSSEWhenRawHTTP2ClientSendsRSTStream(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("raw h2 upstream SSE context was not canceled in time")
		}
	}))
	defer upstream.Close()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "sse-raw-cancel.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2HeadersWithFields(t, fr, streamID, rt.Site.Host, "/events-raw-close", []hpack.HeaderField{
		{Name: "accept", Value: "text/event-stream"},
	})
	if streamEnded := readRawHTTP2ResponseHeadersStatus(t, conn, fr, streamID, "200"); streamEnded {
		t.Fatal("sse raw h2 response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/events-raw-close" {
			t.Fatalf("upstream path = %q, want %q", path, "/events-raw-close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raw h2 sse request did not reach upstream")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("raw h2 upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raw h2 upstream SSE request was not canceled after downstream RST_STREAM")
	}
}

func TestBuildDataServerFlushesRawHTTP2ResponseHeadersBeforeStreamingBodyReachesCompressionThreshold(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.(http.Flusher).Flush()
		time.Sleep(3 * time.Second)
	}))
	defer upstream.Close()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-header-flush.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2Headers(t, fr, streamID, rt.Site.Host, "/stream-headers-only")
	if streamEnded := readRawHTTP2ResponseHeadersStatus(t, conn, fr, streamID, "200"); streamEnded {
		t.Fatal("streaming response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-headers-only" {
			t.Fatalf("upstream path = %q, want %q", path, "/stream-headers-only")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("streaming request did not reach upstream")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingResponseWhenRawHTTP2ClientSendsRSTStreamBeforeBodyArrives(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("streaming upstream context was not canceled in time")
		}
	}))
	defer upstream.Close()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-raw-cancel.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2Headers(t, fr, streamID, rt.Site.Host, "/stream-raw-close")
	if streamEnded := readRawHTTP2ResponseHeadersStatus(t, conn, fr, streamID, "200"); streamEnded {
		t.Fatal("streaming response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-raw-close" {
			t.Fatalf("upstream path = %q, want %q", path, "/stream-raw-close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raw h2 streaming request did not reach upstream")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("streaming upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("streaming upstream request was not canceled after downstream RST_STREAM")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingResponseWhenRawHTTP2ClientSendsRSTStreamAfterPartialBody(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "partial-")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("partial streaming upstream context was not canceled in time")
		}
	}))
	defer upstream.Close()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-partial-raw-cancel.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2Headers(t, fr, streamID, rt.Site.Host, "/stream-partial-raw-close")
	if streamEnded := readRawHTTP2ResponseHeadersStatus(t, conn, fr, streamID, "200"); streamEnded {
		t.Fatal("streaming response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-partial-raw-close" {
			t.Fatalf("upstream path = %q, want %q", path, "/stream-partial-raw-close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("partial raw h2 streaming request did not reach upstream")
	}

	if !readRawHTTP2ResponseDataContains(t, conn, fr, streamID, "partial-") {
		t.Fatal("did not observe partial response body before client reset")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("partial streaming upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("partial streaming upstream request was not canceled after downstream RST_STREAM")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingResponseWhenRawHTTP2ClientClosesConnectionAfterPartialBody(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "partial-")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("partial close upstream context was not canceled in time")
		}
	}))
	defer upstream.Close()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-partial-raw-close-conn.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)

	const streamID uint32 = 1
	writeRawHTTP2Headers(t, fr, streamID, rt.Site.Host, "/stream-partial-raw-close-conn")
	if streamEnded := readRawHTTP2ResponseHeadersStatus(t, conn, fr, streamID, "200"); streamEnded {
		_ = conn.Close()
		t.Fatal("streaming response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-partial-raw-close-conn" {
			_ = conn.Close()
			t.Fatalf("upstream path = %q, want %q", path, "/stream-partial-raw-close-conn")
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("partial raw h2 connection-close request did not reach upstream")
	}

	if !readRawHTTP2ResponseDataContains(t, conn, fr, streamID, "partial-") {
		_ = conn.Close()
		t.Fatal("did not observe partial response body before connection close")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close raw h2 client connection: %v", err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("partial connection-close upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("partial streaming upstream request was not canceled after downstream connection close")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingResponseWhenRawHTTP2ClientSendsRSTStreamAfterCompressedPartialBody(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	payload := strings.Repeat("compressible-", 256)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = io.WriteString(w, payload[:len(payload)/2])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("compressed streaming upstream context was not canceled in time")
		}
	}))
	defer upstream.Close()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-compressed-raw-cancel.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:                       1,
		Protection:                     protection,
		BrotliEnabled:                  false,
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: true,
		ResponseCompressionMinBytes:    1024,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2HeadersWithFields(t, fr, streamID, rt.Site.Host, "/stream-compressed-raw-close", []hpack.HeaderField{
		{Name: "accept-encoding", Value: "gzip"},
	})
	headers, streamEnded := readRawHTTP2ResponseHeaders(t, conn, fr, streamID)
	if got := headers["status"]; got != "200" {
		t.Fatalf("raw h2 response status = %q, want %q", got, "200")
	}
	if got := headers["content-encoding"]; got != "gzip" {
		t.Fatalf("raw h2 response content-encoding = %q, want %q", got, "gzip")
	}
	if streamEnded {
		t.Fatal("compressed streaming response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-compressed-raw-close" {
			t.Fatalf("upstream path = %q, want %q", path, "/stream-compressed-raw-close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("compressed raw h2 streaming request did not reach upstream")
	}

	if !readRawHTTP2ResponseDataContains(t, conn, fr, streamID, "\x1f\x8b") {
		t.Fatal("did not observe gzip response body bytes before client reset")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("compressed streaming upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("compressed streaming upstream request was not canceled after downstream RST_STREAM")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingResponseWhenRawHTTP2ClientClosesConnectionAfterCompressedPartialBody(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	payload := strings.Repeat("compressible-close-", 128)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = io.WriteString(w, payload[:len(payload)/2])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("compressed close upstream context was not canceled in time")
		}
	}))
	defer upstream.Close()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-compressed-raw-close-conn.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:                       1,
		Protection:                     protection,
		BrotliEnabled:                  false,
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: true,
		ResponseCompressionMinBytes:    1024,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)

	const streamID uint32 = 1
	writeRawHTTP2HeadersWithFields(t, fr, streamID, rt.Site.Host, "/stream-compressed-raw-close-conn", []hpack.HeaderField{
		{Name: "accept-encoding", Value: "gzip"},
	})
	headers, streamEnded := readRawHTTP2ResponseHeaders(t, conn, fr, streamID)
	if got := headers["status"]; got != "200" {
		_ = conn.Close()
		t.Fatalf("raw h2 response status = %q, want %q", got, "200")
	}
	if got := headers["content-encoding"]; got != "gzip" {
		_ = conn.Close()
		t.Fatalf("raw h2 response content-encoding = %q, want %q", got, "gzip")
	}
	if streamEnded {
		_ = conn.Close()
		t.Fatal("compressed streaming response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-compressed-raw-close-conn" {
			_ = conn.Close()
			t.Fatalf("upstream path = %q, want %q", path, "/stream-compressed-raw-close-conn")
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("compressed raw h2 connection-close request did not reach upstream")
	}

	if !readRawHTTP2ResponseHasData(t, conn, fr, streamID) {
		_ = conn.Close()
		t.Fatal("did not observe compressed response body bytes before connection close")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close raw h2 client connection: %v", err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("compressed connection-close upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("compressed streaming upstream request was not canceled after downstream connection close")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingResponseWhenRawHTTP2ClientSendsRSTStreamAfterBrotliCompressedPartialBody(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	payload := strings.Repeat("brotli-compressible-", 128)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = io.WriteString(w, payload[:len(payload)/2])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			upstreamCanceled <- errors.New("brotli streaming upstream context was not canceled in time")
		}
	}))
	defer upstream.Close()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-brotli-raw-cancel.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:                       1,
		Protection:                     protection,
		BrotliEnabled:                  true,
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: true,
		ResponseCompressionMinBytes:    1024,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2HeadersWithFields(t, fr, streamID, rt.Site.Host, "/stream-brotli-raw-close", []hpack.HeaderField{
		{Name: "accept-encoding", Value: "br"},
	})
	headers, streamEnded := readRawHTTP2ResponseHeaders(t, conn, fr, streamID)
	if got := headers["status"]; got != "200" {
		t.Fatalf("raw h2 response status = %q, want %q", got, "200")
	}
	if got := headers["content-encoding"]; got != "br" {
		t.Fatalf("raw h2 response content-encoding = %q, want %q", got, "br")
	}
	if streamEnded {
		t.Fatal("brotli streaming response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-brotli-raw-close" {
			t.Fatalf("upstream path = %q, want %q", path, "/stream-brotli-raw-close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("brotli raw h2 streaming request did not reach upstream")
	}

	if !readRawHTTP2ResponseHasData(t, conn, fr, streamID) {
		t.Fatal("did not observe brotli response body bytes before client reset")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("brotli streaming upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("brotli streaming upstream request was not canceled after downstream RST_STREAM")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingResponseWithDecodedGzipWhenRawHTTP2ClientSendsRSTStreamAfterPartialBody(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = io.WriteString(gz, strings.Repeat("decoded-partial-", 128))
		_ = gz.Flush()
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			_ = gz.Close()
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			_ = gz.Close()
			upstreamCanceled <- errors.New("decoded streaming upstream context was not canceled in time")
		}
	}))
	defer upstream.Close()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-decoded-raw-cancel.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2Headers(t, fr, streamID, rt.Site.Host, "/stream-decoded-raw-close")
	headers, streamEnded := readRawHTTP2ResponseHeaders(t, conn, fr, streamID)
	if got := headers["status"]; got != "200" {
		t.Fatalf("raw h2 response status = %q, want %q", got, "200")
	}
	if got := headers["content-encoding"]; got != "" {
		t.Fatalf("raw h2 decoded response content-encoding = %q, want empty", got)
	}
	if streamEnded {
		t.Fatal("decoded streaming response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-decoded-raw-close" {
			t.Fatalf("upstream path = %q, want %q", path, "/stream-decoded-raw-close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("decoded raw h2 streaming request did not reach upstream")
	}

	if !readRawHTTP2ResponseDataContains(t, conn, fr, streamID, "decoded-partial-") {
		t.Fatal("did not observe decoded response body before client reset")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("decoded streaming upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("decoded streaming upstream request was not canceled after downstream RST_STREAM")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingResponseWithDecodedGzipWhenRawHTTP2ClientClosesConnectionAfterPartialBody(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamStarted <- r.URL.Path
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = io.WriteString(gz, strings.Repeat("decoded-partial-", 128))
		_ = gz.Flush()
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			_ = gz.Close()
			upstreamCanceled <- r.Context().Err()
		case <-time.After(3 * time.Second):
			_ = gz.Close()
			upstreamCanceled <- errors.New("decoded close upstream context was not canceled in time")
		}
	}))
	defer upstream.Close()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-decoded-raw-close-conn.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{upstream.URL},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)

	const streamID uint32 = 1
	writeRawHTTP2Headers(t, fr, streamID, rt.Site.Host, "/stream-decoded-raw-close-conn")
	headers, streamEnded := readRawHTTP2ResponseHeaders(t, conn, fr, streamID)
	if got := headers["status"]; got != "200" {
		_ = conn.Close()
		t.Fatalf("raw h2 response status = %q, want %q", got, "200")
	}
	if got := headers["content-encoding"]; got != "" {
		_ = conn.Close()
		t.Fatalf("raw h2 decoded response content-encoding = %q, want empty", got)
	}
	if streamEnded {
		_ = conn.Close()
		t.Fatal("decoded streaming response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-decoded-raw-close-conn" {
			_ = conn.Close()
			t.Fatalf("upstream path = %q, want %q", path, "/stream-decoded-raw-close-conn")
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("decoded raw h2 connection-close request did not reach upstream")
	}

	if !readRawHTTP2ResponseDataContains(t, conn, fr, streamID, "decoded-partial-") {
		_ = conn.Close()
		t.Fatal("did not observe decoded response body before connection close")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close raw h2 client connection: %v", err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("decoded connection-close upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("decoded streaming upstream request was not canceled after downstream connection close")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingResponseWithTrailersWhenRawHTTP2ClientSendsRSTStreamAfterPartialBody(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw upstream: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = req.Body.Close()
		upstreamStarted <- req.URL.Path

		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n")
		_, _ = io.WriteString(conn, "Content-Type: text/plain; charset=utf-8\r\n")
		_, _ = io.WriteString(conn, "Transfer-Encoding: chunked\r\n")
		_, _ = io.WriteString(conn, "Trailer: X-Upstream-Trailer\r\n\r\n")
		if err := writeHTTPChunk(conn, []byte("trailer-partial-")); err != nil {
			return
		}

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		}
		scratch := make([]byte, 1)
		_, readErr := conn.Read(scratch)
		if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
			upstreamCanceled <- errors.New("trailer streaming upstream connection was not closed in time")
			return
		}
		if readErr == nil {
			upstreamCanceled <- errors.New("trailer streaming upstream unexpectedly received additional request bytes")
			return
		}
		upstreamCanceled <- context.Canceled
	}()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-trailer-raw-cancel.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{"http://" + ln.Addr().String()},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)
	t.Cleanup(func() {
		_ = conn.Close()
	})

	const streamID uint32 = 1
	writeRawHTTP2HeadersWithFields(t, fr, streamID, rt.Site.Host, "/stream-trailer-raw-close", []hpack.HeaderField{
		{Name: "te", Value: "trailers"},
	})
	headers, streamEnded := readRawHTTP2ResponseHeaders(t, conn, fr, streamID)
	if got := headers["status"]; got != "200" {
		t.Fatalf("raw h2 response status = %q, want %q", got, "200")
	}
	if streamEnded {
		t.Fatal("trailer streaming response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-trailer-raw-close" {
			t.Fatalf("upstream path = %q, want %q", path, "/stream-trailer-raw-close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("trailer raw h2 streaming request did not reach upstream")
	}

	if !readRawHTTP2ResponseDataContains(t, conn, fr, streamID, "trailer-partial-") {
		t.Fatal("did not observe trailer response body before client reset")
	}

	if err := fr.WriteRSTStream(streamID, http2.ErrCodeCancel); err != nil {
		t.Fatalf("WriteRSTStream(%d) error = %v", streamID, err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("trailer streaming upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("trailer streaming upstream request was not canceled after downstream RST_STREAM")
	}
}

func TestBuildDataServerCancelsUpstreamStreamingResponseWithTrailersWhenRawHTTP2ClientClosesConnectionAfterPartialBody(t *testing.T) {
	upstreamStarted := make(chan string, 1)
	upstreamCanceled := make(chan error, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen raw upstream: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = req.Body.Close()
		upstreamStarted <- req.URL.Path

		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n")
		_, _ = io.WriteString(conn, "Content-Type: text/plain; charset=utf-8\r\n")
		_, _ = io.WriteString(conn, "Transfer-Encoding: chunked\r\n")
		_, _ = io.WriteString(conn, "Trailer: X-Upstream-Trailer\r\n\r\n")
		if err := writeHTTPChunk(conn, []byte("trailer-partial-")); err != nil {
			return
		}

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		}
		scratch := make([]byte, 1)
		_, readErr := conn.Read(scratch)
		if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
			upstreamCanceled <- errors.New("trailer close upstream connection was not closed in time")
			return
		}
		if readErr == nil {
			upstreamCanceled <- errors.New("trailer close upstream unexpectedly received additional request bytes")
			return
		}
		upstreamCanceled <- context.Canceled
	}()

	lnData, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve test bind: %v", err)
	}
	bind := lnData.Addr().String()
	if err := lnData.Close(); err != nil {
		t.Fatalf("release reserved bind: %v", err)
	}

	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false

	holder := &snapshotpkg.Holder{}
	rt := snapshotpkg.SiteRuntime{
		Bind: bind,
		Site: store.Site{
			ID:         1,
			Host:       "stream-trailer-raw-close-conn.example.test",
			Bind:       bind,
			TLSEnabled: true,
			ALPN:       "h2,http/1.1",
		},
		UpstreamURLs:        []string{"http://" + ln.Addr().String()},
		NetworkDefaults:     snapshotpkg.DefaultNetworkDefaults(),
		TLSDefaults:         snapshotpkg.DefaultTLSDefaults(),
		EffectiveProtection: &protection,
	}
	sn := &snapshotpkg.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(bind, rt.Site.Host): rt,
		},
	}
	holder.Store(sn)

	srv := buildDataServer(rt, sn, dataplane.Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   bind,
	})
	if srv == nil {
		t.Fatal("expected data server")
	}

	go srv.Spin()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.IsRunning() {
		if time.Now().After(deadline) {
			t.Fatal("data server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	conn, fr := newRawHTTP2ClientConn(t, bind)

	const streamID uint32 = 1
	writeRawHTTP2HeadersWithFields(t, fr, streamID, rt.Site.Host, "/stream-trailer-raw-close-conn", []hpack.HeaderField{
		{Name: "te", Value: "trailers"},
	})
	headers, streamEnded := readRawHTTP2ResponseHeaders(t, conn, fr, streamID)
	if got := headers["status"]; got != "200" {
		_ = conn.Close()
		t.Fatalf("raw h2 response status = %q, want %q", got, "200")
	}
	if streamEnded {
		_ = conn.Close()
		t.Fatal("trailer streaming response unexpectedly ended with headers only")
	}

	select {
	case path := <-upstreamStarted:
		if path != "/stream-trailer-raw-close-conn" {
			_ = conn.Close()
			t.Fatalf("upstream path = %q, want %q", path, "/stream-trailer-raw-close-conn")
		}
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		t.Fatal("trailer raw h2 connection-close request did not reach upstream")
	}

	if !readRawHTTP2ResponseDataContains(t, conn, fr, streamID, "trailer-partial-") {
		_ = conn.Close()
		t.Fatal("did not observe trailer response body before connection close")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close raw h2 client connection: %v", err)
	}

	select {
	case err := <-upstreamCanceled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("trailer connection-close upstream cancel error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("trailer streaming upstream request was not canceled after downstream connection close")
	}
}

func TestNeedsTLSClientHelloFingerprint(t *testing.T) {
	baseProtection := store.DefaultProtectionConfig()
	baseProtection.BotDetectionEnabled = false

	botProtection := store.DefaultProtectionConfig()
	botProtection.BotDetectionEnabled = true

	tests := []struct {
		name string
		rt   snapshotpkg.SiteRuntime
		want bool
	}{
		{
			name: "handshake metadata only rule does not require client hello parse",
			rt: snapshotpkg.SiteRuntime{
				EffectiveProtection: &baseProtection,
				Rules: []snapshotpkg.CompiledRule{
					{Kind: "tls_sni"},
				},
			},
			want: false,
		},
		{
			name: "tls version rule does not require client hello parse",
			rt: snapshotpkg.SiteRuntime{
				EffectiveProtection: &baseProtection,
				Rules: []snapshotpkg.CompiledRule{
					{Kind: "tls_version"},
				},
			},
			want: false,
		},
		{
			name: "ja4 rule requires client hello parse",
			rt: snapshotpkg.SiteRuntime{
				EffectiveProtection: &baseProtection,
				Rules: []snapshotpkg.CompiledRule{
					{Kind: "tls_ja4"},
				},
			},
			want: true,
		},
		{
			name: "tls cipher suites rule requires client hello parse",
			rt: snapshotpkg.SiteRuntime{
				EffectiveProtection: &baseProtection,
				Rules: []snapshotpkg.CompiledRule{
					{Kind: "tls_cipher_suites"},
				},
			},
			want: true,
		},
		{
			name: "bot detection requires client hello parse",
			rt: snapshotpkg.SiteRuntime{
				EffectiveProtection: &botProtection,
			},
			want: true,
		},
		{
			name: "application route fingerprint target requires client hello parse",
			rt: snapshotpkg.SiteRuntime{
				EffectiveProtection: &baseProtection,
				AppRouteRules: []appresource.CompiledRule{
					{Target: store.AppRouteTargetFingerprint},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needsTLSClientHelloFingerprint(tt.rt); got != tt.want {
				t.Fatalf("needsTLSClientHelloFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRedisRuntimeSyncNeeded(t *testing.T) {
	tests := []struct {
		name           string
		stored         adminsystem.RedisConfig
		runtimeCfg     core.Config
		runtimeEnabled bool
		want           bool
	}{
		{
			name: "stored enabled but runtime disconnected",
			stored: adminsystem.RedisConfig{
				Enabled: true,
				Addr:    "127.0.0.1:6379",
				DB:      3,
			},
			runtimeCfg:     core.Config{RedisAddr: "127.0.0.1:6379", RedisDB: 3},
			runtimeEnabled: false,
			want:           true,
		},
		{
			name: "stored enabled and runtime already matches",
			stored: adminsystem.RedisConfig{
				Enabled:  true,
				Addr:     "127.0.0.1:6379",
				Password: "secret",
				DB:       3,
			},
			runtimeCfg:     core.Config{RedisAddr: "127.0.0.1:6379", RedisPassword: "secret", RedisDB: 3},
			runtimeEnabled: true,
			want:           false,
		},
		{
			name: "stored enabled and runtime db differs",
			stored: adminsystem.RedisConfig{
				Enabled: true,
				Addr:    "127.0.0.1:6379",
				DB:      4,
			},
			runtimeCfg:     core.Config{RedisAddr: "127.0.0.1:6379", RedisDB: 3},
			runtimeEnabled: true,
			want:           true,
		},
		{
			name:           "stored disabled but runtime still attached",
			stored:         adminsystem.RedisConfig{Enabled: false},
			runtimeCfg:     core.Config{RedisAddr: "127.0.0.1:6379", RedisPassword: "secret", RedisDB: 3},
			runtimeEnabled: true,
			want:           true,
		},
		{
			name:           "stored disabled and runtime already cleared",
			stored:         adminsystem.RedisConfig{Enabled: false},
			runtimeCfg:     core.Config{},
			runtimeEnabled: false,
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redisRuntimeSyncNeeded(tt.stored, tt.runtimeCfg, tt.runtimeEnabled); got != tt.want {
				t.Fatalf("redisRuntimeSyncNeeded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldPublishConfigReloadBeforeRedisSwitch(t *testing.T) {
	tests := []struct {
		name           string
		propagate      bool
		stored         adminsystem.RedisConfig
		runtimeCfg     core.Config
		runtimeEnabled bool
		want           bool
	}{
		{
			name:      "local admin reload with redis change should publish before switch",
			propagate: true,
			stored: adminsystem.RedisConfig{
				Enabled:  true,
				Addr:     "127.0.0.1:6379",
				Password: "secret",
				DB:       4,
			},
			runtimeCfg:     core.Config{RedisAddr: "127.0.0.1:6379", RedisPassword: "secret", RedisDB: 3},
			runtimeEnabled: true,
			want:           true,
		},
		{
			name:           "subscriber reload must not republish",
			propagate:      false,
			stored:         adminsystem.RedisConfig{Enabled: true, Addr: "127.0.0.1:6379", DB: 3},
			runtimeCfg:     core.Config{RedisAddr: "127.0.0.1:6379", RedisDB: 3},
			runtimeEnabled: true,
			want:           false,
		},
		{
			name:      "unchanged redis does not need pre publish",
			propagate: true,
			stored: adminsystem.RedisConfig{
				Enabled:  true,
				Addr:     "127.0.0.1:6379",
				Password: "secret",
				DB:       3,
			},
			runtimeCfg:     core.Config{RedisAddr: "127.0.0.1:6379", RedisPassword: "secret", RedisDB: 3},
			runtimeEnabled: true,
			want:           false,
		},
		{
			name:           "redis disabled in runtime cannot pre publish",
			propagate:      true,
			stored:         adminsystem.RedisConfig{Enabled: true, Addr: "127.0.0.1:6379", DB: 3},
			runtimeCfg:     core.Config{RedisAddr: "127.0.0.1:6379", RedisDB: 3},
			runtimeEnabled: false,
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldPublishConfigReloadBeforeRedisSwitch(tt.propagate, tt.stored, tt.runtimeCfg, tt.runtimeEnabled); got != tt.want {
				t.Fatalf("shouldPublishConfigReloadBeforeRedisSwitch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyRedisRuntimeReloadUpdatesRuntimeAndRedisBackedCaches(t *testing.T) {
	redisSrv := startAppMockRedisServer(t)
	t.Cleanup(redisSrv.Close)

	nextClient := goredis.NewClient(&goredis.Options{Addr: redisSrv.Addr()})
	t.Cleanup(func() {
		_ = nextClient.Close()
	})

	pingCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := nextClient.Ping(pingCtx).Err(); err != nil {
		t.Fatalf("ping mock redis: %v", err)
	}

	rt := &core.Runtime{}
	runtimeStateMu := &sync.RWMutex{}
	redisKV := cache.NewRedisKV(nil)
	hotCache := cache.NewHotCache(nil, slog.Default())

	var syncedClient *goredis.Client
	updatedCfg := applyRedisRuntimeReload(rt, adminsystem.RedisConfig{
		Enabled:  true,
		Addr:     redisSrv.Addr(),
		Password: "runtime-pass",
		DB:       7,
	}, nextClient, redisRuntimeReloadDeps{
		runtimeStateMu: runtimeStateMu,
		redisKV:        redisKV,
		hotCache:       hotCache,
		replaceConfigSync: func(client *goredis.Client) {
			syncedClient = client
		},
	})

	if rt.Redis != nextClient {
		t.Fatal("runtime redis client was not updated")
	}
	if updatedCfg.RedisAddr != redisSrv.Addr() {
		t.Fatalf("updated redis addr = %q, want %q", updatedCfg.RedisAddr, redisSrv.Addr())
	}
	if updatedCfg.RedisPassword != "runtime-pass" {
		t.Fatalf("updated redis password = %q, want %q", updatedCfg.RedisPassword, "runtime-pass")
	}
	if updatedCfg.RedisDB != 7 {
		t.Fatalf("updated redis db = %d, want 7", updatedCfg.RedisDB)
	}
	if !redisKV.Available() {
		t.Fatal("redisKV should be available after runtime reload")
	}
	if !hotCache.Available() {
		t.Fatal("hotCache should be available after runtime reload")
	}
	if syncedClient != nextClient {
		t.Fatal("replaceConfigSync did not receive the reloaded redis client")
	}

	if err := redisKV.Set("runtime-switch", []byte("payload"), 5*time.Second); err != nil {
		t.Fatalf("redisKV set after reload: %v", err)
	}
	hotCache.Set("runtime-switch-hot", map[string]string{"value": "payload"}, 5*time.Second)

	deadline := time.Now().Add(time.Second)
	for {
		commands := redisSrv.Commands()
		if appMockRedisHasCommand(commands, "SET OPENWAF:RUNTIME-SWITCH") &&
			appMockRedisHasCommand(commands, "SET OPENWAF:HOT:RUNTIME-SWITCH-HOT") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected redis commands after reload, got %#v", commands)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type appMockRedisServer struct {
	ln       net.Listener
	mu       sync.Mutex
	commands []string
	values   map[string]string
}

func startAppMockRedisServer(t *testing.T) *appMockRedisServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen app mock redis: %v", err)
	}

	srv := &appMockRedisServer{
		ln:     ln,
		values: make(map[string]string),
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handle(conn)
		}
	}()
	return srv
}

func (s *appMockRedisServer) Addr() string { return s.ln.Addr().String() }

func (s *appMockRedisServer) Close() {
	_ = s.ln.Close()
}

func (s *appMockRedisServer) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]string, len(s.commands))
	copy(out, s.commands)
	return out
}

func (s *appMockRedisServer) record(args []string) {
	parts := make([]string, len(args))
	for i := range args {
		parts[i] = strings.ToUpper(args[i])
	}

	s.mu.Lock()
	s.commands = append(s.commands, strings.Join(parts, " "))
	s.mu.Unlock()
}

func (s *appMockRedisServer) setValue(key string, value string) {
	s.mu.Lock()
	s.values[key] = value
	s.mu.Unlock()
}

func (s *appMockRedisServer) getValue(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[key]
	return value, ok
}

func (s *appMockRedisServer) handle(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		args, err := readAppRESPArgs(reader)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}

		s.record(args)

		switch strings.ToUpper(args[0]) {
		case "HELLO":
			_, _ = conn.Write([]byte("-ERR unknown command 'hello'\r\n"))
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))
		case "GET":
			if len(args) < 2 {
				_, _ = conn.Write([]byte("$-1\r\n"))
				continue
			}
			value, ok := s.getValue(args[1])
			if !ok {
				_, _ = conn.Write([]byte("$-1\r\n"))
				continue
			}
			_, _ = conn.Write([]byte(fmt.Sprintf("$%d\r\n%s\r\n", len(value), value)))
		case "SET":
			if len(args) >= 3 {
				s.setValue(args[1], args[2])
			}
			_, _ = conn.Write([]byte("+OK\r\n"))
		default:
			_, _ = conn.Write([]byte("+OK\r\n"))
		}
	}
}

func readAppRESPArgs(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}

	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("expected RESP array, got %q", line)
	}

	count, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}

	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		header, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}

		header = strings.TrimRight(header, "\r\n")
		if !strings.HasPrefix(header, "$") {
			return nil, fmt.Errorf("expected bulk string, got %q", header)
		}

		length, err := strconv.Atoi(header[1:])
		if err != nil {
			return nil, err
		}

		buf := make([]byte, length)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		if _, err := r.Discard(2); err != nil {
			return nil, err
		}

		args = append(args, string(buf))
	}

	return args, nil
}

func appMockRedisHasCommand(commands []string, prefix string) bool {
	for _, command := range commands {
		if strings.Contains(command, prefix) {
			return true
		}
	}
	return false
}

func newRawHTTP2ClientConn(t *testing.T, bind string) (*tls.Conn, *http2.Framer) {
	conn, fr, _ := newRawHTTP2ClientConnWithServerSettings(t, bind)
	return conn, fr
}

func newRawHTTP2ClientConnWithServerSettings(t *testing.T, bind string) (*tls.Conn, *http2.Framer, map[http2.SettingID]uint32) {
	t.Helper()

	conn, err := tls.Dial("tcp", bind, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		t.Fatalf("tls dial raw h2: %v", err)
	}
	if state := conn.ConnectionState(); state.NegotiatedProtocol != "h2" {
		_ = conn.Close()
		t.Fatalf("negotiated protocol = %q, want %q", state.NegotiatedProtocol, "h2")
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		_ = conn.Close()
		t.Fatalf("write client preface: %v", err)
	}

	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		_ = conn.Close()
		t.Fatalf("WriteSettings() error = %v", err)
	}
	settings := waitForRawHTTP2ServerSettings(t, conn, fr)
	return conn, fr, settings
}

func waitForRawHTTP2ServerSettings(t *testing.T, conn *tls.Conn, fr *http2.Framer) map[http2.SettingID]uint32 {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read server settings frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}
		if settings, ok := frame.(*http2.SettingsFrame); ok && !settings.IsAck() {
			got := make(map[http2.SettingID]uint32)
			if err := settings.ForeachSetting(func(s http2.Setting) error {
				got[s.ID] = s.Val
				return nil
			}); err != nil {
				t.Fatalf("ForeachSetting() error = %v", err)
			}
			if err := fr.WriteSettingsAck(); err != nil {
				t.Fatalf("WriteSettingsAck() error = %v", err)
			}
			return got
		}
		if _, ok := frame.(*http2.GoAwayFrame); ok {
			t.Fatal("server sent GOAWAY before request sequence started")
		}
		if time.Now().After(deadline) {
			t.Fatal("did not receive server settings frame in time")
		}
	}
}

func readRawHTTP2SettingsAck(t *testing.T, conn *tls.Conn, fr *http2.Framer) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read settings ack: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY while waiting for settings ack: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.SettingsFrame:
			if typed.IsAck() {
				return
			}
		}

		if time.Now().After(deadline) {
			t.Fatal("did not observe settings ack in time")
		}
	}
}

func encodeRawHTTP2RequestHeadersWithMethodAndFields(t *testing.T, method string, authority string, path string, fields []hpack.HeaderField) []byte {
	t.Helper()

	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	allFields := make([]hpack.HeaderField, 0, 4+len(fields))
	allFields = append(allFields,
		hpack.HeaderField{Name: ":method", Value: method},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: authority},
		hpack.HeaderField{Name: ":path", Value: path},
	)
	allFields = append(allFields, fields...)
	for _, field := range allFields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatalf("encode raw h2 header %q: %v", field.Name, err)
		}
	}
	return block.Bytes()
}

func writeRawHTTP2HeadersFrame(t *testing.T, fr *http2.Framer, streamID uint32, authority string, path string, endStream bool, endHeaders bool) {
	t.Helper()

	writeRawHTTP2HeadersFrameWithFields(t, fr, streamID, authority, path, nil, endStream, endHeaders)
}

func writeRawHTTP2HeadersFrameWithMethod(t *testing.T, fr *http2.Framer, streamID uint32, method string, authority string, path string, endStream bool, endHeaders bool) {
	t.Helper()

	writeRawHTTP2HeadersFrameWithMethodAndFields(t, fr, streamID, method, authority, path, nil, endStream, endHeaders)
}

func writeRawHTTP2HeadersFrameWithFields(t *testing.T, fr *http2.Framer, streamID uint32, authority string, path string, fields []hpack.HeaderField, endStream bool, endHeaders bool) {
	t.Helper()

	writeRawHTTP2HeadersFrameWithMethodAndFields(t, fr, streamID, http.MethodGet, authority, path, fields, endStream, endHeaders)
}

func writeRawHTTP2HeadersFrameWithMethodAndFields(t *testing.T, fr *http2.Framer, streamID uint32, method string, authority string, path string, fields []hpack.HeaderField, endStream bool, endHeaders bool) {
	t.Helper()

	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: encodeRawHTTP2RequestHeadersWithMethodAndFields(t, method, authority, path, fields),
		EndStream:     endStream,
		EndHeaders:    endHeaders,
	}); err != nil {
		t.Fatalf("WriteHeaders(stream=%d,method=%q,path=%q,endStream=%v,endHeaders=%v) error = %v", streamID, method, path, endStream, endHeaders, err)
	}
}

func writeRawHTTP2Headers(t *testing.T, fr *http2.Framer, streamID uint32, authority string, path string) {
	t.Helper()

	writeRawHTTP2HeadersWithFields(t, fr, streamID, authority, path, nil)
}

func writeRawHTTP2HeadersWithFields(t *testing.T, fr *http2.Framer, streamID uint32, authority string, path string, fields []hpack.HeaderField) {
	t.Helper()

	writeRawHTTP2HeadersFrameWithFields(t, fr, streamID, authority, path, fields, true, true)
}

func writeRawHTTP2WindowUpdate(t *testing.T, fr *http2.Framer, streamID uint32, increment uint32) {
	t.Helper()

	prev := fr.AllowIllegalWrites
	fr.AllowIllegalWrites = true
	defer func() {
		fr.AllowIllegalWrites = prev
	}()

	if err := fr.WriteWindowUpdate(streamID, increment); err != nil {
		t.Fatalf("WriteWindowUpdate(stream=%d,increment=%d) error = %v", streamID, increment, err)
	}
}

func writeRawHTTP2Data(t *testing.T, fr *http2.Framer, streamID uint32, endStream bool, data []byte) {
	t.Helper()

	if err := fr.WriteData(streamID, endStream, data); err != nil {
		t.Fatalf("WriteData(stream=%d,endStream=%v,len=%d) error = %v", streamID, endStream, len(data), err)
	}
}

func writeRawHTTP2HeaderFieldsFrame(t *testing.T, fr *http2.Framer, streamID uint32, fields []hpack.HeaderField, endStream bool, endHeaders bool) {
	t.Helper()

	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatalf("encode raw h2 header field %q: %v", field.Name, err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: block.Bytes(),
		EndStream:     endStream,
		EndHeaders:    endHeaders,
	}); err != nil {
		t.Fatalf("WriteHeaders(stream=%d,trailer_fields=%d,endStream=%v,endHeaders=%v) error = %v", streamID, len(fields), endStream, endHeaders, err)
	}
}

func writeHTTPChunk(w io.Writer, chunk []byte) error {
	if _, err := fmt.Fprintf(w, "%x\r\n", len(chunk)); err != nil {
		return err
	}
	if _, err := w.Write(chunk); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func readHTTPFinalResponse(reader *bufio.Reader, req *http.Request) (*http.Response, error) {
	for {
		resp, err := http.ReadResponse(reader, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 100 && resp.StatusCode < 200 {
			_ = resp.Body.Close()
			continue
		}
		return resp, nil
	}
}

func writeRawHTTP2Continuation(t *testing.T, fr *http2.Framer, streamID uint32, endHeaders bool, blockFragment []byte) {
	t.Helper()

	if err := fr.WriteContinuation(streamID, endHeaders, blockFragment); err != nil {
		t.Fatalf("WriteContinuation(stream=%d,endHeaders=%v,len=%d) error = %v", streamID, endHeaders, len(blockFragment), err)
	}
}

func writeRawHTTP2PingFrame(t *testing.T, fr *http2.Framer, streamID uint32, ack bool, data [8]byte) {
	t.Helper()

	var flags http2.Flags
	if ack {
		flags = http2.FlagPingAck
	}
	if err := fr.WriteRawFrame(http2.FramePing, flags, streamID, data[:]); err != nil {
		t.Fatalf("WriteRawFrame(PING,stream=%d,ack=%v) error = %v", streamID, ack, err)
	}
}

func readRawHTTP2ResponseHeadersStatus(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32, wantStatus string) bool {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 response headers frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY during raw h2 response header sequence: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.MetaHeadersFrame:
			if typed.StreamID != streamID {
				continue
			}
			if got := typed.PseudoValue("status"); got != wantStatus {
				t.Fatalf("raw h2 response status = %q, want %q", got, wantStatus)
			}
			return typed.StreamEnded()
		}

		if time.Now().After(deadline) {
			t.Fatalf("did not observe response headers for stream %d", streamID)
		}
	}
}

func readRawHTTP2ResponseHeaders(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32) (map[string]string, bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 response headers frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY during raw h2 response header sequence: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.MetaHeadersFrame:
			if typed.StreamID != streamID {
				continue
			}
			headers := make(map[string]string, len(typed.Fields))
			for _, field := range typed.Fields {
				key := strings.ToLower(field.Name)
				headers[key] = field.Value
				if strings.HasPrefix(key, ":") && len(key) > 1 {
					headers[strings.TrimPrefix(key, ":")] = field.Value
				}
			}
			return headers, typed.StreamEnded()
		}

		if time.Now().After(deadline) {
			t.Fatalf("did not observe response headers for stream %d", streamID)
		}
	}
}

func readRawHTTP2ResponseStatus(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32, wantStatus string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 response frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY during raw h2 sequence: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.MetaHeadersFrame:
			if typed.StreamID != streamID {
				continue
			}
			if got := typed.PseudoValue("status"); got != wantStatus {
				t.Fatalf("raw h2 response status = %q, want %q", got, wantStatus)
			}
			if typed.StreamEnded() {
				return
			}
		case *http2.DataFrame:
			if typed.StreamID == streamID && typed.StreamEnded() {
				return
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("did not observe response completion for stream %d", streamID)
		}
	}
}

func readRawHTTP2ResponseDataContains(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32, wantSubstring string) bool {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 response data frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY during raw h2 response data sequence: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.DataFrame:
			if typed.StreamID != streamID {
				continue
			}
			if strings.Contains(string(typed.Data()), wantSubstring) {
				return true
			}
		}

		if time.Now().After(deadline) {
			return false
		}
	}
}

func readRawHTTP2ResponseHasData(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32) bool {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 response data frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY during raw h2 response data sequence: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.DataFrame:
			if typed.StreamID != streamID {
				continue
			}
			if len(typed.Data()) > 0 {
				return true
			}
		}

		if time.Now().After(deadline) {
			return false
		}
	}
}

func readRawHTTP2StreamCompletion(t *testing.T, conn *tls.Conn, fr *http2.Framer, streamID uint32) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 stream completion frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY during raw h2 stream completion sequence: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.RSTStreamFrame:
			if typed.StreamID == streamID {
				t.Fatalf("stream %d unexpectedly ended with RST_STREAM code %v", streamID, typed.ErrCode)
			}
		case *http2.MetaHeadersFrame:
			if typed.StreamID == streamID && typed.StreamEnded() {
				return
			}
		case *http2.DataFrame:
			if typed.StreamID == streamID && typed.StreamEnded() {
				return
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("did not observe completion for stream %d", streamID)
		}
	}
}

func readRawHTTP2ResponseStatuses(t *testing.T, conn *tls.Conn, fr *http2.Framer, want map[uint32]string) {
	t.Helper()

	pending := make(map[uint32]string, len(want))
	completed := make(map[uint32]bool, len(want))
	for streamID, status := range want {
		pending[streamID] = status
	}

	deadline := time.Now().Add(2 * time.Second)
	for len(pending) > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 response frames: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY during raw h2 multi-response sequence: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.MetaHeadersFrame:
			wantStatus, ok := pending[typed.StreamID]
			if !ok {
				continue
			}
			if got := typed.PseudoValue("status"); got != wantStatus {
				t.Fatalf("raw h2 response status = %q, want %q, stream=%d", got, wantStatus, typed.StreamID)
			}
			if typed.StreamEnded() {
				delete(pending, typed.StreamID)
				delete(completed, typed.StreamID)
				continue
			}
			completed[typed.StreamID] = true
		case *http2.DataFrame:
			if _, ok := pending[typed.StreamID]; !ok {
				continue
			}
			if typed.StreamEnded() {
				if !completed[typed.StreamID] {
					t.Fatalf("stream %d ended with DATA before matching response headers", typed.StreamID)
				}
				delete(pending, typed.StreamID)
				delete(completed, typed.StreamID)
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("did not observe all expected response completions, pending=%d", len(pending))
		}
	}
}

func readRawHTTP2RSTStreams(t *testing.T, conn *tls.Conn, fr *http2.Framer, want map[uint32]http2.ErrCode) {
	t.Helper()

	pending := make(map[uint32]http2.ErrCode, len(want))
	for streamID, code := range want {
		pending[streamID] = code
	}

	deadline := time.Now().Add(2 * time.Second)
	for len(pending) > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 RST_STREAM frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		switch typed := frame.(type) {
		case *http2.GoAwayFrame:
			t.Fatalf("server sent GOAWAY while waiting for RST_STREAM frames: err_code=%v last_stream=%d", typed.ErrCode, typed.LastStreamID)
		case *http2.RSTStreamFrame:
			wantCode, ok := pending[typed.StreamID]
			if !ok {
				continue
			}
			if typed.ErrCode != wantCode {
				t.Fatalf("raw h2 RST_STREAM code = %v, want %v, stream=%d", typed.ErrCode, wantCode, typed.StreamID)
			}
			delete(pending, typed.StreamID)
		}

		if time.Now().After(deadline) {
			t.Fatalf("did not observe all expected RST_STREAM frames, pending=%d", len(pending))
		}
	}
}

func readRawHTTP2GoAway(t *testing.T, conn *tls.Conn, fr *http2.Framer, wantCode http2.ErrCode) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		frame, err := fr.ReadFrame()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			t.Fatalf("read raw h2 GOAWAY frame: %v", err)
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("clear read deadline: %v", err)
		}

		if typed, ok := frame.(*http2.GoAwayFrame); ok {
			if typed.ErrCode != wantCode {
				t.Fatalf("raw h2 GOAWAY code = %v, want %v", typed.ErrCode, wantCode)
			}
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("did not observe GOAWAY frame, want code %v", wantCode)
		}
	}
}

type testTLSHandshakeInfoConn struct {
	net.Conn
	version string
	sni     string
	alpn    string
}

func (c *testTLSHandshakeInfoConn) SetTLSHandshakeInfo(version string, sni string, alpn string) {
	c.version = version
	c.sni = sni
	c.alpn = alpn
}
