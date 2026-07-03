package system

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/core"
	"My-OpenWaf/internal/pkg/logger"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

type testRedisServer struct {
	ln net.Listener
}

func newSystemSettingsRepoForTest(t *testing.T) *repository.SystemSettingsRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

func invokeSystemConfigHandler(t *testing.T, handler app.HandlerFunc, method, uri string, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(payload)

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

func startTestRedisServer(t *testing.T) *testRedisServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock redis: %v", err)
	}

	srv := &testRedisServer{ln: ln}
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

func (s *testRedisServer) Addr() string {
	return s.ln.Addr().String()
}

func (s *testRedisServer) Close() {
	_ = s.ln.Close()
}

func (s *testRedisServer) handle(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		args, err := readRESPArgsForTest(reader)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}

		switch strings.ToUpper(args[0]) {
		case "HELLO":
			_, _ = conn.Write([]byte("-ERR unknown command 'hello'\r\n"))
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))
		default:
			_, _ = conn.Write([]byte("+OK\r\n"))
		}
	}
}

func readRESPArgsForTest(r *bufio.Reader) ([]string, error) {
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

func TestUpdateNetworkConfigPreservesOmittedHTTP3Bind(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyNetwork, `{"ipv6_enabled":false,"http2_enabled":true,"http3_enabled":true,"http3_bind":":8443","default_alpn":"h3,h2,http/1.1","default_network":"tcp"}`); err != nil {
		t.Fatalf("seed network config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, UpdateNetworkConfig(repo, func() error { return nil }), "POST", "/api/v1/network-config", []byte(`{"http3_enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get(settingKeyNetwork)
	if err != nil {
		t.Fatalf("load network config: %v", err)
	}
	var got NetworkConfig
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode network config: %v", err)
	}
	if got.HTTP3Enabled {
		t.Fatalf("explicit http3_enabled=false was not saved: %#v", got)
	}
	if got.HTTP3Bind != ":8443" {
		t.Fatalf("omitted http3_bind should be preserved, got %q", got.HTTP3Bind)
	}
}

func TestLoadNetworkConfigFallsBackInvalidHTTP3Bind(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyNetwork, `{"ipv6_enabled":false,"http2_enabled":true,"http3_enabled":true,"http3_bind":"not-a-bind","default_alpn":"h3,h2,http/1.1","default_network":"tcp"}`); err != nil {
		t.Fatalf("seed network config: %v", err)
	}

	got := loadNetworkConfig(repo)
	if got.HTTP3Bind != ":443" {
		t.Fatalf("invalid http3_bind should fallback to :443, got %q", got.HTTP3Bind)
	}
}

func TestLoadNetworkConfigDerivesMissingDefaultALPNFromProtocolSwitches(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyNetwork, `{"ipv6_enabled":false,"http2_enabled":true,"http3_enabled":false,"http3_bind":":8443","default_network":"tcp"}`); err != nil {
		t.Fatalf("seed network config: %v", err)
	}

	got := loadNetworkConfig(repo)
	if got.HTTP3Enabled {
		t.Fatalf("http3_enabled = true, want false: %#v", got)
	}
	if got.DefaultALPN != "h2,http/1.1" {
		t.Fatalf("default_alpn = %q, want %q", got.DefaultALPN, "h2,http/1.1")
	}
	if got.HTTP3Bind != ":8443" {
		t.Fatalf("http3_bind = %q, want %q", got.HTTP3Bind, ":8443")
	}

	if err := repo.Set(settingKeyNetwork, `{"ipv6_enabled":false,"http2_enabled":true,"http3_enabled":false,"http3_bind":":8443","default_alpn":"h3,http/1.1","default_network":"tcp"}`); err != nil {
		t.Fatalf("seed explicit network config: %v", err)
	}
	got = loadNetworkConfig(repo)
	if got.DefaultALPN != "h3,http/1.1" {
		t.Fatalf("explicit default_alpn = %q, want %q", got.DefaultALPN, "h3,http/1.1")
	}

	if err := repo.Set(settingKeyNetwork, `{"ipv6_enabled":false,"http2_enabled":true,"http3_enabled":true,"http3_bind":":8443","default_alpn":" H2 , h2 , HTTP/1.1 , acme-tls/1 ","default_network":"tcp"}`); err != nil {
		t.Fatalf("seed mixed-case network config: %v", err)
	}
	got = loadNetworkConfig(repo)
	if got.DefaultALPN != "h2,http/1.1,acme-tls/1" {
		t.Fatalf("normalized explicit default_alpn = %q, want %q", got.DefaultALPN, "h2,http/1.1,acme-tls/1")
	}
}

func TestUpdateNetworkConfigPreservesExplicitDefaultNetwork(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyNetwork, `{"ipv6_enabled":false,"http2_enabled":true,"http3_enabled":true,"http3_bind":":8443","default_alpn":"h3,h2,http/1.1","default_network":"tcp"}`); err != nil {
		t.Fatalf("seed network config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, UpdateNetworkConfig(repo, func() error { return nil }), "POST", "/api/v1/network-config", []byte(`{"default_network":" TCP6 "}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get(settingKeyNetwork)
	if err != nil {
		t.Fatalf("load network config: %v", err)
	}
	var got NetworkConfig
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode network config: %v", err)
	}
	if got.DefaultNetwork != "tcp6" {
		t.Fatalf("default_network = %q, want %q", got.DefaultNetwork, "tcp6")
	}
}

func TestUpdateNetworkConfigPreservesExplicitDefaultALPNWhenUpdatingDefaultNetwork(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyNetwork, `{"ipv6_enabled":false,"http2_enabled":true,"http3_enabled":false,"http3_bind":":8443","default_alpn":"h3,http/1.1","default_network":"tcp"}`); err != nil {
		t.Fatalf("seed network config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, UpdateNetworkConfig(repo, func() error { return nil }), "POST", "/api/v1/network-config", []byte(`{"default_network":"tcp6"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get(settingKeyNetwork)
	if err != nil {
		t.Fatalf("load network config: %v", err)
	}
	var got NetworkConfig
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode network config: %v", err)
	}
	if got.DefaultNetwork != "tcp6" {
		t.Fatalf("default_network = %q, want %q", got.DefaultNetwork, "tcp6")
	}
	if got.DefaultALPN != "h3,http/1.1" {
		t.Fatalf("explicit default_alpn changed: got %q, want %q", got.DefaultALPN, "h3,http/1.1")
	}
}

func TestUpdateNetworkConfigNormalizesExplicitDefaultALPN(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, UpdateNetworkConfig(repo, func() error { return nil }), "POST", "/api/v1/network-config", []byte(`{"default_alpn":" H2 , h2 , HTTP/1.1 , acme-tls/1 "}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get(settingKeyNetwork)
	if err != nil {
		t.Fatalf("load network config: %v", err)
	}
	var got NetworkConfig
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode network config: %v", err)
	}
	if got.DefaultALPN != "h2,http/1.1,acme-tls/1" {
		t.Fatalf("default_alpn = %q, want h2,http/1.1,acme-tls/1", got.DefaultALPN)
	}
}

func TestUpdateNetworkConfigValidatesHTTP3Bind(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		wantBind  string
		wantError string
	}{
		{name: "port only", payload: `{"http3_bind":" :8443 "}`, wantBind: ":8443"},
		{name: "host port", payload: `{"http3_bind":"127.0.0.1:8443"}`, wantBind: "127.0.0.1:8443"},
		{name: "bad address", payload: `{"http3_bind":"127.0.0.1"}`, wantError: "invalid http3_bind"},
		{name: "zero port", payload: `{"http3_bind":":0"}`, wantError: "invalid http3_bind"},
		{name: "bad port", payload: `{"http3_bind":":abc"}`, wantError: "invalid http3_bind"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSystemSettingsRepoForTest(t)
			reloadCalled := false
			ctx := invokeSystemConfigHandler(t, UpdateNetworkConfig(repo, func() error {
				reloadCalled = true
				return nil
			}), "POST", "/api/v1/network-config", []byte(tt.payload))
			if tt.wantError != "" {
				if ctx.Response.StatusCode() != 400 {
					t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
				}
				if reloadCalled {
					t.Fatal("reload should not be called")
				}
				var resp map[string]string
				if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if resp["error"] != tt.wantError {
					t.Fatalf("error = %q, want %q", resp["error"], tt.wantError)
				}
				return
			}
			if ctx.Response.StatusCode() != 200 {
				t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			if !reloadCalled {
				t.Fatal("reload should be called")
			}
			val, err := repo.Get(settingKeyNetwork)
			if err != nil {
				t.Fatalf("load network config: %v", err)
			}
			var got NetworkConfig
			if err := json.Unmarshal([]byte(val), &got); err != nil {
				t.Fatalf("decode network config: %v", err)
			}
			if got.HTTP3Bind != tt.wantBind {
				t.Fatalf("http3_bind = %q, want %q", got.HTTP3Bind, tt.wantBind)
			}
		})
	}
}

func TestUpdateNetworkConfigRejectsInvalidDefaultNetwork(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyNetwork, `{"ipv6_enabled":false,"http2_enabled":true,"http3_enabled":true,"http3_bind":":8443","default_alpn":"h3,h2,http/1.1","default_network":"tcp4"}`); err != nil {
		t.Fatalf("seed network config: %v", err)
	}

	reloadCalled := false
	ctx := invokeSystemConfigHandler(t, UpdateNetworkConfig(repo, func() error {
		reloadCalled = true
		return nil
	}), "POST", "/api/v1/network-config", []byte(`{"default_network":"udp"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload should not be called")
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid default_network" {
		t.Fatalf("error = %q, want invalid default_network", resp["error"])
	}

	val, err := repo.Get(settingKeyNetwork)
	if err != nil {
		t.Fatalf("load network config: %v", err)
	}
	var got NetworkConfig
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode network config: %v", err)
	}
	if got.DefaultNetwork != "tcp4" {
		t.Fatalf("default_network changed after rejected update: %q", got.DefaultNetwork)
	}
}

func TestUpdateNetworkConfigDerivesDefaultALPNWhenOmitted(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyNetwork, `{"ipv6_enabled":false,"http2_enabled":true,"http3_enabled":true,"http3_bind":":8443","default_alpn":"h3,h2,http/1.1","default_network":"tcp"}`); err != nil {
		t.Fatalf("seed network config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, UpdateNetworkConfig(repo, func() error { return nil }), "POST", "/api/v1/network-config", []byte(`{"http2_enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get(settingKeyNetwork)
	if err != nil {
		t.Fatalf("load network config: %v", err)
	}
	var got NetworkConfig
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode network config: %v", err)
	}
	if got.DefaultALPN != "h3,http/1.1" {
		t.Fatalf("derived default_alpn = %q, want %q", got.DefaultALPN, "h3,http/1.1")
	}
}

func TestUpdateTLSDefaultConfigPreservesOmittedSelfSignedOnIP(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyTLSDefault, `{"min_version":"TLS12","max_version":"TLS13","cipher_suites":"","default_alpn":"h3,h2,http/1.1","curve_preferences":"X25519,CurveP256","prefer_server_cipher_suites":true,"session_tickets_enabled":false,"self_signed_on_ip":false}`); err != nil {
		t.Fatalf("seed TLS config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(`{"prefer_server_cipher_suites":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get(settingKeyTLSDefault)
	if err != nil {
		t.Fatalf("load TLS config: %v", err)
	}
	var got TLSDefaultConfig
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode TLS config: %v", err)
	}
	if got.PreferServerCipherSuites {
		t.Fatalf("explicit prefer_server_cipher_suites=false was not saved: %#v", got)
	}
	if got.SelfSignedOnIP {
		t.Fatalf("omitted self_signed_on_ip should preserve false: %#v", got)
	}
	if got.SessionTicketsEnabled {
		t.Fatalf("omitted session_tickets_enabled should preserve false: %#v", got)
	}
}

func TestUpdateTLSDefaultConfigPreservesMissingDefaultALPNInheritance(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyTLSDefault, `{"min_version":"TLS12","max_version":"TLS13","cipher_suites":"","curve_preferences":"X25519,CurveP256","prefer_server_cipher_suites":true,"session_tickets_enabled":false,"self_signed_on_ip":false}`); err != nil {
		t.Fatalf("seed TLS config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(`{"prefer_server_cipher_suites":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp TLSDefaultConfig
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.HasExplicitDefaultALPN {
		t.Fatalf("response should preserve inherited default_alpn state: %#v", resp)
	}

	val, err := repo.Get(settingKeyTLSDefault)
	if err != nil {
		t.Fatalf("load TLS config: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(val), &raw); err != nil {
		t.Fatalf("decode TLS config: %v", err)
	}
	if _, ok := raw["default_alpn"]; ok {
		t.Fatalf("omitted default_alpn should remain absent, saved JSON: %s", val)
	}
	defaults := snapshotpkg.LoadTLSDefaults(val)
	if defaults.HasExplicitDefaultALPN {
		t.Fatalf("missing default_alpn should not become explicit: %#v", defaults)
	}
}

func TestUpdateTLSDefaultConfigCanClearExplicitDefaultALPN(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyTLSDefault, `{"min_version":"TLS12","max_version":"TLS13","cipher_suites":"","default_alpn":"h2,http/1.1","curve_preferences":"X25519,CurveP256","prefer_server_cipher_suites":true,"session_tickets_enabled":true,"self_signed_on_ip":false}`); err != nil {
		t.Fatalf("seed TLS config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(`{"default_alpn":""}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp TLSDefaultConfig
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.HasExplicitDefaultALPN {
		t.Fatalf("response should clear explicit default_alpn state: %#v", resp)
	}
	if resp.DefaultALPN != snapshotpkg.DefaultALPNForProtocolSwitches(true, true) {
		t.Fatalf("cleared default_alpn display value = %q", resp.DefaultALPN)
	}

	val, err := repo.Get(settingKeyTLSDefault)
	if err != nil {
		t.Fatalf("load TLS config: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(val), &raw); err != nil {
		t.Fatalf("decode TLS config: %v", err)
	}
	if _, ok := raw["default_alpn"]; ok {
		t.Fatalf("cleared default_alpn should be omitted, saved JSON: %s", val)
	}
	defaults := snapshotpkg.LoadTLSDefaults(val)
	if defaults.HasExplicitDefaultALPN {
		t.Fatalf("cleared default_alpn should not be explicit: %#v", defaults)
	}
}

func TestUpdateTLSDefaultConfigSavesExplicitDefaultALPN(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(`{"default_alpn":" H2 , h2 , HTTP/1.1 , acme-tls/1 "}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp TLSDefaultConfig
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.HasExplicitDefaultALPN {
		t.Fatalf("response should mark explicit default_alpn: %#v", resp)
	}

	val, err := repo.Get(settingKeyTLSDefault)
	if err != nil {
		t.Fatalf("load TLS config: %v", err)
	}
	var got TLSDefaultConfig
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode TLS config: %v", err)
	}
	if got.DefaultALPN != "h2,http/1.1,acme-tls/1" {
		t.Fatalf("default_alpn = %q, want %q", got.DefaultALPN, "h2,http/1.1,acme-tls/1")
	}
	defaults := snapshotpkg.LoadTLSDefaults(val)
	if !defaults.HasExplicitDefaultALPN {
		t.Fatalf("saved default_alpn should be explicit: %#v", defaults)
	}
}

func TestUpdateTLSDefaultConfigNormalizesSupportedRuntimeVersions(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(`{"min_version":"TLS 1.0","max_version":"0x0304"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var got TLSDefaultConfig
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode TLS config response: %v", err)
	}
	if got.MinVersion != "TLS10" || got.MaxVersion != "TLS13" {
		t.Fatalf("normalized TLS bounds = %q,%q; want TLS10,TLS13", got.MinVersion, got.MaxVersion)
	}
}

func TestUpdateTLSDefaultConfigValidatesConfigurableCipherSuites(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCipher string
		wantError  string
	}{
		{
			name:       "tls12 name",
			body:       `{"cipher_suites":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}`,
			wantStatus: 200,
			wantCipher: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
		{
			name:       "tls12 alias",
			body:       `{"cipher_suites":"0xc02f,ECDHE_RSA_WITH_AES_256_GCM_SHA384"}`,
			wantStatus: 200,
			wantCipher: "0xc02f,ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		},
		{
			name:       "tls13 suite",
			body:       `{"cipher_suites":"TLS_AES_128_GCM_SHA256"}`,
			wantStatus: 400,
			wantError:  "unsupported cipher_suites: TLS_AES_128_GCM_SHA256",
		},
		{
			name:       "unknown suite",
			body:       `{"cipher_suites":"UNKNOWN_SUITE_EXAMPLE"}`,
			wantStatus: 400,
			wantError:  "unsupported cipher_suites: UNKNOWN_SUITE_EXAMPLE",
		},
		{
			name:       "empty tokens",
			body:       `{"cipher_suites":","}`,
			wantStatus: 400,
			wantError:  "unsupported cipher_suites: ,",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSystemSettingsRepoForTest(t)
			ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(tt.body))
			if ctx.Response.StatusCode() != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", ctx.Response.StatusCode(), tt.wantStatus, bytes.TrimSpace(ctx.Response.Body()))
			}
			if tt.wantStatus == 200 {
				var got TLSDefaultConfig
				if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if got.CipherSuites != tt.wantCipher {
					t.Fatalf("cipher_suites = %q, want %q", got.CipherSuites, tt.wantCipher)
				}
				return
			}
			var resp map[string]string
			if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp["error"] != tt.wantError {
				t.Fatalf("error = %q, want %q", resp["error"], tt.wantError)
			}
		})
	}
}

func TestUpdateTLSDefaultConfigRejectsUnsupportedSSLRuntimeVersions(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "ssl3 min", body: `{"min_version":"SSL3"}`},
		{name: "ssl2 min", body: `{"min_version":"SSL2"}`},
		{name: "ssl1 min", body: `{"min_version":"SSL1"}`},
		{name: "ssl3 max token", body: `{"max_version":"SSL3"}`},
		{name: "ssl3 max", body: `{"max_version":"0x0300"}`},
		{name: "ssl2 max", body: `{"max_version":"SSL2"}`},
		{name: "ssl1 max", body: `{"max_version":"SSL1"}`},
		{name: "unknown max", body: `{"max_version":"TLS14"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSystemSettingsRepoForTest(t)
			ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(tt.body))
			if ctx.Response.StatusCode() != 400 {
				t.Fatalf("status = %d, want 400, body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
		})
	}
}

func TestUpdateTLSDefaultConfigRejectsInvalidRuntimeVersionRange(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, UpdateTLSDefaultConfig(repo, func() error { return nil }), "POST", "/api/v1/tls-config", []byte(`{"min_version":"TLS13","max_version":"TLS12"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("status = %d, want 400, body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "invalid tls version range" {
		t.Fatalf("error = %q, want invalid tls version range", resp["error"])
	}
}

func TestLoadTLSDefaultConfigDefaultsMissingSessionTicketsToEnabled(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyTLSDefault, `{"min_version":"TLS12","max_version":"TLS13","cipher_suites":"","default_alpn":"h2,http/1.1","curve_preferences":"X25519,CurveP256","prefer_server_cipher_suites":true,"self_signed_on_ip":false}`); err != nil {
		t.Fatalf("seed TLS config: %v", err)
	}

	got := loadTLSDefaultConfig(repo)
	if !got.SessionTicketsEnabled {
		t.Fatalf("missing session_tickets_enabled should default to true: %#v", got)
	}
}

func TestUpdateHTTP2ConfigPreservesOmittedFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyHTTP2, `{"read_timeout_seconds":75,"disable_keepalive":false,"permit_prohibited_cipher_suites":true,"max_concurrent_streams":200,"max_read_frame_size":65536,"idle_timeout_seconds":15,"max_upload_buffer_per_connection":1048576,"max_upload_buffer_per_stream":262144,"max_header_bytes":262144,"max_header_fields":80,"max_handlers":12,"max_queued_control_frames":4096}`); err != nil {
		t.Fatalf("seed http2 config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, UpdateHTTP2Config(repo, func() error { return nil }), "POST", "/api/v1/http2-config", []byte(`{"max_concurrent_streams":250,"disable_keepalive":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get(settingKeyHTTP2)
	if err != nil {
		t.Fatalf("load http2 config: %v", err)
	}
	var got snapshotpkg.HTTP2Config
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode http2 config: %v", err)
	}
	if got.MaxConcurrentStreams != 250 {
		t.Fatalf("max_concurrent_streams = %d, want 250", got.MaxConcurrentStreams)
	}
	if !got.DisableKeepalive {
		t.Fatal("disable_keepalive should be updated to true")
	}
	if got.ReadTimeoutSeconds != 75 || got.IdleTimeoutSeconds != 15 {
		t.Fatalf("omitted timeout fields should be preserved, got %#v", got)
	}
	if got.MaxUploadBufferPerConnection != 1048576 || got.MaxUploadBufferPerStream != 262144 {
		t.Fatalf("omitted buffer fields should be preserved, got %#v", got)
	}
	if got.MaxHeaderBytes != 262144 || got.MaxHeaderFields != 80 {
		t.Fatalf("omitted header limit fields should be preserved, got %#v", got)
	}
	if got.MaxHandlers != 12 {
		t.Fatalf("omitted max_handlers should be preserved, got %#v", got)
	}
	if got.MaxQueuedControlFrames != 4096 {
		t.Fatalf("omitted max_queued_control_frames should be preserved, got %#v", got)
	}
}

func TestUpdateHTTP2ConfigRejectsInvalidFrameSize(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, UpdateHTTP2Config(repo, func() error { return nil }), "POST", "/api/v1/http2-config", []byte(`{"max_read_frame_size":1024}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestUpdateHTTP2ConfigAcceptsMaxHandlers(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, UpdateHTTP2Config(repo, func() error { return nil }), "POST", "/api/v1/http2-config", []byte(`{"max_handlers":18}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get(settingKeyHTTP2)
	if err != nil {
		t.Fatalf("load http2 config: %v", err)
	}
	var got snapshotpkg.HTTP2Config
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode http2 config: %v", err)
	}
	if got.MaxHandlers != 18 {
		t.Fatalf("max_handlers = %d, want 18", got.MaxHandlers)
	}
}

func TestUpdateHTTP2ConfigAcceptsProtocolMaxReadFrameSize(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, UpdateHTTP2Config(repo, func() error { return nil }), "POST", "/api/v1/http2-config", []byte(`{"max_read_frame_size":16777215}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get(settingKeyHTTP2)
	if err != nil {
		t.Fatalf("load http2 config: %v", err)
	}
	var got snapshotpkg.HTTP2Config
	if err := json.Unmarshal([]byte(val), &got); err != nil {
		t.Fatalf("decode http2 config: %v", err)
	}
	if got.MaxReadFrameSize != snapshotpkg.MaxHTTP2ReadFrameSize {
		t.Fatalf("max_read_frame_size = %d, want %d", got.MaxReadFrameSize, snapshotpkg.MaxHTTP2ReadFrameSize)
	}
}

func TestUpdateHTTP2ConfigRejectsNegativeMaxHandlers(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, UpdateHTTP2Config(repo, func() error { return nil }), "POST", "/api/v1/http2-config", []byte(`{"max_handlers":-1}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestUpdateHTTP2ConfigRejectsInvalidHeaderLimits(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	for _, body := range [][]byte{
		[]byte(`{"max_header_bytes":0}`),
		[]byte(`{"max_header_fields":0}`),
	} {
		ctx := invokeSystemConfigHandler(t, UpdateHTTP2Config(repo, func() error { return nil }), "POST", "/api/v1/http2-config", body)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	}
}

func TestUpdateHTTP2ConfigRejectsInvalidQueuedControlFrameLimit(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	for _, body := range [][]byte{
		[]byte(`{"max_queued_control_frames":0}`),
		[]byte(`{"max_queued_control_frames":-1}`),
	} {
		ctx := invokeSystemConfigHandler(t, UpdateHTTP2Config(repo, func() error { return nil }), "POST", "/api/v1/http2-config", body)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	}
}

func TestUpdateHTTP2ConfigRejectsUnsafeLargeLimits(t *testing.T) {
	tests := []string{
		`{"max_concurrent_streams":1001}`,
		`{"max_read_frame_size":16777216}`,
		`{"max_upload_buffer_per_connection":1048577}`,
		`{"max_upload_buffer_per_stream":1048577}`,
		`{"max_header_bytes":1048577}`,
		`{"max_header_fields":101}`,
		`{"max_handlers":1001}`,
		`{"max_queued_control_frames":10001}`,
	}

	for _, body := range tests {
		t.Run(body, func(t *testing.T) {
			repo := newSystemSettingsRepoForTest(t)
			ctx := invokeSystemConfigHandler(t, UpdateHTTP2Config(repo, func() error { return nil }), "POST", "/api/v1/http2-config", []byte(body))
			if ctx.Response.StatusCode() != 400 {
				t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
		})
	}
}

func TestUpdateLogConfigPreservesOmittedOutputFields(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	logPath := filepath.Join(t.TempDir(), "waf.log")
	defer func() {
		_ = logger.Close()
		logger.Configure(logger.Config{Level: "INFO"})
	}()
	if err := repo.Set(settingKeyLog, `{"level":"INFO","file_path":"`+filepath.ToSlash(logPath)+`","also_stdout":true}`); err != nil {
		t.Fatalf("seed log config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, UpdateLogConfig(repo), "POST", "/api/v1/log-config", []byte(`{"level":"WARN"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get(settingKeyLog)
	if err != nil {
		t.Fatalf("load log config: %v", err)
	}
	var stored LogConfig
	if err := json.Unmarshal([]byte(val), &stored); err != nil {
		t.Fatalf("decode stored log config: %v", err)
	}
	if stored.Level != "WARN" {
		t.Fatalf("explicit level update was not saved: %#v", stored)
	}
	if stored.FilePath != filepath.ToSlash(logPath) || !stored.AlsoStdout {
		t.Fatalf("omitted log output fields should be preserved: %#v", stored)
	}

	var resp LogConfig
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response log config: %v", err)
	}
	if resp.Level != "WARN" || resp.FilePath != filepath.ToSlash(logPath) || !resp.AlsoStdout {
		t.Fatalf("response should include full log config, got %#v", resp)
	}
}

func TestUpdateRedisConfigPreservesStoredPasswordWhenOmitted(t *testing.T) {
	redisSrv := startTestRedisServer(t)
	defer redisSrv.Close()

	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(store.SettingKeyRedisConfig, fmt.Sprintf(`{"enabled":true,"addr":"%s","password":"secret-pass","db":2}`, redisSrv.Addr())); err != nil {
		t.Fatalf("seed redis config: %v", err)
	}

	payload := []byte(fmt.Sprintf(`{"enabled":true,"addr":%q,"db":7}`, redisSrv.Addr()))
	ctx := invokeSystemConfigHandler(t, UpdateRedisConfig(repo, func() error { return nil }), "POST", "/api/v1/redis-config", payload)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	val, err := repo.Get(store.SettingKeyRedisConfig)
	if err != nil {
		t.Fatalf("load redis config: %v", err)
	}

	var stored RedisConfig
	if err := json.Unmarshal([]byte(val), &stored); err != nil {
		t.Fatalf("decode stored redis config: %v", err)
	}
	if stored.Password != "secret-pass" {
		t.Fatalf("omitted password should be preserved, got %#v", stored)
	}
	if stored.Addr != redisSrv.Addr() || stored.DB != 7 {
		t.Fatalf("explicit redis fields were not saved: %#v", stored)
	}

	var resp RedisConfigResponse
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode redis response: %v", err)
	}
	if !resp.PasswordSet {
		t.Fatalf("response should keep password_set=true, got %#v", resp)
	}
	if resp.RestartRequired {
		t.Fatalf("response restart_required = %v, want false", resp.RestartRequired)
	}
}

func TestListCipherSuitesIncludesCanonicalMetadata(t *testing.T) {
	ctx := invokeSystemConfigHandler(t, ListCipherSuites(), "GET", "/api/v1/tls-cipher-suites", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		Secure   []cipherSuiteInfo `json:"secure"`
		Insecure []cipherSuiteInfo `json:"insecure"`
		Curves   []curveInfo       `json:"curves"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode cipher suites response: %v", err)
	}
	if len(resp.Secure) == 0 {
		t.Fatal("secure cipher suites should not be empty")
	}
	if len(resp.Curves) == 0 {
		t.Fatal("curves should not be empty")
	}

	var secureSuite *cipherSuiteInfo
	for i := range resp.Secure {
		if resp.Secure[i].Name == "TLS_AES_128_GCM_SHA256" {
			secureSuite = &resp.Secure[i]
			break
		}
	}
	if secureSuite == nil {
		t.Fatalf("secure cipher suites missing TLS_AES_128_GCM_SHA256: %#v", resp.Secure)
	}
	if secureSuite.HexID != "0x1301" {
		t.Fatalf("TLS_AES_128_GCM_SHA256 hex_id = %q, want %q", secureSuite.HexID, "0x1301")
	}
	if secureSuite.Insecure {
		t.Fatalf("TLS_AES_128_GCM_SHA256 should not be marked insecure: %#v", secureSuite)
	}
	if secureSuite.Configurable {
		t.Fatalf("TLS_AES_128_GCM_SHA256 should not be marked configurable for tls.Config.CipherSuites: %#v", secureSuite)
	}

	hasTLS13 := false
	for _, version := range secureSuite.TLSVersions {
		if version == "TLS13" {
			hasTLS13 = true
			break
		}
	}
	if !hasTLS13 {
		t.Fatalf("TLS_AES_128_GCM_SHA256 tls_versions = %#v, want include TLS13", secureSuite.TLSVersions)
	}

	var configurableSuite *cipherSuiteInfo
	for i := range resp.Secure {
		if resp.Secure[i].Name == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
			configurableSuite = &resp.Secure[i]
			break
		}
	}
	if configurableSuite == nil {
		t.Fatalf("secure cipher suites missing TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: %#v", resp.Secure)
	}
	if !configurableSuite.Configurable {
		t.Fatalf("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should be configurable for tls.Config.CipherSuites: %#v", configurableSuite)
	}

	hasX25519 := false
	for _, curve := range resp.Curves {
		if curve.Name == "X25519" {
			hasX25519 = true
			break
		}
	}
	if !hasX25519 {
		t.Fatalf("curves missing X25519: %#v", resp.Curves)
	}
}

func TestGetRuntimeConfigIncludesBrotliRuntimeState(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(store.SettingKeyACMEConfig, `{"enabled":true,"email":"admin@example.com","directory_url":"","auto_renew":true,"renew_before_days":30,"caa_check_enabled":true,"caa_allowed_issuers":"letsencrypt.org, pki.goog","caa_dns_server":"127.0.0.1:5353"}`); err != nil {
		t.Fatalf("seed acme config: %v", err)
	}
	holder := &snapshotpkg.Holder{}
	holder.Store(&snapshotpkg.Snapshot{
		Sites: map[string]snapshotpkg.SiteRuntime{
			snapshotpkg.SiteMapKey(":443", "example.com"): {
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{{OCSPStaple: []byte("ocsp")}},
				},
			},
		},
		NetworkDefaults: snapshotpkg.NetworkDefaults{
			HTTP2Enabled:   false,
			HTTP3Enabled:   true,
			HTTP3Bind:      ":9443",
			DefaultALPN:    "h3,http/1.1",
			DefaultNetwork: "tcp",
		},
		TLSDefaults: snapshotpkg.TLSDefaults{
			MinVersion:            "TLS12",
			MaxVersion:            "TLS13",
			SessionTicketsEnabled: false,
		},
		BrotliEnabled:                  true,
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: false,
		ResponseCompressionMinBytes:    2048,
		HSTSEnabled:                    true,
		XSSProtectionEnabled:           false,
		HPKPEnabled:                    true,
		HPKPValue:                      `pin-sha256="abc"; max-age=86400`,
		HPKPReportOnlyEnabled:          true,
		HPKPReportOnlyValue:            `pin-sha256="abc"; max-age=86400; report-uri="https://report.example/hpkp"`,
	})

	handler := GetRuntimeConfig(func() (core.Config, bool) {
		return core.Config{
			DBDriver:       "sqlite",
			DBDSN:          "file:test.db",
			LogDBDSN:       "file:test-log.db",
			DataDir:        "data",
			RedisAddr:      "127.0.0.1:6379",
			RedisDB:        5,
			AdminBind:      ":9443",
			AdminStaticDir: "embedded",
			Bot: core.BotConfig{
				GeoIPDBPath: "GeoLite2-City.mmdb",
			},
			CVE: core.CVEConfig{
				Enabled:      true,
				FeedEnabled:  true,
				FeedInterval: "12h",
			},
			Drop: core.DropConfig{
				Enabled: true,
			},
		}, true
	}, holder, repo)

	ctx := invokeSystemConfigHandler(t, handler, "GET", "/api/v1/runtime-config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp RuntimeConfigResponse
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode runtime config response: %v", err)
	}
	if !resp.BrotliEnabled {
		t.Fatalf("runtime config brotli_enabled = %v, want true", resp.BrotliEnabled)
	}
	if !resp.ResponseCompressionEnabled || resp.ResponseCompressionGzipEnabled || resp.ResponseCompressionMinBytes != 2048 {
		t.Fatalf("runtime compression fields mismatch: %#v", resp)
	}
	if !resp.RedisEnabled || resp.RedisAddr != "127.0.0.1:6379" || resp.RedisDB != 5 {
		t.Fatalf("runtime redis fields mismatch: %#v", resp)
	}
	if !resp.HSTSEnabled || resp.XSSProtectionEnabled {
		t.Fatalf("runtime security headers mismatch: %#v", resp)
	}
	if !resp.HPKPEnabled || resp.HPKPValue != `pin-sha256="abc"; max-age=86400` || !resp.HPKPReportOnlyEnabled || resp.HPKPReportOnlyValue != `pin-sha256="abc"; max-age=86400; report-uri="https://report.example/hpkp"` {
		t.Fatalf("runtime HPKP fields mismatch: %#v", resp)
	}
	if resp.RestartRequired {
		t.Fatalf("runtime config restart_required = %v, want false", resp.RestartRequired)
	}
	capabilities := make(map[string]TLSCapabilityStatus, len(resp.TLSCapabilities))
	for _, item := range resp.TLSCapabilities {
		capabilities[item.Key] = item
	}
	for _, key := range []string{
		"http2",
		"http3",
		"tls_1_3",
		"tls_1_1",
		"tls_1_0",
		"ssl_1",
		"ssl_2",
		"ssl_3",
		"alpn",
		"npn",
		"session_ticket",
		"session_id_caching",
		"starttls",
		"ocsp_stapling",
		"caa",
		"hsts",
		"xss_protection",
		"hpkp",
		"hpkp_report_only",
		"gzip_compression",
		"brotli_compression",
	} {
		if _, ok := capabilities[key]; !ok {
			t.Fatalf("runtime TLS capabilities missing key %q: %#v", key, resp.TLSCapabilities)
		}
	}
	if got := capabilities["tls_1_3"]; got.Status != "supported" || got.Missing {
		t.Fatalf("tls_1_3 capability = %#v, want supported and not missing", got)
	}
	if got := capabilities["http2"]; got.Status != "disabled" || got.Missing {
		t.Fatalf("http2 capability = %#v, want disabled and not missing", got)
	}
	if got := capabilities["http3"]; got.Status != "enabled" || got.Missing || !strings.Contains(got.Detail, ":9443") {
		t.Fatalf("http3 capability = %#v, want enabled detail with bind", got)
	}
	if got := capabilities["alpn"]; got.Status != "supported" || got.Missing || !strings.Contains(got.Detail, "h3,http/1.1") {
		t.Fatalf("alpn capability = %#v, want supported detail with default alpn", got)
	}
	for _, key := range []string{"tls_1_0", "tls_1_1"} {
		if got := capabilities[key]; got.Status != "disabled" || got.Missing || !strings.Contains(got.Detail, "TLS12 到 TLS13") {
			t.Fatalf("%s capability = %#v, want disabled in TLS12-TLS13 range", key, got)
		}
	}
	var protocolKeys []string
	for _, item := range resp.TLSCapabilities {
		if item.Key == "ssl_1" || item.Key == "ssl_2" || item.Key == "ssl_3" {
			protocolKeys = append(protocolKeys, item.Key)
		}
	}
	if !slices.Equal(protocolKeys, []string{"ssl_1", "ssl_2", "ssl_3"}) {
		t.Fatalf("runtime SSL capability order = %#v, want [ssl_1 ssl_2 ssl_3]", protocolKeys)
	}
	for _, key := range []string{"ssl_1", "ssl_2", "ssl_3"} {
		if got := capabilities[key]; got.Status != "not_supported" || !got.Missing {
			t.Fatalf("%s capability = %#v, want not_supported and missing", key, got)
		}
	}
	if got := capabilities["npn"]; got.Status != "not_supported" || !got.Missing {
		t.Fatalf("npn capability = %#v, want not_supported and missing", got)
	}
	if got := capabilities["session_ticket"]; got.Status != "disabled" || got.Missing {
		t.Fatalf("session_ticket capability = %#v, want disabled and not missing", got)
	}
	if got := capabilities["session_id_caching"]; got.Status != "not_supported" || !got.Missing {
		t.Fatalf("session_id_caching capability = %#v, want not_supported and missing", got)
	}
	if got := capabilities["starttls"]; got.Status != "not_supported" || !got.Missing {
		t.Fatalf("starttls capability = %#v, want not_supported and missing", got)
	}
	if got := capabilities["ocsp_stapling"]; got.Status != "enabled" || got.Missing {
		t.Fatalf("ocsp_stapling capability = %#v, want enabled and not missing", got)
	}
	if got := capabilities["caa"]; got.Status != "enabled" || got.Missing || !strings.Contains(got.Detail, "letsencrypt.org, pki.goog") || !strings.Contains(got.Detail, "127.0.0.1:5353") {
		t.Fatalf("caa capability = %#v, want enabled detail with issuer and dns server", got)
	}
	if got := capabilities["hsts"]; got.Status != "enabled" || got.Missing {
		t.Fatalf("hsts capability = %#v, want enabled and not missing", got)
	}
	if got := capabilities["xss_protection"]; got.Status != "disabled" || got.Missing {
		t.Fatalf("xss_protection capability = %#v, want disabled and not missing", got)
	}
	if got := capabilities["gzip_compression"]; got.Status != "disabled" || got.Missing {
		t.Fatalf("gzip_compression capability = %#v, want disabled and not missing", got)
	}
	if got := capabilities["brotli_compression"]; got.Status != "enabled" || got.Missing {
		t.Fatalf("brotli_compression capability = %#v, want enabled and not missing", got)
	}
}
