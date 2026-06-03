package system

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/pkg/logger"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

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

func TestUpdateTLSDefaultConfigPreservesOmittedSelfSignedOnIP(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyTLSDefault, `{"min_version":"TLS12","max_version":"TLS13","cipher_suites":"","default_alpn":"h3,h2,http/1.1","curve_preferences":"X25519,CurveP256","prefer_server_cipher_suites":true,"self_signed_on_ip":false}`); err != nil {
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
