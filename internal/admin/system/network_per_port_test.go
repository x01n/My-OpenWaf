package system

import (
	"bytes"
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/snapshot"
)

// TestNetworkConfigDefaultsDisableHTTP3PerPort 锁定默认值：
// http3_per_port_enabled 默认必须是 false，即「所有 h3 集中到 http3_bind」的现状。
func TestNetworkConfigDefaultsDisableHTTP3PerPort(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, GetNetworkConfig(repo), "GET", "/api/v1/network-config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var cfg NetworkConfig
	if err := json.Unmarshal(ctx.Response.Body(), &cfg); err != nil {
		t.Fatalf("decode network config: %v", err)
	}
	if cfg.HTTP3PerPortEnabled {
		t.Fatalf("http3_per_port_enabled = true by default, want false: %#v", cfg)
	}
	if cfg.HTTP3Bind != ":443" {
		t.Fatalf("http3_bind = %q, want :443 (legacy default must stay)", cfg.HTTP3Bind)
	}
}

// TestUpdateNetworkConfigPersistsHTTP3PerPortSwitch 覆盖读写往返：
// 显式 true 落库、GET 回显 true；只提交别的字段时该开关必须被保留。
func TestUpdateNetworkConfigPersistsHTTP3PerPortSwitch(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	reloadCalls := 0
	handler := UpdateNetworkConfig(repo, func() error {
		reloadCalls++
		return nil
	})

	ctx := invokeSystemConfigHandler(t, handler, "POST", "/api/v1/network-config", []byte(`{"http3_per_port_enabled":true}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalls != 1 {
		t.Fatalf("reload calls = %d, want 1", reloadCalls)
	}
	val, err := repo.Get(settingKeyNetwork)
	if err != nil {
		t.Fatalf("load network config: %v", err)
	}
	var stored NetworkConfig
	if err := json.Unmarshal([]byte(val), &stored); err != nil {
		t.Fatalf("decode stored config: %v", err)
	}
	if !stored.HTTP3PerPortEnabled {
		t.Fatalf("stored http3_per_port_enabled = false, want true: %s", val)
	}

	// 省略该字段的后续更新必须保留 true（不能因为 zero value 被写回 false）。
	ctx = invokeSystemConfigHandler(t, handler, "POST", "/api/v1/network-config", []byte(`{"http3_bind":":8443"}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	val, err = repo.Get(settingKeyNetwork)
	if err != nil {
		t.Fatalf("reload network config: %v", err)
	}
	if err := json.Unmarshal([]byte(val), &stored); err != nil {
		t.Fatalf("decode reloaded config: %v", err)
	}
	if !stored.HTTP3PerPortEnabled {
		t.Fatalf("omitted http3_per_port_enabled should be preserved, got false: %s", val)
	}
	if stored.HTTP3Bind != ":8443" {
		t.Fatalf("http3_bind = %q, want :8443", stored.HTTP3Bind)
	}

	// 显式 false 必须能关回去。
	ctx = invokeSystemConfigHandler(t, handler, "POST", "/api/v1/network-config", []byte(`{"http3_per_port_enabled":false}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	val, err = repo.Get(settingKeyNetwork)
	if err != nil {
		t.Fatalf("reload network config: %v", err)
	}
	if err := json.Unmarshal([]byte(val), &stored); err != nil {
		t.Fatalf("decode disabled config: %v", err)
	}
	if stored.HTTP3PerPortEnabled {
		t.Fatalf("explicit false was not saved: %s", val)
	}
}

// TestLoadNetworkConfigKeepsStoredHTTP3PerPortSwitch 覆盖存量值读取。
func TestLoadNetworkConfigKeepsStoredHTTP3PerPortSwitch(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(settingKeyNetwork, `{"http2_enabled":true,"http3_enabled":true,"http3_bind":":8443","http3_per_port_enabled":true,"default_alpn":"h2,h3,http/1.1","default_network":"tcp"}`); err != nil {
		t.Fatalf("seed network config: %v", err)
	}
	got := loadNetworkConfig(repo)
	if !got.HTTP3PerPortEnabled {
		t.Fatalf("stored http3_per_port_enabled=true was not loaded: %#v", got)
	}
	if got.HTTP3Bind != ":8443" {
		t.Fatalf("http3_bind = %q, want :8443", got.HTTP3Bind)
	}
}

// TestRuntimeHTTP3BindForSiteFollowsPerPortSwitch 锁定自检侧与运行侧一致：
// 开启后按 TCP 端口推导，关闭时仍取全局 http3_bind。
func TestRuntimeHTTP3BindForSiteFollowsPerPortSwitch(t *testing.T) {
	base := snapshot.DefaultNetworkDefaults()
	base.HTTP3Bind = ":8443"

	legacy := runtimeHTTP3RouteConflictTestRuntime(1, "127.0.0.1:10443", "legacy.example.test", base, snapshot.DefaultTLSDefaults())
	if got := runtimeHTTP3BindForSite(legacy); got != ":8443" {
		t.Fatalf("legacy runtimeHTTP3BindForSite = %q, want :8443", got)
	}

	perPortDefaults := base
	perPortDefaults.HTTP3PerPortEnabled = true
	perPort := runtimeHTTP3RouteConflictTestRuntime(1, "127.0.0.1:10443", "per-port.example.test", perPortDefaults, snapshot.DefaultTLSDefaults())
	if got := runtimeHTTP3BindForSite(perPort); got != ":10443" {
		t.Fatalf("per-port runtimeHTTP3BindForSite = %q, want :10443", got)
	}

	// 端口不可推导时必须返回空串（由调用方跳过），不能退回无端口的 TCP bind。
	brokenDefaults := perPortDefaults
	broken := runtimeHTTP3RouteConflictTestRuntime(2, "127.0.0.1", "broken.example.test", brokenDefaults, snapshot.DefaultTLSDefaults())
	if got := runtimeHTTP3BindForSite(broken); got != "" {
		t.Fatalf("port-less per-port runtimeHTTP3BindForSite = %q, want empty", got)
	}
}

// TestRuntimeHTTP3DetailReportsPerPortMode 锁定自检文案会区分两种模式。
func TestRuntimeHTTP3DetailReportsPerPortMode(t *testing.T) {
	defaults := snapshot.DefaultNetworkDefaults()
	defaults.HTTP3Bind = ":8443"
	tlsDefaults := snapshot.DefaultTLSDefaults()

	legacyDetail := runtimeHTTP3Detail(defaults, tlsDefaults)
	if !bytes.Contains([]byte(legacyDetail), []byte(":8443")) {
		t.Fatalf("legacy HTTP/3 detail = %q, want the global bind", legacyDetail)
	}
	if bytes.Contains([]byte(legacyDetail), []byte("每 TLS 端口独立")) {
		t.Fatalf("legacy HTTP/3 detail must not mention per-port mode: %q", legacyDetail)
	}

	defaults.HTTP3PerPortEnabled = true
	perPortDetail := runtimeHTTP3Detail(defaults, tlsDefaults)
	if !bytes.Contains([]byte(perPortDetail), []byte("每 TLS 端口独立")) {
		t.Fatalf("per-port HTTP/3 detail = %q, want the per-port wording", perPortDetail)
	}
	if bytes.Contains([]byte(perPortDetail), []byte(":8443")) {
		t.Fatalf("per-port HTTP/3 detail must not advertise the ignored http3_bind: %q", perPortDetail)
	}
}
