package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/upstream"
)

func TestGetNetworkConfigReturnsDefaults(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, GetNetworkConfig(repo), "GET", "/api/v1/network-config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var cfg NetworkConfig
	if err := json.Unmarshal(ctx.Response.Body(), &cfg); err != nil {
		t.Fatalf("decode network config: %v", err)
	}
	if !cfg.HTTP2Enabled || !cfg.HTTP3Enabled {
		t.Fatalf("network config = %#v, want HTTP/2 and HTTP/3 enabled by default", cfg)
	}
	if cfg.HTTP3Bind != ":443" {
		t.Fatalf("http3_bind = %q, want :443", cfg.HTTP3Bind)
	}
	if cfg.DefaultNetwork != "tcp" {
		t.Fatalf("default_network = %q, want tcp", cfg.DefaultNetwork)
	}
	if cfg.DefaultALPN == "" {
		t.Fatalf("default_alpn must be derived from the protocol switches")
	}
}

func TestGetNetworkConfigReflectsStoredValues(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	stored, err := json.Marshal(NetworkConfig{
		IPv6Enabled:    true,
		HTTP2Enabled:   false,
		HTTP3Enabled:   false,
		HTTP3Bind:      ":8443",
		DefaultALPN:    "http/1.1",
		DefaultNetwork: "tcp4",
	})
	if err != nil {
		t.Fatalf("encode stored config: %v", err)
	}
	if err := repo.Set(settingKeyNetwork, string(stored)); err != nil {
		t.Fatalf("seed network config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, GetNetworkConfig(repo), "GET", "/api/v1/network-config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var cfg NetworkConfig
	if err := json.Unmarshal(ctx.Response.Body(), &cfg); err != nil {
		t.Fatalf("decode network config: %v", err)
	}
	if !cfg.IPv6Enabled || cfg.HTTP2Enabled || cfg.HTTP3Enabled {
		t.Fatalf("network config = %#v, want the stored protocol switches", cfg)
	}
	if cfg.HTTP3Bind != ":8443" || cfg.DefaultNetwork != "tcp4" {
		t.Fatalf("network config = %#v, want the stored bind and network", cfg)
	}
}

func TestGetHTTP2ConfigReturnsRuntimeDefaults(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, GetHTTP2Config(repo), "GET", "/api/v1/http2-config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	want := loadHTTP2Config(repo)
	var got map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &got); err != nil {
		t.Fatalf("decode http2 config: %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("encode expected config: %v", err)
	}
	var wantMap map[string]any
	if err := json.Unmarshal(wantJSON, &wantMap); err != nil {
		t.Fatalf("decode expected config: %v", err)
	}
	if len(got) != len(wantMap) {
		t.Fatalf("http2 config field count = %d, want %d", len(got), len(wantMap))
	}
	for key, wantVal := range wantMap {
		gotVal, ok := got[key]
		if !ok {
			t.Fatalf("http2 config missing key %q", key)
		}
		if gotVal != wantVal {
			t.Fatalf("http2 config %q = %v, want %v", key, gotVal, wantVal)
		}
	}
}

func TestGetLogConfigReportsEffectiveLevel(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	stored, err := json.Marshal(LogConfig{Level: "warn", FilePath: "/var/log/waf.log", AlsoStdout: true})
	if err != nil {
		t.Fatalf("encode log config: %v", err)
	}
	if err := repo.Set(settingKeyLog, string(stored)); err != nil {
		t.Fatalf("seed log config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, GetLogConfig(repo), "GET", "/api/v1/log-config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var cfg LogConfig
	if err := json.Unmarshal(ctx.Response.Body(), &cfg); err != nil {
		t.Fatalf("decode log config: %v", err)
	}
	if cfg.FilePath != "/var/log/waf.log" || !cfg.AlsoStdout {
		t.Fatalf("log config = %#v, want the stored output settings", cfg)
	}
	// Level 由运行时 logger 覆盖，不回显库中的值，因此只断言非空。
	if cfg.Level == "" {
		t.Fatalf("log level must report the effective runtime level")
	}
}

func TestGetTLSDefaultConfigReturnsDefaults(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	ctx := invokeSystemConfigHandler(t, GetTLSDefaultConfig(repo), "GET", "/api/v1/tls-config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var cfg TLSDefaultConfig
	if err := json.Unmarshal(ctx.Response.Body(), &cfg); err != nil {
		t.Fatalf("decode tls config: %v", err)
	}
	want := loadTLSDefaultConfig(repo)
	if cfg != want {
		t.Fatalf("tls config = %#v, want %#v", cfg, want)
	}
	if cfg.MinVersion == "" || cfg.MaxVersion == "" {
		t.Fatalf("tls config must carry a version range: %#v", cfg)
	}
}

func TestGetRedisConfigNeverReturnsPassword(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(store.SettingKeyRedisConfig, `{"enabled":true,"addr":"10.0.0.9:6379","password":"redis-plaintext-secret","db":3}`); err != nil {
		t.Fatalf("seed redis config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, GetRedisConfig(repo, true), "GET", "/api/v1/redis-config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	body := ctx.Response.Body()
	if bytes.Contains(body, []byte("redis-plaintext-secret")) {
		t.Fatalf("redis config response leaked the password: %s", bytes.TrimSpace(body))
	}
	if bytes.Contains(body, []byte(`"password"`)) {
		t.Fatalf("redis config response must not carry a password field: %s", bytes.TrimSpace(body))
	}

	var resp RedisConfigResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode redis config: %v", err)
	}
	if !resp.Enabled || resp.Addr != "10.0.0.9:6379" || resp.DB != 3 {
		t.Fatalf("redis config = %#v, want the stored connection settings", resp)
	}
	if !resp.PasswordSet {
		t.Fatalf("password_set = false, want true when a password is stored")
	}
	if resp.Source != "database" {
		t.Fatalf("source = %q, want database", resp.Source)
	}
	if !resp.RestartRequired {
		t.Fatalf("restart_required = false, want the injected value")
	}
}

func TestGetRedisConfigReportsUnsetPassword(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(store.SettingKeyRedisConfig, `{"enabled":false,"addr":"","db":0}`); err != nil {
		t.Fatalf("seed redis config: %v", err)
	}

	ctx := invokeSystemConfigHandler(t, GetRedisConfig(repo, false), "GET", "/api/v1/redis-config", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp RedisConfigResponse
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode redis config: %v", err)
	}
	if resp.PasswordSet {
		t.Fatalf("password_set = true, want false when no password is stored")
	}
	if resp.RestartRequired {
		t.Fatalf("restart_required = true, want the injected false")
	}
}

func TestRedisConfigResponseOmitsSecret(t *testing.T) {
	resp := redisConfigResponse(RedisConfig{Enabled: true, Addr: "127.0.0.1:6379", Password: "never-serialize-me", DB: 1}, false)
	if !resp.PasswordSet {
		t.Fatalf("password_set = false, want true")
	}

	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("encode redis config response: %v", err)
	}
	if bytes.Contains(encoded, []byte("never-serialize-me")) {
		t.Fatalf("redis config response type serializes the password: %s", encoded)
	}
}

func TestDeletePolicyBlocksWhileReferenced(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Policy{}, &store.Site{}); err != nil {
		t.Fatalf("migrate policy tables: %v", err)
	}
	policyRepo := repository.NewPolicyRepo(db)
	siteRepo := repository.NewSiteRepo(db)

	policy := &store.Policy{Name: "referenced"}
	if err := policyRepo.Create(policy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID := policy.ID
	if err := siteRepo.Create(&store.Site{Host: "policy.example.test", Bind: ":80", UpstreamURLs: "http://127.0.0.1:8080", Enabled: true, PolicyID: &policyID}); err != nil {
		t.Fatalf("seed referencing site: %v", err)
	}
	idStr := strconv.FormatUint(uint64(policyID), 10)

	reloadCount := 0
	ctx := invokePolicyHandler(t, DeletePolicy(policyRepo, siteRepo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/policies/"+idStr+"/delete", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("referenced delete status = %d, want 400: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 0 {
		t.Fatalf("blocked delete must not reload, got %d calls", reloadCount)
	}

	var resp struct {
		Error    string `json:"error"`
		SiteRefs int64  `json:"site_refs"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode blocked delete response: %v", err)
	}
	if resp.SiteRefs != 1 {
		t.Fatalf("site_refs = %d, want 1", resp.SiteRefs)
	}
	if _, err := policyRepo.Get(policyID); err != nil {
		t.Fatalf("blocked delete must keep the policy: %v", err)
	}
}

func TestDeletePolicySucceedsWhenUnreferenced(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Policy{}, &store.Site{}); err != nil {
		t.Fatalf("migrate policy tables: %v", err)
	}
	policyRepo := repository.NewPolicyRepo(db)
	siteRepo := repository.NewSiteRepo(db)

	policy := &store.Policy{Name: "free"}
	if err := policyRepo.Create(policy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	idStr := strconv.FormatUint(uint64(policy.ID), 10)
	idParams := param.Params{{Key: "id", Value: idStr}}

	reloadCount := 0
	ctx := invokePolicyHandler(t, DeletePolicy(policyRepo, siteRepo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/policies/"+idStr+"/delete", idParams, nil)
	if ctx.Response.StatusCode() != 204 {
		t.Fatalf("delete status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", reloadCount)
	}
	if _, err := policyRepo.Get(policy.ID); err == nil {
		t.Fatalf("policy should be gone after delete")
	}

	badID := invokePolicyHandler(t, DeletePolicy(policyRepo, siteRepo, func() error { return nil }),
		"POST", "/api/v1/policies/nan/delete", param.Params{{Key: "id", Value: "nan"}}, nil)
	if badID.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", badID.Response.StatusCode())
	}
}

func TestDeletePolicyReportsReloadFailure(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Policy{}, &store.Site{}); err != nil {
		t.Fatalf("migrate policy tables: %v", err)
	}
	policyRepo := repository.NewPolicyRepo(db)
	siteRepo := repository.NewSiteRepo(db)

	policy := &store.Policy{Name: "reload-fail"}
	if err := policyRepo.Create(policy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	idStr := strconv.FormatUint(uint64(policy.ID), 10)

	ctx := invokePolicyHandler(t, DeletePolicy(policyRepo, siteRepo, func() error { return errors.New("reload boom") }),
		"POST", "/api/v1/policies/"+idStr+"/delete", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", ctx.Response.StatusCode())
	}
	if !bytes.Contains(ctx.Response.Body(), []byte("reload failed")) {
		t.Fatalf("reload failure body = %s, want it to mention the failure", bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestDashboardSummaryHandlerServesSnapshot(t *testing.T) {
	deps := &DashboardDeps{
		Metrics:  dataplane.NewMetrics(),
		ConfigDB: newDashboardConfigDBForTest(t),
		LogDB:    newDashboardLogDBForTest(t),
	}

	ctx := invokeSystemConfigHandler(t, DashboardSummary(deps), "GET", "/api/v1/dashboard", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("dashboard status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp map[string]any
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode dashboard summary: %v", err)
	}
	for _, key := range []string{"qps_1s", "requests_total", "waf_blocks", "revision", "bot_total_24h", "cve_by_type_24h", "drop_by_source_24h"} {
		if _, ok := resp[key]; !ok {
			t.Fatalf("dashboard summary missing key %q", key)
		}
	}
	sources, ok := resp["drop_by_source_24h"].(map[string]any)
	if !ok {
		t.Fatalf("drop_by_source_24h = %T, want an object", resp["drop_by_source_24h"])
	}
	for _, source := range []string{"bot", "cve", "rule", "ip_reputation"} {
		if _, ok := sources[source]; !ok {
			t.Fatalf("drop_by_source_24h missing source %q", source)
		}
	}
}

func TestUpstreamStatusHandlerReturnsSortedItems(t *testing.T) {
	pool := upstream.NewPool()
	pool.MarkResult("http://b.example.test", nil, 20*time.Millisecond)
	pool.MarkResult("http://a.example.test", assertErr{}, 80*time.Millisecond)

	ctx := invokeSystemConfigHandler(t, UpstreamStatus(pool), "GET", "/api/v1/upstream-status", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("upstream status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		Items []upstreamStatusItem `json:"items"`
		Total int                  `json:"total"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode upstream status: %v", err)
	}
	if resp.Total != 2 || len(resp.Items) != 2 {
		t.Fatalf("upstream status = total %d len %d, want 2", resp.Total, len(resp.Items))
	}
	if resp.Items[0].URL != "http://a.example.test" || resp.Items[1].URL != "http://b.example.test" {
		t.Fatalf("upstream items not sorted by url: %#v", resp.Items)
	}
	// 单次失败只累加 FailCount，健康标记由 Pool 的失败阈值决定，此处不做断言。
	if resp.Items[0].FailCount != 1 || resp.Items[0].LastError != "err" {
		t.Fatalf("first upstream should record the failure: %#v", resp.Items[0])
	}
	if resp.Items[0].LastSuccessAt != "" {
		t.Fatalf("first upstream must not report a success timestamp: %#v", resp.Items[0])
	}
	if resp.Items[1].FailCount != 0 || resp.Items[1].LastError != "" {
		t.Fatalf("second upstream should be clean: %#v", resp.Items[1])
	}
	if resp.Items[1].LastLatencyMs != 20 {
		t.Fatalf("second upstream last_latency_ms = %d, want 20", resp.Items[1].LastLatencyMs)
	}
}

func TestUpstreamStatusHandlerWithEmptyPool(t *testing.T) {
	ctx := invokeSystemConfigHandler(t, UpstreamStatus(upstream.NewPool()), "GET", "/api/v1/upstream-status", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("upstream status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !bytes.Contains(ctx.Response.Body(), []byte(`"total":0`)) {
		t.Fatalf("empty pool body = %s, want total 0", bytes.TrimSpace(ctx.Response.Body()))
	}
	if !bytes.Contains(ctx.Response.Body(), []byte(`"items":[]`)) {
		t.Fatalf("empty pool body = %s, want an empty items array", bytes.TrimSpace(ctx.Response.Body()))
	}
}
