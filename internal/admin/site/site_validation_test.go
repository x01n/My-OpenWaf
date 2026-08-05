package site

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestCreateSiteRejectsMalformedBody(t *testing.T) {
	repo := newSiteRepoForTest(t)
	reloadCalled := false
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error {
		reloadCalled = true
		return nil
	}), []byte(`{"host":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload should not be called")
	}
}

// TestCreateSiteAppliesProtectionModeOverrides 覆盖创建路径上的 attack_protection_level 同步分支。
func TestCreateSiteAppliesProtectionModeOverrides(t *testing.T) {
	repo := newSiteRepoForTest(t)
	body := []byte(`{
		"host":"create-mode.example",
		"upstream_urls":"http://127.0.0.1:8080",
		"bind":":8080",
		"network":"tcp",
		"enabled":true,
		"attack_protection_level":"protect"
	}`)
	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	items, _, err := repo.List(0, 10)
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one site, got %d", len(items))
	}
	created := items[0]
	if created.AttackProtectionLevel != store.SiteProtectionModeProtect {
		t.Fatalf("attack_protection_level = %q", created.AttackProtectionLevel)
	}
	requireBoolPtr(t, "BotProtectionEnabled", created.BotProtectionEnabled, true)
	requireBoolPtr(t, "OWASPEnabled", created.OWASPEnabled, true)
	requireBoolPtr(t, "CVEEnabled", created.CVEEnabled, true)
	requireBoolPtr(t, "RateLimitEnabled", created.RateLimitEnabled, true)
	if created.OWASPSensitivity != "mid" || created.OWASPAction != string(store.ActionIntercept) {
		t.Fatalf("owasp overrides mismatch: %#v", created)
	}
	if created.CVEAction != string(store.ActionIntercept) || created.RateLimitAction != string(store.ActionRateLimit) {
		t.Fatalf("cve/rate limit overrides mismatch: %#v", created)
	}
}

func TestCreateSiteRejectsInvalidUpstreamHost(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		wantError string
	}{
		{name: "unparsable template", host: "{{.Host", wantError: "upstream_host contains invalid template"},
		{name: "invalid host value", host: "bad host", wantError: "upstream_host contains invalid host"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSiteRepoForTest(t)
			payload, err := json.Marshal(map[string]any{
				"host":          "create-upstream-host.example",
				"upstream_urls": "http://127.0.0.1:8080",
				"upstream_host": tt.host,
				"bind":          ":8080",
				"network":       "tcp",
				"enabled":       true,
			})
			if err != nil {
				t.Fatalf("encode payload: %v", err)
			}

			ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), payload)
			if ctx.Response.StatusCode() != 400 {
				t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			requireErrorMessage(t, ctx.Response.Body(), tt.wantError)
		})
	}
}

func TestUpdateSiteRejectsInvalidUpstreamHost(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{Host: "update-upstream-host-invalid.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true, UpstreamHost: "backend.example"}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, []byte(`{"upstream_host":"{{.Host"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "upstream_host contains invalid template")

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.UpstreamHost != "backend.example" {
		t.Fatalf("rejected update should preserve upstream_host, got %q", loaded.UpstreamHost)
	}
}

/**
 * TestCreateSiteRejectsInvalidRuntimeActions 覆盖 validateSiteActions 中
 * cve_action / rate_limit_action / anti_replay_action 的拒绝分支。
 * 注意：*_enabled 为 nil 时 clearInheritedProtectionOverrides 会先清空对应动作，
 * 因此这些用例必须显式开启对应开关才能触达校验。
 */
func TestCreateSiteRejectsInvalidRuntimeActions(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{name: "owasp action", payload: `"owasp_enabled":true,"owasp_action":"not-an-action"`},
		{name: "cve action", payload: `"cve_enabled":true,"cve_action":"not-an-action"`},
		{name: "rate limit action", payload: `"rate_limit_enabled":true,"rate_limit_action":"not-an-action"`},
		{name: "anti replay action", payload: `"anti_replay_enabled":true,"anti_replay_action":"not-an-action"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newSiteRepoForTest(t)
			body := []byte(`{
				"host":"create-invalid-action.example",
				"upstream_urls":"http://127.0.0.1:8080",
				"bind":":8080",
				"network":"tcp",
				"enabled":true,
				` + tt.payload + `
			}`)

			ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), body)
			if ctx.Response.StatusCode() != 400 {
				t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
			}
			requireErrorMessage(t, ctx.Response.Body(), errInvalidSiteAction.Error())

			_, total, err := repo.List(0, 10)
			if err != nil {
				t.Fatalf("list sites: %v", err)
			}
			if total != 0 {
				t.Fatalf("site was created despite invalid action, total=%d", total)
			}
		})
	}
}

// TestCreateSiteNormalizesAntiReplayAction 覆盖 anti_replay_action 通过校验后的归一化赋值。
func TestCreateSiteNormalizesAntiReplayAction(t *testing.T) {
	repo := newSiteRepoForTest(t)
	body := []byte(`{
		"host":"create-anti-replay.example",
		"upstream_urls":"http://127.0.0.1:8080",
		"bind":":8080",
		"network":"tcp",
		"enabled":true,
		"anti_replay_enabled":true,
		"anti_replay_action":"block"
	}`)

	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), body)
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	items, _, err := repo.List(0, 10)
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one site, got %d", len(items))
	}
	// legacy 的 block 会被归一化为 intercept。
	if items[0].AntiReplayAction != string(store.ActionIntercept) {
		t.Fatalf("anti_replay_action = %q, want %q", items[0].AntiReplayAction, store.ActionIntercept)
	}
}

func TestCreateSiteValidatesTLSCertificate(t *testing.T) {
	siteRepo, _, certRepo := newSiteListenerCertReposForTest(t)
	cert := store.Certificate{Name: "site-cert", CertPEM: "cert", KeyPEM: "key"}
	if err := certRepo.Create(&cert); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}

	tests := []struct {
		name       string
		tlsPayload string
		wantStatus int
		wantError  string
	}{
		{name: "tls without cert id", tlsPayload: `"tls_enabled":true`, wantStatus: 400, wantError: "TLS-enabled site requires cert_id"},
		{name: "tls with unknown cert id", tlsPayload: `"tls_enabled":true,"cert_id":9999`, wantStatus: 400, wantError: "certificate not found"},
		{name: "tls with existing cert id", tlsPayload: `"tls_enabled":true,"cert_id":` + strconv.FormatUint(uint64(cert.ID), 10), wantStatus: 201},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(`{
				"host":"create-tls-cert.example",
				"upstream_urls":"http://127.0.0.1:8080",
				"bind":":8443",
				"network":"tcp",
				"enabled":true,
				` + tt.tlsPayload + `
			}`)

			ctx := invokeCreateSiteHandler(t, CreateSite(siteRepo, certRepo, func() error { return nil }), body)
			if ctx.Response.StatusCode() != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", ctx.Response.StatusCode(), tt.wantStatus, bytes.TrimSpace(ctx.Response.Body()))
			}
			if tt.wantError != "" {
				requireErrorMessage(t, ctx.Response.Body(), tt.wantError)
			}
		})
	}
}

func TestCreateSiteReturns500WhenPersistFails(t *testing.T) {
	siteRepo, _ := newSiteReposWithoutSiteTable(t)
	body := []byte(`{
		"host":"create-persist-error.example",
		"upstream_urls":"http://127.0.0.1:8080",
		"bind":":8080",
		"network":"tcp",
		"enabled":true
	}`)

	reloadCalled := false
	ctx := invokeCreateSiteHandler(t, CreateSite(siteRepo, nil, func() error {
		reloadCalled = true
		return nil
	}), body)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload should not be called when persist fails")
	}
}

func TestCreateSiteReportsReloadFailure(t *testing.T) {
	repo := newSiteRepoForTest(t)
	body := []byte(`{
		"host":"create-reload-error.example",
		"upstream_urls":"http://127.0.0.1:8080",
		"bind":":8080",
		"network":"tcp",
		"enabled":true
	}`)

	ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return errTestReload }), body)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Error string     `json:"error"`
		Item  store.Site `json:"item"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "config applied but reload failed: "+errTestReload.Error() {
		t.Fatalf("error = %q", resp.Error)
	}
	if resp.Item.Host != "create-reload-error.example" {
		t.Fatalf("reload failure should echo the created site, got %#v", resp.Item)
	}
	// 站点已经落库，reload 失败不回滚。
	_, total, err := repo.List(0, 10)
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	if total != 1 {
		t.Fatalf("site should be persisted before reload, total=%d", total)
	}
}

func TestUpdateSiteRejectsInvalidIDAndMissingSite(t *testing.T) {
	repo := newSiteRepoForTest(t)
	handler := UpdateSite(repo, nil, func() error { return nil })
	body := []byte(`{"enabled":true}`)

	ctx := invokeSiteRouteHandler(t, handler, "POST", "/api/v1/sites/abc/update", idParams("abc"), body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d", ctx.Response.StatusCode())
	}
	requireErrorMessage(t, ctx.Response.Body(), "invalid id")

	ctx = invokeSiteRouteHandler(t, handler, "POST", "/api/v1/sites/404/update", idParams("404"), body)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing site status = %d", ctx.Response.StatusCode())
	}
	requireErrorMessage(t, ctx.Response.Body(), "not found")
}

func TestUpdateSiteRejectsMalformedBody(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{Host: "update-bad-body.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, []byte(`{"enabled":`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestUpdateSiteValidatesTLSCertificate(t *testing.T) {
	siteRepo, _, certRepo := newSiteListenerCertReposForTest(t)
	item := store.Site{Host: "update-tls-cert.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8443", Network: "tcp", Enabled: true}
	if err := siteRepo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteHandler(t, UpdateSite(siteRepo, certRepo, func() error { return nil }), item.ID, []byte(`{"tls_enabled":true,"cert_id":9999}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	requireErrorMessage(t, ctx.Response.Body(), "certificate not found")

	loaded, err := siteRepo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.TLSEnabled {
		t.Fatal("rejected update should not enable TLS")
	}
}

func TestUpdateSiteReportsReloadFailure(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{Host: "update-reload-error.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp", Enabled: true}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return errTestReload }), item.ID, []byte(`{"upstream_host":"backend.example"}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Error string     `json:"error"`
		Item  store.Site `json:"item"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "config applied but reload failed: "+errTestReload.Error() {
		t.Fatalf("error = %q", resp.Error)
	}
	if resp.Item.ID != item.ID {
		t.Fatalf("reload failure should echo the updated site, got %#v", resp.Item)
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.UpstreamHost != "backend.example" {
		t.Fatalf("update persists before reload, upstream_host = %q", loaded.UpstreamHost)
	}
}

// TestUpdateSiteClearsNetworkWhenBlank 覆盖 validateSiteNetwork 中空值直通（继承全局）的分支。
func TestUpdateSiteClearsNetworkWhenBlank(t *testing.T) {
	repo := newSiteRepoForTest(t)
	item := store.Site{Host: "update-blank-network.example", UpstreamURLs: "http://127.0.0.1:8080", Bind: ":8080", Network: "tcp6", Enabled: true}
	if err := repo.Create(&item); err != nil {
		t.Fatalf("seed site: %v", err)
	}

	ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), item.ID, []byte(`{"network":"   "}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	loaded, err := repo.Get(item.ID)
	if err != nil {
		t.Fatalf("load site: %v", err)
	}
	if loaded.Network != "" {
		t.Fatalf("blank network should clear the override, got %q", loaded.Network)
	}
}

/**
 * TestSiteRequestHasField 直接单测请求体字段探测函数。
 * 非法 JSON 分支在 handler 流程中不可达（BindSiteFromRequestBody 会先返回 400），
 * 因此只能在此处覆盖。
 */
func TestSiteRequestHasField(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		field string
		want  bool
	}{
		{name: "present field", body: `{"owasp_enabled":true}`, field: "owasp_enabled", want: true},
		{name: "explicit null still counts as present", body: `{"owasp_enabled":null}`, field: "owasp_enabled", want: true},
		{name: "absent field", body: `{"cve_enabled":true}`, field: "owasp_enabled", want: false},
		{name: "malformed json", body: `{"owasp_enabled":`, field: "owasp_enabled", want: false},
		{name: "non object json", body: `["owasp_enabled"]`, field: "owasp_enabled", want: false},
		{name: "empty body", body: ``, field: "owasp_enabled", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := siteRequestHasField([]byte(tt.body), tt.field); got != tt.want {
				t.Fatalf("siteRequestHasField(%q, %q) = %v, want %v", tt.body, tt.field, got, tt.want)
			}
		})
	}
}

func TestCreateAndUpdateSiteValidatePolicyReferences(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.Site{}, &store.Policy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := repository.NewSiteRepo(db)
	active := store.Policy{Name: "active"}
	deleted := store.Policy{Name: "deleted"}
	if err := db.Create(&active).Error; err != nil {
		t.Fatalf("seed active policy: %v", err)
	}
	if err := db.Create(&deleted).Error; err != nil {
		t.Fatalf("seed deleted policy: %v", err)
	}
	if err := db.Delete(&deleted).Error; err != nil {
		t.Fatalf("soft delete policy: %v", err)
	}

	for _, policyID := range []uint{999, deleted.ID} {
		body := []byte(`{"host":"policy-create.example","upstream_urls":"http://127.0.0.1:8080","bind":":8080","network":"tcp","enabled":true,"policy_id":` + strconv.FormatUint(uint64(policyID), 10) + `}`)
		ctx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), body)
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("create policy %d status %d: %s", policyID, ctx.Response.StatusCode(), ctx.Response.Body())
		}
	}

	validBody := []byte(`{"host":"policy-valid.example","upstream_urls":"http://127.0.0.1:8080","bind":":8080","network":"tcp","enabled":true,"policy_id":` + strconv.FormatUint(uint64(active.ID), 10) + `}`)
	createdCtx := invokeCreateSiteHandler(t, CreateSite(repo, nil, func() error { return nil }), validBody)
	if createdCtx.Response.StatusCode() != 201 {
		t.Fatalf("valid create status %d: %s", createdCtx.Response.StatusCode(), createdCtx.Response.Body())
	}
	var created store.Site
	if err := json.Unmarshal(createdCtx.Response.Body(), &created); err != nil {
		t.Fatalf("decode created site: %v", err)
	}

	for _, policyID := range []uint{999, deleted.ID} {
		ctx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), created.ID, []byte(`{"policy_id":`+strconv.FormatUint(uint64(policyID), 10)+`}`))
		if ctx.Response.StatusCode() != 400 {
			t.Fatalf("update policy %d status %d: %s", policyID, ctx.Response.StatusCode(), ctx.Response.Body())
		}
	}

	inheritCtx := invokeSiteHandler(t, UpdateSite(repo, nil, func() error { return nil }), created.ID, []byte(`{"policy_id":0}`))
	if inheritCtx.Response.StatusCode() != 200 {
		t.Fatalf("inherit update status %d: %s", inheritCtx.Response.StatusCode(), inheritCtx.Response.Body())
	}
	loaded, err := repo.Get(created.ID)
	if err != nil {
		t.Fatalf("load updated site: %v", err)
	}
	if loaded.PolicyID != nil {
		t.Fatalf("policy_id = %v, want nil inheritance", loaded.PolicyID)
	}
}
