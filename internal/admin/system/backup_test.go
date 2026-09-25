package system

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

func newBackupDBForTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// 用 store.BackupModels 而非手写清单，新增备份模型时不会漏。
	if err := db.AutoMigrate(store.BackupModels()...); err != nil {
		t.Fatalf("migrate backup db: %v", err)
	}
	return db
}

func invokeBackupHandler(t *testing.T, handler app.HandlerFunc, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/backup/import")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

func TestImportBackupRejectsVersionZero(t *testing.T) {
	db := newBackupDBForTest(t)
	reloadCalled := false
	reload := func() error { reloadCalled = true; return nil }

	body, _ := json.Marshal(map[string]any{
		"data":         map[string]any{"version": 0},
		"replace_mode": false,
	})
	ctx := invokeBackupHandler(t, ImportBackup(db, reload), body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("version=0 status = %d, want 400; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCalled {
		t.Fatal("reload must not be called when version is invalid")
	}
}

func TestImportBackupRejectsVersionTooHigh(t *testing.T) {
	db := newBackupDBForTest(t)
	reload := func() error { return nil }

	body, _ := json.Marshal(map[string]any{
		"data":         map[string]any{"version": store.BackupVersion + 99},
		"replace_mode": false,
	})
	ctx := invokeBackupHandler(t, ImportBackup(db, reload), body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("version too high status = %d, want 400; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	respStr := string(bytes.TrimSpace(ctx.Response.Body()))
	if !strings.Contains(respStr, "unsupported backup version") {
		t.Fatalf("error message = %q, want 'unsupported backup version'", respStr)
	}
}

func TestImportBackupCallsReloadOnSuccess(t *testing.T) {
	db := newBackupDBForTest(t)
	reloadCount := 0
	invalidateCount := 0
	reload := func() error { reloadCount++; return nil }

	body, _ := json.Marshal(map[string]any{
		"data":         map[string]any{"version": store.BackupVersion},
		"replace_mode": false,
	})
	ctx := invokeBackupHandler(t, ImportBackup(db, reload, func() { invalidateCount++ }), body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("import status = %d, want 200; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload called %d times, want 1", reloadCount)
	}
	if invalidateCount != 1 {
		t.Fatalf("cache invalidation called %d times, want 1", invalidateCount)
	}
}

func TestImportBackupRejectsInvalidJSON(t *testing.T) {
	db := newBackupDBForTest(t)
	reload := func() error { return nil }

	ctx := invokeBackupHandler(t, ImportBackup(db, reload), []byte(`{not-valid-json`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid json status = %d, want 400", ctx.Response.StatusCode())
	}
}

func TestExportBackupSetsContentDisposition(t *testing.T) {
	db := newBackupDBForTest(t)

	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/backup/export")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ExportBackup(db)(context.Background(), ctx)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("export status = %d, want 200; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	cd := string(ctx.Response.Header.Get("Content-Disposition"))
	if !strings.HasPrefix(cd, "attachment;") {
		t.Fatalf("Content-Disposition = %q, want 'attachment;...'", cd)
	}
	if !strings.Contains(cd, "owaf-backup-") {
		t.Fatalf("Content-Disposition = %q, want filename containing 'owaf-backup-'", cd)
	}

	var data store.BackupData
	if err := json.Unmarshal(ctx.Response.Body(), &data); err != nil {
		t.Fatalf("decode export body: %v", err)
	}
	if data.Version != store.BackupVersion {
		t.Fatalf("backup version = %d, want %d", data.Version, store.BackupVersion)
	}
}

/**
 * TestExportBackupMasksThreatIntelAuthHeaders 验证备份导出响应遮蔽订阅源令牌：
 * 行为与 maskAuthHeaderValue 完全一致——长度大于 4 的值保留前 4 位加 ***，
 * 长度不足 5 的全部标星、空值保持为空。
 */
func TestExportBackupMasksThreatIntelAuthHeaders(t *testing.T) {
	db := newBackupDBForTest(t)
	seed := []store.ThreatIntelFeed{
		{Name: "long-token", Kind: "blacklist", Action: "intercept", AuthHeaderName: "Authorization", AuthHeaderValue: "Bearer secret-token-value"},
		{Name: "short-token", Kind: "blacklist", Action: "intercept", AuthHeaderName: "X-Token", AuthHeaderValue: "abc"},
		{Name: "no-token", Kind: "blacklist", Action: "intercept", AuthHeaderName: "X-Token"},
	}
	for i := range seed {
		if err := db.Create(&seed[i]).Error; err != nil {
			t.Fatalf("create feed %s: %v", seed[i].Name, err)
		}
	}

	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/backup/export")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ExportBackup(db)(context.Background(), ctx)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("export status = %d, want 200; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var data store.BackupData
	if err := json.Unmarshal(ctx.Response.Body(), &data); err != nil {
		t.Fatalf("decode export body: %v", err)
	}
	got := make(map[string]string, len(data.ThreatIntelFeeds))
	for _, f := range data.ThreatIntelFeeds {
		got[f.Name] = f.AuthHeaderValue
	}
	if got["long-token"] != "Bear***" {
		t.Errorf("long-token AuthHeaderValue = %q, want 掩码 Bear***", got["long-token"])
	}
	if got["short-token"] != "***" {
		t.Errorf("short-token AuthHeaderValue = %q, want 短值全部标星 ***", got["short-token"])
	}
	if got["no-token"] != "" {
		t.Errorf("no-token AuthHeaderValue = %q, want 空", got["no-token"])
	}
}

/**
 * TestExportBackupMaskedImportKeepsExistingSecrets 验证遮蔽导出的导入兼容：
 * 空 AuthHeaderValue 空写不破坏其他字段更新；凭据因遮蔽不随备份走，
 * 导入后该字段为空，需管理员重新录入。
 */
func TestExportBackupMaskedImportKeepsExistingSecrets(t *testing.T) {
	dst := newBackupDBForTest(t)
	existing := &store.ThreatIntelFeed{
		Name: "existing", URL: "https://old.example.test/feed", Kind: "blacklist",
		Action: "intercept", Enabled: true, SyncInterval: 3600,
		AuthHeaderName: "X-Token", AuthHeaderValue: "old-secret-kept",
	}
	if err := dst.Create(existing).Error; err != nil {
		t.Fatalf("create existing feed: %v", err)
	}

	masked := &store.BackupData{
		Version: store.BackupVersion,
		ThreatIntelFeeds: []store.ThreatIntelFeed{
			{ID: existing.ID, Name: "existing", URL: "https://old.example.test/feed", Kind: "blacklist",
				Action: "intercept", Enabled: true, SyncInterval: 7200,
				AuthHeaderName: "X-Token", AuthHeaderValue: ""},
		},
	}
	if err := store.ImportBackup(dst, masked, false); err != nil {
		t.Fatalf("import: %v", err)
	}
	var got store.ThreatIntelFeed
	if err := dst.First(&got, existing.ID).Error; err != nil {
		t.Fatalf("load restored feed: %v", err)
	}
	if got.SyncInterval != 7200 {
		t.Errorf("SyncInterval = %d, want 7200（遮蔽导入不得妨碍其他字段更新）", got.SyncInterval)
	}
	if got.AuthHeaderValue != "" {
		t.Errorf("AuthHeaderValue = %q, want 空（凭据不随备份走，导入后需重新录入）", got.AuthHeaderValue)
	}
}

/**
 * TestExportBackupMasksOAuthClientSecrets 验证备份导出只遮蔽 AccessProvider.Config
 * 内的 client_secret：非空密文替换为「前 4 位 + ***」，非空短值整体 ***，
 * 其余配置字段原样保留；password 类型与解析失败的 Config 不受影响。
 */
func TestExportBackupMasksOAuthClientSecrets(t *testing.T) {
	db := newBackupDBForTest(t)
	secretJSON := func(secret string) string {
		t.Helper()
		cfg := store.OAuthProviderConfig{
			ClientID:     "client-app-1",
			ClientSecret: secret,
			AuthURL:      "https://auth.example.test/authorize",
		}
		raw, err := json.Marshal(&cfg)
		if err != nil {
			t.Fatalf("encode oauth config: %v", err)
		}
		return string(raw)
	}
	seed := []store.AccessProvider{
		{SiteID: 1, Type: store.AccessProviderOAuth2, Name: "oauth-long", Config: secretJSON("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=")},
		{SiteID: 1, Type: store.AccessProviderOAuth2, Name: "oauth-short", Config: secretJSON("abcd")},
		{SiteID: 1, Type: store.AccessProviderOIDC, Name: "oidc-empty", Config: secretJSON("")},
		{SiteID: 1, Type: store.AccessProviderPassword, Name: "password-noconfig"},
		{SiteID: 1, Type: store.AccessProviderOAuth2, Name: "oauth-badjson", Config: `{not-valid-json`},
	}
	for i := range seed {
		if err := db.Create(&seed[i]).Error; err != nil {
			t.Fatalf("create provider %s: %v", seed[i].Name, err)
		}
	}

	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/backup/export")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ExportBackup(db)(context.Background(), ctx)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("export status = %d, want 200; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var data store.BackupData
	if err := json.Unmarshal(ctx.Response.Body(), &data); err != nil {
		t.Fatalf("decode export body: %v", err)
	}
	got := make(map[string]store.AccessProvider, len(data.AccessProviders))
	for _, p := range data.AccessProviders {
		got[p.Name] = p
	}
	decode := func(name string) store.OAuthProviderConfig {
		t.Helper()
		p, ok := got[name]
		if !ok {
			t.Fatalf("provider %q not present in export", name)
		}
		var cfg store.OAuthProviderConfig
		if err := json.Unmarshal([]byte(p.Config), &cfg); err != nil {
			t.Fatalf("decode provider %q config: %v", name, err)
		}
		return cfg
	}
	if c := decode("oauth-long"); c.ClientSecret != "QUJD***" {
		t.Errorf("oauth-long client_secret = %q, want 掩码 QUJD***", c.ClientSecret)
	} else if c.ClientID != "client-app-1" || c.AuthURL != "https://auth.example.test/authorize" {
		t.Errorf("oauth-long 非密钥字段被改动: client_id=%q auth_url=%q", c.ClientID, c.AuthURL)
	}
	if c := decode("oauth-short"); c.ClientSecret != "***" {
		t.Errorf("oauth-short client_secret = %q, want 短值整体 ***", c.ClientSecret)
	}
	if c := decode("oidc-empty"); c.ClientSecret != "" {
		t.Errorf("oidc-empty client_secret = %q, want 空值保持为空", c.ClientSecret)
	}
	if p, ok := got["oauth-badjson"]; !ok || p.Config != `{not-valid-json` {
		t.Error("解析失败的 Config 应保持原样不受遮蔽")
	}
	if p, ok := got["password-noconfig"]; !ok || p.Config != "" {
		t.Error("password 类型无配置，导出后 Config 应仍为空")
	}
}

/**
 * TestExportBackupMaskedValueOverwritesOnImport 验证掩码值往返语义（任务 C 项）：
 * 导出物里携带的是 maskAuthHeaderValue 生成的掩码值而非手工空串，导入侧
 * OnConflict{UpdateAll} 会把该掩码值写进目标库、覆盖旧凭据——即旧的明文令牌
 * 不会因「空写保留原值」路径而幸存。
 */
func TestExportBackupMaskedValueOverwritesOnImport(t *testing.T) {
	src := newBackupDBForTest(t)
	feed := store.ThreatIntelFeed{
		Name: "feed", Kind: "blacklist", Action: "intercept",
		AuthHeaderName: "X-Token", AuthHeaderValue: "Bearer original-secret",
	}
	if err := src.Create(&feed).Error; err != nil {
		t.Fatalf("create source feed: %v", err)
	}

	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/backup/export")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ExportBackup(src)(context.Background(), ctx)

	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("export status = %d, want 200; body=%s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var data store.BackupData
	if err := json.Unmarshal(ctx.Response.Body(), &data); err != nil {
		t.Fatalf("decode export body: %v", err)
	}
	var exported store.ThreatIntelFeed
	for _, f := range data.ThreatIntelFeeds {
		if f.Name == "feed" {
			exported = f
		}
	}
	if exported.AuthHeaderValue == "" {
		t.Fatal("导出的凭据列应为掩码值（非手工空串）")
	}
	if exported.AuthHeaderValue == "Bearer original-secret" {
		t.Fatal("令牌明文随备份导出，遮蔽失效")
	}

	dst := newBackupDBForTest(t)
	existing := store.ThreatIntelFeed{
		ID: exported.ID, Name: "feed", Kind: "blacklist", Action: "intercept",
		AuthHeaderName: "X-Token", AuthHeaderValue: "old-dst-secret",
	}
	if err := dst.Create(&existing).Error; err != nil {
		t.Fatalf("create destination feed: %v", err)
	}
	if err := store.ImportBackup(dst, &data, false); err != nil {
		t.Fatalf("import masked backup: %v", err)
	}
	var got store.ThreatIntelFeed
	if err := dst.Where("name = ?", "feed").First(&got).Error; err != nil {
		t.Fatalf("load restored feed: %v", err)
	}
	if got.AuthHeaderValue != exported.AuthHeaderValue {
		t.Errorf("导入后凭据 = %q, want 被掩码值 %q 覆盖而非保留旧凭据", got.AuthHeaderValue, exported.AuthHeaderValue)
	}
}
