package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

/**
 * newBrokenSettingsRepoForTest 返回一个底层表已被删除的设置仓库，用于触发 500 分支。
 */
func newBrokenSettingsRepoForTest(t *testing.T) *repository.SystemSettingsRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	if err := db.Migrator().DropTable(&store.SystemSettings{}); err != nil {
		t.Fatalf("drop settings table: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

func TestReloadSnapshotHandler(t *testing.T) {
	reloadCount := 0
	ok := invokeSettingsHandler(t, ReloadSnapshot(func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/reload", nil, nil)
	if ok.Response.StatusCode() != 200 {
		t.Fatalf("reload status %d: %s", ok.Response.StatusCode(), bytes.TrimSpace(ok.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", reloadCount)
	}
	if !bytes.Contains(ok.Response.Body(), []byte(`"status":"ok"`)) {
		t.Fatalf("reload body = %s, want status ok", bytes.TrimSpace(ok.Response.Body()))
	}

	failed := invokeSettingsHandler(t, ReloadSnapshot(func() error { return errors.New("rebuild failed") }), "POST", "/api/v1/reload", nil, nil)
	if failed.Response.StatusCode() != 500 {
		t.Fatalf("failed reload status = %d, want 500", failed.Response.StatusCode())
	}
	if !bytes.Contains(failed.Response.Body(), []byte("rebuild failed")) {
		t.Fatalf("failed reload body = %s, want the underlying error", bytes.TrimSpace(failed.Response.Body()))
	}
}

func TestHealthCheckHandler(t *testing.T) {
	ctx := invokeSettingsHandler(t, HealthCheck(), "GET", "/api/v1/health", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("health status %d", ctx.Response.StatusCode())
	}
	var resp map[string]string
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("health response = %v, want status ok", resp)
	}
}

func TestCreateSettingPersistsAndReloads(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	reloadCount := 0

	ctx := invokeSettingsHandler(t, CreateSetting(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/settings", nil, []byte(`{"key":"custom_flag","value":"enabled"}`))
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("create status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", reloadCount)
	}
	got, err := repo.Get("custom_flag")
	if err != nil {
		t.Fatalf("load setting: %v", err)
	}
	if got != "enabled" {
		t.Fatalf("stored value = %q, want enabled", got)
	}
}

func TestCreateSettingRejectsMissingKeyAndMalformedBody(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)

	missingKey := invokeSettingsHandler(t, CreateSetting(repo, func() error { return nil }), "POST", "/api/v1/settings", nil, []byte(`{"value":"x"}`))
	if missingKey.Response.StatusCode() != 400 {
		t.Fatalf("missing key status = %d, want 400", missingKey.Response.StatusCode())
	}
	if !bytes.Contains(missingKey.Response.Body(), []byte("key is required")) {
		t.Fatalf("missing key body = %s, want an explanatory error", bytes.TrimSpace(missingKey.Response.Body()))
	}

	malformed := invokeSettingsHandler(t, CreateSetting(repo, func() error { return nil }), "POST", "/api/v1/settings", nil, []byte(`{"key":`))
	if malformed.Response.StatusCode() != 400 {
		t.Fatalf("malformed body status = %d, want 400", malformed.Response.StatusCode())
	}
}

func TestCreateSettingReportsStoreAndReloadFailures(t *testing.T) {
	storeFailure := invokeSettingsHandler(t, CreateSetting(newBrokenSettingsRepoForTest(t), func() error { return nil }),
		"POST", "/api/v1/settings", nil, []byte(`{"key":"custom_flag","value":"v"}`))
	if storeFailure.Response.StatusCode() != 500 {
		t.Fatalf("store failure status = %d, want 500", storeFailure.Response.StatusCode())
	}

	reloadFailure := invokeSettingsHandler(t, CreateSetting(newSystemSettingsRepoForTest(t), func() error { return errors.New("reload boom") }),
		"POST", "/api/v1/settings", nil, []byte(`{"key":"custom_flag","value":"v"}`))
	if reloadFailure.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", reloadFailure.Response.StatusCode())
	}
	if !bytes.Contains(reloadFailure.Response.Body(), []byte("reload failed")) {
		t.Fatalf("reload failure body = %s, want it to mention the failure", bytes.TrimSpace(reloadFailure.Response.Body()))
	}
}

func TestSetSettingPersistsAndReportsFailures(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	reloadCount := 0
	keyParams := param.Params{{Key: "key", Value: "custom_flag"}}

	ok := invokeSettingsHandler(t, SetSetting(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/settings/custom_flag", keyParams, []byte(`{"value":"on"}`))
	if ok.Response.StatusCode() != 200 {
		t.Fatalf("set status %d: %s", ok.Response.StatusCode(), bytes.TrimSpace(ok.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", reloadCount)
	}
	stored, err := repo.Get("custom_flag")
	if err != nil || stored != "on" {
		t.Fatalf("stored value = %q err %v, want on", stored, err)
	}

	malformed := invokeSettingsHandler(t, SetSetting(repo, func() error { return nil }), "POST", "/api/v1/settings/custom_flag", keyParams, []byte(`{"value":`))
	if malformed.Response.StatusCode() != 400 {
		t.Fatalf("malformed body status = %d, want 400", malformed.Response.StatusCode())
	}

	storeFailure := invokeSettingsHandler(t, SetSetting(newBrokenSettingsRepoForTest(t), func() error { return nil }),
		"POST", "/api/v1/settings/custom_flag", keyParams, []byte(`{"value":"on"}`))
	if storeFailure.Response.StatusCode() != 500 {
		t.Fatalf("store failure status = %d, want 500", storeFailure.Response.StatusCode())
	}

	reloadFailure := invokeSettingsHandler(t, SetSetting(newSystemSettingsRepoForTest(t), func() error { return errors.New("reload boom") }),
		"POST", "/api/v1/settings/custom_flag", keyParams, []byte(`{"value":"on"}`))
	if reloadFailure.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", reloadFailure.Response.StatusCode())
	}
}

func TestDeleteSettingRemovesKeyAndReportsFailures(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set("custom_flag", "on"); err != nil {
		t.Fatalf("seed setting: %v", err)
	}
	keyParams := param.Params{{Key: "key", Value: "custom_flag"}}
	reloadCount := 0

	ctx := invokeSettingsHandler(t, DeleteSetting(repo, func() error {
		reloadCount++
		return nil
	}), "POST", "/api/v1/settings/custom_flag/delete", keyParams, nil)
	if ctx.Response.StatusCode() != 204 {
		t.Fatalf("delete status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloadCount != 1 {
		t.Fatalf("reload count = %d, want 1", reloadCount)
	}
	if _, err := repo.Get("custom_flag"); err == nil {
		t.Fatalf("setting should be gone after delete")
	}

	storeFailure := invokeSettingsHandler(t, DeleteSetting(newBrokenSettingsRepoForTest(t), func() error { return nil }),
		"POST", "/api/v1/settings/custom_flag/delete", keyParams, nil)
	if storeFailure.Response.StatusCode() != 500 {
		t.Fatalf("store failure status = %d, want 500", storeFailure.Response.StatusCode())
	}

	reloadRepo := newSystemSettingsRepoForTest(t)
	if err := reloadRepo.Set("custom_flag", "on"); err != nil {
		t.Fatalf("seed setting: %v", err)
	}
	reloadFailure := invokeSettingsHandler(t, DeleteSetting(reloadRepo, func() error { return errors.New("reload boom") }),
		"POST", "/api/v1/settings/custom_flag/delete", keyParams, nil)
	if reloadFailure.Response.StatusCode() != 500 {
		t.Fatalf("reload failure status = %d, want 500", reloadFailure.Response.StatusCode())
	}
	if !bytes.Contains(reloadFailure.Response.Body(), []byte("reload failed")) {
		t.Fatalf("reload failure body = %s, want it to mention the failure", bytes.TrimSpace(reloadFailure.Response.Body()))
	}
}

func TestListSettingsRedactsRedisPassword(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(store.SettingKeyRedisConfig, `{"enabled":true,"addr":"127.0.0.1:6379","password":"s3cr3t-redis-pass","db":0}`); err != nil {
		t.Fatalf("seed redis config: %v", err)
	}
	if err := repo.Set("plain_key", "plain-value"); err != nil {
		t.Fatalf("seed plain setting: %v", err)
	}

	ctx := invokeSettingsHandler(t, ListSettings(repo), "GET", "/api/v1/settings", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("list status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if bytes.Contains(ctx.Response.Body(), []byte("s3cr3t-redis-pass")) {
		t.Fatalf("settings list leaked the redis password: %s", bytes.TrimSpace(ctx.Response.Body()))
	}

	var resp struct {
		Items []store.SystemSettings `json:"items"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode settings list: %v", err)
	}
	var redisItem, plainItem *store.SystemSettings
	for i := range resp.Items {
		switch resp.Items[i].Key {
		case store.SettingKeyRedisConfig:
			redisItem = &resp.Items[i]
		case "plain_key":
			plainItem = &resp.Items[i]
		}
	}
	if redisItem == nil || plainItem == nil {
		t.Fatalf("settings list = %#v, want both seeded keys", resp.Items)
	}
	if !strings.Contains(redisItem.Value, "[redacted]") {
		t.Fatalf("redis config value = %q, want a redacted password", redisItem.Value)
	}
	if !strings.Contains(redisItem.Value, "127.0.0.1:6379") {
		t.Fatalf("redis config value = %q, want the non-secret addr preserved", redisItem.Value)
	}
	// 非敏感键必须原样返回。
	if plainItem.Value != "plain-value" {
		t.Fatalf("plain setting value = %q, want plain-value", plainItem.Value)
	}
}

func TestRedactSettingValue(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		wantFunc func(string) bool
	}{
		{
			name:     "non redis key passes through",
			key:      "plain_key",
			value:    `{"password":"visible"}`,
			wantFunc: func(got string) bool { return got == `{"password":"visible"}` },
		},
		{
			name:     "empty value passes through",
			key:      store.SettingKeyRedisConfig,
			value:    "",
			wantFunc: func(got string) bool { return got == "" },
		},
		{
			name:     "unparseable redis config is fully redacted",
			key:      store.SettingKeyRedisConfig,
			value:    "not-json",
			wantFunc: func(got string) bool { return got == "[redacted]" },
		},
		{
			name:  "empty password stays empty",
			key:   store.SettingKeyRedisConfig,
			value: `{"addr":"127.0.0.1:6379","password":""}`,
			wantFunc: func(got string) bool {
				return !strings.Contains(got, "[redacted]") && strings.Contains(got, "127.0.0.1:6379")
			},
		},
		{
			name:  "set password is redacted",
			key:   store.SettingKeyRedisConfig,
			value: `{"addr":"127.0.0.1:6379","password":"top-secret"}`,
			wantFunc: func(got string) bool {
				return strings.Contains(got, "[redacted]") && !strings.Contains(got, "top-secret")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactSettingValue(tt.key, tt.value)
			if !tt.wantFunc(got) {
				t.Fatalf("redactSettingValue(%q, %q) = %q", tt.key, tt.value, got)
			}
		})
	}
}

func TestGetSettingRedactsAndReports404(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	if err := repo.Set(store.SettingKeyRedisConfig, `{"addr":"127.0.0.1:6379","password":"another-secret"}`); err != nil {
		t.Fatalf("seed redis config: %v", err)
	}

	ok := invokeSettingsHandler(t, GetSetting(repo), "GET", "/api/v1/settings/"+store.SettingKeyRedisConfig,
		param.Params{{Key: "key", Value: store.SettingKeyRedisConfig}}, nil)
	if ok.Response.StatusCode() != 200 {
		t.Fatalf("get status %d: %s", ok.Response.StatusCode(), bytes.TrimSpace(ok.Response.Body()))
	}
	if bytes.Contains(ok.Response.Body(), []byte("another-secret")) {
		t.Fatalf("setting detail leaked the redis password: %s", bytes.TrimSpace(ok.Response.Body()))
	}

	missing := invokeSettingsHandler(t, GetSetting(repo), "GET", "/api/v1/settings/nope", param.Params{{Key: "key", Value: "nope"}}, nil)
	if missing.Response.StatusCode() != 404 {
		t.Fatalf("missing setting status = %d, want 404", missing.Response.StatusCode())
	}
}

func TestListSettingsReportsStoreFailure(t *testing.T) {
	ctx := invokeSettingsHandler(t, ListSettings(newBrokenSettingsRepoForTest(t)), "GET", "/api/v1/settings", nil, nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("store failure status = %d, want 500", ctx.Response.StatusCode())
	}
}
