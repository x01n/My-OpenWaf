package protect

import (
	"bytes"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

/**
 * newBrokenSystemSettingsRepoForTest 返回一个底层缺少 system_settings 表的仓储，
 * 用于驱动写入失败的 500 分支。
 */
func newBrokenSystemSettingsRepoForTest(t *testing.T) *repository.SystemSettingsRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

// TestHandlersReturn500WhenSettingsStoreIsUnavailable 验证配置写入失败时统一返回 500。
func TestHandlersReturn500WhenSettingsStoreIsUnavailable(t *testing.T) {
	cases := []struct {
		name    string
		handler func(*repository.SystemSettingsRepo) app.HandlerFunc
		uri     string
		body    []byte
	}{
		{
			name:    "bot_settings",
			handler: func(r *repository.SystemSettingsRepo) app.HandlerFunc { return UpdateBotSettings(r, nil) },
			uri:     "/api/v1/bot-settings/update",
			body:    []byte(`{"score_threshold":50}`),
		},
		{
			name:    "drop_policy",
			handler: func(r *repository.SystemSettingsRepo) app.HandlerFunc { return UpdateDropPolicy(r, nil) },
			uri:     "/api/v1/drop-policy/update",
			body:    []byte(`{"enabled":true}`),
		},
		{
			name: "captcha_config",
			handler: func(r *repository.SystemSettingsRepo) app.HandlerFunc {
				return UpdateCaptchaConfig(r, func() error { return nil })
			},
			uri:  "/api/v1/captcha/config",
			body: []byte(`{"captcha_enabled":true}`),
		},
		{
			name: "chain_config",
			handler: func(r *repository.SystemSettingsRepo) app.HandlerFunc {
				return UpdateChainConfig(r, func() error { return nil })
			},
			uri:  "/api/v1/chain/config",
			body: []byte(`{"chain_enabled":true}`),
		},
		{
			name: "protection_settings",
			handler: func(r *repository.SystemSettingsRepo) app.HandlerFunc {
				return PutProtectionSettings(r, func() error { return nil })
			},
			uri:  "/api/v1/protection-settings",
			body: []byte(`{"login_max_attempts":5}`),
		},
	}
	for _, tc := range cases {
		repo := newBrokenSystemSettingsRepoForTest(t)
		ctx := invokeProtectHandler(t, tc.handler(repo), "POST", tc.uri, tc.body)
		if ctx.Response.StatusCode() != 500 {
			t.Errorf("%s: expected 500 when the settings store is unavailable, got %d: %s", tc.name, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	}
}

// TestUpdateEscalationConfigReturns500WhenStoreIsUnavailable 验证升级配置写入失败返回 500。
func TestUpdateEscalationConfigReturns500WhenStoreIsUnavailable(t *testing.T) {
	repo := newBrokenSystemSettingsRepoForTest(t)
	ctx := invokeEscalationConfigHandler(t, UpdateEscalationConfig(repo, func() error { return nil }), []byte(`{"escalation_enabled":true}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 when the settings store is unavailable, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdateSensitivityConfigReturns500WhenStoreIsUnavailable 验证灵敏度写入失败返回 500。
func TestUpdateSensitivityConfigReturns500WhenStoreIsUnavailable(t *testing.T) {
	repo := newBrokenSystemSettingsRepoForTest(t)
	ctx := invokeSensitivityHandler(t, UpdateSensitivityConfig(repo, func() error { return nil }), "global", []byte(`{"category_sensitivity":{"sqli":"high"}}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 when the settings store is unavailable, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestPageTemplateHandlersReturn500WhenStoreIsUnavailable 验证页面模板保存/重置失败返回 500。
func TestPageTemplateHandlersReturn500WhenStoreIsUnavailable(t *testing.T) {
	repo := newBrokenSystemSettingsRepoForTest(t)

	ctx := invokePageTemplateHandler(t, UpdatePageTemplate(repo, func() error { return nil }), "POST", "block", []byte(`{"brand_name":"X"}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("update: expected 500 when the settings store is unavailable, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	ctx = invokePageTemplateHandler(t, ResetPageTemplate(repo, func() error { return nil }), "POST", "block", nil)
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("reset: expected 500 when the settings store is unavailable, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

/**
 * newSettingsRepoBlockingKeyForTest 返回一个可正常读写、但拒绝写入指定 key 的仓储。
 * 用于驱动「主配置已落库、跨页同步失败」这一部分失败分支。
 */
func newSettingsRepoBlockingKeyForTest(t *testing.T, blockedKey string) *repository.SystemSettingsRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.SystemSettings{}); err != nil {
		t.Fatalf("migrate settings: %v", err)
	}
	// SQLite 的 CREATE TRIGGER 不支持绑定变量，key 只能内联；限制取值以避免拼接出意外语句。
	switch blockedKey {
	case "protection", "bot_settings", "drop_policy":
	default:
		t.Fatalf("unsupported blocked key %q", blockedKey)
	}
	trigger := "CREATE TRIGGER block_key BEFORE INSERT ON system_settings WHEN NEW.key = '" + blockedKey + "' " +
		"BEGIN SELECT RAISE(ABORT, 'write blocked'); END"
	if err := db.Exec(trigger).Error; err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	return repository.NewSystemSettingsRepo(db)
}

// TestPutProtectionSettingsReturns500WhenBotSyncFails 验证同步 bot_settings 失败时返回 500，
// 此时事务会回滚 protection，且 reload 不会执行。
func TestPutProtectionSettingsReturns500WhenBotSyncFails(t *testing.T) {
	repo := newSettingsRepoBlockingKeyForTest(t, "bot_settings")
	reloaded := false
	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error {
		reloaded = true
		return nil
	}), "POST", "/api/v1/protection-settings", []byte(`{"bot_detection_enabled":true}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 when bot_settings sync fails, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if reloaded {
		t.Fatal("reload must not run after a failed sync")
	}
	if val, err := repo.Get("protection"); err == nil && val != "" {
		t.Fatal("protection must roll back when bot_settings sync fails")
	}
}

// TestPutProtectionSettingsReturns500WhenCVEAutoDropSyncFails 验证同步 drop_policy 失败时返回 500。
func TestPutProtectionSettingsReturns500WhenCVEAutoDropSyncFails(t *testing.T) {
	repo := newSettingsRepoBlockingKeyForTest(t, "drop_policy")
	ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", []byte(`{"cve_auto_drop_critical":false,"cve_auto_drop_high":false}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 when drop_policy sync fails, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdateBotSettingsReturns500WhenProtectionSyncFails 验证 bot 页同步 protection 失败时返回 500。
func TestUpdateBotSettingsReturns500WhenProtectionSyncFails(t *testing.T) {
	repo := newSettingsRepoBlockingKeyForTest(t, "protection")
	for _, body := range [][]byte{
		[]byte(`{"enabled":true}`),
		[]byte(`{"captcha_enabled":true}`),
		[]byte(`{"browser_sign_enabled":true}`),
	} {
		ctx := invokeProtectHandler(t, UpdateBotSettings(repo, func() error { return nil }), "POST", "/api/v1/bot-settings/update", body)
		if ctx.Response.StatusCode() != 500 {
			t.Errorf("body=%s: expected 500 when protection sync fails, got %d: %s", body, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	}
}

// TestUpdateBotSettingsReturns500WhenDropPolicySyncFails 验证 bot 阈值反向同步 drop_policy 失败时返回 500。
func TestUpdateBotSettingsReturns500WhenDropPolicySyncFails(t *testing.T) {
	repo := newSettingsRepoBlockingKeyForTest(t, "drop_policy")
	ctx := invokeProtectHandler(t, UpdateBotSettings(repo, func() error { return nil }), "POST", "/api/v1/bot-settings/update", []byte(`{"score_threshold":51}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 when drop_policy sync fails, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdateDropPolicyReturns500WhenBotSettingsSyncFails 验证 drop 页反向同步 bot_settings 失败时返回 500。
func TestUpdateDropPolicyReturns500WhenBotSettingsSyncFails(t *testing.T) {
	repo := newSettingsRepoBlockingKeyForTest(t, "bot_settings")
	ctx := invokeProtectHandler(t, UpdateDropPolicy(repo, func() error { return nil }), "POST", "/api/v1/drop-policy/update", []byte(`{"bot_score_threshold":59}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 when bot_settings sync fails, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestUpdateDropPolicyReturns500WhenProtectionSaveFails 验证 drop 页写回 protection 失败时返回 500。
func TestUpdateDropPolicyReturns500WhenProtectionSaveFails(t *testing.T) {
	repo := newSettingsRepoBlockingKeyForTest(t, "protection")
	ctx := invokeProtectHandler(t, UpdateDropPolicy(repo, func() error { return nil }), "POST", "/api/v1/drop-policy/update", []byte(`{"enabled":true}`))
	if ctx.Response.StatusCode() != 500 {
		t.Fatalf("expected 500 when protection save fails, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestPutProtectionSettingsRejectsTypeMismatchedField 验证字段类型与 ProtectionConfig 不符时返回 400。
func TestPutProtectionSettingsRejectsTypeMismatchedField(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	for _, body := range [][]byte{
		[]byte(`{"cve_enabled":"yes"}`),
		[]byte(`{"login_max_attempts":"many"}`),
		[]byte(`{"builtin_owasp_on_hit":123}`),
	} {
		ctx := invokeProtectHandler(t, PutProtectionSettings(repo, func() error { return nil }), "POST", "/api/v1/protection-settings", body)
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("body=%s: expected 400, got %d: %s", body, ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	}
}
