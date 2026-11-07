package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

/**
 * TestUpdateACMEConfigTriggersReload 是 B-1 的守门测试。
 *
 * UpdateACMEConfig 原先的签名根本不接收 reload，路由也未注入，因此保存
 * ACME 配置后不会有任何即时重协调：Manager() 的缓存键（Email/DirectoryURL/
 * CAA）虽然变了，但要等到下一次 renewDue tick 才被读取，期间已发布的
 * TLS/监听计划也不会重算。这违反 CLAUDE.md「配置变更必须触发注入的 reload 路径」。
 *
 * 断言：写库成功即调用 reload；reload 失败时按同包既有风格回 500 并带上
 * 「config applied but reload failed」，且此时响应体仍回显已保存的配置。
 */
func TestUpdateACMEConfigTriggersReload(t *testing.T) {
	t.Run("reload 成功", func(t *testing.T) {
		repo := newSystemSettingsRepoForTest(t)
		calls := 0
		ctx := invokeSystemConfigHandler(t, UpdateACMEConfig(repo, func() error {
			calls++
			return nil
		}), "POST", "/api/v1/certificates/acme/config", []byte(`{"enabled":true,"email":"admin@example.com"}`))

		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("status = %d, want 200: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		if calls != 1 {
			t.Fatalf("reload 调用次数 = %d, want 1（配置写入未触发 reload）", calls)
		}
	})

	t.Run("reload 失败", func(t *testing.T) {
		repo := newSystemSettingsRepoForTest(t)
		calls := 0
		ctx := invokeSystemConfigHandler(t, UpdateACMEConfig(repo, func() error {
			calls++
			return errReloadFailed
		}), "POST", "/api/v1/certificates/acme/config", []byte(`{"enabled":true,"email":"admin@example.com"}`))

		if calls != 1 {
			t.Fatalf("reload 调用次数 = %d, want 1", calls)
		}
		if ctx.Response.StatusCode() != 500 {
			t.Fatalf("status = %d, want 500: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
		var resp map[string]any
		if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		msg, _ := resp["error"].(string)
		if want := "config applied but reload failed:"; len(msg) < len(want) || msg[:len(want)] != want {
			t.Fatalf("error = %q, want 前缀 %q", msg, want)
		}
		// 写库已成功：配置必须真的落盘，不能因 reload 失败而回滚。
		if got := loadACMEConfig(repo); got.Email != "admin@example.com" {
			t.Fatalf("落盘 email = %q, want admin@example.com", got.Email)
		}
	})

	t.Run("nil reload 不 panic", func(t *testing.T) {
		repo := newSystemSettingsRepoForTest(t)
		ctx := invokeSystemConfigHandler(t, UpdateACMEConfig(repo, nil), "POST", "/api/v1/certificates/acme/config", []byte(`{"enabled":true,"email":"admin@example.com"}`))
		if ctx.Response.StatusCode() != 200 {
			t.Fatalf("status = %d, want 200: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	})
}

// errReloadFailed 是 reload 失败路径的固定错误。
var errReloadFailed = errors.New("reload boom")
