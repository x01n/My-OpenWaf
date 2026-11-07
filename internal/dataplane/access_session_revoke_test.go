package dataplane

import (
	"testing"
)

/**
 * TestRevokeAllAccessSessionsClearsGlobalStore 验证控制面使用的全量吊销入口
 * RevokeAllAccessSessions 会把包级全局会话存储中的既有会话全部作废。
 *
 * 覆盖三条产品语义：
 *   - 吊销后任何既有 token 的 Validate 返回 nil（备份恢复即权限重置的依据）；
 *   - 吊销幂等：无会话时再次调用不报错；
 *   - 吊销后仍能创建并校验新会话（防「一次吊销让全站无法登录」）。
 *
 * 作用域说明：globalAccessSessionStore 是包级全局变量，本用例会清空它。同包
 * 其他用例（access_control_test.go、replay_revoke_test.go、handler_js_quickjs_test.go）
 * 都在用例内自行 Create 并使用自己的 token，不依赖跨用例残留，且包内测试串行
 * 执行，因此清空不会影响它们。
 */
func TestRevokeAllAccessSessionsClearsGlobalStore(t *testing.T) {
	const sessionCount = 3
	tokens := make([]string, 0, sessionCount)
	for i := 0; i < sessionCount; i++ {
		token, err := globalAccessSessionStore.Create(uint(i+1), "backup-restore-user", "password", 3600)
		if err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		tokens = append(tokens, token)
	}
	for i, token := range tokens {
		if info, _ := globalAccessSessionStore.Validate(token); info == nil {
			t.Fatalf("session #%d should exist before revoke", i)
		}
	}

	if err := RevokeAllAccessSessions(); err != nil {
		t.Fatalf("RevokeAllAccessSessions: %v", err)
	}

	for i, token := range tokens {
		info, err := globalAccessSessionStore.Validate(token)
		if err != nil {
			t.Fatalf("Validate after revoke #%d: %v", i, err)
		}
		if info != nil {
			t.Fatalf("session #%d should be gone after RevokeAllAccessSessions, got %+v", i, info)
		}
	}

	// 幂等：空存储上再次吊销不报错。
	if err := RevokeAllAccessSessions(); err != nil {
		t.Fatalf("RevokeAllAccessSessions on empty store: %v", err)
	}

	fresh, err := globalAccessSessionStore.Create(7, "after-restore", "password", 3600)
	if err != nil {
		t.Fatalf("Create after revoke: %v", err)
	}
	t.Cleanup(func() { _ = globalAccessSessionStore.Revoke(fresh) })
	info, err := globalAccessSessionStore.Validate(fresh)
	if err != nil {
		t.Fatalf("Validate after revoke + Create: %v", err)
	}
	if info == nil {
		t.Fatal("new session must remain usable after RevokeAllAccessSessions")
	}
	if info.SiteID != 7 || info.Identity != "after-restore" {
		t.Fatalf("new session unexpected: %+v", info)
	}
}
