package admin

import (
	"bytes"
	"os"
	"testing"

	"My-OpenWaf/internal/dataplane"
)

/**
 * TestBackupImportRegistersAccessSessionRevoke 守护备份恢复的会话吊销接线。
 *
 * 背景：备份恢复会整体改写 SiteAccessConfig / AccessProvider / AccessUser /
 * AccessPathRule，而访问控制会话存放在数据面的 globalAccessSessionStore（内存/
 * Redis，与库表无关），Gate.CheckAccess 只校验会话的 SiteID 与 ExpiresAt、
 * 不校验用户是否仍存在。若恢复后不吊销，被删用户的旧 token 在 TTL 到期前仍是
 * 有效凭证。
 *
 * 本用例做两件事：
 *   - 扫 router.go 的 adminGroup 块，断言 /backup/import 的 ImportBackup 闭包内
 *     确实调用了 dataplane.RevokeAllAccessSessions()（handler 存在但没接线这类
 *     缺口无法用路由表测试发现，沿用 router_test.go 既有的源码扫描策略）；
 *   - 直接调用 dataplane.RevokeAllAccessSessions()，确认控制面可以调用该入口
 *     且空存储下幂等不报错（顺带证明实际接线不存在 import 环）。
 */
func TestBackupImportRegistersAccessSessionRevoke(t *testing.T) {
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}

	adminBlock := extractGroupBlock(t, src, `adminGroup.Use(RequireRole(auth.RoleAdmin))`)
	idx := bytes.Index(adminBlock, []byte(`POST("/backup/import"`))
	if idx < 0 {
		t.Fatal(`adminGroup 内未注册 POST /backup/import`)
	}

	// 截取 ImportBackup(...) 的完整参数表：从首个左括号配对到对应的右括号，
	// 闭包与其中的吊销调用都落在这段区间内。
	rest := adminBlock[idx:]
	open := bytes.Index(rest, []byte("ImportBackup("))
	if open < 0 {
		t.Fatal(`/backup/import 未调用 system.ImportBackup`)
	}
	depth := 0
	end := -1
	for i := open + len("ImportBackup") - 1; i < len(rest); i++ {
		switch rest[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		t.Fatal("ImportBackup(...) 参数表未闭合")
	}
	call := rest[open : end+1]
	if !bytes.Contains(call, []byte("dataplane.RevokeAllAccessSessions()")) {
		t.Fatalf("ImportBackup 的失效回调内缺少 dataplane.RevokeAllAccessSessions()\n实际接线：\n%s", call)
	}

	// 控制面确实可调用该入口，且无会话时幂等。
	if err := dataplane.RevokeAllAccessSessions(); err != nil {
		t.Fatalf("RevokeAllAccessSessions from admin package: %v", err)
	}
	if err := dataplane.RevokeAllAccessSessions(); err != nil {
		t.Fatalf("RevokeAllAccessSessions must be idempotent: %v", err)
	}
}
