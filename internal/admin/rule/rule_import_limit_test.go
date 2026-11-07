package rule

import (
	"encoding/json"
	"strings"
	"testing"
)

/**
 * TestImportRulesRejectsOversizedBatch 锁定导入条数上限。
 *
 * 导入侧原先对条数不设限：超限请求会先被完整解析成 []store.Rule，再逐条做
 * PolicyExists 查询，最后走一次批量写入。上限取 1000 是因为 repo.BatchCreate
 * 的 `tx.Create(&items)` 绑定变量数随条数线性增长，SQLite 默认变量数量上限
 * （2077）实测在 2000 条可用、2100 条即失败——上限设更高等于放行一批必然 500
 * 的请求。请求体字节数另由 admin server 的 WithMaxRequestBodySize 约束。
 */
func TestImportRulesRejectsOversizedBatch(t *testing.T) {
	repo := newRuleRepoForHandlerTest(t)

	rules := make([]map[string]any, 0, maxImportedRules+1)
	for i := 0; i <= maxImportedRules; i++ {
		rules = append(rules, map[string]any{
			"name":      "bulk",
			"policy_id": 1,
			"phase":     "custom",
			"pattern":   "block_path:/bulk",
			"action":    "intercept",
			"priority":  i + 1,
			"enabled":   true,
		})
	}
	payload, err := json.Marshal(map[string]any{"rules": rules})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	if len(payload) > 32<<20 {
		t.Fatalf("测试载荷 %d 字节超过 admin server 的请求体上限，构造方式需调整", len(payload))
	}

	reloaded := 0
	ctx := invokePersistedRuleHandler(t, ImportRules(repo, func() error {
		reloaded++
		return nil
	}), "/api/v1/rules/import", payload)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("超限导入应当 400，实际 %d: %s", ctx.Response.StatusCode(), strings.TrimSpace(string(ctx.Response.Body())))
	}
	if reloaded != 0 {
		t.Fatalf("被拒的导入不得触发 reload，实际 %d 次", reloaded)
	}

	_, total, err := repo.List(0, 1)
	if err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if total != 0 {
		t.Fatalf("被拒的导入不得写入任何规则，total=%d", total)
	}

	// 边界值本身必须放行：maxImportedRules 条可以导入。
	exact := make([]map[string]any, 0, maxImportedRules)
	for i := 0; i < maxImportedRules; i++ {
		exact = append(exact, map[string]any{
			"name":      "exact",
			"policy_id": 1,
			"phase":     "custom",
			"pattern":   "block_path:/exact",
			"action":    "intercept",
			"priority":  i + 1,
			"enabled":   true,
		})
	}
	exactPayload, err := json.Marshal(map[string]any{"rules": exact})
	if err != nil {
		t.Fatalf("encode exact payload: %v", err)
	}
	okCtx := invokePersistedRuleHandler(t, ImportRules(repo, func() error { return nil }),
		"/api/v1/rules/import", exactPayload)
	if okCtx.Response.StatusCode() != 200 {
		t.Fatalf("边界值 %d 条应当放行，实际 %d: %s", maxImportedRules, okCtx.Response.StatusCode(), strings.TrimSpace(string(okCtx.Response.Body())))
	}
	_, total, err = repo.List(0, 1)
	if err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if total != int64(maxImportedRules) {
		t.Fatalf("导入后 total = %d, want %d", total, maxImportedRules)
	}
}
