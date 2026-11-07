package owasprules

import (
	"encoding/json"
	"testing"
)

// TestListOWASPRulesGroupedCoversAllCategoriesAcrossDefaultPagination 验证
// include_grouped 的分类分组不受分页窗口影响。
//
// 背景：规则按 rule_id ASC 排序，总量（当前 640 条）已超过默认 page_size=500。
// xss、file_upload、template_injection 排在字典序末段，曾因 grouped 基于分页后的
// items 构建而整类缺席；前端站点防护页用 grouped[category] 判断「该类是否有规则」，
// 缺失时显示「(无规则)」并禁用整类防护入口。
func TestListOWASPRulesGroupedCoversAllCategoriesAcrossDefaultPagination(t *testing.T) {
	repo := newSystemSettingsRepoForTest(t)
	ctx := invokeOWASPGet(t, ListOWASPRulesFromRegistry(repo), "/api/v1/owasp-rules")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	var resp struct {
		Items   []owaspRuleView            `json:"items"`
		Grouped map[string][]owaspRuleView `json:"grouped"`
		Total   int                        `json:"total"`
		Stats   owaspRuleStats             `json:"stats"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) >= resp.Total {
		t.Skipf("默认分页窗口未截断（items=%d total=%d），本用例前提不成立", len(resp.Items), resp.Total)
	}
	// grouped 必须覆盖 stats 统计到的每一个分类，且条数与全量统计一致。
	for category, want := range resp.Stats.ByCategory {
		if got := len(resp.Grouped[category]); got != want {
			t.Errorf("category %q: grouped=%d want=%d（分页截断）", category, got, want)
		}
	}
	// 回归锚点：这三个分类位于 rule_id 字典序末段，是最先被默认分页截掉的类别。
	for _, category := range []string{"xss", "file_upload", "template_injection"} {
		if len(resp.Grouped[category]) == 0 {
			t.Errorf("category %q 未出现在 grouped 中", category)
		}
	}
}
