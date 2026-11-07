package owasp

import "testing"

/**
 * TestSensitiveEndpointSQLiRules 锁定 156-157 两条「SQL 族小族」端点判据。
 *
 * 这两条覆盖的形态在语料里的共同点是：**载荷本身落在既有 SQL 电池的抑制面
 * 之外**，因此只能靠「请求了哪个端点」判定。
 *
 *   - 156 NCCHR runScript：`script=select 1,111*333,user,...,10 from dual`，
 *     `select` 与 `from` 之间是逗号表达式列表，既有 sqli:001（union select）
 *     与 sqli:006（分号+引号）都不成立。
 *   - 157 CMS 分页接口：`id=(sleep(6))`，`sleep(` 前是 `(` 而非赋值或布尔
 *     上下文，正是 sqli:003 抑制器判为 JavaScript 误报的形态。
 *
 * 两条判据都在全语料 140572 条上验证过白侧命中为 0（156 要求完整四段，
 * `/ncchr/` 单段前缀另有 1 条白侧命中故不收窄到两段）。
 */
func TestSensitiveEndpointSQLiRules(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		wantID string
	}{
		{"156 NCCHR runScript", "/ncchr/attendScript/internal/runScript", "POST", "owasp:endpoint:156"},
		{"156 大小写折叠", "/ncchr/attendscript/internal/runscript", "post", "owasp:endpoint:156"},
		{"156 带路径参数", "/ncchr/attendScript/internal/runScript;jsessionid=abc", "POST", "owasp:endpoint:156"},
		{"157 CMS 分页接口", "/admin/ajax/pages.php", "GET", "owasp:endpoint:157"},
		{"157 双斜杠前缀", "//admin/ajax/pages.php", "GET", "owasp:endpoint:157"},
	}
	for _, tc := range cases {
		hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method)
		if !ok {
			t.Errorf("%s: %q 应命中 %s", tc.name, tc.path, tc.wantID)
			continue
		}
		if hit.RuleID != tc.wantID {
			t.Errorf("%s: %q 命中 %s，期望 %s", tc.name, tc.path, hit.RuleID, tc.wantID)
		}
	}
}

/**
 * TestSensitiveEndpointSQLiRulesReject 锁定 156-157 的收窄面。
 *
 * 每一条都是「前缀成立但整段不成立」或「方法不符」的形态，用于防止后续把
 * 段序列放宽成子串匹配。
 */
func TestSensitiveEndpointSQLiRulesReject(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
	}{
		{"156 只到 /ncchr/", "/ncchr/", "POST"},
		{"156 缺 internal 段", "/ncchr/attendScript/runScript", "POST"},
		{"156 段名近似", "/ncchr/attendScript/internal2/runScript", "POST"},
		{"156 方法不符", "/ncchr/attendScript/internal/runScript", "GET"},
		{"157 缺 admin 段", "/ajax/pages.php", "GET"},
		{"157 段名近似", "/admin/ajax/pages.php2", "GET"},
		{"157 方法不符", "/admin/ajax/pages.php", "POST"},
		{"157 段名被前缀包裹", "/admin/ajax/xpages.php", "GET"},
	}
	for _, tc := range cases {
		if hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method); ok && hit.RuleID == "owasp:endpoint:157" ||
			ok && hit.RuleID == "owasp:endpoint:156" {
			t.Errorf("%s: %q 不得命中 %s", tc.name, tc.path, hit.RuleID)
		}
	}
}
