package action

import "testing"

// TestResultRuleInfoFieldsCarryThrough 守护 Result 的规则解释字段可被赋值
// 且不改变动作语义：新增字段只承载展示信息，IsTerminal/IsDrop 等判定
// 仍完全由 Type 与 Matched 决定。
func TestResultRuleInfoFieldsCarryThrough(t *testing.T) {
	r := Result{
		Type:         Intercept,
		Matched:      true,
		RuleIDStr:    "owasp:sqli:001",
		RuleName:     "SQL UNION 联合查询注入",
		RuleDesc:     "使用 UNION SELECT 追加攻击者控制的返回结果集",
		MatchScore:   7,
		MatchSnippet: "id=1 union select 1,2,3",
		MatchPart:    "body",
		Severity:     "critical",
		Source:       "nvd",
		CVSSScore:    9.8,
		CWEType:      "CWE-89",
		References:   "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
	}
	if !r.IsTerminal() || r.IsDrop() {
		t.Fatalf("rule-info fields changed action semantics: terminal=%v drop=%v", r.IsTerminal(), r.IsDrop())
	}
	if r.RuleName == "" || r.Severity == "" {
		t.Fatalf("fields did not round trip: %+v", r)
	}
}
