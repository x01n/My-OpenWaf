package owasp

import "testing"

func TestTemplateNestedParamExpansion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"两层展开", "${${x:-j}${w9i0:lv9w:f6:-n}}", true},
		{"空名展开", "${${::-j}}", true},
		{"紧邻形态", "${${", true},
		{"单层不成立", "${a:-j}${b:-n}", false},
		{"普通插值不成立", "${config}", false},
		{"内层无花括号不成立", "${a${b}}", false},
	}
	for _, tc := range cases {
		th := CompileThresholds("mid")
		hit, ok := FirstOWASPHitWithThresholds(th, "/", "", nil, []string{tc.in})
		if ok != tc.want {
			t.Errorf("%s: %q 命中=%v，期望 %v（实际规则 %s）", tc.name, tc.in, ok, tc.want, hit.RuleID)
		}
	}
	th := CompileThresholds("mid")
	hit, ok := FirstOWASPHitWithThresholds(th, "/", "", nil, []string{"${${::-j}${::-n}${::-d}${::-i}:ldap://x}"})
	if !ok {
		t.Fatal("嵌套展开 + jndi 协议前缀应命中")
	}
	if hit.Score < 4 {
		t.Errorf("命中分值 %d 低于 mid 档阈值，单条不足以跨阈", hit.Score)
	}
}
