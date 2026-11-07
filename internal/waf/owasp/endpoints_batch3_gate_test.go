package owasp

import "testing"

/**
 * TestSensitiveEndpointBatch3QueryParamGate 锁定「参数存在性」闸门的边界：
 * 参数名折叠匹配、裸键不算、前缀/后缀近似不算、空查询串不算。
 *
 * 全部通过数据面入口 CheckSensitiveEndpointPathWithRequest 断言，不引用
 * 包内符号，因此在旧代码上可编译、并且必然断言失败（旧代码没有 191 规则）。
 */
func TestSensitiveEndpointBatch3QueryParamGate(t *testing.T) {
	positives := []string{
		"s=/index/qrcode/download/url/x",
		"S=/index/qrcode/download/url/x",
		"a=1&s=/index/think/app/invokefunction",
		"s=",
	}
	for _, q := range positives {
		hit, ok := CheckSensitiveEndpointPathWithRequest("/public/index.php", "GET", q, nil, nil)
		if !ok || hit.RuleID != "owasp:endpoint:191" {
			t.Errorf("query %q 应命中 owasp:endpoint:191，实际 ok=%v id=%q", q, ok, hit.RuleID)
		}
	}
	negatives := []string{
		"",
		"s",
		"sx=1",
		"xs=1",
		"a=1&bs=2",
	}
	for _, q := range negatives {
		if hit, ok := CheckSensitiveEndpointPathWithRequest("/public/index.php", "GET", q, nil, nil); ok {
			t.Errorf("query %q 不得命中，实际命中 %s", q, hit.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointBatch3GateRegistry 校验新增闸门的键都落在规则表内：
 * 每条登记了闸门的规则都必须能被同一条路径在闸门满足时命中、不满足时不命中。
 * 通过公开入口逐条验证，避免直接读包内表结构。
 */
func TestSensitiveEndpointBatch3GateRegistry(t *testing.T) {
	// 179 的 Action 闸门
	if hit, ok := CheckSensitiveEndpointPathWithRequest("/Admin/Access/Setup/Default.aspx", "GET", "action=createadministrator", nil, nil); !ok || hit.RuleID != "owasp:endpoint:179" {
		t.Errorf("179 小写参数名应命中，实际 ok=%v id=%q", ok, hit.RuleID)
	}
	for _, q := range []string{"", "action=setup", "xaction=createadministrator", "action=createadministratorx"} {
		if hit, ok := CheckSensitiveEndpointPathWithRequest("/Admin/Access/Setup/Default.aspx", "GET", q, nil, nil); ok {
			t.Errorf("179 query %q 不得命中，实际命中 %s", q, hit.RuleID)
		}
	}
	// 191 的 s 参数闸门在旧入口（无 query）下恒不命中，新入口满足时命中。
	if hit, ok := CheckSensitiveEndpointPath("/public/index.php", "GET"); ok {
		t.Errorf("旧入口不得命中 /public/index.php，实际命中 %s", hit.RuleID)
	}
	if hit, ok := CheckSensitiveEndpointPathWithRequest("/public/index.php", "GET", "s=/index/qrcode/download/url/x", nil, nil); !ok || hit.RuleID != "owasp:endpoint:191" {
		t.Errorf("新入口应命中 191，实际 ok=%v id=%q", ok, hit.RuleID)
	}
}
