package owasp

import "testing"

/**
 * TestSensitiveEndpointPathMatches 覆盖敏感端点规则的匹配语义：
 * 段边界前缀、大小写折叠、重复斜杠归一、方法约束。
 */
func TestSensitiveEndpointPathMatches(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		wantID string
	}{
		{"单段端点", "/jkstatus", "GET", "owasp:endpoint:011"},
		{"两段端点", "/crumbIssuer/api/xml", "GET", "owasp:endpoint:010"},
		{"重复斜杠归一", "//crumbIssuer/api/xml", "GET", "owasp:endpoint:010"},
		{"多斜杠归一", "/crumbIssuer//api/xml", "GET", "owasp:endpoint:010"},
		{"大小写折叠", "/Global-Protect/Login.ESP", "POST", "owasp:endpoint:001"},
		{"尾随子路径仍命中", "/actuator/gateway/routes/abc123", "DELETE", "owasp:endpoint:007"},
		{"方法约束满足", "/v1.24/containers/create", "POST", "owasp:endpoint:008"},
		{"尾随子路径带方法", "/rdweb/pages/en-US/login.aspx", "POST", "owasp:endpoint:029"},
	}
	for _, tc := range cases {
		hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method)
		if !ok {
			t.Errorf("%s: CheckSensitiveEndpointPath(%q, %q) 未命中，期望 %s", tc.name, tc.path, tc.method, tc.wantID)
			continue
		}
		if hit.RuleID != tc.wantID {
			t.Errorf("%s: 命中规则 = %q，期望 %q", tc.name, hit.RuleID, tc.wantID)
		}
		if hit.Score <= 0 || hit.Desc == "" {
			t.Errorf("%s: 命中缺少分值或说明: %+v", tc.name, hit)
		}
	}
}

/**
 * TestSensitiveEndpointPathRejects 覆盖不得命中的形态：
 * 方法不匹配、首段相同但端点不同、段边界不成立。
 */
func TestSensitiveEndpointPathRejects(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
	}{
		{"方法不匹配", "/global-protect/login.esp", "GET"},
		{"方法不匹配-删除规则", "/actuator/gateway/routes/abc", "GET"},
		{"首段相同次段不同", "/cgi-bin/userLogin", "POST"},
		{"首段相同次段不同-短", "/api/sonicos_other", "GET"},
		{"段边界不成立", "/xcrumbIssuer/api/xml", "GET"},
		{"段前缀不足", "/crumbIssuer", "GET"},
		{"泛化路径不收录", "/api/login", "POST"},
		{"泛化路径不收录-cli", "/cli", "POST"},
		{"泛化路径不收录-setup", "/setup", "POST"},
		{"泛化路径不收录-dl", "/dl/abc/def", "GET"},
		{"空路径", "", "GET"},
		{"仅斜杠", "/", "GET"},
		{"首段超长", "/" + string(make([]byte, 0)) + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/x", "GET"},
		// 调用方约定 path 不含查询串：数据面传的是 URI().PathOriginal()。
		// 这里锁定该前提——带查询串的输入不会被误判为命中，避免上游误用。
		{"带查询串不命中", "/cobbler_api?x=1", "POST"},
	}
	for _, tc := range cases {
		if hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method); ok {
			t.Errorf("%s: CheckSensitiveEndpointPath(%q, %q) 误命中 %s", tc.name, tc.path, tc.method, hit.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointRulesAreRegistered 校验每条敏感端点规则的元信息
 * 都进了内置规则目录，且 ID 唯一、类别与分值合法。
 *
 * 规则目录是管理端展示与规则级覆盖的唯一来源，漏登记会让新规则在 UI 上
 * 变成不可解释的裸 ID。
 */
func TestSensitiveEndpointRulesAreRegistered(t *testing.T) {
	byID := make(map[string]string)
	for _, item := range BuiltinRuleDefinitions() {
		byID[item.RuleID] = item.Description
	}
	seen := make(map[string]bool, len(sensitiveEndpointRules))
	for i := range sensitiveEndpointRules {
		rule := &sensitiveEndpointRules[i]
		if seen[rule.id] {
			t.Errorf("规则 ID 重复: %s", rule.id)
		}
		seen[rule.id] = true
		if rule.score <= 0 {
			t.Errorf("%s: 分值 %d 应大于 0", rule.id, rule.score)
		}
		if rule.desc == "" {
			t.Errorf("%s: 说明为空", rule.id)
		}
		if len(rule.segs) == 0 {
			t.Errorf("%s: 段序列为空", rule.id)
		}
		for _, seg := range rule.segs {
			if seg == "" {
				t.Errorf("%s: 段序列含空段", rule.id)
			}
			if seg != toLowerASCII(seg) {
				t.Errorf("%s: 段 %q 不是小写字面量", rule.id, seg)
			}
		}
		desc, ok := byID[rule.id]
		if !ok {
			t.Errorf("%s: 未登记进 BuiltinRuleDefinitions", rule.id)
			continue
		}
		if !containsHan(desc) {
			t.Errorf("%s: 目录说明 %q 未中文化", rule.id, desc)
		}
	}
}

/**
 * TestSensitiveEndpointSegmentScratchReuse 校验首/次段折叠缓冲区不会把
 * 长度不足的旧内容带进比较：同一缓冲区连续用于长短不同的两段时，
 * 次段比较必须按本次长度切片。
 */
func TestSensitiveEndpointSegmentScratchReuse(t *testing.T) {
	// 先调用一个次段很长的路径，再调用次段很短的路径。
	if _, ok := CheckSensitiveEndpointPath("/wp-content/plugins/adminimize/adminimize_page.php", "GET"); !ok {
		t.Fatal("长次段路径应命中")
	}
	if _, ok := CheckSensitiveEndpointPath("/vendor/.env", "GET"); !ok {
		t.Fatal("短次段路径应命中（缓冲区不得残留上一段内容）")
	}
	if _, ok := CheckSensitiveEndpointPath("/vendor/configuration.php", "GET"); ok {
		t.Fatal("次段不同不应命中")
	}
}
