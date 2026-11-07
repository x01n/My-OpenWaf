package owasp

import (
	"strings"
	"testing"
)

/**
 * TestSensitiveEndpointBodyGateRules 锁定 087-090 的请求体闸门语义。
 *
 * 这四条规则覆盖的端点在语料黑白两侧同时出现，只有请求体字段能把设备的
 * 完整登录表单与精简登录表单分开，因此带闸门的规则必须同时满足
 * 「路径与方法匹配」与「请求体含登记字段」两个条件。
 */
func TestSensitiveEndpointBodyGateRules(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		body   string
		wantID string
	}{
		{
			name:   "087 SonicWall 完整表单",
			path:   "/cgi-bin/userLogin",
			method: "POST",
			body:   "username=postgres&password=Welcome2024%21&ajax=true&state=login&login=true&verifyCert=0&portalname=VirtualOffice&domain=BF",
			wantID: "owasp:endpoint:087",
		},
		{
			name:   "087 仅 portalname 也成立",
			path:   "/cgi-bin/userLogin",
			method: "POST",
			body:   "username=test&password=test&portalname=VirtualOffice",
			wantID: "owasp:endpoint:087",
		},
		{
			name:   "088 ASA 门户登录表单",
			path:   "/+webvpn+/index.html",
			method: "POST",
			body:   "language-selector=en&group_list=TGr-SERVICE&tgroup=&next=&tgcookieset=&Login=Login&username=admin&password=x",
			wantID: "owasp:endpoint:088",
		},
		{
			name:   "089 Fortinet 校验接口",
			path:   "/remote/logincheck",
			method: "POST",
			body:   "ajax=1&username=admin&realm=&credential=Passw0.1",
			wantID: "owasp:endpoint:089",
		},
		{
			name:   "090 NetScaler 完整表单",
			path:   "/cgi/login",
			method: "POST",
			body:   "login=jsmith&dummy_username=&dummy_pass1=&passwd=Spring2025",
			wantID: "owasp:endpoint:090",
		},
	}
	for _, tc := range cases {
		hit, ok := CheckSensitiveEndpointPathWithBody(tc.path, tc.method, []byte(tc.body))
		if !ok {
			t.Errorf("%s: 应命中 %s", tc.name, tc.wantID)
			continue
		}
		if hit.RuleID != tc.wantID {
			t.Errorf("%s: 命中 %s，期望 %s", tc.name, hit.RuleID, tc.wantID)
		}
	}
}

/**
 * TestSensitiveEndpointBodyGateRulesReject 覆盖闸门不成立时不得命中的形态。
 *
 * 其中「精简表单」一组是语料白侧的实测形态：同一端点、同一方法、同一
 * Content-Type，但字段名集合不同。闸门的存在理由就是这一组。
 */
func TestSensitiveEndpointBodyGateRulesReject(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		body   string
	}{
		{
			name:   "087 白侧精简表单",
			path:   "/cgi-bin/userLogin",
			method: "POST",
			body:   "username=cont001&password=Password%21&ajax=true",
		},
		{
			name:   "088 白侧精简表单",
			path:   "/+webvpn+/index.html",
			method: "POST",
			body:   "csrf_token=621aec6b&username=jsmith&password=Welcome2025&Login=Login",
		},
		{
			name:   "089 白侧登录后回跳",
			path:   "/remote/logincheck",
			method: "POST",
			body:   "username=guest&credential=guest&just_logged_in=1&redir=%2Fremote%2Findex",
		},
		{
			name:   "090 白侧精简表单",
			path:   "/cgi/login",
			method: "POST",
			body:   "login=test&passwd=e1e500721de714521f71",
		},
		{
			name:   "087 字段名前缀不成立",
			path:   "/cgi-bin/userLogin",
			method: "POST",
			body:   "xverifyCert=0&portalnamex=VirtualOffice",
		},
		{
			name:   "087 裸键不算命中",
			path:   "/cgi-bin/userLogin",
			method: "POST",
			body:   "verifyCert&portalname",
		},
		{
			name:   "088 字段在值里不算命中",
			path:   "/+webvpn+/index.html",
			method: "POST",
			body:   "next=tgcookieset%3D1",
		},
		{
			name:   "090 方法闸门排除 GET",
			path:   "/cgi/login",
			method: "GET",
			body:   "dummy_username=&dummy_pass1=&login=x&passwd=y",
		},
		{
			name:   "089 空请求体",
			path:   "/remote/logincheck",
			method: "POST",
			body:   "",
		},
	}
	for _, tc := range cases {
		if hit, ok := CheckSensitiveEndpointPathWithBody(tc.path, tc.method, []byte(tc.body)); ok {
			t.Errorf("%s: 不得命中，实际命中 %s", tc.name, hit.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointBodyGateNilBodyKeepsLegacyBehaviour 锁定向后兼容：
 * 不传请求体的旧签名对 087-090 恒不命中，对其余规则的行为不变。
 *
 * 这是「扩展签名不得改变既有 86 条规则行为」的守卫。
 */
func TestSensitiveEndpointBodyGateNilBodyKeepsLegacyBehaviour(t *testing.T) {
	for _, path := range []string{
		"/cgi-bin/userLogin",
		"/+webvpn+/index.html",
		"/remote/logincheck",
		"/cgi/login",
	} {
		if hit, ok := CheckSensitiveEndpointPath(path, "POST"); ok {
			t.Errorf("无请求体时 %q 不得命中，实际命中 %s", path, hit.RuleID)
		}
		if hit, ok := CheckSensitiveEndpointPathWithBody(path, "POST", nil); ok {
			t.Errorf("nil 请求体时 %q 不得命中，实际命中 %s", path, hit.RuleID)
		}
	}
	// 无闸门规则两条路径必须一致。
	for _, tc := range []struct{ path, method, wantID string }{
		{"/global-protect/login.esp", "POST", "owasp:endpoint:001"},
		{"/logincheck", "POST", "owasp:endpoint:085"},
		{"/boaform/admin/formlogin", "POST", "owasp:endpoint:086"},
		{"/jkstatus", "GET", "owasp:endpoint:011"},
	} {
		a, aok := CheckSensitiveEndpointPath(tc.path, tc.method)
		b, bok := CheckSensitiveEndpointPathWithBody(tc.path, tc.method, []byte("a=b"))
		if aok != bok || (aok && a.RuleID != b.RuleID) {
			t.Errorf("%q 两条入口行为不一致: legacy=(%v,%v) withBody=(%v,%v)", tc.path, aok, a, bok, b)
		}
		if !aok || a.RuleID != tc.wantID {
			t.Errorf("%q 期望命中 %s，实际 %v", tc.path, tc.wantID, aok)
		}
	}
}

/**
 * TestEndpointBodyHasField 锁定字段名匹配的边界口径：
 * name 之前必须是请求体首字节或 '&'，之后必须紧跟 '='。
 */
func TestEndpointBodyHasField(t *testing.T) {
	cases := []struct {
		body string
		name string
		want bool
	}{
		{"verifyCert=0", "verifyCert", true},
		{"a=1&verifyCert=0", "verifyCert", true},
		{"a=1&verifyCert=", "verifyCert", true},
		{"xverifyCert=0", "verifyCert", false},
		{"verifyCertx=0", "verifyCert", false},
		{"verifyCert", "verifyCert", false},
		{"a=verifyCert=0", "verifyCert", false},
		{"verifyCertx=0&verifyCert=1", "verifyCert", true},
		{"", "verifyCert", false},
		{"verifyCert=0", "", false},
	}
	for _, tc := range cases {
		if got := endpointBodyHasField([]byte(tc.body), tc.name); got != tc.want {
			t.Errorf("endpointBodyHasField(%q, %q) = %v, 期望 %v", tc.body, tc.name, got, tc.want)
		}
	}
}

/**
 * TestEndpointBodyGateFieldsNotGeneric 锁定闸门字段不含通用凭据字段名。
 *
 * username/password/login 一类字段在任何登录页都有，用作闸门等于把
 * 「端点 + 任意登录表单」变成判据，与收录口径相悖。
 */
func TestEndpointBodyGateFieldsNotGeneric(t *testing.T) {
	generic := map[string]bool{
		"username": true, "password": true, "login": true, "passwd": true,
		"user": true, "pass": true, "pwd": true, "email": true, "token": true,
	}
	for ruleID, fields := range endpointBodyGates {
		if len(fields) == 0 {
			t.Errorf("%s: 闸门字段为空，应删除该条目而不是留空", ruleID)
		}
		for _, field := range fields {
			if generic[strings.ToLower(field)] {
				t.Errorf("%s: 闸门字段 %q 属通用凭据字段", ruleID, field)
			}
		}
	}
	// 闸门键必须都能在规则表里找到，避免拼写错误导致闸门静默失效。
	known := make(map[string]bool, len(sensitiveEndpointRules))
	for i := range sensitiveEndpointRules {
		known[sensitiveEndpointRules[i].id] = true
	}
	for ruleID := range endpointBodyGates {
		if !known[ruleID] {
			t.Errorf("闸门键 %q 不在 sensitiveEndpointRules 中", ruleID)
		}
	}
}
