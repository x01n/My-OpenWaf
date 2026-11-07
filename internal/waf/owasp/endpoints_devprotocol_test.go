package owasp

import (
	"strings"
	"testing"
)

/**
 * TestSensitiveEndpointDeviceProtocolRules 锁定 158-165 这批「协议/设备端点」
 * 判据的命中形态。
 *
 * 这批规则与 087-090 的差别：闸门不看表单字段名，而看协议层标记
 * （Content-Type、Side 头、SOAP 命名空间），因为它们的黑样本本身就是
 * 协议实现（DoH 客户端、WinRM 客户端、HNAP1 设备管理、Nacos 运维脚本、
 * Jenkins CLI），请求体的形态由协议决定而非表单决定。
 */
func TestSensitiveEndpointDeviceProtocolRules(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		method  string
		headers map[string]string
		body    string
		wantID  string
	}{
		{
			name:   "158 DoH 首段",
			path:   "/dns-query",
			method: "GET",
			wantID: "owasp:endpoint:158",
		},
		{
			name:   "158 大小写折叠",
			path:   "/DNS-Query",
			method: "POST",
			wantID: "owasp:endpoint:158",
		},
		{
			name:   "158 双斜杠归一",
			path:   "//dns-query",
			method: "GET",
			wantID: "owasp:endpoint:158",
		},
		{
			name:    "159 WinRM SOAP",
			path:    "/wsman",
			method:  "POST",
			headers: map[string]string{"content-type": "application/soap+xml;charset=UTF-8"},
			body:    `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"></s:Envelope>`,
			wantID:  "owasp:endpoint:159",
		},
		{
			name:    "159 WinRM text/xml",
			path:    "/wsman",
			method:  "POST",
			headers: map[string]string{"content-type": "text/xml;charset=UTF-8"},
			body:    `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"/>`,
			wantID:  "owasp:endpoint:159",
		},
		{
			name:    "160 HNAP1 SOAP",
			path:    "/HNAP1/",
			method:  "POST",
			headers: map[string]string{"content-type": "text/xml; charset=UTF-8"},
			body:    `<soap:Body><IsDeviceReady xmlns="http://purenetworks.com/HNAP1/"/></soap:Body>`,
			wantID:  "owasp:endpoint:160",
		},
		{
			name:   "161 Nacos derby",
			path:   "/nacos/v1/cs/ops/derby",
			method: "GET",
			wantID: "owasp:endpoint:161",
		},
		{
			name:   "162 Nacos servers",
			path:   "/nacos/v1/ns/operator/servers",
			method: "HEAD",
			wantID: "owasp:endpoint:162",
		},
		{
			name:   "163 Nacos configs",
			path:   "/nacos/v1/cs/configs",
			method: "POST",
			wantID: "owasp:endpoint:163",
		},
		{
			name:   "164 Nacos login",
			path:   "/nacos/v1/auth/login",
			method: "POST",
			wantID: "owasp:endpoint:164",
		},
		{
			name:    "165 Jenkins CLI 上传侧",
			path:    "/cli",
			method:  "POST",
			headers: map[string]string{"side": "upload", "session": "dbf5cb3f"},
			body:    "\x00\x00\x00\x0c\x00\x00\nenable-job",
			wantID:  "owasp:endpoint:165",
		},
		{
			name:    "165 Jenkins CLI 下载侧",
			path:    "/cli",
			method:  "POST",
			headers: map[string]string{"side": "download", "session": "7fe93e4f-8743"},
			wantID:  "owasp:endpoint:165",
		},
	}
	for _, tc := range cases {
		hit, ok := CheckSensitiveEndpointPathWithHeaders(tc.path, tc.method, tc.headers, []byte(tc.body))
		if !ok {
			t.Errorf("%s: 应命中 %s", tc.name, tc.wantID)
			continue
		}
		if hit.RuleID != tc.wantID {
			t.Errorf("%s: 命中 %s，期望 %s", tc.name, hit.RuleID, tc.wantID)
		}
		if hit.Score <= 0 || hit.Desc == "" {
			t.Errorf("%s: 命中缺少分值或说明: %+v", tc.name, hit)
		}
	}
}

/**
 * TestSensitiveEndpointDeviceProtocolRulesReject 锁定这批规则不得覆盖的
 * 白侧形态。
 *
 * 全部来自全语料白侧实测：裸路径的设备发现探测（`/wsman`、
 * `/HNAP1` 的 GET/HEAD）、WinRM 会话续传的 multipart/encrypted 请求、
 * HNAP1 的空 SOAPAction 表单、Jenkins CLI 的 GET 查询与正常 Nacos 控制台。
 */
func TestSensitiveEndpointDeviceProtocolRulesReject(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		method  string
		headers map[string]string
		body    string
	}{
		{
			name:   "158 首段近似",
			path:   "/dns-query-cache",
			method: "GET",
		},
		{
			name:   "158 段内前缀不成立",
			path:   "/xdns-query",
			method: "GET",
		},
		{
			name:    "159 WinRM 会话续传",
			path:    "/wsman",
			method:  "POST",
			headers: map[string]string{"content-type": `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted"`},
			body:    "--Encrypted Boundary",
		},
		{
			name:   "159 裸路径 GET",
			path:   "/wsman",
			method: "GET",
		},
		{
			name:    "159 非 SOAP Content-Type",
			path:    "/wsman",
			method:  "POST",
			headers: map[string]string{"content-type": "application/octet-stream"},
			body:    "<s:Envelope/>",
		},
		{
			name:    "160 HNAP1 空 SOAPAction",
			path:    "/HNAP1/",
			method:  "POST",
			headers: map[string]string{"soapaction": `""`},
			body:    `<?xml version="1.0"?><soap:Envelope><soap:Body>< xmlns=""/></soap:Body></soap:Envelope>`,
		},
		{
			name:   "160 HNAP1 裸路径 GET",
			path:   "/HNAP1",
			method: "GET",
		},
		{
			name:   "160 HNAP1 HEAD",
			path:   "/HNAP1/",
			method: "HEAD",
		},
		{
			name:   "161 Nacos 控制台静态资源",
			path:   "/nacos/console-ui/public/js/codemirror.js",
			method: "GET",
		},
		{
			name:   "161 Nacos 根页",
			path:   "/nacos/",
			method: "GET",
		},
		{
			name:   "164 Nacos 用户列表接口",
			path:   "/nacos/v1/auth/users",
			method: "GET",
		},
		{
			name:   "165 Jenkins CLI GET 查询",
			path:   "/cli",
			method: "GET",
		},
		{
			name:    "165 无 Side 头的 POST",
			path:    "/cli",
			method:  "POST",
			headers: map[string]string{"content-type": "text/plain"},
		},
	}
	for _, tc := range cases {
		if hit, ok := CheckSensitiveEndpointPathWithHeaders(tc.path, tc.method, tc.headers, []byte(tc.body)); ok {
			t.Errorf("%s: 不得命中，实际命中 %s", tc.name, hit.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointHeadersEntryKeepsLegacyBehaviour 锁定向后兼容：
 * 不传请求头/请求体的旧入口对 159/160/165 恒不命中，对其余规则行为不变。
 */
func TestSensitiveEndpointHeadersEntryKeepsLegacyBehaviour(t *testing.T) {
	for _, tc := range []struct{ path, method string }{
		{"/wsman", "POST"},
		{"/HNAP1/", "POST"},
		{"/cli", "POST"},
	} {
		if hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method); ok {
			t.Errorf("无请求头时 %q 不得命中，实际命中 %s", tc.path, hit.RuleID)
		}
	}
	// 158 与 161-164 无闸门，两条入口必须一致。
	for _, tc := range []struct{ path, method, wantID string }{
		{"/dns-query", "GET", "owasp:endpoint:158"},
		{"/dns-query", "POST", "owasp:endpoint:158"},
		{"/nacos/v1/cs/ops/derby", "GET", "owasp:endpoint:161"},
		{"/nacos/v1/ns/operator/servers", "HEAD", "owasp:endpoint:162"},
		{"/nacos/v1/cs/configs", "POST", "owasp:endpoint:163"},
		{"/nacos/v1/auth/login", "POST", "owasp:endpoint:164"},
	} {
		a, aok := CheckSensitiveEndpointPath(tc.path, tc.method)
		b, bok := CheckSensitiveEndpointPathWithHeaders(tc.path, tc.method, nil, nil)
		if aok != bok || (aok && a.RuleID != b.RuleID) {
			t.Errorf("%q 两条入口行为不一致: legacy=(%v,%v) withHeaders=(%v,%v)", tc.path, aok, a, bok, b)
		}
		if !aok || a.RuleID != tc.wantID {
			t.Errorf("%q 期望命中 %s，实际 %v/%v", tc.path, tc.wantID, aok, a.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointDeviceProtocolLegacyEntry 只用本次改动之前就存在的
 * 两个公开入口做断言，因此在缺少新规则的旧代码上仍可编译、但必然断言失败。
 *
 * 该用例的作用是给出「旧代码必红」的可编译证据：其余用例引用新入口
 * （CheckSensitiveEndpointPathWithHeaders）时在旧代码上会直接构建失败，
 * 无法单独证明「规则表里没有这批规则」这一事实。
 */
func TestSensitiveEndpointDeviceProtocolLegacyEntry(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		wantID string
	}{
		{"158 DoH", "/dns-query", "GET", "owasp:endpoint:158"},
		{"158 DoH POST", "/dns-query", "POST", "owasp:endpoint:158"},
		{"161 Nacos derby", "/nacos/v1/cs/ops/derby", "GET", "owasp:endpoint:161"},
		{"162 Nacos servers", "/nacos/v1/ns/operator/servers", "HEAD", "owasp:endpoint:162"},
		{"163 Nacos configs", "/nacos/v1/cs/configs", "POST", "owasp:endpoint:163"},
		{"164 Nacos login", "/nacos/v1/auth/login", "POST", "owasp:endpoint:164"},
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
	}
	// 159/160/165 只在带闸门的新入口命中；旧入口（空头与空体）恒不命中，
	// 因此断言的是「不得命中」，这正是旧代码与当前代码行为一致的守卫。
	for _, tc := range []struct{ path, method string }{
		{"/wsman", "POST"},
		{"/HNAP1/", "POST"},
		{"/cli", "POST"},
	} {
		if hit, ok := CheckSensitiveEndpointPathWithBody(tc.path, tc.method, nil); ok {
			t.Errorf("空头空体时 %q 不得命中，实际命中 %s", tc.path, hit.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointDeviceProtocolGateRegistries 锁定闸门表自身的完整性：
 * 键必须落在规则表内，闸门值非空，且不含通用身份字段或过宽的匹配串。
 */
func TestSensitiveEndpointDeviceProtocolGateRegistries(t *testing.T) {
	known := make(map[string]bool, len(sensitiveEndpointRules))
	for i := range sensitiveEndpointRules {
		known[sensitiveEndpointRules[i].id] = true
	}
	generic := map[string]bool{
		"username": true, "password": true, "login": true, "user-agent": true,
		"accept": true, "host": true, "cookie": true, "referer": true,
	}
	for ruleID, gates := range endpointHeaderGates {
		if !known[ruleID] {
			t.Errorf("请求头闸门键 %q 不在 sensitiveEndpointRules 中", ruleID)
		}
		if len(gates) == 0 {
			t.Errorf("%s: 请求头闸门为空，应删除该条目而不是留空", ruleID)
		}
		for _, gate := range gates {
			if gate.name == "" || gate.contains == "" {
				t.Errorf("%s: 请求头闸门项不完整: %+v", ruleID, gate)
			}
			if generic[strings.ToLower(gate.name)] {
				t.Errorf("%s: 请求头闸门 %q 属通用请求头", ruleID, gate.name)
			}
			if gate.name != strings.ToLower(gate.name) {
				t.Errorf("%s: 请求头闸门名 %q 必须是小写字面量", ruleID, gate.name)
			}
		}
	}
	for ruleID, markers := range endpointBodyContainsGates {
		if !known[ruleID] {
			t.Errorf("请求体标记闸门键 %q 不在 sensitiveEndpointRules 中", ruleID)
		}
		if len(markers) == 0 {
			t.Errorf("%s: 请求体标记闸门为空，应删除该条目而不是留空", ruleID)
		}
	}
	// 闸门键不得出现在 endpointBodyGates 与 endpointBodyContainsGates 两处，
	// 否则「同一路径的两套闸门」会变成隐式的或语义。
	for ruleID := range endpointBodyContainsGates {
		if _, ok := endpointBodyGates[ruleID]; ok {
			t.Errorf("%s: 同时登记在表单字段闸门与请求体标记闸门", ruleID)
		}
	}
}
