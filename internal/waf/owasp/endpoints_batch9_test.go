package owasp

import "testing"

/**
 * TestSensitiveEndpointBatch9Rules 锁定 210（网关 gw.cgi URL 内 XML 明文凭据）。
 *
 * 收录口径：全语料 140572 条按「样本内任一子请求命中即判拦截」重算，
 * 黑侧命中 277 条子请求（其中 19 条已因 ;telnet 命令注入被主扫描拦截，
 * 实际新增 258 条），白侧 0 条命中。
 */
func TestSensitiveEndpointBatch9Rules(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		query  string
	}{
		{
			name:   "编码 XML 凭据",
			path:   "/cgi-bin/gw.cgi",
			method: "GET",
			query:  "xml=%3Cjuan+ver%3D%22%22+squ%3D%22%22%3E%3Crpermission+usr%3D%22admin%22+pwd%3D%22ULT%22%3E%3C/rpermission%3E%3C/juan%3E",
		},
		{
			name:   "未编码 XML 凭据",
			path:   "/cgi-bin/gw.cgi",
			method: "GET",
			query:  `xml=<juan ver="" squ="" dir="0"><rpermission usr="admin" pwd="admin12345"><config base=""/></rpermission></juan>`,
		},
		{
			name:   "属性名大小写",
			path:   "/cgi-bin/gw.cgi",
			method: "GET",
			query:  `xml=<juan><rpermission usr="admin" PWD="secret"/></juan>`,
		},
		{
			name:   "等号两侧空白",
			path:   "/cgi-bin/gw.cgi",
			method: "GET",
			query:  `xml=<juan><rpermission pwd = "secret"/></juan>`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, tc.query, nil, nil)
			if !ok {
				t.Fatalf("%s %s?%s 应命中 owasp:endpoint:210", tc.method, tc.path, tc.query)
			}
			if hit.RuleID != "owasp:endpoint:210" {
				t.Errorf("命中规则 = %q，期望 %q", hit.RuleID, "owasp:endpoint:210")
			}
		})
	}
}

/**
 * TestSensitiveEndpointBatch9Rejects 锁定 210 的反例。
 *
 * 空密码是正常的状态读取；非 GET 方法与同前缀的其他 CGI 不命中；
 * pppoePwd 之类的相似属性名不能当成 pwd。
 */
func TestSensitiveEndpointBatch9Rejects(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		query  string
	}{
		{
			name:   "空密码",
			path:   "/cgi-bin/gw.cgi",
			method: "GET",
			query:  `xml=<juan dir="0" squ="" ver=""><rpermission pwd="" usr="admin"><config base=""/></rpermission></juan>`,
		},
		{
			name:   "编码空密码",
			path:   "/cgi-bin/gw.cgi",
			method: "GET",
			query:  "xml=%3Cjuan%3E%3Crpermission+pwd%3D%22%22+usr%3D%22admin%22%3E%3C/juan%3E",
		},
		{
			name:   "无 pwd 属性",
			path:   "/cgi-bin/gw.cgi",
			method: "GET",
			query:  `xml=<juan><config base=""/></juan>`,
		},
		{
			name:   "相似属性名",
			path:   "/cgi-bin/gw.cgi",
			method: "GET",
			query:  `xml=<juan><envload pppoePwd="secret"/></juan>`,
		},
		{
			name:   "非 GET 方法",
			path:   "/cgi-bin/gw.cgi",
			method: "POST",
			query:  `xml=<juan><rpermission pwd="secret"/></juan>`,
		},
		{
			name:   "同前缀其他 CGI",
			path:   "/cgi-bin/other.cgi",
			method: "GET",
			query:  `xml=<juan><rpermission pwd="secret"/></juan>`,
		},
		{
			name:   "缺少 cgi-bin 前段",
			path:   "/gw.cgi",
			method: "GET",
			query:  `xml=<juan><rpermission pwd="secret"/></juan>`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, tc.query, nil, nil)
			if ok && hit.RuleID == "owasp:endpoint:210" {
				t.Errorf("%s %s?%s 不应命中 210", tc.method, tc.path, tc.query)
			}
		})
	}
}

/**
 * TestSensitiveEndpointBatch9GateRegistry 校验解码属性闸门的键都落在规则表内。
 */
func TestSensitiveEndpointBatch9GateRegistry(t *testing.T) {
	known := make(map[string]bool, len(sensitiveEndpointRules))
	for i := range sensitiveEndpointRules {
		known[sensitiveEndpointRules[i].id] = true
	}
	for ruleID, name := range endpointQueryDecodedAttrGates {
		if !known[ruleID] {
			t.Errorf("解码属性闸门键 %q 不在 sensitiveEndpointRules 中", ruleID)
		}
		if name == "" || name != toLowerASCII(name) {
			t.Errorf("%s: 属性名 %q 必须是非空小写字面量", ruleID, name)
		}
	}
}
