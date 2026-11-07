package owasp

import "testing"

/**
 * TestSensitiveEndpointCorpusBatchLegacyEntryOnly 只调用本批之前就存在的
 * 公开入口（CheckSensitiveEndpointPath / CheckSensitiveEndpointPathWithBody /
 * CheckSensitiveEndpointPathWithHeaders），因此在缺少新规则的旧代码上可
 * 编译，但必然断言失败——这就是「旧代码必红」的可运行证据。
 */
func TestSensitiveEndpointCorpusBatchLegacyEntryOnly(t *testing.T) {
	// 166/167/172 带查询串闸门：旧入口不传 query，恒不命中。
	for _, tc := range []struct{ path, method string }{
		{"/server/load.php", "GET"},
		{"/portal.php", "GET"},
		{"/onvif-http/snapshot", "GET"},
	} {
		if hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method); ok {
			t.Errorf("旧入口 %q 不得命中，实际命中 %s", tc.path, hit.RuleID)
		}
	}
	// 170/171 无闸门：两条旧入口都应命中（旧代码没有这批规则，必然红）。
	for _, tc := range []struct{ path, method, wantID string }{
		{"/bot/statistic", "POST", "owasp:endpoint:170"},
		{"/images/vos3000.ico", "GET", "owasp:endpoint:171"},
	} {
		a, aok := CheckSensitiveEndpointPath(tc.path, tc.method)
		b, bok := CheckSensitiveEndpointPathWithHeaders(tc.path, tc.method, nil, nil)
		if aok != bok || (aok && a.RuleID != b.RuleID) {
			t.Errorf("%q 两条入口行为不一致: legacy=(%v,%v) withHeaders=(%v,%v)", tc.path, aok, a, bok, b)
		}
		if !aok || a.RuleID != tc.wantID {
			t.Errorf("%q 期望命中 %s，实际 ok=%v id=%q", tc.path, tc.wantID, aok, a.RuleID)
		}
	}
	// 168/169 带请求体标记闸门：带 body 的 withHeaders 入口应命中。
	for _, tc := range []struct{ path, body, wantID string }{
		{"/api/user/reg", `{"email":"x","username":"y"}`, "owasp:endpoint:168"},
		{"/xmlrpc.php", "<system.listMethods>", "owasp:endpoint:169"},
	} {
		hit, ok := CheckSensitiveEndpointPathWithHeaders(tc.path, "POST", nil, []byte(tc.body))
		if !ok || hit.RuleID != tc.wantID {
			t.Errorf("%q 期望命中 %s，实际 ok=%v id=%q", tc.path, tc.wantID, ok, hit.RuleID)
		}
	}
	// 173/174 带 Basic 闸门：带认证头的 withHeaders 入口应命中。
	for _, tc := range []struct {
		path    string
		headers map[string]string
		wantID  string
	}{
		{
			path:    "/manager/html",
			headers: map[string]string{"authorization": "Basic YWRtaW46dG9tY2F0MTIz"},
			wantID:  "owasp:endpoint:173",
		},
		{
			path:    "/VERM/VERM_AJAX_functions.php",
			headers: map[string]string{"authorization": "Basic Z29vbGlja2VyJywgJycsIChTRUxFQ1QgKE5VTEwpKSk7IyA6cGFzc3dvcmQ="},
			wantID:  "owasp:endpoint:174",
		},
	} {
		hit, ok := CheckSensitiveEndpointPathWithHeaders(tc.path, "GET", tc.headers, nil)
		if !ok || hit.RuleID != tc.wantID {
			t.Errorf("%q 期望命中 %s，实际 ok=%v id=%q", tc.path, tc.wantID, ok, hit.RuleID)
		}
	}
	// 088 增强：新字段并集（csrfmiddlewaretoken 等）应命中。
	hit, ok := CheckSensitiveEndpointPathWithHeaders("/+webvpn+/index.html", "POST", nil,
		[]byte("csrfmiddlewaretoken=e9tI&__csrf_magic=key:12eef&page=login&username=olvo&password=x"))
	if !ok || hit.RuleID != "owasp:endpoint:088" {
		t.Errorf("088 增强字段期望命中，实际 ok=%v id=%q", ok, hit.RuleID)
	}
}
