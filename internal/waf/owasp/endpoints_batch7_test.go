package owasp

import "testing"

/**
 * TestSensitiveEndpointBatch7Rules 锁定 206-208 三条设备接口规则的命中形态。
 *
 * 收录口径：全语料 140572 条按 endpoints.go 的真实段匹配语义重算，
 * videostream.cgi 黑侧 218 条中 216 条带明文凭据（白侧同端点 4 条中 2 条），
 * snapshot.cgi 黑侧 81 条中 69 条带凭据（白侧 77 条中 2 条），
 * ISAPI 认证接口黑侧 53 条全命中（白侧 1 条）。
 */
func TestSensitiveEndpointBatch7Rules(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		query  string
		wantID string
	}{
		{
			name:   "206 摄像头视频流明文凭据",
			path:   "/videostream.cgi",
			method: "GET",
			query:  "user=admin&pwd=admin",
			wantID: "owasp:endpoint:206",
		},
		{
			name:   "206 仅有用户名参数",
			path:   "/videostream.cgi",
			method: "GET",
			query:  "username=root",
			wantID: "owasp:endpoint:206",
		},
		{
			name:   "206 HEAD 探测形态",
			path:   "/videostream.cgi",
			method: "HEAD",
			query:  "pass=1q2w3e4r",
			wantID: "owasp:endpoint:206",
		},
		{
			name:   "207 摄像头快照明文凭据",
			path:   "/snapshot.cgi",
			method: "GET",
			query:  "user=admin144&pwd=admin144",
			wantID: "owasp:endpoint:207",
		},
		{
			name:   "207 passwd 参数名",
			path:   "/snapshot.cgi",
			method: "GET",
			query:  "passwd=guest",
			wantID: "owasp:endpoint:207",
		},
		{
			name:   "208 海康 ISAPI 认证接口",
			path:   "/ISAPI/Security/userCheck",
			method: "GET",
			query:  "",
			wantID: "owasp:endpoint:208",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, tc.query, nil, nil)
			if !ok {
				t.Fatalf("%s %s?%s 应命中 %s", tc.method, tc.path, tc.query, tc.wantID)
			}
			if hit.RuleID != tc.wantID {
				t.Errorf("命中规则 = %q，期望 %q", hit.RuleID, tc.wantID)
			}
		})
	}
}

/**
 * TestSensitiveEndpointBatch7Rejects 锁定 206-208 的反例。
 *
 * 不带凭据参数的同路径请求、参数名相似但不等的请求、以及路径少一段的请求
 * 都必须放行，避免把设备接口的正常访问与静态资源请求一并拦截。
 */
func TestSensitiveEndpointBatch7Rejects(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		query  string
	}{
		{
			name:   "206 无凭据参数",
			path:   "/videostream.cgi",
			method: "GET",
			query:  "",
		},
		{
			name:   "206 参数名相似但不等",
			path:   "/videostream.cgi",
			method: "GET",
			query:  "xuser=admin&pwd2=admin",
		},
		{
			name:   "206 裸键不算",
			path:   "/videostream.cgi",
			method: "GET",
			query:  "user&pwd",
		},
		{
			name:   "207 无凭据参数",
			path:   "/snapshot.cgi",
			method: "GET",
			query:  "channel=1&resolution=1920x1080",
		},
		{
			name:   "路径少一段",
			path:   "/ISAPI/Security",
			method: "GET",
			query:  "",
		},
		{
			name:   "首段相似但不等",
			path:   "/notisapi/Security/userCheck",
			method: "GET",
			query:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, tc.query, nil, nil)
			if ok {
				t.Errorf("%s %s?%s 不应命中，实际命中 %q", tc.method, tc.path, tc.query, hit.RuleID)
			}
		})
	}
}
