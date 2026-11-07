package owasp

import "testing"

/**
 * TestSensitiveEndpointPathSegmentBoundary 锁定段边界语义：
 * 端点名必须整段相等，`/dana-naxxx` 不得命中 `/dana-na` 规则。
 */
func TestSensitiveEndpointPathSegmentBoundary(t *testing.T) {
	if _, ok := CheckSensitiveEndpointPath("/dana-na/nc/nc_gina_ver.txt", "GET"); !ok {
		t.Fatal("/dana-na/nc/nc_gina_ver.txt 应命中")
	}
	for _, path := range []string{
		"/dana-naxxx",
		"/dana-naxxx/nc/nc_gina_ver.txt",
		"/dana-na2/nc/nc_gina_ver.txt",
		"/xdana-na/nc/nc_gina_ver.txt",
		"/foo/dana-na/nc/nc_gina_ver.txt",
		"/wgcgi.cgix",
		"/logincheckx",
		"/jsproxyx",
		"/crumbissuerx/api/xml",
		"/crumbissuer/api/xmlx",
		"/crumbIssuer/api",
	} {
		if hit, ok := CheckSensitiveEndpointPath(path, "GET"); ok {
			t.Errorf("%q 被前缀误伤，命中 %s", path, hit.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointPathSemicolonSegment 锁定 `;` 切段：
 * 段内分号之后是路径参数（Tomcat/Spring 语义），端点名在分号之前。
 * 语料实测：9453 条含分号样本中，仅因分号切段新增的命中为 0（黑 0 / 白 0），
 * 因此该归一化不引入新误报，只补齐 `;jsessionid=` 一类变形。
 */
func TestSensitiveEndpointPathSemicolonSegment(t *testing.T) {
	cases := []struct {
		path   string
		method string
		wantID string
	}{
		{"/crumbissuer/api/xml;a=b", "GET", "owasp:endpoint:010"},
		{"/crumbissuer;a=b/api/xml", "GET", "owasp:endpoint:010"},
		{"/dana-na/nc/nc_gina_ver.txt;jsessionid=abc", "GET", "owasp:endpoint:004"},
		{"/jkstatus;a=1", "GET", "owasp:endpoint:011"},
	}
	for _, tc := range cases {
		hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method)
		if !ok {
			t.Errorf("%q 应命中 %s", tc.path, tc.wantID)
			continue
		}
		if hit.RuleID != tc.wantID {
			t.Errorf("%q 命中 %s，期望 %s", tc.path, hit.RuleID, tc.wantID)
		}
	}
	// 分号后内容不影响匹配，但分号前为空则不成立：`/;a=b` 不是任何单段端点。
	if _, ok := CheckSensitiveEndpointPath("/;a=b", "GET"); ok {
		t.Fatal("/;a=b 不应命中")
	}
}
