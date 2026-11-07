package owasp

import "testing"

/**
 * TestSensitiveEndpointBatch6Rules 锁定 205 这条端点规则的命中形态。
 *
 * 收录口径：全语料 140572 条按 endpoints.go 的真实段匹配语义重算，白侧首请求 /
 * 任一子请求 / 全部子请求三口径均为 0。黑侧 19 条全为 GET
 * `/rest/api/latest/groupuserpicker`，query 逐字节恒为
 * `query=1&maxResults=50000&showAvatar=true`，且 r93 基线上全部仍是漏报（fn）。
 */
func TestSensitiveEndpointBatch6Rules(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		query  string
		wantID string
	}{
		{
			name:   "205 CVE-2019-8449 真实形态",
			path:   "/rest/api/latest/groupuserpicker",
			method: "GET",
			query:  "query=1&maxResults=50000&showAvatar=true",
			wantID: "owasp:endpoint:205",
		},
		{
			name:   "205 参数顺序变化",
			path:   "/rest/api/latest/groupuserpicker",
			method: "GET",
			query:  "maxResults=50000",
			wantID: "owasp:endpoint:205",
		},
		{
			name:   "205 参数名大小写变化",
			path:   "/rest/api/latest/groupuserpicker",
			method: "GET",
			query:  "MAXRESULTS=50000",
			wantID: "owasp:endpoint:205",
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
 * TestSensitiveEndpointBatch6Rejects 锁定 205 的反例。
 *
 * 关键是「正常 Jira REST 调用」必须放行：白侧语料里确实有
 * `/rest/api/2/screens`、`/rest/api/latest/repos` 这类正常请求，且 Jira 的组
 * 选择器默认分页是 20 —— 不带 maxResults=50000 的同路径请求不算攻击。
 */
func TestSensitiveEndpointBatch6Rejects(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		query  string
	}{
		{
			name:   "同路径但无 query",
			path:   "/rest/api/latest/groupuserpicker",
			method: "GET",
			query:  "",
		},
		{
			name:   "同路径但默认分页",
			path:   "/rest/api/latest/groupuserpicker",
			method: "GET",
			query:  "query=1&maxResults=20&showAvatar=true",
		},
		{
			name:   "同路径但 maxResults 前缀不同",
			path:   "/rest/api/latest/groupuserpicker",
			method: "GET",
			query:  "maxResults=5000",
		},
		{
			name:   "参数名相似但不等",
			path:   "/rest/api/latest/groupuserpicker",
			method: "GET",
			query:  "xmaxResults=50000",
		},
		{
			name:   "白侧真实形态 /rest/api/2/screens",
			path:   "/rest/api/2/screens",
			method: "GET",
			query:  "maxResults=50000",
		},
		{
			name:   "白侧真实形态 /rest/api/latest/repos",
			path:   "/rest/api/latest/repos",
			method: "GET",
			query:  "maxResults=50000",
		},
		{
			name:   "方法不符",
			path:   "/rest/api/latest/groupuserpicker",
			method: "POST",
			query:  "maxResults=50000",
		},
		{
			name:   "路径少一段",
			path:   "/rest/api/groupuserpicker",
			method: "GET",
			query:  "maxResults=50000",
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

/**
 * TestSensitiveEndpointBatch6NoSideEffects 校验 205 不抢走既有规则的归属。
 *
 * 同为 `rest` 首段的 092（Liferay sharelinks）与 071（Magento guest-carts）
 * 必须仍报自己的 ID。
 */
func TestSensitiveEndpointBatch6NoSideEffects(t *testing.T) {
	hit, ok := CheckSensitiveEndpointPathWithRequest(
		"/rest/sharelinks/1.0/link", "POST", "maxResults=50000", nil, nil)
	if !ok {
		t.Fatal("/rest/sharelinks/1.0/link 应命中既有规则 092")
	}
	if hit.RuleID != "owasp:endpoint:092" {
		t.Errorf("命中规则 = %q，期望 owasp:endpoint:092", hit.RuleID)
	}
	hit, ok = CheckSensitiveEndpointPathWithRequest(
		"/rest/v1/guest-carts", "POST", "maxResults=50000", nil, nil)
	if !ok {
		t.Fatal("/rest/v1/guest-carts 应命中既有规则 071")
	}
	if hit.RuleID != "owasp:endpoint:071" {
		t.Errorf("命中规则 = %q，期望 owasp:endpoint:071", hit.RuleID)
	}
}
