package owasp

import "testing"

/**
 * TestSensitiveEndpointNacosUsers 锁定 211/212 判定（Nacos 用户管理接口
 * 的未授权访问，CVE-2021-29441 一族）。
 *
 * 该接口 /nacos/v1/auth/users 两条规则各收一种判据，互不覆盖：
 *   - 211：User-Agent: Nacos-Server（服务端身份伪造）。Nacos 1.x 用该 UA
 *     识别「内部调用」并跳过鉴权，攻击者伪造即可匿名访问。黑侧 9 GET +
 *     9 POST 全部带该指纹，白侧同端点 0 条。
 *   - 212：GET 无 accessToken 令牌的批量枚举。控制台访问用户列表必须带
 *     accessToken（登录后前端注入），不带即为未授权调用。黑侧 pageNo+
 *     pageSize 枚举 10 条全命中、白侧 0 条。
 *
 * 两条规则的命中都必须来自判据本身：仅请求路径而不带对应指纹必须放行。
 */
func TestSensitiveEndpointNacosUsers(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		method  string
		query   string
		headers map[string]string
		wantID  string
	}{
		{
			name:    "211 UA Nacos-Server GET",
			path:    "/nacos/v1/auth/users",
			method:  "GET",
			headers: map[string]string{"user-agent": "Nacos-Server"},
			wantID:  "owasp:endpoint:211",
		},
		{
			name:    "211 UA Nacos-Server POST 建用户",
			path:    "/nacos/v1/auth/users",
			method:  "POST",
			query:   "username=zlkdzvfmvilylqdf&password=thiobovkkhjyvpeq",
			headers: map[string]string{"user-agent": "Nacos-Server"},
			wantID:  "owasp:endpoint:211",
		},
		{
			name:    "211 UA 大小写折叠",
			path:    "/nacos/v1/auth/users",
			method:  "POST",
			headers: map[string]string{"user-agent": "nacos-SERVER v2"},
			wantID:  "owasp:endpoint:211",
		},
		{
			name:   "212 GET 无令牌批量枚举",
			path:   "/nacos/v1/auth/users",
			method: "GET",
			query:  "pageNo=1&pageSize=999",
			wantID: "owasp:endpoint:212",
		},
		{
			name:   "212 GET 带 search 无令牌",
			path:   "/nacos/v1/auth/users",
			method: "GET",
			query:  "pageNo=1&pageSize=10&search=admin",
			wantID: "owasp:endpoint:212",
		},
		{
			// 211 的 UA 判据不成立时仍由 212 接管同一请求，验证两条规则
			// 在同段序列上是「接力」而不是「互斥抢占」。
			name:    "浏览器 UA GET 无令牌由 212 兜住",
			path:    "/nacos/v1/auth/users",
			method:  "GET",
			query:   "pageNo=1&pageSize=999",
			headers: map[string]string{"user-agent": "Mozilla/5.0 (Windows NT 10.0)"},
			wantID:  "owasp:endpoint:212",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, tc.query, tc.headers, nil)
			if !ok {
				t.Fatalf("%s %s 应命中 %s", tc.method, tc.path, tc.wantID)
			}
			if hit.RuleID != tc.wantID {
				t.Errorf("命中 %s，期望 %s", hit.RuleID, tc.wantID)
			}
			if hit.Score <= 0 || hit.Desc == "" {
				t.Errorf("命中缺少分值或说明: %+v", hit)
			}
		})
	}
}

/**
 * TestSensitiveEndpointNacosUsersReject 锁定 211/212 的反例（对应全语料
 * 白侧实测形态）：
 *
 *   - 211 不带 Nacos-Server UA → 不命中 211（同路径的 GET 由 212 接管，
 *     不带 UA 的 POST 非建用户则放行）；
 *   - 合法 DELETE 精确用户名（白侧形态）→ 放行；
 *   - 白侧空 POST 探测（不带建用户参数）→ 放行；
 *   - 211 的 UA 判据不得跨路径生效（数据同步路径带 Nacos-Server UA 放行）。
 */
func TestSensitiveEndpointNacosUsersReject(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		method  string
		query   string
		headers map[string]string
	}{
		{
			name:    "POST 建用户但浏览器 UA 非伪造",
			path:    "/nacos/v1/auth/users",
			method:  "POST",
			query:   "username=admin&password=x",
			headers: map[string]string{"user-agent": "Mozilla/5.0"},
		},
		{
			name:    "POST 空 query 探测",
			path:    "/nacos/v1/auth/users",
			method:  "POST",
			query:   "",
			headers: map[string]string{"user-agent": "Mozilla/5.0"},
		},
		{
			name:    "DELETE 精确用户名",
			path:    "/nacos/v1/auth/users",
			method:  "DELETE",
			query:   "username=gxakyy",
			headers: map[string]string{"user-agent": "Mozilla/5.0"},
		},
		{
			name:    "211 UA 判据不跨路径",
			path:    "/nacos/v1/cs/ops/data/removal",
			method:  "POST",
			headers: map[string]string{"user-agent": "Nacos-Server"},
		},
		{
			name:    "212 不得命中 users 的子路径 login（白侧登录页）",
			path:    "/nacos/v1/auth/users/login",
			method:  "GET",
			query:   "",
			headers: map[string]string{"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"},
		},
		{
			name:    "212 不得命中 users/login 且带 Nacos-Server UA",
			path:    "/nacos/v1/auth/users/login",
			method:  "GET",
			headers: map[string]string{"user-agent": "Nacos-Server"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, tc.query, tc.headers, nil)
			if ok {
				t.Errorf("%s %s 不得命中，实际命中 %s", tc.method, tc.path, hit.RuleID)
			}
		})
	}
}
