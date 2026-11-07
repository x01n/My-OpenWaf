package owasp

import "testing"

/**
 * TestSensitiveEndpointBatch3Rules 锁定 175-191 这批端点规则的命中形态。
 *
 * 这批的收录口径与 166-174 一致：全语料 140572 条按「endpoints.go 真实段匹配
 * 语义」逐条重算，白侧任一请求命中数为 0，黑侧仍有 fn。与上一批的差别是
 * 判据全部落在**路径段序列**上（不做首段之外的模糊匹配），因此每条规则都
 * 同时给出「黑侧必中」与「白侧同端点不中」两组用例。
 */
func TestSensitiveEndpointBatch3Rules(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		query  string
		wantID string
	}{
		{
			name:   "175 AWS 密钥文件",
			path:   "/aws.yml",
			method: "GET",
			wantID: "owasp:endpoint:175",
		},
		{
			name:   "175 大小写折叠",
			path:   "/AWS.YML",
			method: "GET",
			wantID: "owasp:endpoint:175",
		},
		{
			name:   "176 配置目录 AWS 密钥",
			path:   "/config/aws.yml",
			method: "GET",
			wantID: "owasp:endpoint:176",
		},
		{
			name:   "177 Spring Boot 配置文件",
			path:   "/config/application.yml",
			method: "GET",
			wantID: "owasp:endpoint:177",
		},
		{
			name:   "178 Crowd 安装向导建管理员",
			path:   "/setup/setupadministrator.action",
			method: "POST",
			wantID: "owasp:endpoint:178",
		},
		{
			name:   "179 DotNetNuke 安装向导建管理员",
			path:   "/Admin/Access/Setup/Default.aspx",
			method: "GET",
			query:  "Action=createadministrator&adminusername=x&adminpassword=y",
			wantID: "owasp:endpoint:179",
		},
		{
			name:   "180 Grafana 插件目录回溯",
			path:   "/public/plugins/alertlist/../../../../../conf/defaults.ini",
			method: "GET",
			wantID: "owasp:endpoint:180",
		},
		{
			name:   "181 public 目录环境变量文件",
			path:   "/public/.env",
			method: "GET",
			wantID: "owasp:endpoint:181",
		},
		{
			name:   "181 探测方法不限于 GET",
			path:   "/public/.env",
			method: "POST",
			wantID: "owasp:endpoint:181",
		},
		{
			name:   "182 OFBiz Groovy 程序导出",
			path:   "/webtools/control/main/ProgramExport",
			method: "POST",
			wantID: "owasp:endpoint:182",
		},
		{
			name:   "183 环境变量备份变体",
			path:   "/.env.old",
			method: "GET",
			wantID: "owasp:endpoint:183",
		},
		{
			name:   "183 探测方法不限于 GET",
			path:   "/.env.old",
			method: "POST",
			wantID: "owasp:endpoint:183",
		},
		{
			name:   "184 环境变量交换变体",
			path:   "/.env.swp",
			method: "GET",
			wantID: "owasp:endpoint:184",
		},
		{
			name:   "185 环境变量备份副本",
			path:   "/.env.backup",
			method: "GET",
			wantID: "owasp:endpoint:185",
		},
		{
			name:   "186 环境变量另存变体",
			path:   "/.env.save",
			method: "GET",
			wantID: "owasp:endpoint:186",
		},
		{
			name:   "187 环境变量生产变体",
			path:   "/.env.prod",
			method: "GET",
			wantID: "owasp:endpoint:187",
		},
		{
			name:   "188 环境变量生产全称变体",
			path:   "/.env.production",
			method: "GET",
			wantID: "owasp:endpoint:188",
		},
		{
			name:   "189 环境变量本地生产变体",
			path:   "/.env.production.local",
			method: "GET",
			wantID: "owasp:endpoint:189",
		},
		{
			name:   "190 环境变量配置变体",
			path:   "/.env.config",
			method: "GET",
			wantID: "owasp:endpoint:190",
		},
		{
			name:   "191 ThinkPHP 文件读取 s 参数",
			path:   "/public/index.php",
			method: "GET",
			query:  "s=/index/qrcode/download/url/L2V0Yy9wYXNzd2Q=",
			wantID: "owasp:endpoint:191",
		},
		{
			name:   "191 ThinkPHP invokefunction",
			path:   "/public/index.php",
			method: "GET",
			query:  `s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system`,
			wantID: "owasp:endpoint:191",
		},
	}
	for _, tc := range cases {
		hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, tc.query, nil, nil)
		if !ok {
			t.Errorf("%s: %s 应命中 %s", tc.name, tc.path, tc.wantID)
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
 * TestSensitiveEndpointBatch3Reject 锁定闸门不成立时不得命中的形态。
 * 全部对应全语料白侧的实测形态：
 *
 *   - 175-177：白侧同名文件出现在别的目录深度（/config/database.yml、
 *     /symfony/config/packages/aws.yaml 等），段序列不同即不命中；
 *   - 178：同端点的 GET 目录探测（白侧 0 条，黑侧 51 条全为 POST）；
 *   - 179：缺 Action 参数的正常访问（启用了安装向导的站点会打开这个页面）；
 *   - 180：白侧真实请求用的是自带插件名，不是 alertlist；
 *   - 181：/public/index.php 的正常图片下载（白侧 3 条）；
 *   - 182：webtools 的 GET/HEAD 目录探测（白侧 2 条）；
 *   - 183-190：子目录下的 .env 探测是白侧扫描流量，不进族；
 *   - 191：同端点无 s 参数的正常下载请求。
 */
func TestSensitiveEndpointBatch3Reject(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		query  string
	}{
		{"175 次段不同", "/config/database.yml", "GET", ""},
		{"175 目录内同名文件不命中", "/symfony/config/packages/aws.yaml", "GET", ""},
		{"176 首段不同", "/private/aws.yml", "GET", ""},
		{"177 白侧 config.yml", "/config/config.yml", "GET", ""},
		{"177 白侧根 application.yml", "/application.yml", "GET", ""},
		{"178 方法不符", "/setup/setupadministrator.action", "GET", ""},
		{"179 缺 Action 参数", "/Admin/Access/Setup/Default.aspx", "GET", ""},
		{"179 Action 值不同", "/Admin/Access/Setup/Default.aspx", "GET", "Action=setup"},
		{"180 白侧自带插件名", "/public/plugins/knightss27-weathermap-panel/../../../../../conf/defaults.ini", "GET", ""},
		{"180 末段不同", "/public/plugins/alertlist/../../../../../conf/app.ini", "GET", ""},
		{"181 子路径不命中以外的次段", "/public/env", "GET", ""},
		{"181 子路径不命中", "/public/.env.bak", "GET", ""},
		{"182 方法不符", "/webtools/control/main/ProgramExport", "GET", ""},
		{"183 子目录形态", "/adm/.env.old", "GET", ""},
		{"187 白侧 prod.local 子路径", "/api/.env.prod", "GET", ""},
		{"184 后缀近似", "/.env.swpx", "GET", ""},
		{"185 后缀近似", "/.env.backups", "GET", ""},
		{"186 后缀近似", "/.env.saved", "GET", ""},
		{"187 后缀近似", "/.env.prod.txt", "GET", ""},
		{"188 白侧 prod.local", "/.env.prod.local", "GET", ""},
		{"189 白侧 dist", "/.env.dist", "GET", ""},
		{"190 后缀近似", "/.env.configuration", "GET", ""},
		{"191 无 s 参数", "/public/index.php", "GET", ""},
		{"191 参数名近似", "/public/index.php", "GET", "sx=/index/qrcode/download/url/x"},
		{"191 裸键不算", "/public/index.php", "GET", "s"},
	}
	for _, tc := range cases {
		if hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, tc.query, nil, nil); ok {
			t.Errorf("%s: %q 不得命中，实际命中 %s", tc.name, tc.path, hit.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointBatch3LegacyEntry 锁定旧入口的边界：这批规则的分值
 * 与说明来自规则表本身，旧入口（无 query）下带闸门的 179/191 恒不命中，
 * 其余规则行为一致。该用例只调用本批之前就存在的公开入口，在旧代码上
 * 可编译且必然断言失败（旧代码没有这批规则）。
 */
func TestSensitiveEndpointBatch3LegacyEntry(t *testing.T) {
	for _, tc := range []struct{ path, method string }{
		{"/Admin/Access/Setup/Default.aspx", "GET"},
		{"/public/index.php", "GET"},
	} {
		if hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method); ok {
			t.Errorf("旧入口（无 query）%q 不得命中，实际命中 %s", tc.path, hit.RuleID)
		}
	}
	for _, tc := range []struct{ path, method, wantID string }{
		{"/aws.yml", "GET", "owasp:endpoint:175"},
		{"/config/aws.yml", "GET", "owasp:endpoint:176"},
		{"/config/application.yml", "GET", "owasp:endpoint:177"},
		{"/setup/setupadministrator.action", "POST", "owasp:endpoint:178"},
		{"/public/.env", "GET", "owasp:endpoint:181"},
		{"/.env.old", "GET", "owasp:endpoint:183"},
	} {
		hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method)
		if !ok || hit.RuleID != tc.wantID {
			t.Errorf("%q 期望命中 %s，实际 ok=%v id=%q", tc.path, tc.wantID, ok, hit.RuleID)
		}
	}
}
