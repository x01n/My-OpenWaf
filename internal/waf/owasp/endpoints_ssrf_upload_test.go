package owasp

import "testing"

/**
 * TestSSRFUploadEndpointRules 锁定 091-141 这段新规则的匹配与归因。
 *
 * 这 51 条覆盖「URL 参数由服务端发起请求（SSRF/开放重定向）」与
 * 「文件上传/任意文件写入」两类产品专属端点。判据只有路径段（仅 135 一条
 * 带 POST 方法约束）；每条规则的命中路径都来自 datacon2025 语料黑侧样本，
 * 且在全语料 140572 条上验证过白侧命中数为 0。
 */
func TestSSRFUploadEndpointRules(t *testing.T) {
	hits := []struct {
		name   string
		path   string
		method string
		wantID string
	}{
		{"Cacti 图片代理", "/pictureproxy.php", "GET", "owasp:endpoint:091"},
		{"Liferay 短链", "/rest/sharelinks/1.0/link", "GET", "owasp:endpoint:092"},
		{"WordPress oEmbed", "/wp-json/oembed/1.0/embed", "GET", "owasp:endpoint:093"},
		{"WordPress 子目录 oEmbed", "//blog//wp-json/oembed/1.0/embed", "GET", "owasp:endpoint:094"},
		{"WordPress 次级子目录 oEmbed", "/sito//wp-json/oembed/1.0/embed", "GET", "owasp:endpoint:095"},
		{"Jellyfin 远程图片", "/Items/RemoteSearch/Image", "GET", "owasp:endpoint:096"},
		{"Drupal Babel 跳转", "/modules/babel/redirect.php", "GET", "owasp:endpoint:097"},
		{"SonarQube 项目选择", "/select_project.php", "GET", "owasp:endpoint:098"},
		{"openwin 弹窗跳转", "/openwin.php", "GET", "owasp:endpoint:099"},
		{"SAFVC 登出跳转", "/ssoAdapter/logoutAction.do", "GET", "owasp:endpoint:100"},
		{"图标抓取", "/getFavicon", "GET", "owasp:endpoint:101"},
		{"Novius OS 登录跳转", "/novius-os/admin/nos/login", "GET", "owasp:endpoint:102"},
		{"Magnolia JSONP 代理", "/api/v1/core/proxy/jsonprequest", "GET", "owasp:endpoint:103"},
		{"Kaseya 本地代理", "/vsaPres/Web20/core/LocalProxy.ashx", "GET", "owasp:endpoint:104"},
		{"Composer 抓取", "/composer/send_email", "GET", "owasp:endpoint:105"},
		{"PMB 抓取", "/pmb/opac_css/pmb.php", "GET", "owasp:endpoint:106"},
		{"后台清缓存跳转", "/backend/admin/common/clearcache", "GET", "owasp:endpoint:107"},
		{"OpenX 点击跳转", "/openx/www/delivery/lg.php", "GET", "owasp:endpoint:108"},
		{"adserve 点击跳转", "/adserve/www/delivery/lg.php", "GET", "owasp:endpoint:109"},
		{"adserver 点击跳转", "/adserver/www/delivery/lg.php", "GET", "owasp:endpoint:110"},
		{"Brandfolder 回调", "/wp-content/plugins/brandfolder/callback.php", "GET", "owasp:endpoint:111"},
		{"find_v2 点击跳转", "/find_v2/_click", "GET", "owasp:endpoint:112"},
		{"OpenCms jsonapi", "/system/modules/alkacon.mercury.template.jsondemo/elements/jsonapi.jsp", "GET", "owasp:endpoint:113"},
		{"StageShow 跳转", "/wp-content/plugins/stageshow/stageshow_redirect.php", "GET", "owasp:endpoint:114"},
		{"Bitrix redirect", "/bitrix/redirect.php", "GET", "owasp:endpoint:115"},
		{"Bitrix 广告点击", "/bitrix/rk.php", "GET", "owasp:endpoint:116"},
		{"回显服务探测页", "/echo-server.html", "GET", "owasp:endpoint:117"},
		{"supportLoad 抓取", "/inc/supportLoad.asp", "GET", "owasp:endpoint:118"},
		{"PhastPress 抓取", "/wp-content/plugins/phastpress/phast.php", "GET", "owasp:endpoint:119"},
		{"WebP Converter 直通", "/wp-content/plugins/webp-converter-for-media/includes/passthru.php", "GET", "owasp:endpoint:120"},
		{"海思参数 CGI", "/web/cgi-bin/hi3510/param.cgi", "GET", "owasp:endpoint:121"},
		{"wp-file-manager 连接器", "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php", "POST", "owasp:endpoint:122"},
		{"致远 dataDir 写入", "/admin/dataDir.html", "POST", "owasp:endpoint:123"},
		{"AIM 上传", "/aim/equipmap/accept.jsp", "POST", "owasp:endpoint:124"},
		{"OAapp 上传", "/OAapp/jsp/upload.jsp", "POST", "owasp:endpoint:125"},
		{"OAapp 文件编辑上传", "/OAapp/htpages/app/module/trace/component/fileEdit/ntkoupload.jsp", "POST", "owasp:endpoint:126"},
		{"pdf_maker 落文件", "/inter/pdf_maker.php", "POST", "owasp:endpoint:127"},
		{"uploadControl 上传", "/mp/uploadControl/uploadFile", "POST", "owasp:endpoint:128"},
		{"varimport 导入", "/variable/varimport", "POST", "owasp:endpoint:129"},
		{"编码穿越指向 CGI", "/images/..%2fcgi/cgi_i_filter.js", "GET", "owasp:endpoint:130"},
		{"泛微 C6 文件下载", "/C6/Jhsoft.Web.module/testbill/dj/download.asp", "GET", "owasp:endpoint:131"},
		{"viral-optins 上传", "/wp-content/plugins/viral-optins/api/uploader/file-uploader.php", "POST", "owasp:endpoint:132"},
		{"畅捷通 T+ 上传", "/tplus/SM/SetupAccount/Upload.aspx", "POST", "owasp:endpoint:133"},
		{"exportImport 上传", "/page/exportImport/uploadOperation.jsp", "POST", "owasp:endpoint:134"},
		{"开发服务器元数据上传", "/developmentserver/metadatauploader", "POST", "owasp:endpoint:135"},
		{"storagemgmt apply", "/Collector/storagemgmt/apply", "GET", "owasp:endpoint:136"},
		{"YouTrack 进程执行", "/app/rest/debug/processes", "POST", "owasp:endpoint:137"},
		{"mesh.cgi 升级", "/cgi-bin/mesh.cgi", "GET", "owasp:endpoint:138"},
		{"BlazeDS AMF 反序列化", "/flex2gateway/amf", "POST", "owasp:endpoint:139"},
		{"图片抓取", "/Images/Remote", "GET", "owasp:endpoint:140"},
		{"头像图标抓取", "/v1/avatars/favicon", "GET", "owasp:endpoint:141"},
	}
	for _, tc := range hits {
		hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method)
		if !ok {
			t.Errorf("%s: %q(%s) 未命中，期望 %s", tc.name, tc.path, tc.method, tc.wantID)
			continue
		}
		if hit.RuleID != tc.wantID {
			t.Errorf("%s: %q 命中 %s，期望 %s", tc.name, tc.path, hit.RuleID, tc.wantID)
		}
	}
}

/**
 * TestSSRFUploadEndpointRulesRejectWhitePaths 锁定白侧不得命中的形态。
 *
 * 两组来源：
 *   - 语料白侧真实请求（全语料普查中白侧命中数为 0 的排除面）；
 *   - 首段与规则相同但次段不同的常规业务路径，验证段边界未被放宽。
 */
func TestSSRFUploadEndpointRulesRejectWhitePaths(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
	}{
		{"白侧跳转端点", "/redirect", "GET"},
		{"白侧社区提交页", "/community/submit.html", "GET"},
		{"白侧搜索引擎跳转", "/owa/auth/logon.aspx", "GET"},
		{"白侧图片调试脚本", "/usr/share/php/magpierss/scripts/magpie_debug.php", "GET"},
		{"白侧 CGI 探针", "/cgi-bin/test.cgi", "GET"},
		{"白侧 Nacos 运维页", "/nacos/", "GET"},
		{"图标抓取次段不同", "/getFaviconX", "GET"},
		{"Magnolia 首段不同", "/xapi/v1/core/proxy/jsonprequest", "GET"},
		{"Cacti 端点变体", "/pictureproxy.phpx", "GET"},
		{"文件管理器次段不同", "/wp-content/plugins/wp-file-managere/lib/php/connector.php", "GET"},
		{"致远端点次段不同", "/admin/dataDirx.html", "GET"},
		{"OAapp 通用页", "/OAapp/jsp/index.jsp", "GET"},
		{"storagemgmt 次段不同", "/Collector/storagemgmt/applyx", "GET"},
		{"YouTrack 端点不完整", "/app/rest/debug", "POST"},
		{"mesh.cgi 次段不同", "/cgi-bin/mesh.cgix", "GET"},
		{"Bitrix 其他脚本", "/bitrix/rk2.php", "GET"},
		{"BlazeDS 首段不同", "/xflex2gateway/amf", "POST"},
		{"SAFVC 首段不同", "/ssoAdapterX/logoutAction.do", "GET"},
		{"开发服务器上传方法不符", "/developmentserver/metadatauploader", "HEAD"},
		{"普通 WordPress 目录", "/wp-content/plugins/akismet/readme.txt", "GET"},
	}
	for _, tc := range cases {
		if hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method); ok {
			t.Errorf("%s: %q(%s) 误命中 %s", tc.name, tc.path, tc.method, hit.RuleID)
		}
	}
}

/**
 * TestSSRFUploadEndpointRuleIDs 锁定新增规则段的 ID 连续性与类别分布。
 *
 * ID 从 091 连续排到 141，中间不留空洞：规则目录、规则级覆盖与前端展示
 * 都按 ID 索引，空洞会让「规则总数」与最大编号对不上。
 *
 * 上界只取本族末条（141）而不取全表最大编号：同期合并的「设备/组件专属
 * 命令执行端点」族占用 142-155，全局最大值已不止 141。拿全局最大值当本族
 * 上界会让之后每并入一个规则族都打断本用例，而本用例要锁的是本族自身的
 * 连续性。
 */
func TestSSRFUploadEndpointRuleIDs(t *testing.T) {
	byID := make(map[string]sensitiveEndpointRule, len(sensitiveEndpointRules))
	for i := range sensitiveEndpointRules {
		rule := &sensitiveEndpointRules[i]
		byID[rule.id] = *rule
	}
	const wantNew = 51
	const familyMax = 90 + wantNew
	if _, ok := byID[endpointRuleID(familyMax)]; !ok {
		t.Fatalf("本族末条规则 %s 缺失", endpointRuleID(familyMax))
	}
	for n := 91; n <= familyMax; n++ {
		id := endpointRuleID(n)
		rule, ok := byID[id]
		if !ok {
			t.Fatalf("规则 %s 缺失", id)
		}
		switch rule.category {
		case CatSSRF, CatWebshell, CatCmdInject, CatDeserial:
		default:
			t.Errorf("%s 类别 %q 不在预期集合内", id, rule.category)
		}
	}
}

/**
 * endpointRuleID 按 owasp:endpoint:NNN 的既有格式拼装 ID。
 * 专用于本文件的编号连续性断言，不参与生产路径。
 */
func endpointRuleID(n int) string {
	const digits = "0123456789"
	return "owasp:endpoint:" + string([]byte{digits[n/100], digits[n/10%10], digits[n%10]})
}
