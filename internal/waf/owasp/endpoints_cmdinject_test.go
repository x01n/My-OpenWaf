package owasp

// 说明：本文件里的规则 ID 是 142-155。原交付树用的是 091-105，
// 与同期合并的 SSRF/文件上传族（091-141）冲突，合并时按 51 顺延。
// 其中的 `/flex2gateway/amf` 一条与 SSRF 族的 139 逐字段等价（139 无方法
// 约束，是它的超集），合并时删除，其后编号各前移一位。

import "testing"

/**
 * TestSensitiveEndpointCmdInjectFamilyLocks 锁定 091-104 这批「设备/组件
 * 专属命令执行端点」规则的匹配结果与收录依据。
 *
 * 每条规则的正例取自 datacon2025 语料中的实际探测样本（黑侧），断言它不仅
 * 命中，而且命中的正是本规则；反例取自同语料白侧与泛化路径，断言不命中。
 *
 * 这组用例的价值不在"能跑通"，而在防止后续有人：
 *   - 放宽某条的 segs 导致白侧泛化路径被误拦（如把 `tmp/dsks.php` 放宽为
 *     `tmp`，或把 `pmd/index.php` 放宽为 `index.php`）；
 *   - 误加方法约束把黑侧多方法形态挡掉（094/101/102 无方法约束是刻意的）。
 */
func TestSensitiveEndpointCmdInjectFamilyLocks(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
		wantID string
	}{
		{"WebShell 落地脚本", "/tmp/Dsks.php", "POST", "owasp:endpoint:142"},
		{"WebShell 落地脚本大小写", "/TMP/DSKS.PHP", "POST", "owasp:endpoint:142"},
		{"GameAPI 命令执行", "/GameAPI", "POST", "owasp:endpoint:143"},
		{"设备登录 CGI", "/LoginPC.cgi", "POST", "owasp:endpoint:144"},
		{"固件上传 quick.cgi", "/cgi-bin/quick/quick.cgi", "POST", "owasp:endpoint:145"},
		{"固件上传 quick.cgi 带查询串", "/cgi-bin/quick/quick.cgi", "GET", "owasp:endpoint:145"},
		{"webctrl.cgi 命令注入", "/cgi-bin/webctrl.cgi", "GET", "owasp:endpoint:146"},
		{"设备菜单 guiw", "/menu/guiw", "GET", "owasp:endpoint:147"},
		{"Fortinet 主机检查", "/remote/hostcheck_validate", "POST", "owasp:endpoint:148"},
		{"popen.cgi 命令执行", "/cgi-bin/popen.cgi", "GET", "owasp:endpoint:149"},
		{"协议配置注入端点", "/protocol/index.php", "POST", "owasp:endpoint:150"},
		{"Boa formPing6", "/boaform/admin/formPing6", "POST", "owasp:endpoint:151"},
		{"运维脚本执行端点", "/utility/run_commands.sh", "POST", "owasp:endpoint:152"},
		{"运维脚本执行端点任意方法", "/utility/run_commands.sh", "PUT", "owasp:endpoint:152"},
		{"固件配置上传端点", "/cgi-bin/mainfunction.cgi/cvmcfgupload", "POST", "owasp:endpoint:153"},
		// /flex2gateway/amf 由 SSRF 族的 owasp:endpoint:139 收录（无方法约束，
		// 覆盖本族原本的 POST 形态），此处断言指向 139 而非另行编号。
		{"Flex AMF 反序列化", "/flex2gateway/amf", "POST", "owasp:endpoint:139"},
		{"phpMyAdmin PMD", "/pmd/index.php", "POST", "owasp:endpoint:154"},
		{"重复斜杠归一", "//cgi-bin//webctrl.cgi", "GET", "owasp:endpoint:146"},
		{"分号路径参数归一", "/cgi-bin/webctrl.cgi;jsessionid=abc", "GET", "owasp:endpoint:146"},
		{"Mirai 载荷落地路径", "/shell", "GET", "owasp:endpoint:155"},
		{"Mirai 载荷落地路径 HEAD", "/shell", "HEAD", "owasp:endpoint:155"},
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
}

/**
 * TestSensitiveEndpointCmdInjectFamilyRejects 锁定这批规则不得覆盖的白侧形态。
 *
 * 反例分三类，都是全语料白侧真实出现过的路径：
 *   - 同首段的泛化路径（`/tmp/` 下的正常文件、`/pmd/` 的 HEAD 探测）；
 *   - 同产品但非该端点的路径（`/cgi-bin/` 下其它 CGI）；
 *   - 段边界不成立（`/xtmp/Dsks.php`）。
 */
func TestSensitiveEndpointCmdInjectFamilyRejects(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
	}{
		{"tmp 下非该脚本", "/tmp/upload.php", "POST"},
		{"tmp 段本身", "/tmp", "POST"},
		{"段边界不成立", "/xtmp/Dsks.php", "POST"},
		{"pmd HEAD 探测", "/pmd/index.php", "HEAD"},
		{"pmd 下其它文件", "/pmd/other.php", "POST"},
		{"cgi-bin 其它 CGI", "/cgi-bin/userLogin", "POST"},
		{"quick 段本身", "/cgi-bin/quick", "POST"},
		{"quick 下其它脚本", "/cgi-bin/quick/other.cgi", "POST"},
		{"方法不匹配-webctrl", "/cgi-bin/webctrl.cgi", "POST"},
		{"方法不匹配-formPing6", "/boaform/admin/formPing6", "GET"},
		// 注意：不得用 /boaform/admin/formLogin 做反例——它已被既有的
		// owasp:endpoint:086（Boa 管理登录端点）收录，会命中那条而非本批规则。
		{"boaform 其它诊断端点", "/boaform/admin/formPing", "POST"},
		{"GameAPI 其它方法", "/GameAPI", "GET"},
		{"根路径", "/", "POST"},
		{"空路径", "", "POST"},
	}
	for _, tc := range cases {
		if hit, ok := CheckSensitiveEndpointPath(tc.path, tc.method); ok {
			t.Errorf("%s: CheckSensitiveEndpointPath(%q, %q) 误命中 %s", tc.name, tc.path, tc.method, hit.RuleID)
		}
	}
}

/**
 * TestSensitiveEndpointCmdInjectFamilySegLiterals 锁定这批规则的段字面量
 * 形态：全部小写、非空、且不含通用词。
 *
 * `segs` 若写成大写或含通用段（index.php、login 等），匹配即会静默失效或
 * 泛化到大量无关路径；这里把这些约束写成断言，避免后续手改时越界。
 */
func TestSensitiveEndpointCmdInjectFamilySegLiterals(t *testing.T) {
	approved := map[string]bool{
		"owasp:endpoint:142": true, "owasp:endpoint:143": true, "owasp:endpoint:144": true,
		"owasp:endpoint:145": true, "owasp:endpoint:146": true, "owasp:endpoint:147": true,
		"owasp:endpoint:148": true, "owasp:endpoint:149": true, "owasp:endpoint:150": true,
		"owasp:endpoint:151": true, "owasp:endpoint:152": true, "owasp:endpoint:153": true,
		"owasp:endpoint:154": true,
	}
	// 这批规则的段序列，作为「不得被改动」的指纹
	want := map[string]string{
		"owasp:endpoint:142": "tmp/dsks.php",
		"owasp:endpoint:143": "gameapi",
		"owasp:endpoint:144": "loginpc.cgi",
		"owasp:endpoint:145": "cgi-bin/quick/quick.cgi",
		"owasp:endpoint:146": "cgi-bin/webctrl.cgi",
		"owasp:endpoint:147": "menu/guiw",
		"owasp:endpoint:148": "remote/hostcheck_validate",
		"owasp:endpoint:149": "cgi-bin/popen.cgi",
		"owasp:endpoint:150": "protocol/index.php",
		"owasp:endpoint:151": "boaform/admin/formping6",
		"owasp:endpoint:152": "utility/run_commands.sh",
		"owasp:endpoint:153": "cgi-bin/mainfunction.cgi/cvmcfgupload",
		"owasp:endpoint:154": "pmd/index.php",
	}
	seen := map[string]bool{}
	for i := range sensitiveEndpointRules {
		rule := &sensitiveEndpointRules[i]
		if !approved[rule.id] {
			continue
		}
		seen[rule.id] = true
		got := ""
		for j, seg := range rule.segs {
			if j > 0 {
				got += "/"
			}
			got += seg
			if seg != toLowerASCII(seg) {
				t.Errorf("%s: 段 %q 不是小写字面量", rule.id, seg)
			}
		}
		if got != want[rule.id] {
			t.Errorf("%s: 段序列 = %q，期望 %q", rule.id, got, want[rule.id])
		}
		if rule.score <= 0 || rule.desc == "" {
			t.Errorf("%s: 分值或说明缺失", rule.id)
		}
	}
	for id := range approved {
		if !seen[id] {
			t.Errorf("%s: 规则不在 sensitiveEndpointRules 中", id)
		}
	}
}
