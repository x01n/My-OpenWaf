package owasp

import "testing"

/**
 * TestSensitiveEndpointBatch8Rules 锁定 209（备份/数据库文件直链下载）的命中形态。
 *
 * 收录口径：全语料 140572 条按真实段匹配语义重算，末段命中高危后缀且方法为
 * GET/HEAD 的样本中，黑侧仍漏报 1127 条、白侧漏报 0 条。`.gz` 刻意不收录，
 * 因为黑侧混有 sitemap.xml.gz 这类正常压缩资源。
 */
func TestSensitiveEndpointBatch8Rules(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
	}{
		{name: "压缩包直链", path: "/18.zip", method: "GET"},
		{name: "数据库导出直链", path: "/96-126-106-159.com.sql", method: "GET"},
		{name: "多段路径备份文件", path: "/backup/db.sql", method: "GET"},
		{name: "tgz 备份包", path: "/web.tgz", method: "HEAD"},
		{name: "大写后缀", path: "/.env.BAK", method: "GET"},
		{name: "矩阵参数截断", path: "/dump.sql;jsessionid=abc", method: "GET"},
		{name: "sqlite 数据库", path: "/dump.sqlite", method: "GET"},
		// 以下两条原本是 181/195 的边界反例，备份文件后缀被 209 接管后改为
		// 锁定「209 不得漏放这些明确应拦的备份泄露形态」。
		{name: "环境变量备份子路径", path: "/public/.env.bak", method: "GET"},
		{name: "源码备份文件", path: "/wp-content/plugins/backup-backup/includes/backup-heart.php.bak", method: "GET"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, "", nil, nil)
			if !ok {
				t.Fatalf("%s %s 应命中 owasp:endpoint:209", tc.method, tc.path)
			}
			if hit.RuleID != "owasp:endpoint:209" {
				t.Errorf("命中规则 = %q，期望 %q", hit.RuleID, "owasp:endpoint:209")
			}
			if hit.Category != CatPathTrav || hit.Score != 6 {
				t.Errorf("规则属性 = (%v, %d)，期望 (%v, 6)", hit.Category, hit.Score, CatPathTrav)
			}
		})
	}
}

/**
 * TestSensitiveEndpointBatch8Rejects 锁定 209 的反例。
 *
 * POST 不属于下载语义；`.gz` 会被正常压缩资源（sitemap.xml.gz）命中；
 * 无高危后缀的普通路径都必须放行。
 */
func TestSensitiveEndpointBatch8Rejects(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
	}{
		{name: "POST 非下载语义", path: "/backup.zip", method: "POST"},
		{name: "gz 刻意不收录", path: "/sitemap.xml.gz", method: "GET"},
		{name: "sql.gz 后缀为 gz", path: "/report.sql.gz", method: "GET"},
		{name: "普通静态资源", path: "/assets/app.js", method: "GET"},
		{name: "无后缀路径", path: "/download", method: "GET"},
		{name: "根路径", path: "/", method: "GET"},
		{name: "后缀不完整", path: "/data.sqlite3", method: "GET"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := CheckSensitiveEndpointPathWithRequest(tc.path, tc.method, "", nil, nil)
			if ok && hit.RuleID == "owasp:endpoint:209" {
				t.Errorf("%s %s 不应命中 209，实际命中 %q", tc.method, tc.path, hit.RuleID)
			}
		})
	}
}

/**
 * TestSensitiveEndpointBatch8Registered 校验 209 已进入内置规则目录。
 *
 * 规则目录是管理端展示与规则级覆盖的唯一来源，硬编码发射点漏登记会让新规则
 * 在 UI 上变成不可解释的裸 ID。
 */
func TestSensitiveEndpointBatch8Registered(t *testing.T) {
	for _, item := range BuiltinRuleDefinitions() {
		if item.RuleID != "owasp:endpoint:209" {
			continue
		}
		if item.Category != string(CatPathTrav) {
			t.Errorf("类别 = %q，期望 %q", item.Category, CatPathTrav)
		}
		if item.Description == "" {
			t.Error("说明为空")
		}
		return
	}
	t.Fatal("owasp:endpoint:209 未登记进 BuiltinRuleDefinitions")
}
