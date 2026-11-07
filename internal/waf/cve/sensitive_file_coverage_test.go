package cve

import (
	"regexp"
	"strings"
	"testing"
)

// sensFileProbeCases 覆盖 reSensitiveFile 与 AC needle 表的对齐关系：
// 每条 needle 对应正则的一个分支，命中 needle 的路径必须能真正命中正则。
var sensFileProbeCases = []string{
	"/.env",
	"/.gitignore",
	"/etc/shadow",
	"/database.yml",
	"/settings.py",
	"/info.php",
	"/server-info",
	"/server-status",
	"/backup.sql",
	"/.svn/entries",
	"/phpinfo.php",
	"/.DS_Store",
	"/.aws/credentials",
	"/Dockerfile",
	"/.git/config",
	"/.htaccess",
	"/wp-config.php",
	"/web.config",
	"/etc/passwd",
	"/.htpasswd",
	"/application.properties",
	"/.idea/workspace.xml",
	"/.vscode/settings.json",
	"/composer.lock",
	"/package.json",
	"/Gemfile.lock",
	"/requirements.txt",
	"/docker-compose.yml",
	"/.ssh/id_rsa",
	"/.bash_history",
	"/.mysql_history",
	"/adminer.php",
	"/.well-known/security.txt",
	"/dump.sql",
	"/WEB-INF/web.xml",
	"/META-INF/MANIFEST.MF",
}

// TestSensitiveFileACNeedleCoverage 锁定 §4.3 的 needle 表修复：
// AC 门（subDetectorACGate + registryACGate 两条路径）对 reSensitiveFile
// 覆盖的每个分支都必须放行，否则该分支的载荷永远到不了正则。
//
// 注意这是一条**必要条件**：AC 门放行不等于端到端可检出——上游还有
// hasCVESuspiciousContent 粗筛（见 TestSensitiveFileResidualPreFilter）。
func TestSensitiveFileACNeedleCoverage(t *testing.T) {
	for _, path := range sensFileProbeCases {
		t.Run(path, func(t *testing.T) {
			if !reSensitiveFile.MatchString(path) {
				t.Fatalf("用例失效：reSensitiveFile 不匹配 %q（该路径不属于本规则覆盖面）", path)
			}
			req := BuildCVERequest(path, "", nil, nil, "")
			hits := computeSubDetectorHits(req)
			if !subDetectorACGate("CVE-2024-SENSFILE", "url", &hits) {
				t.Errorf("子检测器 AC 门拒绝了 %q（needle 表缺该分支的必现字面前缀）", path)
			}
			// DetectAll 的 AC 匹配对象是 registryCombinedLower(...)，即已小写化的
			// 合并串（detector.go:238-253），这里照抄该口径。
			hit := registryACData.ac.MatchMask(strings.ToLower(path))
			if !registryACGate("CVE-2024-SENSFILE", &hit) {
				t.Errorf("注册表 AC 门拒绝了 %q（registryNeedleGroups 缺该分支）", path)
			}
		})
	}
}

// TestSensitiveFileResidualPreFilter 记录 needle 修复后的**残留漏报**与原因。
//
// 端到端链路上的前置门不止 AC 一处：
//
//	phases.go → HasRawCVESuspiciousContent → Bytes.Contains(敏感文件字面量)
//	          → d.DetectFirst → hasCVESuspiciousContent（高危标点/已知指示器）
//	          → 子检测器 AC 门 → reSensitiveFile
//
// 敏感文件路径（/.gitignore、/Dockerfile、/info.php…）不含高危标点、
// 也不命中 Bytes 里的显式字面量清单，因此在 AC 门**之前**就被挡掉。
// 这两层属于 §4.3 之外的独立缺陷（见交付报告），本用例把残留现状固定下来，
// 任何一层被修好后本用例会失败并提醒同步更新。
func TestSensitiveFileResidualPreFilter(t *testing.T) {
	residual := []string{
		"/.gitignore", "/info.php", "/server-info", "/server-status", "/backup.sql",
		"/phpinfo.php", "/.aws/credentials", "/Dockerfile", "/.idea/workspace.xml",
		"/.vscode/settings.json", "/composer.lock", "/package.json", "/Gemfile.lock",
		"/requirements.txt", "/docker-compose.yml", "/.ssh/id_rsa", "/.bash_history",
		"/.mysql_history", "/adminer.php", "/.well-known/security.txt", "/dump.sql",
		"/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
	}
	reachable := []string{
		"/.env", "/etc/shadow", "/database.yml", "/settings.py", "/.svn/entries",
		"/.DS_Store", "/.git/config", "/.htaccess", "/wp-config.php", "/web.config",
		"/etc/passwd", "/.htpasswd", "/application.properties",
	}
	for _, path := range reachable {
		t.Run("reachable"+path, func(t *testing.T) {
			found := detectCVEs(t, path, "", "", "", nil)
			if !found["CVE-2024-SENSFILE"] {
				t.Errorf("可检出集合中的 %q 实际未命中（命中集=%v）", path, keysOf(found))
			}
		})
	}
	for _, path := range residual {
		t.Run("residual"+path, func(t *testing.T) {
			req := BuildCVERequest(path, "", nil, nil, "")
			if hasCVESuspiciousContent(req) || HasRawCVESuspiciousContent(path, "", nil, nil, "") {
				t.Fatalf("前置粗筛已放行 %q —— 残留已消除，请把该路径移到 reachable 列表", path)
			}
			// AC 门这一层必须已修好（否则说明 needle 表仍有缺口）
			hits := computeSubDetectorHits(req)
			if !subDetectorACGate("CVE-2024-SENSFILE", "url", &hits) {
				t.Errorf("AC 门仍拒绝 %q（needle 表缺口）", path)
			}
		})
	}
}

// TestSensitiveFileBenignNegatives 良性反例：普通静态资源路径不得命中本规则。
func TestSensitiveFileBenignNegatives(t *testing.T) {
	benign := []string{
		"/index.html",
		"/assets/app.js",
		"/api/v1/users",
		"/images/logo.png",
		"/package",         // 前缀但非 /package.json
		"/etcetera/report", // 前缀但非 /etc/
		"/docker",          // 前缀但非 /dockerfile
		"/information/faq", // 前缀但非 /info.php
		"/backups/2026",    // 前缀但非 /backup.
		"/status",
		"/server",
		"/info",
	}
	for _, path := range benign {
		t.Run(path, func(t *testing.T) {
			if reSensitiveFile.MatchString(path) {
				t.Fatalf("良性反例被 reSensitiveFile 匹配: %q", path)
			}
			found := detectCVEs(t, path, "", "", "", nil)
			if found["CVE-2024-SENSFILE"] {
				t.Fatalf("良性反例命中 CVE-2024-SENSFILE: %q", path)
			}
		})
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// regexpRef 保留对 reSensitiveFile 类型的静态引用，避免未来重构把
// reSensitiveFile 换成非 *regexp.Regexp 时本文件静默失效。
var regexpRef *regexp.Regexp = reSensitiveFile
