package owasp

import "strings"

var configTraversalSeparators = []string{"/", "\\", "%2f", "%5c"}

var configTraversalLandingTokens = []string{
	"configuration.php",      // Joomla 主配置（数据库口令、secret）
	"localconfiguration.php", // TYPO3 本地配置（数据库口令、加密密钥）
	"web.config",             // ASP.NET 应用配置（连接串、machineKey）
	"config.properties",      // Java 应用通用配置文件（Solr/Jira/WebLogic 等）
	"mysql_config.ini",       // iWebOffice / OA 类产品的 MySQL 连接配置
	"password.properties",    // Tomcat / CFIDE 等管理端口令文件
	"dbconfig.xml",           // Atlassian Jira/Confluence 数据库连接配置
	"localconfig.xml",        // Zimbra 本地配置（含数据库口令）
	"application/database",   // ThinkPHP 数据库配置路径
	"smb.conf",               // Samba 配置
	"system.conf",            // /etc 下的系统服务配置
	"autoce.ini",             // IND780 等设备的应用配置
	"thinvnc.ini",            // ThinVNC 远程桌面配置（含访问口令）
	"userdb.json",            // MPXnode 用户库文件
	"pages-manifest.json",    // Next.js 构建产物内的页面清单，不对外提供
	"thinkphp/base",          // ThinkPHP 基类文件，5.x RCE 的利用目标
	"tracedebug",             // ThinkPHP think-trace 调试组件，可读任意文件
}

const configTraversalLandingWindow = 80

var multiEncodedTraversalDots = []string{"..", "%2e%2e", "%252e%252e"}

var multiEncodedSeparators = []string{"%25252f", "%25255c"}

// stripTraversalLanding 返回 rest 中「穿越序列之后」的落点片段：
// 先截到窗口上限，再截到第一个参数分隔符或空白，返回原始大小写的子串。
//
// 只做切片不做解码：解码会把 `%252e` 变成 `%2e`、破坏「编码层数」这一判据
// 本身，而本函数的调用方判的正是编码层数。
func stripTraversalLanding(rest string) string {
	if len(rest) > configTraversalLandingWindow {
		rest = rest[:configTraversalLandingWindow]
	}
	if k := strings.IndexAny(rest, "&?# \t\r\n"); k >= 0 {
		rest = rest[:k]
	}
	return rest
}

// hasConfigTraversalLanding 判断 s 里是否存在「穿越序列 + 分隔符 + 窗口内高危配置文件」。
//
// 判据在**原始串**上匹配，不做任何解码：调用方传入的 raw 保留原始百分号编码，
// 归一化会把 `%252e%252e` 压成 `../../`，从而抹掉「用了几层编码」这一信息——
// 这正是既有 path_traversal:011 判据在归一化串上恒不命中的原因。
//
// 预筛 `strings.Contains(s, "..")` 是必要的：绝大多数请求的 path 与 query 里
// 不含连续点号，预筛把主循环的成本压到只在可疑串上发生。
func hasConfigTraversalLanding(s string) bool {
	if len(s) < 5 || !strings.Contains(s, "..") {
		return false
	}
	for i := 0; i+2 <= len(s); i++ {
		if s[i] != '.' || s[i+1] != '.' {
			continue
		}
		rest := s[i+2:]
		for _, sep := range configTraversalSeparators {
			if len(rest) < len(sep) || !equalASCIIFold(rest[:len(sep)], sep) {
				continue
			}
			window := stripTraversalLanding(rest[len(sep):])
			for _, tok := range configTraversalLandingTokens {
				if containsASCIIFold(window, tok) {
					return true
				}
			}
		}
	}
	return false
}

// hasMultiEncodedTraversal 判断 s 里是否存在「点对 + 三重编码分隔符」形态。
// 长度下限 8 是因为最短命中形态 `..%25252f` 长 9 字节，`%2e%2e%25252f` 长 13
// 字节；下限只作廉价的早退，不参与语义判定。
func hasMultiEncodedTraversal(s string) bool {
	if len(s) < 9 {
		return false
	}
	for _, dots := range multiEncodedTraversalDots {
		if !containsASCIIFold(s, dots) {
			continue
		}
		for i := 0; i+len(dots) <= len(s); i++ {
			if !equalASCIIFold(s[i:i+len(dots)], dots) {
				continue
			}
			rest := s[i+len(dots):]
			for _, sep := range multiEncodedSeparators {
				if len(rest) >= len(sep) && equalASCIIFold(rest[:len(sep)], sep) {
					return true
				}
			}
		}
	}
	return false
}

// checkConfigFileTraversal 检测「穿越序列指向应用配置文件」的路径穿越载荷。
// path 与 query 都要传：语料实测该族的漏检里 path 侧 39 条、query 侧 105 条，
// 只查 path 会丢掉三分之二的检出面。
func checkConfigFileTraversal(path, query string) (OWASPHit, bool) {
	if hasConfigTraversalLanding(path) || hasConfigTraversalLanding(query) ||
		hasMultiEncodedTraversal(path) || hasMultiEncodedTraversal(query) {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:018", Score: 5,
			Desc: "路径穿越指向应用配置文件或使用多重编码分隔符"}, true
	}
	return OWASPHit{}, false
}
