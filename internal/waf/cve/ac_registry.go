package cve

import "My-OpenWaf/internal/ac"

var registryACData struct {
	ac    *ac.Matcher
	masks map[string]ac.Mask // CVE-ID → 该规则 needle 的 bitset
}

func init() {
	initRegistryAC()
}

// registryNeedleGroups 按 CVE-ID 分组的 gate needle,精确对应
// shouldScanRegisteredCVERuleAC 中纯 OR gate(经 registryACGate)的 CVE。
// 键为 CVE-ID 字符串,值为该规则的 needle 列表(小写字面量,与原 gate 一致)。
// 走 shouldScanRegisteredCVERuleAC 的复合 helper case。
var registryNeedleGroups = map[string][]string{
	"CVE-2014-6271":       {"() {"},
	"CVE-2025-24893":      {"solrsearch", "media=rss", "groovy", "{{async", "{{ async"},
	"CVE-2025-47812":      {"loginok.html", "%00", "io.popen", "lua"},
	"CVE-2025-4632":       {"swupdatefileuploader", "filename=", "magicinfo", "../"},
	"CVE-2025-64446":      {"fwbcgi", "cgiinfo"},
	"CVE-2025-10035":      {"unlicensed.xhtml", "garequestaction=activate", "javax.faces.viewstate"},
	"CVE-2025-41243":      {"actuator/gateway", "addresponseheader", "#{", "spel"},
	"CVE-2025-47916":      {"themeeditor", "customcss", "expression="},
	"CVE-2025-31161":      {"webinterface/function", "aws4-hmac-sha256", "crushftp"},
	"CVE-2025-32756":      {"hostcheck_validate", "authhash"},
	"CVE-2017-8046":       {"json-patch", "application/patch+json", "spel", "#{", "t("},
	"CVE-2021-21351":      {"<java", "<sorted-set", "<dynamic-proxy", "xstream", "processbuilder", "runtime"},
	"CVE-2024-REMOTECALL": {"jndi:", "ldap://", "rmi://", "iiop://", "jdbc:", "dns://"},
	"CVE-2024-XXEUTF7":    {"utf-7", "+adw-", "+adi-", "+afw-"},
	"CVE-2024-LDAPI":      {"objectclass=", ")(|", ")(uid=", "*)(", "ldap"},
	"CVE-2024-SENSFILE": {
		"/.env", "/.git/", "/.gitignore", "/.htaccess", "/.htpasswd",
		"/wp-config.php", "/web.config", "/database.yml", "/settings.py",
		"/application.", "/etc/", "/.ds_store", "/.svn/entries", "/.svn/wc.db",
		"/.idea/workspace.xml", "/.vscode/settings.json", "/composer.",
		"/package.json", "/gemfile", "/requirements.txt", "/dockerfile",
		"/docker-compose.y", "/.aws/credentials", "/.ssh/", "/.bash_history",
		"/.mysql_history", "/phpinfo.php", "/adminer.php", "/info.php",
		"/server-status", "/server-info", "/.well-known/security.txt",
		"/backup.", "/dump.sql", "/web-inf/web.xml", "/meta-inf/manifest.mf",
	},
	"CVE-2026-35273": {"psemhub"},
	// 以下 6 条此前落在 shouldScanRegisteredCVERuleAC 的 default: return true，
	// 即没有任何前置门，每个请求都必跑 CheckFunc。needle 取各自 CheckFunc 所用
	// 正则的**必要字面**（正则命中 ⇒ 该字面必在串中出现），因此只减少调用次数，
	// 不改变任何判定。
	//
	// CVE-2021-44228：reLog4j1..7 中 6 条含 `${`，第 5 条含 `%24%7Bjndi:`；
	// reLog4j4 `${(lower|upper|env|sys|java|:)+...` 的必要字面亦为 `${`。
	"CVE-2021-44228": {"${", "%24%7bjndi:"},
	// CVE-2024-2961：reWPFileRead `(?i)/wp-admin/admin-ajax\.php.*action=.*file`
	// 的前缀字面（`\.php` 的点已转义，故字面含 `.`）。
	"CVE-2024-2961": {"/wp-admin/admin-ajax.php"},
	// CVE-2024-4577：CheckFunc 为
	// rePHPCGI_SoftHyphenArg ∧ (rePHPCGI_AutoPrepend ∨ rePHPCGI_AllowInclude)，
	// 故合取式中的右支整体是必要条件（左支 `%[aA][dD].*-[drnfem]` 无足够专一
	// 的字面可取）。
	"CVE-2024-4577": {"auto_prepend_file", "allow_url_include"},
	// CVE-2025-24813：reTomcat1 `(?i)\.session\.\d+\.ser`。
	"CVE-2025-24813": {".session."},
	// CVE-2025-29927：CheckFunc 要求头名名为 x-middleware-subrequest，
	// 头名字面本身即必要条件（且 registryCombinedLower 拼接时保留头名）。
	"CVE-2025-29927": {"x-middleware-subrequest"},
	// CVE-2025-55182：CheckFunc 为
	// reRSCFlightRef ∧ (reRSCProtoConstructor ∨ reRSCConstructorChain)，
	// 两支均含 `constructor` 字面。
	"CVE-2025-55182": {"constructor"},
}

func initRegistryAC() {
	b := ac.NewBuilder()
	masks := make(map[string]ac.Mask, len(registryNeedleGroups))

	for cveID, needles := range registryNeedleGroups {
		var mask ac.Mask
		for _, n := range needles {
			idx := b.AddPattern(n)
			mask.Set(idx)
		}
		masks[cveID] = mask
	}

	registryACData.ac = b.Build()
	registryACData.masks = masks
}

// registryACGate 使用预编译的 AC bitset 判断纯 OR gate 是否通过,
// 等价于对应 registeredCVERuleContainsAny(combinedLower, ...needles)。
func registryACGate(cveID string, hit *ac.Mask) bool {
	mask, ok := registryACData.masks[cveID]
	if !ok {
		return true // 无 AC gate 的规则不拦截(与 default: return true 一致)
	}
	return hit.Intersects(&mask)
}
