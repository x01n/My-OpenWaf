package cve

// registryACData 编译期生成的 registry gate Aho-Corasick 自动机与规则 mask。
// 用于 shouldScanRegisteredCVERule 中纯 registeredCVERuleContainsAny gate 的
// 等价替换:一遍 matchMask(combinedLower) 替代逐规则多针 strings.Contains。
var registryACData struct {
	ac    *acMatcher
	masks map[string]acGateMask // CVE-ID → 该规则 needle 的 bitset
}

func init() {
	initRegistryAC()
}

// registryNeedleGroups 按 CVE-ID 分组的 gate needle,精确对应
// shouldScanRegisteredCVERule 中纯 registeredCVERuleContainsAny 的 case。
// 键为 CVE-ID 字符串,值为该规则的 needle 列表(小写字面量,与原 gate 一致)。
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
	"CVE-2024-SENSFILE":   {"/.env", "/.git/config", "/.htaccess", "/wp-config.php", "/web.config", "/etc/passwd"},
}

func initRegistryAC() {
	b := newACBuilder()
	masks := make(map[string]acGateMask, len(registryNeedleGroups))

	for cveID, needles := range registryNeedleGroups {
		var mask acGateMask
		for _, n := range needles {
			idx := b.addPattern(n)
			mask.set(idx)
		}
		masks[cveID] = mask
	}

	registryACData.ac = b.build()
	registryACData.masks = masks
}

// registryACGate 使用预编译的 AC bitset 判断纯 OR gate 是否通过,
// 等价于对应 registeredCVERuleContainsAny(combinedLower, ...needles)。
func registryACGate(cveID string, hit *acGateMask) bool {
	mask, ok := registryACData.masks[cveID]
	if !ok {
		return true // 无 AC gate 的规则不拦截(与 default: return true 一致)
	}
	return hit.intersects(&mask)
}
