package owasp

import "strings"

// Cisco ASA 路径遍历判据的三个档位。
const (
	// CiscoASAModeLegacy 保留历史判据：`+CSCOT+` 与 `+CSCOE+` 一并拦截。
	// 数据面未配置档位时不会使用此档；显式配置 legacy 可恢复历史行为。
	CiscoASAModeLegacy = "legacy"
	// CiscoASAModeStrict 只保留 `+CSCOT+` 及其编码变体，误报归零。
	CiscoASAModeStrict = "strict"
	// CiscoASAModeScoped 在 legacy 基础上放过「带 tgroup= 查询参数」的
	// `+CSCOE+` 请求，即放过 VPN 门户登录页跳转。
	CiscoASAModeScoped = "scoped"
)

// ciscoASAModeValues 是合法档位集合，供配置解析与校验复用。
var ciscoASAModeValues = map[string]bool{
	CiscoASAModeLegacy: true,
	CiscoASAModeStrict: true,
	CiscoASAModeScoped: true,
}

// NormalizeCiscoASAMode 归一化显式档位字符串；未知值回落到 legacy。
// 数据面未配置档位时由 internal/core/rules 注入 scoped；此函数保持配置值
// 无效时的安全回落，显式 legacy 仍可恢复历史行为。
func NormalizeCiscoASAMode(raw string) string {
	mode := strings.ToLower(strings.TrimSpace(raw))
	if ciscoASAModeValues[mode] {
		return mode
	}
	return CiscoASAModeLegacy
}

// IsValidCiscoASAMode 判断字符串是否为合法档位（空串视为合法，等价 legacy）。
func IsValidCiscoASAMode(raw string) bool {
	s := strings.TrimSpace(raw)
	return s == "" || ciscoASAModeValues[strings.ToLower(s)]
}

// ciscoCSCOTTokens 是 CVE-2020-3452 的利用路径段（含 URL 编码变体）。
var ciscoCSCOTTokens = []string{"+cscot+/", "%2bcscot%2b/"}

// ciscoCSCOETokens 是 ASA WebVPN 门户路径段（含 URL 编码变体）。
// 它同时出现在攻击流量与正常门户登录里，因此单列一组以便按档位取舍。
var ciscoCSCOETokens = []string{"+cscoe+/", "%2bcscoe%2b/"}

// ciscoPortalTraversalMarkers 是路径穿越序列的通用形态标记（大小写不敏感）。
//
// 用于 scoped 档的放行前置校验：真实的门户登录页跳转不会在 path 里携带
// 穿越序列，出现即说明该请求是在借 tgroup= 掩护穿越。标记只取形态本身，
// 不取任何具体的目标文件或目录名。
var ciscoPortalTraversalMarkers = []string{"../", "..\\", "..;/", "%2e%2e", "%252e", "..%2f", "..%5c"}

// hasCiscoPortalTraversalMarker 判断 path 是否携带路径穿越序列标记。
func hasCiscoPortalTraversalMarker(path string) bool {
	return containsAnyFold(path, ciscoPortalTraversalMarkers)
}

func containsAnyFold(s string, tokens []string) bool {
	for _, t := range tokens {
		if containsASCIIFold(s, t) {
			return true
		}
	}
	return false
}

// hasCiscoTunnelGroupQuery 判断查询串是否携带 `tgroup=` 参数。
//
// 用「参数名精确匹配且必须带等号」而不是子串包含：`tgroup` 之前必须是
// `&` 或串首，之后必须是 `=`。这样 `foobartgroup=x`、`tgroupx=y` 都不算
// 命中；裸键 `tgroup`（不带 `=`）也不算——真实 ASA 门户跳转一律带 `=`，
// 少放行一种形态就少一条漏检面。
func hasCiscoTunnelGroupQuery(query string) bool {
	for query != "" {
		pair := query
		if i := strings.IndexByte(pair, '&'); i >= 0 {
			pair, query = pair[:i], query[i+1:]
		} else {
			query = ""
		}
		if pair == "" {
			continue
		}
		name, _, hasEq := strings.Cut(pair, "=")
		if !hasEq {
			continue
		}
		if strings.EqualFold(name, "tgroup") {
			return true
		}
	}
	return false
}

func checkCiscoASAPathTraversal(path, query, mode string) (OWASPHit, bool) {
	return CheckCiscoASAPathTraversal(path, query, mode)
}

/**
 * CheckCiscoASAPathTraversal 是 Cisco ASA 路径遍历判据的导出版本。
 *
 * 数据面在通用管道之前有一道内联护栏（internal/dataplane/endpoints.go 的
 * matchInlineOWASPGuards），它必须与这里的三档语义逐字节一致，否则同一请求
 * 走完整管道与被内联护栏短路会得到相反结论。导出本函数就是为了让那道护栏
 * 复用同一份判据，而不是复制一份字符串匹配。
 *
 * @param path  请求路径（原始串，未归一化）。
 * @param query 原始查询串。
 * @param mode  档位；空串/未知值按 NormalizeCiscoASAMode 回落。
 * @return 命中结果与是否命中。
 */
func CheckCiscoASAPathTraversal(path, query, mode string) (OWASPHit, bool) {
	switch NormalizeCiscoASAMode(mode) {
	case CiscoASAModeStrict:
		if containsAnyFold(path, ciscoCSCOTTokens) {
			return ciscoASAHit(), true
		}
		return OWASPHit{}, false
	case CiscoASAModeScoped:
		hasCscot := containsAnyFold(path, ciscoCSCOTTokens)
		hasCscoe := containsAnyFold(path, ciscoCSCOETokens)
		if !hasCscot && !hasCscoe {
			return OWASPHit{}, false
		}
		if !hasCscot && hasCiscoTunnelGroupQuery(query) && !hasCiscoPortalTraversalMarker(path) {
			return OWASPHit{}, false
		}
		return ciscoASAHit(), true
	default:
		if containsAnyFold(path, ciscoCSCOTTokens) || containsAnyFold(path, ciscoCSCOETokens) {
			return ciscoASAHit(), true
		}
		return OWASPHit{}, false
	}
}

/**
 * CheckCiscoASAInlineGuard 供数据面管道前护栏使用。
 *
 * 档位语义与 CheckCiscoASAPathTraversal 完全一致（未配置 ⇔ scoped、strict 只留
 * CSCOT、legacy 全留），差别只在 token 形态：引擎在归一化后的目标上比对，
 * 要求 `+CSCOT+/` 带尾斜杠；护栏在原始 path 上、归一化之前执行，历史上是按
 * 子串判定的，`/translation-table/+CSCOT+` 这类不带尾斜杠的变体必须继续命中。
 * 收紧成带尾斜杠会让既有拦截面缩水，因此这里单列一组宽松 token。
 *
 * @param path  原始请求路径。
 * @param query 原始查询串。
 * @param mode  档位；空串/未知值由 NormalizeCiscoASAMode 回落。
 * @return 护栏应当拦截时为 true。
 */
func CheckCiscoASAInlineGuard(path, query, mode string) bool {
	hasCscot := containsAnyFold(path, ciscoInlineCSCOTTokens)
	hasCscoe := containsAnyFold(path, ciscoInlineCSCOETokens)
	switch NormalizeCiscoASAMode(mode) {
	case CiscoASAModeStrict:
		return hasCscot
	case CiscoASAModeScoped:
		if !hasCscot && !hasCscoe {
			return false
		}
		if !hasCscot && hasCiscoTunnelGroupQuery(query) && !hasCiscoPortalTraversalMarker(path) {
			return false
		}
		return true
	default:
		return hasCscot || hasCscoe
	}
}

// ciscoInlineCSCOTTokens 是护栏使用的宽松 CSCOT 形态（不带尾斜杠）。
var ciscoInlineCSCOTTokens = []string{"+cscot+", "%2bcscot%2b"}

// ciscoInlineCSCOETokens 是护栏使用的宽松 CSCOE 形态（不带尾斜杠）。
var ciscoInlineCSCOETokens = []string{"+cscoe+", "%2bcscoe%2b"}

func ciscoASAHit() OWASPHit {
	return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:006", Score: 5,
		Desc: "Cisco ASA 路径遍历"}
}

func checkDangerousPathWithMode(path, query, mode string) (OWASPHit, bool) {
	if hit, ok := checkCiscoASAPathTraversal(path, query, mode); ok {
		return hit, true
	}
	// path:018 在**原始串**上判「穿越序列指向应用配置文件」与「多重编码分隔符」，
	// 需要 path 与 query 两个入参，因此挂在带 query 的入口而不是
	// checkDangerousPathExceptCisco
	if hit, ok := checkConfigFileTraversal(path, query); ok {
		return hit, true
	}
	return checkDangerousPathExceptCisco(path)
}

// checkDangerousPathExceptCisco 复刻 checkDangerousPath 的其余 16 条判据，
// 跳过 Cisco ASA 分支（该分支已由 checkCiscoASAPathTraversal 处理）。
// 入参只有 path：这些判据都是历史上按单参定义的子串匹配。
func checkDangerousPathExceptCisco(path string) (OWASPHit, bool) {
	// path:001 / 002 / 004 / 005
	if containsASCIIFold(path, "/mgmt/tm/util/bash") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:001", Score: 6,
			Desc: "F5 BIG-IP 远程代码执行端点"}, true
	}
	if containsASCIIFold(path, "/api/jsonws/invoke") {
		return OWASPHit{Category: CatDeserial, RuleID: "owasp:path:002", Score: 6,
			Desc: "Liferay JSONWS 反序列化端点"}, true
	}
	if containsASCIIFold(path, "/webtools/control/xmlrpc") ||
		containsASCIIFold(path, "/webtools/control/soapservice") {
		return OWASPHit{Category: CatDeserial, RuleID: "owasp:path:004", Score: 6,
			Desc: "Apache OFBiz webtools 远程代码执行端点"}, true
	}
	if containsASCIIFold(path, "/rest/tinymce/1/macro/preview") {
		return OWASPHit{Category: CatExprLang, RuleID: "owasp:path:005", Score: 6,
			Desc: "Confluence OGNL 注入端点"}, true
	}
	// path:007 / 008 / 009 / 010 / 011 / 012 / 013
	if containsASCIIFold(path, "/think") && containsASCIIFold(path, "invokefunction") {
		return OWASPHit{Category: CatWebshell, RuleID: "owasp:path:007", Score: 6,
			Desc: "ThinkPHP invokefunction 远程代码执行"}, true
	}
	if containsASCIIFold(path, "/gadgets/makerequest") {
		return OWASPHit{Category: CatSSRF, RuleID: "owasp:path:008", Score: 5,
			Desc: "Atlassian gadgets SSRF 端点"}, true
	}
	if containsASCIIFold(path, "coreui_user") || containsASCIIFold(path, "coreui_component") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:009", Score: 5,
			Desc: "Nexus Repository Manager 远程代码执行"}, true
	}
	if containsASCIIFold(path, "/mailsms/") {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:010", Score: 5,
			Desc: "Coremail 配置泄露"}, true
	}
	if containsASCIIFold(path, "/.git/") || (len(path) >= 5 && equalASCIIFold(path[len(path)-5:], "/.git")) {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:011", Score: 5,
			Desc: ".git 目录访问"}, true
	}
	if containsASCIIFold(path, "/securityrealm/") && containsASCIIFold(path, "descriptorbyname") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:012", Score: 5,
			Desc: "Jenkins Script Security 远程代码执行"}, true
	}
	if containsASCIIFold(path, "deleteusername") || containsASCIIFold(path, "deleteuserrequestinfobyxml") {
		return OWASPHit{Category: CatXXE, RuleID: "owasp:path:013", Score: 5,
			Desc: "OFS XML 外部实体端点"}, true
	}
	// path:014 / 015 / 016 / 017
	if strings.Contains(path, ";") && (containsASCIIFold(path, "swagger") ||
		containsASCIIFold(path, "actuator") || containsASCIIFold(path, "admin") ||
		containsASCIIFold(path, "console") || containsASCIIFold(path, "manager")) {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:014", Score: 5,
			Desc: "分号路径参数绕过"}, true
	}
	if containsASCIIFold(path, "/api/index.php/v1/config/") ||
		(containsASCIIFold(path, "/api/") && containsASCIIFold(path, "/v1/config/application")) {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:015", Score: 5,
			Desc: "Joomla API 配置信息泄露"}, true
	}
	if containsASCIIFold(path, "/service/rest/") && containsASCIIFold(path, "/repositories/") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:016", Score: 5,
			Desc: "Nexus Repository Manager API 访问"}, true
	}
	if containsASCIIFold(path, "/service/extdirect") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:017", Score: 5,
			Desc: "ExtDirect 远程代码执行端点"}, true
	}
	return OWASPHit{}, false
}
