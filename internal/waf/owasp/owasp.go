package owasp

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

type OWASPCategory string

const (
	CatSQLi       OWASPCategory = "sqli"
	CatWebshell   OWASPCategory = "webshell"
	CatRevShell   OWASPCategory = "revshell"
	CatXSS        OWASPCategory = "xss"
	CatPathTrav   OWASPCategory = "path_traversal"
	CatSSRF       OWASPCategory = "ssrf"
	CatCmdInject  OWASPCategory = "cmd_injection"
	CatXXE        OWASPCategory = "xxe"
	CatLDAPI      OWASPCategory = "ldap_injection"
	CatFileUpload OWASPCategory = "file_upload"
	CatProtoViol  OWASPCategory = "protocol_violation"
	CatNoSQLi     OWASPCategory = "nosql_injection"
	CatTmplInject OWASPCategory = "template_injection"
	CatJNDI       OWASPCategory = "jndi_injection"
	CatCRLF       OWASPCategory = "crlf_injection"
	CatExprLang   OWASPCategory = "expression_language"
	CatDeserial   OWASPCategory = "deserialization"
	CatGraphQLi   OWASPCategory = "graphql_injection"
	// CatMaliciousClient 表示请求自报为已知攻击/扫描工具。它是确定性签名，
	// 不参与评分阈值，但仍受规则级开关与类别灵敏度过滤。
	CatMaliciousClient OWASPCategory = "malicious_client"
)

const BuiltinVersion = "builtin_owasp_v2"

// maxTargetLen 限制单个扫描目标的长度，以约束正则执行时间。
const maxTargetLen = 16384

var asciiLowerTable = func() [256]byte {
	var table [256]byte
	for i := 0; i < 256; i++ {
		b := byte(i)
		if b >= 'A' && b <= 'Z' {
			table[i] = b + ('a' - 'A')
		} else {
			table[i] = b
		}
	}
	return table
}()

// owaspPattern 表示一条 OWASP 检测规则。
// hint 字段是该正则必须匹配的字面量子串；如果非空，在执行正则前
// 先用 strings.Contains 快速检查，不存在则跳过该正则。
type owaspPattern struct {
	re    *regexp.Regexp
	score int
	id    string
	hint  string
}

type OWASPHit struct {
	Category OWASPCategory
	RuleID   string
	Score    int
	Snippet  string
	Desc     string
}

type categoryThresholdConfig struct {
	threshold int
	enabled   bool
}

type CompiledThresholds struct {
	sqli       categoryThresholdConfig
	xss        categoryThresholdConfig
	cmd        categoryThresholdConfig
	webshell   categoryThresholdConfig
	revShell   categoryThresholdConfig
	pathTrav   categoryThresholdConfig
	ssrf       categoryThresholdConfig
	xxe        categoryThresholdConfig
	ldap       categoryThresholdConfig
	nosqli     categoryThresholdConfig
	template   categoryThresholdConfig
	jndi       categoryThresholdConfig
	crlf       categoryThresholdConfig
	exprLang   categoryThresholdConfig
	deserial   categoryThresholdConfig
	graphql    categoryThresholdConfig
	proto      categoryThresholdConfig
	fileUpload categoryThresholdConfig
}

func CompileThresholds(sensitivity string, categorySensitivity ...map[string]string) CompiledThresholds {
	var categorySensitivityMap map[string]string
	if len(categorySensitivity) > 0 {
		categorySensitivityMap = categorySensitivity[0]
	}
	compile := func(category OWASPCategory) categoryThresholdConfig {
		threshold, enabled := CategoryThreshold(sensitivity, category, categorySensitivityMap)
		return categoryThresholdConfig{threshold: threshold, enabled: enabled}
	}
	return CompiledThresholds{
		sqli:       compile(CatSQLi),
		xss:        compile(CatXSS),
		cmd:        compile(CatCmdInject),
		webshell:   compile(CatWebshell),
		revShell:   compile(CatRevShell),
		pathTrav:   compile(CatPathTrav),
		ssrf:       compile(CatSSRF),
		xxe:        compile(CatXXE),
		ldap:       compile(CatLDAPI),
		nosqli:     compile(CatNoSQLi),
		template:   compile(CatTmplInject),
		jndi:       compile(CatJNDI),
		crlf:       compile(CatCRLF),
		exprLang:   compile(CatExprLang),
		deserial:   compile(CatDeserial),
		graphql:    compile(CatGraphQLi),
		proto:      compile(CatProtoViol),
		fileUpload: compile(CatFileUpload),
	}
}

// CheckOWASP 扫描请求各字段，检测 OWASP 相关攻击。
// bodyTargets 是从请求体预提取的值（表单值、JSON 叶子节点）。
// path 参数同时用于上下文判断：内部 API 路径会降低扫描强度。
func CheckOWASP(sensitivity string, path, query string, headers map[string]string, bodyTargets []string, categorySensitivity ...map[string]string) []OWASPHit {
	return CheckOWASPWithThresholdsAndMode(CompileThresholds(sensitivity, categorySensitivity...), path, query, headers, bodyTargets, "")
}

func CheckOWASPWithThresholds(thresholds CompiledThresholds, path, query string, headers map[string]string, bodyTargets []string) []OWASPHit {
	return CheckOWASPWithThresholdsAndMode(thresholds, path, query, headers, bodyTargets, "")
}

func CheckOWASPWithThresholdsAndMode(thresholds CompiledThresholds, path, query string, headers map[string]string, bodyTargets []string, mode string) []OWASPHit {
	hit, ok, multi := firstOWASPHitWithThresholds(thresholds, path, query, headers, bodyTargets, nil, mode)
	if multi != nil {
		return multi
	}
	if ok {
		return []OWASPHit{hit}
	}
	return nil
}

// FirstOWASPHitWithThresholds 返回首个 OWASP 命中，不在 stop/deep/early 路径分配 []OWASPHit。
// multi 场景（末尾协议/上传/危险路径软命中列表）取第一个。
func FirstOWASPHitWithThresholds(thresholds CompiledThresholds, path, query string, headers map[string]string, bodyTargets []string) (OWASPHit, bool) {
	return FirstOWASPHitWithThresholdsAndMode(thresholds, path, query, headers, bodyTargets, "")
}

func FirstOWASPHitWithThresholdsAndMode(thresholds CompiledThresholds, path, query string, headers map[string]string, bodyTargets []string, mode string) (OWASPHit, bool) {
	hit, ok, multi := firstOWASPHitWithThresholds(thresholds, path, query, headers, bodyTargets, nil, mode)
	if multi != nil {
		if len(multi) == 0 {
			return OWASPHit{}, false
		}
		return multi[0], true
	}
	return hit, ok
}

// FirstAcceptedOWASPHitWithThresholds 返回第一个通过覆盖/白名单过滤的命中。
// 过滤器在每个早停候选产生时执行；被跳过的候选会继续扫描其余类别。
func FirstAcceptedOWASPHitWithThresholds(thresholds CompiledThresholds, path, query string, headers map[string]string, bodyTargets []string, overrides map[string]OWASPRuleOverride, catSens ...map[string]string) (OWASPHit, bool) {
	return firstAcceptedOWASPHitWithThresholdsMode(thresholds, path, query, headers, bodyTargets, overrides, "", catSens...)
}

func FirstAcceptedOWASPHitWithThresholdsAndMode(thresholds CompiledThresholds, path, query string, headers map[string]string, bodyTargets []string, overrides map[string]OWASPRuleOverride, mode string, catSens ...map[string]string) (OWASPHit, bool) {
	return firstAcceptedOWASPHitWithThresholdsMode(thresholds, path, query, headers, bodyTargets, overrides, mode, catSens...)
}

func firstAcceptedOWASPHitWithThresholdsMode(thresholds CompiledThresholds, path, query string, headers map[string]string, bodyTargets []string, overrides map[string]OWASPRuleOverride, mode string, catSens ...map[string]string) (OWASPHit, bool) {
	if len(overrides) == 0 {
		return FirstOWASPHitWithThresholdsAndMode(thresholds, path, query, headers, bodyTargets, mode)
	}
	var categorySensitivity map[string]string
	if len(catSens) > 0 {
		categorySensitivity = catSens[0]
	}
	accept := func(hit OWASPHit) bool {
		return HitPassesFilters(hit, path, overrides, categorySensitivity)
	}
	hit, ok, multi := firstOWASPHitWithThresholds(thresholds, path, query, headers, bodyTargets, accept, mode)
	if multi != nil {
		if len(multi) == 0 {
			return OWASPHit{}, false
		}
		return multi[0], true
	}
	return hit, ok
}

func acceptsOWASPHit(accept func(OWASPHit) bool, hit OWASPHit) bool {
	return accept == nil || accept(hit)
}

// pathContainsTreePrefix 判断 path 中是否存在以完整路径段为边界的 prefix。
// 允许 prefix 出现在根路径或嵌套路径中，但不匹配更长的同名前缀，
// 例如 /g/collect 不匹配 /g/collector。
func pathContainsTreePrefix(path, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	if path == "" || prefix == "" {
		return false
	}
	for start := 0; start < len(path); {
		rel := strings.Index(path[start:], prefix)
		if rel < 0 {
			return false
		}
		idx := start + rel
		end := idx + len(prefix)
		if end == len(path) || path[end] == '/' {
			return true
		}
		start = idx + 1
	}
	return false
}

func firstOWASPHitWithThresholds(thresholds CompiledThresholds, path, query string, headers map[string]string, bodyTargets []string, accept func(OWASPHit) bool, ciscoMode string) (hit OWASPHit, ok bool, multi []OWASPHit) {
	sqliThreshold, sqliEnabled := thresholds.sqli.threshold, thresholds.sqli.enabled
	xssThreshold, xssEnabled := thresholds.xss.threshold, thresholds.xss.enabled
	cmdThreshold, cmdEnabled := thresholds.cmd.threshold, thresholds.cmd.enabled
	webshellThreshold, webshellEnabled := thresholds.webshell.threshold, thresholds.webshell.enabled
	revShellThreshold, revShellEnabled := thresholds.revShell.threshold, thresholds.revShell.enabled
	pathTravThreshold, pathTravEnabled := thresholds.pathTrav.threshold, thresholds.pathTrav.enabled
	ssrfThreshold, ssrfEnabled := thresholds.ssrf.threshold, thresholds.ssrf.enabled
	xxeThreshold, xxeEnabled := thresholds.xxe.threshold, thresholds.xxe.enabled
	ldapThreshold, ldapEnabled := thresholds.ldap.threshold, thresholds.ldap.enabled
	nosqliThreshold, nosqliEnabled := thresholds.nosqli.threshold, thresholds.nosqli.enabled
	templateThreshold, templateEnabled := thresholds.template.threshold, thresholds.template.enabled
	jndiThreshold, jndiEnabled := thresholds.jndi.threshold, thresholds.jndi.enabled
	crlfThreshold, crlfEnabled := thresholds.crlf.threshold, thresholds.crlf.enabled
	exprLangThreshold, exprLangEnabled := thresholds.exprLang.threshold, thresholds.exprLang.enabled
	deserialThreshold, deserialEnabled := thresholds.deserial.threshold, thresholds.deserial.enabled
	graphqlThreshold, graphqlEnabled := thresholds.graphql.threshold, thresholds.graphql.enabled
	protoThreshold, protoEnabled := thresholds.proto.threshold, thresholds.proto.enabled
	fileUploadEnabled := thresholds.fileUpload.enabled

	var hits []OWASPHit
	lowerPath := toLowerASCII(path)
	snippetRaw, snippetNorm, snippetDecoded := "", "", ""
	finalizeHit := func(h OWASPHit) OWASPHit {
		if h.Snippet != "" {
			return h
		}
		for _, target := range [3]string{snippetNorm, snippetRaw, snippetDecoded} {
			if h = AttachMatchSnippet(h, target); h.Snippet != "" {
				return h
			}
		}
		return h
	}

	// 路径感知的请求体扫描抑制：已知的遥测/API 端点上，二进制或 base64 解码后的
	// 请求体内容容易产生误报，这些路径应跳过特定的请求体级检测类别。
	// path 与 query 仍照常扫描。
	skipBodyCmd := false
	skipBodyWebshell := false
	skipBodySSRF := false
	skipBodySQLi := false
	if pathContainsTreePrefix(lowerPath, "/restapi/soa2") || pathContainsTreePrefix(lowerPath, "/web/common") {
		skipBodyCmd = true
	}

	if pathContainsTreePrefix(lowerPath, "/cdn-cgi") {
		skipBodySSRF = true
	}
	if pathContainsTreePrefix(lowerPath, "/g/collect") {
		skipBodySQLi = true
	}
	if crlfEnabled && (strings.ContainsAny(path, "\r\n\v\f") ||
		strings.Contains(lowerPath, "%0d") || strings.Contains(lowerPath, "%0a") ||
		strings.Contains(lowerPath, "%0b") || strings.Contains(lowerPath, "%0c")) {
		hit := OWASPHit{Category: CatCRLF, RuleID: "owasp:crlf:005", Score: 5, Desc: "URL 路径中的裸 CR/LF 字符"}
		if acceptsOWASPHit(accept, hit) {
			return hit, true, nil
		}
	}
	if protoEnabled && hasAbsoluteFormRequestTarget(path) {
		hit := OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:011", Score: 5, Desc: "absolute-form 请求行直连源站"}
		if acceptsOWASPHit(accept, hit) {
			return hit, true, nil
		}
	}
	if protoEnabled && strings.EqualFold(path, "/uc/feedback/api/v1/pc/feedback/add") {
		for _, raw := range bodyTargets {
			if raw == "" {
				continue
			}
			normalized := normalizeWithDecode(raw)
			if isOpaqueEncodedAttackBody(raw, normalized, headers, protoThreshold) {
				hit := OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:010", Score: 5, Desc: "无 content-type 的不透明编码请求体"}
				if acceptsOWASPHit(accept, hit) {
					return hit, true, nil
				}
			}
		}
	}
	if sqliEnabled && strings.Contains(query, "/notificationx/v1/analytics") {
		hit := OWASPHit{Category: CatSQLi, RuleID: "owasp:sqli:056", Score: 6, Desc: "WordPress 插件接口时间盲注"}
		if acceptsOWASPHit(accept, hit) {
			return hit, true, nil
		}
	}
	if pathTravEnabled && strings.Contains(lowerPath, "/translation-table") && (strings.Contains(lowerPath, "+cscot+") || strings.Contains(lowerPath, "+cscoe+")) {
		if hit, ok := checkCiscoASAPathTraversal(path, query, ciscoMode); ok && acceptsOWASPHit(accept, hit) {
			return hit, true, nil
		}
	}

	// 请求体目标的 proto 检测并入下方主循环（normalizeWithDecode 每目标只算一次），
	// 避免每请求重复执行两次。

	var stopHit OWASPHit
	hasStop := false
	cleanPath := isCleanPathTarget(path)
	cleanPlainQuery := isCleanPlainQueryTarget(query)
	type unicodeBase64Target struct {
		raw              string
		queryPlusAsSpace bool
	}
	// 绝大多数请求不会进入 unicode/base64 深扫；小 cap 预分配避免 0->1->2 扩容。
	unicodeBase64Targets := make([]unicodeBase64Target, 0, 2)
	forEachOWASPTarget(path, query, headers, bodyTargets, cleanPath, cleanPlainQuery, cleanPlainQuery, func(raw string, isBodyTarget bool, queryPlusAsSpace bool) bool {
		if raw == "" {
			return true
		}
		if !isBodyTarget {
			if raw == path && cleanPath {
				return true
			}
			if raw == query && cleanPlainQuery {
				return true
			}
		}
		if len(raw) >= 30 && shouldScanUnicodeBase64Target(raw) {
			unicodeBase64Targets = append(unicodeBase64Targets, unicodeBase64Target{raw: raw, queryPlusAsSpace: queryPlusAsSpace})
		}
		// isCleanTarget 只判字符集：全字母数字加空格的串也"干净"，
		// 但形如 `1e1 union select users from password` 的多词 SQL 短语
		// 恰恰由这些字符构成，被整体跳过会漏掉 sqli:001（该规则依赖
		// 词边界而非特殊字符）。带攻击关键词的目标不得走干净短路。
		// 攻击关键词表同样必须参与短路判定：shell_exec 等纯字母下划线
		// 探测串的字符集虽然"干净"，但正是 webshell:028 的目标形态。
		if isCleanTarget(raw) && !hasLikelyBase64Candidate(raw) &&
			!hasSuspiciousKeywords(raw) && !hasPlainTargetAttackKeyword(raw) {
			return true
		}

		normalized := normalizeWithDecodeTarget(raw, queryPlusAsSpace)
		if len(normalized) > maxTargetLen {
			normalized = truncateTarget(normalized)
		}
		snippetRaw, snippetNorm, snippetDecoded = raw, normalized, raw
		// 同一目标的族指示器与规则门控共享一次统合扫描结果。
		gate := scanGateOf(normalized)

		// 不透明编码攻击体的检测只作用于请求体目标。
		// 并入主循环，避免重复计算 normalizeWithDecode。
		if protoEnabled && isBodyTarget {
			if isOpaqueEncodedAttackBody(raw, normalized, headers, protoThreshold) {
				hit := OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:010", Score: 5, Desc: "无 content-type 的不透明编码请求体"}
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}

		// Java 原生序列化流头：归一化会剥离 NUL 字节（0xAC 0xED 0x00 0x05
		// 变成 0xAC 0xED 0x05），deser:001 在归一化串上永远匹配不到，
		// 必须在此对原始目标做字节级判定。流头是 ObjectOutputStream 的
		// 固定前缀，二进制上传（图片/压缩包/Protobuf）不会随机出现。
		if deserialEnabled && strings.Contains(raw, JavaSerializationMagic) {
			hit := OWASPHit{Category: CatDeserial, RuleID: "owasp:deser:001", Score: 6, Desc: "Java 序列化魔数"}
			if acceptsOWASPHit(accept, hit) {
				stopHit, hasStop = finalizeHit(hit), true
				return false
			}
		}
		if deserialEnabled && (strings.Contains(raw, "%ac%ed") || strings.Contains(raw, "%AC%ED") ||
			strings.Contains(raw, "aced0005") || strings.Contains(raw, "ACED0005")) {
			hit := OWASPHit{Category: CatDeserial, RuleID: "owasp:deser:012", Score: 5, Desc: "Java 序列化魔数（URL 编码）"}
			if acceptsOWASPHit(accept, hit) {
				stopHit, hasStop = finalizeHit(hit), true
				return false
			}
		}

		if crlfEnabled && (strings.Contains(raw, "%0d") || strings.Contains(raw, "%0D") ||
			strings.Contains(raw, "%0a") || strings.Contains(raw, "%0A") ||
			strings.Contains(raw, "%25%30") ||
			strings.ContainsAny(raw, "\r\n")) {
			cur := raw
			for range 3 {
				// checkCRLF 内部已统一做 toLowerASCII，此处不再重复小写化。
				if hit, ok := checkCRLF(cur, crlfThreshold, nil); ok {
					if !isCRLFFalsePositive(cur, hit.RuleID) {
						if acceptsOWASPHit(accept, hit) {
							stopHit, hasStop = finalizeHit(hit), true
							return false
						}
					}
				}
				d, err := url.PathUnescape(cur)
				if err != nil || d == cur {
					break
				}
				cur = d
			}
		}
		// 对 normalized 的 CRLF 检查，确保即使原始请求中未显式包含 CRLF 编码，也能捕获潜在攻击。
		if crlfEnabled {
			if hit, ok := checkCRLF(normalized, crlfThreshold, gate); ok {
				if !isCRLFFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}

		// 字符集"干净"（纯字母/数字/下划线）不等于无可疑构造：
		// shell_exec、whoami 等命令词探测串只由这些字符组成，必须再经过
		// 攻击关键词判定，否则会在进入正则前被整体丢弃。
		if !hasSuspiciousContent(normalized) && !hasPlainTargetAttackKeyword(normalized) {
			return true
		}
		if sqliEnabled && !(isBodyTarget && skipBodySQLi) {
			hit, hitOK := nextSQLiHitWithAccept(normalized, sqliThreshold, accept, gate)
			if !hitOK && hasSQLCommentMarker(raw) {
				// 注释垫空白视图：normalizeTarget 会把 /*...*/ 删空，
				// `'/**/and/**/1` 因此粘成 `'and1`，and/or/like/case-when
				// 两侧的边界规则全部失效。仅当主视图无命中且原始目标确实带
				// 块注释标记时才补扫，避免常规请求多付一次归一化。
				spaced := normalizeSQLCommentsAsSpaces(raw, queryPlusAsSpace)
				if spaced != normalized {
					if spacedHit, spacedOK := nextSQLiHitWithAccept(spaced, sqliThreshold, accept, nil); spacedOK {
						hit, hitOK = spacedHit, true
					}
				}
			}
			if hitOK {
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}
		if xssEnabled {
			if hit, ok := nextXSSHit(normalized, xssThreshold, gate); ok {
				if !isKnownTelemetryXSSFalsePositive(path, normalized, hit.RuleID, isBodyTarget) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
			if hit, decodedTarget, ok := nextDecodedXSSHit(raw, queryPlusAsSpace, xssThreshold); ok {
				if !isKnownTelemetryXSSFalsePositive(path, decodedTarget, hit.RuleID, isBodyTarget) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}
		if cmdEnabled && !(isBodyTarget && skipBodyCmd) {
			if hit, ok := checkCmdInjection(normalized, cmdThreshold, gate); ok {
				if isKnownTelemetryCmdFalsePositive(path, normalized, hit.RuleID, isBodyTarget) {
					return true
				}
				if !isCmdInjectionFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}
		if webshellEnabled && !(isBodyTarget && skipBodyWebshell) {
			if hit, ok := checkWebshell(normalized, webshellThreshold, gate); ok {
				if !isWebshellFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}
		if revShellEnabled {
			if hit, ok := checkRevShell(normalized, revShellThreshold, gate); ok {
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}
		if pathTravEnabled {
			if hit, ok := checkPathTraversal(normalized, pathTravThreshold, gate); ok {
				if isKnownTelemetryPathTravFalsePositive(path, normalized, hit.RuleID, isBodyTarget) {
					return true
				}
				if pathTravThreshold <= 2 || !isPathTravFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}
		if ssrfEnabled && !(isBodyTarget && skipBodySSRF) {
			if hit, ok := checkSSRF(normalized, ssrfThreshold, gate); ok {
				if !isSSRFFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						hits = append(hits, hit)
					}
				}
			}
		}
		if xxeEnabled {
			if hit, ok := checkXXE(normalized, xxeThreshold, gate); ok {
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}
		if ldapEnabled {
			if hit, ok := checkLDAPInjection(normalized, ldapThreshold, gate); ok {
				if acceptsOWASPHit(accept, hit) {
					hits = append(hits, hit)
				}
			}
		}
		if nosqliEnabled {
			if hit, ok := checkNoSQLi(normalized, nosqliThreshold, gate); ok {
				if acceptsOWASPHit(accept, hit) {
					hits = append(hits, hit)
				}
			}
		}
		if templateEnabled {
			if hit, ok := checkTemplateInjection(normalized, templateThreshold, gate); ok {
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}
		if jndiEnabled {
			if hit, ok := checkJNDI(normalized, jndiThreshold, gate); ok {
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}
		if exprLangEnabled {
			if hit, ok := checkExprLang(normalized, exprLangThreshold, gate); ok {
				if !isELFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}
		if deserialEnabled {
			if hit, ok := checkDeserialization(normalized, deserialThreshold, gate); ok {
				if !isDeserFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}
		if graphqlEnabled {
			if hit, ok := checkGraphQLi(normalized, graphqlThreshold, gate); ok {
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}
		if len(hits) > 0 {
			// 软命中（ssrf/ldap/nosqli 等）取首个作为终止结果。
			stopHit, hasStop = finalizeHit(hits[0]), true
			return false
		}
		return true
	})
	if hasStop {
		return stopHit, true, nil
	}

	// 第二遍：unicode 转义内嵌 base64 的深度扫描只为能走到该路径的目标分配内存，
	// 使干净请求路径保持零分配。
	var deepHit OWASPHit
	hasDeep := false
	for _, target := range unicodeBase64Targets {
		raw := target.raw
		urlDec := raw
		if strings.Contains(raw, "%") || (target.queryPlusAsSpace && strings.Contains(raw, "+")) {
			d, err := unescapeURLComponent(raw, target.queryPlusAsSpace)
			if err == nil {
				urlDec = d
			}
		}
		if strings.Count(urlDec, "\\u00") < 5 {
			continue
		}
		jsDec := decodeJSEscapesPooled(urlDec)
		if jsDec == urlDec {
			continue
		}
		forEachBase64TokenIndex(jsDec, -1, func(start, end int) bool {
			tok := jsDec[start:end]
			if decoded := decodeBase64IfSuspicious(tok); decoded != "" {
				decodedNorm := normalize(decoded)
				if len(decoded) > maxTargetLen {
					decoded = truncateTarget(decoded)
				}
				snippetRaw, snippetNorm, snippetDecoded = decoded, decodedNorm, decoded
				if sqliEnabled {
					if hit, ok := nextSQLiHitWithAccept(decodedNorm, sqliThreshold, accept, nil); ok {
						if acceptsOWASPHit(accept, hit) {
							deepHit, hasDeep = finalizeHit(hit), true
							return false
						}
					}
				}
				if xssEnabled {
					if hit, ok := nextXSSHit(decodedNorm, xssThreshold, nil); ok {
						if !isKnownTelemetryXSSFalsePositive(path, decodedNorm, hit.RuleID, true) {
							if acceptsOWASPHit(accept, hit) {
								deepHit, hasDeep = finalizeHit(hit), true
								return false
							}
						}
					}
				}
				if cmdEnabled {
					if hit, ok := checkCmdInjection(decodedNorm, cmdThreshold, nil); ok {
						if isKnownTelemetryCmdFalsePositive(path, decodedNorm, hit.RuleID, true) {
							return true
						}
						if !isCmdInjectionFalsePositive(decodedNorm, hit.RuleID) {
							if acceptsOWASPHit(accept, hit) {
								deepHit, hasDeep = finalizeHit(hit), true
								return false
							}
						}
					}
				}
			}
			return true
		})
		if hasDeep {
			break
		}
	}
	if hasDeep {
		return deepHit, true, nil
	}

	if protoEnabled {
		if hit, ok := checkProtocolViolation(headers, protoThreshold); ok {
			if acceptsOWASPHit(accept, hit) {
				hits = append(hits, hit)
			}
		}
	}
	if fileUploadEnabled {
		if hit, ok := checkPathFileUpload(path); ok {
			if acceptsOWASPHit(accept, hit) {
				hits = append(hits, hit)
			}
		}
	}
	if pathTravEnabled {
		if hit, ok := checkDangerousPathWithMode(path, query, ciscoMode); ok {
			if acceptsOWASPHit(accept, hit) {
				hits = append(hits, hit)
			}
		}
	}
	// 恶意工具 UA 是确定性签名而非启发式评分，放在既有命中之后兜底，
	// 不改变任何已有规则的归因优先级。
	if hit, ok := CheckMaliciousUserAgent(headerUserAgent(headers)); ok {
		if acceptsOWASPHit(accept, hit) {
			hits = append(hits, hit)
		}
	}
	if len(hits) == 0 {
		return OWASPHit{}, false, nil
	}
	if len(hits) == 1 {
		return finalizeHit(hits[0]), true, nil
	}
	for i := range hits {
		hits[i] = finalizeHit(hits[i])
	}
	return OWASPHit{}, false, hits
}

func shouldScanUnicodeBase64Target(raw string) bool {
	unicodeEscapes := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '%':
			return true
		case '\\':
			if i+3 < len(raw) && raw[i+1] == 'u' && raw[i+2] == '0' && raw[i+3] == '0' {
				unicodeEscapes++
				if unicodeEscapes >= 5 {
					return true
				}
				i += 3
			}
		}
	}
	return false
}

// CheckFileUpload 检查文件名与 Content-Type 是否构成危险上传。
// 单独调用：它需要原始文件名而非归一化后的值。
func CheckFileUpload(filename, contentType string) (OWASPHit, bool) {
	return checkFileUpload(filename, contentType)
}

// CheckRawMultipartFilenames 扫描原始 multipart 请求体中的危险文件名，
// 这些文件名可能被 Go 的 mime/multipart 解析器漏掉（路径遍历、空格扩展名绕过）。
// 当 multipart.Reader 剥离路径或解析失败时，本函数作为兜底。
func CheckRawMultipartFilenames(body []byte) (OWASPHit, bool) {
	return checkRawMultipartFilenames(body)
}

var reContentDispositionFilename = regexp.MustCompile(`(?i)content-disposition:[^\n]*filename="([^"]+)"`)

func checkRawMultipartFilenames(body []byte) (OWASPHit, bool) {
	matches := reContentDispositionFilename.FindAllSubmatch(body, 10)
	for _, m := range matches {
		filename := string(m[1])
		lower := strings.ToLower(filename)
		// 文件名中的空字节注入（如 shell.php\x00.jpg）
		if strings.Contains(filename, "\x00") || strings.Contains(lower, "%00") {
			return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:001", Score: 6,
				Desc: "文件名中包含空字节"}, true
		}
		// 文件名中的路径遍历
		if strings.Contains(lower, "../") || strings.Contains(lower, "..\\") {
			return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:006", Score: 6,
				Desc: "文件名中包含路径遍历"}, true
		}
		// 归一化用于伪装可执行扩展名的空格与后缀分隔符。
		normalized := normalizeUploadFilename(lower)
		ext := filepath.Ext(normalized)
		if ext != "" {
			withoutExt := normalized[:len(normalized)-len(ext)]
			secondExt := filepath.Ext(withoutExt)
			if secondExt != "" && dangerousExtensions[secondExt] {
				return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:002", Score: 5,
					Desc: "双扩展名上传：" + secondExt + ext}, true
			}
		}
		if dangerousExtensions[ext] {
			return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:003", Score: 5,
				Desc: "危险文件扩展名：" + ext}, true
		}
	}
	return OWASPHit{}, false
}

// CheckMethodViolation 检查 HTTP 方法是否为异常或危险方法。
// 与 CheckOWASP 分开调用：method 不属于常规的目标扫描流水线。
func CheckMethodViolation(method string, headers map[string]string) (OWASPHit, bool) {
	return checkMethodViolation(method, headers)
}

var webExecutableExtensions = map[string]bool{
	".php": true, ".php3": true, ".php4": true, ".php5": true,
	".phtml": true, ".pht": true, ".phar": true,
	".shtml": true, ".shtm": true, ".stm": true,
	".jsp": true, ".jspx": true,
	".asp": true, ".aspx": true, ".cer": true, ".cfm": true,
	".pl": true, ".py": true, ".rb": true, ".htaccess": true,
}

// checkPathFileUpload 检测 URL 路径中的双扩展名绕过，
// 例如 /uploadfiles/shell.php.jpg。像 /page.php 这样的单扩展名
// 属正常 Web 请求，不应触发。
func checkPathFileUpload(path string) (OWASPHit, bool) {
	if path == "" || !strings.Contains(path, ".") {
		return OWASPHit{}, false
	}
	idx := strings.LastIndexByte(path, '/')
	filename := path[idx+1:]
	if filename == "" || !strings.Contains(filename, ".") {
		return OWASPHit{}, false
	}
	lower := strings.ToLower(filename)
	ext := strings.ToLower(filepath.Ext(lower))
	if ext == "" {
		return OWASPHit{}, false
	}
	withoutExt := lower[:len(lower)-len(ext)]
	secondExt := filepath.Ext(withoutExt)
	if secondExt != "" && dangerousExtensions[secondExt] && webExecutableExtensions[secondExt] {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:002", Score: 5,
			Desc: "路径中的双扩展名：" + secondExt + ext}, true
	}
	if strings.Contains(lower, "\x00") || strings.Contains(lower, "%00") {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:001", Score: 6,
			Desc: "路径文件名中包含空字节"}, true
	}
	return OWASPHit{}, false
}

/**
 * hasAbsoluteFormRequestTarget 判断 WAF 侧路径是否为 absolute-form 请求行的
 * 改写残迹。数据面的 FixURIConn 会在 method 与请求行第二 token 之间插入一个
 * '/'（inbound_conn.go），因此「GET http://host/path HTTP/1.1」到达 WAF 时
 * path 恰为 "/http://host/path"；origin-form 路径以 "/" 或 "//" 开头，不会
 * 产生该形态。RFC 7230 §5.3.2 规定 absolute-form 是代理请求的合法形式，
 * 但直连源站仍发送 absolute-form 是扫描器/僵尸网络的高置信特征——真实浏览器
 * 从不这样做，正常业务也不经此路径（网关反向代理场景 Host 头才是权威）。
 *
 * 判据按前缀逐字节折叠比较，不分配、无正则；白名单/规则覆盖照常生效。
 */
func hasAbsoluteFormRequestTarget(path string) bool {
	if len(path) < 9 {
		return false
	}
	// 逐字符折叠比较 "/http://" 或 "/https://" 前缀。
	if path[0] != '/' || path[1] != 'h' && path[1] != 'H' {
		return false
	}
	rest := path[2:]
	const markHTTP = "ttp://"
	const markHTTPS = "ttps://"
	if len(rest) >= len(markHTTPS) && foldHasPrefix(rest, markHTTPS) {
		// scheme:// 后紧跟 ':'（如 /https://:@host）是 origin-form 路径的字面
		// 形态（空 userinfo 的 URL 字面量），不是 absolute-form 的改写残迹。
		return rest[len(markHTTPS)] != ':'
	}
	return len(rest) >= len(markHTTP) && foldHasPrefix(rest, markHTTP) &&
		rest[len(markHTTP)] != ':'
}

// foldHasPrefix 对 s 的前缀做 ASCII 折叠比较，lower 必须全小写。
func foldHasPrefix(s, lower string) bool {
	if len(s) < len(lower) {
		return false
	}
	for i := 0; i < len(lower); i++ {
		if lowerASCIIByte(s[i]) != lower[i] {
			return false
		}
	}
	return true
}

func checkDangerousPath(path string) (OWASPHit, bool) {
	// F5 BIG-IP RCE（CVE-2020-5902、CVE-2022-1388）
	if containsASCIIFold(path, "/mgmt/tm/util/bash") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:001", Score: 6,
			Desc: "F5 BIG-IP 远程代码执行端点"}, true
	}
	// Liferay JSONWS 反序列化（CVE-2020-7961）
	if containsASCIIFold(path, "/api/jsonws/invoke") {
		return OWASPHit{Category: CatDeserial, RuleID: "owasp:path:002", Score: 6,
			Desc: "Liferay JSONWS 反序列化端点"}, true
	}
	// Apache OFBiz webtools RCE（CVE-2023-49070、CVE-2023-51467）
	if containsASCIIFold(path, "/webtools/control/xmlrpc") ||
		containsASCIIFold(path, "/webtools/control/soapservice") {
		return OWASPHit{Category: CatDeserial, RuleID: "owasp:path:004", Score: 6,
			Desc: "Apache OFBiz webtools 远程代码执行端点"}, true
	}
	// Atlassian Confluence OGNL 注入（CVE-2021-26084、CVE-2022-26134）
	if containsASCIIFold(path, "/rest/tinymce/1/macro/preview") {
		return OWASPHit{Category: CatExprLang, RuleID: "owasp:path:005", Score: 6,
			Desc: "Confluence OGNL 注入端点"}, true
	}
	// Cisco ASA 路径遍历（CVE-2020-3452）
	if containsASCIIFold(path, "+cscot+/") ||
		containsASCIIFold(path, "+cscoe+/") ||
		containsASCIIFold(path, "%2bcscot%2b/") ||
		containsASCIIFold(path, "%2bcscoe%2b/") {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:006", Score: 5,
			Desc: "Cisco ASA 路径遍历"}, true
	}
	// ThinkPHP RCE（invokefunction）
	if containsASCIIFold(path, "/think") && containsASCIIFold(path, "invokefunction") {
		return OWASPHit{Category: CatWebshell, RuleID: "owasp:path:007", Score: 6,
			Desc: "ThinkPHP invokefunction 远程代码执行"}, true
	}
	// Atlassian gadgets makeRequest SSRF（CVE-2019-3396 等）
	if containsASCIIFold(path, "/gadgets/makerequest") {
		return OWASPHit{Category: CatSSRF, RuleID: "owasp:path:008", Score: 5,
			Desc: "Atlassian gadgets SSRF 端点"}, true
	}
	// Nexus Repository Manager RCE
	if containsASCIIFold(path, "coreui_user") || containsASCIIFold(path, "coreui_component") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:009", Score: 5,
			Desc: "Nexus Repository Manager 远程代码执行"}, true
	}
	// Coremail 配置泄露
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
	// 分号路径参数绕过（Tomcat/Spring）
	if strings.Contains(path, ";") && (containsASCIIFold(path, "swagger") ||
		containsASCIIFold(path, "actuator") || containsASCIIFold(path, "admin") ||
		containsASCIIFold(path, "console") || containsASCIIFold(path, "manager")) {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:014", Score: 5,
			Desc: "分号路径参数绕过"}, true
	}
	// Joomla API 配置泄露（CVE-2023-23752）
	if containsASCIIFold(path, "/api/index.php/v1/config/") ||
		(containsASCIIFold(path, "/api/") && containsASCIIFold(path, "/v1/config/application")) {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:015", Score: 5,
			Desc: "Joomla API 配置信息泄露"}, true
	}
	// Nexus Repository Manager RCE
	if containsASCIIFold(path, "/service/rest/") && containsASCIIFold(path, "/repositories/") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:016", Score: 5,
			Desc: "Nexus Repository Manager API 访问"}, true
	}
	// Service extdirect RCE
	if containsASCIIFold(path, "/service/extdirect") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:017", Score: 5,
			Desc: "ExtDirect 远程代码执行端点"}, true
	}
	return OWASPHit{}, false
}

func normalizeSensitivityLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "none":
		return "off"
	case "low":
		return "low"
	case "mid", "medium":
		return "mid"
	case "high":
		return "high"
	case "very_high", "very-high", "veryhigh":
		return "very_high"
	case "strict":
		return "strict"
	default:
		return ""
	}
}

func CategoryThreshold(defaultSensitivity string, category OWASPCategory, categorySensitivity ...map[string]string) (int, bool) {
	if len(categorySensitivity) > 0 && categorySensitivity[0] != nil {
		if level := normalizeSensitivityLevel(categorySensitivity[0][string(category)]); level != "" {
			if level == "off" {
				return 0, false
			}
			return sensitivityThreshold(level), true
		}
	}
	level := normalizeSensitivityLevel(defaultSensitivity)
	if level == "off" {
		return 0, false
	}
	return sensitivityThreshold(level), true
}

func sensitivityThreshold(s string) int {
	return sensitivityThresholdForNormalizedLevel(normalizeSensitivityLevel(s))
}

func sensitivityThresholdForNormalizedLevel(level string) int {
	switch level {
	case "low":
		return 7
	case "high":
		return 3 // 从 2 提高到 3 以减少误报
	case "very_high":
		return 2
	case "strict":
		return 1
	default:
		return 4
	}
}

func collectTargets(path, query string, headers map[string]string, extraCapacity int) []string {
	out := make([]string, 0, 2+len(headers)+extraCapacity)
	out = append(out, path, query)
	if path != "" && !strings.HasPrefix(path, "/") {
		out = append(out, "/"+path)
	}
	if query != "" {
		out = append(out, extractQueryValues(query)...)
	}
	for k, v := range headers {
		lk := lowerHeaderName(k)
		if lk != k {
			if lowerValue, ok := headers[lk]; ok && lowerValue == v {
				continue
			}
		}
		if lk == "cookie" {
			out = append(out, extractCookieValues(v)...)
			continue
		}
		if lk == "referer" {
			// 只扫描 Referer URL 的查询串部分，避免 scheme+host 带来的 SSRF 误报
			// （例如 http://10.0.0.1）。
			out = append(out, extractRefererTargets(v)...)
			continue
		}
		if shouldSkipHeaderTarget(lk, v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func forEachOWASPTarget(path, query string, headers map[string]string, bodyTargets []string, skipCleanPath, skipCleanQuery, skipDecodedQuery bool, fn func(raw string, isBodyTarget bool, queryPlusAsSpace bool) bool) bool {
	if !skipCleanPath {
		if !fn(path, false, true) {
			return false
		}
	}
	if !skipCleanQuery {
		if !fn(query, false, true) {
			return false
		}
	}
	if path != "" && !strings.HasPrefix(path, "/") && !skipCleanPath {
		if !fn("/"+path, false, true) {
			return false
		}
	}
	if query != "" && !skipDecodedQuery {
		if !forEachDecodedQueryValue(query, func(value string) bool {
			return fn(value, false, false)
		}) {
			return false
		}
	}
	for k, v := range headers {
		lk := lowerHeaderName(k)
		if lk != k {
			if lowerValue, ok := headers[lk]; ok && lowerValue == v {
				continue
			}
		}
		if lk == "cookie" {
			if !forEachCookieValue(v, func(value string) bool {
				return fn(value, false, true)
			}) {
				return false
			}
			continue
		}
		if lk == "referer" {
			if !forEachRefererTarget(v, func(value string, queryPlusAsSpace bool) bool {
				return fn(value, false, queryPlusAsSpace)
			}) {
				return false
			}
			continue
		}
		if shouldSkipHeaderTarget(lk, v) {
			continue
		}
		if !fn(v, false, false) {
			return false
		}
	}
	for _, raw := range bodyTargets {
		// body 目标不按 query 语义解码：`+` 只在 application/x-www-form-urlencoded
		// 中代表空格，且表单取值已由 extractFormValues 用 url.QueryUnescape 解过；
		// JSON / text/plain / multipart 等 body 里的 `+` 是字面量。按空格解码会
		// 把遥测随机串里的 `$(3qE2q+` 误读成 `$(3qE2q `，触发命令注入误报。
		if !fn(raw, true, false) {
			return false
		}
	}
	return true
}

const commonCleanBrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

func shouldSkipHeaderTarget(name, value string) bool {
	switch name {
	case "user-agent":
		if value == commonCleanBrowserUserAgent {
			return true
		}
		return isCleanBrowserUserAgent(value)
	case "accept":
		if isCommonCleanAcceptHeader(value) {
			return true
		}
		return isCleanAcceptHeader(value)
	case "host",
		"connection",
		"content-length",
		"accept-language",
		"accept-encoding",
		"authorization",
		"cache-control",
		"pragma",
		"if-modified-since",
		"if-none-match",
		"upgrade",
		"upgrade-insecure-requests",
		"dnt",
		"te",
		"origin",
		"sec-fetch-mode",
		"sec-fetch-site",
		"sec-fetch-dest",
		"sec-fetch-user",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"sec-ch-ua-arch",
		"sec-ch-ua-bitness",
		"sec-ch-ua-full-version",
		"sec-ch-ua-full-version-list",
		"sec-ch-ua-model",
		"sec-ch-ua-platform-version",
		"x-client-data":
		return true
	default:
		return false
	}
}

func isCommonCleanAcceptHeader(value string) bool {
	switch value {
	case "text/html",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"application/json",
		"application/vnd.api+json;q=0.8,application/ld+json":
		return true
	default:
		return false
	}
}

func isCleanBrowserUserAgent(value string) bool {
	if len(value) == 0 || len(value) > 512 {
		return false
	}
	hasBrowserToken := false
	wordStart := -1
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 0x80 {
			return false
		}
		switch b {
		case '\r', '\n', '\x00', '%', '\\', '<', '>', '\'', '"', '`', '|', '$', '{', '}', '[', ']', '&', '#', '+', '=':
			return false
		}
		if isASCIILetterOrDigit(b) {
			if wordStart < 0 {
				wordStart = i
			}
		} else if wordStart >= 0 {
			if isShellCommandWord(value[wordStart:i], true) {
				return false
			}
			wordStart = -1
		}
		lb := lowerASCIIByte(b)
		if !hasBrowserToken && hasCleanBrowserTokenAt(value, i, lb) {
			hasBrowserToken = true
		}
		if hasCleanHeaderDangerousNeedleAt(value, i, lb) {
			return false
		}
	}
	if wordStart >= 0 && isShellCommandWord(value[wordStart:], true) {
		return false
	}
	return hasBrowserToken
}

func isCleanAcceptHeader(value string) bool {
	if len(value) == 0 || len(value) > 512 {
		return false
	}
	wordStart := -1
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 0x80 {
			return false
		}
		switch b {
		case '\r', '\n', '\x00', '%', '\\', '<', '>', '\'', '"', '`', '|', '$', '{', '}', '[', ']', '&', '#', ':', '(', ')':
			return false
		}
		if isASCIILetterOrDigit(b) {
			if wordStart < 0 {
				wordStart = i
			}
		} else if wordStart >= 0 {
			if isShellCommandWord(value[wordStart:i], true) {
				return false
			}
			wordStart = -1
		}
		if hasCleanHeaderDangerousNeedleAt(value, i, lowerASCIIByte(b)) {
			return false
		}
	}
	if wordStart >= 0 && isShellCommandWord(value[wordStart:], true) {
		return false
	}
	return isAcceptMediaList(value)
}

func hasCleanBrowserTokenAt(s string, i int, first byte) bool {
	switch first {
	case 'a':
		return hasASCIIFoldAt(s, i, "applewebkit/")
	case 'c':
		return hasASCIIFoldAt(s, i, "chrome/")
	case 'e':
		return hasASCIIFoldAt(s, i, "edge/") || hasASCIIFoldAt(s, i, "edg/")
	case 'f':
		return hasASCIIFoldAt(s, i, "firefox/")
	case 'm':
		return hasASCIIFoldAt(s, i, "mozilla/") || hasASCIIFoldAt(s, i, "msie ")
	case 's':
		return hasASCIIFoldAt(s, i, "safari/")
	case 't':
		return hasASCIIFoldAt(s, i, "trident/")
	default:
		return false
	}
}

func hasCleanHeaderDangerousNeedleAt(s string, i int, first byte) bool {
	switch first {
	case '.':
		return hasASCIIFoldAt(s, i, "../") ||
			hasASCIIFoldAt(s, i, "..\\") ||
			hasASCIIFoldAt(s, i, ".nip.io") ||
			hasASCIIFoldAt(s, i, ".xip.io") ||
			hasASCIIFoldAt(s, i, ".sslip.io")
	case '/':
		return hasASCIIFoldAt(s, i, "/bin/") || hasASCIIFoldAt(s, i, "/proc/")
	case ':':
		return hasASCIIFoldAt(s, i, "://") ||
			hasASCIIFoldAt(s, i, "::ffff:") ||
			hasASCIIFoldAt(s, i, "::1")
	case ')':
		return hasASCIIFoldAt(s, i, ")(")
	case '@':
		return hasASCIIFoldAt(s, i, "@java.")
	case '_':
		return hasASCIIFoldAt(s, i, "__schema") || hasASCIIFoldAt(s, i, "__type")
	case '0':
		return hasASCIIFoldAt(s, i, "0x7f")
	case '1':
		return hasASCIIFoldAt(s, i, "169.254.169.254") ||
			hasASCIIFoldAt(s, i, "100.100.100.200") ||
			hasASCIIFoldAt(s, i, "127.0.")
	case 'a':
		return hasASCIIFoldAt(s, i, "alter") ||
			hasASCIIFoldAt(s, i, "and1=1") ||
			hasASCIIFoldAt(s, i, "alert(") ||
			hasASCIIFoldAt(s, i, "assert(") ||
			hasASCIIFoldAt(s, i, "aced0005")
	case 'b':
		return hasASCIIFoldAt(s, i, "benchmark") || hasASCIIFoldAt(s, i, "boot.ini")
	case 'c':
		return hasASCIIFoldAt(s, i, "concat(") ||
			hasASCIIFoldAt(s, i, "char(") ||
			hasASCIIFoldAt(s, i, "chr(") ||
			hasASCIIFoldAt(s, i, "constructor.constructor") ||
			hasASCIIFoldAt(s, i, "confirm(") ||
			hasASCIIFoldAt(s, i, "cmd.exe") ||
			hasASCIIFoldAt(s, i, "curl ")
	case 'd':
		return hasASCIIFoldAt(s, i, "delete") ||
			hasASCIIFoldAt(s, i, "drop") ||
			hasASCIIFoldAt(s, i, "dumpfile") ||
			hasASCIIFoldAt(s, i, "data:text/html") ||
			hasASCIIFoldAt(s, i, "document.")
	case 'e':
		return hasASCIIFoldAt(s, i, "extractvalue") ||
			hasASCIIFoldAt(s, i, "eval(") ||
			hasASCIIFoldAt(s, i, "exec(") ||
			hasASCIIFoldAt(s, i, "etc/")
	case 'f':
		return hasASCIIFoldAt(s, i, "fetch(") || hasASCIIFoldAt(s, i, "fromcharcode")
	case 'g':
		return hasASCIIFoldAt(s, i, "group_concat") ||
			hasASCIIFoldAt(s, i, "group by") ||
			hasASCIIFoldAt(s, i, "getclass") ||
			hasASCIIFoldAt(s, i, "getruntime")
	case 'i':
		return hasASCIIFoldAt(s, i, "insert") ||
			hasASCIIFoldAt(s, i, "information_schema") ||
			hasASCIIFoldAt(s, i, "innerhtml")
	case 'j':
		return hasASCIIFoldAt(s, i, "jndi:") || hasASCIIFoldAt(s, i, "javascript:")
	case 'l':
		return hasASCIIFoldAt(s, i, "localhost")
	case 'm':
		return hasASCIIFoldAt(s, i, "metadata.google") || hasASCIIFoldAt(s, i, "meta-inf")
	case 'n':
		return hasASCIIFoldAt(s, i, "new java.")
	case 'o':
		return hasASCIIFoldAt(s, i, "outfile") ||
			hasASCIIFoldAt(s, i, "or1=1") ||
			hasASCIIFoldAt(s, i, "order by") ||
			hasASCIIFoldAt(s, i, "onload") ||
			hasASCIIFoldAt(s, i, "onerror") ||
			hasASCIIFoldAt(s, i, "onclick") ||
			hasASCIIFoldAt(s, i, "objectclass") ||
			hasASCIIFoldAt(s, i, "objectinputstream")
	case 'p':
		return hasASCIIFoldAt(s, i, "prompt(") || hasASCIIFoldAt(s, i, "powershell.exe")
	case 'r':
		return hasASCIIFoldAt(s, i, "runtime.getruntime") || hasASCIIFoldAt(s, i, "ro0ab")
	case 's':
		return hasASCIIFoldAt(s, i, "select") ||
			hasASCIIFoldAt(s, i, "sleep") ||
			hasASCIIFoldAt(s, i, "substr(") ||
			hasASCIIFoldAt(s, i, "substring(") ||
			hasASCIIFoldAt(s, i, "system(") ||
			hasASCIIFoldAt(s, i, "shell_exec")
	case 't':
		return hasASCIIFoldAt(s, i, "truncate")
	case 'u':
		return hasASCIIFoldAt(s, i, "union") ||
			hasASCIIFoldAt(s, i, "update") ||
			hasASCIIFoldAt(s, i, "updatexml") ||
			hasASCIIFoldAt(s, i, "unix:")
	case 'v':
		return hasASCIIFoldAt(s, i, "vbscript:")
	case 'w':
		return hasASCIIFoldAt(s, i, "waitfor") ||
			hasASCIIFoldAt(s, i, "window.") ||
			hasASCIIFoldAt(s, i, "whoami") ||
			hasASCIIFoldAt(s, i, "wget ") ||
			hasASCIIFoldAt(s, i, "web-inf") ||
			hasASCIIFoldAt(s, i, "win.ini")
	case 'y':
		return hasASCIIFoldAt(s, i, "ysoserial")
	default:
		return false
	}
}

func isAcceptMediaList(s string) bool {
	i := 0
	for {
		i = skipASCIISpaces(s, i)
		if i >= len(s) {
			return false
		}
		next, ok := consumeAcceptMediaRange(s, i)
		if !ok {
			return false
		}
		i = skipASCIISpaces(s, next)
		for i < len(s) && s[i] == ';' {
			i++
			i = skipASCIISpaces(s, i)
			next, ok = consumeAcceptParam(s, i)
			if !ok {
				return false
			}
			i = skipASCIISpaces(s, next)
		}
		if i >= len(s) {
			return true
		}
		if s[i] != ',' {
			return false
		}
		i++
	}
}

func consumeAcceptMediaRange(s string, i int) (int, bool) {
	next, ok := consumeAcceptTypePart(s, i)
	if !ok || next >= len(s) || s[next] != '/' {
		return i, false
	}
	next++
	return consumeAcceptTypePart(s, next)
}

func consumeAcceptParam(s string, i int) (int, bool) {
	next, ok := consumeAcceptToken(s, i)
	if !ok {
		return i, false
	}
	next = skipASCIISpaces(s, next)
	if next >= len(s) || s[next] != '=' {
		return i, false
	}
	next++
	next = skipASCIISpaces(s, next)
	return consumeAcceptToken(s, next)
}

func consumeAcceptTypePart(s string, i int) (int, bool) {
	if i >= len(s) {
		return i, false
	}
	if s[i] == '*' {
		return i + 1, true
	}
	return consumeAcceptToken(s, i)
}

func consumeAcceptToken(s string, i int) (int, bool) {
	start := i
	for i < len(s) && isAcceptTokenByte(s[i]) {
		i++
	}
	return i, i > start
}

func skipASCIISpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

func isAcceptTokenByte(b byte) bool {
	return isASCIILetterOrDigit(b) || b == '-' || b == '_' || b == '.' || b == '+'
}

func isASCIILetterOrDigit(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func equalASCIIFold(s, lower string) bool {
	if len(s) != len(lower) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lowerASCIIByte(s[i]) != lower[i] {
			return false
		}
	}
	return true
}

func containsASCIIFold(s, lower string) bool {
	n := len(lower)
	if n == 0 {
		return true
	}
	if n > len(s) {
		return false
	}
	first := lowerASCIIByte(lower[0])
	last := len(s) - n
	for i := 0; i <= last; i++ {
		if lowerASCIIByte(s[i]) != first {
			continue
		}
		match := true
		for j := 1; j < n; j++ {
			if lowerASCIIByte(s[i+j]) != lower[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func hasASCIIFoldAt(s string, start int, lower string) bool {
	if start+len(lower) > len(s) {
		return false
	}
	for i := 0; i < len(lower); i++ {
		if lowerASCIIByte(s[start+i]) != lower[i] {
			return false
		}
	}
	return true
}

func lowerASCIIByte(b byte) byte {
	return asciiLowerTable[b]
}

func lowerHeaderName(name string) string {
	switch name {
	case "Accept":
		return "accept"
	case "Accept-Encoding":
		return "accept-encoding"
	case "Accept-Language":
		return "accept-language"
	case "Authorization":
		return "authorization"
	case "Cache-Control":
		return "cache-control"
	case "Connection":
		return "connection"
	case "Content-Length":
		return "content-length"
	case "Content-Type":
		return "content-type"
	case "Cookie":
		return "cookie"
	case "DNT":
		return "dnt"
	case "Host":
		return "host"
	case "If-Modified-Since":
		return "if-modified-since"
	case "If-None-Match":
		return "if-none-match"
	case "Origin":
		return "origin"
	case "Pragma":
		return "pragma"
	case "Referer":
		return "referer"
	case "Sec-Ch-Ua":
		return "sec-ch-ua"
	case "Sec-Ch-Ua-Arch":
		return "sec-ch-ua-arch"
	case "Sec-Ch-Ua-Bitness":
		return "sec-ch-ua-bitness"
	case "Sec-Ch-Ua-Full-Version":
		return "sec-ch-ua-full-version"
	case "Sec-Ch-Ua-Full-Version-List":
		return "sec-ch-ua-full-version-list"
	case "Sec-Ch-Ua-Mobile":
		return "sec-ch-ua-mobile"
	case "Sec-Ch-Ua-Model":
		return "sec-ch-ua-model"
	case "Sec-Ch-Ua-Platform":
		return "sec-ch-ua-platform"
	case "Sec-Ch-Ua-Platform-Version":
		return "sec-ch-ua-platform-version"
	case "Sec-Fetch-Dest":
		return "sec-fetch-dest"
	case "Sec-Fetch-Mode":
		return "sec-fetch-mode"
	case "Sec-Fetch-Site":
		return "sec-fetch-site"
	case "Sec-Fetch-User":
		return "sec-fetch-user"
	case "TE":
		return "te"
	case "Upgrade":
		return "upgrade"
	case "Upgrade-Insecure-Requests":
		return "upgrade-insecure-requests"
	case "User-Agent":
		return "user-agent"
	case "X-Client-Data":
		return "x-client-data"
	}
	if isLowerASCIIHeaderName(name) {
		return name
	}
	return strings.ToLower(name)
}

func isLowerASCIIHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b >= 'A' && b <= 'Z' {
			return false
		}
		if b >= 0x80 {
			return false
		}
	}
	return true
}

func extractQueryValues(rawQuery string) []string {
	var values []string
	forEachDecodedQueryValue(rawQuery, func(value string) bool {
		values = append(values, value)
		return true
	})
	return values
}

func forEachDecodedQueryValue(rawQuery string, fn func(value string) bool) bool {
	for rawQuery != "" {
		pair := rawQuery
		if i := strings.IndexByte(pair, '&'); i >= 0 {
			pair, rawQuery = pair[:i], rawQuery[i+1:]
		} else {
			rawQuery = ""
		}
		if pair == "" {
			continue
		}
		_, value, hasEq := strings.Cut(pair, "=")
		if !hasEq || value == "" {
			continue
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			decoded = value
		}
		if shouldScanDecodedQueryValue(value, decoded) {
			if !fn(decoded) {
				return false
			}
		}
	}
	return true
}

func shouldScanDecodedQueryValue(raw, decoded string) bool {
	if decoded == "" {
		return false
	}
	if len(decoded) >= 256 {
		return true
	}
	if strings.Count(decoded, `\\u00`) >= 4 {
		return true
	}
	if (hasLikelyBase64Candidate(raw) || hasLikelyBase64Candidate(decoded)) && len(decoded) >= 12 {
		return true
	}
	return false
}

// extractRefererTargets 从 Referer URL 中提取可扫描的部分。
// 返回自定义查询串与路径（用于路径遍历检测），
// 但不含 scheme+host，以避免 SSRF 误报。
// 用 strings.Cut 做纯字符串切分而不是 url.Parse：载荷常把引号闭合与标签
// 直接写在**路径段**里（`"><script>alert(1)</script>`），url.Parse 对这类
// 输入会把整串塞进 u.Path、u.RawPath 并重新转义，切分结果不可控；
// 字符串切分对「取第一个 `?` 之前、第一个 `#` 之后」给出确定结论。
func extractRefererTargets(referer string) []string {
	var targets []string
	forEachRefererTarget(referer, func(value string, _ bool) bool {
		targets = append(targets, value)
		return true
	})
	return targets
}

func forEachRefererTarget(referer string, fn func(value string, queryPlusAsSpace bool) bool) bool {
	if referer == "" {
		return true
	}
	rest := referer
	if i := strings.Index(rest, "://"); i >= 0 {
		// 去掉 scheme://host[:port]，只留路径与后续内容；scheme 与 host
		// 本身不扫（避免 http://10.0.0.1 一类 SSRF 误报）。
		rest = rest[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			rest = rest[j:]
		} else {
			rest = ""
		}
	}
	fragment := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest, fragment = rest[:i], rest[i+1:]
	}
	path, query := rest, ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		path, query = rest[:i], rest[i+1:]
	}
	if path != "" {
		if !fn(path, false) {
			return false
		}
	}
	if query != "" {
		if !fn(query, true) {
			return false
		}
	}
	if fragment != "" {
		if !fn(fragment, false) {
			return false
		}
	}
	return true
}

// extractCookieValues 拆分 Cookie 请求头并返回各个值，
// 过滤掉疑似会话标识的值以避免误报。
func extractCookieValues(raw string) []string {
	var values []string
	forEachCookieValue(raw, func(value string) bool {
		values = append(values, value)
		return true
	})
	return values
}

func forEachCookieValue(raw string, fn func(value string) bool) bool {
	for pair := range strings.SplitSeq(raw, ";") {
		pair = strings.TrimSpace(pair)
		_, val, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		val = strings.TrimSpace(val)
		if val == "" || isLikelySessionID(val) {
			continue
		}
		if !fn(val) {
			return false
		}
	}
	return true
}

// isLikelySessionID 对「仅十六进制且长度 ≥16」的字符串（会话令牌）返回 true。
func isLikelySessionID(val string) bool {
	if len(val) < 16 {
		return false
	}
	for _, c := range val {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-') {
			return false
		}
	}
	return true
}
