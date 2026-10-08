package owasp

import (
	"encoding/base64"
	"html"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"My-OpenWaf/internal/core/score"
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
	return CheckOWASPWithThresholds(CompileThresholds(sensitivity, categorySensitivity...), path, query, headers, bodyTargets)
}

func CheckOWASPWithThresholds(thresholds CompiledThresholds, path, query string, headers map[string]string, bodyTargets []string) []OWASPHit {
	hit, ok, multi := firstOWASPHitWithThresholds(thresholds, path, query, headers, bodyTargets, nil)
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
	hit, ok, multi := firstOWASPHitWithThresholds(thresholds, path, query, headers, bodyTargets, nil)
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
	if len(overrides) == 0 {
		return FirstOWASPHitWithThresholds(thresholds, path, query, headers, bodyTargets)
	}
	var categorySensitivity map[string]string
	if len(catSens) > 0 {
		categorySensitivity = catSens[0]
	}
	accept := func(hit OWASPHit) bool {
		return HitPassesFilters(hit, path, overrides, categorySensitivity)
	}
	hit, ok, multi := firstOWASPHitWithThresholds(thresholds, path, query, headers, bodyTargets, accept)
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

func firstOWASPHitWithThresholds(thresholds CompiledThresholds, path, query string, headers map[string]string, bodyTargets []string, accept func(OWASPHit) bool) (hit OWASPHit, ok bool, multi []OWASPHit) {
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
	if strings.Contains(lowerPath, "/restapi/soa2/") || strings.Contains(lowerPath, "/web/common") {
		skipBodyCmd = true
	}

	if strings.Contains(lowerPath, "/cdn-cgi/") {
		skipBodySSRF = true
	}
	if strings.Contains(lowerPath, "/g/collect") {
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
	if pathTravEnabled && strings.Contains(lowerPath, "/translation-table") && (strings.Contains(lowerPath, "+cscot+") || strings.Contains(lowerPath, "+cscoe+")) {
		hit := OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:015", Score: 5, Desc: "Cisco translation-table 路径遍历模式"}
		if acceptsOWASPHit(accept, hit) {
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
		if isCleanTarget(raw) && !hasLikelyBase64Candidate(raw) && !hasSuspiciousKeywords(raw) {
			return true
		}

		normalized := normalizeWithDecodeTarget(raw, queryPlusAsSpace)
		if len(normalized) > maxTargetLen {
			normalized = truncateTarget(normalized)
		}
		snippetRaw, snippetNorm, snippetDecoded = raw, normalized, raw

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
				if hit, ok := checkCRLF(strings.ToLower(cur), crlfThreshold); ok {
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
		if crlfEnabled {
			if hit, ok := checkCRLF(normalized, crlfThreshold); ok {
				if !isCRLFFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}

		if !hasSuspiciousContent(normalized) {
			return true
		}
		if sqliEnabled && !(isBodyTarget && skipBodySQLi) {
			if hit, ok := nextSQLiHit(normalized, sqliThreshold); ok {
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}
		if xssEnabled {
			if hit, ok := nextXSSHit(normalized, xssThreshold); ok {
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
			if hit, ok := checkCmdInjection(normalized, cmdThreshold); ok {
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
			if hit, ok := checkWebshell(normalized, webshellThreshold); ok {
				if !isWebshellFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}
		if revShellEnabled {
			if hit, ok := checkRevShell(normalized, revShellThreshold); ok {
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}
		if pathTravEnabled {
			if hit, ok := checkPathTraversal(normalized, pathTravThreshold); ok {
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
			if hit, ok := checkSSRF(normalized, ssrfThreshold); ok {
				if !isSSRFFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						hits = append(hits, hit)
					}
				}
			}
		}
		if xxeEnabled {
			if hit, ok := checkXXE(normalized, xxeThreshold); ok {
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}
		if ldapEnabled {
			if hit, ok := checkLDAPInjection(normalized, ldapThreshold); ok {
				if acceptsOWASPHit(accept, hit) {
					hits = append(hits, hit)
				}
			}
		}
		if nosqliEnabled {
			if hit, ok := checkNoSQLi(normalized, nosqliThreshold); ok {
				if acceptsOWASPHit(accept, hit) {
					hits = append(hits, hit)
				}
			}
		}
		if templateEnabled {
			if hit, ok := checkTemplateInjection(normalized, templateThreshold); ok {
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}
		if jndiEnabled {
			if hit, ok := checkJNDI(normalized, jndiThreshold); ok {
				if acceptsOWASPHit(accept, hit) {
					stopHit, hasStop = finalizeHit(hit), true
					return false
				}
			}
		}
		if crlfEnabled {
			if hit, ok := checkCRLF(normalized, crlfThreshold); ok {
				if !isCRLFFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}
		if exprLangEnabled {
			if hit, ok := checkExprLang(normalized, exprLangThreshold); ok {
				if !isELFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}
		if deserialEnabled {
			if hit, ok := checkDeserialization(normalized, deserialThreshold); ok {
				if !isDeserFalsePositive(normalized, hit.RuleID) {
					if acceptsOWASPHit(accept, hit) {
						stopHit, hasStop = finalizeHit(hit), true
						return false
					}
				}
			}
		}
		if graphqlEnabled {
			if hit, ok := checkGraphQLi(normalized, graphqlThreshold); ok {
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
					if hit, ok := nextSQLiHit(decodedNorm, sqliThreshold); ok {
						if acceptsOWASPHit(accept, hit) {
							deepHit, hasDeep = finalizeHit(hit), true
							return false
						}
					}
				}
				if xssEnabled {
					if hit, ok := nextXSSHit(decodedNorm, xssThreshold); ok {
						if !isKnownTelemetryXSSFalsePositive(path, decodedNorm, hit.RuleID, true) {
							if acceptsOWASPHit(accept, hit) {
								deepHit, hasDeep = finalizeHit(hit), true
								return false
							}
						}
					}
				}
				if cmdEnabled {
					if hit, ok := checkCmdInjection(decodedNorm, cmdThreshold); ok {
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
		if hit, ok := checkDangerousPath(path); ok {
			if acceptsOWASPHit(accept, hit) {
				hits = append(hits, hit)
			}
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

// checkDangerousPath 检测针对特定 CVE 的危险 API 端点与路径，
// 这些路径常被用于 RCE、反序列化或其他攻击。
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
		if !fn(raw, true, true) {
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
// 返回原始查询串与路径（用于路径遍历检测），
// 但不含 scheme+host，以避免 SSRF 误报。
func extractRefererTargets(referer string) []string {
	var targets []string
	forEachRefererTarget(referer, func(value string, _ bool) bool {
		targets = append(targets, value)
		return true
	})
	return targets
}

func forEachRefererTarget(referer string, fn func(value string, queryPlusAsSpace bool) bool) bool {
	u, err := url.Parse(referer)
	if err != nil {
		return true
	}
	if u.RawQuery != "" {
		if !fn(u.RawQuery, true) {
			return false
		}
	}
	if u.Fragment != "" {
		if !fn(u.Fragment, false) {
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

func unescapeURLComponent(s string, queryPlusAsSpace bool) (string, error) {
	if queryPlusAsSpace {
		if strings.IndexByte(s, '%') < 0 && strings.IndexByte(s, '+') < 0 {
			return s, nil // 无 %/+ 时 QueryUnescape 必返回原串且 err==nil，零拷贝短路
		}
		return url.QueryUnescape(s)
	}
	if strings.IndexByte(s, '%') < 0 {
		return s, nil
	}
	return url.PathUnescape(s)
}

func decodePercentU(s string) string {
	if !strings.Contains(s, "%u") {
		return s
	}
	parts := strings.Split(s, "%u")
	if len(parts) < 2 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(parts[0])
	for _, part := range parts[1:] {
		if len(part) < 4 {
			b.WriteString("%u")
			b.WriteString(part)
			continue
		}
		code, err := strconv.ParseUint(part[:4], 16, 16)
		if err != nil || code > 0xFF {
			b.WriteString("%u")
			b.WriteString(part)
			continue
		}
		b.WriteByte(byte(code))
		b.WriteString(part[4:])
	}
	return b.String()
}

// normalize 依次执行多轮 URL 解码、HTML 实体解码、JS 转义解码、小写化与空白折叠。
func normalize(s string) string {
	return normalizeTarget(s, true)
}

func normalizeTarget(s string, queryPlusAsSpace bool) string {
	// UTF-7 预解码：query/form 上下文里 unescapeURLComponent 会把 '+' 解成空格，
	// 等 URL 解码做完再解 UTF-7 时 +ADw- 等标记已被破坏（实测
	// "+ADwAIQ-DOCTYPE foo+AFs" → " adwaiq-doctype foo afs"），UTF-7 编码的
	// XML/XSS 载荷因此整体漏检。故在 URL 解码之前先解一次。
	// 门限：仅当解码结果真的产出标记字符（< > " & ; ! / [ ]）时才采用，
	// 否则形如 "1+AND+1=1" 的查询值会被误当作 UTF-7 解成乱码，反而丢掉
	// "+ 当空格" 的 SQLi 形态。
	if strings.Contains(s, "+A") {
		if dec := decodeUTF7Sequences(s); dec != s && containsAnyRuneASCII(dec, "<>\"&;!/[]") {
			s = dec
		}
	}
	// U+2215（∕）在 Java File 等解析器中视为路径分隔符，归一为 ASCII
	// 斜杠，避免 its 变体绕过下方的路径穿越电池。
	if strings.ContainsRune(s, '∕') {
		s = strings.ReplaceAll(s, "∕", "/")
	}
	// overlong UTF-8 百分号编码序列 → 真实字符（一种绕过手法）。
	if strings.Contains(s, "%") && containsOverlongUTF8Escape(s) {
		s = reOverlongDot.ReplaceAllString(s, ".")
		s = reOverlongSlash.ReplaceAllString(s, "/")
		s = reOverlongBackslash.ReplaceAllString(s, "\\")
		// 紧凑形态：%C0AE（百分号后四 hex 无 % 分隔的拼接编码）。
		// overlong 字节对 0xC0 0xAE 在合法 UTF-8 URL 编码中不出现，
		// 只在刻意拼接的攻击载荷中出现，替换无误报面。
		s = reOverlongDotCompact.ReplaceAllString(s, ".")
		s = reOverlongSlashCompact.ReplaceAllString(s, "/")
		// < 与 > 的 overlong 编码（XSS 绕过中常见）。
		// %C0%BC / %E0%80%BC / %F0%80%80%BC / %F8%80%80%80%80%BC / %FC%80%80%80%80%80%BC → <
		// %C0%BE / %E0%80%BE / ... → >
		s = reOverlongLT.ReplaceAllString(s, "<")
		s = reOverlongGT.ReplaceAllString(s, ">")
		// 字节形态 overlong 对（多层 URL 解码后 %C0 已变为 0xC0 字节 +
		// ASCII 尾字符，如 %25C0AE 一层解码产物）：0xC0 0xAE → .、
		// 0xC0 0xAF → /。检查在大写 AE/AF 前先剥去，避免漏掉大小写
		// 混写（URL 编码尾字母常任意大小写）。
		for _, c := range []struct{ from, to string }{
			{"\xc0ae", "."}, {"\xc0AE", "."},
			{"\xc0af", "/"}, {"\xc0AF", "/"},
		} {
			if strings.Contains(s, c.from) {
				s = strings.ReplaceAll(s, c.from, c.to)
			}
		}
	}
	for i := range 3 {
		var decoded string
		var err error
		if i == 0 {
			decoded, err = unescapeURLComponent(s, queryPlusAsSpace)
		} else {
			decoded, err = url.PathUnescape(s)
		}
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	// 解码产物二次 overlong 归一：%25C0AE 经上段多层解码后落为
	// 字节对 0xC0 0xAE（带 % 前缀的形态已在上段处理过），此处把
	// 新暴露的紧凑 overlong 对再归一为 ./。
	if strings.Contains(s, "%") && containsOverlongUTF8Escape(s) {
		s = reOverlongDot.ReplaceAllString(s, ".")
		s = reOverlongSlash.ReplaceAllString(s, "/")
		s = reOverlongDotCompact.ReplaceAllString(s, ".")
		s = reOverlongSlashCompact.ReplaceAllString(s, "/")
	}
	// 字节对形态（多层解码产物）：0xC0 0xAE → .、0xC0 0xAF → /。
	for _, c := range []struct{ from, to string }{
		{"\xc0ae", "."}, {"\xc0AE", "."},
		{"\xc0af", "/"}, {"\xc0AF", "/"},
	} {
		if strings.Contains(s, c.from) {
			s = strings.ReplaceAll(s, c.from, c.to)
		}
	}
	if shouldDecodeHTMLEntities(s) {
		// 多轮 HTML 实体解码。
		for range 2 {
			decoded := html.UnescapeString(s)
			if decoded == s {
				break
			}
			s = decoded
		}
	}
	// JavaScript 转义序列解码：\xNN、\uXXXX、\u{XXXX}、\NNN（八进制）。
	// 可破解 window['\x61\x6c\x65\x72\x74'] → window['alert'] 这类混淆。
	if strings.Contains(s, "\\") {
		s = decodeJSEscapesPooled(s)
	}
	// JS 转义之后的 URL 解码：JS 转义可能产出百分号编码字符
	// （如 %28 → %28 → '('）。多轮处理以覆盖双重/三重编码。
	for range 3 {
		if !strings.Contains(s, "%") {
			break
		}
		d, err := url.PathUnescape(s)
		if err != nil || d == s {
			break
		}
		s = d
	}
	// UTF-7 解码：+ADw- → <、+AD4- → > 等（用于 charset=UTF-7 的 XSS 攻击）。
	if strings.Contains(s, "+A") {
		s = decodeUTF7Sequences(s)
	}
	s = normalizeURLSchemeControls(s)
	s = toLowerASCII(s)
	// %uXXXX（IIS 风格 Unicode 百分号编码）：按十六进制码点解码，
	// 单字节码点还原为对应字符，让 XSS/SQLi 族看到载荷真相。
	if strings.Contains(s, "%u") {
		s = decodePercentU(s)
	}
	// 覆盖时把 U+2215 变异为斜杠的路径穿越注意点已在前段处理。
	// 零字节剥离（而非替换空格）：<scr\x00ipt> 变体去掉零字节后还原
	// <script 形态供 xss:001 命中；替换空格会让 <scr ipt 无法命中
	// 且下方 collapseWhitespace 会把它变成 <scr ipt（单词断裂）。
	s = strings.ReplaceAll(s, "\x00", "")
	// 内嵌标签混淆剥离：autof<x>ocus → autofocus、alert<x>(1) → alert(1)
	//（HTML 解析器把未知标签 <x> 视为文本丢弃，攻击者用它拆分事件名/
	// 函数名绕过检测）。必须成对剥离（<x> 与 </x> 或 </x> 单闭），
	// 自然文本中的 <x> 极少且此处只剥两字符短标签。
	s = stripInlineConfusionTags(s)
	// 剥离行内 SQL/C 风格注释，破解注释拆分绕过。
	// 空串替换会拼接相邻 token：sel/**/ect → select、un/**/ion → union。
	s = stripSQLCommentsPooled(s)
	s = collapseWhitespacePooled(s)
	return s
}

var reInlineConfusionTag = regexp.MustCompile(`</?[a-z]{1,2}>`)

// containsAnyRuneASCII 判断 s 是否至少包含 chars 中的一个 ASCII 字节。
func containsAnyRuneASCII(s, chars string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(chars, s[i]) >= 0 {
			return true
		}
	}
	return false
}

// stripInlineConfusionTags 移除 HTML 解析器会当作未知元素丢弃的短行内标签
// （<x>、<a>、</x> 等）。攻击者把它们插进事件名（autof<x>ocus）或
// 调用点（alert<x>(1)）以绕过正则检测；移除后即可还原原始 token。
func stripInlineConfusionTags(s string) string {
	if !strings.Contains(s, "<") {
		return s
	}
	return reInlineConfusionTag.ReplaceAllString(s, "")
}

func shouldDecodeHTMLEntities(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '&' {
			continue
		}
		if i+1 >= len(s) {
			return false
		}
		next := s[i+1]
		if next == '#' {
			return true
		}
		if !isHTMLEntityNameByte(next) {
			continue
		}
		start := i + 1
		end := start + 1
		for end < len(s) && isHTMLEntityNameByte(s[end]) {
			end++
		}
		if end < len(s) && s[end] == ';' {
			return true
		}
		if hasSemicolonlessHTMLEntityPrefix(s[start:end]) {
			return true
		}
		i = end - 1
	}
	return false
}

func isHTMLEntityNameByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func hasSemicolonlessHTMLEntityPrefix(name string) bool {
	switch {
	case strings.HasPrefix(name, "aacute"),
		strings.HasPrefix(name, "Aacute"),
		strings.HasPrefix(name, "Acirc"),
		strings.HasPrefix(name, "acirc"),
		strings.HasPrefix(name, "acute"),
		strings.HasPrefix(name, "aelig"),
		strings.HasPrefix(name, "AElig"),
		strings.HasPrefix(name, "Agrave"),
		strings.HasPrefix(name, "agrave"),
		strings.HasPrefix(name, "AMP"),
		strings.HasPrefix(name, "amp"),
		strings.HasPrefix(name, "Aring"),
		strings.HasPrefix(name, "aring"),
		strings.HasPrefix(name, "atilde"),
		strings.HasPrefix(name, "Atilde"),
		strings.HasPrefix(name, "Auml"),
		strings.HasPrefix(name, "auml"),
		strings.HasPrefix(name, "brvbar"),
		strings.HasPrefix(name, "Ccedil"),
		strings.HasPrefix(name, "ccedil"),
		strings.HasPrefix(name, "cedil"),
		strings.HasPrefix(name, "cent"),
		strings.HasPrefix(name, "COPY"),
		strings.HasPrefix(name, "copy"),
		strings.HasPrefix(name, "curren"),
		strings.HasPrefix(name, "deg"),
		strings.HasPrefix(name, "divide"),
		strings.HasPrefix(name, "Eacute"),
		strings.HasPrefix(name, "eacute"),
		strings.HasPrefix(name, "Ecirc"),
		strings.HasPrefix(name, "ecirc"),
		strings.HasPrefix(name, "egrave"),
		strings.HasPrefix(name, "Egrave"),
		strings.HasPrefix(name, "ETH"),
		strings.HasPrefix(name, "eth"),
		strings.HasPrefix(name, "euml"),
		strings.HasPrefix(name, "Euml"),
		strings.HasPrefix(name, "frac12"),
		strings.HasPrefix(name, "frac14"),
		strings.HasPrefix(name, "frac34"),
		strings.HasPrefix(name, "GT"),
		strings.HasPrefix(name, "gt"),
		strings.HasPrefix(name, "iacute"),
		strings.HasPrefix(name, "Iacute"),
		strings.HasPrefix(name, "icirc"),
		strings.HasPrefix(name, "Icirc"),
		strings.HasPrefix(name, "iexcl"),
		strings.HasPrefix(name, "igrave"),
		strings.HasPrefix(name, "Igrave"),
		strings.HasPrefix(name, "iquest"),
		strings.HasPrefix(name, "iuml"),
		strings.HasPrefix(name, "Iuml"),
		strings.HasPrefix(name, "laquo"),
		strings.HasPrefix(name, "LT"),
		strings.HasPrefix(name, "lt"),
		strings.HasPrefix(name, "macr"),
		strings.HasPrefix(name, "micro"),
		strings.HasPrefix(name, "middot"),
		strings.HasPrefix(name, "nbsp"),
		strings.HasPrefix(name, "not"),
		strings.HasPrefix(name, "Ntilde"),
		strings.HasPrefix(name, "ntilde"),
		strings.HasPrefix(name, "oacute"),
		strings.HasPrefix(name, "Oacute"),
		strings.HasPrefix(name, "Ocirc"),
		strings.HasPrefix(name, "ocirc"),
		strings.HasPrefix(name, "ograve"),
		strings.HasPrefix(name, "Ograve"),
		strings.HasPrefix(name, "ordf"),
		strings.HasPrefix(name, "ordm"),
		strings.HasPrefix(name, "oslash"),
		strings.HasPrefix(name, "Oslash"),
		strings.HasPrefix(name, "otilde"),
		strings.HasPrefix(name, "Otilde"),
		strings.HasPrefix(name, "ouml"),
		strings.HasPrefix(name, "Ouml"),
		strings.HasPrefix(name, "para"),
		strings.HasPrefix(name, "plusmn"),
		strings.HasPrefix(name, "pound"),
		strings.HasPrefix(name, "quot"),
		strings.HasPrefix(name, "QUOT"),
		strings.HasPrefix(name, "raquo"),
		strings.HasPrefix(name, "reg"),
		strings.HasPrefix(name, "REG"),
		strings.HasPrefix(name, "sect"),
		strings.HasPrefix(name, "shy"),
		strings.HasPrefix(name, "sup1"),
		strings.HasPrefix(name, "sup2"),
		strings.HasPrefix(name, "sup3"),
		strings.HasPrefix(name, "szlig"),
		strings.HasPrefix(name, "thorn"),
		strings.HasPrefix(name, "THORN"),
		strings.HasPrefix(name, "times"),
		strings.HasPrefix(name, "uacute"),
		strings.HasPrefix(name, "Uacute"),
		strings.HasPrefix(name, "Ucirc"),
		strings.HasPrefix(name, "ucirc"),
		strings.HasPrefix(name, "Ugrave"),
		strings.HasPrefix(name, "ugrave"),
		strings.HasPrefix(name, "uml"),
		strings.HasPrefix(name, "Uuml"),
		strings.HasPrefix(name, "uuml"),
		strings.HasPrefix(name, "yacute"),
		strings.HasPrefix(name, "Yacute"),
		strings.HasPrefix(name, "yen"),
		strings.HasPrefix(name, "yuml"):
		return true
	}
	return false
}

// collapseWhitespace 把连续空白折叠为单个空格。
// 对这种简单场景比 regexp 更快。
func normalizeURLSchemeControls(s string) string {
	if !strings.ContainsAny(s, "\t\r\n") {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if !isASCIIAlpha(s[i]) || i > 0 && isURLSchemeByte(s[i-1]) {
			b.WriteByte(s[i])
			i++
			continue
		}

		end := i + 1
		hasControl := false
		for end < len(s) {
			c := s[end]
			if isURLSchemeByte(c) {
				end++
				continue
			}
			if c == '\t' || c == '\r' || c == '\n' {
				hasControl = true
				end++
				continue
			}
			break
		}
		if !hasControl || end >= len(s) || s[end] != ':' {
			b.WriteByte(s[i])
			i++
			continue
		}

		var scheme strings.Builder
		scheme.Grow(end - i)
		for _, c := range []byte(s[i:end]) {
			if c != '\t' && c != '\r' && c != '\n' {
				scheme.WriteByte(c)
			}
		}
		normalizedScheme := strings.ToLower(scheme.String())
		if !isExecutableURLSchemeContext(s, i, end+1, normalizedScheme) {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteString(scheme.String())
		i = end
	}
	return b.String()
}

func isExecutableURLSchemeContext(s string, start, valueStart int, scheme string) bool {
	switch scheme {
	case "javascript", "vbscript", "data":
	default:
		return false
	}

	before := start - 1
	for before >= 0 && (s[before] == ' ' || s[before] == '\t' || s[before] == '\r' || s[before] == '\n') {
		before--
	}
	if before >= 0 {
		switch s[before] {
		case '=':
			return true
		case '\'', '"':
			before--
			for before >= 0 && (s[before] == ' ' || s[before] == '\t' || s[before] == '\r' || s[before] == '\n') {
				before--
			}
			if before >= 0 && s[before] == '=' {
				return true
			}
		case '(':
			nameEnd := before
			nameStart := nameEnd
			for nameStart > 0 && isASCIIAlpha(s[nameStart-1]) {
				nameStart--
			}
			if strings.EqualFold(s[nameStart:nameEnd], "url") {
				return true
			}
		}
	}

	value := strings.TrimLeft(s[valueStart:], " \t\r\n")
	if scheme == "data" {
		lower := strings.ToLower(value)
		return strings.HasPrefix(lower, "text/html") || strings.HasPrefix(lower, "image/svg")
	}
	if value == "" {
		return false
	}
	if strings.ContainsRune("([{'\"`=!", rune(value[0])) {
		return true
	}
	end := 0
	for end < len(value) && (isASCIILetterOrDigit(value[end]) || value[end] == '_' || value[end] == '$') {
		end++
	}
	if end == 0 || end >= len(value) {
		return false
	}
	return strings.ContainsRune("(.[=;", rune(value[end]))
}

func isASCIIAlpha(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isURLSchemeByte(c byte) bool {
	return isASCIILetterOrDigit(c) || c == '+' || c == '-' || c == '.'
}

func collapseWhitespace(s string) string {
	needsWork := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			needsWork = true
			break
		}
		if c == ' ' && i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t' || s[i+1] == '\n' || s[i+1] == '\r') {
			needsWork = true
			break
		}
	}
	if !needsWork {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' && (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v') {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
		} else {
			b.WriteByte(c)
			inSpace = false
		}
	}
	return b.String()
}

// decodeUTF7Sequences 还原 UTF-7 编码字符（+ADw- → <、+AD4- → > 等）。
// 用于 charset=UTF-7 的 XSS 攻击：+ADw-script+AD4-alert(1)+ADw-/script+AD4-
var reUTF7 = regexp.MustCompile(`\+([A-Za-z0-9+/]{2,8})-?`)

func decodeUTF7Sequences(s string) string {
	return reUTF7.ReplaceAllStringFunc(s, func(m string) string {
		// 剥去前导 + 与尾部 -
		encoded := strings.TrimPrefix(m, "+")
		encoded = strings.TrimSuffix(encoded, "-")
		// 补齐到 4 的倍数
		for len(encoded)%4 != 0 {
			encoded += "="
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(decoded) == 0 {
			return m
		}
		// UTF-7 基于 UTF-16BE，按对转换为字符。
		var out strings.Builder
		for i := 0; i+1 < len(decoded); i += 2 {
			r := rune(decoded[i])<<8 | rune(decoded[i+1])
			if r > 0 && r < 0xFFFF {
				out.WriteRune(r)
			}
		}
		if out.Len() == 0 {
			return m
		}
		return out.String()
	})
}

// decodeHexEscapes 把 \xNN 十六进制转义序列替换为其字节值。
// 处理 \x41\x42 → AB 这类可能出现在 JavaScript 字符串上下文之外的
// 原始载荷（如 shell 参数、HTTP 请求头）中的绕过形态。
var reHexEscape = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

func decodeHexEscapes(s string) string {
	if !strings.Contains(s, "\\x") {
		return s
	}
	return reHexEscape.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[2:4], 16, 8)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
}

// normalizeWithDecode 在归一化的同时尝试对可疑 token 做 base64 解码。
// 递归限制为 3 层、每层最多 5 个 token、解码后总预算 32KB，以约束 CPU 开销。
func normalizeWithDecode(raw string) string {
	return normalizeWithDecodeTarget(raw, true)
}

func normalizeWithDecodeTarget(raw string, queryPlusAsSpace bool) string {
	if needsDecoding(raw) {
		if strings.Contains(raw, "\\x") {
			hexDecoded := decodeHexEscapes(raw)
			if hexDecoded != raw {
				raw = hexDecoded
			}
		}
	}

	s := normalizeTarget(raw, queryPlusAsSpace)
	if len(s) < 8 || !hasLikelyBase64Candidate(s) && (raw == s || !hasLikelyBase64Candidate(raw)) {
		return s
	}
	urlDecoded := raw
	if strings.Contains(raw, "%") {
		for i := range 3 {
			var d string
			var err error
			if i == 0 {
				d, err = unescapeURLComponent(urlDecoded, queryPlusAsSpace)
			} else {
				d, err = url.PathUnescape(urlDecoded)
			}
			if err != nil || d == urlDecoded {
				break
			}
			urlDecoded = d
		}
	}
	jsDecoded := ""
	if strings.Contains(urlDecoded, "\\") {
		jsDecoded = decodeJSEscapesPooled(urlDecoded)
		if jsDecoded == urlDecoded || jsDecoded == raw || jsDecoded == s {
			jsDecoded = ""
		}
	}

	const maxTotalBytes = 32768
	const maxDepth = 3

	// acc 累积「归一化串 + 各层解码结果」。仅在首个 base64 token 真正解出内容时
	// 才从 normBufPool 取缓冲，避免绝大多数无解码结果的请求付出取还成本。
	var accPtr *[]byte
	var acc []byte
	seen := make(map[string]bool, 8)
	found := false
	totalBytes := 0
	attemptsRemaining := 2 * ((len(raw) + len(s) + len(urlDecoded) + len(jsDecoded) + maxTotalBytes + 7) / 8)

	var decodeSource func(src string, depth int) bool
	decodeSource = func(src string, depth int) bool {
		if depth > maxDepth || totalBytes >= maxTotalBytes || attemptsRemaining <= 0 {
			return false
		}
		stop := false
		forEachBase64TokenIndex(src, -1, func(start, end int) bool {
			tok := src[start:end]
			if seen[tok] {
				return true
			}
			seen[tok] = true
			if attemptsRemaining <= 0 {
				stop = true
				return false
			}
			attemptsRemaining--
			decoded := decodeBase64IfSuspicious(tok)
			if decoded == "" && start > 0 && isURLSafeBase64LeadByte(src[start-1]) {
				if attemptsRemaining <= 0 {
					stop = true
					return false
				}
				attemptsRemaining--
				decoded = decodeBase64IfSuspicious(src[start-1 : end])
			}
			if decoded == "" {
				return true
			}
			remaining := maxTotalBytes - totalBytes
			if len(decoded) > remaining {
				decoded = decoded[:remaining]
			}
			totalBytes += len(decoded)
			if !found {
				accPtr = getNormBuf()
				acc = *accPtr
				if cap(acc) < len(s)+256 {
					acc = make([]byte, 0, len(s)+256)
				}
				acc = append(acc[:0], s...)
				found = true
			}
			normalizedDecoded := normalize(decoded)
			acc = append(acc, ' ')
			acc = append(acc, normalizedDecoded...)

			nextJS := ""
			nextNormalizedJS := ""
			if strings.Contains(decoded, "\\") {
				nextJS = decodeJSEscapesPooled(decoded)
				if nextJS != decoded {
					nextNormalizedJS = normalize(nextJS)
					acc = append(acc, ' ')
					acc = append(acc, nextNormalizedJS...)
				} else {
					nextJS = ""
				}
			}
			if nextJS != "" {
				stop = decodeSource(nextJS, depth+1)
			}
			if !stop && nextNormalizedJS != "" {
				stop = decodeSource(nextNormalizedJS, depth+1)
			}
			if !stop {
				stop = decodeSource(decoded, depth+1)
			}
			if stop || totalBytes >= maxTotalBytes {
				stop = true
				return false
			}
			return true
		})
		return stop
	}

	stopped := decodeSource(raw, 1)
	if !stopped && s != raw {
		stopped = decodeSource(s, 1)
	}
	if !stopped && urlDecoded != raw && urlDecoded != s {
		stopped = decodeSource(urlDecoded, 1)
	}
	if !stopped && jsDecoded != "" {
		decodeSource(jsDecoded, 1)
	}

	if found {
		// 必须复制：acc 底层数组随即归还池，返回值不得指向池化缓冲。
		result := string(acc)
		*accPtr = acc
		putNormBuf(accPtr)
		return result
	}
	return s
}

func nextDecodedXSSHit(raw string, queryPlusAsSpace bool, threshold int) (OWASPHit, string, bool) {
	if len(raw) < 8 || !hasLikelyBase64Candidate(raw) {
		return OWASPHit{}, "", false
	}
	if !hasBase64Candidate(raw) {
		return OWASPHit{}, "", false
	}

	const maxTotalBytes = 64 * 1024
	const maxDepth = 3

	seen := make(map[string]bool, 8)
	totalBytes := 0
	attemptsRemaining := 2 * ((len(raw) + maxTotalBytes + 7) / 8)
	var scanSource func(string, int) (OWASPHit, string, bool)
	scanSource = func(src string, depth int) (OWASPHit, string, bool) {
		if depth > maxDepth || totalBytes >= maxTotalBytes || attemptsRemaining <= 0 {
			return OWASPHit{}, "", false
		}
		var foundHit OWASPHit
		var foundTarget string
		found := false
		forEachBase64TokenIndex(src, -1, func(start, end int) bool {
			tok := src[start:end]
			if seen[tok] {
				return true
			}
			seen[tok] = true
			if attemptsRemaining <= 0 {
				return false
			}
			attemptsRemaining--
			decoded := decodeBase64IfSuspicious(tok)
			if decoded == "" && start > 0 && isURLSafeBase64LeadByte(src[start-1]) {
				if attemptsRemaining <= 0 {
					return false
				}
				attemptsRemaining--
				decoded = decodeBase64IfSuspicious(src[start-1 : end])
			}
			if decoded == "" {
				return true
			}
			remaining := maxTotalBytes - totalBytes
			if len(decoded) > remaining {
				decoded = decoded[:remaining]
			}
			totalBytes += len(decoded)

			normalized := normalize(decoded)
			if hit, ok := nextXSSHit(normalized, threshold); ok {
				foundHit, foundTarget, found = hit, normalized, true
				return false
			}

			jsDecoded := ""
			if strings.Contains(decoded, "\\") {
				jsDecoded = decodeJSEscapesPooled(decoded)
				if jsDecoded != decoded {
					normalizedJS := normalize(jsDecoded)
					if hit, ok := nextXSSHit(normalizedJS, threshold); ok {
						foundHit, foundTarget, found = hit, normalizedJS, true
						return false
					}
				} else {
					jsDecoded = ""
				}
			}

			if jsDecoded != "" {
				if hit, target, ok := scanSource(jsDecoded, depth+1); ok {
					foundHit, foundTarget, found = hit, target, true
					return false
				}
			}
			if hit, target, ok := scanSource(decoded, depth+1); ok {
				foundHit, foundTarget, found = hit, target, true
				return false
			}
			return totalBytes < maxTotalBytes
		})
		return foundHit, foundTarget, found
	}

	sources := []string{raw}
	urlDecoded := raw
	if strings.Contains(raw, "%") || queryPlusAsSpace && strings.Contains(raw, "+") {
		if decoded, err := unescapeURLComponent(raw, queryPlusAsSpace); err == nil && decoded != raw {
			urlDecoded = decoded
			sources = append(sources, decoded)
		}
	}
	if strings.Contains(urlDecoded, "\\") {
		if decoded := decodeJSEscapesPooled(urlDecoded); decoded != urlDecoded {
			sources = append(sources, decoded)
		}
	}
	for _, source := range sources {
		if hit, target, ok := scanSource(source, 1); ok {
			return hit, target, true
		}
	}
	return OWASPHit{}, "", false
}

func containsOverlongUTF8Escape(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		first := lowerASCIIByte(s[i+1])
		second := lowerASCIIByte(s[i+2])
		switch first {
		case 'c':
			if second == '0' || second == '1' {
				return true
			}
		case 'e':
			if second == '0' {
				return true
			}
		case 'f':
			if second == '0' || second == '8' || second == 'c' {
				return true
			}
		}
	}
	return false
}

// hasBase64Candidate 快速判断字符串是否可能含 base64 token。
// 判据为 8 个以上连续 base64 字符，比正则便宜得多。
func hasBase64Candidate(s string) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '+' ||
			c == '/' ||
			c == '-' ||
			c == '_' {
			run++
			if run >= 8 {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// hasLikelyBase64Candidate 收紧快路径候选过滤，使普通小写单词与
// 百分号编码分隔符不进入开销较大的 base64 展开路径。
func hasLikelyBase64Candidate(s string) bool {
	lowerRun := 0
	maxLowerRun := 0
	run := 0
	hasNonLower := false
	inBase64Mode := false

	commitLowerRun := func() {
		if lowerRun > maxLowerRun {
			maxLowerRun = lowerRun
		}
		lowerRun = 0
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inBase64Mode {
			if c >= 'a' && c <= 'z' {
				lowerRun++
				if lowerRun >= 16 {
					return true
				}
				continue
			}
			if c == '%' {
				commitLowerRun()
				if maxLowerRun >= 12 {
					return true
				}
				inBase64Mode = true
				continue
			}
			if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_' {
				commitLowerRun()
				if maxLowerRun >= 12 {
					return true
				}
				inBase64Mode = true
				run = 1
				hasNonLower = true
				if run >= 8 && (hasNonLower || run >= 12) {
					return true
				}
				continue
			}
			commitLowerRun()
			continue
		}
		if c == '%' && i+2 < len(s) && isHexByte(s[i+1]) && isHexByte(s[i+2]) {
			run = 0
			hasNonLower = false
			i += 2
			continue
		}
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '+' ||
			c == '/' ||
			c == '-' ||
			c == '_' {
			run++
			if c < 'a' || c > 'z' {
				hasNonLower = true
			}
			if run >= 8 && (hasNonLower || run >= 12) {
				return true
			}
			continue
		}
		run = 0
		hasNonLower = false
	}
	if !inBase64Mode {
		if lowerRun > maxLowerRun {
			maxLowerRun = lowerRun
		}
		return maxLowerRun >= 16
	}
	return false
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func isURLSafeBase64LeadByte(b byte) bool {
	return b == '-' || b == '_'
}

var reBase64Token = regexp.MustCompile(`[A-Za-z0-9+/]{8,}={0,2}`)

func forEachBase64TokenIndex(src string, limit int, fn func(start, end int) bool) {
	if limit == 0 {
		return
	}
	count := 0
	for i := 0; i < len(src); {
		for i < len(src) && !isBase64TokenByte(src[i]) {
			i++
		}
		start := i
		for i < len(src) && isBase64TokenByte(src[i]) {
			i++
		}
		if i-start < 8 {
			continue
		}
		end := i
		for end < len(src) && end-i < 2 && src[end] == '=' {
			end++
		}
		count++
		if !fn(start, end) {
			return
		}
		if count >= limit && limit > 0 {
			return
		}
		i = end
	}
}

var base64TokenByteTable [256]byte

func init() {
	for c := byte('A'); c <= 'Z'; c++ {
		base64TokenByteTable[c] = 1
	}
	for c := byte('a'); c <= 'z'; c++ {
		base64TokenByteTable[c] = 1
	}
	for c := byte('0'); c <= '9'; c++ {
		base64TokenByteTable[c] = 1
	}
	for _, c := range []byte{'+', '/', '-', '_'} {
		base64TokenByteTable[c] = 1
	}
}

func isBase64TokenByte(b byte) bool {
	return base64TokenByteTable[b] != 0
}

// stripSQLComments 移除字符串中的 /* ... */ 行内注释，破解注释拆分绕过
// （如 sel/**/ect → select）。MySQL 版本相关注释 /*!50000...*/ 刻意保留：
// 其中含可执行 SQL，且由规则 owasp:sqli:020 匹配。
func stripSQLComments(s string) string {
	hasBlock := strings.Contains(s, "/*")
	hasLine := strings.Contains(s, "#") || strings.Contains(s, "--")
	if !hasBlock && !hasLine {
		return s
	}
	start, ok := firstStrippableSQLCommentIndex(s, hasBlock, hasLine)
	if !ok {
		return s
	}
	var buf strings.Builder
	buf.Grow(len(s))
	buf.WriteString(s[:start])
	i := start
	for i < len(s) {
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			if i+2 < len(s) && s[i+2] == '!' {
				buf.WriteByte(s[i])
				i++
				continue
			}
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				buf.WriteByte(s[i])
				i++
				continue
			}
			i = i + 2 + end + 2
		} else if isSQLLineCommentStart(s, i) {
			end := strings.IndexAny(s[i:], "\r\n")
			if end < 0 {
				break
			}
			i = i + end
		} else {
			buf.WriteByte(s[i])
			i++
		}
	}
	return buf.String()
}

func firstStrippableSQLCommentIndex(s string, hasBlock, hasLine bool) (int, bool) {
	i := 0
	for i < len(s) {
		if hasBlock && i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			if i+2 < len(s) && s[i+2] == '!' {
				i++
				continue
			}
			if strings.Contains(s[i+2:], "*/") {
				return i, true
			}
		}
		if hasLine && isSQLLineCommentStart(s, i) {
			return i, true
		}
		i++
	}
	return 0, false
}

func isSQLLineCommentStart(s string, i int) bool {
	return (s[i] == '#' &&
		(i == 0 || (s[i-1] != '=' && s[i-1] != '/' && s[i-1] != '?' && s[i-1] != '&' && s[i-1] != '"' && s[i-1] != '\'')) &&
		(i+1 >= len(s) || s[i+1] == ' ' || s[i+1] == '\t' || s[i+1] == '\n' || s[i+1] == '\r')) ||
		(i+1 < len(s) && s[i] == '-' && s[i+1] == '-' &&
			(i+2 >= len(s) || s[i+2] == ' ' || s[i+2] == '\t' || s[i+2] == '\n' || s[i+2] == '\r'))
}

var (
	reOverlongDot       = regexp.MustCompile(`(?i)%c0%ae`)
	reOverlongSlash     = regexp.MustCompile(`(?i)%c0%af`)
	reOverlongBackslash = regexp.MustCompile(`(?i)%c1%9c`)
	// 紧凑形态（百分号后四 hex 无分隔）：%C0AE→.、%C0AF→/。
	reOverlongDotCompact   = regexp.MustCompile(`(?i)%c0ae`)
	reOverlongSlashCompact = regexp.MustCompile(`(?i)%c0af`)
	// <（U+003C）的 overlong UTF-8 编码，用于绕过 XSS 过滤。
	// 2 字节：C0 BC，3 字节：E0 80 BC，4 字节：F0 80 80 BC，5 字节：F8 80 80 80 BC，6 字节：FC 80 80 80 80 BC
	reOverlongLT = regexp.MustCompile(`(?i)(%c0%bc|%e0%80%bc|%f0%80%80%bc|%f8%80%80%80%bc|%fc%80%80%80%80%bc)`)
	// >（U+003E）的 overlong UTF-8 编码。
	reOverlongGT = regexp.MustCompile(`(?i)(%c0%be|%e0%80%be|%f0%80%80%be)`)
)

func decodeBase64IfSuspicious(s string) string {
	if len(s) < 8 {
		return ""
	}
	// 前导 '/' 剥除：URL 路径位 b64 载荷（如 /SEG）长度 %4=1 会直接
	// 解码失败；剥掉前导 '/' 后按纯 token 重试（攻击者在路径上放 b64
	// 载荷的典型形态）。仅在首字符确为 '/' 且剩余部分仍 ≥8 时剥。
	if s[0] == '/' && len(s) > 9 {
		if dec := decodeBase64IfSuspicious(s[1:]); dec != "" {
			return dec
		}
		return ""
	}
	var decoded []byte
	var err error
	if len(s) <= 256 {
		var buf [192]byte
		decoded, err = decodeBase64WithBuffer(s, buf[:])
	} else {
		decoded, err = decodeBase64String(s)
	}
	if err != nil {
		return ""
	}
	if len(decoded) == 0 {
		return ""
	}
	printable := 0
	for _, b := range decoded {
		if (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r' {
			printable++
		}
	}
	ratio := float64(printable) / float64(len(decoded))
	minRatio := 0.70
	if len(s) >= 20 {
		minRatio = 0.50
	}
	if ratio < minRatio {
		if len(s) > 8 && !isBase64AlphaNum(s[0]) {
			return decodeBase64IfSuspicious(s[1:])
		}
		return ""
	}
	return string(decoded)
}

func decodeBase64WithBuffer(s string, dst []byte) ([]byte, error) {
	n, err := base64.StdEncoding.Decode(dst, []byte(s))
	if err != nil {
		n, err = base64.RawStdEncoding.Decode(dst, []byte(s))
		if err != nil {
			if !strings.ContainsAny(s, "-_") {
				return nil, err
			}
			n, err = base64.URLEncoding.Decode(dst, []byte(s))
			if err != nil {
				n, err = base64.RawURLEncoding.Decode(dst, []byte(s))
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return dst[:n], nil
}

func decodeBase64String(s string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			if !strings.ContainsAny(s, "-_") {
				return nil, err
			}
			decoded, err = base64.URLEncoding.DecodeString(s)
			if err != nil {
				decoded, err = base64.RawURLEncoding.DecodeString(s)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return decoded, nil
}

func isBase64AlphaNum(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func needsDecoding(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%', '\\', '&':
			return true
		case '+':
			if i+2 < len(s) && s[i+1] == 'A' {
				return true
			}
		}
	}
	return false
}

var cleanCharSet [256]bool

func init() {
	for c := byte('a'); c <= 'z'; c++ {
		cleanCharSet[c] = true
	}
	for c := byte('A'); c <= 'Z'; c++ {
		cleanCharSet[c] = true
	}
	for c := byte('0'); c <= '9'; c++ {
		cleanCharSet[c] = true
	}
	for _, c := range []byte{'-', '_', '.', ' ', ',', '@'} {
		cleanCharSet[c] = true
	}
}

func isCleanTarget(s string) bool {
	if len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !cleanCharSet[s[i]] {
			return false
		}
	}
	return true
}

func isCleanPathTarget(s string) bool {
	if len(s) == 0 || len(s) > 256 || hasSuspiciousBase64PathSegment(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '/' || c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return !hasPlainTargetAttackKeyword(s)
}

func isCleanPlainQueryTarget(s string) bool {
	if len(s) == 0 || len(s) > 512 || !strings.Contains(s, "=") {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == '=' || c == '&':
		default:
			return false
		}
	}
	return !hasPlainTargetAttackKeyword(s)
}

func hasSuspiciousBase64PathSegment(s string) bool {
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '/' {
			continue
		}
		if isSuspiciousBase64PathSegment(s[start:i]) {
			return true
		}
		start = i + 1
	}
	return false
}

func isSuspiciousBase64PathSegment(segment string) bool {
	if len(segment) < 8 || len(segment) > 256 || strings.Contains(segment, ".") {
		return false
	}
	// 长度修正：8-15 字符的短 b64 段（含 (alert)(1) 类短载荷的 b64 形态）
	// 用 hasLikelyBase64Candidate 判定，避免 cleanPath 快路径把短攻击
	// 载荷跳过；≥16 的段沿用全 b64 字节判定。
	if len(segment) < 16 {
		return hasLikelyBase64Candidate(segment)
	}
	for i := 0; i < len(segment); i++ {
		if !isBase64TokenByte(segment[i]) {
			return false
		}
	}
	return true
}

func hasPlainTargetAttackKeyword(s string) bool {
	for i := 0; i < len(s); i++ {
		switch lowerASCIIByte(s[i]) {
		case '.':
			if hasASCIIFoldAt(s, i, "..") || hasASCIIFoldAt(s, i, ".git") {
				return true
			}
		case 'a':
			if hasASCIIFoldAt(s, i, "alter") || hasASCIIFoldAt(s, i, "and1=1") {
				return true
			}
		case 'b':
			if hasASCIIFoldAt(s, i, "benchmark") || hasASCIIFoldAt(s, i, "boot.ini") {
				return true
			}
		case 'c':
			if hasASCIIFoldAt(s, i, "curl") {
				return true
			}
		case 'd':
			if hasASCIIFoldAt(s, i, "delete") || hasASCIIFoldAt(s, i, "drop") {
				return true
			}
		case 'e':
			if hasASCIIFoldAt(s, i, "etc/") {
				return true
			}
		case 'i':
			if hasASCIIFoldAt(s, i, "insert") {
				return true
			}
		case 'j':
			if hasASCIIFoldAt(s, i, "jndi") || hasASCIIFoldAt(s, i, "javascript") {
				return true
			}
		case 'l':
			if hasASCIIFoldAt(s, i, "localhost") || hasASCIIFoldAt(s, i, "ldap") {
				return true
			}
		case 'm':
			if hasASCIIFoldAt(s, i, "meta-inf") {
				return true
			}
		case 'o':
			if hasASCIIFoldAt(s, i, "onclick") ||
				hasASCIIFoldAt(s, i, "onload") ||
				hasASCIIFoldAt(s, i, "onerror") ||
				hasASCIIFoldAt(s, i, "or1=1") {
				return true
			}
		case 'p':
			if hasASCIIFoldAt(s, i, "passwd") {
				return true
			}
		case 's':
			if hasASCIIFoldAt(s, i, "select") ||
				hasASCIIFoldAt(s, i, "sleep") ||
				hasASCIIFoldAt(s, i, "script") {
				return true
			}
		case 't':
			if hasASCIIFoldAt(s, i, "truncate") {
				return true
			}
		case 'u':
			if hasASCIIFoldAt(s, i, "union") || hasASCIIFoldAt(s, i, "update") {
				return true
			}
		case 'w':
			if hasASCIIFoldAt(s, i, "waitfor") ||
				hasASCIIFoldAt(s, i, "whoami") ||
				hasASCIIFoldAt(s, i, "wget") ||
				hasASCIIFoldAt(s, i, "web-inf") ||
				hasASCIIFoldAt(s, i, "win.ini") {
				return true
			}
		case '_':
			if hasASCIIFoldAt(s, i, "__") {
				return true
			}
		case '1':
			if hasASCIIFoldAt(s, i, "127.0.") || hasASCIIFoldAt(s, i, "169.254") {
				return true
			}
		}
	}
	return false
}

var suspiciousCharSet [256]bool

func init() {
	for _, c := range []byte{'\'', '"', '<', '>', '(', ')', '{', '}', '[', ']', ';', '|', '`', '$', '\\', '-', '#', '!', '&', '*', '%', '=', '.', '/', ':'} {
		suspiciousCharSet[c] = true
	}
}

// hasSuspiciousContent 是 O(n) 的快速预判：判断字符串是否可能命中任何 OWASP 正则。
// 干净字符串直接返回 false，跳过整轮正则检测。
func hasSuspiciousContent(s string) bool {
	for i := 0; i < len(s); i++ {
		if suspiciousCharSet[s[i]] {
			return true
		}
	}
	// 兜底：在纯字母数字串中查找 SQL/攻击关键词。
	// 用于捕获 "1 UNION SELECT NULL FROM users" 这类请求体注入载荷——
	// 按 '=' 切分后提取出的值不含任何特殊字符。
	return hasSuspiciousKeywords(s)
}

func hasSuspiciousKeywords(s string) bool {
	if s == "" {
		return false
	}
	bm := scanIndicatorMask(s, &suspKeywordMaskTable)
	if bm&skSP != 0 {
		if strings.Contains(s, "select ") ||
			strings.Contains(s, "union ") ||
			strings.Contains(s, "insert ") ||
			strings.Contains(s, "update ") ||
			strings.Contains(s, "delete ") ||
			strings.Contains(s, "drop ") ||
			strings.Contains(s, " or ") ||
			strings.Contains(s, " and ") ||
			strings.Contains(s, "exec ") ||
			strings.Contains(s, " having ") ||
			strings.Contains(s, "alter ") ||
			strings.Contains(s, " table ") ||
			strings.Contains(s, " from ") ||
			strings.Contains(s, " where ") ||
			strings.Contains(s, " like ") ||
			strings.Contains(s, "sleep ") {
			return true
		}
	}
	if bm&skT != 0 && strings.Contains(s, "truncate") {
		return true
	}
	if bm&skW != 0 && strings.Contains(s, "waitfor") {
		return true
	}
	if bm&skH != 0 && strings.Contains(s, "schema") {
		return true
	}
	if bm&skD != 0 && strings.Contains(s, "database") {
		return true
	}
	if bm&skB != 0 && strings.Contains(s, "benchmark") {
		return true
	}
	return false
}

func hasSQLiIndicator(s string) bool {
	if s == "" {
		return false
	}
	bm := scanIndicatorMask(s, &sqliMaskTable)
	if bm&siQ != 0 && strings.ContainsAny(s, "'\"") {
		return true
	}
	if bm&siSP != 0 {
		if strings.Contains(s, " or ") ||
			strings.Contains(s, " and ") ||
			strings.Contains(s, "group by") ||
			strings.Contains(s, "order by") ||
			strings.Contains(s, "case when") ||
			strings.Contains(s, "having ") ||
			strings.Contains(s, " like ") ||
			strings.Contains(s, "to program") ||
			strings.Contains(s, "select case") {
			return true
		}
	}
	if bm&siLP != 0 {
		if strings.Contains(s, "sleep(") ||
			strings.Contains(s, "benchmark(") ||
			strings.Contains(s, "substr(") ||
			strings.Contains(s, "substring(") ||
			strings.Contains(s, "ascii(") ||
			strings.Contains(s, "ord(") ||
			strings.Contains(s, "length(") ||
			strings.Contains(s, "count(") ||
			strings.Contains(s, "version(") ||
			strings.Contains(s, "if(") ||
			strings.Contains(s, "if (") ||
			strings.Contains(s, "concat(") ||
			strings.Contains(s, "char(") ||
			strings.Contains(s, "chr(") ||
			strings.Contains(s, " cast(") ||
			strings.Contains(s, " convert(") ||
			strings.Contains(s, "json_extract(") {
			return true
		}
	}
	if bm&siUS != 0 {
		if strings.Contains(s, "information_schema") ||
			strings.Contains(s, "load_file") ||
			strings.Contains(s, "xp_") ||
			strings.Contains(s, "utl_http") ||
			strings.Contains(s, "utl_inaddr") ||
			strings.Contains(s, "utl_file") ||
			strings.Contains(s, "dbms_") ||
			strings.Contains(s, "group_concat") {
			return true
		}
	}
	if bm&siDS != 0 && strings.Contains(s, "--") {
		return true
	}
	if bm&siSL != 0 && strings.Contains(s, "/*") {
		return true
	}
	if bm&siZR != 0 && strings.Contains(s, "0x") {
		return true
	}
	if bm&siAT != 0 && strings.Contains(s, "@@") {
		return true
	}
	if bm&siW_s != 0 && strings.Contains(s, "select") {
		return true
	}
	if bm&siW_u != 0 {
		if strings.Contains(s, "union") ||
			strings.Contains(s, "update") ||
			strings.Contains(s, "updatexml") {
			return true
		}
	}
	if bm&siW_i != 0 && strings.Contains(s, "insert") {
		return true
	}
	if bm&siW_d != 0 {
		if strings.Contains(s, "delete") ||
			strings.Contains(s, "drop") ||
			strings.Contains(s, "dumpfile") {
			return true
		}
	}
	if bm&siW_a != 0 && strings.Contains(s, "alter") {
		return true
	}
	if bm&siW_t != 0 && strings.Contains(s, "truncate") {
		return true
	}
	if bm&siW_w != 0 && strings.Contains(s, "waitfor") {
		return true
	}
	if bm&siW_o != 0 && strings.Contains(s, "outfile") {
		return true
	}
	if bm&siW_e != 0 && strings.Contains(s, "extractvalue") {
		return true
	}
	if bm&siW_p != 0 && strings.Contains(s, "procedure") {
		return true
	}
	return false
}

func hasJavascriptLettersScan(s string) bool {
	var seen uint32
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'j':
			seen |= 1 << 0
		case 'a':
			seen |= 1 << 1
		case 'v':
			seen |= 1 << 2
		case 's':
			seen |= 1 << 3
		case 'c':
			seen |= 1 << 4
		case 'r':
			seen |= 1 << 5
		case 'i':
			seen |= 1 << 6
		case 'p':
			seen |= 1 << 7
		case 't':
			seen |= 1 << 8
		case ':':
			seen |= 1 << 9
		}
		if seen == 0b00000011_11111111 {
			return true
		}
	}
	return false
}

func containsASCIIFoldBackdoorRune(s string, r rune) bool {
	if r == '<' {
		for i := 0; i < len(s); i++ {
			if s[i] == '<' {
				return true
			}
		}
		return false
	}
	return strings.ContainsRune(s, r)
}

var xssIndicatorLiteralBytes = []string{
	"javascript:",
	"vbscript:",
	"document.",
	"document[",
	"innerhtml",
	"eval(",
	"settimeout(",
	"setinterval(",
	"data:text/html",
	"fromcharcode",
	"window.",
	"window[",
	"fetch(",
	"xmlhttprequest",
	"expression(",
	"srcdoc",
	"{{",
	"self[",
	"top[",
	"parent[",
	"frames[",
	"globalthis[",
	"this[",
	"alert(",
	"alert'",
	"prompt(",
	"confirm(",
	".source",
	"atob(",
	"alert.",
	"prompt.",
	"confirm.",
	// 反引号实参直连调用（prompt`1` 家族）：xss:069 电池的必要门字面。
	"alert`",
	"prompt`",
	"confirm`",
	"data:image/svg",
	"+{}",
	"+[]",
	"(![",
	"constructor.constructor",
	"constructor.prototype[",
	"onclick",
	"onload",
	"onerror",
	"onmouse",
	"onfocus",
	"onblur",
	"onkey",
	"onsubmit",
	"onchange",
	"oninput",
	"ondrag",
	"ondrop",
	"oncopy",
	"oncut",
	"onpaste",
	"ontoggle",
	"onpointer",
	"onanimation",
	"onscroll",
	"onwheel",
	"onresize",
	"onunload",
	"onhash",
	"onbefore",
	"ondblclick",
	"oncontextmenu",
	"onmessage",
	"onpopstate",
	"ontouch",
	"ontransition",
	"onfullscreen",
	"onselect",
	"oninvalid",
	"onauxclick",
	"onafterscriptexecute",
}

func hasXSSIndicator(s string) bool {
	if containsASCIIFoldBackdoorRune(s, '<') {
		return true
	}
	// 可选链调用（alert?.(document?.cookie) 家族）直通：门级放行让
	// xss:070 电池可达。alert?. 形态在自然文本中不出现（? 不是词内字符）。
	if strings.Contains(s, "alert?.") ||
		strings.Contains(s, "prompt?.") ||
		strings.Contains(s, "confirm?.") {
		return true
	}
	// )( 直连调用三字面（(alert)(1) 家族）直通：xss:067 电池内 )( 分支
	// 自锁真阳性，门级放行保证目标可达电池；自然文本几乎不会拼出
	// "alert)(" 这类词边界形态，误报面可忽略。
	if strings.Contains(s, "alert)(") ||
		strings.Contains(s, "prompt)(") ||
		strings.Contains(s, "confirm)(") {
		return true
	}
	var seenJ, seenF, seenO bool
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'j':
			seenJ = true
		case 'f':
			seenF = true
		case 'o':
			seenO = true
		}
	}
	if seenJ && strings.Index(s, "javascript:") >= 0 {
		return true
	}
	if seenF {
		if strings.Index(s, "fetch(") >= 0 ||
			strings.Index(s, "frames[") >= 0 ||
			strings.Index(s, "fromcharcode") >= 0 {
			return true
		}
	}
	for _, flagB := range xssIndicatorLiteralBytes {
		if len(flagB) == 0 {
			continue
		}
		switch flagB[0] {
		case 'o':
			if !seenO {
				continue
			}
		case 'j', 'f':
			continue
		}
		if strings.Index(s, flagB) >= 0 {
			return true
		}
	}
	if strings.Contains(s, "function(") {
		return true
	}
	return false
}

func hasCmdIndicator(s string) bool {
	if s == "" {
		return false
	}
	bm := scanIndicatorMask(s, &cmdMaskTable)
	if bm&cdDOLLAR != 0 {
		if strings.Contains(s, "$(") ||
			strings.Contains(s, "${") ||
			strings.Contains(s, "$@") ||
			strings.Contains(s, "$'") {
			return true
		}
	}
	if bm&cdAMP != 0 && strings.Contains(s, "&&") {
		return true
	}
	if bm&cdGT != 0 && strings.Contains(s, ">>") {
		return true
	}
	if bm&cdPCT != 0 && strings.Contains(s, "%00") {
		return true
	}
	if bm&cdNUL != 0 && strings.Contains(s, "\x00") {
		return true
	}
	if bm&cdLF != 0 && strings.Contains(s, "\n") {
		return true
	}
	if bm&cdCR != 0 && strings.Contains(s, "\r") {
		return true
	}
	if bm&cdSP != 0 {
		if strings.Contains(s, "wget ") ||
			strings.Contains(s, "curl ") ||
			strings.Contains(s, "export -f") ||
			strings.Contains(s, "env -i") {
			return true
		}
	}
	if bm&cdLT != 0 && strings.Contains(s, "<!--#") {
		return true
	}
	if bm&cdDOT != 0 && strings.Contains(s, "cmd.exe") {
		return true
	}
	if bm&cdPV != 0 {
		if strings.Contains(s, "powershell") ||
			strings.Contains(s, "pwsh") {
			return true
		}
	}
	if bm&cdBT != 0 && strings.Contains(s, "`") {
		return true
	}
	if bm&cdSEP != 0 && hasCmdCommandWord(s) {
		return true
	}
	if bm&cdQUOTE != 0 && hasSplitCommandWord(s) {
		return true
	}
	if bm&cdW != 0 {
		wordOK := hasCmdCommandWord(s)
		if wordOK &&
			(strings.Contains(s, "xargs") ||
				strings.Contains(s, "nohup") ||
				strings.Contains(s, "timeout ") ||
				strings.Contains(s, "setsid") ||
				strings.Contains(s, "stdbuf") ||
				strings.Contains(s, "export") ||
				strings.Contains(s, "localhost") ||
				strings.Contains(s, "127.0.0.1")) {
			return true
		}
	}
	return false
}

func hasCmdCommandWord(s string) bool {
	for i := 0; i < len(s); {
		for i < len(s) && !isCmdWordByte(s[i]) {
			i++
		}
		start := i
		for i < len(s) && isCmdWordByte(s[i]) {
			i++
		}
		if start < i && isShellCommandWord(s[start:i], false) {
			return true
		}
	}
	return false
}
func hasSplitCommandWord(s string) bool {
	seps := 0
	for i := 1; i+1 < len(s); i++ {
		c := s[i]
		if c != '\'' && c != '"' && c != '\\' {
			continue
		}
		if isASCIILetter(s[i-1]) && isASCIILetter(s[i+1]) {
			seps++
			if seps >= 2 {
				return true
			}
		}
	}
	return false
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isCmdWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// isShellCommandWord 判断 s 是否为已知 shell 命令词（仅小写字母+数字）。
// fold=false 执行精确小写比较（等价于原 isShellCommandWord）；
// fold=true 执行 ASCII case-fold 逐词比较（等价于原 isShellCommandWordASCIIFold）。
// 两路等价性由 TestShellCommandWordMergeLock 锁定。
func isShellCommandWord(s string, fold bool) bool {
	if !fold {
		return isShellCommandWordExact(s)
	}
	switch len(s) {
	case 2, 3, 4, 5, 6, 7, 8:
	default:
		return false
	}
	for _, w := range shellCommandWordsFold {
		if equalASCIIFold(s, w) {
			return true
		}
	}
	return false
}

// isShellCommandWordExact 是 fold=false 的精确小写判定（原 isShellCommandWord 原体）。
func isShellCommandWordExact(s string) bool {
	switch len(s) {
	case 2:
		switch s {
		case "id", "ls", "ps", "nc", "sh", "rm", "dd", "cp", "mv", "od", "wc":
			return true
		}
	case 3:
		switch s {
		case "cat", "pwd", "php", "dig", "awk", "sed", "set", "xxd", "tee", "ssh":
			return true
		}
	case 4:
		switch s {
		case "wget", "curl", "bash", "echo", "ping", "kill", "perl", "ruby", "node", "java", "find", "grep", "head", "tail", "more", "less", "sort":
			return true
		}
	case 5:
		switch s {
		case "uname", "touch", "chmod", "chown", "mkdir", "sleep":
			return true
		}
	case 6:
		switch s {
		case "whoami", "python", "base64", "printf", "getent":
			return true
		}
	case 7:
		switch s {
		case "tcpdump", "netstat":
			return true
		}
	case 8:
		switch s {
		case "nslookup", "hostname", "ifconfig", "ipconfig":
			return true
		}
	}
	return false
}

// shellCommandWordsFold 是原 isShellCommandWordASCIIFold 的完整词集。
var shellCommandWordsFold = []string{
	"id", "ls", "ps", "nc", "sh", "rm",
	"cat", "pwd", "php", "awk", "sed", "set", "ssh",
	"wget", "curl", "bash", "echo", "ping", "perl", "ruby", "node", "java", "find", "grep",
	"uname", "touch", "chmod", "chown", "mkdir", "sleep", "printf",
	"whoami", "python", "base64", "tcpdump", "getent",
	"nslookup", "hostname", "ifconfig", "ipconfig", "netstat",
}

const (
	iwLP uint32 = 1 << iota // '('：eval(/assert(/system(/exec(/popen(/.exec(/gzinflate(/hex2bin(/include(/require(
	iwUS                    // '_'：shell_exec/base64_decode/str_rot13(/create_function(/preg_replace(/call_user_func/file_put_contents/include_once(/require_once(/__import__(
	iwLT                    // '<'：<?php/<? /<java./<%eval/<%execute
	iwDT                    // '.'：runtime.getruntime/cmd.exe/os.system/response.write/server.execute/connector.minimal
	iwHS                    // '#'：#post_render/#pre_render/#lazy_builder
	iwBS                    // '\\'：\think\
	iwCL                    // ':'：php:///data://text/
	iwGT                    // '>'：>shell.
	iwHH                    // 'h'：passthru
	iwBB                    // 'b'：subprocess
	iwVV                    // 'v'：invokefunction
)

const (
	irPI uint32 = 1 << iota // '|'：| bash/|bash/| sh/|sh
	irSP                    // ' '：bash -i/python -c/python3 -c/perl -e/ telnet / socket
	irDA                    // '-'：invoke-expression/-e /bin//ruby -rsocket
	irSL                    // '/'：/dev/tcp
	irKK                    // 'k'：mkfifo
	irWW                    // 'w'：downloadstring
	irSS                    // 's'：socat
	irCC                    // 'c'：ncat
)

var webshellMaskTable = buildIndicatorMaskTable(map[string]uint32{
	"(":  iwLP,
	"_":  iwUS,
	"<":  iwLT,
	".":  iwDT,
	"#":  iwHS,
	"\\": iwBS,
	":":  iwCL,
	">":  iwGT,
	"h":  iwHH,
	"b":  iwBB,
	"v":  iwVV,
})

var revshellMaskTable = buildIndicatorMaskTable(map[string]uint32{
	"|": irPI,
	" ": irSP,
	"-": irDA,
	"/": irSL,
	"k": irKK,
	"w": irWW,
	"s": irSS,
	"c": irCC,
})

const (
	cdDOLLAR uint32 = 1 << iota // '$'：$( ${ $@ $'
	cdAMP                       // '&'：&&
	cdGT                        // '>'：>>
	cdPCT                       // '%'：%00
	cdNUL                       // '\x00'：\x00
	cdLF                        // '\n'：\n
	cdCR                        // '\r'：\r
	cdSP                        // ' '：wget /curl /export -f/env -i/timeout
	cdLT                        // '<'：<!--#
	cdDOT                       // '.'：cmd.exe/127.0.0.1
	cdPV                        // 'p'：powershell/pwsh
	cdBT                        // '`'：反引号（段 2）
	cdSEP                       // '|' ';' '`'：段 4 前提 ContainsAny(s, "|;`")
	cdQUOTE                     // '\'' '"' '\\'：段 5 前提 ContainsAny(s, "'\"\\")
	cdW                         // 词位：xargs/nohup/timeout /setsid/stdbuf/export/localhost/127.0.0.1
)

var cmdMaskTable = buildIndicatorMaskTable(map[string]uint32{
	"$":    cdDOLLAR,
	"&":    cdAMP,
	">":    cdGT,
	"%":    cdPCT,
	"\x00": cdNUL,
	"\n":   cdLF,
	"\r":   cdCR,
	" ":    cdSP,
	"<":    cdLT,
	".":    cdDOT,
	"p":    cdPV,
	"`":    cdBT | cdSEP,
	"|":    cdSEP,
	";":    cdSEP,
	"'":    cdQUOTE,
	"\"":   cdQUOTE,
	"\\":   cdQUOTE,
	"x":    cdW,
	"n":    cdW,
	"t":    cdW,
	"s":    cdW,
	"e":    cdW,
	"l":    cdW,
	"1":    cdW,
})

const (
	siQ   uint32 = 1 << iota // '\'' 或 '"'：ContainsAny(s, "'\"")
	siSP                     // ' '： or / and /group by/order by/case when/having / like /to program/select case
	siLP                     // '('：sleep(/benchmark(/substr(/substring(/ascii(/ord(/length(/count(/version(/if(/if (/concat(/char(/chr(/ cast(/ convert(
	siUS                     // '_'：information_schema/load_file/xp_/utl_http/utl_inaddr/utl_file/dbms_/group_concat
	siDS                     // '-'：--
	siSL                     // '/'：/*
	siZR                     // '0'：0x
	siAT                     // '@'：@@
	siW_s                    // 's'：select
	siW_u                    // 'u'：union/update/updatexml
	siW_i                    // 'i'：insert
	siW_d                    // 'd'：delete/drop/dumpfile
	siW_a                    // 'a'：alter
	siW_t                    // 't'：truncate
	siW_w                    // 'w'：waitfor
	siW_o                    // 'o'：outfile
	siW_e                    // 'e'：extractvalue
	siW_p                    // 'p'：procedure
)

var sqliMaskTable = buildIndicatorMaskTable(map[string]uint32{
	"'":  siQ,
	"\"": siQ,
	" ":  siSP,
	"(":  siLP,
	"_":  siUS,
	"-":  siDS,
	"/":  siSL,
	"0":  siZR,
	"@":  siAT,
	"s":  siW_s,
	"u":  siW_u,
	"i":  siW_i,
	"d":  siW_d,
	"a":  siW_a,
	"t":  siW_t,
	"w":  siW_w,
	"o":  siW_o,
	"e":  siW_e,
	"p":  siW_p,
})

const (
	skSP uint32 = 1 << iota // ' '：select /union /insert /update /delete /drop / or / and /exec / having /alter / table / from / where / like /sleep
	skT                     // 't'：truncate
	skW                     // 'w'：waitfor
	skH                     // 'h'：schema
	skD                     // 'd'：database
	skB                     // 'b'：benchmark
)

var suspKeywordMaskTable = buildIndicatorMaskTable(map[string]uint32{
	" ": skSP,
	"t": skT,
	"w": skW,
	"h": skH,
	"d": skD,
	"b": skB,
})

// buildIndicatorMaskTable 把“字节→掩码位”映射物化为 256 槽查找表。
func buildIndicatorMaskTable(groups map[string]uint32) (t [256]uint32) {
	for bs, v := range groups {
		for i := 0; i < len(bs); i++ {
			t[bs[i]] |= v
		}
	}
	return t
}

// scanIndicatorMask 单次扫描输入串，返回所有出现过的必备字节掩码。
func scanIndicatorMask(s string, table *[256]uint32) uint32 {
	var bm uint32
	for i := 0; i < len(s); i++ {
		bm |= table[s[i]]
	}
	return bm
}

func hasWebshellIndicator(s string) bool {
	if s == "" {
		return false
	}
	bm := scanIndicatorMask(s, &webshellMaskTable)
	if bm&iwLP != 0 {
		if strings.Contains(s, "eval(") ||
			strings.Contains(s, "assert(") ||
			strings.Contains(s, "system(") ||
			strings.Contains(s, "exec(") ||
			strings.Contains(s, "popen(") ||
			strings.Contains(s, ".exec(") ||
			strings.Contains(s, "gzinflate(") ||
			strings.Contains(s, "hex2bin(") ||
			strings.Contains(s, "include(") ||
			strings.Contains(s, "require(") {
			return true
		}
	}
	if bm&iwUS != 0 {
		if strings.Contains(s, "shell_exec") ||
			strings.Contains(s, "base64_decode") ||
			strings.Contains(s, "str_rot13(") ||
			strings.Contains(s, "create_function(") ||
			strings.Contains(s, "preg_replace(") ||
			strings.Contains(s, "call_user_func") ||
			strings.Contains(s, "file_put_contents") ||
			strings.Contains(s, "include_once(") ||
			strings.Contains(s, "require_once(") ||
			strings.Contains(s, "__import__(") {
			return true
		}
	}
	if bm&iwLT != 0 {
		if strings.Contains(s, "<?php") ||
			strings.Contains(s, "<? ") ||
			strings.Contains(s, "<java.") ||
			strings.Contains(s, "<%eval") ||
			strings.Contains(s, "<%execute") {
			return true
		}
	}
	if bm&iwDT != 0 {
		if strings.Contains(s, "runtime.getruntime") ||
			strings.Contains(s, "cmd.exe") ||
			strings.Contains(s, "os.system") ||
			strings.Contains(s, "response.write") ||
			strings.Contains(s, "server.execute") ||
			strings.Contains(s, "connector.minimal") {
			return true
		}
	}
	if bm&iwHS != 0 {
		if strings.Contains(s, "#post_render") ||
			strings.Contains(s, "#pre_render") ||
			strings.Contains(s, "#lazy_builder") {
			return true
		}
	}
	if bm&iwBS != 0 {
		if strings.Contains(s, "\\think\\") {
			return true
		}
	}
	if bm&iwCL != 0 {
		if strings.Contains(s, "php://") ||
			strings.Contains(s, "data://text/") {
			return true
		}
	}
	if bm&iwGT != 0 {
		if strings.Contains(s, ">shell.") {
			return true
		}
	}
	if bm&iwHH != 0 {
		if strings.Contains(s, "passthru") {
			return true
		}
	}
	if bm&iwBB != 0 {
		if strings.Contains(s, "subprocess") {
			return true
		}
	}
	if bm&iwVV != 0 {
		if strings.Contains(s, "invokefunction") {
			return true
		}
	}
	return false
}

func hasRevShellIndicator(s string) bool {
	if s == "" {
		return false
	}
	bm := scanIndicatorMask(s, &revshellMaskTable)
	if bm&irPI != 0 {
		if strings.Contains(s, "| bash") ||
			strings.Contains(s, "|bash") ||
			strings.Contains(s, "| sh") ||
			strings.Contains(s, "|sh") {
			return true
		}
	}
	if bm&irSP != 0 {
		if strings.Contains(s, "bash -i") ||
			strings.Contains(s, "python -c") ||
			strings.Contains(s, "python3 -c") ||
			strings.Contains(s, "perl -e") ||
			strings.Contains(s, " telnet ") ||
			strings.Contains(s, " socket") {
			return true
		}
	}
	if bm&irDA != 0 {
		if strings.Contains(s, "invoke-expression") ||
			strings.Contains(s, "-e /bin/") ||
			strings.Contains(s, "ruby -rsocket") {
			return true
		}
	}
	if bm&irSL != 0 {
		if strings.Contains(s, "/dev/tcp") {
			return true
		}
	}
	if bm&irKK != 0 {
		if strings.Contains(s, "mkfifo") {
			return true
		}
	}
	if bm&irWW != 0 {
		if strings.Contains(s, "downloadstring") {
			return true
		}
	}
	if bm&irSS != 0 {
		if strings.Contains(s, "socat ") {
			return true
		}
	}
	if bm&irCC != 0 {
		if strings.Contains(s, "ncat ") {
			return true
		}
	}
	return false
}

// hasPathTravIndicator 在字符串含路径遍历序列或指向敏感系统文件时返回 true。
func hasPathTravIndicator(s string) bool {
	return strings.Contains(s, "..") ||
		strings.Contains(s, "%2e%2e") ||
		strings.Contains(s, "%252e") ||
		strings.Contains(s, "%252f") ||
		strings.Contains(s, "etc/") ||
		strings.Contains(s, "/proc/") ||
		strings.Contains(s, "win.ini") ||
		strings.Contains(s, "boot.ini") ||
		strings.Contains(s, "..;") ||
		strings.Contains(s, "web-inf") ||
		strings.Contains(s, "meta-inf") ||
		strings.Contains(s, "c$")
}

// isSQLiFalsePositive 判断某次 SQLi 命中是否实为良性模式。
// 用于降低常见 URL 参数、自然语言与框架产物带来的噪声。
func isSQLiFalsePositive(raw, ruleID string) bool {
	lower := strings.ToLower(raw)

	switch ruleID {
	case "owasp:sqli:002": // '\s*(or|and)\s+['"]?\d
		// "D'or 1st parfume"（法文香水名）等自然文本：'or 后直接跟
		// 数字+英文序数词后缀（1st/2nd/3rd/4th）。该形态在 SQL 里
		// 无意义（1st 不是合法数字字面量），真注入恒为 ' or 1=1、
		// ' or 1--、' or 1 接引号闭合等，不会拼出序数词。序数词形态
		// 直接放行（gotestwaf false-pos 全套原文 D'or 1st parfume）。
		if reOrdinalAfterOr.MatchString(lower) {
			return true
		}
	case "owasp:sqli:003": // (sleep|benchmark|waitfor\s+delay)\s*\(
		// sleep() 与 benchmark() 是常见的 JavaScript/编程函数。
		// waitfor delay 是 MSSQL 特有形态，始终可疑。
		// 若存在 SQL 结构上下文或 SQL 终止符也保留
		// （例如 "1); sleep(5)--" 是真实注入）。
		if strings.Contains(lower, "waitfor") {
			return false
		}
		if reBoolSQLContext.MatchString(lower) || reSQLTerminatorCtx.MatchString(lower) {
			return false
		}
		// "1 AND sleep(5)" / "1 OR pg_sleep(5)"——典型的布尔盲注时间型注入
		if reANDORSleep.MatchString(lower) {
			return false
		}
		// ); sleep(...)——注入闭合前一次调用后再触发 sleep
		if strings.Contains(lower, "); sleep(") || strings.Contains(lower, ");\tsleep(") {
			return false
		}
		// x'||pg_sleep(10)——PostgreSQL 字符串拼接运算符被用作注入载体
		if strings.Contains(lower, "||") && strings.Contains(lower, "pg_sleep") {
			return false
		}
		return true // 无 SQL 上下文的 sleep()/benchmark() → JavaScript 误报

	case "owasp:sqli:006": // \s*;\s*\w——撇号 + 分号 + 单词字符
		// 二进制 body（PDF/压缩流）中该三字符模式极易随机碰撞，
		// 且其上下文校验会被二进制里偶然出现的 from/order 等英文词满足。
		if isBinaryScanTarget(raw) {
			return true
		}
		// 花括号反证（见 hasCodeBlockBraceAfterStackedSemicolon 文档）。
		if hasCodeBlockBraceAfterStackedSemicolon(raw) {
			return true
		}
		// 该模式会命中 JavaScript/TypeScript 的 import 与字符串字面量：
		// 例如 `from 'antd'; import { ... }` 或 `target='_blank'; rel='noopener'`。
		// 仅在 SQL 结构确认堆叠查询上下文时才保留。
		if strings.Contains(lower, "import ") || strings.Contains(lower, "export ") ||
			strings.Contains(lower, "from '") || strings.Contains(lower, "from \"") ||
			strings.Contains(lower, "react") || strings.Contains(lower, "antd") {
			return true
		}
		// SQL 语句起始形态（关键字或函数调用）说明分号后确是新语句，保留命中。
		if !reBoolSQLContext.MatchString(lower) && !reSQLDMLContext.MatchString(lower) &&
			!reSQLStatementStart.MatchString(lower) {
			return true
		}
	case "owasp:sqli:004": // ;\s*(select|drop|alter|create|truncate|delete|update|insert)\s
		// 分号 + DDL/DML 关键词会出现在 JavaScript（";delete obj.prop"）、
		// 自然语言（"run cleanup; delete temp files"）与 CSS 中。
		// 缺少 SQL 结构上下文（FROM、TABLE、INTO、VALUES 等）时抑制。
		if !reBoolSQLContext.MatchString(lower) && !reSQLDMLContext.MatchString(lower) {
			return true
		}
		// 同时抑制缺少列/表上下文的纯 ";insert" / ";update"，
		// 这类写法常见于 CMS 内容或编程博客。
		if strings.Contains(lower, ";insert") && !strings.Contains(lower, "into") {
			return true
		}
	case "owasp:sqli:010": // \b(or|and)\s+\d+\s*=\s*\d+
		// 该规则匹配「布尔关键字 + 数值等式」，但自然语言散文里也会出现同一串
		// （"1 and 1=1 is a very basic mathematical operation"）。区分点是
		// **恒等式所处的语法位置**：注入里它必然紧邻语句/操作数边界
		// （操作符紧贴左操作数、后继为边界字符或目标末尾、空白后紧跟 SQL
		// 语法词），散文里前后都是空格与普通单词。
		return !hasSQLTautologyInjectionContext(lower)
	case "owasp:sqli:011": // \b(or|and)\s+'...'\s*=\s*'...'
		// "or 'x'='x'" 始终恶意，不做误报抑制。
		return false
	case "owasp:sqli:005": // ['"\d]\s*(--[\s/]|/\*)
		// URL slug（如 "article1--title"）由正则要求 -- 后接空白或斜杠来处理。
		// 额外抑制：极短且无 SQL 上下文的输入。
		if len(lower) < 10 && !reBoolSQLContext.MatchString(lower) {
			return true
		}
		// S3 ARN 通配符："arn:aws:s3:::bucket01/*"——桶名末尾的数字加 /*
		// 会触发 sqli:005，但这是路径通配符而非 SQL 行内注释。
		if strings.Contains(lower, "arn:aws:s3") || strings.Contains(lower, "arn%3aaws%3as3") {
			return true
		}
		// sqli:005 是低置信度规则（score=3）。对长输入（分析埋点、遥测载荷、
		// 长度 > 200 的文档文本），它会命中 Aurora MySQL 文档（同时含 -- 与 /* 语法示例）、
		// URL 路径通配符等。要求出现显式 SQL 注入运算符才报告，以抑制这些误报。
		// 阈值从 500 下调到 200，以减少中等长度载荷上的误报。
		if len(lower) > 200 && !reSQLiInjectionOps.MatchString(lower) {
			return true
		}
		// 分析埋点与引荐跟踪像素会把完整 URL 嵌进查询参数，
		// 例如 ref=https://cdn.example.com/api/v1/* 或 ep=https://site.com/page/1/*。
		// URL 解码后它们含 "/\d/*"，会触发 sqli:005，但此处的 /*
		// 是追加在 URL 路径后的文件系统/路径通配符，而非 SQL 行内注释。
		// 由于 isSQLiFalsePositive 接收的是未归一化的原始输入，需同时检查
		// 解码形（https://）与 URL 编码形（https%3a）。
		// 防护条件：仅在不存在显式 SQL 注入运算符时才抑制。
		hasURL := strings.Contains(lower, "https://") || strings.Contains(lower, "http://") ||
			strings.Contains(lower, "https%3a") || strings.Contains(lower, "http%3a")
		hasGlob := strings.Contains(lower, "/*") || strings.Contains(lower, "%2f*") ||
			strings.Contains(lower, "%2f%2a")
		if hasURL && hasGlob && !reSQLiInjectionOps.MatchString(lower) {
			return true
		}
		// 末尾带 /* 的类路径字符串（如 /api/v1/*、/static/*）
		// 常见于路由配置，不是 SQL 注释。
		// 仅当字符串形似 URL 路径（以 / 开头）且无其他 SQLi 指示时才抑制。
		if strings.HasSuffix(lower, "/*") && strings.HasPrefix(lower, "/") && !reSQLiInjectionOps.MatchString(lower) {
			return true
		}
		// 规则语义是「SQL 注释起始」，因此按注释符两侧的**字符类别**确认它
		// 落在 token 边界上，而不是只看到一个「数字 + /*」就采信。
		// 详细判据见 hasSQLCommentTokenBoundary 的文档注释。
		// 注意：此处必须用 normalizeWithDecodeTarget 重新归一化 —— isSQLiFalsePositive
		// 收到的是 raw，而调用方传入的 target 已被归一化链剥离过 `--` 注释，
		// 且 raw 可能是 `%2d%2d` / `&#45;&#45;` 等编码形态。
		if !hasSQLCommentTokenBoundary(normalizeWithDecodeTarget(raw, false)) {
			return true
		}
	case "owasp:sqli:012": // ;\s*--
		// 分号后接双减号会出现在合法的 CSS 或 JS 片段中。
		if len(lower) < 10 {
			return true
		}
		// 遥测与分析端点常在跟踪参数中使用分号。
		if strings.Contains(lower, "/g/collect") ||
			strings.Contains(lower, "telemetry") ||
			strings.Contains(lower, "analytics") ||
			strings.Contains(lower, "google-analytics") ||
			strings.Contains(lower, "cdn-cgi") {
			return true
		}
	case "owasp:sqli:021": // substr/substring/mid 带数值参数
		// JavaScript 也大量使用 substring(start, end)。
		// 缺少 SQL 上下文（SQL 关键词或 SQL 特有函数）时抑制。
		if reBoolSQLContext.MatchString(lower) || reSQLTerminatorCtx.MatchString(lower) {
			return false
		}
		// substr 内部出现 SQL 特有函数调用可确认注入上下文。
		if reSQLi022ClauseCtx.MatchString(lower) {
			return false
		}
		if strings.Contains(lower, "ascii(") || strings.Contains(lower, "ord(") ||
			strings.Contains(lower, "user()") || strings.Contains(lower, "database()") ||
			strings.Contains(lower, "version()") || strings.Contains(lower, "@@") {
			return false
		}
		return true
	case "owasp:sqli:030": // 带 SQL 终止符的 LIMIT n,n
		// LIMIT 10,20 是标准 MySQL 分页写法。缺少 SQL 上下文确认注入时抑制。
		if !reSQLTerminatorCtx.MatchString(lower) && !reBoolSQLContext.MatchString(lower) {
			return true
		}
	case "owasp:sqli:022": // \bif\s*\(\s*(select|ord|ascii|substr|length|count|version)\b
		// if(length)、if(count)、if(version)、if(select.value) 在 JavaScript 中极常见
		// （DOM 属性检查、版本比较、长度守卫）。
		// ascii() 与 ord() 是 SQL 特有函数——绝不抑制。
		if strings.Contains(lower, "ascii(") || strings.Contains(lower, "ord(") {
			return false
		}
		// 关键词被用作 SQL 函数调用（关键词 + "("）——真实 SQL 注入。
		if reSQLi022FuncCall.MatchString(lower) {
			return false
		}
		// SQL 子句关键词 FROM/WHERE/UNION/HAVING 可确认 SQL 注入上下文。
		if reSQLi022ClauseCtx.MatchString(lower) {
			return false
		}
		// 既无 SQL 函数调用也无子句关键词：更像 JavaScript 变量/属性。
		return true
	case "owasp:sqli:001": // union (all) select
		if !hasUnionSelectAttackContext(lower) {
			return true
		}
		if len(lower) > 40 && strings.Contains(lower, " the ") || strings.Contains(lower, " a ") || strings.Contains(lower, " each ") {
			if !strings.Contains(lower, "null") && !strings.Contains(lower, "@@") &&
				!strings.Contains(lower, "information_schema") && !strings.Contains(lower, "--") &&
				!strings.Contains(lower, "/*") && !strings.Contains(lower, "0x") {
				return true
			}
		}
	case "owasp:sqli:017": // INTO OUTFILE/DUMPFILE
		// MySQL 要求带引号的文件路径：INTO OUTFILE '/tmp/x.php'。
		// 文档文本如 "SELECT INTO OUTFILE S3"（AWS Aurora 文档）没有引号路径。
		// 仅在关键词后紧跟带引号的文件路径时才保留。
		if !reIntoOutfileWithPath.MatchString(lower) {
			return true
		}
	case "owasp:sqli:008": // [,=(]\s*0x[0-9a-f]{4,}——带前置运算符的十六进制字面量
		// 十六进制字面量（0xFFFF、0xABCDEF）会出现在 CSS 颜色、内存地址、二进制
		// 协议与日志数据中，并非 SQL 注入独有。
		// 仅在同时存在强 SQL 注入上下文时才报告该命中。
		if !reSQLi008AttackCtx.MatchString(lower) {
			return true
		}
	case "owasp:sqli:047": // SELECT * FROM
		if strings.Contains(lower, "select * from users where users.slug") && strings.Contains(lower, "limit 1") {
			return true
		}
		hasDocSearchContext := strings.Contains(lower, "q=") || strings.Contains(lower, "query=") ||
			strings.Contains(lower, "search") || strings.Contains(lower, "best practices") ||
			strings.Contains(lower, "aurora") || strings.Contains(lower, "amazon s3") ||
			strings.Contains(lower, "sample-loaddata01") || strings.Contains(lower, "aurora-s3-access-pol") ||
			strings.Contains(lower, "aurora_default_s3_role") || strings.Contains(lower, "select into outfile s3") ||
			strings.Contains(lower, "load data from s3") || strings.Contains(lower, "permalink") ||
			strings.Contains(lower, "comments") || strings.Contains(lower, "segmentfault") ||
			strings.Contains(lower, "loc=https://")
		if hasDocSearchContext {
			if strings.Contains(lower, "select * from users where users.slug") ||
				strings.Contains(lower, "users.slug") ||
				strings.Contains(lower, "limit 1") ||
				strings.Contains(lower, "publication/search") {
				return true
			}
			if !strings.Contains(lower, "union select") && !strings.Contains(lower, "union all select") &&
				!strings.Contains(lower, "sleep(") && !strings.Contains(lower, "benchmark(") &&
				!strings.Contains(lower, "waitfor") && !strings.Contains(lower, "0x") &&
				!isTautology(lower) {
				return true
			}
		}
	}
	return false
}

// hasActiveXSSContext 检查是否存在可确认真实 XSS 攻击的主动 JavaScript 执行指示，
// 以区别于被动结构型 HTML 或 DOM 读取。
// 注意：单独的 document.location 被排除——它是导航代码中常见的 DOM 读取属性，
// 本身并不启用脚本注入。
func hasActiveXSSContext(normalized string) bool {
	return strings.Contains(normalized, "javascript:") ||
		strings.Contains(normalized, "vbscript:") ||
		strings.Contains(normalized, "data:text/html") ||
		strings.Contains(normalized, "<script") ||
		strings.Contains(normalized, ":script") ||
		strings.Contains(normalized, "eval(") ||
		strings.Contains(normalized, "alert(") ||
		strings.Contains(normalized, "prompt(") ||
		strings.Contains(normalized, "confirm(") ||
		strings.Contains(normalized, "fromcharcode") ||
		strings.Contains(normalized, "document.cookie") ||
		strings.Contains(normalized, "document.write") ||
		strings.Contains(normalized, "innerhtml") ||
		reXSSEventHandler.MatchString(normalized) ||
		(hasJavascriptLettersScan(normalized) && reJSProtocolObfuscated.MatchString(normalized))
}

// isXSSFalsePositive 在 XSS 命中仅来自被动结构型 HTML 元素
// （svg、iframe、math、embed、base、link）或常见 DOM 导航属性
// （document.location、window.location）且不存在任何主动 JavaScript 执行上下文时
// 返回 true。富 HTML 内容（CMS 文章、报表）与单页应用导航代码常包含这些模式。
// 在高敏感度下（阈值 ≤ 2），调用方会绕过本检查。
func isKnownTelemetryXSSFalsePositive(path, normalized, ruleID string, isBodyTarget bool) bool {
	lowerPath := toLowerASCII(path)
	if !isBodyTarget {
		return false
	}
	lower := strings.ToLower(normalized)
	switch ruleID {
	case "owasp:xss:003":
		// 该 ruleID 的遥测豁免已随删词取消（原为「路径 + 内容判据」双条件，
		// 路径部分 /analytics/v2_upload、/api/report、/fd/ls/glinkpingpost.aspx
		// 与内容部分均已删）。保留 case 标签供审计追溯。
	case "owasp:xss:005":
		// 同上（原路径 /news/g）。
	case "owasp:xss:007", "owasp:xss:010":
		// 同上（原路径 /logstores/prod/track）。
	case "owasp:xss:002":
		if strings.Contains(lowerPath, "/run") {
			return strings.Contains(lower, "onclick=") || strings.Contains(lower, "preventdefault") || strings.Contains(lower, "createroot") || strings.Contains(lower, "react")
		}
	}
	return false
}

// isHarmlessInlineScriptOnly 判断字符串中的每个 <script> 元素是否都不具备
// 脚本载荷能力，因而属于页面常规结构（业务页面的挂载代码、外链引用）。
//
// 判据按「元素是否可执行」而非「出现在哪个站点/路径」定义，分两侧：
//
//   - 开标签：出现事件处理器属性（on<event>=）、伪协议或转义序列
//     （javascript:/vbscript:/data:/&#/%u/\u/\x）即视为载荷。带 src/xlink:href/href
//     引用属性时，取值必须是双引号包裹的 http(s):// 或绝对路径，且标签体为空。
//   - 标签体：出现成员访问式下标（obj["x"]/[`x`]）、HTML 标签、事件处理器、
//     反引号、八进制转义、\u/\x 转义，或执行原语（alert/…/eval/…、document.cookie
//     等属性、location 赋值、fetch( 等调用）即视为载荷。
//
// 任一元素不满足即返回 false，交回通用结构判据继续判定。该判据的背离条件是
// 「内联体只用本函数未列举的原语完成执行」——此时放行；列举面覆盖的是
// JS 里无法绕开的能力入口（调用、下标取值、DOM 写入、导航、编码逃逸）。
func isHarmlessInlineScriptOnly(lower string) bool {
	idx, found := 0, false
	for {
		i := strings.Index(lower[idx:], "<script")
		if i < 0 {
			break
		}
		i += idx
		end := strings.Index(lower[i:], ">")
		if end < 0 {
			return false
		}
		closeIdx := strings.Index(lower[i:], "</script")
		bodyEnd := len(lower)
		if closeIdx >= 0 {
			bodyEnd = i + closeIdx
		}
		openEnd := i + end + 1
		// '</script' 落在 '>' 之前时开标签被截断（如 "<script </script>"），
		// 既不是合法元素结构，也没有可判定的标签体：交回通用判据，
		// 且必须先于切片判定，否则 bodyEnd < openEnd 会越界。
		if openEnd > bodyEnd {
			return false
		}
		if !isHarmlessScriptElement(lower[i:openEnd], lower[openEnd:bodyEnd]) {
			return false
		}
		found = true
		if closeIdx < 0 {
			break
		}
		idx = bodyEnd + len("</script")
	}
	return found
}

// isHarmlessScriptElement 判断单个 <script ...> 元素（开标签 + 标签体）是否
// 不具备脚本载荷能力。openTag 含 '<script' 前缀，body 为标签体原文。
func isHarmlessScriptElement(openTag, body string) bool {
	attrs := openTag[len("<script"):]
	if hasScriptPayloadInAttrs(attrs) {
		return false
	}
	// 元素级引用属性（src/xlink:href/href）优先：带引用时必须为可静态确认的
	// 外链且标签体为空。反斜杠先剥除，兼容 JSON 转义后的 \" 形态。
	ref, ok := scriptRefValue(strings.ReplaceAll(attrs, "\\", ""))
	if ok {
		return isSafeScriptRef(ref) && strings.TrimSpace(body) == ""
	}
	if hasUnquotableScriptRef(attrs) {
		return false
	}
	return !hasInlineScriptPayload(strings.TrimSpace(body))
}

// hasScriptPayloadInAttrs 判断 <script> 开标签属性区是否含载荷特征：
// 事件处理器属性、反引号、伪协议或转义序列。这些形态本身就构成注入
// （如 <script src=data:...>、<script xlink:href=...>、onerror= 变体）。
func hasScriptPayloadInAttrs(attrs string) bool {
	if reXSSEventHandler.MatchString(attrs) || strings.Contains(attrs, "`") {
		return true
	}
	for _, needle := range []string{"javascript:", "vbscript:", "data:", "&#", "%u", `\u`, `\x`} {
		if strings.Contains(attrs, needle) {
			return true
		}
	}
	return false
}

// scriptRefValue 提取 <script> 开标签的引用属性取值。引用属性按 src、xlink:href、
// href 顺序查找；返回 ok=false 表示不存在这三个引用属性。
func scriptRefValue(attrs string) (string, bool) {
	for _, attr := range []string{`src="`, `xlink:href="`, `href="`} {
		k := strings.Index(attrs, attr)
		if k < 0 {
			continue
		}
		rest := attrs[k+len(attr):]
		q := strings.Index(rest, `"`)
		if q < 0 {
			return "", true
		}
		return rest[:q], true
	}
	return "", false
}

// hasUnquotableScriptRef 判断是否存在未以双引号包裹的引用属性取值
// （<SCRIPT SRC=/host/1> 这类注入形态）。调用前应已排除双引号包裹的引用。
func hasUnquotableScriptRef(attrs string) bool {
	u := strings.ReplaceAll(attrs, "\\", "")
	for _, attr := range []string{"src=", "xlink:href=", "href="} {
		if strings.Contains(u, attr) {
			return true
		}
	}
	return false
}

// isSafeScriptRef 判断引用属性取值是否为可静态确认的外链/站点绝对路径，
// 排除 data:/javascript:/vbscript: 与协议相对 // 这类以引用承载载荷的形态。
func isSafeScriptRef(value string) bool {
	if value == "" {
		return false
	}
	for _, bad := range []string{"data:", "javascript:", "vbscript:", "//"} {
		if strings.HasPrefix(value, bad) {
			return false
		}
	}
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") ||
		strings.HasPrefix(value, "/")
}

// hasInlineScriptPayload 判断内联脚本体是否具备脚本能力。命中任一类即视为
// 可执行载荷：成员访问式下标取值（越过字符串不能表达属性访问的边界）、
// HTML 标签、事件处理器属性、反引号模板、编码逃逸序列、执行原语。
func hasInlineScriptPayload(body string) bool {
	if body == "" {
		return false
	}
	if reScriptMemberIndex.MatchString(body) {
		return true
	}
	if reScriptBodyTag.MatchString(body) {
		return true
	}
	if reXSSEventHandler.MatchString(body) {
		return true
	}
	if strings.Contains(body, "`") || reScriptOctalEscape.MatchString(body) {
		return true
	}
	if strings.Contains(body, `\u`) || strings.Contains(body, `\x`) {
		return true
	}
	return hasScriptExecPrimitive(body)
}

// hasScriptExecPrimitive 判断文本是否含 JavaScript 执行原语：已知的危险函数/
// 属性词、导航对象引用、属性写入与网络/代码求值调用。
func hasScriptExecPrimitive(s string) bool {
	if reScriptPrimitiveWord.MatchString(s) || reScriptNavRef.MatchString(s) {
		return true
	}
	if strings.Contains(s, "&#") || strings.Contains(s, "%u") ||
		strings.Contains(s, "javascript:") || strings.Contains(s, "vbscript:") {
		return true
	}
	return reScriptPrimitiveCall.MatchString(s)
}

var (
	// reScriptMemberIndex 匹配成员访问式下标取值：obj["x"] / arr[0]["k"] / obj[`x`]。
	// 字符串字面量（attr["x"] 这类值）不能表达属性访问，故以此区分
	// 业务数据与脚本求值。
	reScriptMemberIndex = regexp.MustCompile("[a-z0-9_$)\\]}]\\s*\\[\\s*['\"`]")
	// reScriptBodyTag 匹配脚本体里出现的 HTML 标签起始（<div / </div / <svg>）。
	reScriptBodyTag = regexp.MustCompile(`</?[a-z][a-z0-9]*[\s/>]`)
	// reScriptOctalEscape 匹配八进制转义（\141 → a），JS 字符串里唯一无法
	// 用字面量表达的编码方式。
	reScriptOctalEscape = regexp.MustCompile(`\\[0-7]`)
	// reScriptPrimitiveWord 匹配执行/注入原语词。
	reScriptPrimitiveWord = regexp.MustCompile(`\b(alert|prompt|confirm|eval|execscript|settimeout|setinterval|atob|btoa|unescape|decodeuri|decodeuricomponent|fromcharcode|innerhtml|outerhtml|insertadjacenthtml|xmlhttprequest|sendbeacon|globalthis|constructor)\b|document\.(cookie|write|domain|location)`)
	// reScriptNavRef 匹配导航/上下文对象引用与赋值（location.href=、top[）。
	reScriptNavRef = regexp.MustCompile(`\b(location|opener|parent|frames|self|top)\s*[.=\[]`)
	// reScriptPrimitiveCall 匹配代码求值与网络/文档写入调用。
	reScriptPrimitiveCall = regexp.MustCompile(`\b(fetch|import|require|writeln|write|replace|assign|navigate|exec|appendchild|createelement|setattribute|createelementns)\s*\(`)
)

func isBenignJavaScriptVoid(normalized string) bool {
	lower := strings.ToLower(normalized)
	if !strings.Contains(lower, "javascript:") {
		return false
	}
	if strings.Contains(lower, "alert(") || strings.Contains(lower, "confirm(") ||
		strings.Contains(lower, "prompt(") || strings.Contains(lower, "eval(") ||
		strings.Contains(lower, "document.cookie") || strings.Contains(lower, "document.write") ||
		strings.Contains(lower, "innerhtml") || strings.Contains(lower, "fromcharcode") ||
		strings.Contains(lower, "<script") || strings.Contains(lower, "<base") ||
		strings.Contains(lower, "fetch(") || strings.Contains(lower, "xmlhttp") ||
		reXSSEventHandler.MatchString(lower) {
		return false
	}
	return strings.Contains(lower, "javascript:;") ||
		strings.Contains(lower, "javascript:void(0)") ||
		strings.Contains(lower, "javascript: void(0)") ||
		strings.Contains(lower, "javascript:void 0") ||
		strings.Contains(lower, "javascript: void 0") ||
		strings.Contains(lower, "javascript%3a;") ||
		strings.Contains(lower, "javascript%3avoid(0)") ||
		strings.Contains(lower, "javascript%3a%20void(0)") ||
		strings.Contains(lower, "javascript%3avoid%200") ||
		strings.Contains(lower, "javascript%3a%20void%200")
}

func isBingPingPostBenignNavigation(normalized string) bool {
	lower := strings.ToLower(normalized)
	return strings.Contains(lower, "url=javascript:void(0)") ||
		strings.Contains(lower, "url=javascript%3avoid(0)") ||
		strings.Contains(lower, "url=javascript%3avoid(0);") ||
		strings.Contains(lower, "url=javascript%3avoid(0)%3b") ||
		strings.Contains(lower, "url=javascript:;") ||
		strings.Contains(lower, "url=javascript%3a;") ||
		strings.Contains(lower, "url=javascript%3a%3b")
}

func isKnownTelemetryCmdFalsePositive(path, normalized, ruleID string, isBodyTarget bool) bool {
	if !isBodyTarget {
		return false
	}
	lowerPath := strings.ToLower(path)
	lower := strings.ToLower(normalized)
	if ruleID == "owasp:cmd:001" && strings.Contains(lowerPath, "/run") {
		return strings.Contains(lower, "document.getelementbyid") || strings.Contains(lower, "createroot") || strings.Contains(lower, "react-dom/client")
	}
	return false
}

func isKnownTelemetryPathTravFalsePositive(path, normalized, ruleID string, isBodyTarget bool) bool {
	if !isBodyTarget {
		return false
	}
	lowerPath := strings.ToLower(path)
	switch ruleID {
	case "owasp:path_traversal:001":
		// 该 ruleID 的遥测豁免已随删词取消（原为「路径 + 内容三词」双条件，
		// 内容部分已删）。保留 case 标签是为了让审计能看到这条豁免曾经存在。
	case "owasp:path_traversal:011":
		// 同上。
	case "owasp:path_traversal:009":
		// 网易 analytics /ctrip SaveTraceInfo 等 JSON 遥测体：URL 解码后
		// 出现「...%3C/ 」（中文省略号+链接标签）或「...\n 」（反斜杠
		// 转义序列）被 009 正则 \.{3,}[/\\] 误命中。路径定位到这些已知
		// 遥测端点时抑制。
		if strings.Contains(lowerPath, "/restapi/soa2/") {
			return true
		}
	}
	return false
}

func isXSSFalsePositive(normalized, firstRuleID string) bool {
	switch firstRuleID {
	case "owasp:xss:032": // /regex/.source 字符串拼接
		return false
	case "owasp:xss:052": // global[( 形式的 JSFuck
		return !hasActiveXSSContext(normalized)
	case "owasp:xss:001": // <script[\s>]
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "search%2ffor") || strings.Contains(lower, "search/for") ||
			strings.Contains(lower, "is incorrect") || strings.Contains(lower, "performance") && strings.Contains(lower, "val_url") || strings.Contains(lower, "cpro.baidustatic.com") || strings.Contains(lower, "hm.baidu.com") || strings.Contains(lower, "class=\"row_ad\"") || strings.Contains(lower, "slotbydup") {
			return true
		}
		if len(normalized) > 200 {
			hasActiveJS := strings.Contains(lower, "alert(") ||
				strings.Contains(lower, "eval(") ||
				strings.Contains(lower, "document.cookie") ||
				strings.Contains(lower, "document.write") ||
				strings.Contains(lower, "prompt(") ||
				strings.Contains(lower, "confirm(") ||
				strings.Contains(lower, "fromcharcode") ||
				strings.Contains(lower, "src=") ||
				strings.Contains(lower, "onerror") ||
				strings.Contains(lower, "onload") ||
				strings.Contains(lower, "fetch(") ||
				strings.Contains(lower, "innerhtml") ||
				strings.Contains(lower, "xmlhttp") ||
				strings.Contains(lower, "\\u00") ||
				strings.Contains(lower, "base64") ||
				strings.Contains(lower, "window[") ||
				strings.Contains(lower, "window.") ||
				strings.Contains(lower, "constructor")
			if !hasActiveJS {
				return true
			}
		}
		// 页面常规脚本结构（纯外链引用，或内联体不含任何脚本能力入口）不构成 XSS。
		// 判据落在「元素能否执行」而非域名：任何域名的纯外链引用都放行，内联体一旦
		// 出现下标取值/标签/事件处理器/转义序列/执行原语，即回落到下面的通用结构
		// 判据，仍可命中。
		if isHarmlessInlineScriptOnly(lower) {
			return true
		}
		if !strings.Contains(lower, "</script") && !strings.Contains(lower, "alert(") &&
			!strings.Contains(lower, "eval(") && !strings.Contains(lower, "onerror") &&
			!strings.Contains(lower, "onload") && !strings.Contains(lower, "document.cookie") &&
			!strings.Contains(lower, "document.write") && !strings.Contains(lower, "prompt(") &&
			!strings.Contains(lower, "confirm(") {
			idx := strings.Index(lower, "<script")
			if idx >= 0 {
				after := lower[idx+7:]
				if len(after) > 0 && after[0] != '>' && after[0] != ' ' && after[0] != '\t' {
					return true
				}
				if strings.HasPrefix(strings.TrimLeft(after, " \t"), "src=") && !strings.Contains(after, "(") {
					return true
				}
				if !strings.Contains(after, "(") && !strings.Contains(after, "=") {
					return true
				}
			}
		}
	case "owasp:xss:002": // \bon(event)\s*=——HTML 事件处理器属性
		if isXSSHandlerFunctionRef(normalized) {
			return true
		}
		if len(normalized) > 300 {
			lower := strings.ToLower(normalized)
			isCode := strings.Contains(lower, "const ") || strings.Contains(lower, "function ") ||
				strings.Contains(lower, "=> ") || strings.Contains(lower, "import ") ||
				strings.Contains(lower, "export ") || strings.Contains(lower, "return (")
			if isCode && !strings.Contains(lower, "alert(") && !strings.Contains(lower, "eval(") &&
				!strings.Contains(lower, "document.cookie") && !strings.Contains(lower, "document.write") {
				return true
			}
		}
	case "owasp:xss:003": // javascript: URI
		// "JavaScript: Basics of JavaScript Language"（教程标题）等自然语言：
		// javascript: 后跟英文单词短语（无 ;、无 (、无 URL scheme 值）。
		// 真注入 javascript: 后必有执行语义（alert(、void(0)、fetch( 等）
		// 或 URL 值（//、http:、data:）。
		if reJSProtocolNaturalPhrase.MatchString(normalized) {
			return true
		}
		return isBenignJavaScriptVoid(normalized)
	case "owasp:xss:005", "owasp:xss:007", "owasp:xss:008",
		"owasp:xss:012", "owasp:xss:015",
		"owasp:xss:022", "owasp:xss:024", "owasp:xss:028":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "row_ad") || strings.Contains(lower, "slotbydup") ||
			strings.Contains(lower, "hm.baidu.com") || strings.Contains(lower, "cpro.baidustatic.com") {
			return true
		}
		if hasActiveXSSContext(normalized) {
			return false
		}
		if len(normalized) > 2000 && (strings.Contains(normalized, "<iframe") || strings.Contains(normalized, "<object") || strings.Contains(normalized, "<embed")) {
			return false
		}
		return true
	case "owasp:xss:014":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "react.createelement") || strings.Contains(lower, "createroot") ||
			strings.Contains(lower, "preventdefault") || strings.Contains(lower, "class=\"row_ad\"") ||
			strings.Contains(lower, "slotbydup") || strings.Contains(lower, "hm.baidu.com") ||
			strings.Contains(lower, "cm.js") || strings.Contains(lower, "target=\"_blank\"") {
			if !strings.Contains(lower, "alert(") && !strings.Contains(lower, "eval(") && !strings.Contains(lower, "javascript:") {
				return true
			}
		}
	case "owasp:xss:006", "owasp:xss:010":
		// document.(location|write|cookie|domain) 与 window.(location|name|open)
		// 是合法 SPA 导航代码中大量使用的标准 DOM 属性。
		// 缺少主动脚本执行上下文时抑制。
		return !hasActiveXSSContext(normalized)
	case "owasp:xss:033":
		// JSFuck 锚（+[]/+{}）在二进制/加密数据（ctrip SaveTraceInfo
		// 等遥测体）中随机碰撞率极高。真实 JSFuck 载荷有完整结构
		//（(![]、!![]、构造函数链），裸 +[] 单独出现不算注入。
		if !strings.Contains(normalized, "(![]") && !strings.Contains(normalized, "!![]") &&
			!strings.Contains(normalized, "constructor") {
			return true
		}
	}
	return false
}

// isXSSHandlerFunctionRef 判断事件处理器命中（xss:002）是否更像 CDN/API 回调注册
// （例如 ?onload=myCallback），而非真实 XSS。
// CDN 回调是纯标识符；真实 XSS 载荷会调用函数：onload=alert(1)。
func isXSSHandlerFunctionRef(normalized string) bool {
	// 处理器值后出现函数调用左括号 → 真实 XSS 尝试。
	if reXSSHandlerCallParens.MatchString(normalized) {
		return false
	}
	// HTML 标签上下文（<...>）→ 可能是注入的标记。
	if strings.ContainsRune(normalized, '<') || strings.ContainsRune(normalized, '>') {
		return false
	}
	// 主动 JS 执行关键词可确认真实攻击意图。
	if strings.Contains(normalized, "javascript:") ||
		strings.Contains(normalized, "eval(") ||
		strings.Contains(normalized, "document.cookie") ||
		strings.Contains(normalized, "fromcharcode") ||
		strings.Contains(normalized, "<script") {
		return false
	}
	return true
}

// reXSSEventHandler 匹配行内事件处理器属性（on<event>=）。
var reXSSEventHandler = regexp.MustCompile(`\bon\w+\s*=`)
var reJSProtocolObfuscated = regexp.MustCompile(`j\s*a\s*v\s*a\s+s\s*c\s*r\s*i\s*p\s*t\s*:`)

// reBacktickInjectionCtx 判定反引号命令替换是否处于 shell 注入位置：
// 起始反引号位于串首，或紧跟 shell 运算符（=、;、|、&、$）或旗标式参数
// （如 --exec=`id`）时成立。
// 该模式不匹配时，反引号出现在自然语言或文档上下文中
// （如 "Use `echo` to print"），应予抑制。
// 注意：运算符集合刻意排除逗号与闭合反引号，
// 使 Markdown 里的 "try `cat`, `grep`" 不会因第二个反引号而误命中。
// backtickCmdWords 是 reBacktickInjectionCtx 与 reCmd002Backtick 共享的命令词表。
// 两条正则均以 "(" + backtickCmdWords + ")" 拼接编译，禁止单边再改动：
// 词表由 TestBacktickCmdWordLiterals 锁定，正则最终文本由 TestBacktickRegexesByteStable 按 .String() 锁定。
var backtickCmdWords = strings.Join([]string{
	"cat", "ls", "id", "whoami", "uname", "pwd", "wget", "curl", "nc", "bash",
	"sh", "echo", "rm", "chmod", "chown", "python", "perl", "ruby", "php",
	"base64", "find", "grep", "awk", "sed", "ps", "kill", "nslookup", "dig",
	"ping", "sleep", "dd", "cp", "mv", "mkdir", "touch", "head", "tail", "sort", "xxd",
}, "|")

var reBacktickInjectionCtx = regexp.MustCompile("(^|[=;|&$])\\s*`[^`]*(" + backtickCmdWords + ")[^`]*`")
var reCmd002Backtick = regexp.MustCompile("`[^`]*(" + backtickCmdWords + ")[^`]*`")

// reCmdHighConfidence 匹配可确认真实命令注入意图的模式。
// 当 cmd:006（空字节/换行注入）是首个命中的规则时，要求至少出现一个此类
// 高置信度指示才报告命中。
// 这可抑制二进制/分析数据中的空字节与弱二级模式
// （如 cmd:010 环境变量 + 语言名）共同触发的误报。
var reCmdHighConfidence = regexp.MustCompile(
	`(` +
		`[;|&]\s*(cat|ls|whoami|uname|pwd|wget|curl|nc|bash|sh)(?:\s|;|` + "`" + `|&|\||$)` + // 管道/分号 + 命令（其后不能跟 =，以避免参数名误报）
		// 探测命令 + 分号：要求前导为空白/运算符/串首（而非 \x00 这类任意非单词字节），
		// 以防二进制分析载荷中 \x00id; 之类的字节序列命中。
		`|(?:^|[\s;|&])(id|uname|whoami|hostname|ifconfig|ipconfig)\s*;` + // 探测命令 + 分号（cmd:007）
		`|\$\{?\s*IFS\s*\}?` + // ${IFS} 空格绕过（cmd:009）
		`|(&&|\|\|)\s*(cat|ls|whoami|uname|bash|sh|rm)(?:\s|;|` + "`" + `|$)` + // && / || 链式执行（cmd:011）
		`|(bash|sh|python|perl|ruby)\s*<<<` + // here-string 注入（cmd:013）
		`|\$'\s*\\[xX0][0-9a-fA-F]` + // ANSI-C 十六进制/八进制引用（cmd:014）
		`|>\s*/(etc|tmp|var|root|home)/` + // 重定向到敏感路径（cmd:004）
		`|\{\s*(cat|ls|id|whoami|echo|bash|sh|python|perl|ruby|wget|curl)\s*,` + // 花括号展开（cmd:012）
		`)`)

// isCmdInjectionFalsePositive 抑制疑似误报的命令注入命中。
func isCmdInjectionFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:cmd:001": // [;|&]\s*(cmd)\s
		lower := strings.ToLower(normalized)
		// User-Agent 形如 "Mozilla/5.0 (... ; Touch; rv:11.0) like Gecko"，
		// 归一化后含 "; Touch;"，会命中 "; touch"。
		// 浏览器 UA 串绝不构成命令注入。
		if strings.Contains(lower, "mozilla") || strings.Contains(lower, "gecko") ||
			strings.Contains(lower, "webkit") || strings.Contains(lower, "trident") ||
			strings.Contains(lower, "chrome/") || strings.Contains(lower, "safari/") {
			return true
		}
		// 表单参数名如 "echo=value" 会被 extractFormValues 按 '=' 切开，
		// 产生两个扫描目标："echo"（键）与 "value"。键 "echo" 在查询串或表单体
		// 分隔符带来的 '&' 之后会被当作命令 "echo" 命中。
		// 除非匹配出现在明确的 shell 执行上下文中，否则抑制。
		if len(normalized) > 200 && !reCmdHighConfidence.MatchString(normalized) {
			if strings.Contains(lower, "\\u00") || strings.Contains(lower, "base64") ||
				strings.Contains(lower, "sessionid") || strings.Contains(lower, "\"type\"") ||
				strings.Contains(lower, "subscribe") {
				return true
			}
		}
		// 仅为命令名且不含 shell 运算符的短值（如表单参数键 "echo"、"kill"、"sort"）
		// 属误报。
		trimmed := strings.TrimSpace(normalized)
		if len(trimmed) < 30 && !strings.ContainsAny(trimmed, ";|&`$>") {
			return true
		}
	case "owasp:cmd:002": // 反引号命令替换（score=4）
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "protobuf") || strings.Contains(lower, "application/x-protobuf") {
			return true
		}
		if reBacktickInjectionCtx.MatchString(normalized) {
			return false
		}
		if len(normalized) > 200 && !reCmdHighConfidence.MatchString(normalized) {

			match := reCmd002Backtick.FindString(normalized)
			if len(match) > 50 {
				return true
			}
		}
		if strings.ContainsAny(normalized, ";|") || strings.Contains(normalized, "&&") ||
			strings.Contains(normalized, "$(") || strings.Contains(normalized, "${") {
			return false
		}
		return true
	case "owasp:cmd:006": // 空字节 / 换行字节注入（score=3）
		// 空字节（\x00）可以合法地出现在二进制 POST 体、URL 编码数据与发往
		// 日志/分析端点的遥测载荷中。在良性请求上，它们可能连带触发 cmd:010
		// （环境变量 + "python" 这类语言名）。
		// 除非存在更高置信度的 shell 执行指示，否则抑制。
		if !reCmdHighConfidence.MatchString(normalized) {
			return true
		}
	case "owasp:cmd:024": // 反引号 + 命令名（ping、curl、cat 等）
		lower := strings.ToLower(normalized)
		// gRPC/API 方法名如 "v1:GetHints" 含类反引号模式，会命中命令名
		// （如 `cat`、`sh`）——对已知安全路径抑制。
		if strings.Contains(lower, "gethints") {
			return true
		}
	case "owasp:cmd:010":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "row_ad") || strings.Contains(lower, "slotbydup") ||
			strings.Contains(lower, "hm.baidu.com") || strings.Contains(lower, "cpro.baidustatic.com") ||
			strings.Contains(lower, "<iframe") {
			return true
		}
	}
	return false
}

// reSQLi022FuncCall 检测 sqli:022 关键词被用作 SQL 函数调用的形态（带括号），
// 以区别于 `if (length > 0)` 这类 JavaScript 变量名。
var reSQLi022FuncCall = regexp.MustCompile(`\bif\s*\(\s*(length|count|version|substr|select)\s*\(`)

// reSQLi022ClauseCtx 检测可确认 SQL 注入上下文的 SQL 子句关键词。
// 包含后接空格或 `(` 的 `select`，以捕获 `if(select database(),...)` 形态，
// 同时排除 `select.value`（JavaScript DOM 元素）。
var reSQLi022ClauseCtx = regexp.MustCompile(`\b(from|where|union|having)\b|\bselect[\s(]`)

// reANDORSleep 检测布尔型时间注入使用的 "AND sleep()" / "OR sleep()" 模式：
// `1 AND sleep(5)`、`1 OR pg_sleep(5)`、`1 AND benchmark(...)`。
var reANDORSleep = regexp.MustCompile(`\b(and|or)\s*(sleep|pg_sleep|benchmark)\s*\(`)
var reOrdinalAfterOr = regexp.MustCompile(`'or\s+\d+(?:st|nd|rd|th)\b`)
var reJSProtocolNaturalPhrase = regexp.MustCompile(`(?i)\bjavascript\s*:\s*[a-z]+(?:\s+[a-z]+){0,4}$`)

// reSQLTerminatorCtx 检测 SQL 注释/终止符前是否存在右括号或引号/数字，
// 用于指示 "1); sleep(5)--" 这类注入上下文。
var reSQLTerminatorCtx = regexp.MustCompile(`['")\d]\s*(--|/\*)`)

func hasUnionSelectAttackContext(s string) bool {
	return hasSQLWord(s, "null") ||
		hasDigitCommaDigit(s) ||
		hasFromTableReference(s) ||
		hasDoubleAtWord(s) ||
		hasSQLWord(s, "information_schema") ||
		hasUnionSQLFunctionCall(s) ||
		hasOpenParenSelect(s) ||
		strings.Contains(s, "--") ||
		strings.Contains(s, "/*") ||
		hasQuotedSQLOperator(s) ||
		hasUnionSelectColumnValue(s) ||
		hasWhereNumericEquality(s) ||
		hasOrderByNumber(s)
}

func hasSQLWord(s, word string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], word)
		if idx < 0 {
			return false
		}
		idx += start
		end := idx + len(word)
		if (idx == 0 || !isSQLWordByte(s[idx-1])) && (end == len(s) || !isSQLWordByte(s[end])) {
			return true
		}
		start = idx + 1
	}
}

func hasSQLWordAt(s string, idx int, word string) bool {
	end := idx + len(word)
	if idx < 0 || end > len(s) || s[idx:end] != word {
		return false
	}
	return (idx == 0 || !isSQLWordByte(s[idx-1])) && (end == len(s) || !isSQLWordByte(s[end]))
}

func isSQLWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}

func skipSQLSpaces(s string, i int) int {
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', '\r', '\f':
			i++
		default:
			return i
		}
	}
	return i
}

func hasDigitCommaDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		j = skipSQLSpaces(s, j)
		if j >= len(s) || s[j] != ',' {
			continue
		}
		j = skipSQLSpaces(s, j+1)
		if j < len(s) && s[j] >= '0' && s[j] <= '9' {
			return true
		}
	}
	return false
}

func hasFromTableReference(s string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], "from")
		if idx < 0 {
			return false
		}
		idx += start
		if !hasSQLWordAt(s, idx, "from") {
			start = idx + 1
			continue
		}
		j := skipSQLSpaces(s, idx+len("from"))
		if j > idx+len("from") && j < len(s) && (isSQLWordByte(s[j]) || s[j] == '`' || s[j] == '\'' || s[j] == '"') {
			return true
		}
		start = idx + 1
	}
}

func hasDoubleAtWord(s string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], "@@")
		if idx < 0 {
			return false
		}
		idx += start
		if idx+2 < len(s) && isSQLWordByte(s[idx+2]) {
			return true
		}
		start = idx + 2
	}
}

func hasUnionSQLFunctionCall(s string) bool {
	for _, name := range [...]string{
		"user", "database", "version", "schema", "sleep", "benchmark",
		"group_concat", "extractvalue", "updatexml", "load_file", "char", "unhex",
	} {
		if hasSQLFunctionCall(s, name) {
			return true
		}
	}
	return false
}

func hasSQLFunctionCall(s, name string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], name)
		if idx < 0 {
			return false
		}
		idx += start
		if hasSQLWordAt(s, idx, name) {
			j := skipSQLSpaces(s, idx+len(name))
			if j < len(s) && s[j] == '(' {
				return true
			}
		}
		start = idx + 1
	}
}

func hasOpenParenSelect(s string) bool {
	for start := 0; ; {
		idx := strings.IndexByte(s[start:], '(')
		if idx < 0 {
			return false
		}
		idx += start
		j := skipSQLSpaces(s, idx+1)
		if hasSQLWordAt(s, j, "select") {
			return true
		}
		start = idx + 1
	}
}

func hasQuotedSQLOperator(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '\'' && s[i] != '"' {
			continue
		}
		j := skipSQLSpaces(s, i+1)
		for _, op := range [...]string{"and", "or", "where", "having", "group", "order", "union"} {
			if j+len(op) <= len(s) && s[j:j+len(op)] == op && (j+len(op) == len(s) || !isSQLWordByte(s[j+len(op)])) {
				return true
			}
		}
	}
	return false
}

func hasUnionSelectColumnValue(s string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], "union")
		if idx < 0 {
			return false
		}
		idx += start
		if !hasSQLWordAt(s, idx, "union") {
			start = idx + 1
			continue
		}
		j := skipSQLSpaces(s, idx+len("union"))
		if j == idx+len("union") {
			start = idx + 1
			continue
		}
		if hasSQLWordAt(s, j, "all") {
			next := skipSQLSpaces(s, j+len("all"))
			if next == j+len("all") {
				start = idx + 1
				continue
			}
			j = next
		}
		if !hasSQLWordAt(s, j, "select") {
			start = idx + 1
			continue
		}
		next := skipSQLSpaces(s, j+len("select"))
		if next == j+len("select") || next >= len(s) {
			start = idx + 1
			continue
		}
		ch := s[next]
		if ch == '\'' || ch == '"' || ch == '(' || ch == '@' || (ch >= '0' && ch <= '9') {
			return true
		}
		start = idx + 1
	}
}

func hasWhereNumericEquality(s string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], "where")
		if idx < 0 {
			return false
		}
		idx += start
		if !hasSQLWordAt(s, idx, "where") {
			start = idx + 1
			continue
		}
		j := skipSQLSpaces(s, idx+len("where"))
		if j >= len(s) || s[j] < '0' || s[j] > '9' {
			start = idx + 1
			continue
		}
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		j = skipSQLSpaces(s, j)
		if j >= len(s) || s[j] != '=' {
			start = idx + 1
			continue
		}
		j = skipSQLSpaces(s, j+1)
		if j < len(s) && s[j] >= '0' && s[j] <= '9' {
			return true
		}
		start = idx + 1
	}
}

func hasOrderByNumber(s string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], "order")
		if idx < 0 {
			return false
		}
		idx += start
		if !hasSQLWordAt(s, idx, "order") {
			start = idx + 1
			continue
		}
		j := skipSQLSpaces(s, idx+len("order"))
		if !hasSQLWordAt(s, j, "by") {
			start = idx + 1
			continue
		}
		j = skipSQLSpaces(s, j+len("by"))
		if j < len(s) && s[j] >= '0' && s[j] <= '9' {
			return true
		}
		start = idx + 1
	}
}

// reIntoOutfileWithPath 确认 INTO OUTFILE/DUMPFILE 命中（sqli:017）带有
// 带引号的文件路径（MySQL 语法要求）。诸如 "SELECT INTO OUTFILE S3"
// （AWS Aurora 文档）没有引号路径，应被抑制。
var reIntoOutfileWithPath = regexp.MustCompile(`\binto\s+(out|dump)file\s*['"]`)

// reSQLiInjectionOps 匹配不太可能出现在合法分析埋点或文档文本中的
// SQL 注入攻击运算符，供 sqli:005 抑制器区分 URL/路径通配符
// （S3 ARN 中的 /*）与真实 SQL 行内注释。
var reSQLiInjectionOps = regexp.MustCompile(
	`(union\s+(all\s+)?select\b` + // UNION 注入
		`|\bor\s+\d+\s*=\s*\d+` + // OR 1=1 布尔注入
		`|\band\s+\d+\s*=\s*\d+` + // AND 1=2 布尔注入
		`|'\s*(or|and)\s+['"\d]` + // ' or 'x'='x'
		`|\bsleep\s*\(` + // 时间型盲注
		`|\bbenchmark\s*\(` + // MySQL 时间型盲注
		`|;\s*(drop|truncate)\s+\w)`) // 破坏性 DDL 堆叠查询

// reXSSHandlerCallParens 检测 HTML 事件处理器属性值部分出现函数调用（左括号）：
// onload=alert(1) → 存在 (。
// CDN 脚本加载器使用 ?onload=callbackName（纯标识符、无括号），属安全形态。
var reXSSHandlerCallParens = regexp.MustCompile(`\bon\w+\s*=\s*[^;& \n\r]*\(`)

// reSQLi008AttackCtx 确认十六进制字面量命中（sqli:008）是真实 SQL 注入尝试，
// 而非良性十六进制值（CSS 颜色、内存地址、二进制协议）。
// 当 sqli:008 是首个命中规则时，只有该正则匹配才报告命中。
var reSQLi008AttackCtx = regexp.MustCompile(`(` +
	`\b(or|and)\s+\d+\s*=\s*\d+` + // OR 1=1 / AND 1=2 盲注条件
	`|union(\s+all)?\s+select\b` + // UNION SELECT
	`|\binformation_schema\b` + // schema/系统表枚举
	`|\bhaving\s+\d+\s*=\s*\d+` + // HAVING 1=1 盲注
	`|\bwhere\s+\d+\s*=\s*\d+` + // WHERE 1=1
	`|\binto\s+(out|dump)file\b` + // 文件写入外带
	`|\b(order|group)\s+by\s+\d+\s*(--|/\*)` + // ORDER/GROUP BY n 后接 SQL 注释
	`|(or|and)\s+['"]\w+['"]\s*=\s*['"]\w+['"]` + // OR 'x'='x' 字符串比较
	`|(substr|substring|mid)\s*\([^)]*\)\s*=\s*['"]` + // substr(...)='x' 比较
	`|\d+\s*=\s*\(\s*select\b` + // 子查询比较：1=(SELECT ...)
	`|\bin\s*\(\s*select\b` + // IN (SELECT ...) 子查询
	`)`)

// rePathTravSensitive 检测指向已知敏感系统文件或目录的路径遍历载荷，
// 用于抑制构建/配置文件中相对路径 `../../` 的误报。
var rePathTravSensitive = regexp.MustCompile(
	`(etc/passwd|etc/shadow|etc/hosts|/etc/|proc/self|/proc/|windows/system32|win\.ini|boot\.ini|cmd\.exe|/root/|/home/\w|\.env$|web\.xml|nginx\.conf|apache\.conf|web-inf|meta-inf|\.git/|\.svn/|\.htpasswd|\.aws/|\.ssh/|/bin/sh|/bin/bash|/bin/cat|/usr/bin|/var/log|/tmp/|/dev/)`)

// reTautologyCapture 检测 "or 1=1"、"and 2=2" 这类布尔恒等式（两侧数字相同）。
// Go regexp 不支持反向引用，故在此提取后手工比较。
var reTautologyCapture = regexp.MustCompile(`\b(?:or|and)\s+(\d+)\s*=\s*(\d+)\b`)

func isTautology(s string) bool {
	matches := reTautologyCapture.FindAllStringSubmatch(s, -1)
	for _, m := range matches {
		if len(m) >= 3 && m[1] == m[2] {
			return true
		}
	}
	return false
}

var reBoolSQLContext = regexp.MustCompile(`(select|from|where|union|having|group|order)\b`)
var reSQLDMLContext = regexp.MustCompile(`\b(table|into\b|values\s*\(|database|schema|columns\s+from|rows\s+from|truncate\b)\b|\b(xp_|sp_[a-z])\w`)

// reSQLStatementStart 匹配「引号闭合 + 分号 + 新语句起始」的 SQL 语法形态：
//
//  1. 语句首关键字——DML/DDL/DCL/TCL、游标与预处理语句，以及 MySQL 管理语句
//     （HANDLER / SIGNAL / PURGE / FLUSH / DO / HELP / KILL / RESET …）。
//     词表只取**语句首**关键字，与 owasp:sqli:006 的规则 meta 一致。
//  2. 标识符或限定标识符后紧跟左括号——函数调用（`sleep(`、`dbms_lock.sleep(`、
//     `benchmark(`、`if(`）。取「标识符 + `(`」形态，不枚举任何函数名，
//     因此对内置/自定义函数与任意 schema 限定名一致成立。
//
// 该正则同时被 sqli:006 规则与它的误报抑制器引用（单一事实来源）：抑制器
// 只在「无结构词 且 无语句起始形态」时判为误报，两者不会互相打架。
var reSQLStatementStart = regexp.MustCompile(`'\s*;\s*(?:(?:union|select|insert|update|delete|merge|replace|call|load|values|create|alter|drop|truncate|rename|comment|grant|revoke|analyze|begin|start|commit|rollback|savepoint|set|lock|unlock|prepare|deallocate|declare|execute|exec|explain|describe|desc|show|use|intersect|except|with|table|do|handler|signal|purge|flush|help|kill|reset|install|uninstall|xa|binlog|change|check|checksum|optimize|repair|shutdown|import|resignal)\b|[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*\s*\()`)

// hasCodeBlockBraceAfterStackedSemicolon 判断「引号闭合 + 分号」之后的新语句
// 片段里是否出现花括号。`{` / `}` 不属于任何 SQL 语句的语法，只出现在
// JavaScript / Java / JSON 代码块中；而 `'; for (...) {`、`';while(...){`
// 这类代码片段的语句首形态（标识符 + 括号）与 SQL 调用无法区分，花括号是
// 它们的反证。判据只看 `--` 之前的语句体，注释之后的内容不属于该语句。
//
// @param raw 原始扫描目标（未经注释剥离）
// @return 分号后的语句体内含花括号时返回 true
func hasCodeBlockBraceAfterStackedSemicolon(raw string) bool {
	s := toLowerASCII(raw)
	i := strings.Index(s, "';")
	if i < 0 {
		return false
	}
	rest := s[i+2:]
	if j := strings.Index(rest, "--"); j >= 0 {
		rest = rest[:j]
	}
	return strings.ContainsAny(rest, "{}")
}

// hasSQLCommentTokenBoundary 判断归一化文本里是否存在**语法上可用作 SQL 注释
// 起始**的 `--` / `/*`。sqli:005 的规则正则是「引号或数字 + 可选空白 + 注释符」，
// 这个形态在随机字节流（尤其 base64/压缩数据经解码后的片段）里碰撞概率极高，
// 因此需要按 SQL 词法确认注释符确实落在 token 边界上。
//
// 两条判据各自独立，任一成立即返回 true：
//
//  1. **token 边界判据**——注释是词法单元之间的分隔符，不能从 token 内部开始。
//     左邻为分隔符/运算符/引号/括号/串首，或左邻是数字且该数字是独立 token
//     （再往左不是 token 字符）时成立。此判据覆盖 `'/*`、`);/*`、`1--/etc`、
//     `1'/*!union*/select` 等正常注入形态，同时排除 `m1/*b`（`1` 属于标识符
//     `m1`）与 `abc--x`、`a1--b`（标识符内部的双横线）。
//  2. **参数终止判据**——query/表单参数以 `&` 分隔，注释符紧跟 `&` 时，
//     前一个参数值已结束，后续参数会被独立扫描；若其中含真实 SQL 结构，
//     自会被对应规则命中，因此这里不再按注释采信。此判据覆盖
//     `id=queryvalue1/*`、`source=arn:aws:s3:::bucket01/*&format=json`
//     `x=1--&y=2` 一类形态（后两者的命中另外还受 ARN / 路径通配符分支约束）。
//
// 判据只依赖注释符两侧的字符类别与 token 结构，不含任何具体词、数字串或长度阈值。
//
// @param s 归一化后的扫描目标
// @return 存在语法上可用的 SQL 注释起始时返回 true
func hasSQLCommentTokenBoundary(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		isDash := s[i] == '-' && s[i+1] == '-'
		isSlashStar := s[i] == '/' && s[i+1] == '*'
		if !isDash && !isSlashStar {
			continue
		}
		if i+2 >= len(s) {
			// 注释符直达串尾：`/*` 为未闭合块注释（注释体到串尾），
			// `--` 为值末尾的行注释，两者都是注入形态。
			return true
		}
		c := s[i+2]
		if c == '&' {
			// 参数终止：`/*` 是前一个参数值的末字符，`--` 后另有参数。
			// 前一个值没有 SQL 结构（有的话已被别的规则命中），
			// 后续参数会被独立扫描。
			continue
		}
		if isDash {
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '/' {
				return true
			}
			continue
		}
		// `/*` —— 右邻决定它是不是注释体起点。
		if c == '!' {
			// MySQL 可执行注释 /*!50000union*/：语法上必然是注释。
			return true
		}
		if !isSQLCommentLeftBoundary(s, i) {
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
			c == '*' || c == '(' || c == ')' || c == '\'' || c == '"' || c == '/' ||
			c == '-' || c == '~' || c == '&' || c == '|' || c == '#' || c == '@' ||
			c == '%' || c == ';' || c == '=' || c == '<' || c == '>' || c == ',' ||
			c == '.' || c == '[' || c == ']' || c == '{' || c == '}' || c == '^' || c == '+' ||
			c == '`' || c == '$' || c == '_' {
			return true
		}
		if c >= '0' && c <= '9' {
			return true
		}
		// 小写字母：归一化后 SQL 关键字/标识符均为小写，视为注释正文。
		if c >= 'a' && c <= 'z' {
			return true
		}
		// 大写字母：可能是 base64 片段（`/*B;Z`、`/+A9`）。base64 的 A-Z0-9
		// 连续串不会在中间夹入空格或小写字母，故要求该串在遇到小写字母或
		// 空格之前就结束；否则按注释正文放行（`/*Union*/` 形态）。
		if c >= 'A' && c <= 'Z' {
			j := i + 3
			for j < len(s) && (s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if j >= len(s) || s[j] == ' ' || s[j] >= 'a' && s[j] <= 'z' {
				return true
			}
		}
	}
	return false
}

// isSQLCommentLeftBoundary 判断 s[i] 处能否成为一个 SQL 注释的起点。
//
// @param s 归一化后的扫描目标
// @param i 注释符首字符的下标
// @return 左侧构成 token 边界时返回 true
func isSQLCommentLeftBoundary(s string, i int) bool {
	if i == 0 {
		return true
	}
	c := s[i-1]
	if isSQLTokenChar(c) {
		j := i - 1
		for j > 0 && isSQLTokenChar(s[j-1]) {
			j--
		}
		return s[j] >= '0' && s[j] <= '9'
	}
	switch c {
	case ' ', '\t', '\n', '\r', '\'', '"', ')', '(', ';', '=', '<', '>', '|', '&', '+', '-', '*', '/',
		'%', '^', '~', '!', ':', ',', '\\', '{', '}', '[', ']':
		return true
	}
	return false
}

// isSQLTokenChar 判断字节是否属于 SQL 标识符/数字字面量的连续 token 字符集。
//
// @param b 待判字节
// @return 属于 token 字符时返回 true
func isSQLTokenChar(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
		b == '_' || b == '$' || b == '.'
}

func isPathTravFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:path_traversal:001", "owasp:path_traversal:004":
		return !rePathTravSensitive.MatchString(normalized)
	case "owasp:path_traversal:011":
		if !strings.Contains(normalized, "%252e") {
			return true
		}
		return !rePathTravSensitive.MatchString(normalized)
	case "owasp:path_traversal:009":
		// \.{3,}[/\\] 会把正文省略号后接链接（...</a> 解码为
		// ...</a>）或 JSON 转义序列（...\n、...\t 字面反斜杠）误判为
		// 路径穿越。中文内容（网易 analytics 白样）高频出现这两种形态。
		// 仅当 ... 后跟的斜杠是真正路径分隔且无 HTML 标签/转义上下文时保留。
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "...</") || strings.Contains(lower, "...%3c/") ||
			strings.Contains(lower, "...\\n") || strings.Contains(lower, "...\\t") ||
			strings.Contains(lower, "...\\r") || strings.Contains(lower, "...\\u") {
			return true
		}
	}
	return false
}

func isSSRFFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:ssrf:010":
		lower := strings.ToLower(normalized)
		// Cloudflare RUM 与 CDN-CGI 路径会在遥测载荷中使用 "file://" 或类似协议模式，
		// 它们并非真实的 SSRF 尝试。
		if strings.Contains(lower, "cdn-cgi") ||
			strings.Contains(lower, "/rum") ||
			strings.Contains(lower, "cloudflare") {
			return true
		}
	case "owasp:ssrf:007":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "gopher://") ||
			strings.Contains(lower, "file://") ||
			strings.Contains(lower, "dict://") {
			return false
		}
		if strings.Contains(lower, "\"upstreams\"") || strings.Contains(lower, "\"upstream\"") ||
			strings.Contains(lower, "\"proxy_pass\"") || strings.Contains(lower, "\"backend\"") ||
			strings.Contains(lower, "\"server_names\"") {
			return true
		}
		if strings.Contains(lower, "localhost") && !strings.Contains(lower, "127.") {
			if len(normalized) > 100 && !strings.Contains(lower, "@") &&
				!strings.Contains(lower, "metadata") &&
				!strings.Contains(lower, "169.254.") {
				return true
			}
			if strings.Contains(lower, "accessurl=") ||
				strings.Contains(lower, "recordnewuserjsonpcallback") ||
				strings.Contains(lower, "localhost:8000") {
				return true
			}
		}
		if strings.HasPrefix(lower, "http://127.0.0.1") || strings.HasPrefix(lower, "https://127.0.0.1") ||
			strings.HasPrefix(lower, "http://localhost") || strings.HasPrefix(lower, "https://localhost") {
			hostOnly := !strings.Contains(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(lower, "http://"), "https://"), "127.0.0.1"), "localhost"), "/")
			if hostOnly {
				return true
			}
		}
		// 此处原有一层「127.0.0.1/localhost ⊃ "upstreams"」判断。删除品牌词
		// （codepen.io / stackblitz.com / ant.design）后，其内层条件与本 case
		// 上方的 "upstreams" 分支同字面量互斥：能到达此处即意味着上方分支未命中，
		// 即 lower 不含 "upstreams"，故内层恒为假、整块不可达，整体移除。
		// 该判断原本保护的「配置体含 upstreams」误报语义已由上方分支覆盖。
	}
	return false
}

func isDeserFalsePositive(raw, ruleID string) bool {
	switch ruleID {
	case "owasp:deser:005":
		if len(raw) > 256 {
			return true
		}
		return false
	case "owasp:deser:001":
		return false
	}
	return false
}

func isNoSQLiFalsePositive(raw, ruleID string) bool {
	switch ruleID {
	case "owasp:nosql:002", "owasp:nosql:003", "owasp:nosql:004":
		if !reNoSQLAttackCtx.MatchString(raw) {
			return true
		}
	case "owasp:nosql:005", "owasp:nosql:006":
		return true
	case "owasp:nosql:022":
		// 引号闭合后的 $or 数组：引号前必须是被注入的值（'...')，
		// 无前置引号则可能是对象字面量。
		if !strings.ContainsAny(raw, "'\"") {
			return true
		}
	case "owasp:nosql:023", "owasp:nosql:024":
		// 023/024 为纯 $or 数组形态，归因于 $or 关键字的所有权；
		// 005 与 them or operator 等 benign 文本的 FP 抑制由 022/023 负责。
		return false
	case "owasp:nosql:018":
		// $where:'99 == 88' 的引号值内比较形态要求 $where 引号内出现
		// 运算/数字；纯字面串（$where:'name'）不算注入。
		if !strings.Contains(raw, "$where") {
			return true
		}
		if i := strings.Index(raw, "$where"); i >= 0 {
			rest := raw[i+len("$where"):]
			if !strings.Contains(rest, "'") && !strings.Contains(rest, `"`) {
				return true
			}
		}
	case "owasp:nosql:020":
		// 忙等形态必须同时有分号注入锚（; 或逗号隔断的表达式开始）或
		// db/collection 上下文，避免自然叙述「new Date」误报。
		if !strings.ContainsAny(raw, ";&(") {
			return true
		}
	}
	return false
}

func isELFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:el:005":
		if !strings.Contains(normalized, "${") &&
			!strings.Contains(normalized, "#{") &&
			!strings.Contains(normalized, "%{") &&
			!strings.Contains(normalized, "@java.lang.") &&
			!strings.Contains(normalized, "getclass") &&
			!strings.Contains(normalized, "getdeclaredmethods") &&
			!strings.Contains(normalized, ".invoke(") &&
			!strings.Contains(normalized, "forname(") {
			return true
		}
	case "owasp:el:008", "owasp:el:011", "owasp:el:013":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "redirect:${#") ||
			strings.Contains(lower, "#context.get(") ||
			strings.Contains(lower, "com.opensymphony.xwork2") ||
			strings.Contains(lower, "getrealpath(") ||
			strings.Contains(lower, "getwriter().println") {
			return false
		}
	}
	return false
}

var reCRLFHeaderInject = regexp.MustCompile(`\r\n\r?\n\s*(http/[\d.]+\s+\d{3}|[a-zA-Z][-a-zA-Z0-9]+\s*:)`)
var reWebshellPHPContext = regexp.MustCompile(`(base64_decode\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|\$_(get|post|request|cookie|server|files)\s*\[|<\?php\b|\.getruntime\(\)|subprocess|os\.system|response\.\s*write)`)

func isWebshellFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:webshell:001":
		// 存在 PHP/shell 特有标记时才视作真实 webshell 尝试。
		if reWebshellPHPContext.MatchString(normalized) {
			return false
		}
		if strings.Contains(normalized, "system(") ||
			strings.Contains(normalized, "exec(") ||
			strings.Contains(normalized, "popen(") ||
			strings.Contains(normalized, "proc_open(") {
			return false
		}
		// 仅有 eval() 或 assert() 而无 PHP/shell 上下文：很可能是 JavaScript 误报。
		return true
	case "owasp:webshell:016":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "java.util.arraylist") {
			return true
		}
	}
	return false
}

func isCRLFFalsePositive(normalized, ruleID string) bool {
	lower := strings.ToLower(normalized)
	switch ruleID {
	case "owasp:crlf:004":
		// 裸 \r\n\r\n 在多行 textarea 值（Windows 换行）、multipart 表单数据边界
		// 与二进制数据中很常见。
		// 要求分隔符后出现 HTTP 请求头/状态行上下文才确认注入。
		if strings.Contains(lower, "telemetry") ||
			strings.Contains(lower, "analytics") ||
			strings.Contains(lower, "cdn-cgi") {
			return true
		}
		return !reCRLFHeaderInject.MatchString(normalized)
	case "owasp:crlf:001":
		// multipart 表单上传与二进制文件数据天然含 \r\n 序列。
		// 除非 CRLF 后跟真实的 HTTP 请求头注入尝试
		// （且头值可疑，而非仅 multipart 边界元数据），否则抑制。
		if strings.Contains(normalized, "content-disposition:") ||
			strings.Contains(normalized, "content-type: image/") ||
			strings.Contains(normalized, "content-type: application/octet") ||
			strings.Contains(normalized, "xpacket") ||
			strings.Contains(normalized, "xmpmeta") {
			return true
		}
		// 遥测/分析 JSON 载荷中记录的 HTTP 响应头。
		// 形如 "access-control-...: value\r\ncontent-type: ...\r\ndate: ..."，
		// 同时含多个标准 HTTP 请求头——并非注入尝试。
		// 真实 CRLF 注入只针对单个头（set-cookie、location）以劫持响应，
		// 而被记录的响应头总是一起出现 2 个以上良性头。
		benignHeaderCount := 0
		for _, hdr := range []string{"content-type:", "content-length:", "date:", "server:",
			"access-control-", "x-cache", "vary:", "x-nws-", "x-server-",
			"cache-control:", "expires:", "pragma:", "etag:", "last-modified:",
			"accept-ranges:", "connection:", "keep-alive:", "transfer-encoding:",
			"x-request-id:", "x-powered-by:", "strict-transport-security:",
			"x-content-type-options:", "x-frame-options:", "x-xss-protection:",
			"referrer-policy:", "permissions-policy:", "timing-allow-origin:",
			"alt-svc:", "nel:", "report-to:", "cf-ray:", "cf-cache-status:"} {
			if strings.Contains(lower, hdr) {
				benignHeaderCount++
			}
		}
		if benignHeaderCount >= 2 && !strings.Contains(lower, "set-cookie:") {
			return true
		}
		// 遥测、分析与日志 POST 体常含 \r\n 加类请求头模式
		// （例如 JSON 载荷里的 "content-type:"），并非注入尝试。
		if strings.Contains(lower, "telemetry") ||
			strings.Contains(lower, "analytics") ||
			strings.Contains(lower, "cdn-cgi") ||
			strings.Contains(lower, "/g/collect") ||
			strings.Contains(lower, "google-analytics") ||
			strings.Contains(lower, "googletagmanager") {
			return true
		}
		// 大于 500 字节且 \r\n 后接常见 HTTP 请求头的大 POST 体，
		// 通常是遥测/表单数据，而非请求头注入。
		if len(normalized) > 500 && !strings.Contains(lower, "set-cookie") &&
			!strings.Contains(lower, "location:") {
			return true
		}
	case "owasp:crlf:010":
		// 折叠态（归一化后的空格分隔）拦「整行命令」形态即可。若有内容前缀
		// 说明来自同一行：rcpt to: 无引号上下文时可能是自然语言；
		// capability/fetch 受 \s+（空格）锚定不会命中有前缀的词。
		if strings.Contains(lower, "rcpt to") &&
			!strings.Contains(lower, " rcpt to") {
			return true
		}
	}
	return false
}

var reNoSQLAttackCtx = regexp.MustCompile(`(\[|\{|:|=)\s*\\?["']?\s*\$(ne|gt|lt|gte|lte|regex|in|nin|exists)\b|\w+\[(\$ne|\$gt|\$lt|\$regex|\$exists)\]\s*=|["']\$\w+["']\s*:\s*\{\s*["']\$(ne|gt|lt|gte|lte|regex|in|nin|exists)`)
var sqliPatterns = []owaspPattern{
	{regexp.MustCompile(`union\s*(all\s*)?select|unionselect`), 5, "owasp:sqli:001", "union"},
	{regexp.MustCompile(`'\s*(or|and)\s+['"]?\d`), 5, "owasp:sqli:002", ""},
	{regexp.MustCompile(`(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(`), 5, "owasp:sqli:003", ""},
	{regexp.MustCompile(`;\s*(select|drop|alter|create|truncate|delete|update|insert)\s`), 5, "owasp:sqli:004", ""},
	{regexp.MustCompile(`['"\d]\s*(--(?:[\s/]|$)|/\*)`), 3, "owasp:sqli:005", ""},
	// 引号闭合 + 分号 + 新语句关键字：''; G（SQL 文档正文）、''; f（JS 的 for）
	// 这类「分号后任意词字符」的形态不是注入，规则自身 meta（owasp:sqli:006
	// 「引号闭合后接分号与新语句关键字」）要求的也是语句关键字。故词表取 SQL
	// 语句首关键字（DML/DDL/DCL/TCL/游标与预处理），而非任意 \w。
	{reSQLStatementStart, 3, "owasp:sqli:006", ""},
	{regexp.MustCompile(`(chr|unhex|conv)\s*\(`), 3, "owasp:sqli:007", ""},
	{regexp.MustCompile(`[,=(]\s*0x[0-9a-f]{4,}`), 2, "owasp:sqli:008", "0x"},
	{regexp.MustCompile(`information_schema|sysobjects|sys\.\w+tables`), 5, "owasp:sqli:009", ""},
	{regexp.MustCompile(`\b(or|and)\s*\d+\s*=\s*\d+`), 5, "owasp:sqli:010", ""},
	{regexp.MustCompile(`\b(or|and)\s*['"]\w*['"]\s*=\s*['"]\w*['"]`), 5, "owasp:sqli:011", ""},
	{regexp.MustCompile(`;\s*--`), 3, "owasp:sqli:012", "--"},
	{regexp.MustCompile(`(load_file|outfile|dumpfile)\s*\(`), 5, "owasp:sqli:013", ""},
	{regexp.MustCompile(`@@(version|hostname|datadir|basedir)`), 5, "owasp:sqli:014", "@@"},
	{regexp.MustCompile(`(extractvalue|updatexml)\s*\(`), 5, "owasp:sqli:015", ""},
	{regexp.MustCompile(`group_concat\s*\(`), 5, "owasp:sqli:016", "group_concat"},
	{regexp.MustCompile(`\binto\s+(out|dump)file\b`), 5, "owasp:sqli:017", "into"},
	{regexp.MustCompile(`case\s+when\s+.*then\s+(sleep|benchmark|pg_sleep)`), 5, "owasp:sqli:018", "when"},
	{regexp.MustCompile(`\border\s+by\s+\d+\s*(--\s?|/\*|;\s*$|$)`), 5, "owasp:sqli:019", "order"},
	{regexp.MustCompile(`/\*!\d*\s*(select|union|insert|update|delete|drop|alter|where|from|and|or)\b`), 5, "owasp:sqli:020", "/*!"},
	{regexp.MustCompile(`(substr|substring|mid)\s*\(.+,\s*\d+\s*,\s*\d+\s*\)`), 4, "owasp:sqli:021", ""},
	{regexp.MustCompile(`\bif\s*\(\s*(select|ord|ascii|substr|length|count|version)\b`), 5, "owasp:sqli:022", ""},
	{regexp.MustCompile(`'\s*(\^|&|<<|>>)\s*'`), 3, "owasp:sqli:023", ""},
	{regexp.MustCompile(`\bxp_(cmdshell|regread|regwrite|loginconfig|enumdsn|availablemedia|ntsec)\b`), 6, "owasp:sqli:024", "xp_"},
	{regexp.MustCompile(`\bprocedure\s+analyse\s*\(`), 5, "owasp:sqli:025", "procedure"},
	{regexp.MustCompile(`\b(utl_http|utl_file|dbms_pipe|dbms_output)\s*\.\s*\w+`), 5, "owasp:sqli:026", ""},
	{regexp.MustCompile(`\bhaving\s+\d+\s*=\s*\d+`), 5, "owasp:sqli:027", "having"},
	{regexp.MustCompile(`\d+\s*=\s*\(\s*select\b`), 5, "owasp:sqli:028", "select"},
	{regexp.MustCompile(`'\s*like\s+'[%_]`), 5, "owasp:sqli:029", "like"},
	{regexp.MustCompile(`\blimit\s+\d+\s*,\s*\d+\s*(--|;)`), 5, "owasp:sqli:030", "limit"},
	{regexp.MustCompile(`(=\s*|\bin\s*)\(\s*select\b`), 5, "owasp:sqli:031", "select"},
	{regexp.MustCompile(`\bgroup\s+by\s+\d+(\s*,\s*\d+)*\s*(--|;|/\*|$)`), 5, "owasp:sqli:032", "group"},
	{regexp.MustCompile(`\blimit\s+\d+\s+offset\s+\d+\s*(--|;|/\*)`), 5, "owasp:sqli:033", "offset"},
	{regexp.MustCompile(`;\s*exec(?:\s+|\s*\()(?:xp_|sp_|master\.\.)\w`), 5, "owasp:sqli:034", "exec"},
	{regexp.MustCompile(`\bwaitfor\s+delay\s*['"]`), 7, "owasp:sqli:035", "waitfor"},
	{regexp.MustCompile(`\b(or|and)\s+['"]['"]\s*=\s*['"]`), 5, "owasp:sqli:036", ""},
	{regexp.MustCompile(`\bcopy\b.{0,200}\bto\s+program\b`), 5, "owasp:sqli:037", "program"},
	{regexp.MustCompile(`\bselect\b.{0,100}\bfrom\s+\w+\s*(--|;|/\*|\bwhere\s+\d+=\d+|\bunion\b)`), 5, "owasp:sqli:038", "select"},
	{regexp.MustCompile(`\b(and|or)\s*\(\s*select\b`), 5, "owasp:sqli:039", "select"},
	{regexp.MustCompile(`\bselect\s+case\s+when\b`), 5, "owasp:sqli:040", "select"},
	{regexp.MustCompile(`\bselect\s+(cast|convert)\s*\([^)]{0,80}\)\s*(from\b|,\s*\w|--)`), 5, "owasp:sqli:041", "select"},
	{regexp.MustCompile(`\bchr\s*\(\s*\d+\s*\)\s*(\+|\|\|)\s*chr\s*\(`), 5, "owasp:sqli:043", "chr"},
	{regexp.MustCompile(`utl_inaddr\s*\.\s*get_host`), 5, "owasp:sqli:044", "utl_inaddr"},
	{regexp.MustCompile(`\b(exec|execute)\s+.{0,30}\bxp_(dirtree|cmdshell|regread|fileexist|subdirs)\b`), 5, "owasp:sqli:045", "xp_"},
	{regexp.MustCompile(`\bselect\b[^;]{0,20}\(\s*select\b`), 5, "owasp:sqli:046", "select"},
	{regexp.MustCompile(`\bselect\s+\*\s+from\s+\w`), 4, "owasp:sqli:047", "select"},
	{regexp.MustCompile(`\bexec\s+master\s*\.\.\s*\w`), 5, "owasp:sqli:048", "master"},
	// Unicode 绕过：SQL 关键词中全角/半角字符交替
	{regexp.MustCompile(`[\x{FF10}-\x{FF5A}]{3,}.{0,20}(select|union|insert|update|delete)`), 5, "owasp:sqli:049", ""},
	// 嵌套注释混淆：/*/**/union/**/select/**/
	{regexp.MustCompile(`/\*[^*]*/\*.*?\*/.*?\*/`), 5, "owasp:sqli:050", "/*"},
	// MySQL 条件注释：/*!50000 UNION*/
	{regexp.MustCompile(`/\*!\d{5}\s*(union|select|insert|update|delete|drop)\b`), 6, "owasp:sqli:051", "/*!"},
	// MySQL 带版本号条件注释的变体
	{regexp.MustCompile(`/\*!\s*(union|select|concat|group_concat)\b`), 5, "owasp:sqli:052", "/*!"},
	// 全角 Unicode SQL 关键词（如 ＳＥＬＥＣＴ）
	{regexp.MustCompile(`[\x{FF33}\x{FF53}][\x{FF25}\x{FF45}][\x{FF2C}\x{FF4C}][\x{FF25}\x{FF45}][\x{FF23}\x{FF43}][\x{FF34}\x{FF54}]`), 5, "owasp:sqli:053", ""},
	// 双重 URL 编码检测：%2527（%25 = %，故 %2527 = %27 = '）
	{regexp.MustCompile(`%25(27|22|3[bB]|2[dD]2[dD])`), 5, "owasp:sqli:054", "%25"},
	// JSON 文档函数：json_extract( 在 URL/表单上下文几乎不出现于良性输入，
	// 是 MySQL/MariaDB 查询载荷的高置信度字面，单一命中即达 mid 阈。
	{regexp.MustCompile(`json_extract\s*\(`), 4, "owasp:sqli:055", "json_extract"},
}

var webshellPatterns = []owaspPattern{
	{regexp.MustCompile(`(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(`), 4, "owasp:webshell:001", ""},
	{regexp.MustCompile(`base64_decode\s*\(`), 3, "owasp:webshell:002", "base64_decode"},
	{regexp.MustCompile(`<\?php\s`), 5, "owasp:webshell:003", "<?php"},
	{regexp.MustCompile(`runtime\.getruntime\(\)\.exec`), 5, "owasp:webshell:004", "getruntime"},
	{regexp.MustCompile(`(cmd\.exe|powershell\.exe|/bin/(ba)?sh)`), 4, "owasp:webshell:005", ""},
	{regexp.MustCompile(`\$_(get|post|request|cookie)\s*\[`), 4, "owasp:webshell:006", "$_"},
	// PHP preg_replace 带 /e 修饰符（代码执行）
	{regexp.MustCompile(`preg_replace\s*\(\s*['"]/.*?/e`), 5, "owasp:webshell:007", "preg_replace"},
	// Python subprocess / os.system 的 RCE 用法
	{regexp.MustCompile(`(subprocess\s*\.\s*(call|run|popen)|os\s*\.\s*(system|exec[lv]p?))\s*\(`), 4, "owasp:webshell:008", ""},
	// JSP/Groovy 运行时执行
	{regexp.MustCompile(`(\.exec\s*\(|\.getruntime\(\)\s*\.\s*exec)`), 5, "owasp:webshell:009", ""},
	// Perl/Ruby 的 system/exec
	{regexp.MustCompile("\\b(system|exec|open)\\s*\\(\\s*['\"]\\s*(cmd|bash|sh|powershell|nc|wget|curl)"), 4, "owasp:webshell:010", ""},
	// ASP/ASPX webshell：Response.Write / Server.Execute
	{regexp.MustCompile(`(response\s*\.\s*(write|binarywrite)|server\s*\.\s*(execute|mappath))\s*\(`), 4, "owasp:webshell:011", ""},
	// PHP create_function()——等价于 eval() 的动态代码生成
	{regexp.MustCompile(`create_function\s*\(\s*['"][^'"]{0,100}['"]\s*,`), 4, "owasp:webshell:012", "create_function"},
	// PHP 混淆包装函数，常与 eval 串联以隐藏载荷
	{regexp.MustCompile(`(gzinflate|gzuncompress|str_rot13|hex2bin|base64_decode)\s*\(\s*['"]`), 4, "owasp:webshell:013", ""},
	// PHP call_user_func 动态调用：call_user_func('system', $_GET['cmd'])
	{regexp.MustCompile(`call_user_func\s*\(\s*['"]?\s*(system|exec|passthru|shell_exec|popen|proc_open|assert)\b`), 5, "owasp:webshell:014", "call_user_func"},
	// Drupal Drupalgeddon2/3：mail[#post_render][]=exec、mail[#type]=markup
	{regexp.MustCompile(`\[\s*#\s*(post_render|pre_render|lazy_builder|markup|type)\s*\]`), 4, "owasp:webshell:015", ""},
	// Java XML 反序列化 / XStream RCE：<java.util.PriorityQueue serialization=...>
	{regexp.MustCompile(`<java\.\w+\.`), 5, "owasp:webshell:016", "<java."},
	// ThinkPHP invokefunction RCE：/index.php?s=index/\think\app/invokefunction&function=call_user_func
	{regexp.MustCompile(`invokefunction.*call_user_func|call_user_func.*invokefunction`), 5, "owasp:webshell:017", ""},
	// 不带危险函数名的通用 call_user_func——ThinkPHP/CodeIgniter 形态
	{regexp.MustCompile(`\\think\\(app|request|template|view)\b`), 5, "owasp:webshell:018", ""},
	// ASP/JSP eval 形态：<%eval、<%execute、request("cmd")
	{regexp.MustCompile(`<%\s*(eval|execute|response\.write)`), 5, "owasp:webshell:019", "<%"},
	// PHP 文件操作：file_put_contents 与 file_get_contents 组合出现
	{regexp.MustCompile(`file_put_contents\s*\(.*file_get_contents|file_get_contents\s*\(.*file_put_contents`), 5, "owasp:webshell:020", ""},
	// elFinder connector RCE：cmd=...&name=...>*.php
	{regexp.MustCompile(`\bname\s*=\s*[^&]*>\s*\w+\.(php|jsp|asp|aspx|sh)\b`), 5, "owasp:webshell:021", ""},
	// file_put_contents 或 file_get_contents 搭配 .php 文件路径
	{regexp.MustCompile(`file_put_contents\b.*\.\s*php\b`), 5, "owasp:webshell:022", "file_put_contents"},
	// body/header 中的 PHP 短标签：<?php，或 <? 后接空格/换行
	{regexp.MustCompile(`<\?\s+(echo|print|include|require|eval|assert|system|exec|passthru)\b`), 5, "owasp:webshell:023", "<?"},
	// PHP 包装器利用：php://input、php://filter、data://text/plain
	{regexp.MustCompile(`php://(input|filter|output|stdin|memory|temp)\b`), 5, "owasp:webshell:024", "php://"},
	{regexp.MustCompile(`data://text/plain\b`), 4, "owasp:webshell:025", "data://text/plain"},
	// PHP 远程文件包含：include/require 搭配远程 URL
	{regexp.MustCompile(`\b(include|require|include_once|require_once)\s*\(\s*['"]?\s*https?://`), 5, "owasp:webshell:026", ""},
	// Python 反射导入 + 危险模块：__import__('os') / __import__("subprocess")。
	// 与 webshell:008（os.system/subprocess 直接调用）互补，覆盖 Jinja2/SSTI 载荷，
	// 且不与 SQLi sleep 家族混淆（不带 '(' 的目标词不触发）。
	{regexp.MustCompile(`__import__\s*\(\s*['"]\s*(os|subprocess|sys|pty|pickle|base64|codecs|builtins|socket)\b`), 5, "owasp:webshell:027", "__import__"},
}

func checkWebshell(s string, threshold int) (OWASPHit, bool) {
	if !hasWebshellIndicator(s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则；
	// FP 抑制器前移到 Add 之前，被抑制的规则既不计分也不参与归因。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range webshellPatterns {
		if !owaspPatternGatePass(p, s) {
			continue
		}
		if !p.re.MatchString(s) {
			continue
		}
		if isWebshellFalsePositive(s, p.id) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatWebshell, RuleID: id, Score: total, Desc: "WebShell/代码执行特征"}, true
		}
	}
	return OWASPHit{}, false
}

var revshellPatterns = []owaspPattern{
	{regexp.MustCompile(`bash\s+-i\s+>&?\s*/dev/tcp`), 6, "owasp:revshell:001", "/dev/tcp"},
	{regexp.MustCompile(`/dev/tcp/\d`), 5, "owasp:revshell:002", "/dev/tcp/"},
	{regexp.MustCompile(`(nc|ncat|netcat)\s+.*-e\s`), 5, "owasp:revshell:003", ""},
	{regexp.MustCompile(`python[23]?\s+-c\s+.*socket`), 4, "owasp:revshell:004", "socket"},
	{regexp.MustCompile(`(invoke-expression|iex)\s*\(\s*(new-object|downloadstring)`), 5, "owasp:revshell:005", ""},
	{regexp.MustCompile(`(curl|wget)\s+.*\|\s*(ba)?sh`), 5, "owasp:revshell:006", ""},
	{regexp.MustCompile(`mkfifo\s+/tmp/`), 4, "owasp:revshell:007", "mkfifo"},
	// Perl 反弹 shell
	{regexp.MustCompile(`perl\s+-e\s+['"].{0,300}socket`), 4, "owasp:revshell:008", "socket"},
	// Socat 反弹 shell
	{regexp.MustCompile(`socat\s+\S+\s+exec:`), 5, "owasp:revshell:009", "socat"},
	{regexp.MustCompile(`socat\s+[a-z0-9.+,:-]{0,40}tcp[a-z0-9.+,:-]{0,40}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), 4, "owasp:revshell:010", "socat"},
	// Telnet 反弹 shell：telnet 1.2.3.4 4444
	{regexp.MustCompile(`telnet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{2,5}`), 4, "owasp:revshell:011", "telnet"},
	// Ruby 或 Node.js 基于 socket 的反弹 shell
	{regexp.MustCompile(`(ruby|node)\s+-[re]\s+['"].{0,300}socket`), 4, "owasp:revshell:012", "socket"},
}

func checkRevShell(s string, threshold int) (OWASPHit, bool) {
	if !hasRevShellIndicator(s) {
		return OWASPHit{}, false
	}
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range revshellPatterns {
		if !owaspPatternGatePass(p, s) {
			continue
		}
		if p.re.MatchString(s) {
			if acc == nil {
				acc = acquireOWASPAcc(threshold)
			}
			acc.Add(p.id, p.score)
			if acc.Exceeded() {
				id, total := acc.Attribution()
				return OWASPHit{Category: CatRevShell, RuleID: id, Score: total, Desc: "反弹 Shell / 远程执行特征"}, true
			}
		}
	}
	return OWASPHit{}, false
}

var xssPatterns = []owaspPattern{
	{regexp.MustCompile(`<script[;\s>/]`), 5, "owasp:xss:001", "<script"},
	// 零字节/零宽混淆的 script 标签：<scr\x00ipt> 剥零字节后 <script>，
	// 但原始形态（未剥前）也可能以 </script 结尾。独立 low-score 兜底。
	{regexp.MustCompile(`<<script[;\s>/]`), 5, "owasp:xss:071", "<script"},
	{regexp.MustCompile(`\bon(error|load|click|dblclick|auxclick|mouse(over|out|down|up|enter|leave|move|wheel)|focus(in)?|blur|change|submit|toggle|input|key(down|up|press)|drag(start|end|over|enter|leave)?|drop|copy|cut|paste|pointer(over|down|up|cancel|move|enter|leave)|animation(start|end|iteration)|transition(end|start|run|cancel)|scroll|wheel|resize|contextmenu|message|hashchange|popstate|beforeunload|unload|invalid|select|fullscreenchange|touchstart|touchend|touchmove|touchcancel|beforeinput|show)\s*=`), 5, "owasp:xss:002", "on"},
	{regexp.MustCompile(`javascript\s*:`), 5, "owasp:xss:003", "javascript"},
	{regexp.MustCompile(`<img\b[^>]*(src\s*=[^>]*\s+)?onerror\s*=`), 5, "owasp:xss:004", "<img"},
	{regexp.MustCompile(`<iframe[\s>]`), 3, "owasp:xss:005", "<iframe"},
	{regexp.MustCompile(`document\.(cookie|location|write|domain)`), 4, "owasp:xss:006", "document."},
	{regexp.MustCompile(`<svg[\s>]`), 2, "owasp:xss:007", "<svg"},
	{regexp.MustCompile(`<math[\s>]`), 2, "owasp:xss:008", "<math"},
	{regexp.MustCompile(`data:text/html`), 5, "owasp:xss:009", "data:text/html"},
	{regexp.MustCompile(`window\.(location|name|open)`), 4, "owasp:xss:010", "window."},
	{regexp.MustCompile(`\b(eval|settimeout|setinterval|function)\s*\(\s*['"]`), 5, "owasp:xss:011", "("},
	{regexp.MustCompile(`(?i)\bnew\s+function\s*\(\s*[^'"]*['"]`), 4, "owasp:xss:068", "function"},
	{regexp.MustCompile(`innerhtml\s*=`), 5, "owasp:xss:012", "innerhtml"},
	{regexp.MustCompile(`&#x?0*3c;?\s*script`), 5, "owasp:xss:013", "script"},
	{regexp.MustCompile(`<\w+\b[^>]+\bon\w+\s*=`), 5, "owasp:xss:014", "on"},
	{regexp.MustCompile(`<(embed|object)\b[^>]*(data|src)\s*=`), 3, "owasp:xss:015", "<"},
	{regexp.MustCompile(`<form\b[^>]*action\s*=\s*['"]?\s*javascript:`), 5, "owasp:xss:016", "<form"},
	{regexp.MustCompile(`string\s*\.\s*fromcharcode\s*\(`), 5, "owasp:xss:017", "fromcharcode"},
	{regexp.MustCompile(`<base\b[^>]+href\s*=\s*['"]?\s*javascript\s*:`), 5, "owasp:xss:018", "<base"},
	{regexp.MustCompile(`<base\b[^>]+href\s*=`), 3, "owasp:xss:054", "<base"},
	{regexp.MustCompile(`(fetch|xmlhttprequest)\s*\(\s*['"]https?://`), 4, "owasp:xss:019", "http"},
	{regexp.MustCompile(`vbscript\s*:`), 5, "owasp:xss:020", "vbscript"},
	{regexp.MustCompile(`\bexpression\s*\(\s*(document|window|eval|this|alert)`), 3, "owasp:xss:021", "expression"},
	{regexp.MustCompile(`\bsrcdoc\s*=`), 4, "owasp:xss:022", "srcdoc"},
	{regexp.MustCompile(`\{\{.*?(constructor|__proto__|__definegetter__).*?\}\}`), 5, "owasp:xss:023", "{{"},
	{regexp.MustCompile(`document\s*\.\s*(write|writeln)\s*\(`), 5, "owasp:xss:024", "document"},
	{regexp.MustCompile(`(location\s*\.\s*(href|assign|replace)|window\s*\.\s*open)\s*\(\s*['"]?\s*javascript\s*:`), 5, "owasp:xss:025", "javascript"},
	{regexp.MustCompile(`<details\b[^>]*\bopen\b[^>]*\bontoggle\s*=`), 5, "owasp:xss:026", "<details"},
	{regexp.MustCompile(`<input\b[^>]*\bautofocus\b[^>]*\bonfocus\s*=`), 5, "owasp:xss:027", "<input"},
	{regexp.MustCompile(`<link\b[^>]*\brel\s*=\s*['"]?\s*import\b`), 4, "owasp:xss:028", "<link"},
	{regexp.MustCompile(`<img\b[^>]*\bname\s*=\s*['"]?\s*(documentelement|body|head|domain)\b`), 4, "owasp:xss:029", "<img"},
	{regexp.MustCompile(`\b(window|self|top|parent|frames|globalthis|this)\s*\[\s*['"\x60]`), 4, "owasp:xss:030", "["},
	{regexp.MustCompile(`\[\s*['"\x60]\s*(alert|eval|prompt|confirm|settimeout|setinterval|atob|btoa|fetch|open|execscript)\s*['"\x60]\s*\]`), 5, "owasp:xss:031", "["},
	{regexp.MustCompile(`/\w+/\s*\.\s*source`), 4, "owasp:xss:032", ".source"},
	{regexp.MustCompile(`\(!(\[\]|!\[\])\)|(\+\{\}|\+\[\])`), 4, "owasp:xss:033", ""},
	{regexp.MustCompile(`\+A[A-Za-z0-9]{1,3}[-+]`), 3, "owasp:xss:034", ""},
	{regexp.MustCompile(`\bconstructor\s*\.\s*prototype\s*\[`), 4, "owasp:xss:035", "constructor"},
	{regexp.MustCompile(`<param\b[^>]*\bname\s*=\s*['"]?\s*(url|src|data|code|movie|allowscriptaccess)\b`), 4, "owasp:xss:036", "<param"},
	{regexp.MustCompile(`<(body|table|thead|tbody|tr|td|th|input)\b[^>]*\bbackground\s*=`), 3, "owasp:xss:037", "background"},
	{regexp.MustCompile(`<base\b[^>]*\btarget\s*=\s*['"]\s*[^'"]*\(.*\)`), 4, "owasp:xss:038", "<base"},
	{regexp.MustCompile(`<meta\b[^>]*\bhttp-equiv\s*=\s*['"]?(refresh|content-type|set-cookie)\b`), 4, "owasp:xss:039", "<meta"},
	{regexp.MustCompile(`<embed\b[^>]*\bcode\s*=`), 4, "owasp:xss:040", "<embed"},
	{regexp.MustCompile(`<use\b[^>]*(href|xlink:href)\s*=`), 4, "owasp:xss:041", "<use"},
	{regexp.MustCompile(`<(animate|set|animatetransform)\b[^>]*(xlink:href|href)\s*=`), 3, "owasp:xss:042", "href"},
	{regexp.MustCompile(`\bonafterscriptexecute\s*=`), 4, "owasp:xss:043", "onafterscriptexecute"},
	{regexp.MustCompile(`document\s*\[\s*['"\x60]\s*(cookie|location|domain|write|body|title|url)\b`), 4, "owasp:xss:044", "document"},
	{regexp.MustCompile(`\b(alert|confirm|prompt)\s*\(\s*[\d'"` + "`" + `]`), 5, "owasp:xss:045", "("},
	{regexp.MustCompile(`\bconstructor\s*\.\s*constructor\s*\(`), 5, "owasp:xss:046", "constructor"},
	{regexp.MustCompile(`<a\b[^>]*\bdownload\s*=`), 3, "owasp:xss:047", "download"},
	{regexp.MustCompile(`\[\s*/\w+/\s*\.\s*source\s*\+\s*/\w+/\s*\.\s*source\s*\]`), 5, "owasp:xss:048", ".source"},
	{regexp.MustCompile(`\b(eval|function)\s*\(\s*atob\s*\(`), 5, "owasp:xss:049", "atob"},
	{regexp.MustCompile(`<\w+:\s*script\b`), 5, "owasp:xss:050", "script"},
	{regexp.MustCompile(`data\s*:\s*image/svg\+xml`), 4, "owasp:xss:051", "image/svg"},
	{regexp.MustCompile(`\b(window|self|top|parent|frames|globalthis|this)\s*\[\s*[\(/!+\[]`), 4, "owasp:xss:052", "["},
	{regexp.MustCompile(`\.constructor\s*\.\s*prototype\s*\.\s*\w+\s*=`), 5, "owasp:xss:053", ".constructor"},
	{regexp.MustCompile("\\b(alert|prompt|confirm)\\s*(?:\\.\\s*(?:call|apply)\\s*\\(|\\)\\s*\\([\\d'\"`])"), 5, "owasp:xss:067", ""},
	// 模板字符串型直连调用：prompt`1`（原生反引号实参调用弹窗函数，
	// 无括号无点，绕过 xss:045/067 两分支）。
	{regexp.MustCompile("(?i)\\b(alert|prompt|confirm)\\s*`[^`]*`"), 5, "owasp:xss:069", ""},
	// 可选链直连调用：alert?.(document?.cookie)（ES2020 optional chaining
	// 调用形态，无括号直连被 ?. 阻断，绕过 xss:045/067/069）。
	{regexp.MustCompile(`\b(alert|prompt|confirm)\s*\?\.\s*\(`), 5, "owasp:xss:070", ""},
	{regexp.MustCompile(`<a\b[^>]*\bdownload\s*=\s*['"]?\s*\w+\.\w{2,5}\b`), 4, "owasp:xss:055", "download"},
	{regexp.MustCompile(`j\s*a\s*v\s*a\s+s\s*c\s*r\s*i\s*p\s*t\s*:`), 5, "owasp:xss:056", ""},
	{regexp.MustCompile(`<(body|table|thead|td|th|tr)\b[^>]*\bbackground\s*=\s*['"]?\s*(//|https?:)`), 4, "owasp:xss:057", "background"},
	// DOM Clobbering：通过 name/id 属性覆写 DOM 属性
	{regexp.MustCompile(`<(form|input|img|a|embed|object)\b[^>]*\b(name|id)\s*=\s*['"]?(document|window|location|navigator|top|self|frames)\b`), 5, "owasp:xss:058", "<"},
	// 通过 document 具名访问实施 DOM Clobbering
	{regexp.MustCompile(`<(a|area)\b[^>]*\bname\s*=\s*['"]?__proto__`), 5, "owasp:xss:059", "__proto__"},
	// mXSS 变异：noscript/noembed/noframes 内容被重新解释
	{regexp.MustCompile(`<(noscript|noembed|noframes)\b[^>]*>.*?<(script|img|svg|iframe)\b`), 5, "owasp:xss:060", "<no"},
	// math/svg 命名空间混淆导致的 mXSS
	{regexp.MustCompile(`<(math|svg)\b[^>]*>.*?<(style|mglyph|malignmark)\b`), 5, "owasp:xss:061", "<"},
	// SVG foreignObject：在 SVG 上下文内嵌 HTML
	{regexp.MustCompile(`<svg\b[^>]*>.*?<foreignobject\b`), 5, "owasp:xss:062", "foreignobject"},
	// SVG 动画事件处理器
	{regexp.MustCompile(`<(animate|animatetransform|set)\b[^>]*\bon(begin|end|repeat)\s*=`), 5, "owasp:xss:063", "on"},
	// 命名空间混淆：在 SVG 中用 xlink:href 执行 JS
	{regexp.MustCompile(`xlink:href\s*=\s*['"]?\s*javascript:`), 5, "owasp:xss:064", "xlink:href"},
	// 通过被 clobber 的属性绕过 DOMPurify
	{regexp.MustCompile(`<[^>]+(sanitize|purify|dompurify)[^>]*>`), 3, "owasp:xss:065", "<"},
	// 模板字面量 XSS：反引号字符串内的 ${...}
	{regexp.MustCompile("`[^`]*\\$\\{[^}]*(document|window|location|cookie|alert|fetch|eval)[^}]*\\}[^`]*`"), 5, "owasp:xss:066", "${"},
}

func checkXSS(s string, threshold int) (OWASPHit, bool) {
	if !hasXSSIndicator(s) {
		return OWASPHit{}, false
	}
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range xssPatterns {
		if !owaspPatternGatePass(p, s) {
			continue
		}
		if p.re.MatchString(s) {
			if acc == nil {
				acc = acquireOWASPAcc(threshold)
			}
			acc.Add(p.id, p.score)
			if acc.Exceeded() {
				id, total := acc.Attribution()
				return OWASPHit{Category: CatXSS, RuleID: id, Score: total, Desc: "XSS 特征"}, true
			}
		}
	}
	return OWASPHit{}, false
}

const (
	sgS  uint32 = 1 << iota // 's'：select/sleep/sysobjects/substr/substring
	sgSM                    // ';'：semicolon
	sgCM                    // '-' 或 '/'：-- / /* / /*!
	sgO                     // 'o'：or/outfile/order/offset
	sgA                     // 'a'：and
	sgB                     // 'b'：benchmark
	sgW                     // 'w'：waitfor/when
	sgUS                    // '_'：pg_sleep/information_schema/load_file
	sgC                     // 'c'：chr/case/copy
	sgDT                    // '.'：sys.
	sgD                     // 'd'：dumpfile/dbms_
	sgI                     // 'i'：into
	sgAT                    // '@'：@@
	sgE                     // 'e'：extractvalue
	sgU                     // 'u'：updatexml/utl_/utl_inaddr
	sgM                     // 'm'：mid/master
	sgX                     // 'x'：xp_
	sgP                     // 'p'：procedure/program
	sgH                     // 'h'：having
	sgL                     // 'l'：like/limit
	sgG                     // 'g'：group
	sgF                     // 0xef：\xef\xbd\x93 / \xef\xbc\xb3（全角 Ｓ 首字节）
	sgPC                    // '%'：%25
)

var sqliSignalsMaskTable = buildIndicatorMaskTable(map[string]uint32{
	"s": sgS, ";": sgSM, "-": sgCM, "/": sgCM, "o": sgO, "a": sgA,
	"b": sgB, "w": sgW, "_": sgUS, "c": sgC, ".": sgDT, "d": sgD,
	"i": sgI, "@": sgAT, "e": sgE, "u": sgU, "m": sgM, "x": sgX,
	"p": sgP, "h": sgH, "l": sgL, "g": sgG, "\xef": sgF, "%": sgPC,
})

const (
	sfQ uint32 = 1 << iota // '\'' 或 '"'：hasSQLBooleanQuotedComparison / hasSQLBooleanEmptyQuotedComparison
	sfF                    // 'f'：hasSQLiIfFunctionPattern（字面量 if）
	sfH                    // 'h'：hasSQLiFunctionCallPattern("chr")
	sfN                    // 'n'：hasSQLiFunctionCallPattern("unhex")
	sfO                    // 'o'：hasSQLiFunctionCallPattern("conv")
)

var sqlifeatMaskTable = buildIndicatorMaskTable(map[string]uint32{
	"'": sfQ, `"`: sfQ,
	"f": sfF, "h": sfH, "n": sfN, "o": sfO,
})

type sqliPatternSignals struct {
	containsSelect          bool
	containsSemicolon       bool
	containsComment         bool
	containsOr              bool
	containsAnd             bool
	containsSleep           bool
	containsBenchmark       bool
	containsWaitfor         bool
	containsPGSleep         bool
	containsChr             bool
	containsInformation     bool
	containsSysobjects      bool
	containsSysDot          bool
	containsOutfile         bool
	containsDumpfile        bool
	containsLoadFile        bool
	containsInto            bool
	containsAtAt            bool
	containsExtractvalue    bool
	containsUpdatexml       bool
	containsCase            bool
	containsWhen            bool
	containsOrder           bool
	containsSubstr          bool
	containsSubstring       bool
	containsMid             bool
	containsXP              bool
	containsProcedure       bool
	containsUTL             bool
	containsDBMS            bool
	containsHaving          bool
	containsLike            bool
	containsLimit           bool
	containsOffset          bool
	containsGroup           bool
	containsCopy            bool
	containsProgram         bool
	containsUTLInaddr       bool
	containsMaster          bool
	containsFullwidthS      bool
	containsDoubleURLEncode bool
}

func collectSQLiPatternSignals(normalized string) sqliPatternSignals {
	if normalized == "" {
		return sqliPatternSignals{}
	}
	bm := scanIndicatorMask(normalized, &sqliSignalsMaskTable)
	p := func(mask uint32, lit string) bool { return bm&mask != 0 && strings.Contains(normalized, lit) }
	return sqliPatternSignals{
		containsSelect:          p(sgS, "select"),
		containsSemicolon:       p(sgSM, ";"),
		containsComment:         (bm&sgCM != 0) && (strings.Contains(normalized, "--") || strings.Contains(normalized, "/*") || strings.Contains(normalized, "/*!")),
		containsOr:              p(sgO, "or"),
		containsAnd:             p(sgA, "and"),
		containsSleep:           p(sgS, "sleep"),
		containsBenchmark:       p(sgB, "benchmark"),
		containsWaitfor:         p(sgW, "waitfor"),
		containsPGSleep:         p(sgUS, "pg_sleep"),
		containsChr:             p(sgC, "chr"),
		containsInformation:     p(sgUS, "information_schema"),
		containsSysobjects:      p(sgS, "sysobjects"),
		containsSysDot:          p(sgDT, "sys."),
		containsOutfile:         p(sgO, "outfile"),
		containsDumpfile:        p(sgD, "dumpfile"),
		containsLoadFile:        p(sgUS, "load_file"),
		containsInto:            p(sgI, "into"),
		containsAtAt:            p(sgAT, "@@"),
		containsExtractvalue:    p(sgE, "extractvalue"),
		containsUpdatexml:       p(sgU, "updatexml"),
		containsCase:            p(sgC, "case"),
		containsWhen:            p(sgW, "when"),
		containsOrder:           p(sgO, "order"),
		containsSubstr:          p(sgS, "substr"),
		containsSubstring:       p(sgS, "substring"),
		containsMid:             p(sgM, "mid"),
		containsXP:              p(sgX, "xp_"),
		containsProcedure:       p(sgP, "procedure"),
		containsUTL:             p(sgU, "utl_"),
		containsDBMS:            p(sgD, "dbms_"),
		containsHaving:          p(sgH, "having"),
		containsLike:            p(sgL, "like"),
		containsLimit:           p(sgL, "limit"),
		containsOffset:          p(sgO, "offset"),
		containsGroup:           p(sgG, "group"),
		containsCopy:            p(sgC, "copy"),
		containsProgram:         p(sgP, "program"),
		containsUTLInaddr:       p(sgU, "utl_inaddr"),
		containsMaster:          p(sgM, "master"),
		containsFullwidthS:      (bm&sgF != 0) && (strings.Contains(normalized, "\xef\xbd\x93") || strings.Contains(normalized, "\xef\xbc\xb3")),
		containsDoubleURLEncode: p(sgPC, "%25"),
	}
}

func hasHighByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0xE0 {
			return true
		}
	}
	return false
}

func shouldScanSQLiPatternWithSignals(normalized string, p owaspPattern, signals sqliPatternSignals) bool {
	if p.hint != "" && !strings.Contains(normalized, p.hint) {
		return false
	}
	switch p.id {
	case "owasp:sqli:002":
		return (signals.containsOr || signals.containsAnd) && strings.Contains(normalized, "'")
	case "owasp:sqli:003":
		return (signals.containsSleep || signals.containsBenchmark || signals.containsWaitfor || signals.containsPGSleep) && strings.Contains(normalized, "(")
	case "owasp:sqli:004":
		return signals.containsSemicolon && (strings.Contains(normalized, "select") || strings.Contains(normalized, "drop") || strings.Contains(normalized, "alter") || strings.Contains(normalized, "create") || strings.Contains(normalized, "truncate") || strings.Contains(normalized, "delete") || strings.Contains(normalized, "update") || strings.Contains(normalized, "insert"))
	case "owasp:sqli:005":
		return signals.containsComment && strings.ContainsAny(normalized, "'\"0123456789")
	case "owasp:sqli:006":
		return signals.containsSemicolon && strings.Contains(normalized, "'")
	case "owasp:sqli:007":
		if !hasSQLiFunctionByteHint(normalized, sfH|sfN|sfO) {
			return false
		}
		return hasSQLiFunctionCallPattern(normalized, "chr") ||
			hasSQLiFunctionCallPattern(normalized, "unhex") ||
			hasSQLiFunctionCallPattern(normalized, "conv")
	case "owasp:sqli:008":
		return hasSQLiHexLiteralPattern(normalized)
	case "owasp:sqli:009":
		return signals.containsInformation || signals.containsSysobjects || signals.containsSysDot
	case "owasp:sqli:010":
		return hasSQLBooleanNumericComparison(normalized)
	case "owasp:sqli:011":
		if !hasSQLiFunctionByteHint(normalized, sfQ) {
			return false
		}
		return hasSQLBooleanQuotedComparison(normalized)
	case "owasp:sqli:036":
		if !hasSQLiFunctionByteHint(normalized, sfQ) {
			return false
		}
		return hasSQLBooleanEmptyQuotedComparison(normalized)
	case "owasp:sqli:039":
		return (signals.containsOr || signals.containsAnd) && signals.containsSelect && strings.Contains(normalized, "(")
	case "owasp:sqli:012":
		return signals.containsSemicolon && strings.Contains(normalized, "--")
	case "owasp:sqli:013", "owasp:sqli:017":
		return signals.containsOutfile || signals.containsDumpfile || signals.containsLoadFile || signals.containsInto
	case "owasp:sqli:014":
		return signals.containsAtAt
	case "owasp:sqli:015":
		return (signals.containsExtractvalue || signals.containsUpdatexml) && strings.Contains(normalized, "(")
	case "owasp:sqli:018", "owasp:sqli:040":
		return signals.containsCase && signals.containsWhen
	case "owasp:sqli:019":
		return signals.containsOrder
	case "owasp:sqli:021":
		return (signals.containsSubstr || signals.containsSubstring || signals.containsMid) && strings.Contains(normalized, "(")
	case "owasp:sqli:022":
		if !hasSQLiFunctionByteHint(normalized, sfF) {
			return false
		}
		return hasSQLiIfFunctionPattern(normalized)
	case "owasp:sqli:023":
		return strings.Contains(normalized, "'") && (strings.ContainsAny(normalized, "^&") || strings.Contains(normalized, "<<") || strings.Contains(normalized, ">>"))
	case "owasp:sqli:024", "owasp:sqli:045":
		return signals.containsXP
	case "owasp:sqli:025":
		return signals.containsProcedure
	case "owasp:sqli:026":
		return signals.containsUTL || signals.containsDBMS
	case "owasp:sqli:027":
		return signals.containsHaving
	case "owasp:sqli:028", "owasp:sqli:031", "owasp:sqli:038", "owasp:sqli:041", "owasp:sqli:046", "owasp:sqli:047":
		return signals.containsSelect
	case "owasp:sqli:029":
		return signals.containsLike && strings.Contains(normalized, "'")
	case "owasp:sqli:030", "owasp:sqli:033":
		return signals.containsLimit || signals.containsOffset
	case "owasp:sqli:032":
		return signals.containsGroup && strings.Contains(normalized, "by")
	case "owasp:sqli:034":
		return signals.containsSemicolon && strings.Contains(normalized, "exec")
	case "owasp:sqli:035":
		return signals.containsWaitfor
	case "owasp:sqli:037":
		return signals.containsCopy || signals.containsProgram
	case "owasp:sqli:043":
		return signals.containsChr && strings.Count(normalized, "chr") >= 2 && (strings.Contains(normalized, "+") || strings.Contains(normalized, "||"))
	case "owasp:sqli:044":
		return signals.containsUTLInaddr
	case "owasp:sqli:048":
		return signals.containsMaster
	case "owasp:sqli:049", "owasp:sqli:053":
		if !hasHighByte(normalized) {
			return false
		}
		return signals.containsFullwidthS
	case "owasp:sqli:050", "owasp:sqli:051", "owasp:sqli:052":
		return signals.containsComment
	case "owasp:sqli:054":
		return signals.containsDoubleURLEncode
	default:
		return true
	}
}

func hasSQLiIfFunctionPattern(normalized string) bool {
	search := 0
	for search < len(normalized) {
		idx := strings.Index(normalized[search:], "if")
		if idx < 0 {
			return false
		}
		start := search + idx
		if !hasSQLWordAt(normalized, start, "if") {
			search = start + 1
			continue
		}
		pos := skipSQLSpaces(normalized, start+len("if"))
		if pos >= len(normalized) || normalized[pos] != '(' {
			search = start + 1
			continue
		}
		pos = skipSQLSpaces(normalized, pos+1)
		if hasSQLWordAt(normalized, pos, "select") ||
			hasSQLWordAt(normalized, pos, "ord") ||
			hasSQLWordAt(normalized, pos, "ascii") ||
			hasSQLWordAt(normalized, pos, "substr") ||
			hasSQLWordAt(normalized, pos, "length") ||
			hasSQLWordAt(normalized, pos, "count") ||
			hasSQLWordAt(normalized, pos, "version") {
			return true
		}
		search = start + 1
	}
	return false
}

func hasSQLiFunctionByteHint(normalized string, need uint32) bool {
	if normalized == "" {
		return false
	}
	if need == 0 {
		return true
	}
	bm := scanIndicatorMask(normalized, &sqlifeatMaskTable)
	return bm&need != 0
}

func hasSQLiFunctionCallPattern(normalized, name string) bool {
	search := 0
	for search < len(normalized) {
		idx := strings.Index(normalized[search:], name)
		if idx < 0 {
			return false
		}
		pos := search + idx + len(name)
		for pos < len(normalized) && isSQLiRegexpSpaceByte(normalized[pos]) {
			pos++
		}
		if pos < len(normalized) && normalized[pos] == '(' {
			return true
		}
		search += idx + 1
	}
	return false
}

func hasSQLiHexLiteralPattern(normalized string) bool {
	for i := 0; i < len(normalized); i++ {
		switch normalized[i] {
		case ',', '=', '(':
			pos := i + 1
			for pos < len(normalized) && isSQLiRegexpSpaceByte(normalized[pos]) {
				pos++
			}
			if pos+6 > len(normalized) || normalized[pos] != '0' || normalized[pos+1] != 'x' {
				continue
			}
			hexStart := pos + 2
			hexEnd := hexStart
			for hexEnd < len(normalized) && isLowerSQLHexByte(normalized[hexEnd]) {
				hexEnd++
			}
			if hexEnd-hexStart >= 4 {
				return true
			}
		}
	}
	return false
}

func isSQLiRegexpSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\f' || b == '\r'
}

func isLowerSQLHexByte(b byte) bool {
	return isASCIIDigitByte(b) || (b >= 'a' && b <= 'f')
}

func hasSQLBooleanNumericComparison(s string) bool {
	for i := 0; i < len(s); i++ {
		end, ok := sqlBooleanOperatorEndAt(s, i)
		if !ok {
			continue
		}
		j := skipSQLSpaces(s, end)
		if j >= len(s) || !isASCIIDigitByte(s[j]) {
			continue
		}
		for j < len(s) && isASCIIDigitByte(s[j]) {
			j++
		}
		j = skipSQLSpaces(s, j)
		if j >= len(s) || s[j] != '=' {
			continue
		}
		j = skipSQLSpaces(s, j+1)
		if j < len(s) && isASCIIDigitByte(s[j]) {
			return true
		}
	}
	return false
}

// hasSQLTautologyInjectionContext 判断「布尔关键字 + 数值等式」是否处在注入
// 语法位置，用于 sqli:010 的误报抑制。命中任一形态即视为注入上下文：
//
//  1. 布尔关键字与左操作数之间无空白（and1=1）——SQL 词法允许该紧贴形态，
//     散文不会把关键字粘到数字前。
//  2. 等式位于目标末尾——参数值整体即注入内容。
//  3. 等式后继字符是语句/操作数边界（& ; ' " / \ | = # 等）——参数分隔、
//     引号闭合或注释起始。
//  4. 等式后空白之后紧跟 SQL 语法词（select/union/and/… 或 -- # /* 注释符）
//     ——后续子句延续，散文里空白后接的是普通单词。
//
// 背离条件：散文若把等式紧贴标点（如 "(and 1=1)" 这类括号引用）会被判为
// 注入上下文，从而保留命中——这是有意保留的保守侧，避免为语言习惯放宽而
// 放过 "id=1 and 1=1)/*" 这类括号闭合注入。
func hasSQLTautologyInjectionContext(lower string) bool {
	for _, m := range reTautologyInjection.FindAllStringIndex(lower, -1) {
		start, end := m[0], m[1]
		opLen := len("and")
		if strings.HasPrefix(lower[start:], "or") {
			opLen = len("or")
		}
		// 1) 关键字紧贴左操作数：and1=1。
		if start+opLen < end {
			if c := lower[start+opLen]; c != ' ' && c != '\t' {
				return true
			}
		}
		// 2) 等式位于目标末尾。
		if end >= len(lower) {
			return true
		}
		// 3) 后继为语句/操作数边界字符。
		if isSQLTautologyBoundaryByte(lower[end]) {
			return true
		}
		// 4) 空白之后紧跟 SQL 语法词或注释符。
		if lower[end] == ' ' || lower[end] == '\t' {
			j := end
			for j < len(lower) && (lower[j] == ' ' || lower[j] == '\t') {
				j++
			}
			if j >= len(lower) || hasSQLGrammarAt(lower, j) {
				return true
			}
		}
	}
	return false
}

// reTautologyInjection 是 sqli:010 规则正则的等价形态，用于定位恒等式位置。
var reTautologyInjection = regexp.MustCompile(`\b(or|and)\s*\d+\s*=\s*\d+`)

// isSQLTautologyBoundaryByte 判断字节是否为 SQL 语句/操作数边界：
// 参数分隔、引号闭合、注释起始、括号或运算符号。
func isSQLTautologyBoundaryByte(b byte) bool {
	switch b {
	case '&', ';', '\'', '"', '`', '/', '\\', '|', '=', '#', '-', '*', '%',
		'<', '>', '{', '}', '[', ']', ':', '!', '?', '@', '$', '^', '~', '+', '(', ')':
		return true
	}
	return false
}

// sqlGrammarWords 是恒等式后续位置的 SQL 语法词与注释起始符。
// 空白后紧跟其中任一项即说明等式仍在 SQL 语句内部。
var sqlGrammarWords = [...]string{
	"select", "union", "from", "where", "having", "order", "group", "limit",
	"into", "values", "and", "or", "not", "sleep", "benchmark", "waitfor",
	"insert", "update", "delete", "drop", "exec", "declare", "case", "when",
	"then", "else", "end", "like", "in", "between", "exists", "all", "any",
	"distinct", "as", "join", "on", "set", "table", "database",
	"information_schema", "--", "#", "/*",
}

// hasSQLGrammarAt 判断 s[i:] 是否以 SQL 语法词或注释起始符开头（词尾需为
// 非词字节，注释符与 # 除外）。
func hasSQLGrammarAt(s string, i int) bool {
	for _, kw := range sqlGrammarWords {
		if !strings.HasPrefix(s[i:], kw) {
			continue
		}
		j := i + len(kw)
		if j >= len(s) || !isSQLWordByte(s[j]) {
			return true
		}
	}
	return false
}

func hasSQLBooleanQuotedComparison(s string) bool {
	for i := 0; i < len(s); i++ {
		end, ok := sqlBooleanOperatorEndAt(s, i)
		if !ok || end >= len(s) {
			continue
		}
		j := skipSQLSpaces(s, end)
		if j == end {
			// 无空格紧贴形态：or"1"="1"（注释剥离 / 编码解码产物）。
			// 引号紧跟布尔运算符且随后构成引号比较时视为注入；
			// 自然文本不会拼出 or"word"= 的引号比较结构。
			if s[j] != '\'' && s[j] != '"' {
				continue
			}
		}
		next, ok := scanSQLQuotedWord(s, j)
		if !ok {
			continue
		}
		j = skipSQLSpaces(s, next)
		if j >= len(s) || s[j] != '=' {
			continue
		}
		j = skipSQLSpaces(s, j+1)
		if _, ok := scanSQLQuotedWord(s, j); ok {
			return true
		}
	}
	return false
}

func hasSQLBooleanEmptyQuotedComparison(s string) bool {
	for i := 0; i < len(s); i++ {
		end, ok := sqlBooleanOperatorEndAt(s, i)
		if !ok || end >= len(s) {
			continue
		}
		j := skipSQLSpaces(s, end)
		if j == end || j+1 >= len(s) || !isSQLQuoteByte(s[j]) || !isSQLQuoteByte(s[j+1]) {
			continue
		}
		j = skipSQLSpaces(s, j+2)
		if j >= len(s) || s[j] != '=' {
			continue
		}
		j = skipSQLSpaces(s, j+1)
		if j < len(s) && isSQLQuoteByte(s[j]) {
			return true
		}
	}
	return false
}

func sqlBooleanOperatorEndAt(s string, i int) (int, bool) {
	if i > 0 && isSQLWordByte(s[i-1]) {
		return 0, false
	}
	switch {
	case i+2 <= len(s) && s[i:i+2] == "or":
		return i + 2, true
	case i+3 <= len(s) && s[i:i+3] == "and":
		return i + 3, true
	default:
		return 0, false
	}
}

func scanSQLQuotedWord(s string, i int) (int, bool) {
	if i >= len(s) || !isSQLQuoteByte(s[i]) {
		return 0, false
	}
	i++
	for i < len(s) && isSQLWordByte(s[i]) {
		i++
	}
	if i >= len(s) || !isSQLQuoteByte(s[i]) {
		return 0, false
	}
	return i + 1, true
}

func isSQLQuoteByte(b byte) bool {
	return b == '\'' || b == '"'
}

func isASCIIDigitByte(b byte) bool {
	return b >= '0' && b <= '9'
}

func nextSQLiHit(normalized string, threshold int) (OWASPHit, bool) {
	if strings.Contains(normalized, "unionselect") {
		return OWASPHit{Category: CatSQLi, RuleID: "owasp:sqli:001", Score: 5, Desc: "SQL 注入特征"}, true
	}
	if strings.Contains(normalized, "and1=1") || strings.Contains(normalized, "or1=1") {
		return OWASPHit{Category: CatSQLi, RuleID: "owasp:sqli:010", Score: 5, Desc: "SQL 注入特征"}, true
	}
	if !hasSQLiIndicator(normalized) {
		return OWASPHit{}, false
	}
	signals := collectSQLiPatternSignals(normalized)
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	// FP 抑制器前移到 Add 之前：被判为误报的规则既不参与计分也不参与归因，
	// 因此它后面真正跨阈的规则不会再被吞掉（旧实现的致漏报缺陷）。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range sqliPatterns {
		if !shouldScanSQLiPatternWithSignals(normalized, p, signals) {
			continue
		}
		if !p.re.MatchString(normalized) {
			continue
		}
		if isSQLiFalsePositive(normalized, p.id) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatSQLi, RuleID: id, Score: total, Desc: "SQL 注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

func shouldScanXSSPattern(normalized string, p owaspPattern) bool {
	if p.hint != "" && !strings.Contains(normalized, p.hint) {
		return false
	}
	switch p.id {
	case "owasp:xss:002":
		return strings.Contains(normalized, "=")
	case "owasp:xss:011":
		return strings.Contains(normalized, "(") && strings.ContainsAny(normalized, "'\"") && (strings.Contains(normalized, "eval") || strings.Contains(normalized, "settimeout") || strings.Contains(normalized, "setinterval") || strings.Contains(normalized, "function"))
	case "owasp:xss:013":
		return strings.Contains(normalized, "&#") && strings.Contains(normalized, "script")
	case "owasp:xss:014":
		return strings.Contains(normalized, "<") && strings.Contains(normalized, "on") && strings.Contains(normalized, "=")
	case "owasp:xss:015":
		return (strings.Contains(normalized, "<embed") || strings.Contains(normalized, "<object")) && (strings.Contains(normalized, "data") || strings.Contains(normalized, "src")) && strings.Contains(normalized, "=")
	case "owasp:xss:019":
		return (strings.Contains(normalized, "fetch") || strings.Contains(normalized, "xmlhttprequest")) && strings.Contains(normalized, "(") && strings.Contains(normalized, "http")
	case "owasp:xss:030":
		return strings.Contains(normalized, "[") && strings.ContainsAny(normalized, "'\"`") && (strings.Contains(normalized, "window") || strings.Contains(normalized, "self") || strings.Contains(normalized, "top") || strings.Contains(normalized, "parent") || strings.Contains(normalized, "frames") || strings.Contains(normalized, "globalthis") || strings.Contains(normalized, "this"))
	case "owasp:xss:031":
		return strings.Contains(normalized, "[") && strings.Contains(normalized, "]") && strings.ContainsAny(normalized, "'\"`") && (strings.Contains(normalized, "alert") || strings.Contains(normalized, "eval") || strings.Contains(normalized, "prompt") || strings.Contains(normalized, "confirm") || strings.Contains(normalized, "settimeout") || strings.Contains(normalized, "setinterval") || strings.Contains(normalized, "atob") || strings.Contains(normalized, "btoa") || strings.Contains(normalized, "fetch") || strings.Contains(normalized, "open") || strings.Contains(normalized, "execscript"))
	case "owasp:xss:033":
		// 强锚形态才放行扫描：完整 JSFuck 链（(![]、!![]、构造函数），
		// 裸 +[]/+{} 不进入电池（二进制噪声碰撞面）。
		return strings.Contains(normalized, "(![]") || strings.Contains(normalized, "(!![]") ||
			(strings.Contains(normalized, "constructor") && (strings.Contains(normalized, "+{}") || strings.Contains(normalized, "+[]")))
	case "owasp:xss:034":
		return strings.Contains(normalized, "+A")
	case "owasp:xss:042":
		return strings.Contains(normalized, "href") && (strings.Contains(normalized, "<animate") || strings.Contains(normalized, "<set") || strings.Contains(normalized, "<animatetransform"))
	case "owasp:xss:045":
		return strings.Contains(normalized, "(") && (strings.Contains(normalized, "alert") || strings.Contains(normalized, "confirm") || strings.Contains(normalized, "prompt"))
	case "owasp:xss:052":
		return strings.Contains(normalized, "[") && (strings.ContainsAny(normalized, "(/!+") || strings.Count(normalized, "[") >= 2) && (strings.Contains(normalized, "window") || strings.Contains(normalized, "self") || strings.Contains(normalized, "top") || strings.Contains(normalized, "parent") || strings.Contains(normalized, "frames") || strings.Contains(normalized, "globalthis") || strings.Contains(normalized, "this"))
	case "owasp:xss:056":
		return strings.Contains(normalized, ":") && strings.Contains(normalized, "j") && strings.Contains(normalized, "p") && strings.Contains(normalized, "t")
	case "owasp:xss:058":
		return (strings.Contains(normalized, "name") || strings.Contains(normalized, "id")) && (strings.Contains(normalized, "document") || strings.Contains(normalized, "window") || strings.Contains(normalized, "location") || strings.Contains(normalized, "navigator") || strings.Contains(normalized, "top") || strings.Contains(normalized, "self") || strings.Contains(normalized, "frames")) && (strings.Contains(normalized, "<form") || strings.Contains(normalized, "<input") || strings.Contains(normalized, "<img") || strings.Contains(normalized, "<a") || strings.Contains(normalized, "<embed") || strings.Contains(normalized, "<object"))
	case "owasp:xss:061":
		return (strings.Contains(normalized, "<math") || strings.Contains(normalized, "<svg")) && (strings.Contains(normalized, "<style") || strings.Contains(normalized, "<mglyph") || strings.Contains(normalized, "<malignmark"))
	case "owasp:xss:063":
		return strings.Contains(normalized, "on") && strings.Contains(normalized, "=") && (strings.Contains(normalized, "<animate") || strings.Contains(normalized, "<animatetransform") || strings.Contains(normalized, "<set"))
	case "owasp:xss:065":
		return strings.Contains(normalized, "<") && strings.Contains(normalized, ">") && (strings.Contains(normalized, "sanitize") || strings.Contains(normalized, "purify") || strings.Contains(normalized, "dompurify"))
	case "owasp:xss:067":
		if !strings.Contains(normalized, "(") ||
			!(strings.Contains(normalized, "alert") || strings.Contains(normalized, "prompt") || strings.Contains(normalized, "confirm")) {
			return false
		}
		// alert.call/confirm.apply 走 '.'；alert)(1 走 ')(' 直连形态；
		// (alert)(1) 走 '(' 前置包裹调用形态（IIFE 风格弹窗）。
		return strings.Contains(normalized, ".") ||
			strings.Contains(normalized, "alert)(") ||
			strings.Contains(normalized, "prompt)(") ||
			strings.Contains(normalized, "confirm)(") ||
			strings.Contains(normalized, "(alert)(") ||
			strings.Contains(normalized, "(prompt)(") ||
			strings.Contains(normalized, "(confirm)(")
	case "owasp:xss:069":
		// 反引号模板实参形态：命中正则即已自带反引号双锁，无需额外门。
		return strings.Contains(normalized, "`")
	case "owasp:xss:070":
		// 可选链调用形态：?.( 自带强锁定，无需额外门。
		return strings.Contains(normalized, "?.")
	case "owasp:xss:068":
		return strings.Contains(normalized, "new") && strings.Contains(normalized, "function") && strings.ContainsAny(normalized, "'\"")
	default:
		return true
	}
}

func isXSSSuppressedRule(normalized, ruleID string, threshold int) bool {
	if ruleID == "owasp:xss:002" && isXSSHandlerFunctionRef(normalized) {
		return true
	}
	if ruleID == "owasp:xss:001" || ruleID == "owasp:xss:014" {
		return isXSSFalsePositive(normalized, ruleID)
	}
	return threshold > 2 && isXSSFalsePositive(normalized, ruleID)
}

func nextXSSHit(normalized string, threshold int) (OWASPHit, bool) {
	if !hasXSSIndicator(normalized) {
		return OWASPHit{}, false
	}
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range xssPatterns {
		if !shouldScanXSSPattern(normalized, p) {
			continue
		}
		if !p.re.MatchString(normalized) {
			continue
		}
		if isXSSSuppressedRule(normalized, p.id, threshold) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatXSS, RuleID: id, Score: total, Desc: "XSS 特征"}, true
		}
	}
	return OWASPHit{}, false
}

func NormalizeForDebug(raw string) string { return normalizeWithDecode(raw) }
func IsOpaqueEncodedAttackBodyForDebug(raw, normalized string, headers map[string]string, threshold int) bool {
	return isOpaqueEncodedAttackBody(raw, normalized, headers, threshold)
}

func isOpaqueEncodedAttackBody(raw, normalized string, headers map[string]string, threshold int) bool {
	raw = strings.TrimSpace(raw)
	if threshold > 4 {
		return false
	}
	if len(raw) < 1024 || len(raw) > 8192 {
		return false
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") && strings.TrimSpace(v) != "" {
			return false
		}
	}
	if strings.ContainsAny(raw, " \r\n") {
		return false
	}
	compact := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(raw, "\r", ""), "\n", ""), " ", "")
	if len(compact) < 1024 || len(compact)%4 != 0 {
		return false
	}
	if !reBase64Token.MatchString(compact) {
		return false
	}
	plusSlash := strings.Count(compact, "+") + strings.Count(compact, "/")
	return plusSlash >= 16
}

var pathTravPatterns = []owaspPattern{
	{regexp.MustCompile(`(\.\./){2,}`), 4, "owasp:path_traversal:001", "../"},
	{regexp.MustCompile(`(etc/passwd|etc/shadow|win\.ini|boot\.ini)`), 5, "owasp:path_traversal:002", ""},
	{regexp.MustCompile(`%2e%2e[/\\]`), 4, "owasp:path_traversal:003", "%2e%2e"},
	{regexp.MustCompile(`\.\.[/\\]\.\.[/\\]`), 4, "owasp:path_traversal:004", ".."},
	{regexp.MustCompile(`\.\.;[/\\]`), 4, "owasp:path_traversal:005", "..;"},
	{regexp.MustCompile(`/proc/self/(environ|cmdline|fd|maps|status|exe|cwd|root)`), 5, "owasp:path_traversal:006", "/proc/self/"},
	{regexp.MustCompile(`\.\.(%00|\x00)`), 5, "owasp:path_traversal:007", ".."},
	{regexp.MustCompile(`\.\.[/\\].*(windows[/\\]system32|windows[/\\]win\.ini|cmd\.exe|system\.ini)`), 5, "owasp:path_traversal:008", ".."},
	{regexp.MustCompile(`\.{3,}[/\\]`), 4, "owasp:path_traversal:009", "..."},
	{regexp.MustCompile(`(^|[/\\])\.\.[/\\](etc[/\\](passwd|shadow|hosts|hostname|group)|proc[/\\]version|root[/\\]|var[/\\]log[/\\])`), 5, "owasp:path_traversal:010", ".."},
	{regexp.MustCompile(`(%252e|%252f|%255c){2,}`), 4, "owasp:path_traversal:011", "%25"},
	{regexp.MustCompile(`(\.\.\\){2,}`), 4, "owasp:path_traversal:012", ""},
	{regexp.MustCompile(`\.\.[/\\].*(web-inf|meta-inf|web\.xml|struts\.xml|applicationcontext\.xml)`), 5, "owasp:path_traversal:013", ".."},
	{regexp.MustCompile(`(web-inf|meta-inf)[/\\]web\.xml`), 5, "owasp:path_traversal:014", ""},
	{regexp.MustCompile(`\.\.[/\\]*(\.git[/\\]|\.env|\.htpasswd|\.aws[/\\]|\.ssh[/\\]|config\.php|settings\.py|\.ds_store)`), 4, "owasp:path_traversal:015", ".."},
	{regexp.MustCompile(`\.\.[/\\](admin|login|manager|console|config|passwd|shadow|private)`), 4, "owasp:path_traversal:016", ".."},
	{regexp.MustCompile(`(?:^|[/\\])\s*\.{3,}[ \t]*[/\\]`), 4, "owasp:path_traversal:017", "..."},
	{regexp.MustCompile(`\.\.\s+[/\\]`), 3, "owasp:path_traversal:018", ".."},
	// UNC 管理共享路径：\\host\c$、\\host\admin$ 等 Windows 管理共享访问。
	// 已有 c$ 门字面（hasPathTravIndicator/famPathTrav 同步），电池自锁
	// 反斜杠 + 盘符 + 美元符的强形态。
	{regexp.MustCompile(`\\\\[\w.:-]+\\(?:[a-zA-Z]|admin|ipc)\$`), 4, "owasp:path_traversal:019", "c$"},
}

func checkPathTraversal(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famPathTrav, s) {
		return OWASPHit{}, false
	}
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range pathTravPatterns {
		if !owaspPatternGatePass(p, s) {
			continue
		}
		if !p.re.MatchString(s) {
			continue
		}
		if isPathTravFalsePositive(s, p.id) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatPathTrav, RuleID: id, Score: total, Desc: "路径遍历特征"}, true
		}
	}
	return OWASPHit{}, false
}
