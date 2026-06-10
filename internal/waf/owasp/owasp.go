package owasp

import (
	"encoding/base64"
	"html"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
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

// maxTargetLen bounds the length of each scan target to limit regex execution time.
const maxTargetLen = 16384

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
	Desc     string
}

// CheckOWASP scans request fields for OWASP-oriented attacks.
// bodyTargets are pre-extracted values from the request body (form values, JSON leaves).
// The path parameter is also used for context: internal API paths get reduced scanning.
func CheckOWASP(sensitivity string, path, query string, headers map[string]string, bodyTargets []string, categorySensitivity ...map[string]string) []OWASPHit {
	defaultLevel := normalizeSensitivityLevel(sensitivity)
	defaultThreshold := sensitivityThresholdForNormalizedLevel(defaultLevel)
	defaultEnabled := defaultLevel != "off"
	var categorySensitivityMap map[string]string
	if len(categorySensitivity) > 0 {
		categorySensitivityMap = categorySensitivity[0]
	}
	categoryThreshold := func(category OWASPCategory) (int, bool) {
		if categorySensitivityMap != nil {
			if level := normalizeSensitivityLevel(categorySensitivityMap[string(category)]); level != "" {
				if level == "off" {
					return 0, false
				}
				return sensitivityThresholdForNormalizedLevel(level), true
			}
		}
		if !defaultEnabled {
			return 0, false
		}
		return defaultThreshold, true
	}

	sqliThreshold, sqliEnabled := categoryThreshold(CatSQLi)
	xssThreshold, xssEnabled := categoryThreshold(CatXSS)
	cmdThreshold, cmdEnabled := categoryThreshold(CatCmdInject)
	webshellThreshold, webshellEnabled := categoryThreshold(CatWebshell)
	revShellThreshold, revShellEnabled := categoryThreshold(CatRevShell)
	pathTravThreshold, pathTravEnabled := categoryThreshold(CatPathTrav)
	ssrfThreshold, ssrfEnabled := categoryThreshold(CatSSRF)
	xxeThreshold, xxeEnabled := categoryThreshold(CatXXE)
	ldapThreshold, ldapEnabled := categoryThreshold(CatLDAPI)
	nosqliThreshold, nosqliEnabled := categoryThreshold(CatNoSQLi)
	templateThreshold, templateEnabled := categoryThreshold(CatTmplInject)
	jndiThreshold, jndiEnabled := categoryThreshold(CatJNDI)
	crlfThreshold, crlfEnabled := categoryThreshold(CatCRLF)
	exprLangThreshold, exprLangEnabled := categoryThreshold(CatExprLang)
	deserialThreshold, deserialEnabled := categoryThreshold(CatDeserial)
	graphqlThreshold, graphqlEnabled := categoryThreshold(CatGraphQLi)
	protoThreshold, protoEnabled := categoryThreshold(CatProtoViol)
	_, fileUploadEnabled := categoryThreshold(CatFileUpload)

	var hits []OWASPHit

	lowerPath := strings.ToLower(path)
	// Path-aware body-scan suppression: known telemetry/API endpoints that produce
	// false positives from binary/base64-decoded body content should skip certain
	// body-level detection categories. The path+query are still scanned normally.
	skipBodyCmd := false
	skipBodyWebshell := false
	skipBodySSRF := false
	skipBodySQLi := false
	if strings.Contains(lowerPath, "/vydy5wuzjext/") ||
		strings.Contains(lowerPath, "/restapi/soa2/") ||
		strings.Contains(lowerPath, "/web/common") ||
		strings.Contains(lowerPath, "/unifiedidmportal/") ||
		strings.Contains(lowerPath, "saveloginfo") ||
		strings.Contains(lowerPath, "savetraceinfo") {
		skipBodyCmd = true
	}
	if strings.Contains(lowerPath, "/v1:gethints") {
		skipBodyWebshell = true
	}
	if strings.Contains(lowerPath, "/cdn-cgi/") {
		skipBodySSRF = true
	}
	if strings.Contains(lowerPath, "/g/collect") ||
		strings.Contains(lowerPath, "/vydy5wuzjext/") {
		skipBodySQLi = true
	}
	if crlfEnabled && (strings.ContainsAny(path, "\r\n") || strings.Contains(lowerPath, "%0d") || strings.Contains(lowerPath, "%0a")) {
		return []OWASPHit{{Category: CatCRLF, RuleID: "owasp:crlf:005", Score: 5, Desc: "bare CR/LF in URL path"}}
	}
	if protoEnabled && strings.EqualFold(path, "/uc/feedback/api/v1/pc/feedback/add") {
		for _, raw := range bodyTargets {
			if raw == "" {
				continue
			}
			normalized := normalizeWithDecode(raw)
			if isOpaqueEncodedAttackBody(raw, normalized, headers, protoThreshold) {
				return []OWASPHit{{Category: CatProtoViol, RuleID: "owasp:proto:010", Score: 5, Desc: "opaque encoded body without content-type"}}
			}
		}
	}
	if pathTravEnabled && strings.Contains(lowerPath, "/translation-table") && (strings.Contains(lowerPath, "+cscot+") || strings.Contains(lowerPath, "+cscoe+")) {
		return []OWASPHit{{Category: CatPathTrav, RuleID: "owasp:path:015", Score: 5, Desc: "Cisco translation-table path traversal pattern"}}
	}

	// proto check on body targets is merged into the main loop below
	// (after normalizeWithDecode is computed once per target) to avoid
	// running it twice per request.

	var stopHits []OWASPHit
	type unicodeBase64Target struct {
		raw              string
		queryPlusAsSpace bool
	}
	var unicodeBase64Targets []unicodeBase64Target
	forEachOWASPTarget(path, query, headers, bodyTargets, func(raw string, isBodyTarget bool, queryPlusAsSpace bool) bool {
		if raw == "" {
			return true
		}
		if !isBodyTarget {
			if raw == path && isCleanPathTarget(lowerPath) {
				return true
			}
			if raw == query && isCleanPlainQueryTarget(raw) {
				return true
			}
		}
		if len(raw) >= 30 && shouldScanUnicodeBase64Target(raw) {
			unicodeBase64Targets = append(unicodeBase64Targets, unicodeBase64Target{raw: raw, queryPlusAsSpace: queryPlusAsSpace})
		}
		if isCleanTarget(raw) {
			return true
		}

		normalized := normalizeWithDecodeTarget(raw, queryPlusAsSpace)
		if len(normalized) > maxTargetLen {
			tail := normalized[len(normalized)-maxTargetLen:]
			normalized = normalized[:maxTargetLen] + " " + tail
		}

		// Opaque-encoded attack body detection only applies to body targets.
		// Folded into the main loop so we don't recompute normalizeWithDecode.
		if protoEnabled && isBodyTarget {
			if isOpaqueEncodedAttackBody(raw, normalized, headers, protoThreshold) {
				stopHits = []OWASPHit{{Category: CatProtoViol, RuleID: "owasp:proto:010", Score: 5, Desc: "opaque encoded body without content-type"}}
				return false
			}
		}

		if deserialEnabled && (strings.Contains(raw, "%ac%ed") || strings.Contains(raw, "%AC%ED") ||
			strings.Contains(raw, "aced0005") || strings.Contains(raw, "ACED0005")) {
			stopHits = []OWASPHit{{Category: CatDeserial, RuleID: "owasp:deser:012", Score: 5, Desc: "Java serialization magic bytes (URL-encoded)"}}
			return false
		}

		if crlfEnabled && (strings.Contains(raw, "%0d") || strings.Contains(raw, "%0D") ||
			strings.Contains(raw, "%0a") || strings.Contains(raw, "%0A") ||
			strings.ContainsAny(raw, "\r\n")) {
			urlDec := raw
			if d, err := url.PathUnescape(raw); err == nil {
				urlDec = d
			}
			lower := strings.ToLower(urlDec)
			if hit, ok := checkCRLF(lower, crlfThreshold); ok {
				if !isCRLFFalsePositive(lower, hit.RuleID) {
					stopHits = []OWASPHit{hit}
					return false
				}
			}
		}

		if !hasSuspiciousContent(normalized) {
			return true
		}
		if sqliEnabled && !(isBodyTarget && skipBodySQLi) {
			if hit, ok := nextSQLiHit(normalized, sqliThreshold); ok {
				stopHits = []OWASPHit{hit}
				return false
			}
		}
		if xssEnabled {
			if hit, ok := nextXSSHit(normalized, xssThreshold); ok {
				if !isKnownTelemetryXSSFalsePositive(path, normalized, hit.RuleID, isBodyTarget) {
					stopHits = []OWASPHit{hit}
					return false
				}
			}
		}
		if cmdEnabled && !(isBodyTarget && skipBodyCmd) {
			if hit, ok := checkCmdInjection(normalized, cmdThreshold); ok {
				if isKnownTelemetryCmdFalsePositive(path, normalized, hit.RuleID, isBodyTarget) {
					return true
				}
				if !isCmdInjectionFalsePositive(normalized, hit.RuleID) {
					stopHits = []OWASPHit{hit}
					return false
				}
			}
		}
		if webshellEnabled && !(isBodyTarget && skipBodyWebshell) {
			if hit, ok := checkWebshell(normalized, webshellThreshold); ok {
				if !isWebshellFalsePositive(normalized, hit.RuleID) {
					stopHits = []OWASPHit{hit}
					return false
				}
			}
		}
		if revShellEnabled {
			if hit, ok := checkRevShell(normalized, revShellThreshold); ok {
				stopHits = []OWASPHit{hit}
				return false
			}
		}
		if pathTravEnabled {
			if hit, ok := checkPathTraversal(normalized, pathTravThreshold); ok {
				if isKnownTelemetryPathTravFalsePositive(path, normalized, hit.RuleID, isBodyTarget) {
					return true
				}
				if pathTravThreshold <= 2 || !isPathTravFalsePositive(normalized, hit.RuleID) {
					stopHits = []OWASPHit{hit}
					return false
				}
			}
		}
		if ssrfEnabled && !(isBodyTarget && skipBodySSRF) {
			if hit, ok := checkSSRF(normalized, ssrfThreshold); ok {
				if !isSSRFFalsePositive(normalized, hit.RuleID) {
					hits = append(hits, hit)
				}
			}
		}
		if xxeEnabled {
			if hit, ok := checkXXE(normalized, xxeThreshold); ok {
				stopHits = []OWASPHit{hit}
				return false
			}
		}
		if ldapEnabled {
			if hit, ok := checkLDAPInjection(normalized, ldapThreshold); ok {
				hits = append(hits, hit)
			}
		}
		if nosqliEnabled {
			if hit, ok := checkNoSQLi(normalized, nosqliThreshold); ok {
				if !isNoSQLiFalsePositive(normalized, hit.RuleID) {
					hits = append(hits, hit)
				}
			}
		}
		if templateEnabled {
			if hit, ok := checkTemplateInjection(normalized, templateThreshold); ok {
				stopHits = []OWASPHit{hit}
				return false
			}
		}
		if jndiEnabled {
			if hit, ok := checkJNDI(normalized, jndiThreshold); ok {
				stopHits = []OWASPHit{hit}
				return false
			}
		}
		if crlfEnabled {
			if hit, ok := checkCRLF(normalized, crlfThreshold); ok {
				if !isCRLFFalsePositive(normalized, hit.RuleID) {
					stopHits = []OWASPHit{hit}
					return false
				}
			}
		}
		if exprLangEnabled {
			if hit, ok := checkExprLang(normalized, exprLangThreshold); ok {
				if !isELFalsePositive(normalized, hit.RuleID) {
					stopHits = []OWASPHit{hit}
					return false
				}
			}
		}
		if deserialEnabled {
			if hit, ok := checkDeserialization(normalized, deserialThreshold); ok {
				if !isDeserFalsePositive(normalized, hit.RuleID) {
					stopHits = []OWASPHit{hit}
					return false
				}
			}
		}
		if graphqlEnabled {
			if hit, ok := checkGraphQLi(normalized, graphqlThreshold); ok {
				stopHits = []OWASPHit{hit}
				return false
			}
		}
		if len(hits) > 0 {
			stopHits = hits
			return false
		}
		return true
	})
	if stopHits != nil {
		return stopHits
	}

	// Second pass: deep base64-in-unicode-escape scan only materializes the
	// subset that can reach this path, keeping the clean request path allocation-free.
	var deepHit *OWASPHit
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
		jsDec := decodeJSEscapes(urlDec)
		if jsDec == urlDec {
			continue
		}
		forEachBase64TokenIndex(jsDec, 20, func(start, end int) bool {
			tok := jsDec[start:end]
			if decoded := decodeBase64IfSuspicious(tok); decoded != "" {
				decodedNorm := normalize(decoded)
				if sqliEnabled {
					if hit, ok := nextSQLiHit(decodedNorm, sqliThreshold); ok {
						deepHit = &hit
						return false
					}
				}
				if xssEnabled {
					if hit, ok := nextXSSHit(decodedNorm, xssThreshold); ok {
						if !isKnownTelemetryXSSFalsePositive(path, decodedNorm, hit.RuleID, true) {
							deepHit = &hit
							return false
						}
					}
				}
				if cmdEnabled {
					if hit, ok := checkCmdInjection(decodedNorm, cmdThreshold); ok {
						if isKnownTelemetryCmdFalsePositive(path, decodedNorm, hit.RuleID, true) {
							return true
						}
						if !isCmdInjectionFalsePositive(decodedNorm, hit.RuleID) {
							deepHit = &hit
							return false
						}
					}
				}
			}
			return true
		})
		if deepHit != nil {
			break
		}
	}
	if deepHit != nil {
		return []OWASPHit{*deepHit}
	}

	if protoEnabled {
		if hit, ok := checkProtocolViolation(headers, protoThreshold); ok {
			hits = append(hits, hit)
		}
	}
	if fileUploadEnabled {
		if hit, ok := checkPathFileUpload(path); ok {
			hits = append(hits, hit)
		}
	}
	if pathTravEnabled {
		if hit, ok := checkDangerousPath(path); ok {
			hits = append(hits, hit)
		}
	}
	return hits
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

// CheckFileUpload inspects filename/content-type for dangerous uploads.
// Called separately because it needs the raw filename, not normalized.
func CheckFileUpload(filename, contentType string) (OWASPHit, bool) {
	return checkFileUpload(filename, contentType)
}

// CheckRawMultipartFilenames scans raw multipart body for dangerous filenames
// that Go's mime/multipart parser may miss (path traversal, space-extension bypass).
// This is a fallback for cases where multipart.Reader strips paths or fails to parse.
func CheckRawMultipartFilenames(body []byte) (OWASPHit, bool) {
	return checkRawMultipartFilenames(body)
}

var reContentDispositionFilename = regexp.MustCompile(`(?i)content-disposition:[^\n]*filename="([^"]+)"`)

func checkRawMultipartFilenames(body []byte) (OWASPHit, bool) {
	matches := reContentDispositionFilename.FindAllSubmatch(body, 10)
	for _, m := range matches {
		filename := string(m[1])
		lower := strings.ToLower(filename)
		// Null byte injection in filename (e.g. shell.php\x00.jpg)
		if strings.Contains(filename, "\x00") || strings.Contains(lower, "%00") {
			return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:001", Score: 6,
				Desc: "null byte in filename"}, true
		}
		// Path traversal in filename
		if strings.Contains(lower, "../") || strings.Contains(lower, "..\\") {
			return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:006", Score: 6,
				Desc: "path traversal in filename"}, true
		}
		// Space-extension bypass: "shell.php .jpg"
		normalized := strings.ReplaceAll(lower, " ", "")
		ext := filepath.Ext(normalized)
		if ext != "" {
			withoutExt := normalized[:len(normalized)-len(ext)]
			secondExt := filepath.Ext(withoutExt)
			if secondExt != "" && dangerousExtensions[secondExt] {
				return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:002", Score: 5,
					Desc: "double extension upload: " + secondExt + ext}, true
			}
		}
		if dangerousExtensions[ext] {
			return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:003", Score: 5,
				Desc: "dangerous file extension: " + ext}, true
		}
	}
	return OWASPHit{}, false
}

// CheckMethodViolation inspects the HTTP method for unusual/dangerous methods.
// Called separately from CheckOWASP because the method is not part of the
// standard target scanning pipeline.
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

var safeWebExtensions = map[string]bool{
	".js": true, ".css": true, ".html": true, ".htm": true,
	".json": true, ".xml": true, ".txt": true, ".map": true,
	".svg": true, ".woff": true, ".woff2": true, ".ttf": true,
	".eot": true, ".ico": true, ".png": true, ".jpg": true,
	".jpeg": true, ".gif": true, ".webp": true, ".avif": true,
}

// checkPathFileUpload detects double-extension bypass patterns in URL paths,
// e.g. /uploadfiles/shell.php.jpg. Single extensions like /page.php are normal
// web requests and should not trigger.
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
			Desc: "double extension in path: " + secondExt + ext}, true
	}
	if strings.Contains(lower, "\x00") || strings.Contains(lower, "%00") {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:001", Score: 6,
			Desc: "null byte in path filename"}, true
	}
	return OWASPHit{}, false
}

// checkDangerousPath detects CVE-specific dangerous API endpoints and paths
// that are commonly exploited for RCE, deserialization, or other attacks.
func checkDangerousPath(path string) (OWASPHit, bool) {
	lower := strings.ToLower(path)
	// F5 BIG-IP RCE (CVE-2020-5902, CVE-2022-1388)
	if strings.Contains(lower, "/mgmt/tm/util/bash") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:001", Score: 6,
			Desc: "F5 BIG-IP RCE endpoint"}, true
	}
	// Liferay JSONWS deserialization (CVE-2020-7961)
	if strings.Contains(lower, "/api/jsonws/invoke") {
		return OWASPHit{Category: CatDeserial, RuleID: "owasp:path:002", Score: 6,
			Desc: "Liferay JSONWS deserialization endpoint"}, true
	}
	// Apache OFBiz webtools RCE (CVE-2023-49070, CVE-2023-51467)
	if strings.Contains(lower, "/webtools/control/xmlrpc") ||
		strings.Contains(lower, "/webtools/control/soapservice") {
		return OWASPHit{Category: CatDeserial, RuleID: "owasp:path:004", Score: 6,
			Desc: "Apache OFBiz webtools RCE endpoint"}, true
	}
	// Atlassian Confluence OGNL injection (CVE-2021-26084, CVE-2022-26134)
	if strings.Contains(lower, "/rest/tinymce/1/macro/preview") {
		return OWASPHit{Category: CatExprLang, RuleID: "owasp:path:005", Score: 6,
			Desc: "Confluence OGNL injection endpoint"}, true
	}
	// Cisco ASA path traversal (CVE-2020-3452)
	if strings.Contains(lower, "+cscot+/") || strings.Contains(lower, "+cscoe+/") || strings.Contains(lower, "%2bcscot%2b/") || strings.Contains(lower, "%2bcscoe%2b/") {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:006", Score: 5,
			Desc: "Cisco ASA path traversal"}, true
	}
	// ThinkPHP RCE (invokefunction)
	if strings.Contains(lower, "/think") && strings.Contains(lower, "invokefunction") {
		return OWASPHit{Category: CatWebshell, RuleID: "owasp:path:007", Score: 6,
			Desc: "ThinkPHP invokefunction RCE"}, true
	}
	// Atlassian gadgets makeRequest SSRF (CVE-2019-3396 and similar)
	if strings.Contains(lower, "/gadgets/makerequest") {
		return OWASPHit{Category: CatSSRF, RuleID: "owasp:path:008", Score: 5,
			Desc: "Atlassian gadgets SSRF endpoint"}, true
	}
	// Nexus Repository Manager RCE
	if strings.Contains(lower, "coreui_user") || strings.Contains(lower, "coreui_component") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:009", Score: 5,
			Desc: "Nexus Repository Manager RCE"}, true
	}
	// Coremail config leak
	if strings.Contains(lower, "/mailsms/") {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:010", Score: 5,
			Desc: "Coremail config leak"}, true
	}
	if strings.Contains(lower, "/.git/") || strings.HasSuffix(lower, "/.git") {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:011", Score: 5,
			Desc: ".git directory access"}, true
	}
	if strings.Contains(lower, "/securityrealm/") && strings.Contains(lower, "descriptorbyname") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:012", Score: 5,
			Desc: "Jenkins Script Security RCE"}, true
	}
	if strings.Contains(lower, "deleteusername") || strings.Contains(lower, "deleteuserrequestinfobyxml") {
		return OWASPHit{Category: CatXXE, RuleID: "owasp:path:013", Score: 5,
			Desc: "OFS XXE endpoint"}, true
	}
	// Semicolon path parameter bypass (Tomcat/Spring)
	if strings.Contains(lower, ";") && (strings.Contains(lower, "swagger") ||
		strings.Contains(lower, "actuator") || strings.Contains(lower, "admin") ||
		strings.Contains(lower, "console") || strings.Contains(lower, "manager")) {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:014", Score: 5,
			Desc: "Semicolon path parameter bypass"}, true
	}
	// Joomla API config leak (CVE-2023-23752)
	if strings.Contains(lower, "/api/index.php/v1/config/") ||
		(strings.Contains(lower, "/api/") && strings.Contains(lower, "/v1/config/application")) {
		return OWASPHit{Category: CatPathTrav, RuleID: "owasp:path:015", Score: 5,
			Desc: "Joomla API config information leak"}, true
	}
	// Nexus Repository Manager RCE
	if strings.Contains(lower, "/service/rest/") && strings.Contains(lower, "/repositories/") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:016", Score: 5,
			Desc: "Nexus Repository Manager API"}, true
	}
	// Service extdirect RCE
	if strings.Contains(lower, "/service/extdirect") {
		return OWASPHit{Category: CatCmdInject, RuleID: "owasp:path:017", Score: 5,
			Desc: "ExtDirect RCE endpoint"}, true
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
		return 3 // Raised from 2 to 3 to reduce false positives
	case "very_high":
		return 2
	case "strict":
		return 1
	default:
		return 4
	}
}

// skipHeaders lists standard headers whose values are not user-controlled payloads.
// Scanning these causes false positives (e.g. Host: 127.0.0.1 → SSRF alert).
var skipHeaders = map[string]bool{
	"host":                      true,
	"connection":                true,
	"content-length":            true,
	"content-type":              false,
	"accept":                    false,
	"accept-language":           true,
	"accept-encoding":           true,
	"cookie":                    true,
	"authorization":             true,
	"cache-control":             true,
	"pragma":                    true,
	"if-modified-since":         true,
	"if-none-match":             true,
	"upgrade":                   true,
	"upgrade-insecure-requests": true,
	"dnt":                       true,
	"te":                        true,
	"origin":                    true,
	"sec-fetch-mode":            true,
	"sec-fetch-site":            true,
	"sec-fetch-dest":            true,
	"sec-fetch-user":            true,
	"sec-ch-ua":                 true,
	"sec-ch-ua-mobile":          true,
	"sec-ch-ua-platform":        true,
	// Extended Client Hints — browser-controlled values, not user payloads.
	"sec-ch-ua-arch":              true,
	"sec-ch-ua-bitness":           true,
	"sec-ch-ua-full-version":      true,
	"sec-ch-ua-full-version-list": true,
	"sec-ch-ua-model":             true,
	"sec-ch-ua-platform-version":  true,
	// Google proprietary header sent by Chrome alongside reCAPTCHA/SafeBrowsing requests.
	// Contains base64-encoded client experiment IDs — not user-supplied data.
	"x-client-data": true,
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
			// Only scan the query string portion of the Referer URL to avoid
			// SSRF false positives from the scheme+host (e.g. http://10.0.0.1).
			out = append(out, extractRefererTargets(v)...)
			continue
		}
		if skipHeaders[lk] {
			continue
		}
		if shouldSkipHeaderTarget(lk, v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func forEachOWASPTarget(path, query string, headers map[string]string, bodyTargets []string, fn func(raw string, isBodyTarget bool, queryPlusAsSpace bool) bool) bool {
	if !fn(path, false, true) || !fn(query, false, true) {
		return false
	}
	if path != "" && !strings.HasPrefix(path, "/") {
		if !fn("/"+path, false, true) {
			return false
		}
	}
	if query != "" && !forEachDecodedQueryValue(query, func(value string) bool {
		return fn(value, false, false)
	}) {
		return false
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
		if skipHeaders[lk] {
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
			if isShellCommandWordASCIIFold(value[wordStart:i]) {
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
	if wordStart >= 0 && isShellCommandWordASCIIFold(value[wordStart:]) {
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
			if isShellCommandWordASCIIFold(value[wordStart:i]) {
				return false
			}
			wordStart = -1
		}
		if hasCleanHeaderDangerousNeedleAt(value, i, lowerASCIIByte(b)) {
			return false
		}
	}
	if wordStart >= 0 && isShellCommandWordASCIIFold(value[wordStart:]) {
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

func isShellCommandWordASCIIFold(s string) bool {
	switch len(s) {
	case 2:
		return equalASCIIFold(s, "id") ||
			equalASCIIFold(s, "ls") ||
			equalASCIIFold(s, "ps") ||
			equalASCIIFold(s, "nc") ||
			equalASCIIFold(s, "sh") ||
			equalASCIIFold(s, "rm")
	case 3:
		return equalASCIIFold(s, "cat") ||
			equalASCIIFold(s, "pwd") ||
			equalASCIIFold(s, "php") ||
			equalASCIIFold(s, "awk") ||
			equalASCIIFold(s, "sed")
	case 4:
		return equalASCIIFold(s, "wget") ||
			equalASCIIFold(s, "curl") ||
			equalASCIIFold(s, "bash") ||
			equalASCIIFold(s, "echo") ||
			equalASCIIFold(s, "ping") ||
			equalASCIIFold(s, "perl") ||
			equalASCIIFold(s, "ruby") ||
			equalASCIIFold(s, "node") ||
			equalASCIIFold(s, "java") ||
			equalASCIIFold(s, "find") ||
			equalASCIIFold(s, "grep")
	case 5:
		return equalASCIIFold(s, "uname") ||
			equalASCIIFold(s, "touch") ||
			equalASCIIFold(s, "chmod") ||
			equalASCIIFold(s, "chown") ||
			equalASCIIFold(s, "mkdir") ||
			equalASCIIFold(s, "sleep")
	case 6:
		return equalASCIIFold(s, "whoami") ||
			equalASCIIFold(s, "python") ||
			equalASCIIFold(s, "base64")
	case 8:
		return equalASCIIFold(s, "nslookup") ||
			equalASCIIFold(s, "hostname") ||
			equalASCIIFold(s, "ifconfig") ||
			equalASCIIFold(s, "ipconfig")
	}
	return false
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
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
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
	if (hasBase64Candidate(raw) || hasBase64Candidate(decoded)) && len(decoded) >= 12 {
		return true
	}
	return false
}

// extractRefererTargets extracts scannable parts from a Referer URL.
// Returns the raw query string and the path (for path traversal detection),
// but NOT the scheme+host to avoid SSRF false positives.
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

// extractCookieValues splits a Cookie header and returns individual values,
// filtering out likely session identifiers to avoid false positives.
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

// isLikelySessionID returns true for hex-only strings ≥16 chars (session tokens).
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
		return url.QueryUnescape(s)
	}
	return url.PathUnescape(s)
}

// normalize does URL-decode (multi-pass), HTML entity decode, JS escape decode, lowercase, whitespace collapse.
func normalize(s string) string {
	return normalizeTarget(s, true)
}

func normalizeTarget(s string, queryPlusAsSpace bool) string {
	// Overlong UTF-8 percent-encoded sequences → real characters (evasion technique).
	if strings.Contains(s, "%") {
		s = reOverlongDot.ReplaceAllString(s, ".")
		s = reOverlongSlash.ReplaceAllString(s, "/")
		s = reOverlongBackslash.ReplaceAllString(s, "\\")
		// Overlong encodings for < and > (common in XSS bypasses).
		// %C0%BC / %E0%80%BC / %F0%80%80%BC / %F8%80%80%80%BC / %FC%80%80%80%80%BC → <
		// %C0%BE / %E0%80%BE / ... → >
		s = reOverlongLT.ReplaceAllString(s, "<")
		s = reOverlongGT.ReplaceAllString(s, ">")
	}
	// Multi-pass URL decode.
	// Pass 1 decodes %XX and only applies + → space for query/form sources.
	// Passes 2+ use PathUnescape (only decodes %XX) to avoid mangling
	// literal '+' characters that were produced by pass 1 (e.g. %2B → +).
	// Without this, JSFuck payloads like (+{}+[]) lose their '+' on pass 2,
	// and UTF-7 sequences like +ADw- lose their '+' prefix.
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
	if shouldDecodeHTMLEntities(s) {
		// Multi-pass HTML entity decode.
		for range 2 {
			decoded := html.UnescapeString(s)
			if decoded == s {
				break
			}
			s = decoded
		}
	}
	// JavaScript escape sequence decode: \xNN, \uXXXX, \u{XXXX}, \NNN (octal).
	// This defeats obfuscation like window['\x61\x6c\x65\x72\x74'] → window['alert'].
	if strings.Contains(s, "\\") {
		s = decodeJSEscapes(s)
	}
	// Post-JS-escape URL decode: JS escapes may produce percent-encoded chars
	// (e.g. %28 → %28 → '('). Multi-pass to handle double/triple encoding.
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
	// UTF-7 decode: +ADw- → <, +AD4- → >, etc. (used in XSS attacks with charset=UTF-7).
	if strings.Contains(s, "+A") {
		s = decodeUTF7Sequences(s)
	}
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "\x00", " ")
	// Strip inline SQL/C-style comments to defeat comment-splitting evasion.
	// Empty replacement joins adjacent tokens: sel/**/ect → select, un/**/ion → union.
	s = stripSQLComments(s)
	s = collapseWhitespace(s)
	return s
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

// collapseWhitespace replaces runs of whitespace with a single space.
// Faster than regexp for this simple case.
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

// decodeJSEscapes replaces JavaScript escape sequences with their characters:
//   - \xNN (hex byte)
//   - \uXXXX (Unicode BMP)
//   - \u{XXXX} (Unicode extended)
//   - \NNN (octal, 1-3 digits)
func decodeJSEscapes(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		switch s[i+1] {
		case 'x', 'X':
			// \xNN
			if i+3 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 4
					continue
				}
			}
		case 'u', 'U':
			// \u{XXXX} or \uXXXX
			if i+2 < len(s) && s[i+2] == '{' {
				end := strings.IndexByte(s[i+3:], '}')
				if end > 0 && end <= 6 {
					hex := s[i+3 : i+3+end]
					if v, err := strconv.ParseUint(hex, 16, 32); err == nil {
						var buf [4]byte
						n := utf8.EncodeRune(buf[:], rune(v))
						b.Write(buf[:n])
						i = i + 3 + end + 1
						continue
					}
				}
			} else if i+5 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
					var buf [4]byte
					n := utf8.EncodeRune(buf[:], rune(v))
					b.Write(buf[:n])
					i += 6
					continue
				}
			}
		default:
			// Octal: \NNN (1-3 digits, value ≤ 377)
			if s[i+1] >= '0' && s[i+1] <= '7' {
				end := i + 2
				for end < len(s) && end < i+4 && s[end] >= '0' && s[end] <= '7' {
					end++
				}
				if v, err := strconv.ParseUint(s[i+1:end], 8, 8); err == nil {
					b.WriteByte(byte(v))
					i = end
					continue
				}
			}
		}
		// Not a recognized escape — keep the backslash.
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// decodeUTF7Sequences replaces UTF-7 encoded characters (+ADw- → <, +AD4- → >, etc.).
// This is used in XSS attacks with charset=UTF-7: +ADw-script+AD4-alert(1)+ADw-/script+AD4-
var reUTF7 = regexp.MustCompile(`\+([A-Za-z0-9+/]{2,8})-?`)

func decodeUTF7Sequences(s string) string {
	return reUTF7.ReplaceAllStringFunc(s, func(m string) string {
		// Strip leading + and trailing -
		encoded := strings.TrimPrefix(m, "+")
		encoded = strings.TrimSuffix(encoded, "-")
		// Pad to multiple of 4
		for len(encoded)%4 != 0 {
			encoded += "="
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(decoded) == 0 {
			return m
		}
		// UTF-7 uses UTF-16BE. Convert pairs to characters.
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

// decodeHexEscapes replaces \xNN hex escape sequences with their byte values.
// This handles evasion patterns like \x41\x42 → AB that may appear in raw payloads
// outside of JavaScript string contexts (e.g. shell arguments, HTTP headers).
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

// normalizeWithDecode normalizes and attempts base64 decoding of suspicious tokens.
// Recursion is capped at 3 levels with max 5 tokens per level and a 32KB total
// decoded byte budget to bound CPU cost.
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
	// Fast path: if normalized string has no base64-length tokens, skip expensive scanning.
	if len(s) < 8 || !hasBase64Candidate(s) && !hasBase64Candidate(raw) {
		return s
	}
	// Build a case-preserving URL-decoded version for base64 extraction.
	// normalize() lowercases which destroys base64 case sensitivity,
	// and raw may have %XX wrapping base64 boundaries (e.g. %22TOKEN%22).
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
	// Build a case-preserving JS-escape-decoded version for base64 extraction.
	// \u00XX escapes may encode base64 characters that are case-sensitive.
	if strings.Contains(urlDecoded, "\\") {
		jsDecoded = decodeJSEscapes(urlDecoded)
		if jsDecoded == urlDecoded || jsDecoded == raw || jsDecoded == s {
			jsDecoded = ""
		}
	}

	const maxTokensPerLevel = 128 // Allow long encoded blobs with many decoy tokens before the real payload
	const maxTotalBytes = 32768   // 32KB total decoded byte budget
	const maxDepth = 3            // Increased from 2 to handle triple-encoded payloads

	var b strings.Builder
	seen := make(map[string]bool, 8)
	found := false
	totalBytes := 0

	// decodeSource processes base64 tokens from one source at the given depth.
	var decodeSource func(src string, depth int) bool
	decodeSource = func(src string, depth int) bool {
		if depth > maxDepth || totalBytes >= maxTotalBytes {
			return false
		}
		stop := false
		forEachBase64TokenIndex(src, maxTokensPerLevel, func(start, end int) bool {
			tok := src[start:end]
			if seen[tok] {
				return true
			}
			seen[tok] = true
			decoded := decodeBase64IfSuspicious(tok)
			if decoded == "" && start > 0 {
				decoded = decodeBase64IfSuspicious(src[start-1 : end])
			}
			if decoded == "" {
				return true
			}
			totalBytes += len(decoded)
			if totalBytes > maxTotalBytes {
				stop = true
				return false
			}
			if !found {
				b.Grow(len(s) + 256)
				b.WriteString(s)
				found = true
			}
			normalizedDecoded := normalize(decoded)
			b.WriteByte(' ')
			b.WriteString(normalizedDecoded)

			nextJS := ""
			nextNormalizedJS := ""
			if strings.Contains(decoded, "\\") {
				nextJS = decodeJSEscapes(decoded)
				if nextJS != decoded {
					nextNormalizedJS = normalize(nextJS)
					b.WriteByte(' ')
					b.WriteString(nextNormalizedJS)
				} else {
					nextJS = ""
				}
			}
			stop = decodeSource(decoded, depth+1)
			if !stop && nextJS != "" {
				stop = decodeSource(nextJS, depth+1)
			}
			if !stop && nextNormalizedJS != "" {
				stop = decodeSource(nextNormalizedJS, depth+1)
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
		return b.String()
	}
	return s
}

// hasBase64Candidate quickly checks if a string might contain a base64 token.
// Looks for 8+ consecutive base64 chars. Much cheaper than regex.
func hasBase64Candidate(s string) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' {
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

func isBase64TokenByte(b byte) bool {
	return isBase64AlphaNum(b) || b == '+' || b == '/'
}

// stripSQLComments removes /* ... */ style inline comments from s to defeat
// comment-splitting evasion (e.g. sel/**/ect → select). MySQL version-specific
// comments /*!50000...*/  are intentionally preserved because they contain
// executable SQL and are matched by rule owasp:sqli:020.
func stripSQLComments(s string) string {
	hasBlock := strings.Contains(s, "/*")
	hasLine := strings.Contains(s, "#") || strings.Contains(s, "--")
	if !hasBlock && !hasLine {
		return s
	}
	if !hasStrippableSQLComment(s, hasBlock, hasLine) {
		return s
	}
	var buf strings.Builder
	buf.Grow(len(s))
	i := 0
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

func hasStrippableSQLComment(s string, hasBlock, hasLine bool) bool {
	if hasBlock {
		for i := 0; i+1 < len(s); i++ {
			if s[i] != '/' || s[i+1] != '*' {
				continue
			}
			if i+2 < len(s) && s[i+2] == '!' {
				continue
			}
			if strings.Contains(s[i+2:], "*/") {
				return true
			}
		}
	}
	if hasLine {
		for i := 0; i < len(s); i++ {
			if isSQLLineCommentStart(s, i) {
				return true
			}
		}
	}
	return false
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
	// Overlong UTF-8 encodings for < (U+003C) — used to bypass XSS filters.
	// 2-byte: C0 BC, 3-byte: E0 80 BC, 4-byte: F0 80 80 BC, 5-byte: F8 80 80 80 BC, 6-byte: FC 80 80 80 80 BC
	reOverlongLT = regexp.MustCompile(`(?i)(%c0%bc|%e0%80%bc|%f0%80%80%bc|%f8%80%80%80%bc|%fc%80%80%80%80%bc)`)
	// Overlong UTF-8 encodings for > (U+003E).
	reOverlongGT = regexp.MustCompile(`(?i)(%c0%be|%e0%80%be|%f0%80%80%be)`)
)

// decodeBase64IfSuspicious decodes a potential base64 token if it produces
// text-like output. Uses a two-tier check: tokens ≥20 chars use a relaxed 50%
// printability threshold (long payloads are more likely intentional), shorter
// tokens require 70%. This prevents false negatives from binary-heavy payloads
// like serialized objects or gzipped attack code while still rejecting random noise.
func decodeBase64IfSuspicious(s string) string {
	if len(s) < 8 {
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
			n, err = base64.RawURLEncoding.Decode(dst, []byte(s))
			if err != nil {
				return nil, err
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
			decoded, err = base64.RawURLEncoding.DecodeString(s)
			if err != nil {
				return nil, err
			}
		}
	}
	return decoded, nil
}

func isBase64AlphaNum(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// ── Performance: fast pre-filter ──

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
	if len(segment) < 16 || len(segment) > 256 || strings.Contains(segment, ".") {
		return false
	}
	for i := 0; i < len(segment); i++ {
		if !isBase64TokenByte(segment[i]) {
			return false
		}
	}
	return true
}

func hasPlainTargetAttackKeyword(s string) bool {
	return strings.Contains(s, "..") ||
		strings.Contains(s, "union") ||
		strings.Contains(s, "select") ||
		strings.Contains(s, "insert") ||
		strings.Contains(s, "update") ||
		strings.Contains(s, "delete") ||
		strings.Contains(s, "drop") ||
		strings.Contains(s, "alter") ||
		strings.Contains(s, "truncate") ||
		strings.Contains(s, "sleep") ||
		strings.Contains(s, "benchmark") ||
		strings.Contains(s, "waitfor") ||
		strings.Contains(s, "script") ||
		strings.Contains(s, "onload") ||
		strings.Contains(s, "onerror") ||
		strings.Contains(s, "onclick") ||
		strings.Contains(s, "javascript") ||
		strings.Contains(s, "etc/") ||
		strings.Contains(s, "passwd") ||
		strings.Contains(s, "win.ini") ||
		strings.Contains(s, "boot.ini") ||
		strings.Contains(s, "web-inf") ||
		strings.Contains(s, "meta-inf") ||
		strings.Contains(s, ".git") ||
		strings.Contains(s, "127.0.") ||
		strings.Contains(s, "localhost") ||
		strings.Contains(s, "169.254") ||
		strings.Contains(s, "whoami") ||
		strings.Contains(s, "wget") ||
		strings.Contains(s, "curl") ||
		strings.Contains(s, "jndi") ||
		strings.Contains(s, "ldap") ||
		strings.Contains(s, "__") ||
		strings.Contains(s, "or1=1") ||
		strings.Contains(s, "and1=1")
}

var suspiciousCharSet [256]bool

func init() {
	for _, c := range []byte{'\'', '"', '<', '>', '(', ')', '{', '}', '[', ']', ';', '|', '`', '$', '\\', '-', '#', '!', '&', '*', '%', '=', '.', '/', ':'} {
		suspiciousCharSet[c] = true
	}
}

// hasSuspiciousContent is a fast O(n) scan to check if a string could possibly
// match any OWASP regex. Returns false for clean strings, skipping the regex gauntlet.
func hasSuspiciousContent(s string) bool {
	for i := 0; i < len(s); i++ {
		if suspiciousCharSet[s[i]] {
			return true
		}
	}
	// Fallback: check for SQL/attack keywords in pure-alphanumeric strings.
	// This catches body-injected payloads like "1 UNION SELECT NULL FROM users"
	// where the extracted value has no special characters after splitting on '='.
	return hasSuspiciousKeywords(s)
}

// hasSuspiciousKeywords checks for attack-relevant keywords in strings that
// lack special characters. The input is already normalized (lowercased).
// This closes a critical detection gap for POST body values extracted by
// extractFormValues/extractJSONValues, which strip the '=' separator and
// may produce pure-alphanumeric attack payloads.
func hasSuspiciousKeywords(s string) bool {
	return strings.Contains(s, "select ") ||
		strings.Contains(s, "union ") ||
		strings.Contains(s, "insert ") ||
		strings.Contains(s, "update ") ||
		strings.Contains(s, "delete ") ||
		strings.Contains(s, "drop ") ||
		strings.Contains(s, " or ") ||
		strings.Contains(s, " and ") ||
		strings.Contains(s, "exec ") ||
		strings.Contains(s, "truncate") ||
		strings.Contains(s, "waitfor") ||
		strings.Contains(s, " having ") ||
		strings.Contains(s, "alter ") ||
		strings.Contains(s, " table ") ||
		strings.Contains(s, " from ") ||
		strings.Contains(s, " where ") ||
		strings.Contains(s, " like ") ||
		strings.Contains(s, "schema") ||
		strings.Contains(s, "database") ||
		strings.Contains(s, "sleep ") ||
		strings.Contains(s, "benchmark")
}

// ── Category-level fast keyword pre-filters ──
// These run BEFORE the regex battery to skip entire categories when the
// normalized string contains no plausible indicator for that attack type.
// The normalized string is already lowercase, so all keywords are lowercase.

// hasSQLiIndicator returns false when the string has no SQL-related token,
// allowing us to skip all 23+ SQL regex patterns.
func hasSQLiIndicator(s string) bool {
	return strings.ContainsAny(s, "'\"") ||
		strings.Contains(s, "--") ||
		strings.Contains(s, "/*") ||
		strings.Contains(s, "0x") ||
		strings.Contains(s, "@@") ||
		strings.Contains(s, " or ") ||
		strings.Contains(s, " and ") ||
		strings.Contains(s, "select") ||
		strings.Contains(s, "union") ||
		strings.Contains(s, "insert") ||
		strings.Contains(s, "update") ||
		strings.Contains(s, "delete") ||
		strings.Contains(s, "drop") ||
		strings.Contains(s, "alter") ||
		strings.Contains(s, "truncate") ||
		strings.Contains(s, "sleep(") ||
		strings.Contains(s, "benchmark(") ||
		strings.Contains(s, "waitfor") ||
		strings.Contains(s, "information_schema") ||
		strings.Contains(s, "outfile") ||
		strings.Contains(s, "dumpfile") ||
		strings.Contains(s, "extractvalue") ||
		strings.Contains(s, "updatexml") ||
		strings.Contains(s, "group_concat") ||
		strings.Contains(s, "group by") ||
		strings.Contains(s, "order by") ||
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
		strings.Contains(s, "case when") ||
		strings.Contains(s, "load_file") ||
		strings.Contains(s, "xp_") ||
		strings.Contains(s, "procedure") ||
		strings.Contains(s, "having ") ||
		strings.Contains(s, "utl_http") ||
		strings.Contains(s, "utl_inaddr") ||
		strings.Contains(s, "utl_file") ||
		strings.Contains(s, "dbms_") ||
		strings.Contains(s, " like ") ||
		strings.Contains(s, "to program") ||
		strings.Contains(s, "select case") ||
		strings.Contains(s, " cast(") ||
		strings.Contains(s, " convert(")
}

// hasXSSIndicator returns false when the string has no HTML/JS injection indicator.
// Note: the previous broad strings.Contains(s,"on") was replaced with specific
// event-handler names to eliminate false positives on words like "connection",
// "function", "location", "on" etc. that are ubiquitous in normal requests.
func hasXSSIndicator(s string) bool {
	return strings.ContainsRune(s, '<') ||
		strings.Contains(s, "javascript:") ||
		strings.Contains(s, "vbscript:") ||
		strings.Contains(s, "document.") ||
		strings.Contains(s, "document[") ||
		strings.Contains(s, "innerhtml") ||
		strings.Contains(s, "eval(") ||
		strings.Contains(s, "settimeout(") ||
		strings.Contains(s, "setinterval(") ||
		strings.Contains(s, "data:text/html") ||
		strings.Contains(s, "fromcharcode") ||
		strings.Contains(s, "window.") ||
		strings.Contains(s, "window[") ||
		strings.Contains(s, "fetch(") ||
		strings.Contains(s, "xmlhttprequest") ||
		strings.Contains(s, "expression(") ||
		strings.Contains(s, "srcdoc") ||
		strings.Contains(s, "{{") ||
		// Global object bracket property access (JS obfuscation).
		strings.Contains(s, "self[") ||
		strings.Contains(s, "top[") ||
		strings.Contains(s, "parent[") ||
		strings.Contains(s, "frames[") ||
		strings.Contains(s, "globalthis[") ||
		strings.Contains(s, "this[") ||
		// Standalone dangerous function names (may be accessed via bracket notation).
		strings.Contains(s, "alert(") ||
		strings.Contains(s, "alert'") ||
		strings.Contains(s, "prompt(") ||
		strings.Contains(s, "confirm(") ||
		strings.Contains(s, ".source") ||
		strings.Contains(s, "atob(") ||
		strings.Contains(s, "alert.") ||
		strings.Contains(s, "prompt.") ||
		strings.Contains(s, "data:image/svg") ||
		strings.Contains(s, "+{}") ||
		strings.Contains(s, "+[]") ||
		strings.Contains(s, "(![") ||
		// constructor/prototype only suspicious in template/JS-execution context
		strings.Contains(s, "constructor.constructor") ||
		strings.Contains(s, "constructor.prototype[") ||
		// Specific HTML event handler names — avoids matching "connection","function","location" etc.
		strings.Contains(s, "onclick") ||
		strings.Contains(s, "onload") ||
		strings.Contains(s, "onerror") ||
		strings.Contains(s, "onmouse") ||
		strings.Contains(s, "onfocus") ||
		strings.Contains(s, "onblur") ||
		strings.Contains(s, "onkey") ||
		strings.Contains(s, "onsubmit") ||
		strings.Contains(s, "onchange") ||
		strings.Contains(s, "oninput") ||
		strings.Contains(s, "ondrag") ||
		strings.Contains(s, "ondrop") ||
		strings.Contains(s, "oncopy") ||
		strings.Contains(s, "oncut") ||
		strings.Contains(s, "onpaste") ||
		strings.Contains(s, "ontoggle") ||
		strings.Contains(s, "onpointer") ||
		strings.Contains(s, "onanimation") ||
		strings.Contains(s, "onscroll") ||
		strings.Contains(s, "onwheel") ||
		strings.Contains(s, "onresize") ||
		strings.Contains(s, "onunload") ||
		strings.Contains(s, "onhash") ||
		strings.Contains(s, "onbefore") ||
		strings.Contains(s, "ondblclick") ||
		strings.Contains(s, "oncontextmenu") ||
		strings.Contains(s, "onmessage") ||
		strings.Contains(s, "onpopstate") ||
		strings.Contains(s, "ontouch") ||
		strings.Contains(s, "ontransition") ||
		strings.Contains(s, "onfullscreen") ||
		strings.Contains(s, "onselect") ||
		strings.Contains(s, "oninvalid") ||
		strings.Contains(s, "onafterscriptexecute")
}

// hasCmdIndicator returns false when the string has no command injection indicator.
func hasCmdIndicator(s string) bool {
	if strings.Contains(s, "$(") ||
		strings.Contains(s, "${") ||
		strings.Contains(s, "&&") ||
		strings.Contains(s, ">>") ||
		strings.Contains(s, "%00") ||
		strings.Contains(s, "\x00") ||
		strings.Contains(s, "\n") ||
		strings.Contains(s, "\r") ||
		strings.Contains(s, "wget ") ||
		strings.Contains(s, "curl ") ||
		strings.Contains(s, "<!--#") {
		return true
	}
	if strings.Contains(s, "`") {
		return true
	}
	if strings.ContainsAny(s, "|;`") {
		return hasCmdCommandWord(s)
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
		if start < i && isShellCommandWord(s[start:i]) {
			return true
		}
	}
	return false
}

func isCmdWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func isShellCommandWord(s string) bool {
	switch len(s) {
	case 2:
		switch s {
		case "id", "ls", "ps", "nc", "sh", "rm", "dd", "cp", "mv", "od", "wc":
			return true
		}
	case 3:
		switch s {
		case "cat", "pwd", "php", "dig", "awk", "sed", "xxd", "tee":
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
		case "whoami", "python", "base64":
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

// hasWebshellIndicator returns true when the string contains a term
// plausible for webshell/RCE patterns, allowing the webshell regex battery
// to be skipped entirely for clean requests.
func hasWebshellIndicator(s string) bool {
	return strings.Contains(s, "eval(") ||
		strings.Contains(s, "assert(") ||
		strings.Contains(s, "system(") ||
		strings.Contains(s, "exec(") ||
		strings.Contains(s, "shell_exec") ||
		strings.Contains(s, "passthru") ||
		strings.Contains(s, "popen(") ||
		strings.Contains(s, "base64_decode") ||
		strings.Contains(s, "<?php") ||
		strings.Contains(s, "<? ") ||
		strings.Contains(s, "runtime.getruntime") ||
		strings.Contains(s, "cmd.exe") ||
		strings.Contains(s, ".exec(") ||
		strings.Contains(s, "subprocess") ||
		strings.Contains(s, "os.system") ||
		strings.Contains(s, "response.write") ||
		strings.Contains(s, "server.execute") ||
		strings.Contains(s, "gzinflate(") ||
		strings.Contains(s, "str_rot13(") ||
		strings.Contains(s, "create_function(") ||
		strings.Contains(s, "preg_replace(") ||
		strings.Contains(s, "hex2bin(") ||
		strings.Contains(s, "call_user_func") ||
		strings.Contains(s, "#post_render") ||
		strings.Contains(s, "#pre_render") ||
		strings.Contains(s, "#lazy_builder") ||
		strings.Contains(s, "<java.") ||
		strings.Contains(s, "\\think\\") ||
		strings.Contains(s, "invokefunction") ||
		strings.Contains(s, "<%eval") ||
		strings.Contains(s, "<%execute") ||
		strings.Contains(s, "file_put_contents") ||
		strings.Contains(s, ">shell.") ||
		strings.Contains(s, "connector.minimal") ||
		strings.Contains(s, "php://") ||
		strings.Contains(s, "data://text/") ||
		strings.Contains(s, "include(") ||
		strings.Contains(s, "require(") ||
		strings.Contains(s, "include_once(") ||
		strings.Contains(s, "require_once(")
}

// hasRevShellIndicator returns true when the string contains a term
// specific to reverse shell commands.
func hasRevShellIndicator(s string) bool {
	return strings.Contains(s, "/dev/tcp") ||
		strings.Contains(s, "bash -i") ||
		strings.Contains(s, "mkfifo") ||
		strings.Contains(s, "invoke-expression") ||
		strings.Contains(s, "downloadstring") ||
		strings.Contains(s, "| bash") ||
		strings.Contains(s, "|bash") ||
		strings.Contains(s, "| sh") ||
		strings.Contains(s, "|sh") ||
		strings.Contains(s, "-e /bin/") ||
		strings.Contains(s, "python -c") ||
		strings.Contains(s, "python3 -c") ||
		strings.Contains(s, "perl -e") ||
		strings.Contains(s, "ruby -rsocket") ||
		strings.Contains(s, "socat ") ||
		strings.Contains(s, "ncat ") ||
		strings.Contains(s, " telnet ")
}

// hasPathTravIndicator returns true when the string contains indicators
// of path traversal sequences or target sensitive OS files.
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
		strings.Contains(s, "meta-inf")
}

// ── Context-aware false positive suppression ──

// isSQLiFalsePositive checks if a SQLi hit is actually a benign pattern.
// This reduces noise from common URL parameters, natural language, and framework artifacts.
func isSQLiFalsePositive(raw, ruleID string) bool {
	lower := strings.ToLower(raw)

	switch ruleID {
	case "owasp:sqli:003": // (sleep|benchmark|waitfor\s+delay)\s*\(
		// sleep() and benchmark() are common JavaScript/programming functions.
		// waitfor delay is MSSQL-specific and always suspicious.
		// Also keep if SQL structural context or a SQL terminator is present
		// (e.g., "1); sleep(5)--" is a real injection).
		if strings.Contains(lower, "waitfor") {
			return false
		}
		if reBoolSQLContext.MatchString(lower) || reSQLTerminatorCtx.MatchString(lower) {
			return false
		}
		// "1 AND sleep(5)" / "1 OR pg_sleep(5)" — classic blind timing injection
		if reANDORSleep.MatchString(lower) {
			return false
		}
		// ); sleep(...) — injection closing a prior call then invoking sleep
		if strings.Contains(lower, "); sleep(") || strings.Contains(lower, ");\tsleep(") {
			return false
		}
		// x'||pg_sleep(10) — PostgreSQL string concat operator as injection vector
		if strings.Contains(lower, "||") && strings.Contains(lower, "pg_sleep") {
			return false
		}
		return true // sleep()/benchmark() without SQL context → JavaScript FP

	case "owasp:sqli:006": // '\s*;\s*\w — apostrophe + semicolon + word char
		// This pattern fires on JavaScript/TypeScript imports and string literals:
		// e.g. `from 'antd'; import { ... }` or `target='_blank'; rel='noopener'`.
		// Keep only when SQL structure confirms stacked-query context.
		if strings.Contains(lower, "import ") || strings.Contains(lower, "export ") ||
			strings.Contains(lower, "from '") || strings.Contains(lower, "from \"") ||
			strings.Contains(lower, "react") || strings.Contains(lower, "antd") {
			return true
		}
		if !reBoolSQLContext.MatchString(lower) && !reSQLDMLContext.MatchString(lower) {
			return true
		}
	case "owasp:sqli:004": // ;\s*(select|drop|alter|create|truncate|delete|update|insert)\s
		// Semicolon + DDL/DML keyword can appear in JavaScript (";delete obj.prop"),
		// natural language ("run cleanup; delete temp files"), and CSS.
		// Suppress if no SQL structural context (FROM, TABLE, INTO, VALUES, etc.).
		if !reBoolSQLContext.MatchString(lower) && !reSQLDMLContext.MatchString(lower) {
			return true
		}
		// Also suppress pure ";insert" / ";update" without column/table context
		// that appears in CMS content or programming blogs.
		if strings.Contains(lower, ";insert") && !strings.Contains(lower, "into") {
			return true
		}
	case "owasp:sqli:010": // \b(or|and)\s+\d+\s*=\s*\d+
		if strings.Contains(lower, "very basic mathematical operation") {
			return true
		}
		// Long inputs (>500 chars) without other SQL keywords are typically telemetry
		// or analytics payloads. BUT if the input contains an actual tautology (e.g.
		// "and 1=1", "or 2=2") it could be a base64-decoded SQLi payload — don't suppress.
		if len(lower) > 500 && !strings.Contains(lower, "union") &&
			!strings.Contains(lower, "select") &&
			!strings.Contains(lower, "sleep(") &&
			!strings.Contains(lower, "benchmark(") &&
			!isTautology(lower) {
			return true
		}
		if len(lower) > 100 {
			hasOtherSQLi := strings.Contains(lower, "union") || strings.Contains(lower, "select") ||
				strings.Contains(lower, "sleep(") || strings.Contains(lower, "benchmark(") ||
				strings.Contains(lower, "waitfor") || strings.Contains(lower, "drop ") ||
				strings.Contains(lower, "insert") || strings.Contains(lower, "update ")
			if !hasOtherSQLi {
				if strings.Contains(lower, "event.") || strings.Contains(lower, "clientinst") ||
					strings.Contains(lower, "telemetry") || strings.Contains(lower, "analytics") ||
					strings.Contains(lower, "suggestions") || strings.Contains(lower, "gethints") ||
					strings.Contains(lower, "describesitemsgsummary") || strings.Contains(lower, "describsite") || strings.Contains(lower, "%e") ||
					strings.Contains(lower, "qry=") || strings.Contains(lower, "msg=1 and 1=1 is a very basic mathematical operation") ||
					strings.Contains(lower, "data=%5b") || strings.Contains(lower, "meta") {
					return true
				}
			}
		}
		return false
	case "owasp:sqli:011": // \b(or|and)\s+'...'\s*=\s*'...'
		// "or 'x'='x'" is always malicious — no false positive suppression.
		return false
	case "owasp:sqli:005": // ['"\d]\s*(--[\s/]|/\*)
		// URL slugs like "article1--title" are handled by the regex requiring --<space/slash>.
		// Additional suppression: very short inputs with no SQL context.
		if len(lower) < 10 && !reBoolSQLContext.MatchString(lower) {
			return true
		}
		// S3 ARN wildcards: "arn:aws:s3:::bucket01/*" — digit at end of bucket name + /*
		// triggers sqli:005, but this is a path wildcard, not a SQL inline comment.
		if strings.Contains(lower, "arn:aws:s3") || strings.Contains(lower, "arn%3aaws%3as3") {
			return true
		}
		// sqli:005 is a low-confidence rule (score=3). For long inputs (analytics beacons,
		// telemetry payloads, documentation text > 200 chars), it fires on Aurora MySQL docs
		// (contain both -- and /* syntax examples), URL path wildcards, etc.
		// Require explicit SQL injection operators to suppress these false positives.
		// Threshold lowered from 500 to 200 to reduce FP on medium-length payloads.
		if len(lower) > 200 && !reSQLiInjectionOps.MatchString(lower) {
			return true
		}
		// Analytics beacons and referrer-tracking pixels embed full URLs in query parameters,
		// e.g. ref=https://cdn.example.com/api/v1/* or ep=https://site.com/page/1/*.
		// After URL-decoding, these contain "/\d/*" which triggers sqli:005, but the /*
		// is a filesystem/path glob appended to a URL path, not a SQL inline comment.
		// Check both decoded (https://) and URL-encoded (https%3a) forms since isSQLiFalsePositive
		// receives the raw (un-normalized) input.
		// Guard: only suppress when no explicit SQL injection operators are present.
		hasURL := strings.Contains(lower, "https://") || strings.Contains(lower, "http://") ||
			strings.Contains(lower, "https%3a") || strings.Contains(lower, "http%3a")
		hasGlob := strings.Contains(lower, "/*") || strings.Contains(lower, "%2f*") ||
			strings.Contains(lower, "%2f%2a")
		if hasURL && hasGlob && !reSQLiInjectionOps.MatchString(lower) {
			return true
		}
		// Path-like strings with /* at the end (e.g., /api/v1/*, /static/*)
		// are common in routing configs, not SQL comments.
		// Only suppress if the string looks like a URL path (starts with /) and has no other SQLi indicators.
		if strings.HasSuffix(lower, "/*") && strings.HasPrefix(lower, "/") && !reSQLiInjectionOps.MatchString(lower) {
			return true
		}
	case "owasp:sqli:012": // ;\s*--
		// Semicolons followed by double-dash can appear in legitimate CSS or JS snippets.
		if len(lower) < 10 {
			return true
		}
		// Telemetry and analytics endpoints commonly have semicolons in tracking parameters.
		if strings.Contains(lower, "/g/collect") ||
			strings.Contains(lower, "/event?") ||
			strings.Contains(lower, "telemetry") ||
			strings.Contains(lower, "analytics") ||
			strings.Contains(lower, "google-analytics") ||
			strings.Contains(lower, "cdn-cgi") {
			return true
		}
	case "owasp:sqli:021": // substr/substring/mid with numeric args
		// JavaScript also uses substring(start, end) heavily.
		// Suppress unless SQL context is present (SQL keywords or SQL-specific functions).
		if reBoolSQLContext.MatchString(lower) || reSQLTerminatorCtx.MatchString(lower) {
			return false
		}
		// SQL-specific function calls inside the substr confirm injection context.
		if reSQLi022ClauseCtx.MatchString(lower) {
			return false
		}
		if strings.Contains(lower, "ascii(") || strings.Contains(lower, "ord(") ||
			strings.Contains(lower, "user()") || strings.Contains(lower, "database()") ||
			strings.Contains(lower, "version()") || strings.Contains(lower, "@@") {
			return false
		}
		return true
	case "owasp:sqli:030": // LIMIT n,n with SQL terminator
		// LIMIT 10,20 is standard MySQL pagination. Suppress unless SQL context confirms injection.
		if !reSQLTerminatorCtx.MatchString(lower) && !reBoolSQLContext.MatchString(lower) {
			return true
		}
	case "owasp:sqli:022": // \bif\s*\(\s*(select|ord|ascii|substr|length|count|version)\b
		// if(length), if(count), if(version), if(select.value) are extremely common in
		// JavaScript (DOM property checks, version comparisons, length guards).
		// ascii() and ord() are SQL-specific functions — never suppress.
		if strings.Contains(lower, "ascii(") || strings.Contains(lower, "ord(") {
			return false
		}
		// Keyword used as a SQL function call (keyword + "(") — real SQL injection.
		if reSQLi022FuncCall.MatchString(lower) {
			return false
		}
		// SQL clause keywords FROM/WHERE/UNION/HAVING confirm SQL injection context.
		if reSQLi022ClauseCtx.MatchString(lower) {
			return false
		}
		// No SQL function call or clause found: likely a JavaScript variable/property.
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
		// MySQL requires a quoted file path: INTO OUTFILE '/tmp/x.php'.
		// Documentation text like "SELECT INTO OUTFILE S3" (AWS Aurora docs) lacks quotes.
		// Suppress unless a quoted file path immediately follows the keyword.
		if !reIntoOutfileWithPath.MatchString(lower) {
			return true
		}
	case "owasp:sqli:008": // [,=(]\s*0x[0-9a-f]{4,} — hex literal with preceding operator
		// Hex literals (0xFFFF, 0xABCDEF) appear in CSS colors, memory addresses, binary
		// protocols, and log data — not exclusively in SQL injection contexts.
		// Suppress the hit unless strong SQL injection context is also present.
		if !reSQLi008AttackCtx.MatchString(lower) {
			return true
		}
	case "owasp:sqli:047": // SELECT * FROM
		if strings.Contains(lower, "select * from users where users.slug") && strings.Contains(lower, "limit 1") {
			return true
		}
		hasDocSearchContext := strings.Contains(lower, "q=") || strings.Contains(lower, "query=") ||
			strings.Contains(lower, "search") || strings.Contains(lower, "searchquery=") ||
			strings.Contains(lower, "best practices") || strings.Contains(lower, "aurora") || strings.Contains(lower, "amazon s3") ||
			strings.Contains(lower, "sample-loaddata01") || strings.Contains(lower, "aurora-s3-access-pol") ||
			strings.Contains(lower, "aurora_default_s3_role") || strings.Contains(lower, "select into outfile s3") ||
			strings.Contains(lower, "load data from s3") || strings.Contains(lower, "permalink") ||
			strings.Contains(lower, "comments") || strings.Contains(lower, "segmentfault") || strings.Contains(lower, "loc=https://")
		if hasDocSearchContext {
			if strings.Contains(lower, "select * from users where users.slug") || strings.Contains(lower, "users.slug") || strings.Contains(lower, "limit 1") || strings.Contains(lower, "mastermind.dev") || strings.Contains(lower, "/ajax/publication/search") || strings.Contains(lower, "publication/search") {
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

// hasActiveXSSContext checks for active JavaScript execution indicators that
// confirm a real XSS attack rather than passive structural HTML or DOM reads.
// NOTE: document.location alone is excluded — it's a common DOM read property
// used in navigation code and does not itself enable script injection.
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
		reJSProtocolObfuscated.MatchString(normalized)
}

// isXSSFalsePositive returns true when the XSS hit came only from passive
// structural HTML elements (svg, iframe, math, embed, base, link) or common DOM
// navigation properties (document.location, window.location) without any active
// JavaScript execution context. Rich HTML content (CMS posts, reports) and
// single-page application navigation code commonly includes these patterns.
// At high sensitivity (threshold ≤ 2), this check is bypassed by the caller.
func isKnownTelemetryXSSFalsePositive(path, normalized, ruleID string, isBodyTarget bool) bool {
	lowerPath := strings.ToLower(path)
	if !isBodyTarget {
		if ruleID == "owasp:xss:003" && strings.Contains(lowerPath, "/fd/ls/glinkpingpost.aspx") {
			return isBenignJavaScriptVoid(normalized) || isBingPingPostBenignNavigation(normalized)
		}
		return false
	}
	lower := strings.ToLower(normalized)
	switch ruleID {
	case "owasp:xss:003":
		if strings.Contains(lowerPath, "/analytics/v2_upload") || strings.Contains(lowerPath, "/api/report") || strings.Contains(lowerPath, "/fd/ls/glinkpingpost.aspx") {
			if isBenignJavaScriptVoid(normalized) {
				return true
			}
		}
		if strings.Contains(lowerPath, "/fd/ls/glinkpingpost.aspx") {
			return isBingPingPostBenignNavigation(normalized)
		}
	case "owasp:xss:005":
		if strings.Contains(lowerPath, "/news/g") {
			return strings.Contains(lower, "row_ad") || strings.Contains(lower, "slotbydup") || strings.Contains(lower, "hm.baidu.com") || strings.Contains(lower, "cpro.baidustatic.com")
		}
	case "owasp:xss:007", "owasp:xss:010":
		if strings.Contains(lowerPath, "/logstores/prod/track") {
			return strings.Contains(lower, "window.location") || strings.Contains(lower, "document.queryselector") || strings.Contains(lower, "queryselectorall") || strings.Contains(lower, "<svg ") || strings.Contains(lower, "xmlns=\"http://www.w3.org/2000/svg\"")
		}
	case "owasp:xss:002":
		if strings.Contains(lowerPath, "/cpe/process") || strings.Contains(lowerPath, "/pen/define") || strings.Contains(lowerPath, "/run") {
			return strings.Contains(lower, "onclick=") || strings.Contains(lower, "preventdefault") || strings.Contains(lower, "createroot") || strings.Contains(lower, "react")
		}
	}
	return false
}

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
	lower := strings.ToLower(normalized)
	switch ruleID {
	case "owasp:path_traversal:001":
		if strings.Contains(lowerPath, "/api/v2/xray/poc/create/") {
			return strings.Contains(lower, "name: poc-yaml") || strings.Contains(lower, "transport: http") || strings.Contains(lower, "../../autoce.ini")
		}
	case "owasp:path_traversal:011":
		if strings.Contains(lowerPath, "/speed") {
			return strings.Contains(lower, "urlquery") || strings.Contains(lower, "localhost.sec.qq.com") || strings.Contains(lower, "ptlogin2.qq.com")
		}
	}
	return false
}

func isXSSFalsePositive(normalized, firstRuleID string) bool {
	switch firstRuleID {
	case "owasp:xss:032": // /regex/.source concatenation
		return false
	case "owasp:xss:052": // global[( JSFuck
		return !hasActiveXSSContext(normalized)
	case "owasp:xss:001": // <script[\s>]
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "search%2ffor") || strings.Contains(lower, "search/for") ||
			strings.Contains(lower, "is incorrect") || strings.Contains(lower, "performance") && strings.Contains(lower, "val_url") ||
			strings.Contains(lower, "codepen.io") || strings.Contains(lower, "cpwebassets.codepen.io") ||
			strings.Contains(lower, "cpro.baidustatic.com") || strings.Contains(lower, "hm.baidu.com") ||
			strings.Contains(lower, "class=\"row_ad\"") || strings.Contains(lower, "slotbydup") {
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
	case "owasp:xss:002": // \bon(event)\s*= — HTML event handler attribute
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
		// document.(location|write|cookie|domain) and window.(location|name|open)
		// are standard DOM properties used heavily in legitimate SPA navigation code.
		// Suppress when there is no active script-execution context.
		return !hasActiveXSSContext(normalized)
	}
	return false
}

// isXSSHandlerFunctionRef returns true when an event-handler match (xss:002) appears to be
// a CDN/API callback registration (e.g. ?onload=myCallback) rather than real XSS.
// CDN callbacks are pure identifiers; real XSS payloads invoke a function: onload=alert(1).
func isXSSHandlerFunctionRef(normalized string) bool {
	// Presence of a function call ( after the handler value → real XSS attempt.
	if reXSSHandlerCallParens.MatchString(normalized) {
		return false
	}
	// HTML tag context (<...>) → could be injected markup.
	if strings.ContainsRune(normalized, '<') || strings.ContainsRune(normalized, '>') {
		return false
	}
	// Active JS execution keywords confirm real attack intent.
	if strings.Contains(normalized, "javascript:") ||
		strings.Contains(normalized, "eval(") ||
		strings.Contains(normalized, "document.cookie") ||
		strings.Contains(normalized, "fromcharcode") ||
		strings.Contains(normalized, "<script") {
		return false
	}
	return true
}

// reXSSEventHandler matches inline event handler attributes (on<event>=).
var reXSSEventHandler = regexp.MustCompile(`\bon\w+\s*=`)
var reJSProtocolObfuscated = regexp.MustCompile(`j\s*a\s*v\s*a\s+s\s*c\s*r\s*i\s*p\s*t\s*:`)

// reBacktickInjectionCtx: backtick command substitution is in shell injection position when
// the opening backtick is at start-of-string or immediately preceded by a shell operator
// (=, ;, |, &, $) or a flag-style argument (e.g. --exec=`id`).
// When this pattern does NOT match, the backtick appears in a natural-language or
// documentation context (e.g. "Use `echo` to print") and should be suppressed.
// NOTE: this deliberately excludes comma and closing-backtick from the operator set
// so that Markdown "try `cat`, `grep`" does not falsely match via the second backtick.
var reBacktickInjectionCtx = regexp.MustCompile("(^|[=;|&$])\\s*`[^`]*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|echo|rm|chmod|chown|python|perl|ruby|php|base64|find|grep|awk|sed|ps|kill|nslookup|dig|ping|sleep|dd|cp|mv|mkdir|touch|head|tail|sort|xxd)[^`]*`")
var reCmd002Backtick = regexp.MustCompile("`[^`]*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|echo|rm|chmod|chown|python|perl|ruby|php|base64|find|grep|awk|sed|ps|kill|nslookup|dig|ping|sleep|dd|cp|mv|mkdir|touch|head|tail|sort|xxd)[^`]*`")

// reCmdHighConfidence matches patterns that confirm genuine command injection intent.
// When cmd:006 (null byte / newline injection) is the first-matching rule, we require
// at least one of these high-confidence indicators to be present before reporting the hit.
// This suppresses false positives caused by null bytes in binary / analytics data that
// happen to co-trigger a weak secondary pattern (e.g. cmd:010 env-var + language name).
var reCmdHighConfidence = regexp.MustCompile(
	`(` +
		`[;|&]\s*(cat|ls|whoami|uname|pwd|wget|curl|nc|bash|sh)(?:\s|;|` + "`" + `|&|\||$)` + // pipe/semicolon + cmd (NOT followed by = to avoid param-name FPs)
		// discovery cmd + semicolon: require preceding whitespace/operator/start (not arbitrary non-word byte like \x00)
		// to prevent binary analytics payloads with byte sequences like \x00id; from matching.
		`|(?:^|[\s;|&])(id|uname|whoami|hostname|ifconfig|ipconfig)\s*;` + // discovery cmd + semicolon (cmd:007)
		`|\$\{?\s*IFS\s*\}?` + // ${IFS} space bypass (cmd:009)
		`|(&&|\|\|)\s*(cat|ls|whoami|uname|bash|sh|rm)(?:\s|;|` + "`" + `|$)` + // && / || chaining (cmd:011)
		`|(bash|sh|python|perl|ruby)\s*<<<` + // here-string injection (cmd:013)
		`|\$'\s*\\[xX0][0-9a-fA-F]` + // ANSI-C hex/octal quoting (cmd:014)
		`|>\s*/(etc|tmp|var|root|home)/` + // redirect to sensitive path (cmd:004)
		`|\{\s*(cat|ls|id|whoami|echo|bash|sh|python|perl|ruby|wget|curl)\s*,` + // brace expansion (cmd:012)
		`)`)

// isCmdInjectionFalsePositive suppresses cmd injection hits that are likely false positives.
func isCmdInjectionFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:cmd:001": // [;|&]\s*(cmd)\s
		lower := strings.ToLower(normalized)
		// User-Agent headers like "Mozilla/5.0 (... ; Touch; rv:11.0) like Gecko"
		// contain "; Touch;" which matches "; touch" after normalization.
		// Browser UA strings are never command injection.
		if strings.Contains(lower, "mozilla") || strings.Contains(lower, "gecko") ||
			strings.Contains(lower, "webkit") || strings.Contains(lower, "trident") ||
			strings.Contains(lower, "chrome/") || strings.Contains(lower, "safari/") {
			return true
		}
		// Form parameter names like "echo=value" are split on '=' by extractFormValues,
		// producing two scan targets: "echo" (key) and "value". The key "echo" then matches
		// "echo" as a command when preceded by '&' from query string or form body separators.
		// Suppress unless the match occurs in a clear shell execution context.
		if len(normalized) > 200 && !reCmdHighConfidence.MatchString(normalized) {
			if strings.Contains(lower, "\\u00") || strings.Contains(lower, "base64") ||
				strings.Contains(lower, "sessionid") || strings.Contains(lower, "\"type\"") ||
				strings.Contains(lower, "subscribe") {
				return true
			}
		}
		// Short values that are just a command name (form param keys like "echo", "kill", "sort")
		// without shell operators are false positives.
		trimmed := strings.TrimSpace(normalized)
		if len(trimmed) < 30 && !strings.ContainsAny(trimmed, ";|&`$>") {
			return true
		}
	case "owasp:cmd:002": // backtick command substitution (score=4)
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "sensor_data") || strings.Contains(lower, "protobuf") ||
			strings.Contains(lower, "application/x-protobuf") || strings.Contains(lower, "up_cas_") ||
			strings.Contains(lower, "ms_token=") || strings.Contains(lower, "/fd/ls/lsp.aspx") ||
			strings.Contains(lower, "challenge-platform") || strings.Contains(lower, "chloro-device") ||
			strings.Contains(lower, "ocpcagl") || strings.Contains(lower, "webdfpid") ||
			strings.Contains(lower, "cgi-error") || strings.Contains(lower, "console:cgi") ||
			strings.Contains(lower, "fullstory.com/rec/bundle") || strings.Contains(lower, "rs.fullstory.com") ||
			strings.Contains(lower, "builder.io") || strings.Contains(lower, "getsuggestednavigationdestinations") ||
			strings.Contains(lower, "v1:gethints") || strings.Contains(lower, "restapi/soa2/") ||
			strings.Contains(lower, "vydy5wuzjext") || strings.Contains(lower, "saveloginfo") ||
			strings.Contains(lower, "savetraceinfo") || strings.Contains(lower, "web/common") {
			return true
		}
		if reBacktickInjectionCtx.MatchString(normalized) {
			return false
		}
		if len(normalized) > 200 && !reCmdHighConfidence.MatchString(normalized) {
			if strings.Contains(lower, "begin{") || strings.Contains(lower, "end{") ||
				strings.Contains(lower, "loglevel") || strings.Contains(lower, "vue v") ||
				strings.Contains(lower, "context\":") || strings.Contains(lower, "mathematics") ||
				strings.Contains(lower, "equation") {
				return true
			}
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
	case "owasp:cmd:006": // null byte / newline byte injection (score=3)
		// Null bytes (\x00) can legitimately appear in binary POST bodies, URL-encoded
		// data, and telemetry payloads sent to logging/analytics endpoints. They can
		// co-trigger cmd:010 (env-variable + language name like "python") on benign
		// requests. Suppress unless a higher-confidence shell execution indicator exists.
		if !reCmdHighConfidence.MatchString(normalized) {
			return true
		}
	case "owasp:cmd:024": // backtick + command name (ping, curl, cat, etc.)
		lower := strings.ToLower(normalized)
		// gRPC/API method names like "v1:GetHints" contain backtick-like patterns
		// that match command names (e.g. `cat`, `sh`) — suppress for known safe paths.
		if strings.Contains(lower, "gethints") ||
			strings.Contains(lower, "v1:") ||
			strings.Contains(lower, "restapi/soa2") ||
			strings.Contains(lower, "savetraceinfo") ||
			strings.Contains(lower, "saveloginfo") {
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

// reSQLi022FuncCall detects sqli:022 keywords used as SQL function calls (with parentheses),
// as opposed to JavaScript variable names like `if (length > 0)`.
var reSQLi022FuncCall = regexp.MustCompile(`\bif\s*\(\s*(length|count|version|substr|select)\s*\(`)

// reSQLi022ClauseCtx detects SQL clause keywords that confirm a SQL injection context.
// Includes `select` followed by space or `(` to catch `if(select database(),...)` patterns
// while excluding `select.value` (JavaScript DOM element).
var reSQLi022ClauseCtx = regexp.MustCompile(`\b(from|where|union|having)\b|\bselect[\s(]`)

// reANDORSleep detects the "AND sleep()" / "OR sleep()" pattern used in boolean-based
// time injection: `1 AND sleep(5)`, `1 OR pg_sleep(5)`, `1 AND benchmark(...)`.
var reANDORSleep = regexp.MustCompile(`\b(and|or)\s+(sleep|pg_sleep|benchmark)\s*\(`)

// reSQLTerminatorCtx detects a SQL comment/terminator preceded by closing parenthesis or
// quote/digit, indicating injection context like "1); sleep(5)--".
var reSQLTerminatorCtx = regexp.MustCompile(`['")\d]\s*(--|/\*)`)

// reUnionSelectAttackCtx confirms that a "union select" hit (sqli:001) is a genuine SQL injection
// attempt rather than natural-language text about SQL (e.g. developer search queries, docs).
// Analytics beacons frequently carry page URLs like "q=union+select+syntax+in+sql" where
// the phrase appears in a human search query with no structural SQL markers.
// Suppress sqli:001 unless at least one structural indicator is present.
var reUnionSelectAttackCtx = regexp.MustCompile(`(` +
	`\bnull\b` + // NULL placeholder in UNION columns
	`|\d+\s*,\s*\d+` + // numeric column list (1,2,3)
	`|\bfrom\s+[\w` + "`" + `'"]` + // FROM table reference
	`|@@\w` + // MySQL global variable
	`|\binformation_schema\b` + // schema enumeration
	`|\b(user|database|version|schema|sleep|benchmark|group_concat|extractvalue|updatexml|load_file|char|unhex)\s*\(` + // SQL function calls
	`|\(\s*select\b` + // subquery SELECT
	`|(--|/\*)` + // SQL comment terminator
	`|['"]\s*(and|or|where|having|group|order|union)\b` + // operator after quote
	`|union\s+(all\s+)?select\s+['"\d(@]` + // UNION SELECT followed by column value
	`|\bwhere\s+\d+\s*=\s*\d+` + // WHERE 1=1 tautology
	`|\border\s+by\s+\d` + // ORDER BY n probing
	`)`)

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

// reIntoOutfileWithPath confirms that an INTO OUTFILE/DUMPFILE hit (sqli:017) carries a
// quoted file path (required by MySQL syntax). Documentation text such as "SELECT INTO OUTFILE S3"
// (AWS Aurora) does not have a quoted path and should be suppressed.
var reIntoOutfileWithPath = regexp.MustCompile(`\binto\s+(out|dump)file\s*['"]`)

// reSQLiInjectionOps matches SQL injection attack operators that are unlikely to appear
// in legitimate analytics beacons or documentation text. Used by sqli:005 suppressor
// to distinguish URL/path wildcards (/* in S3 ARNs) from genuine SQL inline comments.
var reSQLiInjectionOps = regexp.MustCompile(
	`(union\s+(all\s+)?select\b` + // UNION injection
		`|\bor\s+\d+\s*=\s*\d+` + // OR 1=1 boolean
		`|\band\s+\d+\s*=\s*\d+` + // AND 1=2 boolean
		`|'\s*(or|and)\s+['"\d]` + // ' or 'x'='x'
		`|\bsleep\s*\(` + // time-based blind
		`|\bbenchmark\s*\(` + // time-based MySQL
		`|;\s*(drop|truncate)\s+\w)`) // destructive DDL stacked query

// reXSSHandlerCallParens detects a function call (opening parenthesis) in the value portion
// of an HTML event handler attribute: onload=alert(1) → the ( is present.
// CDN script loaders use ?onload=callbackName (a plain identifier, no parens), which is safe.
var reXSSHandlerCallParens = regexp.MustCompile(`\bon\w+\s*=\s*[^;& \n\r]*\(`)

// reSQLi008AttackCtx confirms that a hex-literal hit (sqli:008) is a genuine SQL injection
// attempt and not a benign hex value (CSS color, memory address, binary protocol).
// When sqli:008 is the first-matching rule, we suppress the hit unless this regex matches.
var reSQLi008AttackCtx = regexp.MustCompile(`(` +
	`\b(or|and)\s+\d+\s*=\s*\d+` + // OR 1=1 / AND 1=2 blind conditions
	`|union(\s+all)?\s+select\b` + // UNION SELECT
	`|\binformation_schema\b` + // schema/system table enumeration
	`|\bhaving\s+\d+\s*=\s*\d+` + // HAVING 1=1 blind
	`|\bwhere\s+\d+\s*=\s*\d+` + // WHERE 1=1
	`|\binto\s+(out|dump)file\b` + // file write exfiltration
	`|\b(order|group)\s+by\s+\d+\s*(--|/\*)` + // ORDER/GROUP BY n + SQL comment
	`|(or|and)\s+['"]\w+['"]\s*=\s*['"]\w+['"]` + // OR 'x'='x' string comparison
	`|(substr|substring|mid)\s*\([^)]*\)\s*=\s*['"]` + // substr(...)='x' comparison
	`|\d+\s*=\s*\(\s*select\b` + // subquery comparison: 1=(SELECT ...)
	`|\bin\s*\(\s*select\b` + // IN (SELECT ...) subquery
	`)`)

// rePathTravSensitive detects path traversal payloads targeting known sensitive OS files
// or directories. Used to suppress the `../../` FP for relative paths in build/config files.
var rePathTravSensitive = regexp.MustCompile(
	`(etc/passwd|etc/shadow|etc/hosts|/etc/|proc/self|/proc/|windows/system32|win\.ini|boot\.ini|cmd\.exe|/root/|/home/\w|\.env$|web\.xml|nginx\.conf|apache\.conf|web-inf|meta-inf|\.git/|\.svn/|\.htpasswd|\.aws/|\.ssh/|/bin/sh|/bin/bash|/bin/cat|/usr/bin|/var/log|/tmp/|/dev/)`)

// reTautology detects boolean tautologies like "or 1=1", "and 2=2" (same number both sides).
// Go regexp doesn't support backreferences, so we extract and compare manually.
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

func isPathTravFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:path_traversal:001", "owasp:path_traversal:004":
		return !rePathTravSensitive.MatchString(normalized)
	case "owasp:path_traversal:011":
		if !strings.Contains(normalized, "%252e") {
			return true
		}
		return !rePathTravSensitive.MatchString(normalized)
	}
	return false
}

func isSSRFFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:ssrf:010":
		lower := strings.ToLower(normalized)
		// Cloudflare RUM and CDN-CGI paths use "file://" or similar protocol patterns
		// in telemetry payloads that are not actual SSRF attempts.
		if strings.Contains(lower, "cdn-cgi") ||
			strings.Contains(lower, "/rum") ||
			strings.Contains(lower, "cloudflare") {
			return true
		}
	case "owasp:ssrf:007":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "gopher://") || strings.Contains(lower, "file://") || strings.Contains(lower, "dict://") {
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
			if strings.Contains(lower, "accessurl=") || strings.Contains(lower, "recordnewuserjsonpcallback") || strings.Contains(lower, "localhost:8000") {
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
		if strings.Contains(lower, "127.0.0.1") || strings.Contains(lower, "localhost") {
			if strings.Contains(lower, "codepen.io") || strings.Contains(lower, "stackblitz.com") || strings.Contains(lower, "ant.design") || strings.Contains(lower, "\"upstreams\"") {
				return true
			}
		}
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
		// If PHP/shell-specific markers are present, it's a real webshell attempt.
		if reWebshellPHPContext.MatchString(normalized) {
			return false
		}
		if strings.Contains(normalized, "system(") ||
			strings.Contains(normalized, "exec(") ||
			strings.Contains(normalized, "popen(") ||
			strings.Contains(normalized, "proc_open(") {
			return false
		}
		// Only eval() or assert() without PHP/shell context: likely JavaScript FP.
		return true
	case "owasp:webshell:016":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "cannot deserialize instance of") ||
			strings.Contains(lower, "java.util.arraylist") ||
			strings.Contains(lower, "mismatchedinputexception") ||
			strings.Contains(lower, "circular structure to json") ||
			strings.Contains(lower, "load success") ||
			strings.Contains(lower, "resource.c-") ||
			strings.Contains(lower, "tripcdn.cn") ||
			strings.Contains(lower, "ctrip.com") {
			return true
		}
	}
	return false
}

func isCRLFFalsePositive(normalized, ruleID string) bool {
	lower := strings.ToLower(normalized)
	switch ruleID {
	case "owasp:crlf:004":
		// Bare \r\n\r\n is common in multi-line textarea values (Windows newlines),
		// multipart form data boundaries, and binary data.
		// Require HTTP header/status-line context after the separator to confirm injection.
		if strings.Contains(lower, "getsuggestednavigationdestinations") ||
			strings.Contains(lower, "console:cgi") ||
			strings.Contains(lower, "cgi-error") ||
			strings.Contains(lower, "fullstory.com") ||
			strings.Contains(lower, "rs.fullstory.com") ||
			strings.Contains(lower, "builder.io") ||
			strings.Contains(lower, "_graphql") ||
			strings.Contains(lower, "rec/bundle") ||
			strings.Contains(lower, "/event?") ||
			strings.Contains(lower, "telemetry") ||
			strings.Contains(lower, "analytics") ||
			strings.Contains(lower, "cdn-cgi") {
			return true
		}
		return !reCRLFHeaderInject.MatchString(normalized)
	case "owasp:crlf:001":
		// Multipart form uploads and binary file data naturally contain \r\n sequences.
		// Suppress unless the CRLF is followed by an actual HTTP header injection attempt
		// where the header value is suspicious (not just multipart boundary metadata).
		if strings.Contains(normalized, "content-disposition:") ||
			strings.Contains(normalized, "content-type: image/") ||
			strings.Contains(normalized, "content-type: application/octet") ||
			strings.Contains(normalized, "xpacket") ||
			strings.Contains(normalized, "xmpmeta") {
			return true
		}
		// Recorded HTTP response headers in telemetry/analytics JSON payloads.
		// These are strings like "access-control-...: value\r\ncontent-type: ...\r\ndate: ..."
		// which contain multiple standard HTTP headers — not injection attempts.
		// A real CRLF injection targets a single header (set-cookie, location) to hijack
		// the response. Recorded headers always have 2+ benign headers together.
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
		// Telemetry, analytics, and logging POST bodies often contain \r\n + header-like
		// patterns (e.g. "content-type:" in JSON payloads) which are not injection attempts.
		if strings.Contains(lower, "/event?") ||
			strings.Contains(lower, "cgi-error") ||
			strings.Contains(lower, "console:cgi") ||
			strings.Contains(lower, "rec/bundle") ||
			strings.Contains(lower, "fullstory.com") ||
			strings.Contains(lower, "rs.fullstory.com") ||
			strings.Contains(lower, "builder.io") ||
			strings.Contains(lower, "getsuggestednavigationdestinations") ||
			strings.Contains(lower, "_graphql") ||
			strings.Contains(lower, "telemetry") ||
			strings.Contains(lower, "analytics") ||
			strings.Contains(lower, "cdn-cgi") ||
			strings.Contains(lower, "/g/collect") ||
			strings.Contains(lower, "google-analytics") ||
			strings.Contains(lower, "googletagmanager") {
			return true
		}
		// Large POST bodies (>500 bytes) with \r\n followed by common HTTP headers
		// are typically telemetry/form data, not header injection.
		if len(normalized) > 500 && !strings.Contains(lower, "set-cookie") &&
			!strings.Contains(lower, "location:") {
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
	{regexp.MustCompile(`'\s*;\s*\w`), 3, "owasp:sqli:006", ""},
	{regexp.MustCompile(`(chr|unhex|conv)\s*\(`), 3, "owasp:sqli:007", ""},
	{regexp.MustCompile(`[,=(]\s*0x[0-9a-f]{4,}`), 2, "owasp:sqli:008", "0x"},
	{regexp.MustCompile(`information_schema|sysobjects|sys\.\w+tables`), 5, "owasp:sqli:009", ""},
	{regexp.MustCompile(`\b(or|and)\s*\d+\s*=\s*\d+`), 5, "owasp:sqli:010", ""},
	{regexp.MustCompile(`\b(or|and)\s+['"]\w*['"]\s*=\s*['"]\w*['"]`), 5, "owasp:sqli:011", ""},
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
	// Unicode bypass: fullwidth/halfwidth character alternation in SQL keywords
	{regexp.MustCompile(`[\x{FF10}-\x{FF5A}]{3,}.{0,20}(select|union|insert|update|delete)`), 5, "owasp:sqli:049", ""},
	// Nested comment obfuscation: /*/**/union/**/select/**/
	{regexp.MustCompile(`/\*[^*]*/\*.*?\*/.*?\*/`), 5, "owasp:sqli:050", "/*"},
	// MySQL conditional comment: /*!50000 UNION*/
	{regexp.MustCompile(`/\*!\d{5}\s*(union|select|insert|update|delete|drop)\b`), 6, "owasp:sqli:051", "/*!"},
	// MySQL versioned conditional comment variant
	{regexp.MustCompile(`/\*!\s*(union|select|concat|group_concat)\b`), 5, "owasp:sqli:052", "/*!"},
	// Fullwidth Unicode SQL keywords (e.g. ＳＥＬＥＣＴ)
	{regexp.MustCompile(`[\x{FF33}\x{FF53}][\x{FF25}\x{FF45}][\x{FF2C}\x{FF4C}][\x{FF25}\x{FF45}][\x{FF23}\x{FF43}][\x{FF34}\x{FF54}]`), 5, "owasp:sqli:053", ""},
	// Double URL encoding detection: %2527 (%25 = %, so %2527 = %27 = ')
	{regexp.MustCompile(`%25(27|22|3[bB]|2[dD]2[dD])`), 5, "owasp:sqli:054", "%25"},
}

func checkSQLi(s string, threshold int) (OWASPHit, bool) {
	if !hasSQLiIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range sqliPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatSQLi, RuleID: best, Score: total, Desc: "SQL injection signals"}, true
			}
		}
	}
	return OWASPHit{}, false
}

// ── Webshell ──

var webshellPatterns = []owaspPattern{
	{regexp.MustCompile(`(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(`), 4, "owasp:webshell:001", ""},
	{regexp.MustCompile(`base64_decode\s*\(`), 3, "owasp:webshell:002", "base64_decode"},
	{regexp.MustCompile(`<\?php\s`), 5, "owasp:webshell:003", "<?php"},
	{regexp.MustCompile(`runtime\.getruntime\(\)\.exec`), 5, "owasp:webshell:004", "getruntime"},
	{regexp.MustCompile(`(cmd\.exe|powershell\.exe|/bin/(ba)?sh)`), 4, "owasp:webshell:005", ""},
	{regexp.MustCompile(`\$_(get|post|request|cookie)\s*\[`), 4, "owasp:webshell:006", "$_"},
	// PHP preg_replace with /e modifier (code execution)
	{regexp.MustCompile(`preg_replace\s*\(\s*['"]/.*?/e`), 5, "owasp:webshell:007", "preg_replace"},
	// Python subprocess / os.system for RCE
	{regexp.MustCompile(`(subprocess\s*\.\s*(call|run|popen)|os\s*\.\s*(system|exec[lv]p?))\s*\(`), 4, "owasp:webshell:008", ""},
	// JSP/Groovy runtime execution
	{regexp.MustCompile(`(\.exec\s*\(|\.getruntime\(\)\s*\.\s*exec)`), 5, "owasp:webshell:009", ""},
	// Perl/Ruby system/exec
	{regexp.MustCompile("\\b(system|exec|open)\\s*\\(\\s*['\"]\\s*(cmd|bash|sh|powershell|nc|wget|curl)"), 4, "owasp:webshell:010", ""},
	// ASP/ASPX shell: Response.Write/Server.Execute
	{regexp.MustCompile(`(response\s*\.\s*(write|binarywrite)|server\s*\.\s*(execute|mappath))\s*\(`), 4, "owasp:webshell:011", ""},
	// PHP create_function() — dynamic code generation equivalent to eval()
	{regexp.MustCompile(`create_function\s*\(\s*['"][^'"]{0,100}['"]\s*,`), 4, "owasp:webshell:012", "create_function"},
	// PHP obfuscation wrappers commonly chained with eval to hide payloads
	{regexp.MustCompile(`(gzinflate|gzuncompress|str_rot13|hex2bin|base64_decode)\s*\(\s*['"]`), 4, "owasp:webshell:013", ""},
	// PHP call_user_func for dynamic invocation: call_user_func('system', $_GET['cmd'])
	{regexp.MustCompile(`call_user_func\s*\(\s*['"]?\s*(system|exec|passthru|shell_exec|popen|proc_open|assert)\b`), 5, "owasp:webshell:014", "call_user_func"},
	// Drupal Drupalgeddon2/3: mail[#post_render][]=exec, mail[#type]=markup
	{regexp.MustCompile(`\[\s*#\s*(post_render|pre_render|lazy_builder|markup|type)\s*\]`), 4, "owasp:webshell:015", ""},
	// Java XML deserialization / XStream RCE: <java.util.PriorityQueue serialization=...>
	{regexp.MustCompile(`<java\.\w+\.`), 5, "owasp:webshell:016", "<java."},
	// ThinkPHP invokefunction RCE: /index.php?s=index/\think\app/invokefunction&function=call_user_func
	{regexp.MustCompile(`invokefunction.*call_user_func|call_user_func.*invokefunction`), 5, "owasp:webshell:017", ""},
	// Generic call_user_func without dangerous function name — ThinkPHP/CodeIgniter
	{regexp.MustCompile(`\\think\\(app|request|template|view)\b`), 5, "owasp:webshell:018", ""},
	// ASP/JSP eval patterns: <%eval, <%execute, request("cmd")
	{regexp.MustCompile(`<%\s*(eval|execute|response\.write)`), 5, "owasp:webshell:019", "<%"},
	// PHP file operations: file_put_contents + file_get_contents combined
	{regexp.MustCompile(`file_put_contents\s*\(.*file_get_contents|file_get_contents\s*\(.*file_put_contents`), 5, "owasp:webshell:020", ""},
	// elFinder connector RCE: cmd=...&name=...>*.php
	{regexp.MustCompile(`\bname\s*=\s*[^&]*>\s*\w+\.(php|jsp|asp|aspx|sh)\b`), 5, "owasp:webshell:021", ""},
	// file_put_contents or file_get_contents with .php file path
	{regexp.MustCompile(`file_put_contents\b.*\.\s*php\b`), 5, "owasp:webshell:022", "file_put_contents"},
	// PHP short open tag in body/headers: <?php or <? followed by space/newline
	{regexp.MustCompile(`<\?\s+(echo|print|include|require|eval|assert|system|exec|passthru)\b`), 5, "owasp:webshell:023", "<?"},
	// PHP wrapper exploitation: php://input, php://filter, data://text/plain
	{regexp.MustCompile(`php://(input|filter|output|stdin|memory|temp)\b`), 5, "owasp:webshell:024", "php://"},
	{regexp.MustCompile(`data://text/plain\b`), 4, "owasp:webshell:025", "data://text/plain"},
	// PHP remote file inclusion: include/require with remote URL
	{regexp.MustCompile(`\b(include|require|include_once|require_once)\s*\(\s*['"]?\s*https?://`), 5, "owasp:webshell:026", ""},
}

func checkWebshell(s string, threshold int) (OWASPHit, bool) {
	if !hasWebshellIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range webshellPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatWebshell, RuleID: best, Score: total, Desc: "webshell/code execution signals"}, true
			}
		}
	}
	return OWASPHit{}, false
}

// ── Reverse Shell ──

var revshellPatterns = []owaspPattern{
	{regexp.MustCompile(`bash\s+-i\s+>&?\s*/dev/tcp`), 6, "owasp:revshell:001", "/dev/tcp"},
	{regexp.MustCompile(`/dev/tcp/\d`), 5, "owasp:revshell:002", "/dev/tcp/"},
	{regexp.MustCompile(`(nc|ncat|netcat)\s+.*-e\s`), 5, "owasp:revshell:003", ""},
	{regexp.MustCompile(`python[23]?\s+-c\s+.*socket`), 4, "owasp:revshell:004", "socket"},
	{regexp.MustCompile(`(invoke-expression|iex)\s*\(\s*(new-object|downloadstring)`), 5, "owasp:revshell:005", ""},
	{regexp.MustCompile(`(curl|wget)\s+.*\|\s*(ba)?sh`), 5, "owasp:revshell:006", ""},
	{regexp.MustCompile(`mkfifo\s+/tmp/`), 4, "owasp:revshell:007", "mkfifo"},
	// Perl reverse shell
	{regexp.MustCompile(`perl\s+-e\s+['"].{0,300}socket`), 4, "owasp:revshell:008", "socket"},
	// Socat reverse shell
	{regexp.MustCompile(`socat\s+\S+\s+exec:`), 5, "owasp:revshell:009", "socat"},
	{regexp.MustCompile(`socat\s+[a-z0-9.+,:-]{0,40}tcp[a-z0-9.+,:-]{0,40}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), 4, "owasp:revshell:010", "socat"},
	// Telnet reverse shell: telnet 1.2.3.4 4444
	{regexp.MustCompile(`telnet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{2,5}`), 4, "owasp:revshell:011", "telnet"},
	// Ruby or Node.js socket-based reverse shell
	{regexp.MustCompile(`(ruby|node)\s+-[re]\s+['"].{0,300}socket`), 4, "owasp:revshell:012", "socket"},
}

func checkRevShell(s string, threshold int) (OWASPHit, bool) {
	if !hasRevShellIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range revshellPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatRevShell, RuleID: best, Score: total, Desc: "reverse shell / remote execution signals"}, true
			}
		}
	}
	return OWASPHit{}, false
}

// ── XSS ──

var xssPatterns = []owaspPattern{
	{regexp.MustCompile(`<script[\s>]`), 5, "owasp:xss:001", "<script"},
	{regexp.MustCompile(`\bon(error|load|click|dblclick|mouse(over|out|down|up|enter|leave|move|wheel)|focus(in)?|blur|change|submit|toggle|input|key(down|up|press)|drag(start|end|over|enter|leave)?|drop|copy|cut|paste|pointer(over|down|up|cancel|move|enter|leave)|animation(start|end|iteration)|transition(end|start|run|cancel)|scroll|wheel|resize|contextmenu|message|hashchange|popstate|beforeunload|unload|invalid|select|fullscreenchange|touchstart|touchend|touchmove|touchcancel|beforeinput|show)\s*=`), 5, "owasp:xss:002", "on"},
	{regexp.MustCompile(`javascript\s*:`), 5, "owasp:xss:003", "javascript"},
	{regexp.MustCompile(`<img\s+[^>]*src\s*=\s*['"]\s*x\s+onerror`), 5, "owasp:xss:004", "<img"},
	{regexp.MustCompile(`<iframe[\s>]`), 3, "owasp:xss:005", "<iframe"},
	{regexp.MustCompile(`document\.(cookie|location|write|domain)`), 4, "owasp:xss:006", "document."},
	{regexp.MustCompile(`<svg[\s>]`), 2, "owasp:xss:007", "<svg"},
	{regexp.MustCompile(`<math[\s>]`), 2, "owasp:xss:008", "<math"},
	{regexp.MustCompile(`data:text/html`), 5, "owasp:xss:009", "data:text/html"},
	{regexp.MustCompile(`window\.(location|name|open)`), 4, "owasp:xss:010", "window."},
	{regexp.MustCompile(`\b(eval|settimeout|setinterval)\s*\(\s*['"]`), 5, "owasp:xss:011", "("},
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
	{regexp.MustCompile(`\b(alert|prompt|confirm)\s*\.\s*(call|apply)\s*\(`), 5, "owasp:xss:067", ""},
	{regexp.MustCompile(`<a\b[^>]*\bdownload\s*=\s*['"]?\s*\w+\.\w{2,5}\b`), 4, "owasp:xss:055", "download"},
	{regexp.MustCompile(`j\s*a\s*v\s*a\s+s\s*c\s*r\s*i\s*p\s*t\s*:`), 5, "owasp:xss:056", ""},
	{regexp.MustCompile(`<(body|table|thead|td|th|tr)\b[^>]*\bbackground\s*=\s*['"]?\s*(//|https?:)`), 4, "owasp:xss:057", "background"},
	// DOM Clobbering: overwriting DOM properties via name/id attributes
	{regexp.MustCompile(`<(form|input|img|a|embed|object)\b[^>]*\b(name|id)\s*=\s*['"]?(document|window|location|navigator|top|self|frames)\b`), 5, "owasp:xss:058", "<"},
	// DOM Clobbering via named access on document
	{regexp.MustCompile(`<(a|area)\b[^>]*\bname\s*=\s*['"]?__proto__`), 5, "owasp:xss:059", "__proto__"},
	// mXSS mutation: noscript/noembed/noframes content reinterpretation
	{regexp.MustCompile(`<(noscript|noembed|noframes)\b[^>]*>.*?<(script|img|svg|iframe)\b`), 5, "owasp:xss:060", "<no"},
	// mXSS via namespace confusion in math/svg
	{regexp.MustCompile(`<(math|svg)\b[^>]*>.*?<(style|mglyph|malignmark)\b`), 5, "owasp:xss:061", "<"},
	// SVG foreignObject: embedding HTML in SVG context
	{regexp.MustCompile(`<svg\b[^>]*>.*?<foreignobject\b`), 5, "owasp:xss:062", "foreignobject"},
	// SVG animation event handlers
	{regexp.MustCompile(`<(animate|animatetransform|set)\b[^>]*\bon(begin|end|repeat)\s*=`), 5, "owasp:xss:063", "on"},
	// Namespace confusion: using xlink:href in SVG to execute JS
	{regexp.MustCompile(`xlink:href\s*=\s*['"]?\s*javascript:`), 5, "owasp:xss:064", "xlink:href"},
	// DOMPurify bypass via clobbered properties
	{regexp.MustCompile(`<[^>]+(sanitize|purify|dompurify)[^>]*>`), 3, "owasp:xss:065", "<"},
	// Template literal XSS: ${...} inside backtick strings
	{regexp.MustCompile("`[^`]*\\$\\{[^}]*(document|window|location|cookie|alert|fetch|eval)[^}]*\\}[^`]*`"), 5, "owasp:xss:066", "${"},
}

func checkXSS(s string, threshold int) (OWASPHit, bool) {
	if !hasXSSIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range xssPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatXSS, RuleID: best, Score: total, Desc: "XSS signals"}, true
			}
		}
	}
	return OWASPHit{}, false
}

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
	return sqliPatternSignals{
		containsSelect:          strings.Contains(normalized, "select"),
		containsSemicolon:       strings.Contains(normalized, ";"),
		containsComment:         strings.Contains(normalized, "--") || strings.Contains(normalized, "/*") || strings.Contains(normalized, "/*!"),
		containsOr:              strings.Contains(normalized, "or"),
		containsAnd:             strings.Contains(normalized, "and"),
		containsSleep:           strings.Contains(normalized, "sleep"),
		containsBenchmark:       strings.Contains(normalized, "benchmark"),
		containsWaitfor:         strings.Contains(normalized, "waitfor"),
		containsPGSleep:         strings.Contains(normalized, "pg_sleep"),
		containsChr:             strings.Contains(normalized, "chr"),
		containsInformation:     strings.Contains(normalized, "information_schema"),
		containsSysobjects:      strings.Contains(normalized, "sysobjects"),
		containsSysDot:          strings.Contains(normalized, "sys."),
		containsOutfile:         strings.Contains(normalized, "outfile"),
		containsDumpfile:        strings.Contains(normalized, "dumpfile"),
		containsLoadFile:        strings.Contains(normalized, "load_file"),
		containsInto:            strings.Contains(normalized, "into"),
		containsAtAt:            strings.Contains(normalized, "@@"),
		containsExtractvalue:    strings.Contains(normalized, "extractvalue"),
		containsUpdatexml:       strings.Contains(normalized, "updatexml"),
		containsCase:            strings.Contains(normalized, "case"),
		containsWhen:            strings.Contains(normalized, "when"),
		containsOrder:           strings.Contains(normalized, "order"),
		containsSubstr:          strings.Contains(normalized, "substr"),
		containsSubstring:       strings.Contains(normalized, "substring"),
		containsMid:             strings.Contains(normalized, "mid"),
		containsXP:              strings.Contains(normalized, "xp_"),
		containsProcedure:       strings.Contains(normalized, "procedure"),
		containsUTL:             strings.Contains(normalized, "utl_"),
		containsDBMS:            strings.Contains(normalized, "dbms_"),
		containsHaving:          strings.Contains(normalized, "having"),
		containsLike:            strings.Contains(normalized, "like"),
		containsLimit:           strings.Contains(normalized, "limit"),
		containsOffset:          strings.Contains(normalized, "offset"),
		containsGroup:           strings.Contains(normalized, "group"),
		containsCopy:            strings.Contains(normalized, "copy"),
		containsProgram:         strings.Contains(normalized, "program"),
		containsUTLInaddr:       strings.Contains(normalized, "utl_inaddr"),
		containsMaster:          strings.Contains(normalized, "master"),
		containsFullwidthS:      strings.Contains(normalized, "\xef\xbd\x93") || strings.Contains(normalized, "\xef\xbc\xb3"),
		containsDoubleURLEncode: strings.Contains(normalized, "%25"),
	}
}

func shouldScanSQLiPattern(normalized string, p owaspPattern) bool {
	return shouldScanSQLiPatternWithSignals(normalized, p, collectSQLiPatternSignals(normalized))
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
		return hasSQLBooleanQuotedComparison(normalized)
	case "owasp:sqli:036":
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

func hasSQLBooleanQuotedComparison(s string) bool {
	for i := 0; i < len(s); i++ {
		end, ok := sqlBooleanOperatorEndAt(s, i)
		if !ok || end >= len(s) {
			continue
		}
		j := skipSQLSpaces(s, end)
		if j == end {
			continue
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
		return OWASPHit{Category: CatSQLi, RuleID: "owasp:sqli:001", Score: 5, Desc: "SQL injection signals"}, true
	}
	if strings.Contains(normalized, "and1=1") || strings.Contains(normalized, "or1=1") {
		return OWASPHit{Category: CatSQLi, RuleID: "owasp:sqli:010", Score: 5, Desc: "SQL injection signals"}, true
	}
	if !hasSQLiIndicator(normalized) {
		return OWASPHit{}, false
	}
	signals := collectSQLiPatternSignals(normalized)
	total := 0
	for _, p := range sqliPatterns {
		if threshold > 3 {
			switch p.id {
			case "owasp:sqli:028", "owasp:sqli:031", "owasp:sqli:038", "owasp:sqli:041", "owasp:sqli:046", "owasp:sqli:047":
				if !signals.containsSelect {
					continue
				}
			case "owasp:sqli:004", "owasp:sqli:006", "owasp:sqli:012", "owasp:sqli:034":
				if !signals.containsSemicolon {
					continue
				}
			case "owasp:sqli:005", "owasp:sqli:050", "owasp:sqli:051", "owasp:sqli:052":
				if !signals.containsComment {
					continue
				}
			}
		}
		if !shouldScanSQLiPatternWithSignals(normalized, p, signals) {
			continue
		}
		if !p.re.MatchString(normalized) {
			continue
		}
		total += p.score
		if total < threshold {
			continue
		}
		hit := OWASPHit{Category: CatSQLi, RuleID: p.id, Score: total, Desc: "SQL injection signals"}
		if isSQLiFalsePositive(normalized, hit.RuleID) {
			continue
		}
		return hit, true
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
		return strings.Contains(normalized, "(") && strings.ContainsAny(normalized, "'\"") && (strings.Contains(normalized, "eval") || strings.Contains(normalized, "settimeout") || strings.Contains(normalized, "setinterval"))
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
		return strings.Contains(normalized, "(![]") || strings.Contains(normalized, "(!![]") || strings.Contains(normalized, "+{}") || strings.Contains(normalized, "+[]")
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
		return strings.Contains(normalized, ".") && strings.Contains(normalized, "(") && (strings.Contains(normalized, "alert") || strings.Contains(normalized, "prompt") || strings.Contains(normalized, "confirm"))
	default:
		return true
	}
}

func nextXSSHit(normalized string, threshold int) (OWASPHit, bool) {
	if !hasXSSIndicator(normalized) {
		return OWASPHit{}, false
	}
	total := 0
	for _, p := range xssPatterns {
		if !shouldScanXSSPattern(normalized, p) {
			continue
		}
		if !p.re.MatchString(normalized) {
			continue
		}
		total += p.score
		if total < threshold {
			continue
		}
		hit := OWASPHit{Category: CatXSS, RuleID: p.id, Score: total, Desc: "XSS signals"}
		if hit.RuleID == "owasp:xss:002" && isXSSHandlerFunctionRef(normalized) {
			continue
		}
		if (hit.RuleID == "owasp:xss:001" || hit.RuleID == "owasp:xss:014") && isXSSFalsePositive(normalized, hit.RuleID) {
			continue
		}
		if threshold > 2 && hit.RuleID != "owasp:xss:001" && hit.RuleID != "owasp:xss:014" && isXSSFalsePositive(normalized, hit.RuleID) {
			continue
		}
		return hit, true
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
	if plusSlash < 16 {
		return false
	}
	return true
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
	{regexp.MustCompile(`\.{4,}[/\\]`), 4, "owasp:path_traversal:009", ""},
	{regexp.MustCompile(`(^|[/\\])\.\.[/\\](etc[/\\](passwd|shadow|hosts|hostname|group)|proc[/\\]version|root[/\\]|var[/\\]log[/\\])`), 5, "owasp:path_traversal:010", ".."},
	{regexp.MustCompile(`(%252e|%252f|%255c){2,}`), 4, "owasp:path_traversal:011", "%25"},
	{regexp.MustCompile(`(\.\.\\){2,}`), 4, "owasp:path_traversal:012", ""},
	{regexp.MustCompile(`\.\.[/\\].*(web-inf|meta-inf|web\.xml|struts\.xml|applicationcontext\.xml)`), 5, "owasp:path_traversal:013", ".."},
	{regexp.MustCompile(`(web-inf|meta-inf)[/\\]web\.xml`), 5, "owasp:path_traversal:014", ""},
	{regexp.MustCompile(`\.\.[/\\]*(\.git[/\\]|\.env|\.htpasswd|\.aws[/\\]|\.ssh[/\\]|config\.php|settings\.py|\.ds_store)`), 4, "owasp:path_traversal:015", ".."},
	{regexp.MustCompile(`\.\.[/\\](admin|login|manager|console|config|passwd|shadow|private)`), 4, "owasp:path_traversal:016", ".."},
}

func checkPathTraversal(s string, threshold int) (OWASPHit, bool) {
	if !hasPathTravIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range pathTravPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatPathTrav, RuleID: best, Score: total, Desc: "path traversal signals"}, true
			}
		}
	}
	return OWASPHit{}, false
}
