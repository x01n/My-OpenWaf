package waf

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
)

const BuiltinVersion = "builtin_owasp_v2"

// maxTargetLen bounds the length of each scan target to limit regex execution time.
const maxTargetLen = 8192

type OWASPHit struct {
	Category OWASPCategory
	RuleID   string
	Score    int
	Desc     string
}

// CheckOWASP scans request fields for OWASP-oriented attacks.
// bodyTargets are pre-extracted values from the request body (form values, JSON leaves).
// The path parameter is also used for context: internal API paths get reduced scanning.
func CheckOWASP(sensitivity string, path, query string, headers map[string]string, bodyTargets []string) []OWASPHit {
	threshold := sensitivityThreshold(sensitivity)
	var hits []OWASPHit

	targets := collectTargets(path, query, headers)
	targets = append(targets, bodyTargets...)
	for _, raw := range targets {
		if raw == "" {
			continue
		}
		// Fast path: skip targets that are clearly safe (pure alphanumeric + safe chars).
		if isCleanTarget(raw) {
			continue
		}
		// Truncate oversized targets to bound regex scan time.
		if len(raw) > maxTargetLen {
			raw = raw[:maxTargetLen]
		}
		normalized := normalizeWithDecode(raw)
		// Check raw string for Java serialization patterns that get mangled by normalize.
		if strings.Contains(raw, "%ac%ed") || strings.Contains(raw, "%AC%ED") ||
			strings.Contains(raw, "aced0005") || strings.Contains(raw, "ACED0005") {
			return []OWASPHit{{Category: CatDeserial, RuleID: "owasp:deser:012", Score: 5, Desc: "Java serialization magic bytes (URL-encoded)"}}
		}
		// CRLF check on URL-decoded (but not whitespace-normalized) input,
		// because normalize() replaces \r\n with spaces.
		if strings.Contains(raw, "%0d") || strings.Contains(raw, "%0D") ||
			strings.Contains(raw, "%0a") || strings.Contains(raw, "%0A") ||
			strings.ContainsAny(raw, "\r\n") {
			urlDec := raw
			if d, err := url.PathUnescape(raw); err == nil {
				urlDec = d
			}
			lower := strings.ToLower(urlDec)
			if hit, ok := checkCRLF(lower, threshold); ok {
				if !isCRLFFalsePositive(lower, hit.RuleID) {
					return []OWASPHit{hit}
				}
			}
		}
		if !hasSuspiciousContent(normalized) {
			continue
		}
		if hit, ok := checkSQLi(normalized, threshold); ok {
			// Context check: reduce false positives on common natural language patterns.
			if !isSQLiFalsePositive(normalized, hit.RuleID) {
				return []OWASPHit{hit}
			}
		}
		if hit, ok := checkXSS(normalized, threshold); ok {
			// CDN ?onload=callbackName callbacks (no parens, no HTML context) are never XSS.
			// isXSSHandlerFunctionRef is precise enough to apply at ALL sensitivity levels.
			if hit.RuleID == "owasp:xss:002" && isXSSHandlerFunctionRef(normalized) {
				// Suppress: plain CDN callback identifier (e.g. onload=_cf_chl_turnstile_l)
			} else if threshold <= 2 || !isXSSFalsePositive(normalized, hit.RuleID) {
				// At high sensitivity, always report XSS (except the CDN callback case above).
				// At mid/low sensitivity, suppress structural-HTML-only hits.
				return []OWASPHit{hit}
			}
		}
		if hit, ok := checkCmdInjection(normalized, threshold); ok {
			if !isCmdInjectionFalsePositive(normalized, hit.RuleID) {
				return []OWASPHit{hit}
			}
		}
		if hit, ok := checkWebshell(normalized, threshold); ok {
			if !isWebshellFalsePositive(normalized, hit.RuleID) {
				return []OWASPHit{hit}
			}
		}
		if hit, ok := checkRevShell(normalized, threshold); ok {
			return []OWASPHit{hit}
		}
		if hit, ok := checkPathTraversal(normalized, threshold); ok {
			if threshold <= 2 || !isPathTravFalsePositive(normalized, hit.RuleID) {
				return []OWASPHit{hit}
			}
		}
		if hit, ok := checkSSRF(normalized, threshold); ok {
			if !isSSRFFalsePositive(normalized, hit.RuleID) {
				hits = append(hits, hit)
			}
		}
		if hit, ok := checkXXE(normalized, threshold); ok {
			return []OWASPHit{hit}
		}
		if hit, ok := checkLDAPInjection(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkNoSQLi(normalized, threshold); ok {
			if !isNoSQLiFalsePositive(normalized, hit.RuleID) {
				hits = append(hits, hit)
			}
		}
		if hit, ok := checkTemplateInjection(normalized, threshold); ok {
			return []OWASPHit{hit}
		}
		if hit, ok := checkJNDI(normalized, threshold); ok {
			return []OWASPHit{hit}
		}
		if hit, ok := checkCRLF(normalized, threshold); ok {
			if !isCRLFFalsePositive(normalized, hit.RuleID) {
				return []OWASPHit{hit}
			}
		}
		if hit, ok := checkExprLang(normalized, threshold); ok {
			if !isELFalsePositive(normalized, hit.RuleID) {
				return []OWASPHit{hit}
			}
		}
		if hit, ok := checkDeserialization(normalized, threshold); ok {
			// Context check: skip binary false positives (short payloads from innocent data).
			if !isDeserFalsePositive(normalized, hit.RuleID) {
				return []OWASPHit{hit}
			}
		}
		if len(hits) > 0 {
			return hits
		}
	}

	// Protocol-level checks that inspect headers directly (not normalized).
	if hit, ok := checkProtocolViolation(headers, threshold); ok {
		hits = append(hits, hit)
	}

	// Check URL path for dangerous file extension patterns (e.g. /upload/shell.php.jpg).
	if hit, ok := checkPathFileUpload(path); ok {
		hits = append(hits, hit)
	}

	// CVE-specific dangerous paths (F5, Liferay, Apache OFBiz, etc.)
	if hit, ok := checkDangerousPath(path); ok {
		hits = append(hits, hit)
	}

	return hits
}

// CheckFileUpload inspects filename/content-type for dangerous uploads.
// Called separately because it needs the raw filename, not normalized.
func CheckFileUpload(filename, contentType string) (OWASPHit, bool) {
	return checkFileUpload(filename, contentType)
}

var webExecutableExtensions = map[string]bool{
	".php": true, ".php3": true, ".php4": true, ".php5": true,
	".phtml": true, ".phar": true, ".jsp": true, ".jspx": true,
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
	if strings.Contains(lower, "+cscot+/") || strings.Contains(lower, "+cscoe+/") {
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

func sensitivityThreshold(s string) int {
	switch strings.ToLower(s) {
	case "low":
		return 7
	case "high":
		return 3 // Raised from 2 to 3 to reduce false positives
	default:
		return 4
	}
}

// skipHeaders lists standard headers whose values are not user-controlled payloads.
// Scanning these causes false positives (e.g. Host: 127.0.0.1 → SSRF alert).
var skipHeaders = map[string]bool{
	"host":                          true,
	"connection":                    true,
	"content-length":                true,
	"content-type":                  false,
	"accept":                        false,
	"accept-language":               true,
	"accept-encoding":               true,
	"cookie":                        true,
	"authorization":                 true,
	"cache-control":                 true,
	"pragma":                        true,
	"if-modified-since":             true,
	"if-none-match":                 true,
	"upgrade":                       true,
	"upgrade-insecure-requests":     true,
	"dnt":                           true,
	"te":                            true,
	"origin":                        true,
	"sec-fetch-mode":                true,
	"sec-fetch-site":                true,
	"sec-fetch-dest":                true,
	"sec-fetch-user":                true,
	"sec-ch-ua":                     true,
	"sec-ch-ua-mobile":              true,
	"sec-ch-ua-platform":            true,
	// Extended Client Hints — browser-controlled values, not user payloads.
	"sec-ch-ua-arch":                true,
	"sec-ch-ua-bitness":             true,
	"sec-ch-ua-full-version":        true,
	"sec-ch-ua-full-version-list":   true,
	"sec-ch-ua-model":               true,
	"sec-ch-ua-platform-version":    true,
	// Google proprietary header sent by Chrome alongside reCAPTCHA/SafeBrowsing requests.
	// Contains base64-encoded client experiment IDs — not user-supplied data.
	"x-client-data":                 true,
}

func collectTargets(path, query string, headers map[string]string) []string {
	out := []string{path, query}
	for k, v := range headers {
		lk := strings.ToLower(k)
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
		out = append(out, v)
	}
	return out
}

// extractRefererTargets extracts scannable parts from a Referer URL.
// Returns the raw query string and the path (for path traversal detection),
// but NOT the scheme+host to avoid SSRF false positives.
func extractRefererTargets(referer string) []string {
	u, err := url.Parse(referer)
	if err != nil {
		return nil
	}
	var targets []string
	if u.RawQuery != "" {
		targets = append(targets, u.RawQuery)
	}
	if u.Fragment != "" {
		targets = append(targets, u.Fragment)
	}
	return targets
}

// extractCookieValues splits a Cookie header and returns individual values,
// filtering out likely session identifiers to avoid false positives.
func extractCookieValues(raw string) []string {
	var values []string
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
		values = append(values, val)
	}
	return values
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

// normalize does URL-decode (multi-pass), HTML entity decode, JS escape decode, lowercase, whitespace collapse.
func normalize(s string) string {
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
	// Pass 1 uses QueryUnescape (decodes both %XX and + → space).
	// Passes 2+ use PathUnescape (only decodes %XX) to avoid mangling
	// literal '+' characters that were produced by pass 1 (e.g. %2B → +).
	// Without this, JSFuck payloads like (+{}+[]) lose their '+' on pass 2,
	// and UTF-7 sequences like +ADw- lose their '+' prefix.
	for i := range 3 {
		var decoded string
		var err error
		if i == 0 {
			decoded, err = url.QueryUnescape(s)
		} else {
			decoded, err = url.PathUnescape(s)
		}
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	// Multi-pass HTML entity decode.
	for range 2 {
		decoded := html.UnescapeString(s)
		if decoded == s {
			break
		}
		s = decoded
	}
	// JavaScript escape sequence decode: \xNN, \uXXXX, \u{XXXX}, \NNN (octal).
	// This defeats obfuscation like window['\x61\x6c\x65\x72\x74'] → window['alert'].
	if strings.Contains(s, "\\") {
		s = decodeJSEscapes(s)
	}
	// Post-JS-escape URL decode: JS escapes may produce percent-encoded chars
	// (e.g. \u0025\u0032\u0038 → %28 → '('). Multi-pass to handle double/triple encoding.
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

// normalizeWithDecode normalizes and attempts base64 decoding of suspicious tokens.
func normalizeWithDecode(raw string) string {
	s := normalize(raw)
	// Fast path: if normalized string has no base64-length tokens, skip expensive scanning.
	if len(s) < 8 || !hasBase64Candidate(s) && !hasBase64Candidate(raw) {
		return s
	}
	// Build a case-preserving URL-decoded version for base64 extraction.
	// normalize() lowercases which destroys base64 case sensitivity,
	// and raw may have %XX wrapping base64 boundaries (e.g. %22TOKEN%22).
	urlDecoded := raw
	for i := range 3 {
		var d string
		var err error
		if i == 0 {
			d, err = url.QueryUnescape(urlDecoded)
		} else {
			d, err = url.PathUnescape(urlDecoded)
		}
		if err != nil || d == urlDecoded {
			break
		}
		urlDecoded = d
	}
	sources := []string{raw, s}
	if urlDecoded != raw {
		sources = append(sources, urlDecoded)
	}
	// Build a case-preserving JS-escape-decoded version for base64 extraction.
	// \u00XX escapes may encode base64 characters that are case-sensitive.
	if strings.Contains(urlDecoded, "\\") {
		jsDecoded := decodeJSEscapes(urlDecoded)
		if jsDecoded != urlDecoded {
			sources = append(sources, jsDecoded)
		}
	}
	var b strings.Builder
	seen := make(map[string]bool, 8)
	found := false
	for _, src := range sources {
		for _, tok := range reBase64Token.FindAllString(src, 20) {
			if seen[tok] {
				continue
			}
			seen[tok] = true
			if decoded := decodeBase64IfSuspicious(tok); decoded != "" {
				if !found {
					b.Grow(len(s) + 256)
					b.WriteString(s)
					found = true
				}
				normalizedDecoded := normalize(decoded)
				b.WriteByte(' ')
				b.WriteString(normalizedDecoded)
				decodedForB64 := decoded
				if strings.Contains(decoded, "\\") {
					decodedForB64 = decodeJSEscapes(decoded)
				}
				for _, src2 := range []string{decoded, decodedForB64} {
					for _, tok2 := range reBase64Token.FindAllString(src2, 10) {
						if seen[tok2] {
							continue
						}
						seen[tok2] = true
						if decoded2 := decodeBase64IfSuspicious(tok2); decoded2 != "" {
							normalizedDecoded2 := normalize(decoded2)
							b.WriteByte(' ')
							b.WriteString(normalizedDecoded2)
							decodedForB64_2 := decoded2
							if strings.Contains(decoded2, "\\") {
								decodedForB64_2 = decodeJSEscapes(decoded2)
							}
							for _, src3 := range []string{decoded2, decodedForB64_2} {
								for _, tok3 := range reBase64Token.FindAllString(src3, 10) {
									if seen[tok3] {
										continue
									}
									seen[tok3] = true
									if decoded3 := decodeBase64IfSuspicious(tok3); decoded3 != "" {
										b.WriteByte(' ')
										b.WriteString(normalize(decoded3))
									}
								}
							}
						}
					}
				}
			}
		}
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

// stripSQLComments removes /* ... */ style inline comments from s to defeat
// comment-splitting evasion (e.g. sel/**/ect → select). MySQL version-specific
// comments /*!50000...*/  are intentionally preserved because they contain
// executable SQL and are matched by rule owasp:sqli:020.
func stripSQLComments(s string) string {
	if !strings.Contains(s, "/*") {
		return s
	}
	var buf strings.Builder
	buf.Grow(len(s))
	i := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			if i+2 < len(s) && s[i+2] == '!' {
				// MySQL version comment /*!50000...*/: keep in place so rule:020 can match.
				buf.WriteByte(s[i])
				i++
				continue
			}
			// Regular comment /* ... */: strip entirely (join surrounding tokens).
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				// Unclosed comment — write literally.
				buf.WriteByte(s[i])
				i++
				continue
			}
			i = i + 2 + end + 2 // advance past closing */
		} else {
			buf.WriteByte(s[i])
			i++
		}
	}
	return buf.String()
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
// mostly printable ASCII (≥80%). Returns empty string on failure or binary data.
func decodeBase64IfSuspicious(s string) string {
	if len(s) < 8 {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return ""
		}
	}
	if len(decoded) == 0 {
		return ""
	}
	printable := 0
	for _, b := range decoded {
		if b >= 0x20 && b <= 0x7E {
			printable++
		}
	}
	if float64(printable)/float64(len(decoded)) < 0.8 {
		// Binary output might be caused by a non-base64 prefix (e.g. path '/')
		// that happens to be valid base64 but shifts the decode alignment.
		if len(s) > 8 && !isBase64AlphaNum(s[0]) {
			return decodeBase64IfSuspicious(s[1:])
		}
		return ""
	}
	return string(decoded)
}

func isBase64AlphaNum(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// ── Performance: fast pre-filter ──

// cleanCharSet marks bytes that are safe in target values (no attack potential).
// Alphanumeric + hyphen + underscore + period + space + comma + @.
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

// isCleanTarget returns true if the raw string contains only safe chars
// that cannot form any attack pattern. This skips all normalization and scanning.
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
	return strings.ContainsAny(s, "|;`") ||
		strings.Contains(s, "$(") ||
		strings.Contains(s, "${") ||
		strings.Contains(s, "&&") ||
		strings.Contains(s, ">>") ||
		strings.Contains(s, "%00") ||
		strings.Contains(s, "\x00") ||
		strings.Contains(s, "\n") ||
		strings.Contains(s, "\r") ||
		strings.Contains(s, "wget ") ||
		strings.Contains(s, "curl ") ||
		strings.Contains(s, "<!--#")
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
		strings.Contains(s, "connector.minimal")
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
		return true // sleep()/benchmark() without SQL context → JavaScript FP

	case "owasp:sqli:006": // '\s*;\s*\w — apostrophe + semicolon + word char
		// This pattern fires on JavaScript code in CSP/NEL reports and browser telemetry:
		// e.g. "'use strict'; concat(a, b)" — apostrophe ends a string literal, semicolon
		// terminates a statement, and concat is a common function name.
		// Suppress unless a SQL structural keyword confirms injection context.
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
		if len(lower) > 500 && !strings.Contains(lower, "union") &&
			!strings.Contains(lower, "select") &&
			!strings.Contains(lower, "sleep(") &&
			!strings.Contains(lower, "benchmark(") {
			return true
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
		if !reUnionSelectAttackCtx.MatchString(lower) {
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
func isXSSFalsePositive(normalized, firstRuleID string) bool {
	switch firstRuleID {
	case "owasp:xss:032": // /regex/.source concatenation
		return false
	case "owasp:xss:052": // global[( JSFuck
		return !hasActiveXSSContext(normalized)
	case "owasp:xss:001": // <script[\s>]
		lower := strings.ToLower(normalized)
		if len(normalized) > 200 {
			if !strings.Contains(lower, "alert(") &&
				!strings.Contains(lower, "eval(") &&
				!strings.Contains(lower, "document.cookie") &&
				!strings.Contains(lower, "document.write") &&
				!strings.Contains(lower, "prompt(") &&
				!strings.Contains(lower, "confirm(") &&
				!strings.Contains(lower, "fromcharcode") &&
				!strings.Contains(lower, "</script") &&
				!strings.Contains(lower, "src=") &&
				!strings.Contains(lower, "onerror") &&
				!strings.Contains(lower, "onload") &&
				!strings.Contains(lower, "fetch(") &&
				!strings.Contains(lower, "innerhtml") &&
				!strings.Contains(lower, "xmlhttp") &&
				!strings.Contains(lower, "\\u00") &&
				!strings.Contains(lower, "base64") {
				return true
			}
		}
		if !strings.Contains(lower, "</script") && !strings.Contains(lower, "alert(") &&
			!strings.Contains(lower, "eval(") && !strings.Contains(lower, "src=") &&
			!strings.Contains(lower, "onerror") && !strings.Contains(lower, "onload") {
			idx := strings.Index(lower, "<script")
			if idx >= 0 {
				after := lower[idx+7:]
				if len(after) > 0 && after[0] != '>' && after[0] != ' ' && after[0] != '\t' {
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
		// javascript:void(0) and javascript:; are ubiquitous in legitimate HTML
		// (<a href="javascript:void(0)">). Analytics/CMS data frequently contains these.
		// At mid sensitivity, suppress when no dangerous JS function calls or
		// event handlers are present alongside the javascript: URI.
		// NOTE: we do NOT use hasActiveXSSContext because it contains "javascript:" itself.
		lower := strings.ToLower(normalized)
		if !strings.Contains(lower, "alert(") &&
			!strings.Contains(lower, "confirm(") &&
			!strings.Contains(lower, "prompt(") &&
			!strings.Contains(lower, "eval(") &&
			!strings.Contains(lower, "document.cookie") &&
			!strings.Contains(lower, "document.write") &&
			!strings.Contains(lower, "innerhtml") &&
			!strings.Contains(lower, "fromcharcode") &&
			!strings.Contains(lower, "<script") &&
			!strings.Contains(lower, "fetch(") &&
			!strings.Contains(lower, "xmlhttp") &&
			!reXSSEventHandler.MatchString(lower) {
			return true
		}
	case "owasp:xss:005", "owasp:xss:007", "owasp:xss:008",
		"owasp:xss:012", "owasp:xss:015",
		"owasp:xss:022", "owasp:xss:024", "owasp:xss:028":
		return !hasActiveXSSContext(normalized)
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
		strings.Contains(normalized, "<script") {
		return false
	}
	return true
}

// reXSSEventHandler matches inline event handler attributes (on<event>=).
var reXSSEventHandler = regexp.MustCompile(`(?i)\bon\w+\s*=`)
var reJSProtocolObfuscated = regexp.MustCompile(`(?i)j\s*a\s*v\s*a\s+s\s*c\s*r\s*i\s*p\s*t\s*:`)

// reBacktickInjectionCtx: backtick command substitution is in shell injection position when
// the opening backtick is at start-of-string or immediately preceded by a shell operator
// (=, ;, |, &, $) or a flag-style argument (e.g. --exec=`id`).
// When this pattern does NOT match, the backtick appears in a natural-language or
// documentation context (e.g. "Use `echo` to print") and should be suppressed.
// NOTE: this deliberately excludes comma and closing-backtick from the operator set
// so that Markdown "try `cat`, `grep`" does not falsely match via the second backtick.
var reBacktickInjectionCtx = regexp.MustCompile("(?i)(^|[=;|&$])\\s*`[^`]*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|echo|rm|chmod|chown|python|perl|ruby|php|base64|find|grep|awk|sed|ps|kill|nslookup|dig|ping|sleep|dd|cp|mv|mkdir|touch|head|tail|sort|xxd)[^`]*`")

// reCmdHighConfidence matches patterns that confirm genuine command injection intent.
// When cmd:006 (null byte / newline injection) is the first-matching rule, we require
// at least one of these high-confidence indicators to be present before reporting the hit.
// This suppresses false positives caused by null bytes in binary / analytics data that
// happen to co-trigger a weak secondary pattern (e.g. cmd:010 env-var + language name).
var reCmdHighConfidence = regexp.MustCompile(
	`(?i)(` +
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
	case "owasp:cmd:002": // backtick command substitution (score=4)
		if reBacktickInjectionCtx.MatchString(normalized) {
			return false
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
	}
	return false
}

// reSQLi022FuncCall detects sqli:022 keywords used as SQL function calls (with parentheses),
// as opposed to JavaScript variable names like `if (length > 0)`.
var reSQLi022FuncCall = regexp.MustCompile(`(?i)\bif\s*\(\s*(length|count|version|substr|select)\s*\(`)

// reSQLi022ClauseCtx detects SQL clause keywords that confirm a SQL injection context.
// Includes `select` followed by space or `(` to catch `if(select database(),...)` patterns
// while excluding `select.value` (JavaScript DOM element).
var reSQLi022ClauseCtx = regexp.MustCompile(`(?i)\b(from|where|union|having)\b|\bselect[\s(]`)

// reANDORSleep detects the "AND sleep()" / "OR sleep()" pattern used in boolean-based
// time injection: `1 AND sleep(5)`, `1 OR pg_sleep(5)`, `1 AND benchmark(...)`.
var reANDORSleep = regexp.MustCompile(`(?i)\b(and|or)\s+(sleep|pg_sleep|benchmark)\s*\(`)

// reSQLTerminatorCtx detects a SQL comment/terminator preceded by closing parenthesis or
// quote/digit, indicating injection context like "1); sleep(5)--".
var reSQLTerminatorCtx = regexp.MustCompile(`(?i)['")\d]\s*(--|/\*)`)

// reUnionSelectAttackCtx confirms that a "union select" hit (sqli:001) is a genuine SQL injection
// attempt rather than natural-language text about SQL (e.g. developer search queries, docs).
// Analytics beacons frequently carry page URLs like "q=union+select+syntax+in+sql" where
// the phrase appears in a human search query with no structural SQL markers.
// Suppress sqli:001 unless at least one structural indicator is present.
var reUnionSelectAttackCtx = regexp.MustCompile(`(?i)(` +
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

// reIntoOutfileWithPath confirms that an INTO OUTFILE/DUMPFILE hit (sqli:017) carries a
// quoted file path (required by MySQL syntax). Documentation text such as "SELECT INTO OUTFILE S3"
// (AWS Aurora) does not have a quoted path and should be suppressed.
var reIntoOutfileWithPath = regexp.MustCompile(`(?i)\binto\s+(out|dump)file\s*['"]`)

// reSQLiInjectionOps matches SQL injection attack operators that are unlikely to appear
// in legitimate analytics beacons or documentation text. Used by sqli:005 suppressor
// to distinguish URL/path wildcards (/* in S3 ARNs) from genuine SQL inline comments.
var reSQLiInjectionOps = regexp.MustCompile(
	`(?i)(union\s+(all\s+)?select\b` + // UNION injection
		`|\bor\s+\d+\s*=\s*\d+` + // OR 1=1 boolean
		`|\band\s+\d+\s*=\s*\d+` + // AND 1=2 boolean
		`|'\s*(or|and)\s+['"\d]` + // ' or 'x'='x'
		`|\bsleep\s*\(` + // time-based blind
		`|\bbenchmark\s*\(` + // time-based MySQL
		`|;\s*(drop|truncate)\s+\w)`) // destructive DDL stacked query

// reXSSHandlerCallParens detects a function call (opening parenthesis) in the value portion
// of an HTML event handler attribute: onload=alert(1) → the ( is present.
// CDN script loaders use ?onload=callbackName (a plain identifier, no parens), which is safe.
var reXSSHandlerCallParens = regexp.MustCompile(`(?i)\bon\w+\s*=\s*[^;& \n\r]*\(`)

// reSQLi008AttackCtx confirms that a hex-literal hit (sqli:008) is a genuine SQL injection
// attempt and not a benign hex value (CSS color, memory address, binary protocol).
// When sqli:008 is the first-matching rule, we suppress the hit unless this regex matches.
var reSQLi008AttackCtx = regexp.MustCompile(`(?i)(` +
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
	`(?i)(etc/passwd|etc/shadow|etc/hosts|/etc/|proc/self|/proc/|windows/system32|win\.ini|boot\.ini|cmd\.exe|/root/|/home/\w|\.env$|web\.xml|nginx\.conf|apache\.conf|web-inf|meta-inf|\.git/|\.svn/|\.htpasswd|\.aws/|\.ssh/|/bin/sh|/bin/bash|/bin/cat|/usr/bin|/var/log|/tmp/|/dev/)`)

// reTautology detects boolean tautologies like "or 1=1", "and 2=2" (same number both sides).
// Go regexp doesn't support backreferences, so we extract and compare manually.
var reTautologyCapture = regexp.MustCompile(`(?i)\b(?:or|and)\s+(\d+)\s*=\s*(\d+)\b`)

func isTautology(s string) bool {
	matches := reTautologyCapture.FindAllStringSubmatch(s, -1)
	for _, m := range matches {
		if len(m) >= 3 && m[1] == m[2] {
			return true
		}
	}
	return false
}

// reBoolSQLContext checks whether a boolean condition is used near SQL keywords,
// indicating a real SQLi attempt rather than a coincidental number comparison.
var reBoolSQLContext = regexp.MustCompile(`(?i)(select|from|where|union|having|group|order)\b`)

// reSQLDMLContext matches SQL structural markers that confirm a DML/DDL injection
// context (e.g. "drop table", "delete from", "insert into", "values(").
// MSSQL-specific stored-procedure prefixes (xp_/sp_) are unambiguous SQL context.
// Used to avoid false positives on ";" + keyword in JavaScript or natural language.
var reSQLDMLContext = regexp.MustCompile(`(?i)\b(table|into\b|values\s*\(|database|schema|columns\s+from|rows\s+from|truncate\b)\b|\b(xp_|sp_[a-z])\w`)

// isPathTravFalsePositive suppresses path traversal hits from basic `../../` sequences
// that appear in relative JavaScript imports, TypeScript paths, and build system configs
// when no known-sensitive OS file or directory is present in the payload.
// At high sensitivity (threshold ≤ 2), this check is bypassed by the caller.
func isPathTravFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:path_traversal:001", "owasp:path_traversal:004":
		// Basic ../../ sequences are common in relative module paths (require('../../utils')).
		// Only block if the traversal targets a known sensitive OS path.
		return !rePathTravSensitive.MatchString(normalized)
	}
	return false
}
func isSSRFFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:ssrf:007":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "gopher://") ||
			strings.Contains(lower, "file://") ||
			strings.Contains(lower, "dict://") {
			return false
		}
		if strings.Contains(lower, "localhost") && !strings.Contains(lower, "127.") {
			if len(normalized) > 100 && !strings.Contains(lower, "@") &&
				!strings.Contains(lower, "metadata") &&
				!strings.Contains(lower, "169.254.") {
				return true
			}
		}
	}
	return false
}

func isDeserFalsePositive(raw, ruleID string) bool {
	switch ruleID {
	case "owasp:deser:005": // Ruby marshal magic \x04\x08
		// This two-byte sequence is extremely common in binary data.
		// Only flag if the payload is relatively short and has other suspicious content.
		if len(raw) > 256 {
			return true // Long binary payload — likely file upload, not exploit
		}
		return false
	case "owasp:deser:001": // Java serialization \xac\xed\x00\x05
		// Java serialization magic is a strong signal, rarely a false positive.
		return false
	}
	return false
}

// isNoSQLiFalsePositive returns true when a low-signal NoSQL operator match
// lacks the surrounding query structure that indicates real injection.
// Operators like $ne/$gt/$regex at score=3 can appear in legitimate API messages.
func isNoSQLiFalsePositive(raw, ruleID string) bool {
	switch ruleID {
	case "owasp:nosql:002", "owasp:nosql:003", "owasp:nosql:004": // $ne, $gt, $regex
		// Require MongoDB-like attack context: operator preceded by [ { : or =
		// (bracket subscript, JSON object, or URL parameter).
		if !reNoSQLAttackCtx.MatchString(raw) {
			return true
		}
	case "owasp:nosql:005", "owasp:nosql:006": // $or:[ and $exists
		// These operators are standard in legitimate MongoDB query filters.
		// When best rule is nosql:005/006, higher-priority operators ($where/nosql:001 score=5,
		// $ne/nosql:002, $gt/003, $regex/004) did not fire first, meaning the signal is too
		// low-confidence to distinguish legitimate query APIs from injection.
		// $where (nosql:001) alone already triggers at mid sensitivity (score=5 ≥ 4).
		return true
	}
	return false
}

// isELFalsePositive returns true when an Expression Language hit is likely from
// a Java class reference in a stack trace or error message rather than an
// actual EL template injection attempt.
func isELFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:el:005": // java.lang.(Runtime|ProcessBuilder|Class) reference
		// Java class names appear in stack traces, error messages, API docs, and
		// log submissions. Only flag if embedded in an EL template context OR
		// OGNL reflection chain (getClass, getDeclaredMethods, invoke, forName).
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
	}
	return false
}

// reCRLFHeaderInject matches HTTP header names or a status line following double-CRLF,
// indicating a real HTTP response-splitting attempt (e.g., \r\n\r\nLocation: https://evil.com).
var reCRLFHeaderInject = regexp.MustCompile(`(?i)\r\n\r?\n\s*(HTTP/[\d.]+\s+\d{3}|[A-Za-z][-A-Za-z0-9]+\s*:)`)

// reWebshellPHPContext matches PHP-specific markers that confirm a webshell context.
// eval()/exec()/system() alone are common in JavaScript/Python; these PHP-specific
// markers distinguish real webshells from legitimate code.
var reWebshellPHPContext = regexp.MustCompile(`(?i)(base64_decode\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|\$_(get|post|request|cookie|server|files)\s*\[|<\?php\b|\.getruntime\(\)|subprocess|os\.system|response\.\s*write)`)

// isWebshellFalsePositive suppresses webshell:001 hits that come only from eval() or assert(),
// which are extremely common in JavaScript (frontend code, test suites, REPL sessions).
// High-confidence shell functions (system, exec, shell_exec, popen, proc_open) are never suppressed.
func isWebshellFalsePositive(normalized, ruleID string) bool {
	if ruleID == "owasp:webshell:001" {
		// If PHP/shell-specific markers are present, it's a real webshell attempt.
		if reWebshellPHPContext.MatchString(normalized) {
			return false
		}
		// system/exec/popen are high-confidence RCE signals — always flag.
		if strings.Contains(normalized, "system(") ||
			strings.Contains(normalized, "exec(") ||
			strings.Contains(normalized, "popen(") ||
			strings.Contains(normalized, "proc_open(") {
			return false
		}
		// Only eval() or assert() without PHP/shell context: likely JavaScript FP.
		return true
	}
	return false
}

// isCRLFFalsePositive suppresses the bare double-CRLF pattern (crlf:004) when
// there is no HTTP header or status-line injection following the separator.
// Legitimate multi-line text fields on Windows naturally contain \r\n\r\n (blank
// lines between paragraphs) without any header-name: value following them.
func isCRLFFalsePositive(normalized, ruleID string) bool {
	if ruleID == "owasp:crlf:004" {
		// Bare \r\n\r\n is common in multi-line textarea values (Windows newlines).
		// Require HTTP header/status-line context after the separator to confirm injection.
		return !reCRLFHeaderInject.MatchString(normalized)
	}
	return false
}

// reNoSQLAttackCtx matches MongoDB operator injection context: {"key":{"$ne":val}} or ?k[$ne]=v
var reNoSQLAttackCtx = regexp.MustCompile(`(?i)(\[|\{|:|=)\s*\\?["']?\s*\$(ne|gt|lt|gte|lte|regex|in|nin)\b`)

// ── SQL Injection ──

var sqliPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`(?i)union\s*(all\s*)?select`), 5, "owasp:sqli:001"},
	{regexp.MustCompile(`(?i)'\s*(or|and)\s+['"]?\d`), 5, "owasp:sqli:002"},
	{regexp.MustCompile(`(?i)(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(`), 5, "owasp:sqli:003"},
	// Stacked query with DDL/DML/SELECT in SQL injection context
	{regexp.MustCompile(`(?i);\s*(select|drop|alter|create|truncate|delete|update|insert)\s`), 5, "owasp:sqli:004"},
	// SQL comment terminator preceded by quote or digit (-- requires trailing space/end-of-string, no # to avoid URL fragment FP)
	{regexp.MustCompile(`(?i)['"\d]\s*(--(?:[\s/]|$)|/\*)`), 3, "owasp:sqli:005"},
	{regexp.MustCompile(`(?i)'\s*;\s*\w`), 3, "owasp:sqli:006"},
	{regexp.MustCompile(`(?i)(chr|unhex|conv)\s*\(`), 3, "owasp:sqli:007"},
	// Hex literal with SQLi context (require preceding operator or comma)
	{regexp.MustCompile(`(?i)[,=(]\s*0x[0-9a-f]{4,}`), 2, "owasp:sqli:008"},
	{regexp.MustCompile(`(?i)information_schema|sysobjects|sys\.\w+tables`), 5, "owasp:sqli:009"},
	// Boolean-based blind SQLi
	{regexp.MustCompile(`(?i)\b(or|and)\s+\d+\s*=\s*\d+`), 5, "owasp:sqli:010"},
	{regexp.MustCompile(`(?i)\b(or|and)\s+['"]\w*['"]\s*=\s*['"]\w*['"]`), 5, "owasp:sqli:011"},
	// Stacked queries with comments
	{regexp.MustCompile(`(?i);\s*--`), 3, "owasp:sqli:012"},
	// Out-of-band exfiltration
	{regexp.MustCompile(`(?i)(load_file|outfile|dumpfile)\s*\(`), 5, "owasp:sqli:013"},
	// Database fingerprinting
	{regexp.MustCompile(`(?i)@@(version|hostname|datadir|basedir)`), 5, "owasp:sqli:014"},
	// EXTRACTVALUE / UPDATEXML error-based SQLi
	{regexp.MustCompile(`(?i)(extractvalue|updatexml)\s*\(`), 5, "owasp:sqli:015"},
	// GROUP_CONCAT / INTO OUTFILE / HAVING
	{regexp.MustCompile(`(?i)group_concat\s*\(`), 5, "owasp:sqli:016"},
	{regexp.MustCompile(`(?i)\binto\s+(out|dump)file\b`), 5, "owasp:sqli:017"},
	// CASE WHEN time-based
	{regexp.MustCompile(`(?i)case\s+when\s+.*then\s+(sleep|benchmark|pg_sleep)`), 5, "owasp:sqli:018"},
	// ORDER BY with suspicious trailing syntax (SQL comment/semicolon = probing)
	{regexp.MustCompile(`(?i)\border\s+by\s+\d+\s*(--\s?|/\*|;\s*$)`), 5, "owasp:sqli:019"},
	// MySQL version-specific inline comment bypass /*!50000union*/
	{regexp.MustCompile(`(?i)/\*!\d*\s*(select|union|insert|update|delete|drop|alter|where|from|and|or)\b`), 5, "owasp:sqli:020"},
	// Blind SQLi extraction: substr/substring/mid with numeric offset args
	{regexp.MustCompile(`(?i)(substr|substring|mid)\s*\(.+,\s*\d+\s*,\s*\d+\s*\)`), 4, "owasp:sqli:021"},
	// Conditional blind SQLi: IF(select/ascii/ord/...)
	{regexp.MustCompile(`(?i)\bif\s*\(\s*(select|ord|ascii|substr|length|count|version)\b`), 5, "owasp:sqli:022"},
	// Bitwise/arithmetic operators in injection context (e.g., id=1&1, id=1^1)
	{regexp.MustCompile(`(?i)'\s*(\^|&|<<|>>)\s*'`), 3, "owasp:sqli:023"},
	// MSSQL stored procedure for OS command execution
	{regexp.MustCompile(`(?i)\bxp_(cmdshell|regread|regwrite|loginconfig|enumdsn|availablemedia|ntsec)\b`), 6, "owasp:sqli:024"},
	// MySQL PROCEDURE ANALYSE — used to enumerate column types
	{regexp.MustCompile(`(?i)\bprocedure\s+analyse\s*\(`), 5, "owasp:sqli:025"},
	// Oracle UTL_HTTP / UTL_FILE / DBMS out-of-band exfiltration
	{regexp.MustCompile(`(?i)\b(utl_http|utl_file|dbms_pipe|dbms_output)\s*\.\s*\w+`), 5, "owasp:sqli:026"},
	// HAVING with tautology (blind SQLi enumeration)
	{regexp.MustCompile(`(?i)\bhaving\s+\d+\s*=\s*\d+`), 5, "owasp:sqli:027"},
	// Subquery in numeric comparison: 1=(SELECT 1 FROM ...)
	{regexp.MustCompile(`(?i)\d+\s*=\s*\(\s*select\b`), 5, "owasp:sqli:028"},
	// LIKE-based blind SQLi with wildcard
	{regexp.MustCompile(`(?i)'\s*like\s+'[%_]`), 5, "owasp:sqli:029"},
	// LIMIT/OFFSET injection for MySQL enumeration with terminator
	{regexp.MustCompile(`(?i)\blimit\s+\d+\s*,\s*\d+\s*(--|;)`), 5, "owasp:sqli:030"},
	// Subquery in comparison: id=1=(SELECT 1 FROM...) or id IN (SELECT ...)
	{regexp.MustCompile(`(?i)(=\s*|\bIN\s*)\(\s*SELECT\b`), 5, "owasp:sqli:031"},
	// GROUP BY column enumeration with explicit SQL terminator
	{regexp.MustCompile(`(?i)\bGROUP\s+BY\s+\d+(\s*,\s*\d+)*\s*(--|;|/\*)`), 5, "owasp:sqli:032"},
	// LIMIT x OFFSET y injection (MySQL/PostgreSQL enumeration) — require SQL terminator
	{regexp.MustCompile(`(?i)\blimit\s+\d+\s+offset\s+\d+\s*(--|;|/\*)`), 5, "owasp:sqli:033"},
	// MSSQL EXEC with stored procedures / system procs
	{regexp.MustCompile(`(?i);\s*exec(?:\s+|\s*\()(?:xp_|sp_|master\.\.)\w`), 5, "owasp:sqli:034"},
	// MSSQL WAITFOR DELAY without parentheses: WAITFOR DELAY '0:0:10'
	{regexp.MustCompile(`(?i)\bwaitfor\s+delay\s+['"]`), 5, "owasp:sqli:035"},
	// Empty string tautology: or ''=' or and ""="
	{regexp.MustCompile(`(?i)\b(or|and)\s+['"]['"]\s*=\s*['"]`), 5, "owasp:sqli:036"},
	// PostgreSQL COPY TO PROGRAM (command execution via SQL)
	{regexp.MustCompile(`(?i)\bcopy\b.{0,200}\bto\s+program\b`), 5, "owasp:sqli:037"},
	// Standalone SELECT ... FROM with SQL injection context (terminator/tautology/union)
	{regexp.MustCompile(`(?i)\bselect\b.{0,100}\bfrom\s+\w+\s*(--|;|/\*|\bwhere\s+\d+=\d+|\bunion\b)`), 5, "owasp:sqli:038"},
	// AND/OR before subquery: and (select ...), or (select ...)
	{regexp.MustCompile(`(?i)\b(and|or)\s*\(\s*select\b`), 5, "owasp:sqli:039"},
	// SELECT CASE WHEN without sleep (conditional error/division blind SQLi)
	{regexp.MustCompile(`(?i)\bselect\s+case\s+when\b`), 5, "owasp:sqli:040"},
	// SELECT CAST/CONVERT (type casting for data extraction) — require SQL context
	{regexp.MustCompile(`(?i)\bselect\s+(cast|convert)\s*\([^)]{0,80}\)\s*(from\b|,\s*\w|--)`), 5, "owasp:sqli:041"},
	// chr() or char() concatenation — Oracle/PostgreSQL/SQL Server string building
	{regexp.MustCompile(`(?i)\bchr\s*\(\s*\d+\s*\)\s*(\+|\|\|)\s*chr\s*\(`), 5, "owasp:sqli:043"},
	// utl_inaddr.get_host_name — Oracle OOB data exfiltration
	{regexp.MustCompile(`(?i)utl_inaddr\s*\.\s*get_host`), 5, "owasp:sqli:044"},
	// EXEC master..xp_dirtree / xp_cmdshell — MSSQL stored procedure abuse
	{regexp.MustCompile(`(?i)\b(exec|execute)\s+.{0,30}\bxp_(dirtree|cmdshell|regread|fileexist|subdirs)\b`), 5, "owasp:sqli:045"},
	// Nested SELECT: SELECT CAST((SELECT ... FROM ...) AS type)
	{regexp.MustCompile(`(?i)\bselect\b[^;]{0,20}\(\s*select\b`), 5, "owasp:sqli:046"},
	// Bare SELECT * FROM — very specific pattern
	{regexp.MustCompile(`(?i)\bselect\s+\*\s+from\s+\w`), 4, "owasp:sqli:047"},
	// EXEC master.. — MSSQL linked server / system stored procedure call
	{regexp.MustCompile(`(?i)\bexec\s+master\s*\.\.\s*\w`), 5, "owasp:sqli:048"},
}

func checkSQLi(s string, threshold int) (OWASPHit, bool) {
	if !hasSQLiIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range sqliPatterns {
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

var webshellPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`(?i)(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(`), 4, "owasp:webshell:001"},
	{regexp.MustCompile(`(?i)base64_decode\s*\(`), 3, "owasp:webshell:002"},
	{regexp.MustCompile(`(?i)<\?php\s`), 5, "owasp:webshell:003"},
	{regexp.MustCompile(`(?i)runtime\.getruntime\(\)\.exec`), 5, "owasp:webshell:004"},
	{regexp.MustCompile(`(?i)(cmd\.exe|powershell\.exe|/bin/(ba)?sh)`), 4, "owasp:webshell:005"},
	{regexp.MustCompile(`(?i)\$_(get|post|request|cookie)\s*\[`), 4, "owasp:webshell:006"},
	// PHP preg_replace with /e modifier (code execution)
	{regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"]/.*?/e`), 5, "owasp:webshell:007"},
	// Python subprocess / os.system for RCE
	{regexp.MustCompile(`(?i)(subprocess\s*\.\s*(call|run|Popen)|os\s*\.\s*(system|exec[lv]p?))\s*\(`), 4, "owasp:webshell:008"},
	// JSP/Groovy runtime execution
	{regexp.MustCompile(`(?i)(\.exec\s*\(|\.getruntime\(\)\s*\.\s*exec)`), 5, "owasp:webshell:009"},
	// Perl/Ruby system/exec
	{regexp.MustCompile("(?i)\\b(system|exec|open)\\s*\\(\\s*['\"]\\s*(cmd|bash|sh|powershell|nc|wget|curl)"), 4, "owasp:webshell:010"},
	// ASP/ASPX shell: Response.Write/Server.Execute
	{regexp.MustCompile(`(?i)(response\s*\.\s*(write|binarywrite)|server\s*\.\s*(execute|mappath))\s*\(`), 4, "owasp:webshell:011"},
	// PHP create_function() — dynamic code generation equivalent to eval()
	{regexp.MustCompile(`(?i)create_function\s*\(\s*['"][^'"]{0,100}['"]\s*,`), 4, "owasp:webshell:012"},
	// PHP obfuscation wrappers commonly chained with eval to hide payloads
	{regexp.MustCompile(`(?i)(gzinflate|gzuncompress|str_rot13|hex2bin|base64_decode)\s*\(\s*['"]`), 4, "owasp:webshell:013"},
	// PHP call_user_func for dynamic invocation: call_user_func('system', $_GET['cmd'])
	{regexp.MustCompile(`(?i)call_user_func\s*\(\s*['"]?\s*(system|exec|passthru|shell_exec|popen|proc_open|assert)\b`), 5, "owasp:webshell:014"},
	// Drupal Drupalgeddon2/3: mail[#post_render][]=exec, mail[#type]=markup
	{regexp.MustCompile(`(?i)\[\s*#\s*(post_render|pre_render|lazy_builder|markup|type)\s*\]`), 4, "owasp:webshell:015"},
	// Java XML deserialization / XStream RCE: <java.util.PriorityQueue serialization=...>
	{regexp.MustCompile(`(?i)<java\.\w+\.`), 5, "owasp:webshell:016"},
	// ThinkPHP invokefunction RCE: /index.php?s=index/\think\app/invokefunction&function=call_user_func
	{regexp.MustCompile(`(?i)invokefunction.*call_user_func|call_user_func.*invokefunction`), 5, "owasp:webshell:017"},
	// Generic call_user_func without dangerous function name — ThinkPHP/CodeIgniter
	{regexp.MustCompile(`(?i)\\think\\(app|request|template|view)\b`), 5, "owasp:webshell:018"},
	// ASP/JSP eval patterns: <%eval, <%execute, request("cmd")
	{regexp.MustCompile(`(?i)<%\s*(eval|execute|response\.write)`), 5, "owasp:webshell:019"},
	// PHP file operations: file_put_contents + file_get_contents combined
	{regexp.MustCompile(`(?i)file_put_contents\s*\(.*file_get_contents|file_get_contents\s*\(.*file_put_contents`), 5, "owasp:webshell:020"},
	// elFinder connector RCE: cmd=...&name=...>*.php
	{regexp.MustCompile(`(?i)\bname\s*=\s*[^&]*>\s*\w+\.(php|jsp|asp|aspx|sh)\b`), 5, "owasp:webshell:021"},
	// file_put_contents or file_get_contents with .php file path
	{regexp.MustCompile(`(?i)file_put_contents\b.*\.\s*php\b`), 5, "owasp:webshell:022"},
}

func checkWebshell(s string, threshold int) (OWASPHit, bool) {
	if !hasWebshellIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range webshellPatterns {
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

var revshellPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`(?i)bash\s+-i\s+>&?\s*/dev/tcp`), 6, "owasp:revshell:001"},
	{regexp.MustCompile(`(?i)/dev/tcp/\d`), 5, "owasp:revshell:002"},
	{regexp.MustCompile(`(?i)(nc|ncat|netcat)\s+.*-e\s`), 5, "owasp:revshell:003"},
	{regexp.MustCompile(`(?i)python[23]?\s+-c\s+.*socket`), 4, "owasp:revshell:004"},
	{regexp.MustCompile(`(?i)(invoke-expression|iex)\s*\(\s*(new-object|downloadstring)`), 5, "owasp:revshell:005"},
	{regexp.MustCompile(`(?i)(curl|wget)\s+.*\|\s*(ba)?sh`), 5, "owasp:revshell:006"},
	{regexp.MustCompile(`(?i)mkfifo\s+/tmp/`), 4, "owasp:revshell:007"},
	// Perl reverse shell
	{regexp.MustCompile(`(?i)perl\s+-e\s+['"].{0,300}socket`), 4, "owasp:revshell:008"},
	// Socat reverse shell
	{regexp.MustCompile(`(?i)socat\s+\S+\s+exec:`), 5, "owasp:revshell:009"},
	{regexp.MustCompile(`(?i)socat\s+[a-z0-9.+,:-]{0,40}tcp[a-z0-9.+,:-]{0,40}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), 4, "owasp:revshell:010"},
	// Telnet reverse shell: telnet 1.2.3.4 4444
	{regexp.MustCompile(`(?i)telnet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{2,5}`), 4, "owasp:revshell:011"},
	// Ruby or Node.js socket-based reverse shell
	{regexp.MustCompile(`(?i)(ruby|node)\s+-[re]\s+['"].{0,300}socket`), 4, "owasp:revshell:012"},
}

func checkRevShell(s string, threshold int) (OWASPHit, bool) {
	if !hasRevShellIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range revshellPatterns {
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

var xssPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`(?i)<script[\s>]`), 5, "owasp:xss:001"},
	// HTML event handler — extended to cover all standard DOM event names.
	{regexp.MustCompile(`(?i)\bon(error|load|click|dblclick|mouse(over|out|down|up|enter|leave|move|wheel)|focus(in)?|blur|change|submit|toggle|input|key(down|up|press)|drag(start|end|over|enter|leave)?|drop|copy|cut|paste|pointer(over|down|up|cancel|move|enter|leave)|animation(start|end|iteration)|transition(end|start|run|cancel)|scroll|wheel|resize|contextmenu|message|hashchange|popstate|beforeunload|unload|invalid|select|fullscreenchange|touchstart|touchend|touchmove|touchcancel|beforeinput|show)\s*=`), 5, "owasp:xss:002"},
	{regexp.MustCompile(`(?i)javascript\s*:`), 5, "owasp:xss:003"},
	{regexp.MustCompile(`(?i)<img\s+[^>]*src\s*=\s*['"]\s*x\s+onerror`), 5, "owasp:xss:004"},
	{regexp.MustCompile(`(?i)<iframe[\s>]`), 3, "owasp:xss:005"},
	{regexp.MustCompile(`(?i)document\.(cookie|location|write|domain)`), 4, "owasp:xss:006"},
	// SVG / MathML XSS carriers — low score, require combination with active context
	{regexp.MustCompile(`(?i)<svg[\s>]`), 2, "owasp:xss:007"},
	{regexp.MustCompile(`(?i)<math[\s>]`), 2, "owasp:xss:008"},
	// data: URL with script content
	{regexp.MustCompile(`(?i)data:text/html`), 5, "owasp:xss:009"},
	// Window/eval/Function references
	{regexp.MustCompile(`(?i)window\.(location|name|open)`), 4, "owasp:xss:010"},
	{regexp.MustCompile(`(?i)\b(eval|setTimeout|setInterval)\s*\(\s*['"]`), 5, "owasp:xss:011"},
	// DOM-based sinks
	{regexp.MustCompile(`(?i)innerhtml\s*=`), 5, "owasp:xss:012"},
	// Encoded script tags
	{regexp.MustCompile(`(?i)&#x?0*3c;?\s*script`), 5, "owasp:xss:013"},
	// HTML tag with inline event handler (generic catch-all for tag+onX=)
	{regexp.MustCompile(`(?i)<\w+\b[^>]+\bon\w+\s*=`), 5, "owasp:xss:014"},
	// <embed>/<object> with data/src attributes
	{regexp.MustCompile(`(?i)<(embed|object)\b[^>]*(data|src)\s*=`), 3, "owasp:xss:015"},
	// <form> with javascript: action
	{regexp.MustCompile(`(?i)<form\b[^>]*action\s*=\s*['"]?\s*javascript:`), 5, "owasp:xss:016"},
	// String.fromCharCode encoding bypass
	{regexp.MustCompile(`(?i)string\s*\.\s*fromcharcode\s*\(`), 5, "owasp:xss:017"},
	// <base href> tag injection
	{regexp.MustCompile(`(?i)<base\b[^>]+href\s*=`), 3, "owasp:xss:018"},
	// fetch/XMLHttpRequest data exfiltration
	{regexp.MustCompile(`(?i)(fetch|xmlhttprequest)\s*\(\s*['"]https?://`), 4, "owasp:xss:019"},
	// vbscript: protocol (Internet Explorer XSS)
	{regexp.MustCompile(`(?i)vbscript\s*:`), 5, "owasp:xss:020"},
	// CSS expression() injection (Internet Explorer)
	{regexp.MustCompile(`(?i)\bexpression\s*\(\s*(document|window|eval|this|alert)`), 3, "owasp:xss:021"},
	// srcdoc attribute — allows HTML injection without separate request
	{regexp.MustCompile(`(?i)\bsrcdoc\s*=`), 4, "owasp:xss:022"},
	// Angular/Vue/Template constructor chain: {{constructor.constructor(...)()}}
	{regexp.MustCompile(`(?i)\{\{.*?(constructor|__proto__|__defineGetter__).*?\}\}`), 5, "owasp:xss:023"},
	// document.write/writeln with injection context
	{regexp.MustCompile(`(?i)document\s*\.\s*(write|writeln)\s*\(`), 5, "owasp:xss:024"},
	// location.href / window.open assignment with javascript:
	{regexp.MustCompile(`(?i)(location\s*\.\s*(href|assign|replace)|window\s*\.\s*open)\s*\(\s*['"]?\s*javascript\s*:`), 5, "owasp:xss:025"},
	// HTML5 <details ontoggle> — fires without user interaction in auto-opened detail
	{regexp.MustCompile(`(?i)<details\b[^>]*\bopen\b[^>]*\bontoggle\s*=`), 5, "owasp:xss:026"},
	// <input autofocus onfocus> — fires on page load
	{regexp.MustCompile(`(?i)<input\b[^>]*\bautofocus\b[^>]*\bonfocus\s*=`), 5, "owasp:xss:027"},
	// <link rel=import> — HTML import XSS (older browsers)
	{regexp.MustCompile(`(?i)<link\b[^>]*\brel\s*=\s*['"]?\s*import\b`), 4, "owasp:xss:028"},
	// DOM clobbering: <img name=...> overwriting DOM properties
	{regexp.MustCompile(`(?i)<img\b[^>]*\bname\s*=\s*['"]?\s*(documentElement|body|head|domain)\b`), 4, "owasp:xss:029"},
	// Bracket property access on global objects: window['alert'], self['eval'], globalThis['alert'], etc.
	{regexp.MustCompile(`(?i)\b(window|self|top|parent|frames|globalthis|this)\s*\[\s*['"\x60]`), 4, "owasp:xss:030"},
	// Dangerous function accessed via bracket notation: ['alert'], ["eval"], [`confirm`].
	{regexp.MustCompile(`(?i)\[\s*['"\x60]\s*(alert|eval|prompt|confirm|settimeout|setinterval|atob|btoa|fetch|open|execscript)\s*['"\x60]\s*\]`), 5, "owasp:xss:031"},
	// Regex source concatenation XSS: /al/.source+/ert/.source (bypasses string detection).
	{regexp.MustCompile(`(?i)/\w+/\s*\.\s*source`), 4, "owasp:xss:032"},
	// JSFuck / bracket overload obfuscation: (![] or (+{} or (![]+[] patterns.
	{regexp.MustCompile(`\(!(\[\]|!\[\])\)|(\+\{\}|\+\[\])`), 4, "owasp:xss:033"},
	// UTF-7 encoded XSS: +ADw- (< in UTF-7), +ADo- (: in UTF-7), +AGk- (i), etc.
	{regexp.MustCompile(`(?i)\+A[A-Za-z0-9]{1,3}[-+]`), 3, "owasp:xss:034"},
	// Prototype/constructor chain abuse: toString.constructor.prototype — require exploit context
	{regexp.MustCompile(`(?i)\bconstructor\s*\.\s*prototype\s*\[`), 4, "owasp:xss:035"},
	// <param name=url|src|data|code value=...> inside <object>/<embed>.
	{regexp.MustCompile(`(?i)<param\b[^>]*\bname\s*=\s*['"]?\s*(url|src|data|code|movie|allowscriptaccess)\b`), 4, "owasp:xss:036"},
	// <body background=...> or <table background=...> or <input type=image src=...> pointing to remote.
	{regexp.MustCompile(`(?i)<(body|table|thead|tbody|tr|td|th|input)\b[^>]*\bbackground\s*=`), 3, "owasp:xss:037"},
	// <base target="alert(1)"> or other target= injection.
	{regexp.MustCompile(`(?i)<base\b[^>]*\btarget\s*=\s*['"]\s*[^'"]*\(.*\)`), 4, "owasp:xss:038"},
	// <meta http-equiv="refresh" content="0;url=javascript:..."> or charset override.
	{regexp.MustCompile(`(?i)<meta\b[^>]*\bhttp-equiv\s*=\s*['"]?(refresh|content-type|set-cookie)\b`), 4, "owasp:xss:039"},
	// <embed code=... type=text/html> (embed with code attribute pointing to external resource).
	{regexp.MustCompile(`(?i)<embed\b[^>]*\bcode\s*=`), 4, "owasp:xss:040"},
	// <use href="data:..."> or <use xlink:href=...> in SVG (SVG use element injection).
	{regexp.MustCompile(`(?i)<use\b[^>]*(href|xlink:href)\s*=`), 4, "owasp:xss:041"},
	// <animate> or <set> with xlink:href pointing to another element.
	{regexp.MustCompile(`(?i)<(animate|set|animatetransform)\b[^>]*(xlink:href|href)\s*=`), 3, "owasp:xss:042"},
	// onafterscriptexecute — rare but valid event handler in older Firefox.
	{regexp.MustCompile(`(?i)\bonafterscriptexecute\s*=`), 4, "owasp:xss:043"},
	// document['...'] bracket notation for document property access.
	{regexp.MustCompile(`(?i)document\s*\[\s*['"\x60]\s*(cookie|location|domain|write|body|title|url)\b`), 4, "owasp:xss:044"},
	// Standalone alert/confirm/prompt call (XSS proof-of-concept payload).
	{regexp.MustCompile(`(?i)\b(alert|confirm|prompt)\s*\(\s*[\d'"` + "`" + `]`), 5, "owasp:xss:045"},
	// constructor.constructor('code')() — JS prototype chain RCE in template contexts.
	{regexp.MustCompile(`(?i)\bconstructor\s*\.\s*constructor\s*\(`), 5, "owasp:xss:046"},
	// <a download=...> attribute — file download injection
	{regexp.MustCompile(`(?i)<a\b[^>]*\bdownload\s*=`), 3, "owasp:xss:047"},
	// Regex source concatenation for function call: obj[/x/.source+/y/.source](args)
	{regexp.MustCompile(`(?i)\[\s*/\w+/\s*\.\s*source\s*\+\s*/\w+/\s*\.\s*source\s*\]`), 5, "owasp:xss:048"},
	// eval(atob(...)) — base64 encoded XSS payload execution.
	{regexp.MustCompile(`(?i)\b(eval|function)\s*\(\s*atob\s*\(`), 5, "owasp:xss:049"},
	// Namespaced script tag: <x:script xmlns:x="..."> bypasses <script> filters.
	{regexp.MustCompile(`(?i)<\w+:\s*script\b`), 5, "owasp:xss:050"},
	// data:image/svg+xml — SVG data URI (can contain <script> inside SVG).
	{regexp.MustCompile(`(?i)data\s*:\s*image/svg\+xml`), 4, "owasp:xss:051"},
	// Global object bracket access with non-string (JSFuck): this[(...)] window[(...)]
	{regexp.MustCompile(`(?i)\b(window|self|top|parent|frames|globalthis|this)\s*\[\s*[\(/!+\[]`), 4, "owasp:xss:052"},
	// toString().constructor.prototype.charAt=[].join — AngularJS sandbox bypass
	{regexp.MustCompile(`(?i)\.constructor\s*\.\s*prototype\s*\.\s*\w+\s*=`), 5, "owasp:xss:053"},
	// prompt.call / alert.call — function.call() XSS
	{regexp.MustCompile(`(?i)\b(alert|prompt|confirm)\s*\.\s*(call|apply)\s*\(`), 5, "owasp:xss:054"},
	// <a download=...> with file extension — more specific to avoid FP
	{regexp.MustCompile(`(?i)<a\b[^>]*\bdownload\s*=\s*['"]?\s*\w+\.\w{2,5}\b`), 4, "owasp:xss:055"},
	// Whitespace-obfuscated javascript: protocol (e.g. j a v a s c r i p t :)
	{regexp.MustCompile(`(?i)j\s*a\s*v\s*a\s+s\s*c\s*r\s*i\s*p\s*t\s*:`), 5, "owasp:xss:056"},
	{regexp.MustCompile(`(?i)<(body|table|thead|td|th|tr)\b[^>]*\bbackground\s*=\s*['"]?\s*(//|https?:)`), 4, "owasp:xss:057"},
}

func checkXSS(s string, threshold int) (OWASPHit, bool) {
	if !hasXSSIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range xssPatterns {
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

// ── Path Traversal ──

var pathTravPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`(?i)(\.\./){2,}`), 4, "owasp:path_traversal:001"},
	{regexp.MustCompile(`(?i)(etc/passwd|etc/shadow|win\.ini|boot\.ini)`), 5, "owasp:path_traversal:002"},
	{regexp.MustCompile(`(?i)%2e%2e[/\\]`), 4, "owasp:path_traversal:003"},
	{regexp.MustCompile(`(?i)\.\.[/\\]\.\.[/\\]`), 4, "owasp:path_traversal:004"},
	// Tomcat path parameter bypass: ..;/ allows traversal through path segments
	{regexp.MustCompile(`\.\.;[/\\]`), 4, "owasp:path_traversal:005"},
	// /proc/self/ Linux proc filesystem access (information leak)
	{regexp.MustCompile(`(?i)/proc/self/(environ|cmdline|fd|maps|status|exe|cwd|root)`), 5, "owasp:path_traversal:006"},
	// Null-byte injection in path (%00 to truncate extension checks)
	{regexp.MustCompile(`(?i)\.\.(%00|\x00)`), 5, "owasp:path_traversal:007"},
	// Windows-specific: traversal to system32 or cmd.exe
	{regexp.MustCompile(`(?i)\.\.[/\\].*(windows[/\\]system32|windows[/\\]win\.ini|cmd\.exe|system\.ini)`), 5, "owasp:path_traversal:008"},
	// Quadruple-dot bypass: ..../ = ../../ (some normalisers collapse one level only)
	{regexp.MustCompile(`(?i)\.{4,}[/\\]`), 4, "owasp:path_traversal:009"},
	// Single ../ directly to sensitive Linux files
	{regexp.MustCompile(`(?i)(^|[/\\])\.\.[/\\](etc[/\\](passwd|shadow|hosts|hostname|group)|proc[/\\]version|root[/\\]|var[/\\]log[/\\])`), 5, "owasp:path_traversal:010"},
	// Double URL-encoded slash/dot: %252f / %252e (secondary decode bypass)
	{regexp.MustCompile(`(?i)(%252e|%252f|%255c){2,}`), 4, "owasp:path_traversal:011"},
	// Backslash traversal: ..\..\ (Windows)
	{regexp.MustCompile(`(?i)(\.\.\\){2,}`), 4, "owasp:path_traversal:012"},
	// Access to Java/J2EE sensitive config paths (WEB-INF, META-INF, web.xml)
	{regexp.MustCompile(`(?i)\.\.[/\\].*(web-inf|meta-inf|web\.xml|struts\.xml|applicationcontext\.xml)`), 5, "owasp:path_traversal:013"},
	// Sensitive framework config files accessible via single traversal
	{regexp.MustCompile(`(?i)(web-inf|meta-inf)[/\\]web\.xml`), 5, "owasp:path_traversal:014"},
	// ../ access to .git, .env, .ssh or other sensitive root files
	{regexp.MustCompile(`(?i)\.\.[/\\]*(\.git[/\\]|\.env|\.htpasswd|\.aws[/\\]|\.ssh[/\\]|config\.php|settings\.py|\.DS_Store)`), 4, "owasp:path_traversal:015"},
	// Single ../ or ..\ to admin/login/config paths
	{regexp.MustCompile(`(?i)\.\.[/\\](admin|login|manager|console|config|passwd|shadow|private)`), 4, "owasp:path_traversal:016"},
}

func checkPathTraversal(s string, threshold int) (OWASPHit, bool) {
	if !hasPathTravIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range pathTravPatterns {
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
