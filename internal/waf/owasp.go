package waf

import (
	"encoding/base64"
	"html"
	"net/url"
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
		// Truncate oversized targets to bound regex scan time.
		if len(raw) > maxTargetLen {
			raw = raw[:maxTargetLen]
		}
		normalized := normalizeWithDecode(raw)
		if !hasSuspiciousContent(normalized) {
			continue
		}
		if hit, ok := checkSQLi(normalized, threshold); ok {
			// Context check: reduce false positives on common natural language patterns.
			if !isSQLiFalsePositive(raw, hit.RuleID) {
				return []OWASPHit{hit}
			}
		}
		if hit, ok := checkXSS(normalized, threshold); ok {
			// At high sensitivity, always report XSS.
			// At mid/low sensitivity, suppress structural-HTML-only hits to reduce false positives.
			if threshold <= 2 || !isXSSFalsePositive(normalized, hit.RuleID) {
				return []OWASPHit{hit}
			}
		}
		if hit, ok := checkCmdInjection(normalized, threshold); ok {
			return []OWASPHit{hit}
		}
		if hit, ok := checkWebshell(normalized, threshold); ok {
			return []OWASPHit{hit}
		}
		if hit, ok := checkRevShell(normalized, threshold); ok {
			return []OWASPHit{hit}
		}
		if hit, ok := checkPathTraversal(normalized, threshold); ok {
			return []OWASPHit{hit}
		}
		if hit, ok := checkSSRF(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkXXE(normalized, threshold); ok {
			return []OWASPHit{hit}
		}
		if hit, ok := checkLDAPInjection(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkNoSQLi(normalized, threshold); ok {
			if !isNoSQLiFalsePositive(raw, hit.RuleID) {
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
			return []OWASPHit{hit}
		}
		if hit, ok := checkExprLang(normalized, threshold); ok {
			return []OWASPHit{hit}
		}
		if hit, ok := checkDeserialization(normalized, threshold); ok {
			// Context check: skip binary false positives (short payloads from innocent data).
			if !isDeserFalsePositive(raw, hit.RuleID) {
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

	return hits
}

// CheckFileUpload inspects filename/content-type for dangerous uploads.
// Called separately because it needs the raw filename, not normalized.
func CheckFileUpload(filename, contentType string) (OWASPHit, bool) {
	return checkFileUpload(filename, contentType)
}

func sensitivityThreshold(s string) int {
	switch strings.ToLower(s) {
	case "low":
		return 6
	case "high":
		return 2
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
	"content-type":              true,
	"accept":                    true,
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
	"referer":                   true,
	"sec-fetch-mode":            true,
	"sec-fetch-site":            true,
	"sec-fetch-dest":            true,
	"sec-fetch-user":            true,
	"sec-ch-ua":                 true,
	"sec-ch-ua-mobile":          true,
	"sec-ch-ua-platform":        true,
}

func collectTargets(path, query string, headers map[string]string) []string {
	out := []string{path, query}
	for k, v := range headers {
		lk := strings.ToLower(k)
		if lk == "cookie" {
			out = append(out, extractCookieValues(v)...)
			continue
		}
		if skipHeaders[lk] {
			continue
		}
		out = append(out, v)
	}
	return out
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

// normalize does URL-decode (multi-pass), HTML entity decode, lowercase, whitespace collapse.
func normalize(s string) string {
	// Overlong UTF-8 percent-encoded sequences → real characters (evasion technique).
	if strings.Contains(s, "%") {
		s = reOverlongDot.ReplaceAllString(s, ".")
		s = reOverlongSlash.ReplaceAllString(s, "/")
		s = reOverlongBackslash.ReplaceAllString(s, "\\")
	}
	// Multi-pass URL decode.
	for range 3 {
		decoded, err := url.QueryUnescape(s)
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
	s = strings.ToLower(s)
	// Strip inline SQL/C-style comments to defeat comment-splitting evasion.
	// Empty replacement joins adjacent tokens: sel/**/ect → select, un/**/ion → union.
	s = stripSQLComments(s)
	s = reWhitespace.ReplaceAllString(s, " ")
	return s
}

// normalizeWithDecode normalizes and attempts base64 decoding of suspicious tokens.
func normalizeWithDecode(raw string) string {
	s := normalize(raw)
	// Extract base64 candidate tokens and append decoded forms.
	tokens := reBase64Token.FindAllString(raw, 5)
	if len(tokens) == 0 {
		return s
	}
	var b strings.Builder
	b.WriteString(s)
	for _, tok := range tokens {
		if decoded := decodeBase64IfSuspicious(tok); decoded != "" {
			b.WriteByte(' ')
			b.WriteString(normalize(decoded))
		}
	}
	return b.String()
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
		return ""
	}
	return string(decoded)
}

// ── Performance: fast pre-filter ──

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
	return false
}

var reWhitespace = regexp.MustCompile(`\s+`)

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
		strings.Contains(s, "case when") ||
		strings.Contains(s, "load_file") ||
		strings.Contains(s, "xp_") ||
		strings.Contains(s, "procedure") ||
		strings.Contains(s, "having ") ||
		strings.Contains(s, "utl_http") ||
		strings.Contains(s, "utl_file") ||
		strings.Contains(s, "dbms_") ||
		strings.Contains(s, " like ")
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
		strings.Contains(s, "innerhtml") ||
		strings.Contains(s, "eval(") ||
		strings.Contains(s, "settimeout(") ||
		strings.Contains(s, "setinterval(") ||
		strings.Contains(s, "data:text/html") ||
		strings.Contains(s, "fromcharcode") ||
		strings.Contains(s, "window.") ||
		strings.Contains(s, "fetch(") ||
		strings.Contains(s, "xmlhttprequest") ||
		strings.Contains(s, "expression(") ||
		strings.Contains(s, "srcdoc") ||
		strings.Contains(s, "{{") ||
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
		strings.Contains(s, "onbefore")
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
		strings.Contains(s, "wget ") ||
		strings.Contains(s, "curl ")
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
		strings.Contains(s, "server.execute")
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
		strings.Contains(s, "-e /bin/")
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
		strings.Contains(s, "..;")
}

// ── Context-aware false positive suppression ──

// isSQLiFalsePositive checks if a SQLi hit is actually a benign pattern.
// This reduces noise from common URL parameters, natural language, and framework artifacts.
func isSQLiFalsePositive(raw, ruleID string) bool {
	lower := strings.ToLower(raw)

	switch ruleID {
	case "owasp:sqli:004": // ;\s*(select|drop|alter|create|truncate|delete|update|insert)\s
		// Semicolon + DDL/DML keyword can appear in JavaScript (";delete obj.prop"),
		// natural language ("run cleanup; delete temp files"), and CSS.
		// Suppress if no SQL structural context (FROM, TABLE, INTO, VALUES, etc.).
		if !reBoolSQLContext.MatchString(lower) && !reSQLDMLContext.MatchString(lower) {
			return true
		}
	case "owasp:sqli:010": // \b(or|and)\s+\d+\s*=\s*\d+
		// Pure digit=digit comparisons after OR/AND are highly specific to SQLi probes.
		// Both tautologies (1=1) and false conditions (1=2) are classic blind SQLi patterns.
		// No false positive suppression: "or 1=1" / "and 1=2" in URL params is always suspicious.
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
	case "owasp:sqli:012": // ;\s*--
		// Semicolons followed by double-dash can appear in legitimate CSS or JS snippets.
		if len(lower) < 10 {
			return true
		}
	}
	return false
}

// hasActiveXSSContext checks for active JavaScript execution indicators that
// confirm a real XSS attack rather than passive structural HTML.
func hasActiveXSSContext(normalized string) bool {
	return strings.Contains(normalized, "javascript:") ||
		strings.Contains(normalized, "vbscript:") ||
		strings.Contains(normalized, "data:text/html") ||
		strings.Contains(normalized, "<script") ||
		strings.Contains(normalized, "eval(") ||
		strings.Contains(normalized, "fromcharcode") ||
		strings.Contains(normalized, "document.cookie") ||
		strings.Contains(normalized, "document.write") ||
		reXSSEventHandler.MatchString(normalized)
}

// isXSSFalsePositive returns true when the XSS hit came only from passive
// structural HTML elements (svg, iframe, math, embed, base, link) without any
// active JavaScript execution context. Rich HTML content (CMS posts, reports)
// commonly includes these elements and should not be blocked.
// At high sensitivity (threshold ≤ 2), this check is bypassed by the caller.
func isXSSFalsePositive(normalized, firstRuleID string) bool {
	switch firstRuleID {
	case "owasp:xss:005", "owasp:xss:007", "owasp:xss:008",
		"owasp:xss:015", "owasp:xss:018", "owasp:xss:022",
		"owasp:xss:028":
		return !hasActiveXSSContext(normalized)
	}
	return false
}

// reXSSEventHandler matches inline event handler attributes (on<event>=).
var reXSSEventHandler = regexp.MustCompile(`(?i)\bon\w+\s*=`)

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
// Used to avoid false positives on ";" + keyword in JavaScript or natural language.
var reSQLDMLContext = regexp.MustCompile(`(?i)\b(table|into\b|values\s*\(|database|schema|columns\s+from|rows\s+from)\b`)

// isDeserFalsePositive suppresses deserialization hits on very short or
// common binary patterns that appear innocuously in image EXIF, fonts, etc.
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
	}
	return false
}

// reNoSQLAttackCtx matches MongoDB operator injection context: {"key":{"$ne":val}} or ?k[$ne]=v
var reNoSQLAttackCtx = regexp.MustCompile(`(?i)(\[|\{|:|=)\s*["']?\s*\$(ne|gt|lt|gte|lte|regex|in|nin)\b`)

// ── SQL Injection ──

var sqliPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`(?i)union\s*(all\s*)?select`), 5, "owasp:sqli:001"},
	{regexp.MustCompile(`(?i)'\s*(or|and)\s+['"]?\d`), 5, "owasp:sqli:002"},
	{regexp.MustCompile(`(?i)(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(`), 5, "owasp:sqli:003"},
	// Stacked query with DDL/DML/SELECT — includes SELECT for "1; SELECT user()--"
	{regexp.MustCompile(`(?i);\s*(select|drop|alter|create|truncate|delete|update|insert)\s`), 4, "owasp:sqli:004"},
	// SQL comment terminator preceded by quote or digit (-- requires trailing space/end, no # to avoid URL fragment FP)
	{regexp.MustCompile(`(?i)['"\d]\s*(--[\s/]|/\*)`), 2, "owasp:sqli:005"},
	{regexp.MustCompile(`(?i)'\s*;\s*\w`), 3, "owasp:sqli:006"},
	{regexp.MustCompile(`(?i)(char|chr|concat|hex|unhex|conv)\s*\(`), 2, "owasp:sqli:007"},
	// Hex literal with SQLi context (require preceding operator or comma)
	{regexp.MustCompile(`(?i)[,=(]\s*0x[0-9a-f]{4,}`), 2, "owasp:sqli:008"},
	{regexp.MustCompile(`(?i)information_schema|sysobjects|sys\.\w+tables`), 4, "owasp:sqli:009"},
	// Boolean-based blind SQLi
	{regexp.MustCompile(`(?i)\b(or|and)\s+\d+\s*=\s*\d+`), 4, "owasp:sqli:010"},
	{regexp.MustCompile(`(?i)\b(or|and)\s+['"]\w+['"]\s*=\s*['"]\w+['"]`), 4, "owasp:sqli:011"},
	// Stacked queries with comments
	{regexp.MustCompile(`(?i);\s*--`), 3, "owasp:sqli:012"},
	// Out-of-band exfiltration
	{regexp.MustCompile(`(?i)(load_file|outfile|dumpfile)\s*\(`), 5, "owasp:sqli:013"},
	// Database fingerprinting
	{regexp.MustCompile(`(?i)@@(version|hostname|datadir|basedir)`), 3, "owasp:sqli:014"},
	// EXTRACTVALUE / UPDATEXML error-based SQLi
	{regexp.MustCompile(`(?i)(extractvalue|updatexml)\s*\(`), 5, "owasp:sqli:015"},
	// GROUP_CONCAT / INTO OUTFILE / HAVING
	{regexp.MustCompile(`(?i)group_concat\s*\(`), 3, "owasp:sqli:016"},
	{regexp.MustCompile(`(?i)\binto\s+(out|dump)file\b`), 5, "owasp:sqli:017"},
	// CASE WHEN time-based
	{regexp.MustCompile(`(?i)case\s+when\s+.*then\s+(sleep|benchmark|pg_sleep)`), 5, "owasp:sqli:018"},
	// ORDER BY with suspicious trailing syntax (SQL comment/semicolon = probing)
	{regexp.MustCompile(`(?i)\border\s+by\s+\d+\s*(--\s?|/\*|;\s*$)`), 3, "owasp:sqli:019"},
	// MySQL version-specific inline comment bypass /*!50000union*/
	{regexp.MustCompile(`(?i)/\*!\d*\s*(select|union|insert|update|delete|drop|alter|where|from|and|or)\b`), 4, "owasp:sqli:020"},
	// Blind SQLi extraction: substr/substring/mid with numeric offset args
	{regexp.MustCompile(`(?i)(substr|substring|mid)\s*\(.+,\s*\d+\s*,\s*\d+\s*\)`), 3, "owasp:sqli:021"},
	// Conditional blind SQLi: IF(select/ascii/ord/...)
	{regexp.MustCompile(`(?i)\bif\s*\(\s*(select|ord|ascii|substr|length|count|version)\b`), 4, "owasp:sqli:022"},
	// Bitwise/arithmetic operators in injection context (e.g., id=1&1, id=1^1)
	{regexp.MustCompile(`(?i)'\s*(\^|&|<<|>>)\s*'`), 3, "owasp:sqli:023"},
	// MSSQL stored procedure for OS command execution
	{regexp.MustCompile(`(?i)\bxp_(cmdshell|regread|regwrite|loginconfig|enumdsn|availablemedia|ntsec)\b`), 6, "owasp:sqli:024"},
	// MySQL PROCEDURE ANALYSE — used to enumerate column types
	{regexp.MustCompile(`(?i)\bprocedure\s+analyse\s*\(`), 4, "owasp:sqli:025"},
	// Oracle UTL_HTTP / UTL_FILE / DBMS out-of-band exfiltration
	{regexp.MustCompile(`(?i)\b(utl_http|utl_file|dbms_pipe|dbms_output)\s*\.\s*\w+`), 5, "owasp:sqli:026"},
	// HAVING with tautology (blind SQLi enumeration)
	{regexp.MustCompile(`(?i)\bhaving\s+\d+\s*=\s*\d+`), 3, "owasp:sqli:027"},
	// Subquery in numeric comparison: 1=(SELECT 1 FROM ...)
	{regexp.MustCompile(`(?i)\d+\s*=\s*\(\s*select\b`), 4, "owasp:sqli:028"},
	// LIKE-based blind SQLi with wildcard
	{regexp.MustCompile(`(?i)'\s*like\s+'[%_]`), 3, "owasp:sqli:029"},
	// LIMIT/OFFSET injection for MySQL enumeration
	{regexp.MustCompile(`(?i)\blimit\s+\d+\s*,\s*\d+\s*(--|;|$)`), 3, "owasp:sqli:030"},
	// Subquery in comparison: id=1=(SELECT 1 FROM...) or id IN (SELECT ...)
	{regexp.MustCompile(`(?i)(=\s*|\bIN\s*)\(\s*SELECT\b`), 4, "owasp:sqli:031"},
	// GROUP BY column enumeration with explicit SQL terminator
	{regexp.MustCompile(`(?i)\bGROUP\s+BY\s+\d+(\s*,\s*\d+)*\s*(--|;|/\*)`), 4, "owasp:sqli:032"},
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
	{regexp.MustCompile(`(?i)<\?php\s`), 3, "owasp:webshell:003"},
	{regexp.MustCompile(`(?i)runtime\.getruntime\(\)\.exec`), 5, "owasp:webshell:004"},
	{regexp.MustCompile(`(?i)(cmd\.exe|powershell\.exe|/bin/(ba)?sh)`), 3, "owasp:webshell:005"},
	{regexp.MustCompile(`(?i)\$_(get|post|request|cookie)\s*\[`), 3, "owasp:webshell:006"},
	// PHP preg_replace with /e modifier (code execution)
	{regexp.MustCompile(`(?i)preg_replace\s*\(\s*['"]/.*?/e`), 5, "owasp:webshell:007"},
	// Python subprocess / os.system for RCE
	{regexp.MustCompile(`(?i)(subprocess\s*\.\s*(call|run|Popen)|os\s*\.\s*(system|exec[lv]p?))\s*\(`), 4, "owasp:webshell:008"},
	// JSP/Groovy runtime execution
	{regexp.MustCompile(`(?i)(\.exec\s*\(|\.getruntime\(\)\s*\.\s*exec)`), 5, "owasp:webshell:009"},
	// Perl/Ruby system/exec
	{regexp.MustCompile("(?i)\\b(system|exec|open)\\s*\\(\\s*['\"]\\s*(cmd|bash|sh|powershell|nc|wget|curl)"), 4, "owasp:webshell:010"},
	// ASP/ASPX shell: Response.Write/Server.Execute
	{regexp.MustCompile(`(?i)(response\s*\.\s*(write|binarywrite)|server\s*\.\s*(execute|mappath))\s*\(`), 3, "owasp:webshell:011"},
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
	{regexp.MustCompile(`(?i)<script[\s>]`), 4, "owasp:xss:001"},
	// HTML event handler — score 4: "onload=", "onclick=", etc. are strong XSS signals even
	// without surrounding HTML tag context (e.g., injected into an existing attribute).
	{regexp.MustCompile(`(?i)\bon(error|load|click|mouse(over|out|down|up|enter|leave)|focus(in)?|blur|change|submit|toggle|input|key(down|up|press)|drag(start)?|drop|copy|cut|paste|pointer(over|down)|animation(start|end)|beforeinput)\s*=`), 4, "owasp:xss:002"},
	{regexp.MustCompile(`(?i)javascript\s*:`), 3, "owasp:xss:003"},
	{regexp.MustCompile(`(?i)<img\s+[^>]*src\s*=\s*['"]\s*x\s+onerror`), 4, "owasp:xss:004"},
	{regexp.MustCompile(`(?i)<iframe`), 1, "owasp:xss:005"},
	{regexp.MustCompile(`(?i)document\.(cookie|location|write|domain)`), 3, "owasp:xss:006"},
	// SVG / MathML XSS carriers
	{regexp.MustCompile(`(?i)<svg[\s>]`), 2, "owasp:xss:007"},
	{regexp.MustCompile(`(?i)<math[\s>]`), 1, "owasp:xss:008"},
	// data: URL with script content
	{regexp.MustCompile(`(?i)data:text/html`), 4, "owasp:xss:009"},
	// Window/eval/Function references
	{regexp.MustCompile(`(?i)window\.(location|name|open)`), 3, "owasp:xss:010"},
	{regexp.MustCompile(`(?i)\b(eval|setTimeout|setInterval)\s*\(\s*['"]`), 4, "owasp:xss:011"},
	// DOM-based sinks
	{regexp.MustCompile(`(?i)innerhtml\s*=`), 3, "owasp:xss:012"},
	// Encoded script tags
	{regexp.MustCompile(`(?i)&#x?0*3c;?\s*script`), 4, "owasp:xss:013"},
	// HTML tag with inline event handler (generic catch-all for tag+onX=)
	{regexp.MustCompile(`(?i)<\w+\b[^>]+\bon\w+\s*=`), 3, "owasp:xss:014"},
	// <embed>/<object> with data/src attributes
	{regexp.MustCompile(`(?i)<(embed|object)\b[^>]*(data|src)\s*=`), 2, "owasp:xss:015"},
	// <form> with javascript: action
	{regexp.MustCompile(`(?i)<form\b[^>]*action\s*=\s*['"]?\s*javascript:`), 4, "owasp:xss:016"},
	// String.fromCharCode encoding bypass
	{regexp.MustCompile(`(?i)string\s*\.\s*fromcharcode\s*\(`), 4, "owasp:xss:017"},
	// <base href> tag injection
	{regexp.MustCompile(`(?i)<base\b[^>]+href\s*=`), 2, "owasp:xss:018"},
	// fetch/XMLHttpRequest data exfiltration
	{regexp.MustCompile(`(?i)(fetch|xmlhttprequest)\s*\(\s*['"]https?://`), 3, "owasp:xss:019"},
	// vbscript: protocol (Internet Explorer XSS)
	{regexp.MustCompile(`(?i)vbscript\s*:`), 4, "owasp:xss:020"},
	// CSS expression() injection (Internet Explorer)
	{regexp.MustCompile(`(?i)\bexpression\s*\(\s*(document|window|eval|this|alert)`), 3, "owasp:xss:021"},
	// srcdoc attribute — allows HTML injection without separate request
	{regexp.MustCompile(`(?i)\bsrcdoc\s*=`), 3, "owasp:xss:022"},
	// Angular/Vue/Template constructor chain: {{constructor.constructor(...)()}}
	{regexp.MustCompile(`(?i)\{\{.*?(constructor|__proto__|__defineGetter__).*?\}\}`), 5, "owasp:xss:023"},
	// document.write/writeln with injection context
	{regexp.MustCompile(`(?i)document\s*\.\s*(write|writeln)\s*\(`), 3, "owasp:xss:024"},
	// location.href / window.open assignment with javascript:
	{regexp.MustCompile(`(?i)(location\s*\.\s*(href|assign|replace)|window\s*\.\s*open)\s*\(\s*['"]?\s*javascript\s*:`), 4, "owasp:xss:025"},
	// HTML5 <details ontoggle> — fires without user interaction in auto-opened detail
	{regexp.MustCompile(`(?i)<details\b[^>]*\bopen\b[^>]*\bontoggle\s*=`), 4, "owasp:xss:026"},
	// <input autofocus onfocus> — fires on page load
	{regexp.MustCompile(`(?i)<input\b[^>]*\bautofocus\b[^>]*\bonfocus\s*=`), 4, "owasp:xss:027"},
	// <link rel=import> — HTML import XSS (older browsers)
	{regexp.MustCompile(`(?i)<link\b[^>]*\brel\s*=\s*['"]?\s*import\b`), 3, "owasp:xss:028"},
	// DOM clobbering: <img name=...> overwriting DOM properties
	{regexp.MustCompile(`(?i)<img\b[^>]*\bname\s*=\s*['"]?\s*(documentElement|body|head|domain)\b`), 4, "owasp:xss:029"},
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
	{regexp.MustCompile(`(?i)\.\.[/\\]\.\.[/\\]`), 3, "owasp:path_traversal:004"},
	// Tomcat path parameter bypass: ..;/ allows traversal through path segments
	{regexp.MustCompile(`\.\.;[/\\]`), 4, "owasp:path_traversal:005"},
	// /proc/self/ Linux proc filesystem access (information leak)
	{regexp.MustCompile(`(?i)/proc/self/(environ|cmdline|fd|maps|status|exe|cwd|root)`), 5, "owasp:path_traversal:006"},
	// Null-byte injection in path (%00 to truncate extension checks)
	{regexp.MustCompile(`(?i)\.\.(%00|\x00)`), 5, "owasp:path_traversal:007"},
	// Windows-specific: traversal to system32 or cmd.exe
	{regexp.MustCompile(`(?i)\.\.[/\\].*(windows[/\\]system32|windows[/\\]win\.ini|cmd\.exe|system\.ini)`), 5, "owasp:path_traversal:008"},
	// Quadruple-dot bypass: ..../ = ../../ (some normalisers collapse one level only)
	{regexp.MustCompile(`(?i)\.{4,}[/\\]`), 3, "owasp:path_traversal:009"},
	// Single ../ directly to sensitive Linux files
	{regexp.MustCompile(`(?i)(^|[/\\])\.\.[/\\](etc[/\\](passwd|shadow|hosts|hostname|group)|proc[/\\]version|root[/\\]|var[/\\]log[/\\])`), 5, "owasp:path_traversal:010"},
	// Double URL-encoded slash/dot: %252f / %252e (secondary decode bypass)
	{regexp.MustCompile(`(?i)(%252e|%252f|%255c){2,}`), 4, "owasp:path_traversal:011"},
	// Backslash traversal: ..\..\ (Windows)
	{regexp.MustCompile(`(?i)(\.\.\\){2,}`), 4, "owasp:path_traversal:012"},
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
