package waf

import (
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
)

const BuiltinVersion = "builtin_owasp_v1"

type OWASPHit struct {
	Category OWASPCategory
	RuleID   string
	Score    int
	Desc     string
}

// CheckOWASP scans request fields for OWASP-oriented attacks.
// Returns all hits above the sensitivity threshold.
func CheckOWASP(sensitivity string, path, query string, headers map[string]string) []OWASPHit {
	threshold := sensitivityThreshold(sensitivity)
	var hits []OWASPHit

	targets := collectTargets(path, query, headers)
	for _, raw := range targets {
		normalized := normalize(raw)
		if hit, ok := checkSQLi(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkWebshell(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkRevShell(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkXSS(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkPathTraversal(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkSSRF(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkCmdInjection(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkXXE(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkLDAPInjection(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkNoSQLi(normalized, threshold); ok {
			hits = append(hits, hit)
		}
		if hit, ok := checkTemplateInjection(normalized, threshold); ok {
			hits = append(hits, hit)
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
		if skipHeaders[strings.ToLower(k)] {
			continue
		}
		out = append(out, v)
	}
	return out
}

// normalize does URL-decode (multi-pass), lowercase, Unicode normalization, whitespace collapse.
func normalize(s string) string {
	for i := 0; i < 3; i++ {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	s = strings.ToLower(s)
	s = reWhitespace.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "/**/", " ")
	return s
}

var reWhitespace = regexp.MustCompile(`\s+`)

// ── SQL Injection ──

var sqliPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`(?i)union\s+(all\s+)?select`), 5, "owasp:sqli:001"},
	{regexp.MustCompile(`(?i)'\s*(or|and)\s+['"]?\d`), 5, "owasp:sqli:002"},
	{regexp.MustCompile(`(?i)(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(`), 5, "owasp:sqli:003"},
	{regexp.MustCompile(`(?i);\s*(drop|alter|create|truncate|delete|update|insert)\s`), 4, "owasp:sqli:004"},
	{regexp.MustCompile(`(?i)(--|#|/\*)\s*$`), 2, "owasp:sqli:005"},
	{regexp.MustCompile(`(?i)'\s*;\s*\w`), 3, "owasp:sqli:006"},
	{regexp.MustCompile(`(?i)(char|chr|concat|hex|unhex|conv)\s*\(`), 3, "owasp:sqli:007"},
	{regexp.MustCompile(`(?i)0x[0-9a-f]{4,}`), 2, "owasp:sqli:008"},
	{regexp.MustCompile(`(?i)information_schema|sysobjects|sys\.`), 4, "owasp:sqli:009"},
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
}

func checkSQLi(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range sqliPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
		}
	}
	if total >= threshold {
		return OWASPHit{Category: CatSQLi, RuleID: best, Score: total, Desc: "SQL injection signals"}, true
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
}

func checkWebshell(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range webshellPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
		}
	}
	if total >= threshold {
		return OWASPHit{Category: CatWebshell, RuleID: best, Score: total, Desc: "webshell/code execution signals"}, true
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
	total := 0
	best := ""
	for _, p := range revshellPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
		}
	}
	if total >= threshold {
		return OWASPHit{Category: CatRevShell, RuleID: best, Score: total, Desc: "reverse shell / remote execution signals"}, true
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
	{regexp.MustCompile(`(?i)on(error|load|click|mouseover|focus|blur|change|submit)\s*=`), 3, "owasp:xss:002"},
	{regexp.MustCompile(`(?i)javascript\s*:`), 3, "owasp:xss:003"},
	{regexp.MustCompile(`(?i)<img\s+[^>]*src\s*=\s*['"]\s*x\s+onerror`), 4, "owasp:xss:004"},
	{regexp.MustCompile(`(?i)<iframe`), 2, "owasp:xss:005"},
	{regexp.MustCompile(`(?i)document\.(cookie|location|write|domain)`), 3, "owasp:xss:006"},
	// SVG / MathML XSS carriers
	{regexp.MustCompile(`(?i)<svg[\s>]`), 3, "owasp:xss:007"},
	{regexp.MustCompile(`(?i)<math[\s>]`), 3, "owasp:xss:008"},
	// data: URL with script content
	{regexp.MustCompile(`(?i)data:text/html`), 4, "owasp:xss:009"},
	// Window/eval/Function references
	{regexp.MustCompile(`(?i)window\.(location|name|open)`), 3, "owasp:xss:010"},
	{regexp.MustCompile(`(?i)\b(eval|setTimeout|setInterval)\s*\(\s*['"]`), 4, "owasp:xss:011"},
	// DOM-based sinks
	{regexp.MustCompile(`(?i)innerhtml\s*=`), 3, "owasp:xss:012"},
	// Encoded script tags
	{regexp.MustCompile(`(?i)&#x?0*3c;?\s*script`), 4, "owasp:xss:013"},
}

func checkXSS(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range xssPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
		}
	}
	if total >= threshold {
		return OWASPHit{Category: CatXSS, RuleID: best, Score: total, Desc: "XSS signals"}, true
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
}

func checkPathTraversal(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range pathTravPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
		}
	}
	if total >= threshold {
		return OWASPHit{Category: CatPathTrav, RuleID: best, Score: total, Desc: "path traversal signals"}, true
	}
	return OWASPHit{}, false
}
