package waf

import (
	"path/filepath"
	"regexp"
	"strings"
)

// ── SSRF (Server-Side Request Forgery) ──

var ssrfPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	// Cloud metadata endpoints
	{regexp.MustCompile(`(?i)169\.254\.169\.254`), 6, "owasp:ssrf:001"}, // AWS/Azure/GCP metadata
	{regexp.MustCompile(`(?i)metadata\.google\.internal`), 6, "owasp:ssrf:002"},
	{regexp.MustCompile(`(?i)100\.100\.100\.200`), 6, "owasp:ssrf:003"}, // Alibaba Cloud
	// Private IP ranges
	{regexp.MustCompile(`(?i)\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`), 3, "owasp:ssrf:004"},
	{regexp.MustCompile(`(?i)\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b`), 3, "owasp:ssrf:005"},
	{regexp.MustCompile(`(?i)\b192\.168\.\d{1,3}\.\d{1,3}\b`), 3, "owasp:ssrf:006"},
	// Localhost variants
	{regexp.MustCompile(`(?i)\b(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost)\b`), 3, "owasp:ssrf:007"},
	{regexp.MustCompile(`(?i)\[::1\]|\[::\]|\b0\.0\.0\.0\b`), 3, "owasp:ssrf:008"},
	// DNS rebinding / encoding bypasses
	{regexp.MustCompile(`(?i)\b0x[0-9a-f]{8}\b`), 3, "owasp:ssrf:009"},
	// file:// / gopher:// / dict:// schemes
	{regexp.MustCompile(`(?i)(file|gopher|dict|ldap|sftp|tftp)://`), 5, "owasp:ssrf:010"},
}

func checkSSRF(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range ssrfPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
		}
	}
	if total >= threshold {
		return OWASPHit{Category: CatSSRF, RuleID: best, Score: total, Desc: "SSRF signals"}, true
	}
	return OWASPHit{}, false
}

// ── Command Injection ──

var cmdInjectPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	// Pipe / semicolon / backtick / $() command chaining
	{regexp.MustCompile(`(?i)[;|&]\s*(ls|cat|id|whoami|uname|pwd|ps|wget|curl|nc|bash|sh)\b`), 5, "owasp:cmd:001"},
	{regexp.MustCompile("`[^`]*`"), 3, "owasp:cmd:002"},
	{regexp.MustCompile(`\$\(.*?\)`), 4, "owasp:cmd:003"},
	// Redirections that typically indicate injection
	{regexp.MustCompile(`(?i)(>|>>)\s*/(etc|tmp|var|root|home)/`), 4, "owasp:cmd:004"},
	// Explicit command execution
	{regexp.MustCompile(`(?i)(^|[\s;|&])(wget|curl)\s+https?://`), 3, "owasp:cmd:005"},
	// Null byte / newline injection
	{regexp.MustCompile(`%00|\x00|%0a|%0d`), 3, "owasp:cmd:006"},
	// Common discovery commands
	{regexp.MustCompile(`(?i)\b(id|uname|whoami|hostname|ifconfig|ipconfig)\s*;`), 3, "owasp:cmd:007"},
}

func checkCmdInjection(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range cmdInjectPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
		}
	}
	if total >= threshold {
		return OWASPHit{Category: CatCmdInject, RuleID: best, Score: total, Desc: "command injection signals"}, true
	}
	return OWASPHit{}, false
}

// ── XXE (XML External Entity) ──

var xxePatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`(?i)<!doctype[^>]+\[`), 5, "owasp:xxe:001"},
	{regexp.MustCompile(`(?i)<!entity\s+\w+\s+system`), 6, "owasp:xxe:002"},
	{regexp.MustCompile(`(?i)<!entity\s+\w+\s+public`), 6, "owasp:xxe:003"},
	{regexp.MustCompile(`(?i)&\w+;.*&\w+;`), 2, "owasp:xxe:004"}, // entity expansion
	{regexp.MustCompile(`(?i)system\s+['"](file|http|ftp|php)://`), 5, "owasp:xxe:005"},
}

func checkXXE(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range xxePatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
		}
	}
	if total >= threshold {
		return OWASPHit{Category: CatXXE, RuleID: best, Score: total, Desc: "XML external entity signals"}, true
	}
	return OWASPHit{}, false
}

// ── LDAP Injection ──

var ldapiPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`\)\(\|`), 4, "owasp:ldap:001"},
	{regexp.MustCompile(`\*\)\(objectclass\s*=`), 5, "owasp:ldap:002"},
	{regexp.MustCompile(`\)\(\&`), 4, "owasp:ldap:003"},
	{regexp.MustCompile(`\(\|\(\w+\s*=\s*\*\)`), 4, "owasp:ldap:004"},
	{regexp.MustCompile(`(?i)admin\*\)\(`), 5, "owasp:ldap:005"},
}

func checkLDAPInjection(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range ldapiPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
		}
	}
	if total >= threshold {
		return OWASPHit{Category: CatLDAPI, RuleID: best, Score: total, Desc: "LDAP injection signals"}, true
	}
	return OWASPHit{}, false
}

// ── NoSQL Injection ──

var nosqliPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`(?i)\$where\b`), 5, "owasp:nosql:001"},
	{regexp.MustCompile(`(?i)\$ne\b`), 3, "owasp:nosql:002"},
	{regexp.MustCompile(`(?i)\$gt\b`), 3, "owasp:nosql:003"},
	{regexp.MustCompile(`(?i)\$regex\b`), 3, "owasp:nosql:004"},
	{regexp.MustCompile(`(?i)\$or\b\s*:\s*\[`), 3, "owasp:nosql:005"},
	{regexp.MustCompile(`(?i)\$exists\b`), 3, "owasp:nosql:006"},
}

func checkNoSQLi(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range nosqliPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
		}
	}
	if total >= threshold {
		return OWASPHit{Category: CatNoSQLi, RuleID: best, Score: total, Desc: "NoSQL injection signals"}, true
	}
	return OWASPHit{}, false
}

// ── Template Injection (SSTI) ──

var tmplInjectPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	// Jinja2 / Django / Twig
	{regexp.MustCompile(`\{\{\s*\d+\s*[\*\+\-/]\s*\d+\s*\}\}`), 5, "owasp:ssti:001"},
	{regexp.MustCompile(`\{\{\s*config\.`), 5, "owasp:ssti:002"},
	{regexp.MustCompile(`\{\{\s*['"]\w*['"]\.__class__`), 6, "owasp:ssti:003"},
	// ${...} Freemarker / Velocity / JSP EL
	{regexp.MustCompile(`\$\{\s*\d+\s*[\*\+\-/]\s*\d+\s*\}`), 5, "owasp:ssti:004"},
	{regexp.MustCompile(`\$\{.*?getClass\(\)`), 6, "owasp:ssti:005"},
	// <%= ... %> ERB / JSP
	{regexp.MustCompile(`<%=.*?%>`), 3, "owasp:ssti:006"},
}

func checkTemplateInjection(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range tmplInjectPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
		}
	}
	if total >= threshold {
		return OWASPHit{Category: CatTmplInject, RuleID: best, Score: total, Desc: "template injection signals"}, true
	}
	return OWASPHit{}, false
}

// ── File Upload Validation ──

var dangerousExtensions = map[string]bool{
	".php":    true,
	".php3":   true,
	".php4":   true,
	".php5":   true,
	".phtml":  true,
	".phar":   true,
	".jsp":    true,
	".jspx":   true,
	".asp":    true,
	".aspx":   true,
	".cer":    true,
	".cfm":    true,
	".exe":    true,
	".sh":     true,
	".bat":    true,
	".cmd":    true,
	".ps1":    true,
	".dll":    true,
	".so":     true,
	".war":    true,
	".jar":    true,
	".pl":     true,
	".py":     true,
	".rb":     true,
	".htaccess": true,
}

func checkFileUpload(filename, contentType string) (OWASPHit, bool) {
	if filename == "" {
		return OWASPHit{}, false
	}
	lower := strings.ToLower(filename)

	// Null byte injection in filename.
	if strings.Contains(lower, "\x00") || strings.Contains(lower, "%00") {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:001", Score: 6,
			Desc: "null byte in filename"}, true
	}

	// Double extension e.g. shell.php.jpg
	ext := filepath.Ext(lower)
	if ext != "" {
		withoutExt := lower[:len(lower)-len(ext)]
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

	// .htaccess override attempt
	if strings.HasSuffix(lower, ".htaccess") || lower == ".htaccess" {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:004", Score: 5,
			Desc: "htaccess override attempt"}, true
	}

	// Content-Type mismatch with image extension
	if (ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".gif") &&
		contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "image/") {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:005", Score: 3,
			Desc: "content-type mismatch for image"}, true
	}

	return OWASPHit{}, false
}

// ── HTTP Protocol Violation ──

func checkProtocolViolation(headers map[string]string, threshold int) (OWASPHit, bool) {
	if len(headers) == 0 {
		return OWASPHit{}, false
	}

	// Look up headers case-insensitively.
	get := func(key string) string {
		for k, v := range headers {
			if strings.EqualFold(k, key) {
				return v
			}
		}
		return ""
	}

	// HTTP Request Smuggling: both Content-Length and Transfer-Encoding set.
	cl := get("Content-Length")
	te := get("Transfer-Encoding")
	if cl != "" && te != "" && strings.Contains(strings.ToLower(te), "chunked") {
		return OWASPHit{
			Category: CatProtoViol, RuleID: "owasp:proto:001", Score: 6,
			Desc: "request smuggling: CL+TE conflict",
		}, true
	}

	// Duplicate Content-Length detection (rudimentary).
	if strings.Contains(cl, ",") {
		return OWASPHit{
			Category: CatProtoViol, RuleID: "owasp:proto:002", Score: 5,
			Desc: "duplicate content-length header",
		}, true
	}

	// Excessive header length (potential buffer overflow probe).
	for k, v := range headers {
		if len(k)+len(v) > 8192 {
			return OWASPHit{
				Category: CatProtoViol, RuleID: "owasp:proto:003", Score: 4,
				Desc: "oversized header: " + k,
			}, true
		}
	}

	return OWASPHit{}, false
}
