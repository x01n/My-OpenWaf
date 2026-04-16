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
	// Private IP ranges — require URL-scheme or path-separator context to avoid false positives
	// on legitimate payloads that merely mention an IP address (e.g. logging, network tools).
	// Raising score to 4 so a single hit at mid-sensitivity (threshold=4) triggers correctly.
	{regexp.MustCompile(`(?i)(https?://|ftps?://|[/@])10\.\d{1,3}\.\d{1,3}\.\d{1,3}`), 4, "owasp:ssrf:004"},
	{regexp.MustCompile(`(?i)(https?://|ftps?://|[/@])172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}`), 4, "owasp:ssrf:005"},
	{regexp.MustCompile(`(?i)(https?://|ftps?://|[/@])192\.168\.\d{1,3}\.\d{1,3}`), 4, "owasp:ssrf:006"},
	// Localhost variants — score raised to 5: http://127.0.0.1 is an unambiguous SSRF attempt
	// and must trigger at mid-sensitivity (threshold=4) without needing to combine with others.
	{regexp.MustCompile(`(?i)(https?://|[/@])(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost)(:\d+|/)`), 5, "owasp:ssrf:007"},
	{regexp.MustCompile(`(?i)(https?://|[/@])(\[::1\]|\[::\]|0\.0\.0\.0)(:\d+|/)`), 5, "owasp:ssrf:008"},
	// DNS rebinding / encoding bypasses — require URL scheme to avoid matching CSS hex colors (#DEADBEEF)
	{regexp.MustCompile(`(?i)https?://\s*0x[0-9a-f]{8}\b`), 4, "owasp:ssrf:009"},
	// file:// / gopher:// / dict:// schemes
	{regexp.MustCompile(`(?i)(file|gopher|dict|ldap|sftp|tftp)://`), 5, "owasp:ssrf:010"},
	// Decimal/octal IP encoding (e.g., http://2130706433 = 127.0.0.1)
	{regexp.MustCompile(`(?i)https?://\d{8,10}(/|$|\s|:)`), 4, "owasp:ssrf:011"},
	// IPv6-mapped IPv4 private addresses
	{regexp.MustCompile(`(?i)::ffff:(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)`), 4, "owasp:ssrf:012"},
	// AWS IMDSv2 token header (indicates SSRF exploit chain)
	{regexp.MustCompile(`(?i)x-aws-ec2-metadata-token`), 5, "owasp:ssrf:013"},
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
			if total >= threshold {
				return OWASPHit{Category: CatSSRF, RuleID: best, Score: total, Desc: "SSRF signals"}, true
			}
		}
	}
	return OWASPHit{}, false
}

// ── Command Injection ──

var cmdInjectPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	// Pipe / semicolon / backtick / $() command chaining.
	// Using (?:[\s;|&`]|$) instead of \b prevents matching URL key=value params:
	// "a=1;id=123" → ";id" followed by "=" → no match.
	// "host=x;id" at end of string → matches via $.
	{regexp.MustCompile("(?i)[;|&]\\s*(ls|cat|id|whoami|uname|pwd|ps|wget|curl|nc|bash|sh)(?:[\\s;|&`]|$)"), 5, "owasp:cmd:001"},
	// Backtick command substitution — require a known shell command inside (avoids Markdown FP)
	{regexp.MustCompile("(?i)`[^`]*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|echo|rm|chmod|chown|python|perl|ruby|php|base64|find|grep|awk|sed|ps|kill|nslookup|dig|ping|sleep|dd|cp|mv|mkdir|touch|head|tail|sort|xxd)[^`]*`"), 4, "owasp:cmd:002"},
	// $() with shell commands inside (excludes jQuery selectors)
	{regexp.MustCompile(`\$\([^)]*\b(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|echo|rm|chmod|chown|python|perl|ruby|php|base64|dd|nslookup|dig|ping|sleep|kill|find|grep|awk|sed|head|tail|wc|sort|xxd|od)\b`), 4, "owasp:cmd:003"},
	// Redirections that typically indicate injection
	{regexp.MustCompile(`(?i)(>|>>)\s*/(etc|tmp|var|root|home)/`), 4, "owasp:cmd:004"},
	// Explicit command execution
	{regexp.MustCompile(`(?i)(^|[\s;|&])(wget|curl)\s+https?://`), 3, "owasp:cmd:005"},
	// Null byte / newline injection
	{regexp.MustCompile(`%00|\x00|%0a|%0d`), 3, "owasp:cmd:006"},
	// Common discovery commands followed by semicolon
	{regexp.MustCompile(`(?i)\b(id|uname|whoami|hostname|ifconfig|ipconfig)\s*;`), 3, "owasp:cmd:007"},
	// Pipe to shell commands — same (?:[\s;|&`]|$) fix to avoid URL-param false positives
	{regexp.MustCompile("(?i)\\|+\\s*(cat|ls|id|whoami|uname|pwd|ps|wget|curl|nc|bash|sh|ping|nslookup|dig|echo|head|tail|more|less|find|grep|awk|sed|base64|python|perl|ruby|php|node|java)(?:[\\s;|&`]|$)"), 5, "owasp:cmd:008"},
	// ${IFS} space bypass (common in filter evasion)
	{regexp.MustCompile(`(?i)\$\{?\s*IFS\s*\}?`), 4, "owasp:cmd:009"},
	// Env variable prefix + command execution: VAR=val command
	{regexp.MustCompile(`(?i)\b\w+=\S+\s+(cat|id|whoami|curl|wget|bash|sh|python|perl|ruby|php)\b`), 3, "owasp:cmd:010"},
	// Chained command using && or ||
	{regexp.MustCompile("(?i)(&&|\\|\\|)\\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|rm|chmod)(?:[\\s;|&`]|$)"), 4, "owasp:cmd:011"},
	// Bash brace expansion: {cat,/etc/passwd} — bypasses space detection
	{regexp.MustCompile(`\{\s*(cat|ls|id|whoami|echo|bash|sh|python|perl|ruby|wget|curl)\s*,`), 4, "owasp:cmd:012"},
	// Here-string injection: bash<<<'command'
	{regexp.MustCompile(`(?i)(bash|sh|python|perl|ruby)\s*<<<`), 4, "owasp:cmd:013"},
	// ANSI-C quoting with hex/octal encoding: $'\x63\x61\x74'
	{regexp.MustCompile(`\$'\s*\\[xX0][0-9a-fA-F]`), 4, "owasp:cmd:014"},
	// Tee / dd / base64 piped to shell — alternative command execution chain
	{regexp.MustCompile(`(?i)(base64\s+-d|dd\s+if=|tee\s+/tmp)\s*\|`), 4, "owasp:cmd:015"},
}

func checkCmdInjection(s string, threshold int) (OWASPHit, bool) {
	if !hasCmdIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range cmdInjectPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatCmdInject, RuleID: best, Score: total, Desc: "command injection signals"}, true
			}
		}
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
	// Parametric entity expansion (exclude common HTML entities)
	{regexp.MustCompile(`(?i)%\w+;`), 2, "owasp:xxe:004"},
	{regexp.MustCompile(`(?i)system\s+['"](file|http|ftp|php|expect|data)://`), 5, "owasp:xxe:005"},
	// Blind OOB XXE via parameter entity exfiltration
	{regexp.MustCompile(`(?i)<!entity\s+%\s+\w+\s+system`), 6, "owasp:xxe:006"},
	// XInclude injection
	{regexp.MustCompile(`(?i)<xi:include\s+.*href\s*=`), 5, "owasp:xxe:007"},
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
			if total >= threshold {
				return OWASPHit{Category: CatXXE, RuleID: best, Score: total, Desc: "XML external entity signals"}, true
			}
		}
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
			if total >= threshold {
				return OWASPHit{Category: CatLDAPI, RuleID: best, Score: total, Desc: "LDAP injection signals"}, true
			}
		}
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
	// MongoDB aggregation pipeline injection
	{regexp.MustCompile(`(?i)\$lookup\b\s*:\s*\{`), 4, "owasp:nosql:007"},
	// JavaScript-based NoSQL injection in $where context
	{regexp.MustCompile(`(?i)this\.\w+\s*(==|!=|===|!==)\s*['"]`), 3, "owasp:nosql:008"},
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
			if total >= threshold {
				return OWASPHit{Category: CatNoSQLi, RuleID: best, Score: total, Desc: "NoSQL injection signals"}, true
			}
		}
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
	// Smarty {php}...{/php} template execution
	{regexp.MustCompile(`(?i)\{/?php\}`), 4, "owasp:ssti:007"},
	// Python dunder attribute traversal (__subclasses__, __builtins__, __import__)
	{regexp.MustCompile(`(?i)__(subclasses|builtins|globals|import|init|reduce)__`), 5, "owasp:ssti:008"},
	// Pebble template engine: beans / getClass access
	{regexp.MustCompile(`(?i)\{\{.*\.(getclass|forname|getmethod|invoke)\(`), 5, "owasp:ssti:009"},
	// JavaScript prototype pollution via JSON key injection
	{regexp.MustCompile(`(?i)["'\[\{]__proto__["'\]\}]`), 5, "owasp:ssti:010"},
	// Constructor prototype pollution: {"constructor":{"prototype":...}}
	{regexp.MustCompile(`(?i)["']constructor["']\s*:\s*\{`), 5, "owasp:ssti:011"},
	// EJS template RCE: <%- process.env / require(...)  %>
	{regexp.MustCompile(`(?i)<%[-=]?\s*(process\s*\.\s*env|require\s*\(|global\s*\[)`), 5, "owasp:ssti:012"},
	// Handlebars/Mustache: {{lookup this ...}} or {{#with (...)}}
	// Score reduced to 2: these helpers appear in legitimate Handlebars templates.
	{regexp.MustCompile(`(?i)\{\{\s*(lookup|with|each|log)\s+`), 2, "owasp:ssti:013"},
	// Tornado / Mako: ${self.module / caller.body}
	{regexp.MustCompile(`(?i)\$\{self\.(module|template|loader|init_code)\b`), 5, "owasp:ssti:014"},
}

// hasTemplateInjectionIndicator returns true when the string contains markers
// specific to template injection patterns, skipping the 14-regex SSTI battery
// for strings with no plausible injection content.
func hasTemplateInjectionIndicator(s string) bool {
	return strings.Contains(s, "{{") ||
		strings.Contains(s, "${") ||
		strings.Contains(s, "<%") ||
		strings.Contains(s, "__class__") ||
		strings.Contains(s, "__proto__") ||
		strings.Contains(s, "__subclasses__") ||
		strings.Contains(s, "__builtins__") ||
		strings.Contains(s, "__import__") ||
		strings.Contains(s, "constructor") ||
		strings.Contains(s, "getclass(") ||
		strings.Contains(s, "java.lang.") ||
		strings.Contains(s, "process.env") ||
		strings.Contains(s, "{php}") ||
		strings.Contains(s, "$self.")
}

func checkTemplateInjection(s string, threshold int) (OWASPHit, bool) {
	if !hasTemplateInjectionIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range tmplInjectPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatTmplInject, RuleID: best, Score: total, Desc: "template injection signals"}, true
			}
		}
	}
	return OWASPHit{}, false
}

// ── File Upload Validation ──

var dangerousExtensions = map[string]bool{
	".php":      true,
	".php3":     true,
	".php4":     true,
	".php5":     true,
	".phtml":    true,
	".phar":     true,
	".jsp":      true,
	".jspx":     true,
	".asp":      true,
	".aspx":     true,
	".cer":      true,
	".cfm":      true,
	".exe":      true,
	".sh":       true,
	".bat":      true,
	".cmd":      true,
	".ps1":      true,
	".dll":      true,
	".so":       true,
	".war":      true,
	".jar":      true,
	".pl":       true,
	".py":       true,
	".rb":       true,
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

// ── JNDI / Log4Shell Injection ──

var jndiPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`(?i)\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)s?://`), 6, "owasp:jndi:001"},
	{regexp.MustCompile(`(?i)\$\{(lower|upper|env|sys|java|base64):.*\}`), 4, "owasp:jndi:002"},
	{regexp.MustCompile(`(?i)\$\{.*\$\{.*\}\}`), 3, "owasp:jndi:003"},
	{regexp.MustCompile(`(?i)\$\{(env|sys):.*\}`), 4, "owasp:jndi:004"},
	// Split-character / obfuscated JNDI: ${j${::-n}d${::-i}:...}
	{regexp.MustCompile(`(?i)\$\{[^}]*j[^}]*\$\{[^}]*\}[^}]*n[^}]*d[^}]*i\s*:`), 5, "owasp:jndi:005"},
	// URL-encoded JNDI: %24%7Bjndi:
	{regexp.MustCompile(`(?i)%24%7[bB]jndi\s*%3[aA]`), 5, "owasp:jndi:006"},
	// Unicode-escaped JNDI: \u0024\u007bjndi:
	{regexp.MustCompile(`(?i)\\u0024\\u007[bB]jndi`), 5, "owasp:jndi:007"},
}

func checkJNDI(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range jndiPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatJNDI, RuleID: best, Score: total, Desc: "JNDI/Log4Shell injection signals"}, true
			}
		}
	}
	return OWASPHit{}, false
}

// ── CRLF Injection ──

var crlfPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	{regexp.MustCompile(`\r\n\s*(set-cookie|location|content-type|x-)\s*:`), 6, "owasp:crlf:001"},
	{regexp.MustCompile(`%0d%0a\s*(set-cookie|location|content-type)\s*:`), 6, "owasp:crlf:002"},
	{regexp.MustCompile(`%0d%0a%0d%0a`), 5, "owasp:crlf:003"},
	{regexp.MustCompile(`\r\n\r\n`), 4, "owasp:crlf:004"},
}

func checkCRLF(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range crlfPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatCRLF, RuleID: best, Score: total, Desc: "CRLF injection / HTTP response splitting"}, true
			}
		}
	}
	return OWASPHit{}, false
}

// ── Expression Language Injection (Spring EL, OGNL, SpEL) ──

var exprLangPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	// Spring Expression Language
	{regexp.MustCompile(`(?i)#\{T\(java\.lang\.`), 6, "owasp:el:001"},
	{regexp.MustCompile(`(?i)\$\{T\(java\.lang\.`), 6, "owasp:el:002"},
	// OGNL
	{regexp.MustCompile(`(?i)%\{.*getClass\(\)`), 5, "owasp:el:003"},
	{regexp.MustCompile(`(?i)\(#rt\s*=\s*@java\.lang\.Runtime\)`), 6, "owasp:el:004"},
	// Generic class/runtime access
	{regexp.MustCompile(`(?i)java\.lang\.(runtime|processbuilder|class)`), 4, "owasp:el:005"},
	{regexp.MustCompile(`(?i)getruntime\(\)\s*\.\s*exec\s*\(`), 5, "owasp:el:006"},
}

func checkExprLang(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range exprLangPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatExprLang, RuleID: best, Score: total, Desc: "expression language injection signals"}, true
			}
		}
	}
	return OWASPHit{}, false
}

// ── Deserialization Attacks ──

var deserialPatterns = []struct {
	re    *regexp.Regexp
	score int
	id    string
}{
	// Java serialization magic bytes
	{regexp.MustCompile(`\xac\xed\x00\x05`), 6, "owasp:deser:001"},
	// PHP serialization
	{regexp.MustCompile(`(?i)O:\d+:"[^"]+"`), 4, "owasp:deser:002"},
	// Python pickle
	{regexp.MustCompile(`(?i)c(os|posix|nt)\n(system|popen)`), 5, "owasp:deser:003"},
	// .NET ViewState
	{regexp.MustCompile(`(?i)__viewstate.*ysoserial`), 5, "owasp:deser:004"},
	// Ruby Marshal — require version bytes + type indicator to avoid matching random binary
	{regexp.MustCompile(`\x04\x08[\x30\x49\x5b\x6f\x7b]`), 3, "owasp:deser:005"},
	// .NET BinaryFormatter / LosFormatter magic
	{regexp.MustCompile(`(?i)AAEAAAD//`), 5, "owasp:deser:006"},
	// Node.js serialize-javascript RCE pattern
	{regexp.MustCompile(`(?i)\{"rce":\s*"_\$\$ND_FUNC\$\$_`), 5, "owasp:deser:007"},
}

func checkDeserialization(s string, threshold int) (OWASPHit, bool) {
	total := 0
	best := ""
	for _, p := range deserialPatterns {
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatDeserial, RuleID: best, Score: total, Desc: "deserialization attack signals"}, true
			}
		}
	}
	return OWASPHit{}, false
}

// ── HTTP Protocol Violation ──

func checkProtocolViolation(headers map[string]string, _ int) (OWASPHit, bool) {
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
