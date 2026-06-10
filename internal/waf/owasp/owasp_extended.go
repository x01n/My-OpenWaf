package owasp

import (
	"path/filepath"
	"regexp"
	"strings"
)

// ── SSRF (Server-Side Request Forgery) ──

// hasSSRFIndicator returns true when the string contains URL schemes or known
// private/cloud-internal addresses that may indicate an SSRF payload.
// Avoids running 13 SSRF regexes on every clean request.
func hasSSRFIndicator(s string) bool {
	return strings.Contains(s, "://") ||
		strings.Contains(s, "169.254.169.254") ||
		strings.Contains(s, "metadata.google") ||
		strings.Contains(s, "100.100.100.200") ||
		strings.Contains(s, "x-aws-ec2-metadata") ||
		strings.Contains(s, "localhost") ||
		strings.Contains(s, "127.0.") ||
		strings.Contains(s, "::ffff:") ||
		strings.Contains(s, "::1") ||
		strings.Contains(s, "0x7f") ||
		strings.Contains(s, "unix:") ||
		strings.Contains(s, "0177.0") ||
		strings.Contains(s, ".nip.io") ||
		strings.Contains(s, ".xip.io") ||
		strings.Contains(s, ".sslip.io") ||
		strings.Contains(s, "2130706433")
}

var ssrfPatterns = []owaspPattern{
	// Cloud metadata endpoints
	{regexp.MustCompile(`169\.254\.169\.254`), 6, "owasp:ssrf:001", "169.254.169.254"}, // AWS/Azure/GCP metadata
	{regexp.MustCompile(`metadata\.google\.internal`), 6, "owasp:ssrf:002", "metadata.google.internal"},
	{regexp.MustCompile(`100\.100\.100\.200`), 6, "owasp:ssrf:003", "100.100.100.200"}, // Alibaba Cloud
	// Private IP ranges — raise to 5 for new threshold
	{regexp.MustCompile(`(https?://|ftps?://|[/@])10\.\d{1,3}\.\d{1,3}\.\d{1,3}`), 5, "owasp:ssrf:004", ""},
	{regexp.MustCompile(`(https?://|ftps?://|[/@])172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}`), 5, "owasp:ssrf:005", ""},
	{regexp.MustCompile(`(https?://|ftps?://|[/@])192\.168\.\d{1,3}\.\d{1,3}`), 5, "owasp:ssrf:006", "192.168."},
	// Localhost variants
	{regexp.MustCompile(`(https?://|[/@])(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost)(:\d+|/)`), 5, "owasp:ssrf:007", ""},
	{regexp.MustCompile(`(https?://|[/@])(\[::1\]|\[::\]|0\.0\.0\.0)(:\d+|/)`), 5, "owasp:ssrf:008", ""},
	// DNS rebinding / encoding bypasses
	{regexp.MustCompile(`https?://\s*0x[0-9a-f]{8}\b`), 5, "owasp:ssrf:009", ""},
	// file:// / gopher:// / dict:// schemes
	{regexp.MustCompile(`(file|gopher|dict|ldap|sftp|tftp|php|expect|phar)://`), 5, "owasp:ssrf:010", ""},
	// Decimal/octal IP encoding (e.g., http://2130706433 = 127.0.0.1)
	{regexp.MustCompile(`https?://\d{8,10}(/|$|\s|:)`), 5, "owasp:ssrf:011", ""},
	// IPv6-mapped IPv4 private addresses
	{regexp.MustCompile(`::ffff:(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)`), 5, "owasp:ssrf:012", "::ffff:"},
	// AWS IMDSv2 token header (indicates SSRF exploit chain)
	{regexp.MustCompile(`x-aws-ec2-metadata-token`), 5, "owasp:ssrf:013", "x-aws-ec2-metadata-token"},
	// Unix socket SSRF (CVE-2023-46809 style): unix:path|http://...
	{regexp.MustCompile(`\bunix:[^\s]{10,}`), 4, "owasp:ssrf:014", "unix:"},
	// Azure Instance Metadata Service (IMDS)
	{regexp.MustCompile(`169\.254\.169\.254.{0,50}metadata/instance`), 6, "owasp:ssrf:015", "169.254.169.254"},
	// GCP metadata with flavor header
	{regexp.MustCompile(`metadata\.google\.internal.{0,50}(computemetadata|v1/)`), 6, "owasp:ssrf:016", "metadata.google.internal"},
	// AWS IMDSv2 token PUT request pattern
	{regexp.MustCompile(`put.{0,100}169\.254\.169\.254.{0,50}api/token`), 6, "owasp:ssrf:017", "169.254.169.254"},
	// DigitalOcean metadata endpoint
	{regexp.MustCompile(`169\.254\.169\.254.{0,50}/metadata/v1`), 5, "owasp:ssrf:018", "169.254.169.254"},
	// Oracle Cloud IMDS
	{regexp.MustCompile(`169\.254\.169\.254.{0,50}opc/v[12]/`), 5, "owasp:ssrf:019", "169.254.169.254"},
	// Octal IP bypass: http://0177.0.0.1/ (127.0.0.1 in octal)
	{regexp.MustCompile(`https?://0[0-7]{1,3}\.0{0,3}\.0{0,3}\.[0-7]{1,3}(/|$|\s|:)`), 5, "owasp:ssrf:020", ""},
	// DNS rebinding services: *.nip.io, *.xip.io, *.sslip.io pointing to internal IPs
	{regexp.MustCompile(`(127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\.(nip|xip|sslip)\.io\b`), 5, "owasp:ssrf:021", ""},
	// IPv6 mapped IPv4 in URL context: http://[::ffff:127.0.0.1]/
	{regexp.MustCompile(`https?://\[::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]`), 5, "owasp:ssrf:022", "::ffff:"},
	// Decimal IP in URL: http://2130706433/ (127.0.0.1), http://3232235521/ (192.168.0.1)
	{regexp.MustCompile(`https?://\d{9,10}\b`), 4, "owasp:ssrf:023", ""},
}

func shouldScanSSRFPattern(s string, p owaspPattern) bool {
	if p.hint != "" && !strings.Contains(s, p.hint) {
		return false
	}
	switch p.id {
	case "owasp:ssrf:004":
		return strings.Contains(s, "10.")
	case "owasp:ssrf:005":
		return strings.Contains(s, "172.")
	case "owasp:ssrf:006":
		return strings.Contains(s, "192.168.")
	case "owasp:ssrf:007":
		return strings.Contains(s, "127.") || strings.Contains(s, "localhost")
	case "owasp:ssrf:008":
		return strings.Contains(s, "::1") || strings.Contains(s, "[::") || strings.Contains(s, "0.0.0.0")
	case "owasp:ssrf:009":
		return strings.Contains(s, "0x")
	case "owasp:ssrf:010":
		return strings.Contains(s, "file://") || strings.Contains(s, "gopher://") || strings.Contains(s, "dict://") || strings.Contains(s, "ldap://") || strings.Contains(s, "sftp://") || strings.Contains(s, "tftp://") || strings.Contains(s, "php://") || strings.Contains(s, "expect://") || strings.Contains(s, "phar://")
	case "owasp:ssrf:011", "owasp:ssrf:023":
		return strings.Contains(s, "http://") || strings.Contains(s, "https://")
	case "owasp:ssrf:020":
		return strings.Contains(s, "0177.") || strings.Contains(s, "http://0") || strings.Contains(s, "https://0")
	case "owasp:ssrf:021":
		return strings.Contains(s, ".nip.io") || strings.Contains(s, ".xip.io") || strings.Contains(s, ".sslip.io")
	default:
		return true
	}
}

func checkSSRF(s string, threshold int) (OWASPHit, bool) {
	if !hasSSRFIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range ssrfPatterns {
		if !shouldScanSSRFPattern(s, p) {
			continue
		}
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

var cmdInjectPatterns = []owaspPattern{
	// Pipe / semicolon / backtick / $() command chaining.
	// Using (?:[\s;|&`]|$) instead of \b prevents matching URL key=value params:
	// "a=1;id=123" → ";id" followed by "=" → no match.
	// "host=x;id" at end of string → matches via $.
	{regexp.MustCompile("[;|&]\\s*(ls|cat|id|whoami|uname|pwd|ps|wget|curl|nc|bash|sh|echo|rm|chmod|chown|ping|touch|kill|python|perl|ruby|php|node|java|nslookup|dig)(?:[\\s;|&`]|$)"), 5, "owasp:cmd:001", ""},
	// Backtick command substitution — require a known shell command inside (avoids Markdown FP)
	{regexp.MustCompile("`[^`]*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|echo|rm|chmod|chown|python|perl|ruby|php|base64|find|grep|awk|sed|ps|kill|nslookup|dig|ping|sleep|dd|cp|mv|mkdir|touch|head|tail|sort|xxd)[^`]*`"), 3, "owasp:cmd:002", ""},
	// $() with shell commands inside (excludes jQuery selectors)
	{regexp.MustCompile(`\$\([^)]*\b(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|echo|rm|chmod|chown|python|perl|ruby|php|base64|dd|nslookup|dig|ping|sleep|kill|find|grep|awk|sed|head|tail|wc|sort|xxd|od)\b`), 4, "owasp:cmd:003", ""},
	// Redirections that typically indicate injection
	{regexp.MustCompile(`(>|>>)\s*/(etc|tmp|var|root|home)/`), 4, "owasp:cmd:004", ">"},
	// Explicit command execution
	{regexp.MustCompile(`(^|[\s;|&])(wget|curl)\s+https?://`), 3, "owasp:cmd:005", ""},
	// Null byte / newline injection (includes actual newline/CR bytes from URL-decode)
	{regexp.MustCompile(`%00|\x00|%0[aAdD]|\x0a|\x0d`), 3, "owasp:cmd:006", ""},
	// Common discovery commands followed by semicolon
	{regexp.MustCompile(`\b(id|uname|whoami|hostname|ifconfig|ipconfig)\s*;`), 3, "owasp:cmd:007", ""},
	// Pipe to shell commands — same (?:[\s;|&`]|$) fix to avoid URL-param false positives
	{regexp.MustCompile("\\|+\\s*(cat|ls|id|whoami|uname|pwd|ps|wget|curl|nc|bash|sh|ping|nslookup|dig|echo|head|tail|more|less|find|grep|awk|sed|base64|python|perl|ruby|php|node|java)(?:[\\s;|&`]|$)"), 5, "owasp:cmd:008", ""},
	// ${IFS} space bypass (common in filter evasion)
	{regexp.MustCompile(`\$\{?\s*ifs\s*\}?`), 4, "owasp:cmd:009", "ifs"},
	// Env variable prefix + command execution: VAR=val command
	{regexp.MustCompile(`\b\w+=\S+\s+(cat|id|whoami|curl|wget|bash|sh|python|perl|ruby|php)\b`), 3, "owasp:cmd:010", ""},
	// Chained command using && or ||
	{regexp.MustCompile("(&&|\\|\\|)\\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|rm|chmod)(?:[\\s;|&`]|$)"), 4, "owasp:cmd:011", ""},
	// Bash brace expansion: {cat,/etc/passwd} — bypasses space detection
	{regexp.MustCompile(`\{\s*(cat|ls|id|whoami|echo|bash|sh|python|perl|ruby|wget|curl)\s*,`), 4, "owasp:cmd:012", "{"},
	// Here-string injection: bash<<<'command'
	{regexp.MustCompile(`(bash|sh|python|perl|ruby)\s*<<<`), 4, "owasp:cmd:013", ""},
	// ANSI-C quoting with hex/octal encoding: $'\x63\x61\x74'
	{regexp.MustCompile(`\$'\s*\\[xX0][0-9a-fA-F]`), 4, "owasp:cmd:014", "$'"},
	// Tee / dd / base64 piped to shell — alternative command execution chain
	{regexp.MustCompile(`(base64\s+-d|dd\s+if=|tee\s+/tmp)\s*\|`), 4, "owasp:cmd:015", ""},
	// Newline/CR-separated command injection (%0a / %0d bypass semicolon filters)
	{regexp.MustCompile("[\\r\\n]\\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php|echo|rm|chmod|kill|nslookup|dig|ping|sleep|find|awk|sed)(?:[\\s;|&`]|$)"), 4, "owasp:cmd:016", ""},
	// Server-Side Include (SSI) injection: <!--#exec cmd="..."--> and <!--#include virtual="...">
	{regexp.MustCompile(`<!--\s*#\s*(exec|include|echo|config|fsize|flastmod)\b`), 5, "owasp:cmd:017", "<!--"},
	// Backtick concatenation evasion: wh``oami, c``at, i``d — empty backticks split command names
	{regexp.MustCompile("(?:^|[;|&\\s])(w``?h``?o``?a``?m``?i|i``d|c``?a``?t|u``?n``?a``?m``?e)(?:[\\s;|&`]|$)"), 4, "owasp:cmd:018", ""},
	// touch/rm with path — file creation/deletion as RCE proof
	{regexp.MustCompile(`[;|&]\s*(?:touch|rm)\s+/`), 5, "owasp:cmd:019", "touch"},
	// Git argument injection: --open-files-in-pager, --upload-pack, --exec, etc.
	{regexp.MustCompile(`--(?:open-files-in-pager|upload-pack|exec|receive-pack)\s*=`), 5, "owasp:cmd:020", "--"},
	// ${IFS} as space substitute in shell command injection.
	{regexp.MustCompile(`\$\{ifs\}`), 5, "owasp:cmd:021", ""},
	// $(command) subshell execution in parameter value context.
	{regexp.MustCompile(`\$\(\s*\w+[\s$]`), 4, "owasp:cmd:022", ""},
	// Backtick-split evasion with empty backticks inside command: wh``oami, ca``t.
	{regexp.MustCompile("\\b\\w+``\\w+\\b"), 4, "owasp:cmd:023", ""},
	// Backtick command execution: `ping ...`, `touch ...`, `whoami`
	{regexp.MustCompile("`\\s*(ping|curl|wget|whoami|id|cat|ls|touch|rm|chmod|nc|nslookup|dig|python|perl|ruby|php|bash|sh|uname)\\b"), 5, "owasp:cmd:024", ""},
}

func shouldScanCmdPattern(s string, p owaspPattern) bool {
	if p.hint != "" && !strings.Contains(s, p.hint) {
		return false
	}
	switch p.id {
	case "owasp:cmd:001":
		return hasShellCommandAfterCmdSeparator(s)
	case "owasp:cmd:002", "owasp:cmd:024":
		return strings.Contains(s, "`")
	case "owasp:cmd:003", "owasp:cmd:022":
		return strings.Contains(s, "$(")
	case "owasp:cmd:004":
		return strings.Contains(s, ">") && strings.Contains(s, "/")
	case "owasp:cmd:005":
		return strings.Contains(s, "wget") || strings.Contains(s, "curl")
	case "owasp:cmd:006":
		return strings.Contains(s, "%00") || strings.Contains(s, "\x00") || strings.Contains(s, "%0a") || strings.Contains(s, "%0d") || strings.Contains(s, "\x0a") || strings.Contains(s, "\x0d")
	case "owasp:cmd:007":
		return hasDiscoveryCommandBeforeSemicolon(s)
	case "owasp:cmd:008":
		return hasShellCommandAfterPipe(s)
	case "owasp:cmd:015":
		return hasPipeAfterCmdOutputTransform(s)
	case "owasp:cmd:010":
		return hasEnvAssignmentBeforeCommand(s)
	case "owasp:cmd:011":
		return hasShellCommandAfterLogicalSeparator(s)
	case "owasp:cmd:013":
		return strings.Contains(s, "<<<")
	case "owasp:cmd:014":
		return strings.Contains(s, "$'")
	case "owasp:cmd:016":
		return strings.ContainsAny(s, "\r\n")
	case "owasp:cmd:018", "owasp:cmd:023":
		return strings.Contains(s, "``")
	case "owasp:cmd:019":
		return strings.Contains(s, "touch") || strings.Contains(s, "rm")
	case "owasp:cmd:020":
		return strings.Contains(s, "--")
	case "owasp:cmd:021":
		return strings.Contains(s, "${ifs}")
	default:
		return true
	}
}

func hasDiscoveryCommandBeforeSemicolon(s string) bool {
	for semi := strings.IndexByte(s, ';'); semi >= 0; {
		start := semi - 1
		for start >= 0 && (s[start] == ' ' || s[start] == '\t') {
			start--
		}
		end := start + 1
		for start >= 0 && isCmdWordByte(s[start]) {
			start--
		}
		word := s[start+1 : end]
		switch word {
		case "id", "uname", "whoami", "hostname", "ifconfig", "ipconfig":
			return true
		}
		next := semi + 1
		if next >= len(s) {
			return false
		}
		rest := s[next:]
		nextSemi := strings.IndexByte(rest, ';')
		if nextSemi < 0 {
			return false
		}
		semi = next + nextSemi
	}
	return false
}

func hasEnvAssignmentBeforeCommand(s string) bool {
	for eq := strings.IndexByte(s, '='); eq >= 0; {
		if hasEnvAssignmentCommandAfter(s, eq+1) {
			return true
		}
		next := eq + 1
		if next >= len(s) {
			return false
		}
		rest := s[next:]
		nextEq := strings.IndexByte(rest, '=')
		if nextEq < 0 {
			return false
		}
		eq = next + nextEq
	}
	return false
}

func hasEnvAssignmentCommandAfter(s string, offset int) bool {
	i := offset
	for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\r' && s[i] != '\n' && s[i] != '&' && s[i] != ';' && s[i] != '|' {
		i++
	}
	if i == offset || i >= len(s) {
		return false
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	start := i
	for i < len(s) && isCmdWordByte(s[i]) {
		i++
	}
	if start == i {
		return false
	}
	switch s[start:i] {
	case "cat", "id", "whoami", "curl", "wget", "bash", "sh", "python", "perl", "ruby", "php":
		return true
	default:
		return false
	}
}

func hasPipeAfterCmdOutputTransform(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'b':
			if hasWordSpaceThenPrefixBeforePipe(s, i, "base64", "-d") {
				return true
			}
		case 'd':
			if hasWordSpaceThenPrefixBeforePipe(s, i, "dd", "if=") {
				return true
			}
		case 't':
			if hasWordSpaceThenPrefixBeforePipe(s, i, "tee", "/tmp") {
				return true
			}
		}
	}
	return false
}

func hasWordSpaceThenPrefixBeforePipe(s string, offset int, word, next string) bool {
	if offset > 0 && isCmdWordByte(s[offset-1]) {
		return false
	}
	if len(s)-offset < len(word) || s[offset:offset+len(word)] != word {
		return false
	}
	i := offset + len(word)
	if i >= len(s) || (s[i] != ' ' && s[i] != '\t' && s[i] != '\r' && s[i] != '\n') {
		return false
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	if len(s)-i < len(next) || s[i:i+len(next)] != next {
		return false
	}
	return strings.Contains(s[i+len(next):], "|")
}

func hasShellCommandAfterCmdSeparator(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ';', '|', '&':
			if hasShellCommandAtCmdOffset(s, i+1) {
				return true
			}
		}
	}
	return false
}

func hasShellCommandAfterPipe(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '|' && hasShellCommandAtCmdOffset(s, i+1) {
			return true
		}
	}
	return false
}

func hasShellCommandAfterLogicalSeparator(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if ((s[i] == '&' && s[i+1] == '&') || (s[i] == '|' && s[i+1] == '|')) && hasShellCommandAtCmdOffset(s, i+2) {
			return true
		}
	}
	return false
}

func hasShellCommandAtCmdOffset(s string, i int) bool {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	start := i
	for i < len(s) && isCmdWordByte(s[i]) {
		i++
	}
	if start == i || !isShellCommandWord(s[start:i]) {
		return false
	}
	return i == len(s) || s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n' || s[i] == ';' || s[i] == '|' || s[i] == '&' || s[i] == '`'
}

func checkCmdInjection(s string, threshold int) (OWASPHit, bool) {
	if !hasCmdIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range cmdInjectPatterns {
		if !shouldScanCmdPattern(s, p) {
			continue
		}
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

func hasXXEIndicator(s string) bool {
	return strings.Contains(s, "<!doctype") ||
		strings.Contains(s, "<!entity") ||
		strings.Contains(s, "!entity") ||
		strings.Contains(s, " system ") ||
		strings.Contains(s, " public ") ||
		strings.Contains(s, "xi:include") ||
		strings.Contains(s, "file://") ||
		strings.Contains(s, "expect://") ||
		strings.Contains(s, "php://")
}

var xxePatterns = []owaspPattern{
	{regexp.MustCompile(`<!doctype[^>]{1,100}\[`), 5, "owasp:xxe:001", "<!doctype"},
	{regexp.MustCompile(`<!entity\s+\w+\s+system`), 6, "owasp:xxe:002", "<!entity"},
	{regexp.MustCompile(`<!entity\s+\w+\s+public`), 6, "owasp:xxe:003", "<!entity"},
	// Parametric entity expansion (exclude common HTML entities)
	{regexp.MustCompile(`%\w+;`), 2, "owasp:xxe:004", ""},
	{regexp.MustCompile(`system\s+['"](file|http|ftp|php|expect|data)://`), 5, "owasp:xxe:005", "system"},
	// Blind OOB XXE via parameter entity exfiltration
	{regexp.MustCompile(`<!entity\s+%\s+\w+\s+system`), 6, "owasp:xxe:006", "<!entity"},
	// XInclude injection
	{regexp.MustCompile(`<xi:include\s+.*href\s*=`), 5, "owasp:xxe:007", "xi:include"},
}

func checkXXE(s string, threshold int) (OWASPHit, bool) {
	if !hasXXEIndicator(s) {
		return OWASPHit{}, false
	}
	// Suppress XXE detection in large JSON/analytics payloads that contain serialized
	// HTML with <!DOCTYPE html> but no actual XML entity declarations.
	// Real XXE attacks require <!ENTITY or SYSTEM/PUBLIC keywords in DTD context.
	// Use precise patterns: "<!entity" (DTD decl), " system " or " public " (DTD keywords),
	// not just substrings like "system" which match JSON property names like ":systemId".
	if len(s) > 500 {
		lower := strings.ToLower(s)
		hasEntity := strings.Contains(lower, "<!entity") || strings.Contains(lower, "!entity")
		hasSystem := strings.Contains(lower, " system ") || strings.Contains(lower, " system\"") || strings.Contains(lower, " system'")
		hasPublic := strings.Contains(lower, " public ") || strings.Contains(lower, " public\"") || strings.Contains(lower, " public'")
		hasXInclude := strings.Contains(lower, "xi:include")
		if !hasEntity && !hasSystem && !hasPublic && !hasXInclude {
			return OWASPHit{}, false
		}
	}
	total := 0
	best := ""
	for _, p := range xxePatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
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

// hasLDAPInjectionIndicator returns true when the string contains LDAP filter
// structure characters specific to LDAP injection payloads.
func hasLDAPInjectionIndicator(s string) bool {
	return strings.Contains(s, ")(") ||
		strings.Contains(s, "objectclass") ||
		strings.Contains(s, ")(|") ||
		strings.Contains(s, ")(&")
}

var ldapiPatterns = []owaspPattern{
	{regexp.MustCompile(`\)\(\|`), 4, "owasp:ldap:001", ""},
	{regexp.MustCompile(`\*\)\(objectclass\s*=`), 5, "owasp:ldap:002", "objectclass"},
	{regexp.MustCompile(`\)\(\&`), 4, "owasp:ldap:003", ""},
	{regexp.MustCompile(`\(\|\(\w+\s*=\s*\*\)`), 4, "owasp:ldap:004", ""},
	{regexp.MustCompile(`admin\*\)\(`), 5, "owasp:ldap:005", "admin"},
	{regexp.MustCompile(`\)\(!\(`), 4, "owasp:ldap:006", ""},
	{regexp.MustCompile(`\(\|\s*\(uid=\*\)\s*\(\|`), 4, "owasp:ldap:007", "uid"},
	{regexp.MustCompile(`\(\w+\s*=\s*\*\)\s*\(mail=\*\)`), 4, "owasp:ldap:008", "mail"},
}

func checkLDAPInjection(s string, threshold int) (OWASPHit, bool) {
	if !hasLDAPInjectionIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range ldapiPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
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

var nosqliPatterns = []owaspPattern{
	{regexp.MustCompile(`\$where\b`), 5, "owasp:nosql:001", ""},
	{regexp.MustCompile(`\$ne\b`), 3, "owasp:nosql:002", ""},
	{regexp.MustCompile(`\$gt\b`), 3, "owasp:nosql:003", ""},
	{regexp.MustCompile(`\$regex\b`), 4, "owasp:nosql:004", ""},
	{regexp.MustCompile(`\$or\b\s*:\s*\[`), 3, "owasp:nosql:005", ""},
	{regexp.MustCompile(`\$exists\b`), 3, "owasp:nosql:006", ""},
	// MongoDB aggregation pipeline injection
	{regexp.MustCompile(`\$lookup\b\s*:\s*\{`), 4, "owasp:nosql:007", ""},
	// JavaScript-based NoSQL injection in $where context
	{regexp.MustCompile(`this\.\w+\s*(==|!=|===|!==)\s*['"]`), 3, "owasp:nosql:008", ""},
	// MongoDB $function operator injection
	{regexp.MustCompile(`\$function\b\s*:\s*\{`), 5, "owasp:nosql:009", ""},
	// MongoDB $accumulator operator injection
	{regexp.MustCompile(`\$accumulator\b\s*:\s*\{`), 4, "owasp:nosql:010", ""},
	// CouchDB _all_docs / _find / _view injection
	{regexp.MustCompile(`(/_all_docs|/_find|/_view/)\b`), 4, "owasp:nosql:011", ""},
	// Redis protocol injection: EVAL / EVALSHA commands
	{regexp.MustCompile(`\b(eval|evalsha)\s+['"]`), 4, "owasp:nosql:012", ""},
	// Cassandra CQL injection: ALLOW FILTERING
	{regexp.MustCompile(`\ballow\s+filtering\b`), 3, "owasp:nosql:013", "filtering"},
	{regexp.MustCompile(`["']?\$\w+["']?\s*:\s*\{\s*["']?\$(?:ne|gt|lt|gte|lte|regex|in|nin|exists)\b`), 5, "owasp:nosql:014", ""},
	{regexp.MustCompile(`(?:^|[?&\s])\w+\[(?:\$ne|\$gt|\$lt|\$regex|\$exists)\]\s*=`), 5, "owasp:nosql:015", ""},
	{regexp.MustCompile(`["']?\$match["']?\s*:\s*\{`), 4, "owasp:nosql:016", ""},
	{regexp.MustCompile(`\$where\s*:\s*['"][^'"]{0,120}(?:sleep|function|return|this\.)`), 5, "owasp:nosql:017", ""},
}

func hasNoSQLiIndicator(s string) bool {
	return strings.Contains(s, "$where") ||
		strings.Contains(s, "$ne") ||
		strings.Contains(s, "$gt") ||
		strings.Contains(s, "$lt") ||
		strings.Contains(s, "$gte") ||
		strings.Contains(s, "$lte") ||
		strings.Contains(s, "$regex") ||
		strings.Contains(s, "$or") ||
		strings.Contains(s, "$and") ||
		strings.Contains(s, "$exists") ||
		strings.Contains(s, "$lookup") ||
		strings.Contains(s, "$function") ||
		strings.Contains(s, "$accumulator") ||
		strings.Contains(s, "$match") ||
		strings.Contains(s, "/_all_docs") ||
		strings.Contains(s, "/_find") ||
		strings.Contains(s, "/_view/") ||
		strings.Contains(s, "allow filtering") ||
		strings.Contains(s, "evalsha") ||
		strings.Contains(s, "eval ") ||
		strings.Contains(s, "this.")
}

func checkNoSQLi(s string, threshold int) (OWASPHit, bool) {
	if !hasNoSQLiIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range nosqliPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
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

var tmplInjectPatterns = []owaspPattern{
	// Jinja2 / Django / Twig
	{regexp.MustCompile(`\{\{\s*\d+\s*[\*\+\-/]\s*['"]?\d+['"]?\s*\}\}`), 5, "owasp:ssti:001", ""},
	{regexp.MustCompile(`\{\{\s*config\.`), 5, "owasp:ssti:002", "config."},
	{regexp.MustCompile(`\{\{\s*['"]\w*['"]\.__class__`), 6, "owasp:ssti:003", "__class__"},
	// ${...} Freemarker / Velocity / JSP EL
	{regexp.MustCompile(`\$\{\s*\d+\s*[\*\+\-/]\s*\d+\s*\}`), 5, "owasp:ssti:004", ""},
	{regexp.MustCompile(`\$\{.*?getclass\(\)`), 6, "owasp:ssti:005", "getclass()"},
	// <%= ... %> ERB / JSP
	{regexp.MustCompile(`<%=.*?%>`), 3, "owasp:ssti:006", ""},
	// Smarty {php}...{/php} template execution
	{regexp.MustCompile(`\{/?php\}`), 5, "owasp:ssti:007", "{php}"},
	// Python dunder attribute traversal (__subclasses__, __builtins__, __import__)
	{regexp.MustCompile(`__(subclasses|builtins|globals|import|init|reduce)__`), 5, "owasp:ssti:008", "__"},
	// Pebble template engine: beans / getClass access
	{regexp.MustCompile(`\{\{.*\.(getclass|forname|getmethod|invoke)\(`), 5, "owasp:ssti:009", ""},
	// JavaScript prototype pollution via JSON key injection
	{regexp.MustCompile(`["'\[\{]__proto__["'\]\}]`), 5, "owasp:ssti:010", "__proto__"},
	// Constructor prototype pollution: {"constructor":{"prototype":...}}
	{regexp.MustCompile(`["']constructor["']\s*:\s*\{`), 5, "owasp:ssti:011", "constructor"},
	// EJS template RCE: <%- process.env / require(...)  %>
	{regexp.MustCompile(`<%[-=]?\s*(process\s*\.\s*env|require\s*\(|global\s*\[)`), 5, "owasp:ssti:012", ""},
	// Handlebars/Mustache: {{lookup this ...}} or {{#with (...)}}
	// Score reduced to 2: these helpers appear in legitimate Handlebars templates.
	{regexp.MustCompile(`\{\{\s*(lookup|with|each|log)\s+`), 2, "owasp:ssti:013", ""},
	// Tornado / Mako: ${self.module / caller.body}
	{regexp.MustCompile(`\$\{self\.(module|template|loader|init_code)\b`), 5, "owasp:ssti:014", "."},
	// ThinkPHP template injection: {pbohome/Indexot:if(...)} or {pboot:if(...)}
	{regexp.MustCompile(`\{[a-z]+[:/][a-z]+:[a-z]+\(`), 5, "owasp:ssti:015", ""},
	// Generic template tag with function call: {tag:function(...)}
	{regexp.MustCompile(`\{[a-z_]+:[a-z_]+\([^}]{0,200}\)\}`), 4, "owasp:ssti:016", ""},
	// DedeCMS template injection: {dede:field name='source' runphp='yes'}
	{regexp.MustCompile(`\{dede:\w+\s+[^}]*runphp`), 5, "owasp:ssti:017", "{dede:"},
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
		// constructor only in template context ({{...constructor...}})
		(strings.Contains(s, "constructor") && (strings.Contains(s, "{{") || strings.Contains(s, "${") || strings.Contains(s, "<%"))) ||
		strings.Contains(s, "getclass(") ||
		strings.Contains(s, "java.lang.") ||
		strings.Contains(s, "process.env") ||
		strings.Contains(s, "{php}") ||
		strings.Contains(s, "$self.") ||
		strings.Contains(s, "{dede:")
}

func checkTemplateInjection(s string, threshold int) (OWASPHit, bool) {
	if !hasTemplateInjectionIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range tmplInjectPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
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
	".pht":      true,
	".phar":     true,
	".shtml":    true,
	".shtm":     true,
	".stm":      true,
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

	// Path traversal in filename (e.g. ../../tmp/shell.php)
	if strings.Contains(lower, "../") || strings.Contains(lower, "..\\") {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:006", Score: 6,
			Desc: "path traversal in filename"}, true
	}

	// Normalize spaces in filename for extension checks.
	// Evasion: "shell.php .jpg" uses space to defeat filepath.Ext double-extension detection.
	// Apache on Windows strips trailing spaces, so "shell.php .jpg" serves as PHP.
	normalized := strings.ReplaceAll(lower, " ", "")

	// Double extension e.g. shell.php.jpg or shell.php .jpg
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

	// Also check the original extension without space normalization
	origExt := filepath.Ext(lower)
	if origExt != ext && dangerousExtensions[origExt] {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:003", Score: 5,
			Desc: "dangerous file extension: " + origExt}, true
	}

	// .htaccess override attempt
	if strings.HasSuffix(lower, ".htaccess") || lower == ".htaccess" {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:004", Score: 5,
			Desc: "htaccess override attempt"}, true
	}

	// Content-Type mismatch with image extension
	if (origExt == ".jpg" || origExt == ".jpeg" || origExt == ".png" || origExt == ".gif") &&
		contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "image/") {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:005", Score: 3,
			Desc: "content-type mismatch for image"}, true
	}

	// Content-Type mismatch: executable extension with image content-type (bypass attempt).
	// An attacker may upload shell.php with Content-Type: image/jpeg to evade server-side checks.
	if contentType != "" && strings.HasPrefix(strings.ToLower(contentType), "image/") {
		execExts := map[string]bool{
			".php": true, ".php3": true, ".php4": true, ".php5": true, ".phtml": true, ".pht": true,
			".jsp": true, ".jspx": true, ".asp": true, ".aspx": true, ".cfm": true,
			".shtml": true, ".shtm": true, ".stm": true,
		}
		if execExts[origExt] || execExts[ext] {
			return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:007", Score: 5,
				Desc: "executable extension with image content-type"}, true
		}
	}

	return OWASPHit{}, false
}

// ── JNDI / Log4Shell Injection ──

// hasJNDIIndicator returns true when the string contains JNDI/Log4Shell-style
// injection markers.
func hasJNDIIndicator(s string) bool {
	return strings.Contains(s, "jndi:") ||
		strings.Contains(s, "${lower") ||
		strings.Contains(s, "${upper") ||
		strings.Contains(s, "${env:") ||
		strings.Contains(s, "${sys:") ||
		strings.Contains(s, "${java:") ||
		strings.Contains(s, "${base64:") ||
		strings.Contains(s, "\\u0024\\u007") // Unicode-escaped ${
}

var jndiPatterns = []owaspPattern{
	{regexp.MustCompile(`\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)s?://`), 6, "owasp:jndi:001", "jndi:"},
	{regexp.MustCompile(`\$\{(lower|upper|env|sys|java|base64):.*\}`), 4, "owasp:jndi:002", ""},
	{regexp.MustCompile(`\$\{.*\$\{.*\}\}`), 3, "owasp:jndi:003", ""},
	{regexp.MustCompile(`\$\{(env|sys):.*\}`), 4, "owasp:jndi:004", ""},
	// Split-character / obfuscated JNDI: ${j${::-n}d${::-i}:...}
	{regexp.MustCompile(`\$\{[^}]*j[^}]*\$\{[^}]*\}[^}]*n[^}]*d[^}]*i\s*:`), 5, "owasp:jndi:005", "jndi"},
	// URL-encoded JNDI: %24%7Bjndi:
	{regexp.MustCompile(`%24%7[bB]jndi\s*%3[aA]`), 5, "owasp:jndi:006", "%24%7"},
	// Unicode-escaped JNDI: \u0024\u007bjndi:
	{regexp.MustCompile(`\\u0024\\u007[bB]jndi`), 5, "owasp:jndi:007", "\u0024"},
}

func checkJNDI(s string, threshold int) (OWASPHit, bool) {
	if !hasJNDIIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range jndiPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
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

var crlfPatterns = []owaspPattern{
	{regexp.MustCompile(`\r\n\s*(set-cookie|location|content-type|x-[\w-]+)\s*:`), 6, "owasp:crlf:001", ""},
	{regexp.MustCompile(`%0d%0a\s*(set-cookie|location|content-type)\s*:`), 6, "owasp:crlf:002", "%0d%0a"},
	{regexp.MustCompile(`%0d%0a%0d%0a`), 5, "owasp:crlf:003", "%0d%0a%0d%0a"},
	{regexp.MustCompile(`\r\n\r\n`), 4, "owasp:crlf:004", ""},
}

func hasCRLFIndicator(s string) bool {
	return strings.Contains(s, "%0d") ||
		strings.Contains(s, "%0a") ||
		strings.Contains(s, "\r") ||
		strings.Contains(s, "\n") ||
		strings.Contains(s, "set-cookie:") ||
		strings.Contains(s, "location:") ||
		strings.Contains(s, "content-type:")
}

func hasDeserializationIndicator(s string) bool {
	return strings.Contains(s, "\xac\xed\x00\x05") ||
		strings.Contains(s, "aced0005") ||
		strings.Contains(s, "ro0ab") ||
		hasPHPSerializedObjectIndicator(s) ||
		hasPHPSerializedStringPairIndicator(s) ||
		strings.Contains(s, "ysoserial") ||
		strings.Contains(s, "aaeaaad//") ||
		strings.Contains(s, "nd_func") ||
		strings.Contains(s, "objectinputstream") ||
		strings.Contains(s, "xstream") ||
		strings.Contains(s, "<sorted-set") ||
		strings.Contains(s, "<tree-map") ||
		strings.Contains(s, "<dynamic-proxy") ||
		strings.Contains(s, "java.util") ||
		strings.Contains(s, "javax.") ||
		strings.Contains(s, "jdk.") ||
		strings.Contains(s, "com.sun.org.apache.xalan") ||
		strings.Contains(s, "org.apache.commons.collections") ||
		strings.Contains(s, "readobject") ||
		strings.Contains(s, "deserializ")
}

func hasPHPSerializedObjectIndicator(s string) bool {
	for i := 0; i+3 < len(s); i++ {
		if s[i] != 'o' || s[i+1] != ':' {
			continue
		}
		j := i + 2
		if j >= len(s) || !isASCIIDigitByte(s[j]) {
			continue
		}
		for j < len(s) && isASCIIDigitByte(s[j]) {
			j++
		}
		if j+1 < len(s) && s[j] == ':' && s[j+1] == '"' {
			return true
		}
	}
	return false
}

func hasPHPSerializedStringPairIndicator(s string) bool {
	for i := 0; i+5 < len(s); i++ {
		if s[i] != 's' || s[i+1] != ':' {
			continue
		}
		j := i + 2
		if j >= len(s) || !isASCIIDigitByte(s[j]) {
			continue
		}
		for j < len(s) && isASCIIDigitByte(s[j]) {
			j++
		}
		if j+1 >= len(s) || s[j] != ':' || s[j+1] != '"' {
			continue
		}
		contentStart := j + 2
		for endQuote := contentStart; endQuote < len(s); endQuote++ {
			if s[endQuote] != '"' {
				continue
			}
			next := endQuote + 1
			if next+3 >= len(s) || s[next] != ';' || s[next+1] != 's' || s[next+2] != ':' {
				break
			}
			k := next + 3
			if k >= len(s) || !isASCIIDigitByte(s[k]) {
				break
			}
			for k < len(s) && isASCIIDigitByte(s[k]) {
				k++
			}
			if k < len(s) && s[k] == ':' {
				return true
			}
			break
		}
	}
	return false
}

func checkCRLF(s string, threshold int) (OWASPHit, bool) {
	if !hasCRLFIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range crlfPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
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

// hasELIndicator returns true when the string contains expression language
// injection markers (Spring EL, OGNL, SpEL) specific enough to justify
// running the full EL regex battery.
func hasELIndicator(s string) bool {
	return strings.Contains(s, "#{t(") ||
		strings.Contains(s, "${t(") ||
		strings.Contains(s, "${") ||
		strings.Contains(s, "java.lang.") ||
		strings.Contains(s, "getclass()") ||
		strings.Contains(s, "getruntime") ||
		strings.Contains(s, "getdeclaredmethods") ||
		strings.Contains(s, "#rt") ||
		strings.Contains(s, "@java.") ||
		strings.Contains(s, "#context") ||
		strings.Contains(s, "%{#") ||
		strings.Contains(s, "new java.") ||
		strings.Contains(s, "newjava.")
}

var exprLangPatterns = []owaspPattern{
	// Spring Expression Language
	{regexp.MustCompile(`#\{t\(java\.lang\.`), 6, "owasp:el:001", "java.lang."},
	{regexp.MustCompile(`\$\{t\(java\.lang\.`), 6, "owasp:el:002", "java.lang."},
	// OGNL
	{regexp.MustCompile(`%\{.*getclass\(\)`), 5, "owasp:el:003", "getclass()"},
	{regexp.MustCompile(`\(#rt\s*=\s*@java\.lang\.runtime\)`), 6, "owasp:el:004", "@java.lang.runtime"},
	// Generic class/runtime access
	{regexp.MustCompile(`java\.lang\.(runtime|processbuilder|class|system)`), 4, "owasp:el:005", "java.lang."},
	{regexp.MustCompile(`getruntime\(\)\s*\.\s*exec\s*\(`), 5, "owasp:el:006", "getruntime()"},
	// Struts2 OGNL: %{#context['com.opensymphony...
	{regexp.MustCompile(`%\{#context\[`), 5, "owasp:el:007", "%{#context"},
	// OGNL redirect/action: redirect:${...} or action:${...}
	{regexp.MustCompile(`(redirect|action)\s*:\s*\$\{`), 5, "owasp:el:008", ""},
	// OGNL static method call: @class@method
	{regexp.MustCompile(`@java\.\w+\.\w+@\w+`), 5, "owasp:el:009", "@java."},
	// java.net.URL / new java construct
	{regexp.MustCompile(`\bnew\s*java\.\w+\.`), 4, "owasp:el:010", "java."},
	// OGNL #context.get / #req=#context
	{regexp.MustCompile(`#(req|request|response|session|application|context)\s*[=.]`), 5, "owasp:el:011", ""},
	// OGNL reflection chain: getDeclaredMethods + invoke
	{regexp.MustCompile(`getdeclaredmethods\b.*\.invoke\s*\(`), 5, "owasp:el:012", "getdeclaredmethods"},
	// OGNL reflection chain: getClass().forName() or Class.forName()
	{regexp.MustCompile(`(getclass\(\)|class)\s*\.\s*forname\s*\(`), 4, "owasp:el:013", "forname"},
}

func checkExprLang(s string, threshold int) (OWASPHit, bool) {
	if !hasELIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range exprLangPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
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

var deserialPatterns = []owaspPattern{
	// Java serialization magic bytes
	{regexp.MustCompile(`\xac\xed\x00\x05`), 6, "owasp:deser:001", ""},
	// Java serialization hex-encoded: aced0005 (common in URL params)
	{regexp.MustCompile(`aced0005`), 6, "owasp:deser:008", "aced0005"},
	// PHP serialization
	{regexp.MustCompile(`o:\d+:"[^"]+"`), 4, "owasp:deser:002", "o:"},
	// PHP serialization in URL params: s:11:"key";s:16:"value"
	{regexp.MustCompile(`s:\d+:"[^"]*";s:\d+:`), 4, "owasp:deser:009", ""},
	// Python pickle
	{regexp.MustCompile(`c(os|posix|nt)\n(system|popen)`), 5, "owasp:deser:003", ""},
	// .NET ViewState
	{regexp.MustCompile(`__viewstate.*ysoserial`), 5, "owasp:deser:004", ""},
	// Ruby Marshal — require version bytes + type indicator to avoid matching random binary
	{regexp.MustCompile(`\x04\x08[\x30\x49\x5b\x6f\x7b]`), 3, "owasp:deser:005", ""},
	// .NET BinaryFormatter / LosFormatter magic
	{regexp.MustCompile(`aaeaaad//`), 5, "owasp:deser:006", "aaeaaad//"},
	// Node.js serialize-javascript RCE pattern
	{regexp.MustCompile(`\{"rce":\s*"_\$\$nd_func\$\$_`), 5, "owasp:deser:007", "nd_func"},
	// Java serialization base64 magic: rO0AB (base64 of \xac\xed\x00\x05)
	{regexp.MustCompile(`ro0ab`), 5, "owasp:deser:010", "ro0ab"},
	// .NET ViewState base64 marker
	{regexp.MustCompile(`javax\.faces\.viewstate\s*=\s*ro0ab`), 6, "owasp:deser:011", "ro0ab"},
	// Raw Java serialization magic bytes (URL-encoded or hex)
	{regexp.MustCompile(`(%ac%ed|aced0005)`), 5, "owasp:deser:012", ""},
	// XStream gadget chains
	{regexp.MustCompile(`<(sorted-set|tree-map|java\.util|dynamic-proxy|javax\.\w+\.|jdk\.\w+\.)`), 5, "owasp:deser:013", ""},
	// Java ObjectInputStream — used to deserialize untrusted data
	{regexp.MustCompile(`\bobjectinputstream\b`), 4, "owasp:deser:014", "objectinputstream"},
	// Apache Xalan gadget chain (CVE-2022-34169 and similar)
	{regexp.MustCompile(`com\.sun\.org\.apache\.xalan\b`), 5, "owasp:deser:015", "com.sun.org.apache.xalan"},
	// Apache Commons Collections gadget chain (widely exploited)
	{regexp.MustCompile(`org\.apache\.commons\.collections\b`), 5, "owasp:deser:016", "org.apache.commons.collections"},
	// java.util.HashMap in suspicious serialization context (gadget trigger class)
	{regexp.MustCompile(`java\.util\.hashmap\b.{0,100}(aced|ro0ab|serial|objectinput|readobject|deserializ)`), 5, "owasp:deser:017", ""},
}

func checkDeserialization(s string, threshold int) (OWASPHit, bool) {
	// Direct binary Java serialization magic byte check
	if strings.Contains(s, "\xac\xed\x00\x05") {
		return OWASPHit{Category: CatDeserial, RuleID: "owasp:deser:001", Score: 5, Desc: "Java serialization magic bytes"}, true
	}
	if !hasDeserializationIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range deserialPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
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

// checkMethodViolation flags unusual HTTP methods that are commonly abused.
// CORS preflight OPTIONS requests (with Origin and Access-Control-Request-Method)
// are excluded as legitimate.
func checkMethodViolation(method string, headers map[string]string) (OWASPHit, bool) {
	switch strings.ToUpper(method) {
	case "TRACE", "TRACK":
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:004", Score: 5,
			Desc: "dangerous HTTP method: " + method}, true
	case "CONNECT":
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:005", Score: 5,
			Desc: "CONNECT method (tunneling)"}, true
	case "DEBUG":
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:006", Score: 5,
			Desc: "DEBUG method (ASP.NET diagnostics)"}, true
	case "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK":
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:007", Score: 4,
			Desc: "WebDAV method: " + method}, true
	case "PATCH":
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:008", Score: 3,
			Desc: "PATCH method (uncommon)"}, true
	case "OPTIONS":
		// Allow CORS preflight requests (have Origin + Access-Control-Request-Method).
		origin := ""
		acrm := ""
		for k, v := range headers {
			lk := strings.ToLower(k)
			if lk == "origin" {
				origin = v
			}
			if lk == "access-control-request-method" {
				acrm = v
			}
		}
		if origin != "" && acrm != "" {
			// Legitimate CORS preflight — not suspicious.
			return OWASPHit{}, false
		}
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:009", Score: 3,
			Desc: "OPTIONS method (non-CORS)"}, true
	}
	return OWASPHit{}, false
}

// ── GraphQL Injection ──

// hasGraphQLIndicator returns true when the string contains GraphQL
// introspection or injection markers.
func hasGraphQLIndicator(s string) bool {
	return strings.Contains(s, "__schema") ||
		strings.Contains(s, "__type") ||
		strings.Contains(s, "introspectionquery")
}

var graphqlPatterns = []owaspPattern{
	// GraphQL introspection query with query keyword context
	{regexp.MustCompile(`\bquery\b[^}]{0,200}__schema\b`), 6, "owasp:graphql:001", "__schema"},
	{regexp.MustCompile(`\bquery\b[^}]{0,200}__type\b`), 5, "owasp:graphql:002", "__type"},
	{regexp.MustCompile(`\bintrospectionquery\b`), 5, "owasp:graphql:003", "introspectionquery"},
	// Direct __schema access in a GraphQL body (e.g., {"query":"{ __schema { ... } }"})
	{regexp.MustCompile(`\{\s*__schema\b`), 5, "owasp:graphql:004", "__schema"},
	{regexp.MustCompile(`\{\s*__type\b`), 5, "owasp:graphql:005", "__type"},
	// GraphQL batching attack: array of operations
	{regexp.MustCompile(`\[\s*\{\s*"query"\s*:`), 4, "owasp:graphql:006", ""},
	// GraphQL directive abuse: @skip/@include with variable injection
	{regexp.MustCompile(`@(skip|include)\s*\(\s*if\s*:\s*\$`), 3, "owasp:graphql:007", ""},
	// GraphQL subscription abuse
	{regexp.MustCompile(`\bsubscription\b\s*\{`), 3, "owasp:graphql:008", "subscription"},
	// GraphQL field suggestion / enumeration probing
	{regexp.MustCompile(`"(did you mean|cannot query field|unknown field)"?`), 3, "owasp:graphql:009", ""},
}

func checkGraphQLi(s string, threshold int) (OWASPHit, bool) {
	if !hasGraphQLIndicator(s) {
		return OWASPHit{}, false
	}
	total := 0
	best := ""
	for _, p := range graphqlPatterns {
		if p.hint != "" && !strings.Contains(s, p.hint) {
			continue
		}
		if p.re.MatchString(s) {
			total += p.score
			if best == "" {
				best = p.id
			}
			if total >= threshold {
				return OWASPHit{Category: CatGraphQLi, RuleID: best, Score: total, Desc: "GraphQL introspection/injection signals"}, true
			}
		}
	}
	return OWASPHit{}, false
}
