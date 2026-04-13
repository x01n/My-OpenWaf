package waf

import (
	"regexp"
	"strings"
)

// BotVerdict represents the bot detection result.
// Score is 0-100; higher means more likely a bot/attacker.
type BotVerdict struct {
	IsBot    bool
	Score    int
	Category string // "human", "good", "suspicious", "malicious"
	Reason   string
	RuleID   string
}

// BotRequest is the minimal request surface needed for fingerprint scoring.
type BotRequest struct {
	UserAgent      string
	Method         string
	Path           string
	Headers        map[string]string
	AcceptHeader   string
	AcceptLanguage string
	AcceptEncoding string
	Referer        string
	Connection     string
	HasCookie      bool
}

// NewBotRequest builds a BotRequest from a header map for quick pipeline use.
func NewBotRequest(method, path string, headers map[string]string) BotRequest {
	br := BotRequest{Method: method, Path: path, Headers: headers}
	for k, v := range headers {
		lk := strings.ToLower(k)
		switch lk {
		case "user-agent":
			br.UserAgent = v
		case "accept":
			br.AcceptHeader = v
		case "accept-language":
			br.AcceptLanguage = v
		case "accept-encoding":
			br.AcceptEncoding = v
		case "referer":
			br.Referer = v
		case "connection":
			br.Connection = v
		case "cookie":
			br.HasCookie = v != ""
		}
	}
	return br
}

// ── verified legitimate crawlers ──

var goodBotUA = []*regexp.Regexp{
	regexp.MustCompile(`(?i)googlebot|google-inspectiontool`),
	regexp.MustCompile(`(?i)bingbot|msnbot`),
	regexp.MustCompile(`(?i)yandexbot`),
	regexp.MustCompile(`(?i)duckduckbot`),
	regexp.MustCompile(`(?i)baiduspider`),
	regexp.MustCompile(`(?i)applebot`),
	regexp.MustCompile(`(?i)facebookexternalhit`),
	regexp.MustCompile(`(?i)twitterbot`),
	regexp.MustCompile(`(?i)linkedinbot`),
	regexp.MustCompile(`(?i)slackbot`),
}

// ── hacking tools / malicious UA ──

var maliciousToolUA = []struct {
	re     *regexp.Regexp
	name   string
	ruleID string
}{
	{regexp.MustCompile(`(?i)sqlmap`), "sqlmap", "bot:mal:001"},
	{regexp.MustCompile(`(?i)nikto`), "nikto", "bot:mal:002"},
	{regexp.MustCompile(`(?i)nmap|masscan|zmap`), "port_scanner", "bot:mal:003"},
	{regexp.MustCompile(`(?i)acunetix|netsparker|burpsuite|burp suite`), "web_scanner", "bot:mal:004"},
	{regexp.MustCompile(`(?i)dirbuster|gobuster|wfuzz|ffuf`), "dir_bruteforcer", "bot:mal:005"},
	{regexp.MustCompile(`(?i)nessus|openvas|qualys`), "vuln_scanner", "bot:mal:006"},
	{regexp.MustCompile(`(?i)havij|pangolin`), "sqli_tool", "bot:mal:007"},
	{regexp.MustCompile(`(?i)metasploit\b|\bmsf\b`), "metasploit", "bot:mal:008"},
	{regexp.MustCompile(`(?i)hydra|medusa|patator`), "password_cracker", "bot:mal:009"},
	{regexp.MustCompile(`(?i)nuclei`), "nuclei", "bot:mal:010"},
	{regexp.MustCompile(`(?i)zgrab`), "zgrab", "bot:mal:011"},
	{regexp.MustCompile(`(?i)xspider|crawler4j`), "malicious_crawler", "bot:mal:012"},
}

// ── fingerprint signals ──
//
// Modern browsers send a predictable set of headers (Accept, Accept-Language,
// Accept-Encoding, User-Agent) in characteristic combinations. Automated tools
// skip or malform some of these. We score the divergence from a "browser-like"
// baseline rather than relying solely on the UA string.

func fingerprintScore(r BotRequest) (score int, reasons []string) {
	ua := strings.TrimSpace(r.UserAgent)

	// Missing / empty User-Agent.
	if ua == "" {
		score += 40
		reasons = append(reasons, "empty_ua")
	} else if len(ua) < 12 {
		score += 25
		reasons = append(reasons, "short_ua")
	}

	// Missing Accept header — almost all real browsers send one.
	if r.AcceptHeader == "" {
		score += 20
		reasons = append(reasons, "no_accept")
	} else if !strings.Contains(r.AcceptHeader, "text/html") && !strings.Contains(r.AcceptHeader, "*/*") {
		score += 5
		reasons = append(reasons, "unusual_accept")
	}

	// Missing Accept-Language — browsers always send it for non-XHR navigations.
	if r.AcceptLanguage == "" {
		score += 15
		reasons = append(reasons, "no_accept_language")
	}

	// Missing Accept-Encoding.
	if r.AcceptEncoding == "" {
		score += 10
		reasons = append(reasons, "no_accept_encoding")
	}

	// SDK / library user agents that claim to be a browser but lack browser headers.
	if strings.Contains(strings.ToLower(ua), "python-requests") ||
		strings.Contains(strings.ToLower(ua), "python-urllib") ||
		strings.Contains(strings.ToLower(ua), "go-http-client") ||
		strings.HasPrefix(strings.ToLower(ua), "java/") ||
		strings.HasPrefix(strings.ToLower(ua), "curl/") ||
		strings.HasPrefix(strings.ToLower(ua), "wget/") ||
		strings.Contains(strings.ToLower(ua), "libwww-perl") ||
		strings.Contains(strings.ToLower(ua), "okhttp") {
		score += 50
		reasons = append(reasons, "automation_lib_ua")
	}

	// "Mozilla/5.0" claim without the expected trailing browser tokens.
	if strings.HasPrefix(ua, "Mozilla/") && !strings.Contains(ua, "(") {
		score += 30
		reasons = append(reasons, "fake_mozilla")
	}

	// Connection header is almost always "keep-alive" in browsers; "close" is
	// a mild signal unless it's a legitimate old HTTP/1.0 client.
	if strings.EqualFold(r.Connection, "close") {
		score += 5
		reasons = append(reasons, "conn_close")
	}

	// Presence of Cookie usually indicates a real session. Lack of it on a POST
	// to an authenticated-looking path is a small signal.
	if !r.HasCookie && (r.Method == "POST" || r.Method == "PUT") {
		score += 5
		reasons = append(reasons, "no_cookie_post")
	}

	return score, reasons
}

// CheckBot evaluates the full bot signal (UA signature + fingerprint score).
func CheckBot(r BotRequest) BotVerdict {
	ua := strings.TrimSpace(r.UserAgent)

	// Known good bots short-circuit.
	for _, re := range goodBotUA {
		if re.MatchString(ua) {
			return BotVerdict{
				IsBot:    true,
				Score:    0,
				Category: "good",
				Reason:   "verified legitimate crawler",
			}
		}
	}

	// Known malicious tools → immediate block.
	for _, p := range maliciousToolUA {
		if p.re.MatchString(ua) {
			return BotVerdict{
				IsBot:    true,
				Score:    100,
				Category: "malicious",
				Reason:   "security tool: " + p.name,
				RuleID:   p.ruleID,
			}
		}
	}

	// Cumulative fingerprint scoring.
	score, reasons := fingerprintScore(r)
	if score >= 80 {
		return BotVerdict{
			IsBot:    true,
			Score:    score,
			Category: "malicious",
			Reason:   "fingerprint: " + strings.Join(reasons, ","),
			RuleID:   "bot:fp:001",
		}
	}
	if score >= 50 {
		return BotVerdict{
			IsBot:    true,
			Score:    score,
			Category: "suspicious",
			Reason:   "fingerprint: " + strings.Join(reasons, ","),
			RuleID:   "bot:fp:002",
		}
	}
	if score >= 25 {
		return BotVerdict{
			IsBot:    true,
			Score:    score,
			Category: "suspicious",
			Reason:   "fingerprint: " + strings.Join(reasons, ","),
			RuleID:   "bot:fp:003",
		}
	}

	return BotVerdict{IsBot: false, Score: score, Category: "human"}
}

// CheckBotByUA is a legacy helper that wraps CheckBot with only a user-agent.
// Kept for API compatibility; new code should call CheckBot with a BotRequest.
func CheckBotByUA(userAgent string) BotVerdict {
	return CheckBot(BotRequest{UserAgent: userAgent})
}
