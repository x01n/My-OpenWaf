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
	regexp.MustCompile(`(?i)googlebot|google-inspectiontool|storebot-google`),
	regexp.MustCompile(`(?i)bingbot|msnbot|bingpreview`),
	regexp.MustCompile(`(?i)yandexbot|yandex\.com/bots`),
	regexp.MustCompile(`(?i)duckduckbot|duckduckgo-favicons-bot`),
	regexp.MustCompile(`(?i)baiduspider`),
	regexp.MustCompile(`(?i)applebot|applebot-extended`),
	regexp.MustCompile(`(?i)facebookexternalhit|facebookcatalog`),
	regexp.MustCompile(`(?i)twitterbot|tweetmemebot`),
	regexp.MustCompile(`(?i)linkedinbot|linkedin`),
	regexp.MustCompile(`(?i)slackbot|slack-imgproxy`),
	regexp.MustCompile(`(?i)discordbot|discord`),
	regexp.MustCompile(`(?i)telegrambot`),
	regexp.MustCompile(`(?i)whatsapp`),
	regexp.MustCompile(`(?i)pinterestbot`),
	regexp.MustCompile(`(?i)redditbot`),
	regexp.MustCompile(`(?i)amazonbot`),
	regexp.MustCompile(`(?i)semrushbot|ahrefs|mj12bot|dotbot`),
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
	{regexp.MustCompile(`(?i)dirbuster|gobuster|wfuzz|ffuf|feroxbuster`), "dir_bruteforcer", "bot:mal:005"},
	{regexp.MustCompile(`(?i)nessus|openvas|qualys`), "vuln_scanner", "bot:mal:006"},
	{regexp.MustCompile(`(?i)havij|pangolin`), "sqli_tool", "bot:mal:007"},
	{regexp.MustCompile(`(?i)metasploit\b|\bmsf\b`), "metasploit", "bot:mal:008"},
	{regexp.MustCompile(`(?i)hydra|medusa|patator|thc-hydra`), "password_cracker", "bot:mal:009"},
	{regexp.MustCompile(`(?i)nuclei`), "nuclei", "bot:mal:010"},
	{regexp.MustCompile(`(?i)zgrab`), "zgrab", "bot:mal:011"},
	{regexp.MustCompile(`(?i)xspider|crawler4j`), "malicious_crawler", "bot:mal:012"},
	{regexp.MustCompile(`(?i)commix|xsser|beef`), "exploit_tool", "bot:mal:013"},
	{regexp.MustCompile(`(?i)w3af|skipfish|arachni`), "web_app_scanner", "bot:mal:014"},
	{regexp.MustCompile(`(?i)joomscan|wpscan|droopescan`), "cms_scanner", "bot:mal:015"},
	{regexp.MustCompile(`(?i)shodan|censys|zoomeye`), "recon_bot", "bot:mal:016"},
	{regexp.MustCompile(`(?i)scrapy|beautifulsoup|selenium`), "scraper_lib", "bot:mal:017"},
	{regexp.MustCompile(`(?i)python-requests|python-urllib|go-http-client`), "http_lib", "bot:mal:018"},
	{regexp.MustCompile(`(?i)curl|wget|libwww-perl|lwp-`), "cli_tool", "bot:mal:019"},
	{regexp.MustCompile(`(?i)postman|insomnia|httpie`), "api_client", "bot:mal:020"},
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
	uaLower := strings.ToLower(ua)
	if strings.Contains(uaLower, "python-requests") ||
		strings.Contains(uaLower, "python-urllib") ||
		strings.Contains(uaLower, "go-http-client") ||
		strings.HasPrefix(uaLower, "java/") ||
		strings.HasPrefix(uaLower, "curl/") ||
		strings.HasPrefix(uaLower, "wget/") ||
		strings.Contains(uaLower, "libwww-perl") ||
		strings.Contains(uaLower, "okhttp") ||
		strings.Contains(uaLower, "apache-httpclient") ||
		strings.Contains(uaLower, "node-fetch") ||
		strings.Contains(uaLower, "axios/") {
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

	// Additional fingerprint checks

	// Suspicious path patterns (common scanner paths)
	if strings.Contains(r.Path, "/.env") ||
		strings.Contains(r.Path, "/phpMyAdmin") ||
		strings.Contains(r.Path, "/wp-admin") ||
		strings.Contains(r.Path, "/.git") ||
		strings.Contains(r.Path, "/admin") && r.Method == "GET" && !r.HasCookie {
		score += 10
		reasons = append(reasons, "scanner_path")
	}

	// Referer anomalies
	if r.Method == "POST" && r.Referer == "" {
		score += 8
		reasons = append(reasons, "post_no_referer")
	}

	// User-Agent version mismatch patterns
	if strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "safari") {
		score += 15
		reasons = append(reasons, "chrome_without_safari")
	}

	return score, reasons
}

// CheckBot evaluates the full bot signal (UA signature + fingerprint score).
// The level parameter controls detection sensitivity: "low", "medium", "high".
func CheckBot(r BotRequest) BotVerdict {
	return CheckBotWithLevel(r, "medium")
}

// CheckBotWithLevel evaluates bot signals with configurable protection level.
func CheckBotWithLevel(r BotRequest, level string) BotVerdict {
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

	// Cumulative fingerprint scoring with level-based thresholds.
	score, reasons := fingerprintScore(r)

	// Adjust thresholds based on protection level
	var maliciousThreshold, suspiciousHighThreshold, suspiciousLowThreshold int
	switch level {
	case "low":
		maliciousThreshold = 90
		suspiciousHighThreshold = 70
		suspiciousLowThreshold = 40
	case "high":
		maliciousThreshold = 60
		suspiciousHighThreshold = 35
		suspiciousLowThreshold = 15
	default: // "medium"
		maliciousThreshold = 80
		suspiciousHighThreshold = 50
		suspiciousLowThreshold = 25
	}

	if score >= maliciousThreshold {
		return BotVerdict{
			IsBot:    true,
			Score:    score,
			Category: "malicious",
			Reason:   "fingerprint: " + strings.Join(reasons, ","),
			RuleID:   "bot:fp:001",
		}
	}
	if score >= suspiciousHighThreshold {
		return BotVerdict{
			IsBot:    true,
			Score:    score,
			Category: "suspicious",
			Reason:   "fingerprint: " + strings.Join(reasons, ","),
			RuleID:   "bot:fp:002",
		}
	}
	if score >= suspiciousLowThreshold {
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
