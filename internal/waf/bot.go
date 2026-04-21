package waf

import (
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ── Result types ──

// BotScore holds the itemised result of a full (deep) bot evaluation.
type BotScore struct {
	Total            int
	GeoIPScore       int
	FingerprintScore int
	BehaviorScore    int // reserved for future behavioral analysis
	IPRepScore       int
	IsHighRisk       bool
	Details          map[string]string // human-readable reason per category
}

// BotVerdict represents the bot detection result (kept for backward compat).
// Score is 0-100; higher means more likely a bot/attacker.
type BotVerdict struct {
	IsBot    bool
	Score    int
	Category string // "human", "good", "suspicious", "malicious"
	Reason   string
	RuleID   string
}

// ── Request surface ──

// BotRequest is the minimal request surface needed for fingerprint scoring.
type BotRequest struct {
	UserAgent      string
	Method         string
	Path           string
	Headers        map[string]string
	HeaderKeys     []string // Ordered list of header keys for TLS/HTTP2 fingerprint analysis
	AcceptHeader   string
	AcceptLanguage string
	AcceptEncoding string
	Referer        string
	Connection     string
	HasCookie      bool

	// Fields used by the two-phase flow (optional for legacy callers).
	ClientIP net.IP
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

// ── Known-bot / tool patterns ──

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

// ── Good Bot DNS Verification ──

// goodBotDNSCache caches DNS-verified good bot IPs for 1 hour.
// Key: IP string, Value: goodBotCacheEntry.
var goodBotDNSCache sync.Map

type goodBotCacheEntry struct {
	verified bool
	expiry   time.Time
}

// goodBotDNSPatterns maps goodBotUA index to allowed reverse DNS suffixes.
var goodBotDNSPatterns = map[int][]string{
	0: {".googlebot.com.", ".google.com."},           // Googlebot
	1: {".search.msn.com."},                          // Bingbot
	2: {".yandex.ru.", ".yandex.net.", ".yandex.com."}, // Yandexbot
	5: {".apple.com.", ".applebot.apple.com."},       // Applebot
}

// verifyGoodBotDNS checks if the client IP reverse-resolves to an allowed domain
// for the given bot pattern index. Results are cached for 1 hour.
func verifyGoodBotDNS(ip net.IP, patternIdx int) bool {
	suffixes, needsVerify := goodBotDNSPatterns[patternIdx]
	if !needsVerify {
		// No DNS verification configured for this bot — trust the UA.
		return true
	}
	ipStr := ip.String()
	cacheKey := ipStr + ":" + string(rune(patternIdx+'0'))

	// Check cache first.
	if v, ok := goodBotDNSCache.Load(cacheKey); ok {
		entry := v.(goodBotCacheEntry)
		if time.Now().Before(entry.expiry) {
			return entry.verified
		}
		// Expired — will re-verify below.
	}

	verified := false
	names, err := net.LookupAddr(ipStr)
	if err == nil {
		for _, name := range names {
			nameLower := strings.ToLower(name)
			for _, suffix := range suffixes {
				if strings.HasSuffix(nameLower, suffix) {
					// Forward-confirm: resolve the hostname back to an IP.
					addrs, err2 := net.LookupHost(name)
					if err2 == nil {
						for _, a := range addrs {
							if a == ipStr {
								verified = true
								break
							}
						}
					}
					if verified {
						break
					}
				}
			}
			if verified {
				break
			}
		}
	}

	goodBotDNSCache.Store(cacheKey, goodBotCacheEntry{
		verified: verified,
		expiry:   time.Now().Add(1 * time.Hour),
	})
	return verified
}

// ── Phase 1: Fast Pre-Screening ──

// PreScreen performs a cheap, nanosecond-level check to decide whether a
// request warrants the full deep-scoring pipeline. Returns true if the
// request should be considered high-risk and must enter Phase 2.
//
// Criteria checked (any hit → high-risk):
//   - IP in blacklist / auto-ban (via IPReputation)
//   - GeoIP IsHighRisk (datacenter/VPN ASN, high-risk country)
//   - UA matches a known malicious tool
func PreScreen(r BotRequest, ipRep *IPReputation, geo *MaxMindResolver) bool {
	// 1. Known-malicious UA → always high risk (very cheap regex).
	ua := strings.TrimSpace(r.UserAgent)
	for _, p := range maliciousToolUA {
		if p.re.MatchString(ua) {
			return true
		}
	}

	// 2. IP reputation: blacklisted or auto-banned.
	if ipRep != nil && r.ClientIP != nil {
		dec := ipRep.Check(r.ClientIP)
		if dec.Matched && !dec.Allowed {
			return true
		}
	}

	// 3. GeoIP fast check.
	if geo != nil && r.ClientIP != nil {
		if geo.IsHighRisk(r.ClientIP) {
			return true
		}
	}

	return false
}

// ── Phase 2: Deep Scoring ──

// DeepScore runs the full bot evaluation, combining GeoIP weighting,
// fingerprint analysis, and IP reputation. Only called for high-risk IPs.
func DeepScore(r BotRequest, ipRep *IPReputation, geo *MaxMindResolver) BotScore {
	bs := BotScore{
		IsHighRisk: true,
		Details:    make(map[string]string),
	}

	// ── GeoIP scoring ──
	if geo != nil && r.ClientIP != nil {
		bs.GeoIPScore = geo.ScoreIP(r.ClientIP)
		if bs.GeoIPScore > 0 {
			info := geo.Lookup(r.ClientIP)
			if info.ASN != 0 {
				bs.Details["geoip_asn"] = info.ASNOrg
			}
			if info.Country != "" {
				bs.Details["geoip_country"] = info.Country
			}
		}
	}

	// ── UA/header heuristic fingerprint scoring ──
	fpScore, fpReasons := fingerprintScore(r)

	// ── TLS/HTTP2 deep fingerprint scoring (JA3/JA4/H2/header order) ──
	tlsFpResult := DeepFingerprintScore(r)
	fpScore += tlsFpResult.Score
	if len(tlsFpResult.Reasons) > 0 {
		fpReasons = append(fpReasons, tlsFpResult.Reasons...)
	}
	if tlsFpResult.MatchedDB != "" {
		bs.Details["tls_fingerprint_match"] = tlsFpResult.MatchedDB
	}

	bs.FingerprintScore = fpScore
	if len(fpReasons) > 0 {
		bs.Details["fingerprint"] = strings.Join(fpReasons, ",")
	}

	// ── IP reputation scoring ──
	if ipRep != nil && r.ClientIP != nil {
		dec := ipRep.Check(r.ClientIP)
		if dec.Matched && !dec.Allowed {
			switch dec.Category {
			case "blacklist":
				bs.IPRepScore = 30
			case "auto_ban":
				bs.IPRepScore = 25
			default:
				bs.IPRepScore = 15
			}
			bs.Details["iprep"] = dec.Category + ": " + dec.Reason
		}
	}

	// ── Total ──
	bs.Total = bs.GeoIPScore + bs.FingerprintScore + bs.BehaviorScore + bs.IPRepScore
	return bs
}

// ── Fingerprint heuristics (unchanged logic) ──

func fingerprintScore(r BotRequest) (score int, reasons []string) {
	ua := strings.TrimSpace(r.UserAgent)
	if ua == "" {
		score += 40
		reasons = append(reasons, "empty_ua")
	} else if len(ua) < 12 {
		score += 25
		reasons = append(reasons, "short_ua")
	}
	if r.AcceptHeader == "" {
		score += 20
		reasons = append(reasons, "no_accept")
	} else if !strings.Contains(r.AcceptHeader, "text/html") && !strings.Contains(r.AcceptHeader, "*/*") {
		score += 5
		reasons = append(reasons, "unusual_accept")
	}
	if r.AcceptLanguage == "" {
		score += 15
		reasons = append(reasons, "no_accept_language")
	}
	if r.AcceptEncoding == "" {
		score += 10
		reasons = append(reasons, "no_accept_encoding")
	}
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
	if strings.HasPrefix(ua, "Mozilla/") && !strings.Contains(ua, "(") {
		score += 30
		reasons = append(reasons, "fake_mozilla")
	}
	if strings.EqualFold(r.Connection, "close") {
		score += 5
		reasons = append(reasons, "conn_close")
	}
	if !r.HasCookie && (r.Method == "POST" || r.Method == "PUT") {
		score += 5
		reasons = append(reasons, "no_cookie_post")
	}
	if strings.Contains(r.Path, "/.env") ||
		strings.Contains(r.Path, "/phpMyAdmin") ||
		strings.Contains(r.Path, "/wp-admin") ||
		strings.Contains(r.Path, "/.git") ||
		strings.Contains(r.Path, "/admin") && r.Method == "GET" && !r.HasCookie {
		score += 10
		reasons = append(reasons, "scanner_path")
	}
	if r.Method == "POST" && r.Referer == "" {
		score += 8
		reasons = append(reasons, "post_no_referer")
	}
	if strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "safari") {
		score += 15
		reasons = append(reasons, "chrome_without_safari")
	}

	return score, reasons
}

// ── Legacy API (backward-compatible) ──

// CheckBot runs the original single-pass bot detection (no GeoIP weighting).
func CheckBot(r BotRequest) BotVerdict {
	return CheckBotWithLevel(r, "medium")
}

// CheckBotWithLevel runs single-pass detection with a configurable sensitivity level.
func CheckBotWithLevel(r BotRequest, level string) BotVerdict {
	ua := strings.TrimSpace(r.UserAgent)
	for i, re := range goodBotUA {
		if re.MatchString(ua) {
			// DNS verification for bots that support it.
			if r.ClientIP != nil && !verifyGoodBotDNS(r.ClientIP, i) {
				// DNS verification failed — don't mark as good bot,
				// let it proceed through normal scoring.
				break
			}
			return BotVerdict{
				IsBot:    true,
				Score:    0,
				Category: "good",
				Reason:   "verified legitimate crawler",
			}
		}
	}
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
	score, reasons := fingerprintScore(r)
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
	default:
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

// CheckBotByUA is a convenience wrapper for UA-only checks.
func CheckBotByUA(userAgent string) BotVerdict {
	return CheckBot(BotRequest{UserAgent: userAgent})
}

// defaultFingerprintScorer is a package-level scorer instance for reuse.
var defaultFingerprintScorer = NewFingerprintScorer()

// DeepFingerprintScore performs TLS/HTTP2/browser fingerprint scoring.
// It extracts JA3/JA4, HTTP/2 settings, and header order fingerprints,
// then evaluates them against the known fingerprint database.
func DeepFingerprintScore(r BotRequest) FingerprintResult {
	info := ExtractFingerprint(r.Headers, r.HeaderKeys)
	return defaultFingerprintScorer.ScoreFingerprint(info)
}

// ── Two-phase combined entry point ──

// CheckBotTwoPhase runs the complete two-phase bot detection pipeline.
// It first runs PreScreen; if the IP is not flagged, it returns a clean verdict.
// Otherwise it runs DeepScore and translates the result into a BotVerdict.
func CheckBotTwoPhase(r BotRequest, ipRep *IPReputation, geo *MaxMindResolver, threshold int) (BotVerdict, BotScore) {
	// Quick check for known good bots first (always, regardless of risk).
	ua := strings.TrimSpace(r.UserAgent)
	for i, re := range goodBotUA {
		if re.MatchString(ua) {
			// DNS verification for bots that support it.
			if r.ClientIP != nil && !verifyGoodBotDNS(r.ClientIP, i) {
				break // DNS verification failed — continue to scoring.
			}
			return BotVerdict{
				IsBot: true, Score: 0, Category: "good",
				Reason: "verified legitimate crawler",
			}, BotScore{}
		}
	}

	// Phase 1 – pre-screen.
	if !PreScreen(r, ipRep, geo) {
		// Not high-risk → fast path, skip deep scoring.
		return BotVerdict{IsBot: false, Score: 0, Category: "human"}, BotScore{}
	}

	// Phase 2 – deep score.
	bs := DeepScore(r, ipRep, geo)

	if threshold <= 0 {
		threshold = 80
	}

	verdict := BotVerdict{Score: bs.Total}
	switch {
	case bs.Total >= threshold:
		verdict.IsBot = true
		verdict.Category = "malicious"
		verdict.RuleID = "bot:deep:001"
	case bs.Total >= threshold*60/100:
		verdict.IsBot = true
		verdict.Category = "suspicious"
		verdict.RuleID = "bot:deep:002"
	default:
		verdict.Category = "suspicious"
		verdict.IsBot = true
		verdict.RuleID = "bot:deep:003"
	}

	// Build a combined reason string.
	var parts []string
	if bs.GeoIPScore > 0 {
		parts = append(parts, "geoip:"+bs.Details["geoip_country"])
	}
	if fp, ok := bs.Details["fingerprint"]; ok {
		parts = append(parts, "fp:"+fp)
	}
	if ir, ok := bs.Details["iprep"]; ok {
		parts = append(parts, "iprep:"+ir)
	}
	verdict.Reason = strings.Join(parts, "; ")

	return verdict, bs
}
