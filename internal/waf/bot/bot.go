package bot

import (
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"My-OpenWaf/internal/waf/iprep"
)

// BotScore holds the itemised result of a full (deep) bot evaluation.
type BotScore struct {
	Total            int
	GeoIPScore       int
	FingerprintScore int
	BehaviorScore    int
	IPRepScore       int
	IsHighRisk       bool
	Details          map[string]string
}

type BotVerdict struct {
	IsBot    bool
	Score    int
	Category string
	Reason   string
	RuleID   string
}

type BotRequest struct {
	UserAgent      string
	Method         string
	Path           string
	Headers        map[string]string
	HeaderKeys     []string
	AcceptHeader   string
	AcceptLanguage string
	AcceptEncoding string
	Referer        string
	Connection     string
	HasCookie      bool
	ClientIP       net.IP
	TLS            TLSClientFingerprint
}

func NewBotRequest(method, path string, headers map[string]string) BotRequest {
	return BotRequest{
		Method:         method,
		Path:           path,
		Headers:        headers,
		UserAgent:      botHeaderValue(headers, "user-agent"),
		AcceptHeader:   botHeaderValue(headers, "accept"),
		AcceptLanguage: botHeaderValue(headers, "accept-language"),
		AcceptEncoding: botHeaderValue(headers, "accept-encoding"),
		Referer:        botHeaderValue(headers, "referer"),
		Connection:     botHeaderValue(headers, "connection"),
		HasCookie:      botHeaderValue(headers, "cookie") != "",
	}
}

func botHeaderValue(headers map[string]string, name string) string {
	if value, ok := headers[name]; ok {
		return value
	}
	if lower := strings.ToLower(name); lower != name {
		if value, ok := headers[lower]; ok {
			return value
		}
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

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

type maliciousToolUAPattern struct {
	re      *regexp.Regexp
	needles []string
	name    string
	ruleID  string
}

var maliciousToolUA = []maliciousToolUAPattern{
	{regexp.MustCompile(`(?i)sqlmap`), []string{"sqlmap"}, "sqlmap", "bot:mal:001"},
	{regexp.MustCompile(`(?i)nikto`), []string{"nikto"}, "nikto", "bot:mal:002"},
	{regexp.MustCompile(`(?i)nmap|masscan|zmap`), []string{"nmap", "masscan", "zmap"}, "port_scanner", "bot:mal:003"},
	{regexp.MustCompile(`(?i)acunetix|netsparker|burpsuite|burp suite`), []string{"acunetix", "netsparker", "burpsuite", "burp suite"}, "web_scanner", "bot:mal:004"},
	{regexp.MustCompile(`(?i)dirbuster|gobuster|wfuzz|ffuf|feroxbuster`), []string{"dirbuster", "gobuster", "wfuzz", "ffuf", "feroxbuster"}, "dir_bruteforcer", "bot:mal:005"},
	{regexp.MustCompile(`(?i)nessus|openvas|qualys`), []string{"nessus", "openvas", "qualys"}, "vuln_scanner", "bot:mal:006"},
	{regexp.MustCompile(`(?i)havij|pangolin`), []string{"havij", "pangolin"}, "sqli_tool", "bot:mal:007"},
	{regexp.MustCompile(`(?i)metasploit\b|\bmsf\b`), []string{"metasploit", "msf"}, "metasploit", "bot:mal:008"},
	{regexp.MustCompile(`(?i)hydra|medusa|patator|thc-hydra`), []string{"hydra", "medusa", "patator", "thc-hydra"}, "password_cracker", "bot:mal:009"},
	{regexp.MustCompile(`(?i)nuclei`), []string{"nuclei"}, "nuclei", "bot:mal:010"},
	{regexp.MustCompile(`(?i)zgrab`), []string{"zgrab"}, "zgrab", "bot:mal:011"},
	{regexp.MustCompile(`(?i)xspider|crawler4j`), []string{"xspider", "crawler4j"}, "malicious_crawler", "bot:mal:012"},
	{regexp.MustCompile(`(?i)commix|xsser|beef`), []string{"commix", "xsser", "beef"}, "exploit_tool", "bot:mal:013"},
	{regexp.MustCompile(`(?i)w3af|skipfish|arachni`), []string{"w3af", "skipfish", "arachni"}, "web_app_scanner", "bot:mal:014"},
	{regexp.MustCompile(`(?i)joomscan|wpscan|droopescan`), []string{"joomscan", "wpscan", "droopescan"}, "cms_scanner", "bot:mal:015"},
	{regexp.MustCompile(`(?i)shodan|censys|zoomeye`), []string{"shodan", "censys", "zoomeye"}, "recon_bot", "bot:mal:016"},
	{regexp.MustCompile(`(?i)scrapy|beautifulsoup|selenium`), []string{"scrapy", "beautifulsoup", "selenium"}, "scraper_lib", "bot:mal:017"},
	{regexp.MustCompile(`(?i)python-requests|python-urllib|go-http-client`), []string{"python-requests", "python-urllib", "go-http-client"}, "http_lib", "bot:mal:018"},
	{regexp.MustCompile(`(?i)curl|wget|libwww-perl|lwp-`), []string{"curl", "wget", "libwww-perl", "lwp-"}, "cli_tool", "bot:mal:019"},
	{regexp.MustCompile(`(?i)postman|insomnia|httpie`), []string{"postman", "insomnia", "httpie"}, "api_client", "bot:mal:020"},
}

var goodBotDNSCache sync.Map

type goodBotCacheEntry struct {
	verified bool
	expiry   time.Time
}

var goodBotDNSPatterns = map[int][]string{
	0: {".googlebot.com.", ".google.com."},
	1: {".search.msn.com."},
	2: {".yandex.ru.", ".yandex.net.", ".yandex.com."},
	5: {".apple.com.", ".applebot.apple.com."},
}

func verifyGoodBotDNS(ip net.IP, patternIdx int) bool {
	suffixes, needsVerify := goodBotDNSPatterns[patternIdx]
	if !needsVerify {
		return true
	}
	ipStr := ip.String()
	cacheKey := ipStr + ":" + string(rune(patternIdx+'0'))
	if v, ok := goodBotDNSCache.Load(cacheKey); ok {
		entry := v.(goodBotCacheEntry)
		if time.Now().Before(entry.expiry) {
			return entry.verified
		}
	}
	verified := false
	names, err := net.LookupAddr(ipStr)
	if err == nil {
		for _, name := range names {
			nameLower := strings.ToLower(name)
			for _, suffix := range suffixes {
				if strings.HasSuffix(nameLower, suffix) {
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
	goodBotDNSCache.Store(cacheKey, goodBotCacheEntry{verified: verified, expiry: time.Now().Add(1 * time.Hour)})
	return verified
}

func PreScreen(r BotRequest, ipRepSvc *iprep.IPReputation, geo *MaxMindResolver) bool {
	ua := strings.TrimSpace(r.UserAgent)
	if _, _, ok := matchMaliciousToolUA(ua); ok {
		return true
	}
	if ipRepSvc != nil && r.ClientIP != nil {
		dec := ipRepSvc.Check(r.ClientIP)
		if dec.Matched && !dec.Allowed {
			return true
		}
	}
	if geo != nil && r.ClientIP != nil {
		if geo.IsHighRisk(r.ClientIP) {
			return true
		}
	}
	return false
}

func matchMaliciousToolUA(ua string) (string, string, bool) {
	if ua == "" {
		return "", "", false
	}
	if !containsKnownMaliciousToolUANeedle(ua) {
		return "", "", false
	}
	for _, p := range maliciousToolUA {
		if !maliciousToolUAContainsAny(ua, p.needles) {
			continue
		}
		if p.re.MatchString(ua) {
			return p.name, p.ruleID, true
		}
	}
	return "", "", false
}

func maliciousToolUAContainsAny(ua string, needles []string) bool {
	for _, needle := range needles {
		if containsASCIIFold(ua, needle) {
			return true
		}
	}
	return false
}

func containsKnownMaliciousToolUANeedle(ua string) bool {
	for i := 0; i < len(ua); i++ {
		switch toASCIILower(ua[i]) {
		case 'a':
			if hasASCIIFoldPrefixAt(ua, i, "acunetix") ||
				hasASCIIFoldPrefixAt(ua, i, "arachni") {
				return true
			}
		case 'b':
			if hasASCIIFoldPrefixAt(ua, i, "burpsuite") ||
				hasASCIIFoldPrefixAt(ua, i, "burp suite") ||
				hasASCIIFoldPrefixAt(ua, i, "beautifulsoup") ||
				hasASCIIFoldPrefixAt(ua, i, "beef") {
				return true
			}
		case 'c':
			if hasASCIIFoldPrefixAt(ua, i, "crawler4j") ||
				hasASCIIFoldPrefixAt(ua, i, "commix") ||
				hasASCIIFoldPrefixAt(ua, i, "curl") ||
				hasASCIIFoldPrefixAt(ua, i, "censys") {
				return true
			}
		case 'd':
			if hasASCIIFoldPrefixAt(ua, i, "dirbuster") ||
				hasASCIIFoldPrefixAt(ua, i, "droopescan") {
				return true
			}
		case 'f':
			if hasASCIIFoldPrefixAt(ua, i, "ffuf") ||
				hasASCIIFoldPrefixAt(ua, i, "feroxbuster") {
				return true
			}
		case 'g':
			if hasASCIIFoldPrefixAt(ua, i, "gobuster") ||
				hasASCIIFoldPrefixAt(ua, i, "go-http-client") {
				return true
			}
		case 'h':
			if hasASCIIFoldPrefixAt(ua, i, "havij") ||
				hasASCIIFoldPrefixAt(ua, i, "hydra") ||
				hasASCIIFoldPrefixAt(ua, i, "httpie") {
				return true
			}
		case 'i':
			if hasASCIIFoldPrefixAt(ua, i, "insomnia") {
				return true
			}
		case 'j':
			if hasASCIIFoldPrefixAt(ua, i, "joomscan") {
				return true
			}
		case 'l':
			if hasASCIIFoldPrefixAt(ua, i, "libwww-perl") ||
				hasASCIIFoldPrefixAt(ua, i, "lwp-") {
				return true
			}
		case 'm':
			if hasASCIIFoldPrefixAt(ua, i, "masscan") ||
				hasASCIIFoldPrefixAt(ua, i, "metasploit") ||
				hasASCIIFoldPrefixAt(ua, i, "medusa") ||
				hasASCIIFoldPrefixAt(ua, i, "msf") {
				return true
			}
		case 'n':
			if hasASCIIFoldPrefixAt(ua, i, "nikto") ||
				hasASCIIFoldPrefixAt(ua, i, "nmap") ||
				hasASCIIFoldPrefixAt(ua, i, "nessus") ||
				hasASCIIFoldPrefixAt(ua, i, "nuclei") ||
				hasASCIIFoldPrefixAt(ua, i, "netsparker") {
				return true
			}
		case 'o':
			if hasASCIIFoldPrefixAt(ua, i, "openvas") {
				return true
			}
		case 'p':
			if hasASCIIFoldPrefixAt(ua, i, "pangolin") ||
				hasASCIIFoldPrefixAt(ua, i, "patator") ||
				hasASCIIFoldPrefixAt(ua, i, "python-requests") ||
				hasASCIIFoldPrefixAt(ua, i, "python-urllib") ||
				hasASCIIFoldPrefixAt(ua, i, "postman") {
				return true
			}
		case 'q':
			if hasASCIIFoldPrefixAt(ua, i, "qualys") {
				return true
			}
		case 's':
			if hasASCIIFoldPrefixAt(ua, i, "sqlmap") ||
				hasASCIIFoldPrefixAt(ua, i, "shodan") ||
				hasASCIIFoldPrefixAt(ua, i, "scrapy") ||
				hasASCIIFoldPrefixAt(ua, i, "selenium") ||
				hasASCIIFoldPrefixAt(ua, i, "skipfish") {
				return true
			}
		case 't':
			if hasASCIIFoldPrefixAt(ua, i, "thc-hydra") {
				return true
			}
		case 'w':
			if hasASCIIFoldPrefixAt(ua, i, "wfuzz") ||
				hasASCIIFoldPrefixAt(ua, i, "w3af") ||
				hasASCIIFoldPrefixAt(ua, i, "wpscan") ||
				hasASCIIFoldPrefixAt(ua, i, "wget") {
				return true
			}
		case 'x':
			if hasASCIIFoldPrefixAt(ua, i, "xspider") ||
				hasASCIIFoldPrefixAt(ua, i, "xsser") {
				return true
			}
		case 'z':
			if hasASCIIFoldPrefixAt(ua, i, "zmap") ||
				hasASCIIFoldPrefixAt(ua, i, "zgrab") ||
				hasASCIIFoldPrefixAt(ua, i, "zoomeye") {
				return true
			}
		}
	}
	return false
}

func containsASCIIFold(value, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(value) < len(needle) {
		return false
	}
	first := toASCIILower(needle[0])
	limit := len(value) - len(needle)
	for i := 0; i <= limit; i++ {
		if toASCIILower(value[i]) != first {
			continue
		}
		if hasASCIIFoldAt(value, needle, i) {
			return true
		}
	}
	return false
}

func hasASCIIFoldPrefixAt(value string, offset int, needle string) bool {
	if len(value)-offset < len(needle) {
		return false
	}
	return hasASCIIFoldAt(value, needle, offset)
}

func hasASCIIFoldAt(value, needle string, offset int) bool {
	for i := 0; i < len(needle); i++ {
		if toASCIILower(value[offset+i]) != toASCIILower(needle[i]) {
			return false
		}
	}
	return true
}

func toASCIILower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func DeepScore(r BotRequest, ipRepSvc *iprep.IPReputation, geo *MaxMindResolver) BotScore {
	bs := BotScore{Details: make(map[string]string)}
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
	fpScore, fpReasons := fingerprintScore(r)
	hoScore, hoReasons := headerOrderScore(r)
	fpScore += hoScore
	fpReasons = append(fpReasons, hoReasons...)
	bs.FingerprintScore = fpScore
	if len(fpReasons) > 0 {
		bs.Details["fingerprint"] = strings.Join(fpReasons, ",")
	}
	if ipRepSvc != nil && r.ClientIP != nil {
		dec := ipRepSvc.Check(r.ClientIP)
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
	if r.TLS.JA4 != "" {
		bs.Details["tls_ja4"] = r.TLS.JA4
	}
	if r.TLS.JA3Hash != "" {
		bs.Details["tls_ja3"] = r.TLS.JA3Hash
	}
	if r.TLS.TLSVersion != "" {
		bs.Details["tls_version"] = r.TLS.TLSVersion
	}
	if r.TLS.SNI != "" {
		bs.Details["tls_sni"] = r.TLS.SNI
	}
	if len(r.TLS.ALPN) > 0 {
		bs.Details["tls_alpn"] = strings.Join(r.TLS.ALPN, ",")
	}
	if len(r.HeaderKeys) > 0 {
		bs.Details["header_order"] = strings.Join(r.HeaderKeys, ",")
	}
	bs.Total = bs.GeoIPScore + bs.FingerprintScore + bs.BehaviorScore + bs.IPRepScore
	bs.IsHighRisk = bs.Total >= 80 || bs.GeoIPScore >= 40 || bs.IPRepScore >= 25
	return bs
}

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
	if strings.Contains(uaLower, "python-requests") || strings.Contains(uaLower, "python-urllib") || strings.Contains(uaLower, "go-http-client") || strings.HasPrefix(uaLower, "java/") || strings.HasPrefix(uaLower, "curl/") || strings.HasPrefix(uaLower, "wget/") || strings.Contains(uaLower, "libwww-perl") || strings.Contains(uaLower, "okhttp") || strings.Contains(uaLower, "apache-httpclient") || strings.Contains(uaLower, "node-fetch") || strings.Contains(uaLower, "axios/") {
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
	if strings.Contains(r.Path, "/.env") || strings.Contains(r.Path, "/phpMyAdmin") || strings.Contains(r.Path, "/wp-admin") || strings.Contains(r.Path, "/.git") || strings.Contains(r.Path, "/admin") && r.Method == "GET" && !r.HasCookie {
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
	if r.TLS.TLSVersion == "TLS10" || r.TLS.TLSVersion == "TLS11" {
		score += 12
		reasons = append(reasons, "legacy_tls_version")
	}
	if r.TLS.JA4 != "" && ua != "" {
		if strings.Contains(uaLower, "chrome/") && !strings.Contains(r.TLS.JA4, "h2") && !strings.Contains(r.AcceptEncoding, "br") {
			score += 10
			reasons = append(reasons, "chrome_tls_http_mismatch")
		}
		if strings.Contains(uaLower, "firefox/") && strings.Contains(r.TLS.JA4, "h2") && !strings.Contains(strings.ToLower(r.AcceptEncoding), "br") {
			score += 8
			reasons = append(reasons, "firefox_encoding_mismatch")
		}
	}
	return score, reasons
}

func CheckBot(r BotRequest) BotVerdict { return CheckBotWithLevel(r, "medium") }

func CheckBotWithLevel(r BotRequest, level string) BotVerdict {
	ua := strings.TrimSpace(r.UserAgent)
	for i, re := range goodBotUA {
		if re.MatchString(ua) {
			if r.ClientIP != nil && !verifyGoodBotDNS(r.ClientIP, i) {
				break
			}
			return BotVerdict{IsBot: true, Score: 0, Category: "good", Reason: "known good bot", RuleID: "bot:good"}
		}
	}
	if name, ruleID, ok := matchMaliciousToolUA(ua); ok {
		return BotVerdict{IsBot: true, Score: 95, Category: "malicious", Reason: name, RuleID: ruleID}
	}
	score, reasons := fingerprintScore(r)
	category := "human"
	reason := ""
	if score >= 80 {
		category = "malicious"
		reason = strings.Join(reasons, ",")
	} else if score >= 40 {
		category = "suspicious"
		reason = strings.Join(reasons, ",")
	}
	return BotVerdict{IsBot: category != "human", Score: score, Category: category, Reason: reason, RuleID: "bot:heuristic"}
}

func CheckBotTwoPhase(r BotRequest, ipRepSvc *iprep.IPReputation, geo *MaxMindResolver, threshold int) (BotVerdict, BotScore) {
	if !PreScreen(r, ipRepSvc, geo) {
		return BotVerdict{IsBot: false, Score: 0, Category: "human", Reason: "pre-screen passed", RuleID: "bot:prescreen"}, BotScore{}
	}
	bs := DeepScore(r, ipRepSvc, geo)
	category := "suspicious"
	if bs.Total >= threshold {
		category = "malicious"
	}
	return BotVerdict{IsBot: true, Score: bs.Total, Category: category, Reason: "two-phase score", RuleID: "bot:two_phase"}, bs
}
