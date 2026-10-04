package bot

import (
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"My-OpenWaf/internal/waf/bot/geoip"
	"My-OpenWaf/internal/waf/bot/tlsfp"
	"My-OpenWaf/internal/waf/iprep"
)

type BotScore struct {
	Total            int
	UAScore          int
	GeoIPScore       int
	FingerprintScore int
	BehaviorScore    int
	IPRepScore       int
	IsHighRisk       bool
	Details          map[string]string

	// Dangerous 表示本请求已被判定为「危险」——与分数正交，不受权重影响，
	// 消费方据此保证「只要判断危险就不能放过去」。DangerReasons 是危险来源，
	// 供日志与归因使用。
	Dangerous     bool
	DangerReasons []string

	// Raw 保存各模块的原始分（单模块上限 100，未加权）。
	Raw ModuleScores
}

// ModuleScores 是 bot 综合评分各模块的原始分（未加权，单模块上限 100）。
//
//	UA          User-Agent 字面证据（工具/库/异常 UA）
//	Fingerprint 请求指纹（头缺失、头序、TLS 与 UA 声明一致性）
//	GeoIP       网络环境（机房 ASN、VPN ASN、高风险国家）
//	IPRep       IP 声誉名单与自动封禁
//	Behavior    行为信号（请求频率）
type ModuleScores struct {
	UA          int
	Fingerprint int
	GeoIP       int
	IPRep       int
	Behavior    int
}

// moduleWeights 是模块权重表（整数百分数，合计必须为 100）。
type moduleWeights struct {
	UA          int
	Fingerprint int
	Behavior    int
	GeoIP       int
	IPRep       int
}

// botModuleWeights 定义各模块在总分中的权重。
//
// 模块        权重   理由
//
//	UA          40    无标识客户端（空 UA）必须至少落「记录」档，这是 UA 模块
//	                  需要独立跨过 observe 下界的唯一理由：100×40% = 40。
//	                  而常规工具 curl/wget（原始分 15）仅 6 分，仍是放行档；
//	                  明确攻击工具（90）也只有 36 分——它们靠「危险标记」
//	                  终止，不靠权重，因此 UA 权重不必为「致死」而抬高。
//	请求指纹    25    头缺失/头序/TLS 一致性属被动证据，难以伪造且覆盖面广，
//	                  给次高权重；但与 UA 叠加满值仍只到 65 分（挑战档），
//	                  不会因「可疑头」直接触及拦截。
//	行为        15    请求频率反映扫描强度，需限流后端提供数据。
//	GeoIP        5    机房/高风险国家只是环境概率，不能单独定性。
//	IP 声誉     15    名单命中已由危险标记保证终止，权重只作次要叠加；
//	                  15% 让黑名单 IP 单独贡献 9 分，与其它信号一起抬高总分。
//
// 总分 = Σ(模块分 × 权重) / 100，四舍五入到整数，落在 [0,100]；
// 五档处置边界由 ClassifyScore 从阈值派生，见该函数注释。
//
// 两条正交通道的职责划分：加权总分只决定「档位」，危险标记决定「是否终止」。
// 确定性强的证据（明确攻击工具、名单命中）走危险标记，可被伪造的弱信号
// 走权重——单一弱信号叠加到多高都不会致死，而任一危险判定必定终止。
// 正因为终止已由危险标记保证，权重表可以回归本职：只衡量「可疑程度」，
// 不必为「保证处置」而扭曲分配。
var botModuleWeights = moduleWeights{UA: 40, Fingerprint: 25, Behavior: 15, GeoIP: 5, IPRep: 15}

// dangerToolSeverityThreshold 是 UA 工具严重度表中触发「危险标记」的下界。
// 达到该值的工具（sqlmap/metasploit/爆破框架 90；主动扫描器 80）属明确攻击
// 工具，构成危险；常规自动化工具（curl/wget 15、python-requests 20、
// Postman 25）只是怀疑信号，不置危险。
const dangerToolSeverityThreshold = 80

// BotTier 是 bot 综合评分的五档处置等级。
type BotTier int

const (
	// TierPass 放行：不记录、不处置。
	TierPass BotTier = iota
	// TierObserve 记录：写入 bot 评分日志，请求照常放行。
	TierObserve
	// TierChallenge 挑战：下发 JS 挑战等待验证。
	TierChallenge
	// TierIntercept 拦截：返回 403 拦截页。
	TierIntercept
	// TierDrop 断连：直接关闭 TCP 连接。
	TierDrop
)

// ClassifyScore 把加权总分映射到五档处置
//
//	pass      总分 <  T*0.5   (< 40)
//	observe   T*0.5 ≤ 总分 < T*0.75  (40-59)
//	challenge T*0.75 ≤ 总分 < T      (60-79)
//	intercept T    ≤ 总分 < T*1.125  (80-89)
//	drop      总分 ≥ T*1.125  (≥ 90)
//
// @param total 加权总分。
// @param threshold 处置阈值；<=0 时按默认 80 处理。
// @return 对应的五档处置等级。
func ClassifyScore(total, threshold int) BotTier {
	if threshold <= 0 {
		threshold = 80
	}
	switch {
	case total < threshold/2:
		return TierPass
	case total < threshold*3/4:
		return TierObserve
	case total < threshold:
		return TierChallenge
	case total < threshold*9/8:
		return TierIntercept
	default:
		return TierDrop
	}
}

// Category 返回该档位的日志分类串（命中防护模块 category）。
func (t BotTier) Category() string {
	switch t {
	case TierObserve:
		return "bot_observe"
	case TierChallenge:
		return "bot_challenge"
	case TierIntercept:
		return "bot_intercept"
	case TierDrop:
		return "bot_drop"
	default:
		return "bot_pass"
	}
}

// LogAction 返回与 BotScoreLog.Action 及前端 i18n 键一致的动作串。
func (t BotTier) LogAction() string {
	switch t {
	case TierObserve:
		return "observe"
	case TierChallenge:
		return "challenge"
	case TierIntercept:
		return "intercept"
	case TierDrop:
		return "drop"
	default:
		return "allow"
	}
}

type BotVerdict struct {
	IsBot    bool
	Score    int
	Tier     BotTier
	Category string
	Reason   string
	RuleID   string

	// Dangerous 表示本请求构成「危险」——消费方必须终止该请求，
	// 该决定不得被低权重的分数稀释（用户硬约束：「只要判断危险就不能放过去」）。
	// 具体终止档位仍由 Tier 决定：危险只保证「不低于挑战」。
	Dangerous     bool
	DangerReasons []string
}

type BotRequest struct {
	UserAgent      string
	Method         string
	Path           string
	Headers        map[string]string
	HeaderKeys     []string
	HeaderOrder    string
	AcceptHeader   string
	AcceptLanguage string
	AcceptEncoding string
	Referer        string
	Connection     string
	HasCookie      bool
	ClientIP       net.IP
	TLS            tlsfp.TLSClientFingerprint
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
	{regexp.MustCompile(`(?i)acunetix|netsparker|burpsuite|burp suite|burpcollaborator`), []string{"acunetix", "netsparker", "burpsuite", "burp suite", "burpcollaborator"}, "web_scanner", "bot:mal:004"},
	{regexp.MustCompile(`(?i)dirbuster|gobuster|wfuzz|ffuf|faster u fool|feroxbuster`), []string{"dirbuster", "gobuster", "wfuzz", "ffuf", "faster u fool", "feroxbuster"}, "dir_bruteforcer", "bot:mal:005"},
	{regexp.MustCompile(`(?i)nessus|openvas|qualys|mercuryboard_user_agent_sql_injection`), []string{"nessus", "openvas", "qualys", "mercuryboard_user_agent_sql_injection"}, "vuln_scanner", "bot:mal:006"},
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

func PreScreen(r BotRequest, ipRepSvc *iprep.IPReputation, geo *geoip.MaxMindResolver) bool {
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
				hasASCIIFoldPrefixAt(ua, i, "burpcollaborator") ||
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
				hasASCIIFoldPrefixAt(ua, i, "faster u fool") ||
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
				hasASCIIFoldPrefixAt(ua, i, "mercuryboard_user_agent_sql_injection") ||
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

// uaToolSeverity 把 maliciousToolUA 的工具名映射为 UA 模块原始分（满分 100）。
//
// 分档理由：明确攻击工具（注入、爆破、漏洞利用框架、主动扫描器）95；
// 采集/侦察/爬虫框架 65；常规自动化工具只给低分——cli_tool（curl/wget）
// 15、http_lib（python-requests/go-http-client）20、api_client（Postman 等）25。
// 常规工具的 UA 字面不构成处置依据，只在与其他模块叠加时才抬高总分。
var uaToolSeverity = map[string]int{
	"sqlmap": 95, "sqli_tool": 95, "metasploit": 95, "password_cracker": 95, "exploit_tool": 95,
	"nikto": 95, "port_scanner": 95, "web_scanner": 95, "dir_bruteforcer": 95,
	"vuln_scanner": 95, "nuclei": 95, "web_app_scanner": 95, "cms_scanner": 95,
	"zgrab": 65, "malicious_crawler": 65, "recon_bot": 65, "scraper_lib": 65,
	"cli_tool": 15, "http_lib": 20, "api_client": 25,
}

// uaToolSeverityFallback 是工具名未登记时的 UA 模块原始分。
const uaToolSeverityFallback = 60

// automationClientNeedles 列出未纳入 maliciousToolUA 的常规 HTTP 客户端库字面。
var automationClientNeedles = []string{"okhttp", "apache-httpclient", "node-fetch", "axios/"}

/**
 * uaScore 计算 UA 模块原始分：只看 User-Agent 字面证据。
 *
 * 判定顺序：空 UA → 工具/库字面（maliciousToolUA 与 automationClientNeedles）
 * → 过短 UA → 伪造 Mozilla → Chrome 缺 Safari 标记。工具字面优先于长度，
 * 因此 "okhttp/4.9" 这类短 UA 仍按库字面计入常规自动化档（25），
 * 而不是被短 UA 规则抬到 70。
 *
 * @param r 请求特征。
 * @return score 原始分（0-100）；reasons 命中的原因串。
 */
func uaScore(r BotRequest) (score int, reasons []string) {
	ua := strings.TrimSpace(r.UserAgent)
	if ua == "" {
		return 100, []string{"empty_ua"}
	}
	if name, _, ok := matchMaliciousToolUA(ua); ok {
		severity, registered := uaToolSeverity[name]
		if !registered {
			severity = uaToolSeverityFallback
		}
		return severity, []string{"tool_ua:" + name}
	}
	uaLower := strings.ToLower(ua)
	if strings.HasPrefix(uaLower, "java/") {
		return 25, []string{"automation_lib_ua"}
	}
	for _, needle := range automationClientNeedles {
		if strings.Contains(uaLower, needle) {
			return 25, []string{"automation_lib_ua"}
		}
	}
	if len(ua) < 12 {
		return 70, []string{"short_ua"}
	}
	if strings.HasPrefix(ua, "Mozilla/") && !strings.Contains(ua, "(") {
		return 45, []string{"fake_mozilla"}
	}
	if strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "safari") {
		return 20, []string{"chrome_without_safari"}
	}
	return 0, nil
}

// BehaviorScoreFromCount 把窗口内请求计数换算为行为模块原始分（满分 100）。
//
// 阶梯以限流阈值为基准，计数正常（低于 1.5 倍阈值）时不加分：
//
//	≥ 3 倍 max → 100
//	≥ 2 倍 max → 60
//	≥ 1.5 倍 max → 30
//	否则        → 0
//
// @param count 当前窗口计数（含本次请求）。
// @param maxReqs 同窗口的限流阈值；<=0 时返回 0。
// @return 行为模块原始分。
func BehaviorScoreFromCount(count, maxReqs int) int {
	if maxReqs <= 0 || count <= 0 {
		return 0
	}
	switch {
	case count >= maxReqs*3:
		return 100
	case count >= maxReqs*2:
		return 60
	case count*2 >= maxReqs*3:
		return 30
	default:
		return 0
	}
}

/**
 * weightedTotal 按模块权重表把原始分折算为总分。
 *
 * @param raw 各模块原始分。
 * @return 加权总分，四舍五入，落在 [0,100]。
 */
func weightedTotal(raw ModuleScores) int {
	w := botModuleWeights
	sum := clampModule(raw.UA)*w.UA +
		clampModule(raw.Fingerprint)*w.Fingerprint +
		clampModule(raw.Behavior)*w.Behavior +
		clampModule(raw.GeoIP)*w.GeoIP +
		clampModule(raw.IPRep)*w.IPRep
	return (sum + 50) / 100
}

// clampModule 把模块原始分限制到 [0,100]。
func clampModule(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// DeepScore 计算完整 bot 评分（不带行为信号）。
func DeepScore(r BotRequest, ipRepSvc *iprep.IPReputation, geo *geoip.MaxMindResolver) BotScore {
	return deepScore(r, ipRepSvc, geo, 0)
}

// DeepScoreWithBehavior 在完整评分中并入行为模块原始分（请求频率）。
func DeepScoreWithBehavior(r BotRequest, ipRepSvc *iprep.IPReputation, geo *geoip.MaxMindResolver, behaviorScore int) BotScore {
	return deepScore(r, ipRepSvc, geo, behaviorScore)
}

func deepScore(r BotRequest, ipRepSvc *iprep.IPReputation, geo *geoip.MaxMindResolver, behaviorScore int) BotScore {
	// Details 保持 nil 直到首个 detail 写入：干净流量不产生 map 分配。
	// 写入统一走 setDetail，nil map 时提前分配，天然保持旧行为。
	var bs BotScore
	var raw ModuleScores

	var uaReasons []string
	raw.UA, uaReasons = uaScore(r)
	if len(uaReasons) > 0 {
		bs.setDetail("ua", strings.Join(uaReasons, ","))
	}
	// 危险标记：明确攻击工具 UA（严重度 ≥ dangerToolSeverityThreshold）。
	// 常规自动化工具（curl/wget 15、python-requests 20、Postman 25）不达标，
	// 不置危险——用户的「curl 不该被直接处置」由此保证。
	if name, _, ok := matchMaliciousToolUA(strings.TrimSpace(r.UserAgent)); ok {
		if sev, registered := uaToolSeverity[name]; registered && sev >= dangerToolSeverityThreshold {
			bs.Dangerous = true
			bs.DangerReasons = append(bs.DangerReasons, "tool_ua:"+name)
		}
	}

	if geo != nil && r.ClientIP != nil {
		raw.GeoIP = geo.ScoreIP(r.ClientIP)
		if raw.GeoIP > 0 {
			info := geo.Lookup(r.ClientIP)
			if info.ASN != 0 {
				bs.setDetail("geoip_asn", info.ASNOrg)
			}
			if info.Country != "" {
				bs.setDetail("geoip_country", info.Country)
			}
		}
	}

	fpScore, fpReasons := fingerprintScore(r)
	hoScore, hoReasons := headerOrderScore(r.HeaderKeys)
	raw.Fingerprint = fpScore + hoScore
	fpReasons = append(fpReasons, hoReasons...)
	if len(fpReasons) > 0 {
		bs.setDetail("fingerprint", strings.Join(fpReasons, ","))
	}

	if ipRepSvc != nil && r.ClientIP != nil {
		dec := ipRepSvc.Check(r.ClientIP)
		if dec.Matched && !dec.Allowed {
			switch dec.Category {
			case "blacklist":
				raw.IPRep = 60
			case "auto_ban":
				raw.IPRep = 50
			default:
				raw.IPRep = 30
			}
			// 名单命中是确定性证据（比 UA 字面硬），置危险标记：
			// 即便站点只开 bot 而未开 IP 声誉阶段，也必须终止。
			bs.Dangerous = true
			bs.DangerReasons = append(bs.DangerReasons, "iprep:"+dec.Category)
			bs.setDetail("iprep", dec.Category+": "+dec.Reason)
		}
	}

	raw.Behavior = clampModule(behaviorScore)

	if r.TLS.JA4 != "" {
		bs.setDetail("tls_ja4", r.TLS.JA4)
	}
	if r.TLS.JA3Hash != "" {
		bs.setDetail("tls_ja3", r.TLS.JA3Hash)
	}
	if r.TLS.TLSVersion != "" {
		bs.setDetail("tls_version", r.TLS.TLSVersion)
	}
	if r.TLS.SNI != "" {
		bs.setDetail("tls_sni", r.TLS.SNI)
	}
	if len(r.TLS.ALPN) > 0 {
		bs.setDetail("tls_alpn", strings.Join(r.TLS.ALPN, ","))
	}
	if len(r.HeaderKeys) > 0 {
		order := r.HeaderOrder
		if order == "" {
			order = strings.Join(r.HeaderKeys, ",")
		}
		bs.setDetail("header_order", order)
	}

	w := botModuleWeights
	bs.Raw = raw
	bs.UAScore = clampModule(raw.UA) * w.UA / 100
	bs.FingerprintScore = clampModule(raw.Fingerprint) * w.Fingerprint / 100
	bs.BehaviorScore = clampModule(raw.Behavior) * w.Behavior / 100
	bs.GeoIPScore = clampModule(raw.GeoIP) * w.GeoIP / 100
	bs.IPRepScore = clampModule(raw.IPRep) * w.IPRep / 100
	bs.Total = weightedTotal(raw)
	bs.IsHighRisk = bs.Total >= 80 || raw.GeoIP >= 40 || raw.IPRep >= 25
	return bs
}

/**
 * setDetail 写入一条 bot 详情。Details 为 nil 时先分配，
 * 使 DeepScore 在干净流量（无任何 detail）下保持零 map 分配。
 *
 * @param key 详情字段名。
 * @param value 详情字段值。
 */
func (bs *BotScore) setDetail(key, value string) {
	if bs.Details == nil {
		bs.Details = make(map[string]string)
	}
	bs.Details[key] = value
}

// fingerprintScore 计算请求指纹模块原始分：只看请求头缺失/异常、头序、
// 路径与 TLS 一致性，不再评估 UA 字面（UA 由 uaScore 独立成模块）。
func fingerprintScore(r BotRequest) (score int, reasons []string) {
	ua := strings.TrimSpace(r.UserAgent)
	if r.AcceptHeader == "" {
		score += 25
		reasons = append(reasons, "no_accept")
	} else if !strings.Contains(r.AcceptHeader, "text/html") && !strings.Contains(r.AcceptHeader, "*/*") {
		score += 5
		reasons = append(reasons, "unusual_accept")
	}
	if r.AcceptLanguage == "" {
		score += 20
		reasons = append(reasons, "no_accept_language")
	}
	if r.AcceptEncoding == "" {
		score += 15
		reasons = append(reasons, "no_accept_encoding")
	}
	uaLower := strings.ToLower(ua)
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

/**
 * CheckBotTwoPhase 两阶段评分：PreScreen 预筛命中后进入加权综合评分。
 *
 * 与旧实现的区别：
 *   - 不再有「恶意工具 UA 直接判死」短路——工具 UA 只通过 UA 模块高分
 *     参与加权，处置一律由 ClassifyScore 决定；
 *   - 处置档位由五档（放行/记录/挑战/拦截/断连）取代原三分类。
 *
 * @param r 请求特征。
 * @param ipRepSvc IP 声誉服务，可为 nil。
 * @param geo GeoIP 解析器，可为 nil。
 * @param threshold 处置阈值，默认 80。
 * @return 判定结果与完整加权评分。
 */
func CheckBotTwoPhase(r BotRequest, ipRepSvc *iprep.IPReputation, geo *geoip.MaxMindResolver, threshold int) (BotVerdict, BotScore) {
	if !PreScreen(r, ipRepSvc, geo) {
		return BotVerdict{IsBot: false, Score: 0, Tier: TierPass, Category: "human", Reason: "pre-screen passed", RuleID: "bot:prescreen"}, BotScore{}
	}
	bs := DeepScore(r, ipRepSvc, geo)
	if name, ruleID, ok := matchGoodBotUA(r); ok {
		return BotVerdict{IsBot: true, Score: bs.Total, Tier: TierPass, Category: "good", Reason: name, RuleID: ruleID}, bs
	}
	tier := ClassifyScore(bs.Total, threshold)
	tier = applyDangerFloor(tier, bs.Dangerous)
	return BotVerdict{
		IsBot:         tier != TierPass,
		Score:         bs.Total,
		Tier:          tier,
		Category:      tier.Category(),
		Reason:        bs.TotalReason(),
		RuleID:        "bot:two_phase",
		Dangerous:     bs.Dangerous,
		DangerReasons: bs.DangerReasons,
	}, bs
}

/**
 * CheckBotTwoPhaseWithBehavior 在预筛后并入行为模块（请求频率）的两阶段评分。
 *
 * 与 CheckBotTwoPhase 的唯一差别是评分前注入 behaviorScore（原始分，0-100），
 * 使高频请求在 UA/指纹正常时也能被抬到记录/挑战档。
 *
 * @param r 请求特征。
 * @param ipRepSvc IP 声誉服务，可为 nil。
 * @param geo GeoIP 解析器，可为 nil。
 * @param threshold 处置阈值，默认 80。
 * @param behaviorScore 行为模块原始分。
 * @return 判定结果与完整加权评分。
 */
func CheckBotTwoPhaseWithBehavior(r BotRequest, ipRepSvc *iprep.IPReputation, geo *geoip.MaxMindResolver, threshold, behaviorScore int) (BotVerdict, BotScore) {
	if !PreScreen(r, ipRepSvc, geo) {
		return BotVerdict{IsBot: false, Score: 0, Tier: TierPass, Category: "human", Reason: "pre-screen passed", RuleID: "bot:prescreen"}, BotScore{}
	}
	bs := DeepScoreWithBehavior(r, ipRepSvc, geo, behaviorScore)
	if name, ruleID, ok := matchGoodBotUA(r); ok {
		return BotVerdict{IsBot: true, Score: bs.Total, Tier: TierPass, Category: "good", Reason: name, RuleID: ruleID}, bs
	}
	tier := ClassifyScore(bs.Total, threshold)
	tier = applyDangerFloor(tier, bs.Dangerous)
	return BotVerdict{
		IsBot:         tier != TierPass,
		Score:         bs.Total,
		Tier:          tier,
		Category:      tier.Category(),
		Reason:        bs.TotalReason(),
		RuleID:        "bot:two_phase",
		Dangerous:     bs.Dangerous,
		DangerReasons: bs.DangerReasons,
	}, bs
}

/**
 * applyDangerFloor 把「危险」判定提升到终止下界。
 *
 * 用户硬约束：「只要判断危险就不能放过去」。危险标记与加权总分是两条正交通道——
 * 总分只决定档位，危险标记保证终止，且不得被低权重稀释。因此危险请求的档位
 * 不低于 TierChallenge（挑战），但仍尊重更高总分带来的更重档位：
 * 危险 + 低分 → 挑战（不一次性打死断连）；危险 + 高分 → 拦截或断连。
 *
 * @param tier 由总分派生的档位。
 * @param dangerous 是否已判定危险。
 * @return 施加危险下界后的档位。
 */
func applyDangerFloor(tier BotTier, dangerous bool) BotTier {
	if dangerous && tier < TierChallenge {
		return TierChallenge
	}
	return tier
}

/**
 * matchGoodBotUA 识别已知良性爬虫（并对其 IP 做反向 DNS 校验）。
 *
 * @param r 请求特征。
 * @return 爬虫名、规则 ID、是否命中。
 */
func matchGoodBotUA(r BotRequest) (string, string, bool) {
	ua := strings.TrimSpace(r.UserAgent)
	for i, re := range goodBotUA {
		if !re.MatchString(ua) {
			continue
		}
		if r.ClientIP != nil && !verifyGoodBotDNS(r.ClientIP, i) {
			return "", "", false
		}
		return "known good bot", "bot:good", true
	}
	return "", "", false
}

/**
 * TotalReason 汇总各模块命中原因，形如 "ua:tool_ua:sqlmap;fingerprint:no_accept"。
 *
 * @return 命中原因串；无任何命中时返回说明性文案。
 */
func (bs *BotScore) TotalReason() string {
	if bs == nil || len(bs.Details) == 0 {
		return "two-phase score"
	}
	var b strings.Builder
	for _, key := range []string{"ua", "fingerprint", "iprep", "geoip_country"} {
		value, ok := bs.Details[key]
		if !ok {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(';')
		}
		b.WriteString(key)
		b.WriteByte(':')
		b.WriteString(value)
	}
	if b.Len() == 0 {
		return "two-phase score"
	}
	return b.String()
}

func headerOrderScore(headerKeys []string) (int, []string) {
	if len(headerKeys) == 0 {
		return 0, nil
	}
	lower := make([]string, 0, len(headerKeys))
	for _, key := range headerKeys {
		lower = append(lower, strings.ToLower(strings.TrimSpace(key)))
	}
	score := 0
	var reasons []string
	if sort.StringsAreSorted(lower) && len(lower) >= 5 {
		score += 8
		reasons = append(reasons, "alphabetic_header_order")
	}
	if containsHeader(lower, "user-agent") && containsHeader(lower, "host") && indexHeader(lower, "user-agent") < indexHeader(lower, "host") {
		score += 6
		reasons = append(reasons, "ua_before_host")
	}
	return score, reasons
}

func containsHeader(keys []string, target string) bool { return indexHeader(keys, target) >= 0 }

func indexHeader(keys []string, target string) int {
	for i, key := range keys {
		if key == target {
			return i
		}
	}
	return -1
}
