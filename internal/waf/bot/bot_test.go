package bot

import "testing"

func TestNewBotRequestExtractsCanonicalHeadersWithoutMapScan(t *testing.T) {
	req := NewBotRequest("POST", "/login", map[string]string{
		"User-Agent":      "Mozilla/5.0",
		"Accept":          "application/json",
		"Accept-Language": "zh-CN,zh;q=0.9",
		"Accept-Encoding": "gzip, br",
		"Referer":         "https://example.com/login",
		"Connection":      "keep-alive",
		"Cookie":          "sid=abc",
		"X-Test":          "1",
	})

	if req.UserAgent != "Mozilla/5.0" {
		t.Fatalf("UserAgent = %q, want %q", req.UserAgent, "Mozilla/5.0")
	}
	if req.AcceptHeader != "application/json" {
		t.Fatalf("AcceptHeader = %q, want %q", req.AcceptHeader, "application/json")
	}
	if req.AcceptLanguage != "zh-CN,zh;q=0.9" {
		t.Fatalf("AcceptLanguage = %q, want %q", req.AcceptLanguage, "zh-CN,zh;q=0.9")
	}
	if req.AcceptEncoding != "gzip, br" {
		t.Fatalf("AcceptEncoding = %q, want %q", req.AcceptEncoding, "gzip, br")
	}
	if req.Referer != "https://example.com/login" {
		t.Fatalf("Referer = %q, want %q", req.Referer, "https://example.com/login")
	}
	if req.Connection != "keep-alive" {
		t.Fatalf("Connection = %q, want %q", req.Connection, "keep-alive")
	}
	if !req.HasCookie {
		t.Fatal("HasCookie = false, want true")
	}
}

func TestNewBotRequestAcceptsLowercaseHeaders(t *testing.T) {
	req := NewBotRequest("GET", "/", map[string]string{
		"user-agent":      "curl/8.0",
		"accept":          "*/*",
		"accept-language": "en-US",
		"accept-encoding": "gzip",
		"referer":         "https://example.com",
		"connection":      "close",
		"cookie":          "sid=xyz",
	})

	if req.UserAgent != "curl/8.0" {
		t.Fatalf("UserAgent = %q, want %q", req.UserAgent, "curl/8.0")
	}
	if req.AcceptHeader != "*/*" {
		t.Fatalf("AcceptHeader = %q, want %q", req.AcceptHeader, "*/*")
	}
	if req.AcceptLanguage != "en-US" {
		t.Fatalf("AcceptLanguage = %q, want %q", req.AcceptLanguage, "en-US")
	}
	if req.AcceptEncoding != "gzip" {
		t.Fatalf("AcceptEncoding = %q, want %q", req.AcceptEncoding, "gzip")
	}
	if req.Referer != "https://example.com" {
		t.Fatalf("Referer = %q, want %q", req.Referer, "https://example.com")
	}
	if req.Connection != "close" {
		t.Fatalf("Connection = %q, want %q", req.Connection, "close")
	}
	if !req.HasCookie {
		t.Fatal("HasCookie = false, want true")
	}
}

// TestBotMaliciousToolUARules 覆盖工具 UA 字面识别与两阶段评分下的 UA 模块分档。
//
// 断言路径是生产真实入口 CheckBotTwoPhase；工具 UA 命中 PreScreen 后进入完整加权评分，
// 单凭 UA 模块（20% 权重）不足以进入拦截档，这里钉住两件事：
//  1. 工具 UA 永不单独到拦截/断连（用户硬约束：curl 等 UA 不应被直接拦截）；
//  2. 明确攻击工具（危险工具）由 applyDangerFloor 保证不低于挑战档。
func TestBotMaliciousToolUARules(t *testing.T) {
	tests := []struct {
		name        string
		ua          string
		reason      string
		ruleID      string
		dangerous   bool
		wantAtLeast BotTier
	}{
		{name: "sqlmap", ua: "sqlmap/1.7.8", reason: "sqlmap", ruleID: "bot:mal:001", dangerous: true, wantAtLeast: TierChallenge},
		{name: "nikto", ua: "Nikto/2.5.0", reason: "nikto", ruleID: "bot:mal:002", dangerous: true, wantAtLeast: TierChallenge},
		{name: "port scanner", ua: "masscan/1.3", reason: "port_scanner", ruleID: "bot:mal:003", dangerous: true, wantAtLeast: TierChallenge},
		{name: "web scanner", ua: "Burp Suite Professional", reason: "web_scanner", ruleID: "bot:mal:004", dangerous: true, wantAtLeast: TierChallenge},
		{name: "dir brute", ua: "ffuf/2.1.0", reason: "dir_bruteforcer", ruleID: "bot:mal:005", dangerous: true, wantAtLeast: TierChallenge},
		{name: "vuln scanner", ua: "Nessus Agent", reason: "vuln_scanner", ruleID: "bot:mal:006", dangerous: true, wantAtLeast: TierChallenge},
		{name: "sqli tool", ua: "Havij", reason: "sqli_tool", ruleID: "bot:mal:007", dangerous: true, wantAtLeast: TierChallenge},
		{name: "metasploit", ua: "metasploit/6.4", reason: "metasploit", ruleID: "bot:mal:008", dangerous: true, wantAtLeast: TierChallenge},
		{name: "msf", ua: "msf", reason: "metasploit", ruleID: "bot:mal:008", dangerous: true, wantAtLeast: TierChallenge},
		{name: "password cracker", ua: "THC-Hydra", reason: "password_cracker", ruleID: "bot:mal:009", dangerous: true, wantAtLeast: TierChallenge},
		{name: "nuclei", ua: "nuclei/v3", reason: "nuclei", ruleID: "bot:mal:010", dangerous: true, wantAtLeast: TierChallenge},
		{name: "zgrab", ua: "zgrab/0.x", reason: "zgrab", ruleID: "bot:mal:011", dangerous: false, wantAtLeast: TierObserve},
		{name: "crawler", ua: "crawler4j", reason: "malicious_crawler", ruleID: "bot:mal:012", dangerous: false, wantAtLeast: TierObserve},
		{name: "exploit", ua: "commix", reason: "exploit_tool", ruleID: "bot:mal:013", dangerous: true, wantAtLeast: TierChallenge},
		{name: "web app scanner", ua: "skipfish", reason: "web_app_scanner", ruleID: "bot:mal:014", dangerous: true, wantAtLeast: TierChallenge},
		{name: "cms scanner", ua: "wpscan", reason: "cms_scanner", ruleID: "bot:mal:015", dangerous: true, wantAtLeast: TierChallenge},
		{name: "recon", ua: "Shodan", reason: "recon_bot", ruleID: "bot:mal:016", dangerous: false, wantAtLeast: TierObserve},
		{name: "scraper", ua: "python selenium", reason: "scraper_lib", ruleID: "bot:mal:017", dangerous: false, wantAtLeast: TierObserve},
		{name: "http lib", ua: "python-requests/2.32", reason: "http_lib", ruleID: "bot:mal:018", dangerous: false, wantAtLeast: TierPass},
		{name: "cli", ua: "curl/8.7.1", reason: "cli_tool", ruleID: "bot:mal:019", dangerous: false, wantAtLeast: TierPass},
		{name: "api client", ua: "PostmanRuntime/7.39", reason: "api_client", ruleID: "bot:mal:020", dangerous: false, wantAtLeast: TierPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := BotRequest{UserAgent: tt.ua}
			if !PreScreen(req, nil, nil) {
				t.Fatalf("PreScreen(%q) = false", tt.ua)
			}
			if name, ruleID, ok := matchMaliciousToolUA(tt.ua); !ok || name != tt.reason || ruleID != tt.ruleID {
				t.Fatalf("matchMaliciousToolUA(%q) = %q/%q/%v", tt.ua, name, ruleID, ok)
			}
			got, _ := CheckBotTwoPhase(req, nil, nil, 80)
			if got.Tier >= TierIntercept {
				t.Fatalf("工具 UA 单独不得拦截/断连：CheckBotTwoPhase(%q) = %+v", tt.ua, got)
			}
			if got.Dangerous != tt.dangerous {
				t.Fatalf("CheckBotTwoPhase(%q) Dangerous = %v, want %v (%+v)", tt.ua, got.Dangerous, tt.dangerous, got)
			}
			if got.Tier < tt.wantAtLeast {
				t.Fatalf("CheckBotTwoPhase(%q) tier = %d, want >= %d (%+v)", tt.ua, got.Tier, tt.wantAtLeast, got)
			}
		})
	}
}

// TestBotCleanBrowserUAPassesPreScreen 验证干净浏览器不被 PreScreen 命中，
// 因而两阶段路径直接返回 human/prescreen（不进入评分，也就不可能产生处置）。
func TestBotCleanBrowserUAPassesPreScreen(t *testing.T) {
	req := cleanBrowserBotRequest()
	if PreScreen(req, nil, nil) {
		t.Fatal("clean browser User-Agent should pass PreScreen")
	}
	got, _ := CheckBotTwoPhase(req, nil, nil, 80)
	if got.IsBot || got.Tier != TierPass || got.Category != "human" || got.RuleID != "bot:prescreen" {
		t.Fatalf("CheckBotTwoPhase(clean browser) = %+v", got)
	}
}

func BenchmarkPreScreenCleanBrowserUA(b *testing.B) {
	req := cleanBrowserBotRequest()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if PreScreen(req, nil, nil) {
			b.Fatal("clean browser User-Agent should pass PreScreen")
		}
	}
}

func BenchmarkCheckBotTwoPhaseCleanBrowserUA(b *testing.B) {
	req := cleanBrowserBotRequest()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		got, _ := CheckBotTwoPhase(req, nil, nil, 80)
		if got.IsBot {
			b.Fatalf("clean browser User-Agent should be human: %+v", got)
		}
	}
}

func BenchmarkNewBotRequestDenseHeaders(b *testing.B) {
	headers := map[string]string{
		"User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"user-agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language":  "zh-CN,zh;q=0.9,en;q=0.8",
		"accept-language":  "zh-CN,zh;q=0.9,en;q=0.8",
		"Accept-Encoding":  "gzip, deflate, br",
		"accept-encoding":  "gzip, deflate, br",
		"Referer":          "https://example.com/dashboard",
		"referer":          "https://example.com/dashboard",
		"Connection":       "keep-alive",
		"connection":       "keep-alive",
		"Cookie":           "sid=abc; pref=1",
		"cookie":           "sid=abc; pref=1",
		"X-Forwarded-For":  "203.0.113.10",
		"x-forwarded-for":  "203.0.113.10",
		"X-Requested-With": "XMLHttpRequest",
		"x-requested-with": "XMLHttpRequest",
		"Cache-Control":    "no-cache",
		"cache-control":    "no-cache",
		"Upgrade-Insecure": "1",
		"upgrade-insecure": "1",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req := NewBotRequest("GET", "/dashboard", headers)
		if req.UserAgent == "" || !req.HasCookie {
			b.Fatalf("unexpected bot request: %+v", req)
		}
	}
}

func cleanBrowserBotRequest() BotRequest {
	return BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		Method:         "GET",
		Path:           "/",
		AcceptHeader:   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br",
		HasCookie:      true,
	}
}
