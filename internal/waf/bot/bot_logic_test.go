package bot

import (
	"testing"

	"My-OpenWaf/internal/waf/bot/tlsfp"
)

// --- containsASCIIFold ---

func TestContainsASCIIFold(t *testing.T) {
	cases := []struct {
		value  string
		needle string
		want   bool
	}{
		{"sqlmap/1.7", "sqlmap", true},
		{"SQLMAP/1.7", "sqlmap", true},
		{"SqlMap", "sqlmap", true},
		{"no match here", "sqlmap", false},
		{"", "sqlmap", false},
		{"abc", "abcd", false},
		{"anything", "", true},
		{"curl/8.0", "curl", true},
		{"CURL/8.0", "curl", true},
	}
	for _, c := range cases {
		got := containsASCIIFold(c.value, c.needle)
		if got != c.want {
			t.Errorf("containsASCIIFold(%q, %q) = %v, want %v", c.value, c.needle, got, c.want)
		}
	}
}

// --- matchMaliciousToolUA ---

func TestMatchMaliciousToolUA(t *testing.T) {
	t.Run("empty ua returns no match", func(t *testing.T) {
		name, ruleID, ok := matchMaliciousToolUA("")
		if ok || name != "" || ruleID != "" {
			t.Errorf("empty ua should not match, got name=%q ruleID=%q ok=%v", name, ruleID, ok)
		}
	})
	t.Run("clean browser ua returns no match", func(t *testing.T) {
		_, _, ok := matchMaliciousToolUA("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/125 Safari/537.36")
		if ok {
			t.Error("clean browser ua should not match malicious tools")
		}
	})
	t.Run("sqlmap matches", func(t *testing.T) {
		name, ruleID, ok := matchMaliciousToolUA("sqlmap/1.8")
		if !ok || name != "sqlmap" || ruleID != "bot:mal:001" {
			t.Errorf("got name=%q ruleID=%q ok=%v", name, ruleID, ok)
		}
	})
	t.Run("nuclei case-insensitive matches", func(t *testing.T) {
		name, ruleID, ok := matchMaliciousToolUA("NUCLEI/v3.0")
		if !ok || name != "nuclei" || ruleID != "bot:mal:010" {
			t.Errorf("got name=%q ruleID=%q ok=%v", name, ruleID, ok)
		}
	})
}

// TestMatchMaliciousToolUAGotestwaf 覆盖 gotestwaf community-user-agent 载荷的
// 三条新增字面：ffuf（dir bruteforcer）、mercuryboard NVT（Nessus 语法）、
// burpcollaborator（OAST 回连域名）。
func TestMatchMaliciousToolUAGotestwaf(t *testing.T) {
	pos := []struct {
		ua     string
		ruleID string
	}{
		{"Fuzz Faster U Fool v2.0.0", "bot:mal:005"},
		{"mercuryboard_user_agent_sql_injection.nasl'", "bot:mal:006"},
		{"http://lmb1ikpej3yys0gqft8lxewm2d89w5qtgh840sp.burpcollaborator.net/6.17.0.RELEASE iPhone12,8 iOS/14.5.1))", "bot:mal:004"},
	}
	for _, c := range pos {
		_, ruleID, ok := matchMaliciousToolUA(c.ua)
		if !ok || ruleID != c.ruleID {
			t.Errorf("UA %q: ok=%v ruleID=%q, want ruleID %q", c.ua, ok, ruleID, c.ruleID)
		}
	}
	neg := []string{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/128.0",
	}
	for _, ua := range neg {
		if _, _, ok := matchMaliciousToolUA(ua); ok {
			t.Errorf("良性 UA %q 被误判 scanner", ua)
		}
	}
}

// --- fingerprintScore ---

// --- uaScore（UA 模块） ---

// 旧断言：指纹模块里 empty_ua 加 40 分、short_ua 加 25 分。
// 新断言：UA 字面独立成 uaScore 模块（empty_ua=100、short_ua=70），
// fingerprintScore 不再评估 UA。
func TestUAScoreEmptyUA(t *testing.T) {
	r := BotRequest{}
	score, reasons := uaScore(r)
	if score != 100 {
		t.Errorf("empty ua should score 100 in UA module, got %d", score)
	}
	if !containsReason(reasons, "empty_ua") {
		t.Errorf("reasons should contain empty_ua, got %v", reasons)
	}
	fpScore, fpReasons := fingerprintScore(r)
	if containsReason(fpReasons, "empty_ua") {
		t.Errorf("fingerprint module must not score UA literals, got %v", fpReasons)
	}
	if fpScore < 45 {
		t.Errorf("empty ua fingerprint score = %d, want the header-deficit signals (>=45)", fpScore)
	}
	if !containsReason(fpReasons, "no_accept") || !containsReason(fpReasons, "no_accept_language") || !containsReason(fpReasons, "no_accept_encoding") {
		t.Errorf("empty request must trip every header-deficit signal, got %v", fpReasons)
	}
}

func TestUAScoreShortUA(t *testing.T) {
	r := BotRequest{UserAgent: "ab", AcceptHeader: "text/html", AcceptLanguage: "en", AcceptEncoding: "gzip"}
	score, reasons := uaScore(r)
	if !containsReason(reasons, "short_ua") {
		t.Errorf("reasons should contain short_ua, got %v", reasons)
	}
	if score != 70 {
		t.Errorf("short ua should score 70 in UA module, got %d", score)
	}
}

func TestFingerprintScoreNoAccept(t *testing.T) {
	r := BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0) Chrome/125",
		AcceptLanguage: "en-US",
		AcceptEncoding: "gzip",
	}
	score, reasons := fingerprintScore(r)
	if !containsReason(reasons, "no_accept") {
		t.Errorf("reasons should contain no_accept, got %v", reasons)
	}
	_ = score
}

func TestFingerprintScoreUnusualAccept(t *testing.T) {
	r := BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0) Chrome/125",
		AcceptHeader:   "application/json",
		AcceptLanguage: "en-US",
		AcceptEncoding: "gzip",
	}
	_, reasons := fingerprintScore(r)
	if !containsReason(reasons, "unusual_accept") {
		t.Errorf("reasons should contain unusual_accept, got %v", reasons)
	}
}

func TestFingerprintScoreNoAcceptLanguage(t *testing.T) {
	r := BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0) Chrome/125",
		AcceptHeader:   "text/html",
		AcceptEncoding: "gzip",
	}
	_, reasons := fingerprintScore(r)
	if !containsReason(reasons, "no_accept_language") {
		t.Errorf("reasons should contain no_accept_language, got %v", reasons)
	}
}

func TestFingerprintScoreNoAcceptEncoding(t *testing.T) {
	r := BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0) Chrome/125",
		AcceptHeader:   "text/html",
		AcceptLanguage: "en-US",
	}
	_, reasons := fingerprintScore(r)
	if !containsReason(reasons, "no_accept_encoding") {
		t.Errorf("reasons should contain no_accept_encoding, got %v", reasons)
	}
}

// 旧断言：automation_lib、fake_mozilla、chrome_without_safari 都在 fingerprintScore 里加分。
// 新断言：这三条 UA 字面规则移入 uaScore 模块，fingerprintScore 不再产出它们。
func TestUAScoreAutomationLibUA(t *testing.T) {
	libUAs := []string{
		"python-requests/2.32",
		"python-urllib/3.11",
		"go-http-client/1.1",
		"java/11.0.2",
		"curl/8.0",
		"wget/1.21",
		"libwww-perl/6.08",
		"okhttp/4.9",
		"apache-httpclient/4.5",
		"node-fetch/2.6",
		"axios/1.6",
	}
	for _, ua := range libUAs {
		r := BotRequest{UserAgent: ua, AcceptHeader: "text/html", AcceptLanguage: "en", AcceptEncoding: "gzip"}
		score, reasons := uaScore(r)
		if !containsReason(reasons, "automation_lib_ua") && !containsReason(reasons, "tool_ua:cli_tool") && !containsReason(reasons, "tool_ua:http_lib") {
			t.Errorf("UA %q should be classified as automation in UA module, got %v", ua, reasons)
		}
		if score > 25 {
			t.Errorf("routine automation UA %q must stay in the low band, got UA score %d", ua, score)
		}
	}
}

func TestUAScoreFakeMozilla(t *testing.T) {
	r := BotRequest{
		UserAgent:      "Mozilla/5.0 NoParentheses",
		AcceptHeader:   "text/html",
		AcceptLanguage: "en-US",
		AcceptEncoding: "gzip",
	}
	_, reasons := uaScore(r)
	if !containsReason(reasons, "fake_mozilla") {
		t.Errorf("reasons should contain fake_mozilla, got %v", reasons)
	}
	_, fpReasons := fingerprintScore(r)
	if containsReason(fpReasons, "fake_mozilla") {
		t.Errorf("fingerprint module must not carry UA literals, got %v", fpReasons)
	}
}

func TestFingerprintScoreConnClose(t *testing.T) {
	r := BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows) Chrome/125",
		AcceptHeader:   "text/html",
		AcceptLanguage: "en-US",
		AcceptEncoding: "gzip",
		Connection:     "close",
	}
	_, reasons := fingerprintScore(r)
	if !containsReason(reasons, "conn_close") {
		t.Errorf("reasons should contain conn_close, got %v", reasons)
	}
}

func TestFingerprintScoreNoCookiePost(t *testing.T) {
	r := BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows) Chrome/125",
		AcceptHeader:   "text/html",
		AcceptLanguage: "en-US",
		AcceptEncoding: "gzip",
		Method:         "POST",
		HasCookie:      false,
	}
	_, reasons := fingerprintScore(r)
	if !containsReason(reasons, "no_cookie_post") {
		t.Errorf("reasons should contain no_cookie_post, got %v", reasons)
	}
}

func TestFingerprintScoreScannerPath(t *testing.T) {
	paths := []string{"/.env", "/phpMyAdmin", "/wp-admin", "/.git"}
	for _, path := range paths {
		r := BotRequest{
			UserAgent:      "Mozilla/5.0 (Windows) Chrome/125",
			AcceptHeader:   "text/html",
			AcceptLanguage: "en-US",
			AcceptEncoding: "gzip",
			Path:           path,
		}
		_, reasons := fingerprintScore(r)
		if !containsReason(reasons, "scanner_path") {
			t.Errorf("path %q should trigger scanner_path, got %v", path, reasons)
		}
	}
}

func TestFingerprintScorePostNoReferer(t *testing.T) {
	r := BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows) Chrome/125",
		AcceptHeader:   "text/html",
		AcceptLanguage: "en-US",
		AcceptEncoding: "gzip",
		Method:         "POST",
		Referer:        "",
		HasCookie:      true,
	}
	_, reasons := fingerprintScore(r)
	if !containsReason(reasons, "post_no_referer") {
		t.Errorf("reasons should contain post_no_referer, got %v", reasons)
	}
}

func TestFingerprintScoreLegacyTLS(t *testing.T) {
	r := BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows) Chrome/125",
		AcceptHeader:   "text/html",
		AcceptLanguage: "en-US",
		AcceptEncoding: "gzip",
		TLS:            tlsfp.TLSClientFingerprint{TLSVersion: "TLS10"},
	}
	_, reasons := fingerprintScore(r)
	if !containsReason(reasons, "legacy_tls_version") {
		t.Errorf("TLS10 should trigger legacy_tls_version, got %v", reasons)
	}
}

// TestDeepScoreDoesNotTreatJA4PresenceAsRisk 归位自 tlsfp 子包：断言的是 bot 评分模块的语义。
func TestDeepScoreDoesNotTreatJA4PresenceAsRisk(t *testing.T) {
	bs := DeepScore(BotRequest{
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		AcceptHeader:   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br",
		TLS:            tlsfp.TLSClientFingerprint{JA4: "t13d1516h2_8daaf6152771_e5627efa2ab1"},
	}, nil, nil)
	if bs.FingerprintScore != 0 {
		t.Fatalf("JA4 presence alone should not add fingerprint score, got %d", bs.FingerprintScore)
	}
	if bs.IsHighRisk {
		t.Fatal("benign request with JA4 presence alone should not be high risk")
	}
}

func TestFingerprintScoreCleanBrowserNoReasons(t *testing.T) {
	r := cleanBrowserBotRequest()
	score, reasons := fingerprintScore(r)
	// clean browser 应该没有 negative reasons，score 非常低或为0
	for _, bad := range []string{"no_accept", "unusual_accept", "no_accept_language", "no_accept_encoding", "legacy_tls_version"} {
		if containsReason(reasons, bad) {
			t.Errorf("clean browser should not trigger %q, score=%d reasons=%v", bad, score, reasons)
		}
	}
}

func TestFingerprintScoreCleanBrowserHasNoUASignals(t *testing.T) {
	r := cleanBrowserBotRequest()
	_, reasons := fingerprintScore(r)
	for _, bad := range []string{"empty_ua", "short_ua", "automation_lib_ua", "fake_mozilla", "chrome_without_safari"} {
		if containsReason(reasons, bad) {
			t.Errorf("UA-derived signal %q must not appear in the fingerprint module, got %v", bad, reasons)
		}
	}
}

// --- CheckBotTwoPhase 预筛直通与工具 UA 的真实入口语义 ---

// 干净浏览器不触发 PreScreen，两阶段路径在此直接返回，不进入评分。
func TestCheckBotTwoPhaseCleanBrowserPassesThroughPreScreen(t *testing.T) {
	r := cleanBrowserBotRequest()
	if PreScreen(r, nil, nil) {
		t.Fatal("clean browser should pass PreScreen")
	}
	got, bs := CheckBotTwoPhase(r, nil, nil, 80)
	if got.IsBot || got.Category != "human" || got.RuleID != "bot:prescreen" {
		t.Errorf("clean browser should be human/prescreen, got %+v", got)
	}
	if bs.Total != 0 {
		t.Errorf("pre-screen pass must not run scoring, BotScore.Total = %d", bs.Total)
	}
}

// 常规自动化工具（curl 类）PreScreen 命中但评分不足以处置，保持放行。
func TestCheckBotTwoPhaseToolUAPreScreenHitStillPasses(t *testing.T) {
	r := BotRequest{UserAgent: "curl/8.7.1"}
	if !PreScreen(r, nil, nil) {
		t.Fatal("curl UA should hit PreScreen")
	}
	got, bs := CheckBotTwoPhase(r, nil, nil, 80)
	if got.Tier != TierPass || got.Category != "bot_pass" || got.IsBot {
		t.Errorf("curl UA must stay pass, got %+v", got)
	}
	if bs.Total <= 0 {
		t.Errorf("PreScreen hit must run scoring, BotScore.Total = %d", bs.Total)
	}
}

// --- CheckBotTwoPhase 不命中预筛时的返回契约 ---

// 短 UA 无任何缺头信号，不构成预筛命中，返回 prescreen 直通结果。
func TestCheckBotTwoPhaseShortUANoPreScreenHit(t *testing.T) {
	r := BotRequest{UserAgent: "short"} // 无 accept / language / encoding
	if PreScreen(r, nil, nil) {
		t.Fatal("short UA without signal should not hit PreScreen")
	}
	got, _ := CheckBotTwoPhase(r, nil, nil, 80)
	if got.Tier != TierPass || got.Category != "human" || got.RuleID != "bot:prescreen" || got.IsBot {
		t.Errorf("expected human/prescreen pass, got %+v", got)
	}
}

// 空 UA + 缺头同样不构成预筛命中：两阶段路径只按「工具 UA / IP 声誉 / GeoIP」
// 三条件预筛，缺头信号要到评分阶段才起作用，因此该请求在预筛处直通。
func TestCheckBotTwoPhaseMissingHeadersNoPreScreenHit(t *testing.T) {
	r := BotRequest{
		UserAgent:      "",
		AcceptHeader:   "",
		AcceptLanguage: "",
		AcceptEncoding: "",
		Method:         "POST",
		HasCookie:      false,
	}
	if PreScreen(r, nil, nil) {
		t.Fatal("missing-header request without tool UA should not hit PreScreen")
	}
	got, _ := CheckBotTwoPhase(r, nil, nil, 80)
	if got.Tier != TierPass || got.Category != "human" || got.RuleID != "bot:prescreen" {
		t.Errorf("expected human/prescreen pass, got %+v", got)
	}
}

// Googlebot 在无 IP 声誉/GeoIP 时同样不命中预筛，直通返回；
// matchGoodBotUA 的 good 短路位于 PreScreen 之后，故本用例只覆盖直通分支。
func TestCheckBotTwoPhaseGoodBotNoIP(t *testing.T) {
	r := BotRequest{
		UserAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		ClientIP:  nil,
	}
	if PreScreen(r, nil, nil) {
		t.Fatal("Googlebot UA without IP reputation/geo hit should not hit PreScreen")
	}
	got, _ := CheckBotTwoPhase(r, nil, nil, 80)
	if got.Category != "human" || got.RuleID != "bot:prescreen" || got.IsBot {
		t.Errorf("expected human/prescreen pass, got %+v", got)
	}
}

// --- DeepScore 基础路径 ---

func TestDeepScoreNoGeoNoIPRep(t *testing.T) {
	r := cleanBrowserBotRequest()
	bs := DeepScore(r, nil, nil)
	// 无 GeoIP 和 IPRep，只有 UA 与指纹模块
	if bs.GeoIPScore != 0 {
		t.Errorf("GeoIPScore should be 0 without geo resolver, got %d", bs.GeoIPScore)
	}
	if bs.IPRepScore != 0 {
		t.Errorf("IPRepScore should be 0 without iprep, got %d", bs.IPRepScore)
	}
	if bs.UAScore != 0 {
		t.Errorf("clean browser UA should score 0, got %d", bs.UAScore)
	}
	if bs.Total != bs.UAScore+bs.FingerprintScore+bs.BehaviorScore {
		t.Errorf("Total mismatch: %d != UA(%d)+FP(%d)+Behav(%d)", bs.Total, bs.UAScore, bs.FingerprintScore, bs.BehaviorScore)
	}
}

// 旧断言：空请求的指纹分 >=80 → IsHighRisk（指纹模块独自可达高危）。
// 新断言：单一请求的 UA/指纹/行为等弱模块之和不得进入拦截档，
// 空请求只落在中间档；最终数值由权重表决定，此处只钉住硬上界。
func TestDeepScoreEmptyRequestStaysBelowIntercept(t *testing.T) {
	r := BotRequest{}
	bs := DeepScore(r, nil, nil)
	if bs.Total >= 80 {
		t.Errorf("UA/fingerprint modules alone must not reach the intercept band, got Total=%d", bs.Total)
	}
	if bs.IsHighRisk {
		t.Errorf("empty request should not be flagged high risk, got Total=%d", bs.Total)
	}
	if bs.UAScore == 0 || bs.FingerprintScore == 0 {
		t.Errorf("empty request must populate both weak modules, got %+v", bs)
	}
}

func TestDeepScoreTLSDetailsRecorded(t *testing.T) {
	r := cleanBrowserBotRequest()
	r.TLS = tlsfp.TLSClientFingerprint{
		JA4:        "t13d1516h2_8daaf6152771_e5627efa2ab1",
		JA3Hash:    "abc123",
		TLSVersion: "TLS13",
		SNI:        "example.com",
		ALPN:       []string{"h2", "http/1.1"},
	}
	bs := DeepScore(r, nil, nil)
	if bs.Details["tls_ja4"] != r.TLS.JA4 {
		t.Errorf("tls_ja4 not recorded: %v", bs.Details)
	}
	if bs.Details["tls_ja3"] != r.TLS.JA3Hash {
		t.Errorf("tls_ja3 not recorded: %v", bs.Details)
	}
	if bs.Details["tls_sni"] != "example.com" {
		t.Errorf("tls_sni not recorded: %v", bs.Details)
	}
}

// --- CheckBotTwoPhase ---

func TestCheckBotTwoPhaseCleanPassesPreScreen(t *testing.T) {
	r := cleanBrowserBotRequest()
	verdict, bs := CheckBotTwoPhase(r, nil, nil, 80)
	if verdict.IsBot {
		t.Errorf("clean browser should not be bot in two-phase, got %+v %+v", verdict, bs)
	}
	if verdict.RuleID != "bot:prescreen" {
		t.Errorf("expected bot:prescreen ruleID, got %q", verdict.RuleID)
	}
}

// 旧断言：sqlmap UA 走两阶段即判 bot（旧实现靠「恶意 UA 直接判死」短路，
// Score=95/Category=malicious）。
// 新断言：短路已删除，工具 UA 改走两条正交通道——加权总分（20% 权重下
// 单凭 UA 只到 observe）与危险标记（危险只保证「不低于挑战」，不一次性打死）。
func TestCheckBotTwoPhaseToolUAConstrainedByWeight(t *testing.T) {
	r := BotRequest{UserAgent: "sqlmap/1.8"}
	verdict, bs := CheckBotTwoPhase(r, nil, nil, 80)
	if !verdict.IsBot {
		t.Errorf("sqlmap UA should still be flagged as bot, got %+v", verdict)
	}
	if verdict.Score != bs.Total {
		t.Errorf("verdict score must equal weighted total: verdict=%d total=%d", verdict.Score, bs.Total)
	}
	if bs.UAScore == 0 {
		t.Errorf("UA module must carry the tool signal, got %+v", bs)
	}
	if !bs.Dangerous {
		t.Errorf("明确攻击工具 UA 必须置危险标记, got %+v", bs)
	}
	if verdict.Tier < TierChallenge {
		t.Errorf("危险标记必须把档位抬到挑战以上, got %+v", verdict)
	}
	if verdict.Tier > TierChallenge {
		t.Errorf("工具 UA 单独不得直接拦截/断连, got %+v", verdict)
	}
	if ClassifyScore(bs.Total, 80) >= TierIntercept {
		t.Errorf("加权总分不得单凭 UA 进入拦截档: Total=%d", bs.Total)
	}
}

// 用户裁决第 3 条：curl 等常规自动化工具 UA 不得被直接处置，
// 即便是两阶段路径也不置危险、不高于记录档。
func TestCheckBotTwoPhaseAutomationUAStaysBenign(t *testing.T) {
	for _, ua := range []string{"curl/8.7.1", "wget/1.21", "python-requests/2.32", "Go-http-client/1.1"} {
		t.Run(ua, func(t *testing.T) {
			r := BotRequest{UserAgent: ua}
			verdict, bs := CheckBotTwoPhase(r, nil, nil, 80)
			if bs.Dangerous {
				t.Fatalf("常规自动化工具 UA 不得置危险: %+v", bs)
			}
			if verdict.Tier >= TierChallenge {
				t.Fatalf("常规自动化工具 UA 不得触发挑战及以上: %+v", verdict)
			}
			if bs.UAScore > 25 {
				t.Fatalf("常规自动化工具 UA 模块分必须保持低位: %+v", bs)
			}
		})
	}
}

// --- 五档边界值 ---

func TestClassifyScoreBandBoundaries(t *testing.T) {
	cases := []struct {
		total int
		want  BotTier
	}{
		{39, TierPass}, {40, TierObserve}, {59, TierObserve}, {60, TierChallenge},
		{79, TierChallenge}, {80, TierIntercept}, {89, TierIntercept}, {90, TierDrop}, {100, TierDrop},
	}
	for _, c := range cases {
		if got := ClassifyScore(c.total, 80); got != c.want {
			t.Errorf("ClassifyScore(%d, 80) = %d, want %d", c.total, got, c.want)
		}
	}
	if got := ClassifyScore(0, 0); got != TierPass {
		t.Errorf("ClassifyScore(0, 0) = %d, want pass (default threshold 80)", got)
	}
	if got := ClassifyScore(45, 60); got != TierChallenge {
		t.Errorf("ClassifyScore(45, 60) = %d, want challenge (threshold-derived bands)", got)
	}
}

func TestBotTierCategoryAndLogAction(t *testing.T) {
	cases := []struct {
		tier     BotTier
		category string
		action   string
	}{
		{TierPass, "bot_pass", "allow"},
		{TierObserve, "bot_observe", "observe"},
		{TierChallenge, "bot_challenge", "challenge"},
		{TierIntercept, "bot_intercept", "intercept"},
		{TierDrop, "bot_drop", "drop"},
	}
	for _, c := range cases {
		if got := c.tier.Category(); got != c.category {
			t.Errorf("tier %d category = %q, want %q", c.tier, got, c.category)
		}
		if got := c.tier.LogAction(); got != c.action {
			t.Errorf("tier %d action = %q, want %q", c.tier, got, c.action)
		}
	}
}

// --- 行为模块 ---

func TestBehaviorScoreFromCountLadder(t *testing.T) {
	cases := []struct {
		count, max, want int
	}{
		{10, 100, 0}, {149, 100, 0}, {150, 100, 30}, {199, 100, 30},
		{200, 100, 60}, {299, 100, 60}, {300, 100, 100}, {5000, 100, 100},
		{5, 0, 0}, {0, 100, 0}, {-1, 100, 0},
	}
	for _, c := range cases {
		if got := BehaviorScoreFromCount(c.count, c.max); got != c.want {
			t.Errorf("BehaviorScoreFromCount(%d, %d) = %d, want %d", c.count, c.max, got, c.want)
		}
	}
}

func TestDeepScoreWithBehaviorRaisesTotal(t *testing.T) {
	r := cleanBrowserBotRequest()
	base := DeepScore(r, nil, nil)
	boosted := DeepScoreWithBehavior(r, nil, nil, 100)
	if boosted.BehaviorScore <= base.BehaviorScore {
		t.Fatalf("behavior module not applied: base=%+v boosted=%+v", base, boosted)
	}
	if boosted.Total != base.Total+boosted.BehaviorScore-base.BehaviorScore {
		t.Fatalf("total must track the weighted behaviour delta: base=%d boosted=%d", base.Total, boosted.Total)
	}
	// 干净浏览器也不该被行为模块单独推到处置档以上。
	if boosted.Total >= 80 {
		t.Fatalf("behaviour alone must not reach the intercept band, got %d", boosted.Total)
	}
	// 常规工具 UA + 高频行为叠加后应进入处置区间。
	auto := BotRequest{
		UserAgent:      "curl/8.7.1",
		AcceptHeader:   "text/html",
		AcceptLanguage: "en-US",
		AcceptEncoding: "gzip",
	}
	combined := DeepScoreWithBehavior(auto, nil, nil, 100)
	if combined.Total <= DeepScore(auto, nil, nil).Total {
		t.Fatalf("behaviour signal must raise the automation score: %+v", combined)
	}
}

// --- PreScreen ---

func TestPreScreenEmptyUAPassesWhenNoIPRep(t *testing.T) {
	r := BotRequest{UserAgent: ""}
	// 空UA 不在 maliciousToolUA 中，无 IPRep，无 Geo → PreScreen 应 false
	if PreScreen(r, nil, nil) {
		t.Error("empty UA should pass PreScreen (not in malicious tool list)")
	}
}

// --- helper ---

// TestHeaderOrderScoreDetectsAlphabeticOrder 归位自 tlsfp 子包：被测函数属 bot 评分职责。
func TestHeaderOrderScoreDetectsAlphabeticOrder(t *testing.T) {
	score, reasons := headerOrderScore([]string{"accept", "accept-encoding", "host", "user-agent", "x-test"})
	if score == 0 || len(reasons) == 0 {
		t.Fatalf("expected suspicious score for alphabetic header order, score=%d reasons=%v", score, reasons)
	}
}

func containsReason(reasons []string, target string) bool {
	for _, r := range reasons {
		if r == target {
			return true
		}
	}
	return false
}
