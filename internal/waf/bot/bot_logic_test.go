package bot

import (
	"testing"
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

// --- fingerprintScore ---

func TestFingerprintScoreEmptyUA(t *testing.T) {
	r := BotRequest{}
	score, reasons := fingerprintScore(r)
	if score < 40 {
		t.Errorf("empty ua should add >=40 score, got %d", score)
	}
	if !containsReason(reasons, "empty_ua") {
		t.Errorf("reasons should contain empty_ua, got %v", reasons)
	}
}

func TestFingerprintScoreShortUA(t *testing.T) {
	r := BotRequest{UserAgent: "ab", AcceptHeader: "text/html", AcceptLanguage: "en", AcceptEncoding: "gzip"}
	score, reasons := fingerprintScore(r)
	if !containsReason(reasons, "short_ua") {
		t.Errorf("reasons should contain short_ua, got %v", reasons)
	}
	if score < 25 {
		t.Errorf("short ua should add >=25 score, got %d", score)
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

func TestFingerprintScoreAutomationLibUA(t *testing.T) {
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
		_, reasons := fingerprintScore(r)
		if !containsReason(reasons, "automation_lib_ua") {
			t.Errorf("UA %q should trigger automation_lib_ua, got %v", ua, reasons)
		}
	}
}

func TestFingerprintScoreFakeMozilla(t *testing.T) {
	r := BotRequest{
		UserAgent:      "Mozilla/5.0 NoParentheses",
		AcceptHeader:   "text/html",
		AcceptLanguage: "en-US",
		AcceptEncoding: "gzip",
	}
	_, reasons := fingerprintScore(r)
	if !containsReason(reasons, "fake_mozilla") {
		t.Errorf("reasons should contain fake_mozilla, got %v", reasons)
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
		TLS:            TLSClientFingerprint{TLSVersion: "TLS10"},
	}
	_, reasons := fingerprintScore(r)
	if !containsReason(reasons, "legacy_tls_version") {
		t.Errorf("TLS10 should trigger legacy_tls_version, got %v", reasons)
	}
}

func TestFingerprintScoreCleanBrowserNoReasons(t *testing.T) {
	r := cleanBrowserBotRequest()
	score, reasons := fingerprintScore(r)
	// clean browser 应该没有 negative reasons，score 非常低或为0
	for _, bad := range []string{"empty_ua", "short_ua", "automation_lib_ua", "fake_mozilla", "legacy_tls_version"} {
		if containsReason(reasons, bad) {
			t.Errorf("clean browser should not trigger %q, score=%d reasons=%v", bad, score, reasons)
		}
	}
}

// --- CheckBot (默认 level=medium) ---

func TestCheckBotDefaultLevel(t *testing.T) {
	r := cleanBrowserBotRequest()
	got := CheckBot(r)
	if got.IsBot {
		t.Errorf("clean browser should not be bot, got %+v", got)
	}
}

// --- CheckBotWithLevel 阈值 ---

func TestCheckBotWithLevelSuspicious(t *testing.T) {
	// score >=40 但 <80 → suspicious
	r := BotRequest{
		UserAgent: "short",
		// no accept, no language, no encoding → 25(short_ua)+20+15+10 = 70 → suspicious
	}
	got := CheckBotWithLevel(r, "medium")
	if got.Category != "suspicious" && got.Category != "malicious" {
		t.Errorf("expected suspicious or malicious, got %+v", got)
	}
	if !got.IsBot {
		t.Errorf("suspicious request should be IsBot=true")
	}
}

func TestCheckBotWithLevelMaliciousHighScore(t *testing.T) {
	// empty UA + no accept + no language + no encoding ≥ 80 → malicious
	r := BotRequest{
		UserAgent:      "",
		AcceptHeader:   "",
		AcceptLanguage: "",
		AcceptEncoding: "",
		Method:         "POST",
		HasCookie:      false,
	}
	got := CheckBotWithLevel(r, "medium")
	if got.Category != "malicious" {
		t.Errorf("expected malicious, got %+v", got)
	}
	if !got.IsBot {
		t.Errorf("malicious request should be IsBot=true")
	}
	if got.RuleID != "bot:heuristic" {
		t.Errorf("expected bot:heuristic, got %q", got.RuleID)
	}
}

func TestCheckBotWithLevelGoodBotNoIP(t *testing.T) {
	// Googlebot UA with nil ClientIP → verifyGoodBotDNS 返回 true（无需验证或跳过）
	r := BotRequest{
		UserAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		ClientIP:  nil,
	}
	got := CheckBotWithLevel(r, "medium")
	if !got.IsBot || got.Category != "good" {
		t.Errorf("Googlebot UA without IP should be good bot, got %+v", got)
	}
}

// --- DeepScore 基础路径 ---

func TestDeepScoreNoGeoNoIPRep(t *testing.T) {
	r := cleanBrowserBotRequest()
	bs := DeepScore(r, nil, nil)
	// 无 GeoIP 和 IPRep，只有 fingerprint 分
	if bs.GeoIPScore != 0 {
		t.Errorf("GeoIPScore should be 0 without geo resolver, got %d", bs.GeoIPScore)
	}
	if bs.IPRepScore != 0 {
		t.Errorf("IPRepScore should be 0 without iprep, got %d", bs.IPRepScore)
	}
	if bs.Total != bs.FingerprintScore+bs.BehaviorScore {
		t.Errorf("Total mismatch: %d != FP(%d)+Behav(%d)", bs.Total, bs.FingerprintScore, bs.BehaviorScore)
	}
}

func TestDeepScoreHighRiskByFingerprintTotal(t *testing.T) {
	// empty UA + no headers → high fingerprint score → IsHighRisk when >=80
	r := BotRequest{}
	bs := DeepScore(r, nil, nil)
	if bs.Total < 80 && !bs.IsHighRisk {
		// 预期 score 较高，but 逻辑是 Total>=80 OR GeoIPScore>=40 OR IPRepScore>=25
		// empty UA(40)+no_accept(20)+no_language(15)+no_encoding(10) = 85 ≥ 80
		t.Errorf("expected IsHighRisk=true for empty request, Total=%d", bs.Total)
	}
}

func TestDeepScoreTLSDetailsRecorded(t *testing.T) {
	r := cleanBrowserBotRequest()
	r.TLS = TLSClientFingerprint{
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

func TestCheckBotTwoPhaseMaliciousUATriggersDeepScore(t *testing.T) {
	r := BotRequest{UserAgent: "sqlmap/1.8"}
	verdict, bs := CheckBotTwoPhase(r, nil, nil, 80)
	if !verdict.IsBot {
		t.Errorf("sqlmap UA should be bot in two-phase, got %+v", verdict)
	}
	_ = bs
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

func containsReason(reasons []string, target string) bool {
	for _, r := range reasons {
		if r == target {
			return true
		}
	}
	return false
}
