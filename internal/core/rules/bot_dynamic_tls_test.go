package rules

import (
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/bot/tlsfp"
)

// 本文件用真实 botPhase.Execute 链路验证「TLS 指纹 + 上下文」动态判定：
// rules 层必须把 ctx.TLS 与 ctx.Host 传进 bot 判定，否则判定拿不到上下文，
// 动态判据在端到端路径上永远不生效。

// rtdChromeUA 是当前 Chrome 的完整桌面 UA。
const rtdChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

// rtdHeadlessChromeUA 是 Puppeteer/Playwright 默认的受控浏览器 UA。
const rtdHeadlessChromeUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/125.0.0.0 Safari/537.36"

// rtdBrowserHeaders 返回一套完整浏览器头。
func rtdBrowserHeaders(ua string) map[string]string {
	return map[string]string{
		"User-Agent":      ua,
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
		"Referer":         "https://example.com/",
		"Connection":      "keep-alive",
		"Cookie":          "sid=abc",
	}
}

// rtdChromeTLS 是真实 Chromium 的 ClientHello 结构（含 17613/ALPS 与 GREASE 占位值）。
func rtdChromeTLS() tlsfp.TLSClientFingerprint {
	return tlsfp.TLSClientFingerprint{
		JA4:          "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		TLSVersion:   "TLS13",
		SNI:          "example.com",
		ALPN:         []string{"h2", "http/1.1"},
		ALPNRaw:      []string{"h2", "http/1.1"},
		CipherSuites: []uint16{0x1301, 0x1302, 0xc02b},
		Extensions:   []uint16{0, 5, 10, 11, 13, 16, 18, 23, 43, 45, 51, 17613, 65281},
		Curves:       []uint16{0x0a0a, 4570, 29, 23},
	}
}

// rtdNonBrowserTLS 是「无 ALPS、无 GREASE、只声明 http/1.1」的非浏览器栈形态。
func rtdNonBrowserTLS() tlsfp.TLSClientFingerprint {
	return tlsfp.TLSClientFingerprint{
		JA4:          "t12d1207h1_d34a8e72043a_036209cd1ead",
		TLSVersion:   "TLS12",
		SNI:          "example.com",
		ALPN:         []string{"http/1.1"},
		ALPNRaw:      []string{"http/1.1"},
		CipherSuites: []uint16{0xc02b, 0xc02f},
		Extensions:   []uint16{0, 5, 10, 11, 13, 23, 65281},
		Curves:       []uint16{29, 23, 24},
	}
}

// rtdFirefoxUA 是当前 Firefox 的完整桌面 UA。
const rtdFirefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"

// rtdFirefoxTLS 是真实 Firefox 的 ClientHello 结构（无 ALPS、无 GREASE，声明 h2）。
func rtdFirefoxTLS() tlsfp.TLSClientFingerprint {
	return tlsfp.TLSClientFingerprint{
		JA4:          "t13d1715h2_5b57614c22b0_5c2c66f702b0",
		TLSVersion:   "TLS13",
		SNI:          "example.com",
		ALPN:         []string{"h2", "http/1.1"},
		ALPNRaw:      []string{"h2", "http/1.1"},
		CipherSuites: []uint16{0x1301, 0x1303, 0xc02b},
		Extensions:   []uint16{0, 5, 10, 11, 13, 16, 23, 28, 34, 35, 43, 45, 51, 65281},
		Curves:       []uint16{29, 23, 24, 25},
	}
}

// rtdCtx 构造带 Host 的请求上下文。
func rtdCtx(ua string, fp tlsfp.TLSClientFingerprint) *pipeline.RequestCtx {
	h := rtdBrowserHeaders(ua)
	ctx := &pipeline.RequestCtx{
		Method:  "GET",
		Path:    "/",
		Host:    "example.com",
		Bind:    ":443",
		SiteID:  11,
		Headers: h,
		TLS:     fp,
	}
	ctx.UserAgent = ua
	return ctx
}

// TestRulesDynamicTLSFakeBrowserIsTerminated 端到端：自称 Chrome 而非浏览器 TLS 实况
// 必须经 botPhase.Execute 被终止，且 action 不低于 challenge（危险下界）。
func TestRulesDynamicTLSFakeBrowserIsTerminated(t *testing.T) {
	ctx := rtdCtx(rtdChromeUA, rtdNonBrowserTLS())
	phase := NewBotPhaseWithGeo(nil, nil, 80)

	result, stop := phase.Execute(ctx)

	if ctx.BotScoreResult == nil {
		t.Fatal("非放行档必须写入 BotScoreResult")
	}
	if !ctx.BotScoreResult.Dangerous {
		t.Fatalf("确定性 TLS 矛盾必须置危险：%+v", ctx.BotScoreResult)
	}
	if !stop {
		t.Fatalf("危险请求必须终止，实际 action=%q", result.Type)
	}
	if result.Type != action.Challenge && result.Type != action.Intercept && result.Type != action.Drop {
		t.Fatalf("档位过低：action=%q（总分=%d）", result.Type, ctx.BotScoreResult.TotalScore)
	}
	if result.RuleIDStr != "bot:two_phase" {
		t.Fatalf("走的是动态判定分支时规则应为 bot:two_phase，实际 %q", result.RuleIDStr)
	}
}

// TestRulesDynamicTLSHeadlessIsTerminated 端到端：受控浏览器 UA + 容器级 TLS 实况
// 必须被终止。
func TestRulesDynamicTLSHeadlessIsTerminated(t *testing.T) {
	ctx := rtdCtx(rtdHeadlessChromeUA, rtdChromeTLS())
	phase := NewBotPhaseWithGeo(nil, nil, 80)

	result, stop := phase.Execute(ctx)

	if ctx.BotScoreResult == nil || !ctx.BotScoreResult.Dangerous {
		t.Fatalf("受控浏览器必须置危险：%+v", ctx.BotScoreResult)
	}
	if !stop || result.Type == action.Allow || result.Type == action.Observe {
		t.Fatalf("受控浏览器必须终止于挑战及以上，实际 action=%q stop=%v", result.Type, stop)
	}
}

// TestRulesDynamicTLSConsistentBrowserStaysAllowed 反向断言（防误伤）：UA 与 TLS
// 完全一致的浏览器请求在 rules 层必须放行、不写评分日志。
func TestRulesDynamicTLSConsistentBrowserStaysAllowed(t *testing.T) {
	ctx := rtdCtx(rtdChromeUA, rtdChromeTLS())
	phase := NewBotPhaseWithGeo(nil, nil, 80)

	result, stop := phase.Execute(ctx)

	if result.Type != action.Allow || stop {
		t.Fatalf("一致的浏览器请求应放行：action=%q stop=%v", result.Type, stop)
	}
	if ctx.BotScoreResult != nil {
		t.Fatalf("放行档不应写评分日志：%+v", ctx.BotScoreResult)
	}
}

/**
 * TestRulesDynamicTLSHostReachesBotRequest 接线断言：ctx.Host 必须被传进 bot 判定。
 *
 * 构造对照实验：两侧使用同一份 UA 与 ClientHello，只有 Host 不同（域名 ↔ IP
 * 字面量）。样本自称 Firefox 且只声明 http/1.1，因此两侧都会命中预筛动态入口
 * （ALPN 观测级矛盾），都会写评分日志；ClientHello 声明了 SNI，于是 IP 字面量
 * 那一侧还会多出「RFC 6066 禁止的 SNI」观测分。若 ctx.Host 未接线，两侧分数会
 * 完全相同，本用例即失败。
 *
 * 该观测量级很小，两侧都应保持放行且不置危险——本用例断言的是分数差与「不置
 * 危险」，处置由 TestRulesDynamicTLSFakeBrowserIsTerminated 覆盖。
 */
func TestRulesDynamicTLSHostReachesBotRequest(t *testing.T) {
	fp := rtdFirefoxTLS()
	fp.ALPN = []string{"http/1.1"}
	fp.ALPNRaw = []string{"http/1.1"}
	fp.JA4 = "t13d1715h1_5b57614c22b0_5c2c66f702b0"
	phase := NewBotPhaseWithGeo(nil, nil, 80)

	domainCtx := rtdCtx(rtdFirefoxUA, fp)
	domainResult, domainStop := phase.Execute(domainCtx)

	ipCtx := rtdCtx(rtdFirefoxUA, fp)
	ipCtx.Host = "203.0.113.9"
	ipResult, ipStop := phase.Execute(ipCtx)

	if domainCtx.BotScoreResult == nil || ipCtx.BotScoreResult == nil {
		t.Fatal("两侧都应写入 BotScoreResult，以便比较分数")
	}
	if ipCtx.BotScoreResult.FingerprintScore <= domainCtx.BotScoreResult.FingerprintScore {
		t.Fatalf("ctx.Host 未传入判定：IP 字面量 + SNI 的矛盾未抬升指纹模块分（domain=%d ip=%d）",
			domainCtx.BotScoreResult.FingerprintScore, ipCtx.BotScoreResult.FingerprintScore)
	}
	if ipCtx.BotScoreResult.Dangerous || domainCtx.BotScoreResult.Dangerous {
		t.Fatalf("观测级矛盾不得置危险：domain=%v ip=%v",
			domainCtx.BotScoreResult.DangerReasons, ipCtx.BotScoreResult.DangerReasons)
	}
	if domainResult.Type != action.Allow || ipResult.Type != action.Allow {
		t.Fatalf("观测级证据不得改变处置：domain=%q ip=%q", domainResult.Type, ipResult.Type)
	}
	if domainStop || ipStop {
		t.Fatalf("观测级证据不得停止管道：domain=%v ip=%v", domainStop, ipStop)
	}
}
