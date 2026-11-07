package bot

import (
	"net"
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/bot/tlsfp"
)

// ─────────────────────────────────────────────────────────────────────────────
// 机制断言：指纹构造自真实 ClientHello 结构，而非手写字段组合
// ─────────────────────────────────────────────────────────────────────────────

// dynamicChromeUAFull 是当前 Chrome 的完整桌面 UA。
const dynamicChromeUAFull = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

// dynamicFirefoxUAFull 是当前 Firefox 的完整桌面 UA。
const dynamicFirefoxUAFull = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"

// dynamicSafariUAFull 是 Safari 的完整桌面 UA。
const dynamicSafariUAFull = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"

// dynamicHeadlessChromeUAFull 是 Puppeteer/Playwright 驱动真实 Chromium 的默认 UA。
const dynamicHeadlessChromeUAFull = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/125.0.0.0 Safari/537.36"

/**
 * dynamicChromeStructure 返回一套「真实 Chromium 生成」的 ClientHello 结构字段。
 *
 * 取值来自对 utls HelloChrome_133 真实握手的解析结果（本包 temp/_botfp 探针的
 * 原始输出）：扩展 16 项且含 17613(ALPS)、曲线含 GREASE 占位值 0x0a0a、
 * 声明 ALPN 为 h2/http/1.1。这里只固化判定所依赖的结构特征，不复制整份列表。
 */
func dynamicChromeStructure() tlsfp.TLSClientFingerprint {
	return tlsfp.TLSClientFingerprint{
		JA4:          "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		TLSVersion:   "TLS13",
		SNI:          "example.com",
		ALPN:         []string{"h2", "http/1.1"},
		ALPNRaw:      []string{"h2", "http/1.1"},
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
		Extensions:   []uint16{0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 65037, 65281},
		Curves:       []uint16{0x0a0a, 4570, 29, 23, 24},
	}
}

/**
 * dynamicFirefoxStructure 返回一套「真实 Firefox 生成」的 ClientHello 结构字段。
 *
 * 同样取自 utls HelloFirefox_120 的解析结果：无 ALPS、无 GREASE，但声明 h2。
 */
func dynamicFirefoxStructure() tlsfp.TLSClientFingerprint {
	return tlsfp.TLSClientFingerprint{
		JA4:          "t13d1715h2_5b57614c22b0_5c2c66f702b0",
		TLSVersion:   "TLS13",
		SNI:          "example.com",
		ALPN:         []string{"h2", "http/1.1"},
		ALPNRaw:      []string{"h2", "http/1.1"},
		CipherSuites: []uint16{0x1301, 0x1303, 0x1302, 0xc02b},
		Extensions:   []uint16{0, 5, 10, 11, 13, 16, 23, 28, 34, 35, 43, 45, 51, 65037, 65281},
		Curves:       []uint16{29, 23, 24, 25, 256, 257},
	}
}

/**
 * dynamicHTTP11ClientStructure 返回一套「通用非浏览器 TLS 栈」的 ClientHello 结构，
 * 特征是只声明 http/1.1、无 ALPS、无 GREASE——okhttp / Java / 老式抓取框架的常见形态。
 *
 * 字段取自本包 probe 对 utls HelloAndroid_11_OkHttp 真实握手的解析结果
 * （ja4=t12d120700、扩展 7 项、曲线 3 项），并把「未声明 ALPN」的 00 段替换为
 * h1 以覆盖「明确只支持 http/1.1」这一更明确否定的形态。
 */
func dynamicHTTP11ClientStructure() tlsfp.TLSClientFingerprint {
	return tlsfp.TLSClientFingerprint{
		JA4:          "t12d1207h1_d34a8e72043a_036209cd1ead",
		TLSVersion:   "TLS12",
		SNI:          "example.com",
		ALPN:         []string{"http/1.1"},
		ALPNRaw:      []string{"http/1.1"},
		CipherSuites: []uint16{0xc02b, 0xc02f, 0xc013},
		Extensions:   []uint16{0, 5, 10, 11, 13, 23, 65281},
		Curves:       []uint16{29, 23, 24},
	}
}

// dynamicBrowserHeaders 返回一套完整浏览器请求头（不含 UA）。
func dynamicBrowserHeaders() map[string]string {
	return map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate, br",
		"Referer":         "https://example.com/",
		"Connection":      "keep-alive",
		"Cookie":          "sid=abc",
	}
}

// dynamicRequest 用指定 UA 构造一个带完整浏览器头与 Host 的请求。
func dynamicRequest(ua string, fp tlsfp.TLSClientFingerprint) BotRequest {
	r := NewBotRequest("GET", "/", dynamicBrowserHeaders())
	r.UserAgent = ua
	r.TLS = fp
	r.HostHeader = "example.com"
	return r
}

// ─────────────────────────────────────────────────────────────────────────────
// 一、确定性矛盾：伪装浏览器 UA + 非浏览器 TLS 实况 → 不再落入 human/prescreen
// ─────────────────────────────────────────────────────────────────────────────

// TestDynamicFakeBrowserClaimNoLongerHuman 断言「自称 Chrome 但实况连 ALPS/GREASE/
// h2 都没有」的请求必须离开 human/prescreen 直通分支，并带确定性危险标记。
func TestDynamicFakeBrowserClaimNoLongerHuman(t *testing.T) {
	r := dynamicRequest(dynamicChromeUAFull, dynamicHTTP11ClientStructure())
	// 先确认该实况确实没有任何 Chromium 结构标记——否则这条用例测的不是目标判据。
	alps, grease := tlsChromiumStructuralMarkers(r.TLS)
	if alps || grease || tlsDeclaredHTTP2Like(r.TLS) {
		t.Fatalf("样本前提不成立：alps=%v grease=%v h2=%v", alps, grease, tlsDeclaredHTTP2Like(r.TLS))
	}

	got, bs := CheckBotTwoPhase(r, nil, nil, 80)

	if got.RuleID == "bot:prescreen" || got.Category == "human" {
		t.Fatalf("伪装浏览器必须离开预筛直通分支，实际 %+v", got)
	}
	if !got.Dangerous || !bs.Dangerous {
		t.Fatalf("确定性矛盾必须置危险标记：verdict=%+v score=%+v", got, bs)
	}
	if got.Tier < TierChallenge {
		t.Fatalf("危险下界必须把档位抬到挑战及以上，实际 %s", got.Tier.Category())
	}
	if bs.Raw.Fingerprint == 0 {
		t.Fatalf("确定性矛盾必须计入指纹模块原始分：%+v", bs.Raw)
	}
	if !strings.Contains(bs.Details["fingerprint"], tlsReasonFakeBrowserClaim) {
		t.Fatalf("指纹详情缺原因码 %q：%v", tlsReasonFakeBrowserClaim, bs.Details)
	}
	if !containsReason(bs.DangerReasons, tlsReasonFakeBrowserClaim) {
		t.Fatalf("危险来源缺原因码 %q：%v", tlsReasonFakeBrowserClaim, bs.DangerReasons)
	}
}

// TestDynamicFakeBrowserClaimDoesNotFireForRealBrowsers 反向断言：三种真实浏览器的
// ClientHello 结构（Chromium 有 ALPS+GREASE、Firefox 无标记但声明 h2、
// Safari 有 GREASE）都不得触发确定性判据。
func TestDynamicFakeBrowserClaimDoesNotFireForRealBrowsers(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		fp   tlsfp.TLSClientFingerprint
	}{
		{"chromium", dynamicChromeUAFull, dynamicChromeStructure()},
		{"firefox", dynamicFirefoxUAFull, dynamicFirefoxStructure()},
		{"safari_grease_no_alps", dynamicSafariUAFull, tlsfp.TLSClientFingerprint{
			JA4: "t13d2014h2_a09f3c656075_d8a2da3f94cd", TLSVersion: "TLS13",
			SNI: "example.com", ALPN: []string{"h2", "http/1.1"}, ALPNRaw: []string{"h2", "http/1.1"},
			CipherSuites: []uint16{0x1301, 0x1302, 0xc02b},
			Extensions:   []uint16{0, 5, 10, 11, 13, 16, 23, 43, 45, 51, 65281},
			Curves:       []uint16{0x0a0a, 29, 23, 24},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := evaluateDynamicTLS(dynamicRequest(tc.ua, tc.fp))
			if v.Dangerous {
				t.Fatalf("真实浏览器被误判为确定性矛盾：reasons=%v", v.DangerReasons)
			}
			if v.Score != 0 {
				t.Fatalf("真实浏览器不应产生任何矛盾分：score=%d reasons=%v", v.Score, v.Reasons)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 二、反向断言：UA 与 TLS 一致的正常浏览器仍然 human/pass
// ─────────────────────────────────────────────────────────────────────────────

// TestDynamicConsistentBrowserStaysHuman 断言 TLS 与 UA 完全一致的浏览器请求
// 既不命中预筛动态入口，也不产生任何处置。
func TestDynamicConsistentBrowserStaysHuman(t *testing.T) {
	r := dynamicRequest(dynamicChromeUAFull, dynamicChromeStructure())
	if PreScreen(r, nil, nil) {
		t.Fatal("一致的浏览器请求不应命中预筛")
	}
	got, bs := CheckBotTwoPhase(r, nil, nil, 80)
	if got.IsBot || got.Tier != TierPass || got.Category != "human" || got.RuleID != "bot:prescreen" {
		t.Fatalf("一致的浏览器请求应保持 human/prescreen，实际 %+v", got)
	}
	if bs.Total != 0 {
		t.Fatalf("预筛未命中时不应产生评分，实际 Total=%d", bs.Total)
	}
	// 逐条确认上下文判据都不成立，避免「恰好整体为 0」掩盖单条误报。
	if hostRequiresSNI(r.HostHeader) == false {
		t.Fatal("样本 Host 应为域名，否则 SNI 判据测不到")
	}
	if !tlsDeclaresSNI(r.TLS) || !tlsDeclaredHTTP2Like(r.TLS) {
		t.Fatal("样本应声明 SNI 与 h2，否则一致性前提不成立")
	}
}

// TestDynamicConsistentFirefoxStaysHuman 用另一族系（无 ALPS/GREASE 更少标记的
// Firefox）验证一致性路径不依赖 Chromium 专属结构。
func TestDynamicConsistentFirefoxStaysHuman(t *testing.T) {
	r := dynamicRequest(dynamicFirefoxUAFull, dynamicFirefoxStructure())
	if PreScreen(r, nil, nil) {
		t.Fatal("一致的 Firefox 请求不应命中预筛")
	}
	got, _ := CheckBotTwoPhase(r, nil, nil, 80)
	if got.RuleID != "bot:prescreen" || got.IsBot {
		t.Fatalf("一致的 Firefox 请求应保持预筛直通，实际 %+v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 三、观测级判据：只抬加权分，不置危险
// ─────────────────────────────────────────────────────────────────────────────

// TestDynamicALPNMismatchIsWeightedOnly 自称浏览器却声明只有 http/1.1（无 h2/h3）
// 时应进入评分并抬指纹模块分，但不得被置为危险——中间设备可能重写 ALPN。
func TestDynamicALPNMismatchIsWeightedOnly(t *testing.T) {
	fp := dynamicChromeStructure()
	fp.JA4 = "t13d1515h1_8daaf6152771_d8a2da3f94cd"
	fp.ALPN = []string{"http/1.1"}
	fp.ALPNRaw = []string{"http/1.1"}
	r := dynamicRequest(dynamicChromeUAFull, fp)

	if !PreScreen(r, nil, nil) {
		t.Fatal("ALPN 矛盾应作为预筛动态入口命中")
	}
	got, bs := CheckBotTwoPhase(r, nil, nil, 80)
	if got.RuleID == "bot:prescreen" {
		t.Fatalf("预筛命中后不应再返回直通结果：%+v", got)
	}
	if bs.Dangerous {
		t.Fatalf("ALPN 矛盾是观测级证据，不得置危险：%v", bs.DangerReasons)
	}
	if !containsReason(bs.DangerReasons, "") && len(bs.DangerReasons) != 0 {
		t.Fatalf("观测级证据不应写危险来源：%v", bs.DangerReasons)
	}
	if !strings.Contains(bs.Details["fingerprint"], tlsReasonALPNUAMismatch) {
		t.Fatalf("指纹详情缺原因码 %q：%v", tlsReasonALPNUAMismatch, bs.Details)
	}
	v := evaluateDynamicTLS(r)
	if v.Score != tlsWeightALPNUAMismatch {
		t.Fatalf("该样本应只命中 ALPN 判据一次：score=%d reasons=%v", v.Score, v.Reasons)
	}
}

// TestDynamicNoSNIForDNSHostIsWeightedOnly 自称浏览器族系、Host 是域名，但
// ClientHello 未声明 SNI（JA4 指示位为 i）时应只抬分。
func TestDynamicNoSNIForDNSHostIsWeightedOnly(t *testing.T) {
	fp := dynamicChromeStructure()
	fp.SNI = ""
	fp.JA4 = "t13i1516h2_8daaf6152771_d8a2da3f94cd"
	r := dynamicRequest(dynamicChromeUAFull, fp)

	v := evaluateDynamicTLS(r)
	if v.Dangerous {
		t.Fatalf("缺少 SNI 是观测级证据，不得置危险：%v", v.DangerReasons)
	}
	if !containsReason(v.Reasons, tlsReasonSNIMissingForDNS) {
		t.Fatalf("应命中 %q，实际 %v", tlsReasonSNIMissingForDNS, v.Reasons)
	}
	if !PreScreen(r, nil, nil) {
		t.Fatal("该矛盾应让请求进入评分路径")
	}
}

// TestDynamicSNIForIPHostIsWeightedOnly 断言「Host 是 IP 字面量 + 声明了 SNI」
// 只抬分不置危险，并覆盖 host:port 与 IPv6 两种写法。
func TestDynamicSNIForIPHostIsWeightedOnly(t *testing.T) {
	for _, host := range []string{"203.0.113.9", "203.0.113.9:8443", "[2001:db8::1]", "[2001:db8::1]:8443"} {
		t.Run(host, func(t *testing.T) {
			if !hostIsIPLiteral(host) {
				t.Fatalf("hostIsIPLiteral(%q) = false，样本前提不成立", host)
			}
			r := dynamicRequest(dynamicChromeUAFull, dynamicChromeStructure())
			r.HostHeader = host
			v := evaluateDynamicTLS(r)
			if v.Dangerous {
				t.Fatalf("IP 直连 + SNI 是观测级证据，不得置危险：%v", v.DangerReasons)
			}
			if !containsReason(v.Reasons, tlsReasonSNIForIPHost) {
				t.Fatalf("应命中 %q，实际 %v", tlsReasonSNIForIPHost, v.Reasons)
			}
		})
	}
}

// TestDynamicIPHostWithoutSNIIsClean 反向断言：IP 直连且未发 SNI（真实浏览器的
// 做法）不得被记分，更不得被预筛动态入口命中。这是「不误伤内网 IP 直连运维访问」
// 的机制护栏。
func TestDynamicIPHostWithoutSNIIsClean(t *testing.T) {
	fp := dynamicChromeStructure()
	fp.SNI = ""
	fp.JA4 = "t13i1516h2_8daaf6152771_d8a2da3f94cd"
	r := dynamicRequest(dynamicChromeUAFull, fp)
	r.HostHeader = "192.168.1.10"

	v := evaluateDynamicTLS(r)
	if len(v.Reasons) != 0 || v.Score != 0 || v.Dangerous {
		t.Fatalf("IP 直连且无 SNI 属正常形态，不应记分：score=%d reasons=%v", v.Score, v.Reasons)
	}
	if PreScreen(r, nil, nil) {
		t.Fatal("该请求不应命中预筛")
	}
	if got, _ := CheckBotTwoPhase(r, nil, nil, 80); got.RuleID != "bot:prescreen" {
		t.Fatalf("该请求应保持预筛直通，实际 %+v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 四、自动化浏览器 UA：UA 自述与 TLS 实况互证 → 确定性
// ─────────────────────────────────────────────────────────────────────────────

// TestDynamicAutomationBrowserUAIsDangerous 断言 HeadlessChrome（Puppeteer/Playwright
// 默认 UA）在实况确认为浏览器栈时被判为确定性矛盾。
func TestDynamicAutomationBrowserUAIsDangerous(t *testing.T) {
	r := dynamicRequest(dynamicHeadlessChromeUAFull, dynamicChromeStructure())

	got, bs := CheckBotTwoPhase(r, nil, nil, 80)
	if got.RuleID == "bot:prescreen" {
		t.Fatalf("受控浏览器必须进入评分路径，实际 %+v", got)
	}
	if !bs.Dangerous || !containsReason(bs.DangerReasons, tlsReasonAutomationBrowserUA) {
		t.Fatalf("受控浏览器应带 %q，实际 dangerous=%v reasons=%v",
			tlsReasonAutomationBrowserUA, bs.Dangerous, bs.DangerReasons)
	}
	if got.Tier < TierChallenge {
		t.Fatalf("危险下界未生效，档位 %s", got.Tier.Category())
	}
}

// TestDynamicAutomationBrowserUANeedsBrowserStack 反向断言：自称 HeadlessChrome 但
// 实况不是浏览器栈（无 ALPS、无 GREASE）时，该判据不成立——它要求 UA 自述与
// 实况互证，而不是单凭 UA 字面。
func TestDynamicAutomationBrowserUANeedsBrowserStack(t *testing.T) {
	r := dynamicRequest(dynamicHeadlessChromeUAFull, dynamicHTTP11ClientStructure())
	v := evaluateDynamicTLS(r)
	if containsReason(v.Reasons, tlsReasonAutomationBrowserUA) {
		t.Fatalf("实况非浏览器栈时不应命中 %q：%v", tlsReasonAutomationBrowserUA, v.Reasons)
	}
	if containsReason(v.Reasons, tlsReasonFakeBrowserClaim) {
		t.Fatalf("HeadlessChrome 走自动化判据，不应落到 %q", tlsReasonFakeBrowserClaim)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 五、浏览器级 TLS 栈 + 空 UA / 非浏览器 UA
// ─────────────────────────────────────────────────────────────────────────────

// TestDynamicBrowserStackWithoutUAIsDangerous 断言空 UA 搭配浏览器级 ClientHello
// 被判为确定性矛盾：没有主流浏览器会省略 UA。
func TestDynamicBrowserStackWithoutUAIsDangerous(t *testing.T) {
	r := dynamicRequest("", dynamicChromeStructure())
	v := evaluateDynamicTLS(r)
	if !v.Dangerous || !containsReason(v.DangerReasons, tlsReasonBrowserStackNoUA) {
		t.Fatalf("空 UA + 浏览器栈应带 %q，实际 dangerous=%v reasons=%v",
			tlsReasonBrowserStackNoUA, v.Dangerous, v.DangerReasons)
	}
	if !PreScreen(r, nil, nil) {
		t.Fatal("空 UA + 浏览器栈应命中预筛")
	}
}

// TestDynamicBrowserStackWithForeignUAIsWeightedOnly 断言浏览器栈搭配常规 HTTP 库
// UA 只抬分不置危险：Electron/CEF 类应用可能嵌入浏览器栈并带库 UA。
func TestDynamicBrowserStackWithForeignUAIsWeightedOnly(t *testing.T) {
	for _, ua := range []string{"okhttp/4.9.3", "axios/1.6.0", "Go-http-client/1.1"} {
		t.Run(ua, func(t *testing.T) {
			r := dynamicRequest(ua, dynamicChromeStructure())
			v := evaluateDynamicTLS(r)
			if v.Dangerous {
				t.Fatalf("库 UA + 浏览器栈是观测级证据，不得置危险：%v", v.DangerReasons)
			}
			if !containsReason(v.Reasons, tlsReasonBrowserStackForeignUA) {
				t.Fatalf("应命中 %q，实际 %v", tlsReasonBrowserStackForeignUA, v.Reasons)
			}
			if v.Score < tlsWeightBrowserStackForeignUA {
				t.Fatalf("观测分未计入：score=%d", v.Score)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 六、兼容边界：无 ClientHello 结构数据时行为与改造前一致
// ─────────────────────────────────────────────────────────────────────────────

// TestDynamicNoStructureNeverFires 断言仅带 TLSVersion（生产 h2 降级接管路径的
// 常见形态）或完全无指纹时，动态判据一律不命中。这正是四条既有预筛用例所处的
// 形态，是它们保持通过的机制保证。
func TestDynamicNoStructureNeverFires(t *testing.T) {
	cases := []struct {
		name      string
		userAgent string
		fp        tlsfp.TLSClientFingerprint
	}{
		{"empty_fp_chrome_ua", dynamicChromeUAFull, tlsfp.TLSClientFingerprint{}},
		{"version_only_chrome_ua", dynamicChromeUAFull, tlsfp.TLSClientFingerprint{TLSVersion: "TLS10"}},
		{"empty_fp_empty_ua", "", tlsfp.TLSClientFingerprint{}},
		{"version_only_headless", dynamicHeadlessChromeUAFull, tlsfp.TLSClientFingerprint{TLSVersion: "TLS13"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := dynamicRequest(tc.userAgent, tc.fp)
			if tlsStructurePresent(tc.fp) {
				t.Fatalf("样本前提不成立：该指纹被判为有结构")
			}
			v := evaluateDynamicTLS(r)
			if v.Score != 0 || v.Dangerous || len(v.Reasons) != 0 {
				t.Fatalf("无结构数据时动态判据必须沉默：%+v", v)
			}
			if PreScreen(r, nil, nil) {
				t.Fatal("无结构数据 + 非工具 UA 不应命中预筛")
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 七、辅助原语：JA4 取值与 Host 形态识别
// ─────────────────────────────────────────────────────────────────────────────

func TestDynamicJA4FieldExtraction(t *testing.T) {
	cases := []struct {
		ja4      string
		wantALPN string
		wantSNI  byte
	}{
		{"t13d1516h2_8daaf6152771_e5627efa2ab1", "h2", 'd'},
		{"t13i1516h2_8daaf6152771_e5627efa2ab1", "h2", 'i'},
		{"t12d120700_d34a8e72043a_036209cd1ead", "00", 'd'},
		{"", "", 0},
		{"t13d1516h2", "h2", 'd'},
	}
	for _, c := range cases {
		if got := ja4ALPNCode(c.ja4); got != c.wantALPN {
			t.Errorf("ja4ALPNCode(%q) = %q, want %q", c.ja4, got, c.wantALPN)
		}
		if got := ja4SNIIndicator(c.ja4); got != c.wantSNI {
			t.Errorf("ja4SNIIndicator(%q) = %q, want %q", c.ja4, got, c.wantSNI)
		}
	}
}

func TestDynamicHostFormClassification(t *testing.T) {
	cases := []struct {
		host        string
		wantIP      bool
		wantRequire bool
	}{
		{"example.com", false, true},
		{"example.com:8443", false, true},
		{"203.0.113.9", true, false},
		{"203.0.113.9:8443", true, false},
		{"[2001:db8::1]", true, false},
		{"[2001:db8::1]:8443", true, false},
		{"2001:db8::1", true, false},
		{"", false, false},
	}
	for _, c := range cases {
		if got := hostIsIPLiteral(c.host); got != c.wantIP {
			t.Errorf("hostIsIPLiteral(%q) = %v, want %v", c.host, got, c.wantIP)
		}
		if got := hostRequiresSNI(c.host); got != c.wantRequire {
			t.Errorf("hostRequiresSNI(%q) = %v, want %v", c.host, got, c.wantRequire)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 八、良性爬虫白名单必须动态验证：未校验 ≠ 已验证
// ─────────────────────────────────────────────────────────────────────────────

// TestDynamicGoodBotWhitelistRequiresVerification 断言良性爬虫短路不再无条件放行：
// 没有官方后缀表可校验的 UA 模式、以及无从校验的 nil IP，都不得走 "good" 短路。
func TestDynamicGoodBotWhitelistRequiresVerification(t *testing.T) {
	cases := []struct {
		name string
		ua   string
	}{
		{"no_dns_table_pattern", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"},
		{"semrush", "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)"},
		{"googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := matchGoodBotUA(BotRequest{UserAgent: tc.ua}); ok {
				t.Fatal("nil IP 无从反向 DNS 校验，不得短路为 good")
			}
			_, _, ok := matchGoodBotUA(BotRequest{UserAgent: tc.ua, ClientIP: net.ParseIP("203.0.113.77")})
			if ok {
				t.Fatal("未经反向 DNS 校验的 UA 不得短路为 good")
			}
		})
	}
	// 无官方后缀表的模式不得被当成「已验证」。
	if verifyGoodBotDNS(net.ParseIP("203.0.113.77"), 4) {
		t.Fatal("baiduspider 模式没有官方后缀表，必须返回未通过而非无条件通过")
	}
	if verifyGoodBotDNS(nil, 0) {
		t.Fatal("nil IP 必须返回未通过")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 九、接线断言：动态判据必须真的进入 DeepScore 的评分与详情
// ─────────────────────────────────────────────────────────────────────────────

// TestDynamicScoreReachesDeepScore 断言 DeepScore 自身（不经两阶段入口）也把动态
// 判据计入指纹模块，并把原因码写入详情、把确定性矛盾写入危险来源。
func TestDynamicScoreReachesDeepScore(t *testing.T) {
	t.Run("weighted_only", func(t *testing.T) {
		fp := dynamicChromeStructure()
		fp.ALPN = []string{"http/1.1"}
		fp.ALPNRaw = []string{"http/1.1"}
		r := dynamicRequest(dynamicChromeUAFull, fp)
		bs := DeepScore(r, nil, nil)
		if bs.Raw.Fingerprint < tlsWeightALPNUAMismatch {
			t.Fatalf("动态观测分未进入指纹模块：raw=%+v", bs.Raw)
		}
		if bs.Dangerous {
			t.Fatalf("观测级证据不得置危险：%v", bs.DangerReasons)
		}
		if !strings.Contains(bs.Details["fingerprint"], tlsReasonALPNUAMismatch) {
			t.Fatalf("详情缺原因码：%v", bs.Details)
		}
	})

	t.Run("dangerous", func(t *testing.T) {
		r := dynamicRequest(dynamicChromeUAFull, dynamicHTTP11ClientStructure())
		bs := DeepScore(r, nil, nil)
		if !bs.Dangerous || !containsReason(bs.DangerReasons, tlsReasonFakeBrowserClaim) {
			t.Fatalf("DeepScore 未带出确定性危险：dangerous=%v reasons=%v", bs.Dangerous, bs.DangerReasons)
		}
		if bs.Total <= 0 {
			t.Fatalf("加权总分应反映证据：%+v", bs)
		}
	})
}
