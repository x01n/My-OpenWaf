package bot

import (
	"strings"
)

const (
	tlsExtensionApplicationSettings    uint16 = 17513
	tlsExtensionApplicationSettingsNew uint16 = 17613
)

const (
	// 自称浏览器族系，但声明的 ALPN 既无 h2 也无 h3。
	tlsWeightALPNUAMismatch = 18
	// 自称浏览器族系，却未声明 SNI，而 Host 是需要 SNI 的域名。
	tlsWeightSNIMissingForDNS = 10
	// 自称浏览器族系，Host 是 IP 字面量，却声明了 SNI（RFC 6066 禁止）。
	tlsWeightSNIForIPHost = 8
	// 浏览器级 ClientHello 搭配「未自称浏览器」的 UA。
	tlsWeightBrowserStackForeignUA = 25
)

// 确定性判据在 Fingerprint 模块中的权重：同样计入模块分，让日志里的
// FingerprintScore 反映证据强度，但终止由 Dangerous 通道负责。
const (
	// 自称 Chromium 系，已解析的扩展与 ALPN 却同时否定 Chromium 的三项结构特征。
	tlsWeightFakeBrowserClaim = 30
	// UA 为空，却携带浏览器级 ClientHello。
	tlsWeightBrowserStackNoUA = 30
	// UA 自称受程序控制的浏览器，实况确认为浏览器栈。
	tlsWeightAutomationBrowserUA = 40
)

// 判据原因码：写入 Details["fingerprint"] 与 DangerReasons，供日志与归因。
const (
	tlsReasonFakeBrowserClaim      = "tls_fake_browser_claim"
	tlsReasonBrowserStackNoUA      = "tls_browser_stack_without_ua"
	tlsReasonAutomationBrowserUA   = "tls_automation_browser_ua"
	tlsReasonALPNUAMismatch        = "tls_alpn_ua_mismatch"
	tlsReasonSNIMissingForDNS      = "tls_no_sni_for_dns_host"
	tlsReasonSNIForIPHost          = "tls_sni_for_ip_host"
	tlsReasonBrowserStackForeignUA = "tls_browser_stack_foreign_ua"
)

// automationBrowserUATokens 标记「自称受程序控制的浏览器引擎」的 UA 字面。
//
// 这些 UA 主动声明自己是自动化浏览器（HeadlessChrome 是 Puppeteer/Playwright
// 驱动真实 Chromium 时的默认 UA），与 TLS 实况互证，因此不属伪装，而是
// 「已确认的自动化浏览器」——结论由 UA 声明给出、TLS 只作佐证。
var automationBrowserUATokens = []string{
	"headlesschrome", "headless", "phantomjs", "puppeteer", "playwright",
	"electron/", "nightmare", "slimerjs", "splash/",
}

/**
 * dynamicTLSVerdict 是「TLS 指纹 + 上下文」判定的结果。
 *
 * Score 只影响 Fingerprint 模块的加权总分；Dangerous 走独立通道，由
 * applyDangerFloor 保证档位不低于挑战，两条通道互不换算。
 */
type dynamicTLSVerdict struct {
	Score         int
	Reasons       []string
	Dangerous     bool
	DangerReasons []string
}

// addWeighted 记入一条观测级矛盾：只抬 Fingerprint 模块分。
func (v *dynamicTLSVerdict) addWeighted(weight int, reason string) {
	v.Score += weight
	v.Reasons = append(v.Reasons, reason)
}

// addDangerous 记入一条确定性矛盾：同时抬分（让日志可见）并置危险标记。
func (v *dynamicTLSVerdict) addDangerous(weight int, reason string) {
	v.Dangerous = true
	v.DangerReasons = append(v.DangerReasons, reason)
	v.addWeighted(weight, reason)
}

/**
 * evaluateDynamicTLS 把 ClientHello 实况与请求自称的身份、Host 上下文对照。
 *
 * 确定性判据（走 Dangerous 通道，逐条说明其为何不可反驳）：
 *
 *	D1 tls_fake_browser_claim —— 自称 Chromium 系，而已解析的扩展列表与 ALPN 声明
 *	   同时否定三项链路上真实存在的结构特征：无 ALPS、无 GREASE、未声明 h2/h3。
 *	   三项都由浏览器协议栈在明文 ClientHello 中生成，且互为独立实现路径：
 *	   GREASE 自 Chrome 57 起稳定存在；ALPS 只有 Chrome 桌面版发送。实测分布为
 *	   Chrome 桌面 alps+grease、Edge/Safari/iOS WebKit 仅 grease、Firefox/Go
 *	   两者皆无但声明 h2，故任何真实 Chromium 构建至少满足其一，三项同时为假
 *	   意味着该 ClientHello 不是 Chromium 生成的。该结论由协议栈实现决定、
 *	   与客户端行为无关，故判为确定性。
 *	D2 tls_browser_stack_without_ua —— UA 为空，却携带浏览器级 ClientHello
 *	   （ALPS，或 GREASE 且声明 h2）。没有任何主流浏览器会省略 UA，故
 *	   「浏览器栈 + 空 UA」不可能是浏览器；缺少 UA 本身已让 UA 模块满分，
 *	   本判据把「空 UA」升级为确定性结论。
 *	D3 tls_automation_browser_ua —— UA 明说自己是受程序控制的浏览器（见
 *	   automationBrowserUATokens），实况确认为浏览器栈。UA 的自述与实况互证，
 *	   结论没有歧义；要求实况为浏览器栈，是为了让「工具 UA 伪装浏览器」落 D1
 *	   而不是落这里。该口径与 challenge/envcheck 把 headless UA 视为硬终止一致。
 *
 * 观测级判据（只计入 Fingerprint 模块加权分）：
 *
 *	W1 tls_alpn_ua_mismatch —— 自称浏览器族系且扩展列表已解析，却未声明 h2/h3。
 *	   真实浏览器一律声明 h2；但 TLS 中间设备或降级代理会重写 ALPN，故观测级。
 *	W2 tls_no_sni_for_dns_host —— 自称浏览器族系且未声明 SNI，而 Host 是域名。
 *	   浏览器对域名必发 SNI；隐私代理与抓取框架可能省略，故观测级。
 *	W3 tls_sni_for_ip_host —— 自称浏览器族系而 Host 是 IP 字面量，却声明了 SNI。
 *	   RFC 6066 禁止用 IP 字面量做 SNI，浏览器不会这样发；但非浏览器客户端与
 *	   中间设备可能不遵守，故观测级。
 *	W4 tls_browser_stack_foreign_ua —— 浏览器级 ClientHello 搭配未自称浏览器的 UA。
 *	   可能是嵌入了浏览器栈的应用（Electron/CEF 类）或伪造 UA 的工具，故观测级。
 *
 * @param r 请求特征；r.TLS 无结构数据时返回空结论。
 * @return 判定结果：加权分、原因码与危险标记。
 */
func evaluateDynamicTLS(r BotRequest) dynamicTLSVerdict {
	var v dynamicTLSVerdict
	if !tlsStructurePresent(r.TLS) {
		return v
	}

	ua := strings.TrimSpace(r.UserAgent)
	family := browserFamilyFromUA(ua)
	extensionsKnown := tlsExtensionListKnown(r.TLS)
	declaredHTTP2 := tlsDeclaredHTTP2Like(r.TLS)
	alps, grease := tlsChromiumStructuralMarkers(r.TLS)
	browserStack := alps || (grease && declaredHTTP2)

	switch {
	case ua == "":
		if browserStack {
			v.addDangerous(tlsWeightBrowserStackNoUA, tlsReasonBrowserStackNoUA)
		}
	case isAutomationBrowserUA(ua):
		if browserStack {
			v.addDangerous(tlsWeightAutomationBrowserUA, tlsReasonAutomationBrowserUA)
		}
	case family == uaFamilyChromium && extensionsKnown && !alps && !grease && !declaredHTTP2:
		v.addDangerous(tlsWeightFakeBrowserClaim, tlsReasonFakeBrowserClaim)
	case browserStack && family == uaFamilyUnknown:
		v.addWeighted(tlsWeightBrowserStackForeignUA, tlsReasonBrowserStackForeignUA)
	}

	return v.addBrowserContextualChecks(r, family, extensionsKnown, declaredHTTP2)
}

/**
 * addBrowserContextualChecks 追加只对「自称浏览器族系」成立的上下文一致性判据。
 *
 * 非浏览器客户端不声明 SNI 或 ALPN 是正常形态，对它们作这些判断只会制造误报，
 * 因此族系未知时直接返回。ALPN 判据在 D1 已命中时不再重复记分：D1 的前提本就
 * 含「未声明 h2/h3」，重复累加只是把同一份证据算两遍。
 *
 * @param r 请求特征。
 * @param family UA 自称的族系。
 * @param extensionsKnown 扩展列表是否已解析。
 * @param declaredHTTP2 实况是否声明 h2/h3。
 * @return 累加后的结论。
 */
func (v dynamicTLSVerdict) addBrowserContextualChecks(r BotRequest, family uaBrowserFamily, extensionsKnown, declaredHTTP2 bool) dynamicTLSVerdict {
	if family == uaFamilyUnknown {
		return v
	}
	if extensionsKnown && !declaredHTTP2 {
		alps, grease := tlsChromiumStructuralMarkers(r.TLS)
		if !(family == uaFamilyChromium && !alps && !grease) {
			v.addWeighted(tlsWeightALPNUAMismatch, tlsReasonALPNUAMismatch)
		}
	}
	if !tlsDeclaresSNI(r.TLS) && hostRequiresSNI(r.HostHeader) {
		v.addWeighted(tlsWeightSNIMissingForDNS, tlsReasonSNIMissingForDNS)
	}
	if tlsDeclaresSNI(r.TLS) && hostIsIPLiteral(r.HostHeader) {
		v.addWeighted(tlsWeightSNIForIPHost, tlsReasonSNIForIPHost)
	}
	return v
}

/**
 * dynamicPrescreenHit 报告是否存在「TLS 指纹 + 上下文」矛盾证据。
 *
 * 它把预筛从「三条件静态闸门」变成「快速排除 + 可疑证据入口」：名单与 GeoIP
 * 之外的动态证据也能让请求进入加权评分，而不是在预筛处被当成人工访问直接放行。
 *
 * @param r 请求特征。
 * @return 存在任一矛盾证据时为 true。
 */
func dynamicPrescreenHit(r BotRequest) bool {
	return len(evaluateDynamicTLS(r).Reasons) > 0
}

/**
 * isAutomationBrowserUA 报告 UA 是否自称受程序控制的浏览器引擎。
 *
 * @param ua User-Agent 原文。
 * @return 命中 automationBrowserUATokens 时为 true。
 */
func isAutomationBrowserUA(ua string) bool {
	lower := strings.ToLower(strings.TrimSpace(ua))
	if lower == "" {
		return false
	}
	for _, token := range automationBrowserUATokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}
