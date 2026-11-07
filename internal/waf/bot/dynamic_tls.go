package bot

import (
	"net"
	"strings"

	"My-OpenWaf/internal/waf/bot/tlsfp"
)

const tlsGREASEMarker uint16 = 0x0a0a

type uaBrowserFamily int

const (
	// uaFamilyUnknown 表示 UA 未自称任何浏览器族系（含空 UA）。
	uaFamilyUnknown uaBrowserFamily = iota
	// uaFamilyChromium 覆盖 Chrome/Chromium/Edge/Opera 与受控的 HeadlessChrome。
	uaFamilyChromium
	// uaFamilyFirefox 覆盖 Firefox 与 Firefox iOS。
	uaFamilyFirefox
	// uaFamilySafari 覆盖 Safari 与 iOS 上的其他 WebKit 浏览器。
	uaFamilySafari
)

/**
 * tlsStructurePresent 报告指纹是否带有可用于一致性判断的 ClientHello 结构。
 *
 * TLSVersion 单独存在不算结构：版本号回答不了「声明了哪些 ALPN」「有哪些扩展」
 * 「有没有 GREASE」,因此不能据它推断任何结构性矛盾。生产路径（TCP 前缀窃读与
 * h3 元数据转发）总是带上 ALPN/扩展/曲线，判定总是有据可依。
 *
 * @param fp TLS 指纹。
 * @return 存在结构数据时为 true。
 */
func tlsStructurePresent(fp tlsfp.TLSClientFingerprint) bool {
	return len(fp.Extensions) > 0 || len(fp.CipherSuites) > 0 || len(fp.Curves) > 0 ||
		len(fp.ALPN) > 0 || len(fp.ALPNRaw) > 0 || fp.SNI != "" || fp.JA4 != ""
}

/**
 * ja4ALPNCode 取 JA4 的 ALPN 段。
 *
 * JA4 首段形如 `t13d1516h2`（协议 1 位 + 版本 2 位 + SNI 指示 1 位 + 密码套件数
 * 2 位 + 扩展数 2 位 + ALPN 码 2 位），末两位就是解析层记录的 ALPN 码。客户端
 * 未声明 ALPN 时该段为 `00`（tlsfp.appendJA4FirstALPNStrings 的约定），因此
 * 空串表示「没有 JA4、无从判断」，`00` 才是「明确未声明 ALPN」。
 *
 * @param ja4 JA4 字符串。
 * @return 两位 ALPN 码；无法取得时为空串。
 */
func ja4ALPNCode(ja4 string) string {
	if ja4 == "" {
		return ""
	}
	head := ja4
	if i := strings.IndexByte(head, '_'); i >= 0 {
		head = head[:i]
	}
	if len(head) < 2 {
		return ""
	}
	return head[len(head)-2:]
}

/**
 * ja4SNIIndicator 取 JA4 的 SNI 指示位。
 *
 * 该位位于首段第 4 个字符（下标 3）：`t` + 版本 2 位 + `d`/`i`。
 *
 * @param ja4 JA4 字符串。
 * @return 'd'（有 SNI）、'i'（无 SNI），或 0 表示 JA4 缺失/格式不识别。
 */
func ja4SNIIndicator(ja4 string) byte {
	if len(ja4) < 4 {
		return 0
	}
	switch ja4[3] {
	case 'd':
		return 'd'
	case 'i':
		return 'i'
	default:
		return 0
	}
}

/**
 * tlsDeclaredHTTP2Like 报告客户端是否声明了 h2 或 h3。
 *
 * @param fp TLS 指纹。
 * @return 声明列表（或 JA4 兜底）含 h2/h3 时为 true。
 */
func tlsDeclaredHTTP2Like(fp tlsfp.TLSClientFingerprint) bool {
	declared := fp.DeclaredALPN()
	for _, proto := range declared {
		if alpnIsHTTP2Or3(proto) {
			return true
		}
	}
	if len(declared) > 0 {
		return false
	}
	return alpnIsHTTP2Or3(ja4ALPNCode(fp.JA4))
}

// alpnIsHTTP2Or3 判断单个 ALPN 串是否为 h2/h3。
func alpnIsHTTP2Or3(proto string) bool {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "h2", "h3":
		return true
	}
	return false
}

/**
 * tlsExtensionListKnown 报告扩展列表是否已解析。
 *
 * 「没有 ALPS、没有 GREASE」这类否定结论只能建立在已解析的列表上；列表为空时
 * 分不清「客户端没发」与「解析层没拿到」，此时的否定属于无据推断。
 *
 * @param fp TLS 指纹。
 * @return 扩展列表非空时为 true。
 */
func tlsExtensionListKnown(fp tlsfp.TLSClientFingerprint) bool {
	return len(fp.Extensions) > 0
}

/**
 * tlsChromiumStructuralMarkers 报告 Chromium 系的两类结构性标记。
 *
 * alps   应用设置扩展（17513 旧编号 / 17613 新编号）。非 IANA 编号，实测只有
 *        Chrome 桌面版发送（含同栈的 iOS CriOS）；Edge、Safari、iOS WebKit、
 *        Firefox 与 Go 均不发。
 * grease RFC 8701 填充值。实测 Chrome、Edge、Safari、iOS WebKit 会发；
 *        Firefox 与 Go/Java 等通用栈不发。
 *
 * 两项标记在真实族系上的分布（逐条来自 uTLS 真实握手解析）：Chrome 桌面
 * alps+grease；Edge/Safari/iOS WebKit 仅 grease；Firefox/Go 两者皆无但声明 h2。
 * 因此 D1（自称 Chromium × 无 ALPS × 无 GREASE × 无 h2）对上述七种真实栈
 * 没有一种会误触发——Edge/Safari/iOS 靠 grease 豁免，Firefox/Go 靠 h2 豁免。
 *
 * @param fp TLS 指纹。
 * @return alps、grease 两项标记是否出现。
 */
func tlsChromiumStructuralMarkers(fp tlsfp.TLSClientFingerprint) (alps, grease bool) {
	for _, ext := range fp.Extensions {
		switch ext {
		case tlsExtensionApplicationSettings, tlsExtensionApplicationSettingsNew:
			alps = true
		}
	}
	return alps, tlsCarriesGREASE(fp)
}

/**
 * tlsCarriesGREASE 报告 ClientHello 是否携带 GREASE 填充值。
 *
 * @param fp TLS 指纹。
 * @return 密码套件、曲线、扩展任一列表含 GREASE 占位值时为 true。
 */
func tlsCarriesGREASE(fp tlsfp.TLSClientFingerprint) bool {
	for _, list := range [][]uint16{fp.Extensions, fp.CipherSuites, fp.Curves} {
		for _, value := range list {
			if value == tlsGREASEMarker {
				return true
			}
		}
	}
	return false
}

/**
 * tlsDeclaresSNI 报告 ClientHello 是否声明了 SNI。
 *
 * JA4 的指示位优先（它对「无 SNI」同样是权威结论），缺失时回退 SNI 字段。
 *
 * @param fp TLS 指纹。
 * @return 声明了 SNI 时为 true。
 */
func tlsDeclaresSNI(fp tlsfp.TLSClientFingerprint) bool {
	if indicator := ja4SNIIndicator(fp.JA4); indicator != 0 {
		return indicator == 'd'
	}
	return fp.SNI != ""
}

/**
 * browserFamilyFromUA 从 UA 字面解析自称的浏览器族系。
 *
 * 判定顺序 Chromium → Firefox → Safari：Chromium 系与 Safari 的 UA 都含
 * `Safari/…`（Chrome 的 UA 尾部即 `Safari/537.36`），先判 Chromium 才不会把
 * Chrome 误认成 Safari。
 *
 * @param ua User-Agent 原文。
 * @return 自称的族系；未自称浏览器时为 uaFamilyUnknown。
 */
func browserFamilyFromUA(ua string) uaBrowserFamily {
	lower := strings.ToLower(strings.TrimSpace(ua))
	if lower == "" {
		return uaFamilyUnknown
	}
	for _, token := range []string{"chrome/", "chromium/", "crios/", "edg/", "edgios/", "edga/", "headlesschrome/"} {
		if strings.Contains(lower, token) {
			return uaFamilyChromium
		}
	}
	for _, token := range []string{"firefox/", "fxios/"} {
		if strings.Contains(lower, token) {
			return uaFamilyFirefox
		}
	}
	if strings.Contains(lower, "safari/") {
		return uaFamilySafari
	}
	return uaFamilyUnknown
}

/**
 * hostRequiresSNI 报告该 Host 是否属于「浏览器必发 SNI」的形态。
 *
 * 只有域名才需要 SNI：RFC 6066 明确禁止用 IP 字面量做 SNI，浏览器对 IP 直连一律
 * 不发。Host 为空（无上下文可比对）时返回 false，此时不作该判据。
 *
 * @param host 请求 Host（可含端口或 IPv6 方括号）。
 * @return 需要 SNI 的域名形态时为 true。
 */
func hostRequiresSNI(host string) bool {
	trimmed := strings.TrimSpace(host)
	return trimmed != "" && !hostIsIPLiteral(trimmed)
}

/**
 * hostIsIPLiteral 报告 Host 是否为 IP 字面量（含 IPv6 方括号与 host:port 写法）。
 *
 * @param host 请求 Host。
 * @return 是 IP 字面量时为 true。
 */
func hostIsIPLiteral(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	if strings.HasPrefix(h, "[") {
		if end := strings.IndexByte(h, ']'); end > 1 {
			h = h[1:end]
		}
	} else if net.ParseIP(h) == nil {
		// 只在「恰好一个冒号」时按 host:port 去端口；多个冒号是 IPv6 字面量本身。
		if i := strings.LastIndexByte(h, ':'); i > 0 && strings.IndexByte(h, ':') == i {
			h = h[:i]
		}
	}
	return net.ParseIP(h) != nil
}
