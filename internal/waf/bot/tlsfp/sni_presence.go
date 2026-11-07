package tlsfp

/**
 * JA4 a 段的固定布局是 `<protocol:1><version:2><sni:1>`，因此下标 3 的字符
 * 就是 ClientHello 中 server_name 扩展的存在标记。
 *
 * 该布局由本包 buildJA4StringRaw / buildJA4String /
 * buildJA4StringFromClientHelloInfo 三个构建器共同保证；标记语义与 go-ja4
 * 的 unmarshalSNI 一致：'d' 表示扩展存在，'i' 表示扩展不存在。
 */
const ja4SNIMarkerOffset = 3

const (
	// SNIPresencePresent 表示 ClientHello 携带了 server_name 扩展。
	SNIPresencePresent = "present"
	// SNIPresenceAbsent 表示这次握手已确认客户端没有发送 server_name 扩展。
	//
	// RFC 6066 只允许 SNI 里放 DNS 名，客户端用 IP 字面量访问时（Go 的
	// crypto/tls 在 handshake_client.go 的 hostnameInSNI 里显式返回空串）
	// 就不会发出该扩展，因此这种情况是协议上正确的，不是采集故障。
	SNIPresenceAbsent = "absent"
	// SNIPresenceUnknown 表示未取得可判定该扩展存在性的证据（例如明文请求，
	// 或既无 JA4 又无握手信息）。空串即未知，便于 omitempty。
	SNIPresenceUnknown = ""
)

/**
 * SNIPresenceFromValues 判定「tls_sni 为空」的两种含义，供日志读取侧使用。
 *
 * 判定顺序是：
 *  1. SNI 名非空 → 扩展必然存在；
 *  2. JA4 存在 → 读它的 a 段标记：'d' 判 present、'i' 判 absent；
 *  3. JA4 缺位但有握手信息 → 服务端 TLS 栈自己解析过 ClientHello，报出的
 *     ServerName 为空即「客户端没发扩展」，判 absent；
 *  4. 两者都没有（明文请求、连接未完成握手）→ 无法判定。
 *
 * 第 3 步是必要的：这条路径同时服务「有 JA4 但无 SNI」与「开着窃读、但客户端
 * 根本没发 SNI 扩展」——后者在 Go 的 crypto/tls 里会以连接级 ServerName 为空
 * 的形式回填进来，此时 JA4 虽然存在（窃读已解析），但指纹里可能只剩握手字段。
 *
 * @param sni ClientHello 解析出的 SNI 名，可能为空。
 * @param ja4 同一个 ClientHello 的 JA4 指纹，可能为空。
 * @param hasClientHelloMetadata 是否已取得该连接的 ClientHello 派生信息。
 * @return SNIPresencePresent / SNIPresenceAbsent / SNIPresenceUnknown。
 */
func SNIPresenceFromValues(sni string, ja4 string, hasClientHelloMetadata bool) string {
	if sni != "" {
		return SNIPresencePresent
	}
	if !hasClientHelloMetadata {
		return SNIPresenceUnknown
	}
	if len(ja4) <= ja4SNIMarkerOffset {
		// 已解析过 ClientHello，但 JA4 缺位（未开窃读、或该指纹被上游丢弃）：
		// 此时「无 SNI 名」只能来自连接级握手信息，按协议含义务判为 absent。
		return SNIPresenceAbsent
	}
	switch ja4[ja4SNIMarkerOffset] {
	case 'd':
		return SNIPresencePresent
	case 'i':
		return SNIPresenceAbsent
	default:
		return SNIPresenceUnknown
	}
}

/**
 * HasClientHelloMetadata 表示这份指纹是否携带可证明「ClientHello 已解析」的字段。
 *
 * 判定依据是 TLSVersion：连接级握手回填只写 TLSVersion / SNI / ALPN，而
 * ClientHello 解析产出的指纹里 TLSVersion 一定非空（JA3 与 JA4 都建立在它之上）。
 * 换句话说，TLSVersion 非空即代表连接上确实解析到了 ClientHello。
 */
func (f TLSClientFingerprint) HasClientHelloMetadata() bool {
	return f.TLSVersion != ""
}

/**
 * SNIPresence 返回该指纹所记录的 server_name 扩展存在性。
 *
 * @return SNIPresencePresent / SNIPresenceAbsent / SNIPresenceUnknown。
 */
func (f TLSClientFingerprint) SNIPresence() string {
	return SNIPresenceFromValues(f.SNI, f.JA4, f.HasClientHelloMetadata())
}
