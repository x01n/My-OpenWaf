package snapshot

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"My-OpenWaf/internal/tlsmeta"
)

type NetworkDefaults struct {
	IPv6Enabled         bool   `json:"ipv6_enabled"`
	HTTP2Enabled        bool   `json:"http2_enabled"`
	HTTP3Enabled        bool   `json:"http3_enabled"`
	HTTP3Bind           string `json:"http3_bind"`
	HTTP3PerPortEnabled bool   `json:"http3_per_port_enabled"`
	DefaultALPN         string `json:"default_alpn"`
	DefaultNetwork      string `json:"default_network"`
}

type TLSDefaults struct {
	MinVersion               string `json:"min_version"`
	MaxVersion               string `json:"max_version"`
	CipherSuites             string `json:"cipher_suites"`
	DefaultALPN              string `json:"default_alpn"`
	HasExplicitDefaultALPN   bool   `json:"-"`
	CurvePreferences         string `json:"curve_preferences"`
	PreferServerCipherSuites bool   `json:"prefer_server_cipher_suites"`
	SessionTicketsEnabled    bool   `json:"session_tickets_enabled"`
	Allow0RTT                bool   `json:"allow_0rtt"`
	HasExplicitAllow0RTT     bool   `json:"-"`
	SelfSignedOnIP           bool   `json:"self_signed_on_ip"`
}

func DefaultALPNForProtocolSwitches(http2Enabled bool, http3Enabled bool) string {
	protos := make([]string, 0, 3)
	if http2Enabled {
		protos = append(protos, "h2")
	}
	if http3Enabled {
		protos = append(protos, "h3")
	}
	protos = append(protos, "http/1.1")
	return strings.Join(protos, ",")
}

/**
 * NormalizeALPNList 把逗号分隔的 ALPN 列表规范化为小写、去重、顺序稳定的形式。
 *
 * 自定义协议原样保留，不做白名单过滤——ALPN 的取值由站点自行决定，
 * 这里只负责等价写法归一（大小写、空白、重复项）。
 *
 * @param raw 站点配置的 ALPN 原串。
 * @return 规范化后的逗号分隔列表。
 */
func NormalizeALPNList(raw string) string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 3)
	for _, item := range strings.Split(raw, ",") {
		proto := strings.ToLower(strings.TrimSpace(item))
		if proto == "" {
			continue
		}
		if _, ok := seen[proto]; ok {
			continue
		}
		seen[proto] = struct{}{}
		out = append(out, proto)
	}
	return strings.Join(out, ",")
}

func DefaultNetworkDefaults() NetworkDefaults {
	return NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      ":443",
		DefaultALPN:    DefaultALPNForProtocolSwitches(true, true),
		DefaultNetwork: "tcp",
	}
}

func DefaultTLSDefaults() TLSDefaults {
	return TLSDefaults{
		MinVersion:               "TLS10",
		MaxVersion:               "TLS13",
		DefaultALPN:              DefaultALPNForProtocolSwitches(true, true),
		CurvePreferences:         "X25519,CurveP256,CurveP384",
		PreferServerCipherSuites: true,
		SessionTicketsEnabled:    true,
		SelfSignedOnIP:           true,
	}
}

/**
 * NormalizeNetwork 返回数据面监听可接受的 network 取值（net.Listen 口径）。
 *
 * @param raw 配置中的 network 原值。
 * @return tcp / tcp4 / tcp6 之一；其他取值返回空串表示非法。
 */
func NormalizeNetwork(raw string) string {
	network := strings.ToLower(strings.TrimSpace(raw))
	switch network {
	case "tcp", "tcp4", "tcp6":
		return network
	default:
		return ""
	}
}

/**
 * NormalizeHTTP3Bind 校验并规范化 HTTP/3 的 UDP 监听地址。
 *
 * 空串视为合法（表示不单独指定，沿用默认端口），此时第二个返回值为 true。
 *
 * @param raw 配置中的 HTTP/3 监听地址。
 * @return 规范化后的 host:port 与是否合法。
 */
func NormalizeHTTP3Bind(raw string) (string, bool) {
	bind := strings.TrimSpace(raw)
	if bind == "" {
		return "", true
	}
	host, portRaw, err := net.SplitHostPort(bind)
	if err != nil {
		return "", false
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1 || port > 65535 {
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), true
}

func normalizeNetworkDefaults(defaults NetworkDefaults) NetworkDefaults {
	if !defaults.IPv6Enabled &&
		!defaults.HTTP2Enabled &&
		!defaults.HTTP3Enabled &&
		strings.TrimSpace(defaults.HTTP3Bind) == "" &&
		strings.TrimSpace(defaults.DefaultALPN) == "" &&
		strings.TrimSpace(defaults.DefaultNetwork) == "" {
		return DefaultNetworkDefaults()
	}
	if strings.TrimSpace(defaults.DefaultALPN) == "" {
		defaults.DefaultALPN = DefaultALPNForProtocolSwitches(defaults.HTTP2Enabled, defaults.HTTP3Enabled)
	}
	defaults.DefaultALPN = NormalizeALPNList(defaults.DefaultALPN)
	if normalizedNetwork := NormalizeNetwork(defaults.DefaultNetwork); normalizedNetwork != "" {
		defaults.DefaultNetwork = normalizedNetwork
	} else {
		defaults.DefaultNetwork = DefaultNetworkDefaults().DefaultNetwork
	}
	if defaults.HTTP3Enabled && strings.TrimSpace(defaults.HTTP3Bind) == "" {
		defaults.HTTP3Bind = DefaultNetworkDefaults().HTTP3Bind
	}
	if normalizedBind, ok := NormalizeHTTP3Bind(defaults.HTTP3Bind); ok {
		defaults.HTTP3Bind = normalizedBind
	} else {
		defaults.HTTP3Bind = DefaultNetworkDefaults().HTTP3Bind
	}
	return defaults
}

/**
 * HTTP3BindFromTCPBind 由 TCP 监听地址推导「每端口一个 HTTP/3 监听」时的 UDP 监听地址。
 *
 * @param tcpBind 站点 TCP 监听地址。
 * @return 规范化后的 UDP 监听地址与是否可解析。
 */
func HTTP3BindFromTCPBind(tcpBind string) (string, bool) {
	_, portRaw, err := net.SplitHostPort(strings.TrimSpace(tcpBind))
	if err != nil {
		return "", false
	}
	port, err := strconv.Atoi(strings.TrimSpace(portRaw))
	if err != nil || port < 1 || port > 65535 {
		return "", false
	}
	return net.JoinHostPort("", strconv.Itoa(port)), true
}

func LoadNetworkDefaults(raw string) NetworkDefaults {
	cfg := DefaultNetworkDefaults()
	if strings.TrimSpace(raw) == "" {
		return cfg
	}
	var explicit struct {
		DefaultALPN *string `json:"default_alpn"`
	}
	if err := json.Unmarshal([]byte(raw), &explicit); err != nil {
		return DefaultNetworkDefaults()
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return DefaultNetworkDefaults()
	}
	if explicit.DefaultALPN == nil || strings.TrimSpace(cfg.DefaultALPN) == "" {
		cfg.DefaultALPN = DefaultALPNForProtocolSwitches(cfg.HTTP2Enabled, cfg.HTTP3Enabled)
	}
	cfg.DefaultALPN = NormalizeALPNList(cfg.DefaultALPN)
	if normalizedNetwork := NormalizeNetwork(cfg.DefaultNetwork); normalizedNetwork != "" {
		cfg.DefaultNetwork = normalizedNetwork
	} else {
		cfg.DefaultNetwork = DefaultNetworkDefaults().DefaultNetwork
	}
	if cfg.HTTP3Enabled && strings.TrimSpace(cfg.HTTP3Bind) == "" {
		cfg.HTTP3Bind = ":443"
	}
	if normalizedBind, ok := NormalizeHTTP3Bind(cfg.HTTP3Bind); ok {
		cfg.HTTP3Bind = normalizedBind
	} else {
		cfg.HTTP3Bind = DefaultNetworkDefaults().HTTP3Bind
	}
	return cfg
}

func LoadTLSDefaults(raw string) TLSDefaults {
	cfg := DefaultTLSDefaults()
	if strings.TrimSpace(raw) == "" {
		return cfg
	}
	var explicit struct {
		DefaultALPN           *string `json:"default_alpn"`
		SessionTicketsEnabled *bool   `json:"session_tickets_enabled"`
		Allow0RTT             *bool   `json:"allow_0rtt"`
	}
	if err := json.Unmarshal([]byte(raw), &explicit); err != nil {
		return DefaultTLSDefaults()
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return DefaultTLSDefaults()
	}
	if strings.TrimSpace(cfg.MinVersion) == "" {
		cfg.MinVersion = DefaultTLSDefaults().MinVersion
	}
	if strings.TrimSpace(cfg.MaxVersion) == "" {
		cfg.MaxVersion = DefaultTLSDefaults().MaxVersion
	}
	if strings.TrimSpace(cfg.DefaultALPN) == "" {
		cfg.DefaultALPN = DefaultTLSDefaults().DefaultALPN
	}
	cfg.DefaultALPN = NormalizeALPNList(cfg.DefaultALPN)
	cfg.HasExplicitDefaultALPN = explicit.DefaultALPN != nil && strings.TrimSpace(*explicit.DefaultALPN) != ""
	if strings.TrimSpace(cfg.CurvePreferences) == "" {
		cfg.CurvePreferences = DefaultTLSDefaults().CurvePreferences
	}
	if explicit.SessionTicketsEnabled == nil {
		cfg.SessionTicketsEnabled = DefaultTLSDefaults().SessionTicketsEnabled
	}
	// allow_0rtt 三态：未显式配置时保持零值并把继承交给 EffectiveAllow0RTT，
	// 由它回落 SessionTicketsEnabled，使未配置的历史配置行为逐字节不变。
	cfg.HasExplicitAllow0RTT = explicit.Allow0RTT != nil
	if explicit.Allow0RTT != nil {
		cfg.Allow0RTT = *explicit.Allow0RTT
	} else {
		cfg.Allow0RTT = false
	}
	return cfg
}

/**
 * EffectiveAllow0RTT 返回 HTTP/3 监听实际采用的 0-RTT 决策。
 *
 * 显式开为 true 但会话票据关闭时，服务端不会签发 NewSessionTicket，
 * 客户端拿不到 PSK，0-RTT 自然不可用；这是协议前提，不是本函数的判定。
 *
 * @return 是否接受 HTTP/3 0-RTT 早期数据。
 */
func (d TLSDefaults) EffectiveAllow0RTT() bool {
	if d.HasExplicitAllow0RTT {
		return d.Allow0RTT
	}
	return d.SessionTicketsEnabled
}

// H3Allow0RTTEnvKey 是覆盖 HTTP/3 0-RTT 判定的环境变量名。
//
// 数据面监听决策与 Admin 运行态自检共用该常量与 H3Allow0RTT，
// 避免同一套 env 语义在两处各写一份而漂移。
const H3Allow0RTTEnvKey = "MY_OPENWAF_H3_ALLOW_0RTT"

/**
 * H3Allow0RTT 按环境变量取值与 TLS 默认配置计算 HTTP/3 0-RTT 的最终判定。
 *
 * 语义（`*EnvValue` 为该环境变量的原始字符串）：
 *   - `"0"`：恒关，仅收紧重放面，不改会话票据配置。
 *   - `"1"`：显式开，但仍受会话票据约束——票据关闭时不签发 NewSessionTicket。
 *   - 其他取值（含未设置与非法值）：透传 `EffectiveAllow0RTT()`，未显式配置
 *     `allow_0rtt` 时回落 `SessionTicketsEnabled`，与历史行为逐 case 等价。
 * @param envValue 环境变量原始取值；不读进程环境，便于调用方与测试显式传入。
 * @param d 当前 TLS 全局默认配置。
 * @return 是否接受 HTTP/3 0-RTT 早期数据。
 */
func H3Allow0RTT(envValue string, d TLSDefaults) bool {
	switch strings.TrimSpace(envValue) {
	case "1":
		return d.SessionTicketsEnabled
	case "0":
		return false
	default:
		return d.EffectiveAllow0RTT()
	}
}

func EffectiveSiteNetwork(siteALPN string, siteNetwork string, defaults NetworkDefaults, tlsDefaults TLSDefaults) (string, string) {
	defaults = normalizeNetworkDefaults(defaults)

	network := NormalizeNetwork(siteNetwork)
	if network == "" {
		network = NormalizeNetwork(defaults.DefaultNetwork)
	}
	if network == "" {
		network = DefaultNetworkDefaults().DefaultNetwork
	}

	alpn := strings.TrimSpace(siteALPN)
	if alpn == "" && tlsDefaults.HasExplicitDefaultALPN {
		alpn = strings.TrimSpace(tlsDefaults.DefaultALPN)
	}
	if alpn == "" {
		alpn = strings.TrimSpace(defaults.DefaultALPN)
	}
	if alpn == "" {
		alpn = strings.TrimSpace(tlsDefaults.DefaultALPN)
	}
	if alpn == "" {
		alpn = DefaultALPNForProtocolSwitches(defaults.HTTP2Enabled, defaults.HTTP3Enabled)
	}
	alpn = NormalizeALPNList(strings.Join(filterALPNProtocols(parseALPNProtocols(alpn), defaults), ","))

	return network, alpn
}

func filterALPNProtocols(protocols []string, defaults NetworkDefaults) []string {
	if len(protocols) == 0 {
		return []string{"http/1.1"}
	}

	out := make([]string, 0, len(protocols))
	for _, proto := range protocols {
		switch strings.TrimSpace(proto) {
		case "":
			continue
		case "h2":
			if !defaults.HTTP2Enabled {
				continue
			}
		case "h3":
			if !defaults.HTTP3Enabled {
				continue
			}
		}
		out = append(out, strings.TrimSpace(proto))
	}
	if len(out) == 0 {
		return []string{"http/1.1"}
	}
	return out
}

func EffectiveSiteTLS(siteMin string, siteMax string, siteCipherSuites string, defaults TLSDefaults) (string, string, string) {
	minVersion := strings.TrimSpace(siteMin)
	if minVersion == "" && strings.TrimSpace(defaults.MinVersion) != "" {
		minVersion = strings.TrimSpace(defaults.MinVersion)
	}
	if normalized := tlsmeta.NormalizeRuntimeVersionToken(minVersion); normalized != "" {
		minVersion = normalized
	} else {
		minVersion = tlsmeta.NormalizeRuntimeVersionToken(defaults.MinVersion)
	}
	if minVersion == "" {
		minVersion = DefaultTLSDefaults().MinVersion
	}

	maxVersion := strings.TrimSpace(siteMax)
	if maxVersion == "" {
		maxVersion = strings.TrimSpace(defaults.MaxVersion)
	}
	if normalized := tlsmeta.NormalizeRuntimeVersionToken(maxVersion); normalized != "" {
		maxVersion = normalized
	} else {
		maxVersion = tlsmeta.NormalizeRuntimeVersionToken(defaults.MaxVersion)
	}
	if maxVersion == "" {
		maxVersion = DefaultTLSDefaults().MaxVersion
	}
	if !tlsmeta.RuntimeVersionRangeValid(minVersion, maxVersion) {
		minVersion = tlsmeta.NormalizeRuntimeVersionToken(defaults.MinVersion)
		maxVersion = tlsmeta.NormalizeRuntimeVersionToken(defaults.MaxVersion)
		if minVersion == "" || maxVersion == "" || !tlsmeta.RuntimeVersionRangeValid(minVersion, maxVersion) {
			minVersion = DefaultTLSDefaults().MinVersion
			maxVersion = DefaultTLSDefaults().MaxVersion
		}
	}

	cipherSuites := strings.TrimSpace(siteCipherSuites)
	if cipherSuites == "" {
		cipherSuites = strings.TrimSpace(defaults.CipherSuites)
	}

	return minVersion, maxVersion, cipherSuites
}

// ParseTLSVersion 将字符串形式的 TLS 版本（如 "TLS12"）转换为 crypto/tls 常量。
func ParseTLSVersion(v string) uint16 {
	return tlsmeta.ParseVersion(v)
}

func ParseCurvePreferences(raw string) []tls.CurveID {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	nameToID := map[string]tls.CurveID{
		"X25519":     tls.X25519,
		"CURVEP256":  tls.CurveP256,
		"P256":       tls.CurveP256,
		"CURVE_P256": tls.CurveP256,
		"P-256":      tls.CurveP256,
		"CURVEP384":  tls.CurveP384,
		"P384":       tls.CurveP384,
		"CURVE_P384": tls.CurveP384,
		"P-384":      tls.CurveP384,
		"CURVEP521":  tls.CurveP521,
		"P521":       tls.CurveP521,
		"CURVE_P521": tls.CurveP521,
		"P-521":      tls.CurveP521,
	}
	seen := make(map[tls.CurveID]struct{})
	var curves []tls.CurveID
	for _, name := range strings.Split(raw, ",") {
		key := strings.ToUpper(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		if id, ok := nameToID[key]; ok {
			if _, exists := seen[id]; exists {
				continue
			}
			seen[id] = struct{}{}
			curves = append(curves, id)
		}
	}
	return curves
}
