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
	IPv6Enabled    bool   `json:"ipv6_enabled"`
	HTTP2Enabled   bool   `json:"http2_enabled"`
	HTTP3Enabled   bool   `json:"http3_enabled"`
	HTTP3Bind      string `json:"http3_bind"`
	DefaultALPN    string `json:"default_alpn"`
	DefaultNetwork string `json:"default_network"`
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

// NormalizeALPNList converts a comma-separated ALPN list into a canonical,
// lowercase, de-duplicated form while preserving custom protocols.
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

// NormalizeNetwork returns the network value accepted by net.Listen for data listeners.
func NormalizeNetwork(raw string) string {
	network := strings.ToLower(strings.TrimSpace(raw))
	switch network {
	case "tcp", "tcp4", "tcp6":
		return network
	default:
		return ""
	}
}

// NormalizeHTTP3Bind validates and canonicalizes the UDP listen address for HTTP/3.
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
	return cfg
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
