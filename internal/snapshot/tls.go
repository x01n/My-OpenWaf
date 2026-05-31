package snapshot

import (
	"crypto/tls"
	"encoding/json"
	"strings"
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
	CurvePreferences         string `json:"curve_preferences"`
	PreferServerCipherSuites bool   `json:"prefer_server_cipher_suites"`
	SelfSignedOnIP           bool   `json:"self_signed_on_ip"`
}

func DefaultNetworkDefaults() NetworkDefaults {
	return NetworkDefaults{
		HTTP2Enabled:   true,
		HTTP3Enabled:   true,
		HTTP3Bind:      ":443",
		DefaultALPN:    "h2,h3,http/1.1",
		DefaultNetwork: "tcp",
	}
}

func DefaultTLSDefaults() TLSDefaults {
	return TLSDefaults{
		MinVersion:               "TLS10",
		MaxVersion:               "TLS13",
		DefaultALPN:              "h2,h3,http/1.1",
		CurvePreferences:         "X25519,CurveP256,CurveP384",
		PreferServerCipherSuites: true,
		SelfSignedOnIP:           true,
	}
}

func LoadNetworkDefaults(raw string) NetworkDefaults {
	cfg := DefaultNetworkDefaults()
	if strings.TrimSpace(raw) == "" {
		return cfg
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return DefaultNetworkDefaults()
	}
	if strings.TrimSpace(cfg.DefaultALPN) == "" {
		cfg.DefaultALPN = DefaultNetworkDefaults().DefaultALPN
	}
	if strings.TrimSpace(cfg.DefaultNetwork) == "" {
		cfg.DefaultNetwork = DefaultNetworkDefaults().DefaultNetwork
	}
	if cfg.HTTP3Enabled && strings.TrimSpace(cfg.HTTP3Bind) == "" {
		cfg.HTTP3Bind = ":443"
	}
	return cfg
}

func LoadTLSDefaults(raw string) TLSDefaults {
	cfg := DefaultTLSDefaults()
	if strings.TrimSpace(raw) == "" {
		return cfg
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
	if strings.TrimSpace(cfg.CurvePreferences) == "" {
		cfg.CurvePreferences = DefaultTLSDefaults().CurvePreferences
	}
	return cfg
}

func EffectiveSiteNetwork(siteALPN string, siteNetwork string, defaults NetworkDefaults, tlsDefaults TLSDefaults) (string, string) {
	network := strings.TrimSpace(siteNetwork)
	if network == "" {
		network = strings.TrimSpace(defaults.DefaultNetwork)
	}
	if network == "" {
		network = DefaultNetworkDefaults().DefaultNetwork
	}

	alpn := strings.TrimSpace(siteALPN)
	if alpn == "" || strings.EqualFold(alpn, "h2,http/1.1") {
		alpn = strings.TrimSpace(defaults.DefaultALPN)
	}
	if alpn == "" {
		alpn = strings.TrimSpace(tlsDefaults.DefaultALPN)
	}
	if alpn == "" {
		alpn = DefaultTLSDefaults().DefaultALPN
	}

	return network, alpn
}

func EffectiveSiteTLS(siteMin string, siteMax string, siteCipherSuites string, defaults TLSDefaults) (string, string, string) {
	minVersion := strings.TrimSpace(siteMin)
	if isLegacyDefaultTLSMin(minVersion) && strings.TrimSpace(defaults.MinVersion) != "" {
		minVersion = strings.TrimSpace(defaults.MinVersion)
	}
	if minVersion == "" {
		minVersion = DefaultTLSDefaults().MinVersion
	}

	maxVersion := strings.TrimSpace(siteMax)
	if maxVersion == "" {
		maxVersion = strings.TrimSpace(defaults.MaxVersion)
	}
	if maxVersion == "" {
		maxVersion = DefaultTLSDefaults().MaxVersion
	}

	cipherSuites := strings.TrimSpace(siteCipherSuites)
	if cipherSuites == "" {
		cipherSuites = strings.TrimSpace(defaults.CipherSuites)
	}

	return minVersion, maxVersion, cipherSuites
}

func isLegacyDefaultTLSMin(v string) bool {
	return v == "" || strings.EqualFold(v, "TLS12")
}

// ParseTLSVersion 将字符串形式的 TLS 版本（如 "TLS12"）转换为 crypto/tls 常量。
func ParseTLSVersion(v string) uint16 {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "TLS10", "1.0":
		return tls.VersionTLS10
	case "TLS11", "1.1":
		return tls.VersionTLS11
	case "TLS12", "1.2":
		return tls.VersionTLS12
	case "TLS13", "1.3":
		return tls.VersionTLS13
	default:
		return 0
	}
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
