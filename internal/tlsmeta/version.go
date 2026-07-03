package tlsmeta

import (
	"crypto/tls"
	"strconv"
	"strings"
)

var tlsVersionTokenReplacer = strings.NewReplacer(" ", "", "-", "", "_", "", ".", "")

const versionSSL30 = 0x0300

// CanonicalVersionName returns the repository-wide canonical TLS version token.
func CanonicalVersionName(version uint16) string {
	switch version {
	case versionSSL30:
		return "SSL3"
	case tls.VersionTLS10:
		return "TLS10"
	case tls.VersionTLS11:
		return "TLS11"
	case tls.VersionTLS12:
		return "TLS12"
	case tls.VersionTLS13:
		return "TLS13"
	default:
		return ""
	}
}

// ParseVersion accepts canonical tokens, common aliases, decimal wire values,
// and hexadecimal wire values, then returns the matching crypto/tls constant.
func ParseVersion(raw string) uint16 {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0
	}

	switch strings.ToUpper(trimmed) {
	case "3.0":
		return versionSSL30
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	}

	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		parsed, err := strconv.ParseUint(trimmed[2:], 16, 16)
		if err != nil {
			return 0
		}
		return parseVersionValue(uint16(parsed))
	}

	if isDecimalVersionValue(trimmed) {
		parsed, err := strconv.ParseUint(trimmed, 10, 16)
		if err != nil {
			return 0
		}
		return parseVersionValue(uint16(parsed))
	}

	compact := strings.ToUpper(trimmed)
	compact = tlsVersionTokenReplacer.Replace(compact)
	if strings.HasPrefix(compact, "TLSV") {
		compact = "TLS" + strings.TrimPrefix(compact, "TLSV")
	}
	if strings.HasPrefix(compact, "SSLV") {
		compact = "SSL" + strings.TrimPrefix(compact, "SSLV")
	}

	switch compact {
	case "SSL3", "SSL30":
		return versionSSL30
	case "TLS10":
		return tls.VersionTLS10
	case "TLS11":
		return tls.VersionTLS11
	case "TLS12":
		return tls.VersionTLS12
	case "TLS13":
		return tls.VersionTLS13
	default:
		return 0
	}
}

// NormalizeVersionToken converts a raw TLS version string into the canonical
// repository token such as TLS13 or SSL3.
func NormalizeVersionToken(raw string) string {
	return CanonicalVersionName(ParseVersion(raw))
}

// NormalizeRuntimeVersionToken converts a raw TLS version into a canonical
// token accepted by crypto/tls for live server handshakes.
func NormalizeRuntimeVersionToken(raw string) string {
	version := ParseVersion(raw)
	switch version {
	case tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13:
		return CanonicalVersionName(version)
	default:
		return ""
	}
}

// RuntimeVersionRangeValid reports whether the live TLS version range can be
// used by crypto/tls. Empty values are treated as inherited and valid here.
func RuntimeVersionRangeValid(minRaw string, maxRaw string) bool {
	minRaw = strings.TrimSpace(minRaw)
	maxRaw = strings.TrimSpace(maxRaw)
	if minRaw == "" || maxRaw == "" {
		return true
	}
	minVersion := ParseVersion(NormalizeRuntimeVersionToken(minRaw))
	maxVersion := ParseVersion(NormalizeRuntimeVersionToken(maxRaw))
	if minVersion == 0 || maxVersion == 0 {
		return false
	}
	return minVersion <= maxVersion
}

func parseVersionValue(version uint16) uint16 {
	switch version {
	case versionSSL30, tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13:
		return version
	default:
		return 0
	}
}

func isDecimalVersionValue(raw string) bool {
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return raw != ""
}
