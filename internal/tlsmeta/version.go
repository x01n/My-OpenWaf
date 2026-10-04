package tlsmeta

import (
	"crypto/tls"
	"strconv"
	"strings"
)

var tlsVersionTokenReplacer = strings.NewReplacer(" ", "", "-", "", "_", "", ".", "")

const versionSSL30 = 0x0300

/**
 * CanonicalVersionName 返回仓库内统一的 TLS 版本标识。
 *
 * @param version 版本号，取 crypto/tls 的 Version* 常量或 versionSSL30。
 * @return 规范标识，如 TLS12、SSL3；未知版本返回空字符串。
 */
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

/**
 * ParseVersion 解析配置中的 TLS 版本。
 *
 * 接受规范标识、常见别名、十进制线值以及十六进制线值，返回对应的 crypto/tls 常量。
 *
 * @param raw 原始版本串，如 "1.2"、"TLSv1.3"、"0x0303"。
 * @return 匹配的版本常量；无法识别时返回 0。
 */
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

/**
 * NormalizeVersionToken 把原始 TLS 版本串转换为仓库规范标识，如 TLS13、SSL3。
 *
 * @param raw 原始版本串。
 * @return 规范标识；无法识别时返回空字符串。
 */
func NormalizeVersionToken(raw string) string {
	return CanonicalVersionName(ParseVersion(raw))
}

/**
 * NormalizeRuntimeVersionToken 把原始 TLS 版本转换为 crypto/tls 在真实握手时可接受的规范标识。
 *
 * SSL3 虽能被解析，但不能用于实际服务端握手，因此一并归入不支持范围。
 *
 * @param raw 原始版本串。
 * @return 可用的规范标识；SSL3 或无法识别时返回空字符串。
 */
func NormalizeRuntimeVersionToken(raw string) string {
	version := ParseVersion(raw)
	switch version {
	case tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13:
		return CanonicalVersionName(version)
	default:
		return ""
	}
}

/**
 * RuntimeVersionRangeValid 判断实际握手使用的 TLS 版本区间是否可被 crypto/tls 接受。
 *
 * 空值在此视为继承配置，按有效处理。
 *
 * @param minRaw 最低版本串。
 * @param maxRaw 最高版本串。
 * @return 任一端为空或区间合法时返回 true；任一端无法识别或 min 高于 max 时返回 false。
 */
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
