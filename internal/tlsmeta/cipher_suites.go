package tlsmeta

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type tlsCipherSuiteCatalog struct {
	aliasToCanonical map[string]string
	idToCanonical    map[uint16]string
	canonicalToID    map[string]uint16
	configurable     map[string]bool
}

var tlsCipherSuiteCatalogState struct {
	once    sync.Once
	catalog tlsCipherSuiteCatalog
}

func loadTLSCipherSuiteCatalog() tlsCipherSuiteCatalog {
	tlsCipherSuiteCatalogState.once.Do(func() {
		catalog := tlsCipherSuiteCatalog{
			aliasToCanonical: make(map[string]string),
			idToCanonical:    make(map[uint16]string),
			canonicalToID:    make(map[string]uint16),
			configurable:     make(map[string]bool),
		}
		register := func(id uint16, name string, versions []uint16) {
			if name == "" {
				return
			}
			if _, ok := catalog.idToCanonical[id]; !ok {
				catalog.idToCanonical[id] = name
			}
			catalog.canonicalToID[name] = id
			if isTLSConfigCipherSuite(versions) {
				catalog.configurable[name] = true
			}
			registerTLSCipherSuiteAlias(catalog.aliasToCanonical, name, name)
			registerTLSCipherSuiteAlias(catalog.aliasToCanonical, strings.TrimPrefix(name, "TLS_"), name)
			registerTLSCipherSuiteAlias(catalog.aliasToCanonical, strconv.Itoa(int(id)), name)
			registerTLSCipherSuiteAlias(catalog.aliasToCanonical, fmt.Sprintf("0x%04x", id), name)
		}
		for _, suite := range tls.CipherSuites() {
			register(suite.ID, suite.Name, suite.SupportedVersions)
		}
		for _, suite := range tls.InsecureCipherSuites() {
			register(suite.ID, suite.Name, suite.SupportedVersions)
		}
		tlsCipherSuiteCatalogState.catalog = catalog
	})
	return tlsCipherSuiteCatalogState.catalog
}

func isTLSConfigCipherSuite(versions []uint16) bool {
	for _, version := range versions {
		switch version {
		case tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12:
			return true
		}
	}
	return false
}

func registerTLSCipherSuiteAlias(aliasToCanonical map[string]string, alias, canonical string) {
	alias = strings.ToUpper(strings.TrimSpace(alias))
	if alias == "" {
		return
	}
	aliasToCanonical[alias] = canonical
}

/**
 * NormalizeCipherSuiteToken 把套件名、别名、十进制值或十六进制值转换为仓库内统一的规范套件名。
 *
 * 无法在目录中命中时退回大写原文，由后续解析环节判定是否可用。
 *
 * @param raw 原始套件标识串。
 * @return 规范套件名；输入为空时返回空字符串。
 */
func NormalizeCipherSuiteToken(raw string) string {
	token := strings.TrimSpace(raw)
	if token == "" {
		return ""
	}
	catalog := loadTLSCipherSuiteCatalog()
	if canonical, ok := catalog.aliasToCanonical[strings.ToUpper(token)]; ok {
		return canonical
	}
	return strings.ToUpper(token)
}

/**
 * ParseCipherSuites 把逗号分隔的套件名、别名、十进制 ID 或十六进制 ID 列表转换为运行时支持的套件 ID。
 *
 * @param raw 逗号分隔的套件标识列表。
 * @return 去重后的套件 ID；输入为空或全部无效时返回 nil。
 */
func ParseCipherSuites(raw string) []uint16 {
	return parseCipherSuites(raw, false)
}

/**
 * ParseTLSConfigCipherSuites 把逗号分隔的列表转换为可写入 tls.Config.CipherSuites 的套件 ID。
 *
 * TLS 1.3 套件被有意排除，因为 crypto/tls 不提供其配置入口。
 *
 * @param raw 逗号分隔的套件标识列表。
 * @return 去重后且可配置的套件 ID；输入为空或全部无效时返回 nil。
 */
func ParseTLSConfigCipherSuites(raw string) []uint16 {
	return parseCipherSuites(raw, true)
}

/**
 * IsTLSConfigCipherSuiteToken 判断某个标识能否写入 tls.Config.CipherSuites。
 *
 * @param raw 原始套件标识串。
 * @return 标识能解析为套件且该套件可配置时返回 true。
 */
func IsTLSConfigCipherSuiteToken(raw string) bool {
	canonical := NormalizeCipherSuiteToken(raw)
	if canonical == "" {
		return false
	}
	catalog := loadTLSCipherSuiteCatalog()
	if _, ok := catalog.canonicalToID[canonical]; !ok {
		return false
	}
	return catalog.configurable[canonical]
}

/**
 * InvalidTLSConfigCipherSuiteToken 返回列表中第一个无法通过 tls.Config.CipherSuites 配置的标识。
 *
 * @param raw 逗号分隔的套件标识列表。
 * @return 首个不可配置的标识；列表中没有任何标识时返回去空白后的原文。
 */
func InvalidTLSConfigCipherSuiteToken(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	seenToken := false
	for _, item := range strings.Split(raw, ",") {
		token := strings.TrimSpace(item)
		if token == "" {
			continue
		}
		seenToken = true
		if !IsTLSConfigCipherSuiteToken(token) {
			return token
		}
	}
	if !seenToken {
		return strings.TrimSpace(raw)
	}
	return ""
}

func parseCipherSuites(raw string, tlsConfigOnly bool) []uint16 {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	catalog := loadTLSCipherSuiteCatalog()
	seen := make(map[uint16]struct{})
	var suites []uint16
	for _, item := range strings.Split(raw, ",") {
		canonical := NormalizeCipherSuiteToken(item)
		if canonical == "" {
			continue
		}
		id, ok := catalog.canonicalToID[canonical]
		if !ok {
			continue
		}
		if tlsConfigOnly && !catalog.configurable[canonical] {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		suites = append(suites, id)
	}
	return suites
}

/**
 * FormatCipherSuites 把数字套件 ID 转换为仓库内统一的逗号分隔表示。
 *
 * 目录中不存在的 ID 用 0x 前缀的十六进制（补齐四位）表示。
 *
 * @param cipherSuites 待格式化的套件 ID 列表。
 * @return 逗号分隔的规范表示；列表为空时返回空字符串。
 */
func FormatCipherSuites(cipherSuites []uint16) string {
	if len(cipherSuites) == 0 {
		return ""
	}
	catalog := loadTLSCipherSuiteCatalog()
	var b strings.Builder
	b.Grow(len(cipherSuites) * 24)
	for i, suiteID := range cipherSuites {
		if i > 0 {
			b.WriteByte(',')
		}
		if canonical, ok := catalog.idToCanonical[suiteID]; ok {
			b.WriteString(canonical)
			continue
		}
		b.WriteString("0x")
		hex := strconv.FormatUint(uint64(suiteID), 16)
		for pad := 4 - len(hex); pad > 0; pad-- {
			b.WriteByte('0')
		}
		b.WriteString(hex)
	}
	return b.String()
}
