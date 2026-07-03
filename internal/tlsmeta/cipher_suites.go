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

// NormalizeCipherSuiteToken converts a suite name, alias, decimal value, or
// hexadecimal value into the repository-wide canonical cipher suite name.
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

// ParseCipherSuites converts a comma-separated list of suite names, aliases,
// decimal IDs, or hexadecimal IDs into runtime-supported cipher suite IDs.
func ParseCipherSuites(raw string) []uint16 {
	return parseCipherSuites(raw, false)
}

// ParseTLSConfigCipherSuites converts a comma-separated list into cipher suite
// IDs that can be applied to tls.Config.CipherSuites. TLS 1.3 suites are
// deliberately excluded because crypto/tls does not make them configurable.
func ParseTLSConfigCipherSuites(raw string) []uint16 {
	return parseCipherSuites(raw, true)
}

// IsTLSConfigCipherSuiteToken reports whether a token can be applied to tls.Config.CipherSuites.
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

// InvalidTLSConfigCipherSuiteToken returns the first token not configurable through tls.Config.CipherSuites.
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

// FormatCipherSuites converts raw numeric cipher suite IDs into a canonical,
// comma-separated repository representation.
func FormatCipherSuites(cipherSuites []uint16) string {
	if len(cipherSuites) == 0 {
		return ""
	}
	catalog := loadTLSCipherSuiteCatalog()
	var b strings.Builder
	for i, suiteID := range cipherSuites {
		if i > 0 {
			b.WriteByte(',')
		}
		if canonical, ok := catalog.idToCanonical[suiteID]; ok {
			b.WriteString(canonical)
			continue
		}
		b.WriteString(fmt.Sprintf("0x%04x", suiteID))
	}
	return b.String()
}
