package rules

import (
	"My-OpenWaf/internal/tlsmeta"
)

const (
	tlsCipherSuitesHeaderCanonical = "X-OWAF-TLS-Cipher-Suites"
	tlsCipherSuitesHeaderLower     = "x-owaf-tls-cipher-suites"
)

func normalizeTLSCipherSuiteToken(raw string) string {
	return tlsmeta.NormalizeCipherSuiteToken(raw)
}

func formatTLSCipherSuitesHeaderValue(cipherSuites []uint16) string {
	return tlsmeta.FormatCipherSuites(cipherSuites)
}
