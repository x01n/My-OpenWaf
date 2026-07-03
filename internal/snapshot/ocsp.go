package snapshot

import (
	"encoding/base64"
	"encoding/pem"
	"strings"
)

// ParseOCSPStaple decodes an optional OCSP response stored as PEM, raw base64, or raw DER text.
func ParseOCSPStaple(raw string) ([]byte, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, false
	}
	block, _ := pem.Decode([]byte(trimmed))
	if block != nil && strings.EqualFold(block.Type, "OCSP RESPONSE") && len(block.Bytes) > 0 {
		return append([]byte(nil), block.Bytes...), true
	}
	if decoded, err := base64.StdEncoding.DecodeString(compactBase64(trimmed)); err == nil && len(decoded) > 0 {
		return decoded, true
	}
	return []byte(trimmed), true
}

func compactBase64(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, ch := range raw {
		switch ch {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			b.WriteRune(ch)
		}
	}
	return b.String()
}
