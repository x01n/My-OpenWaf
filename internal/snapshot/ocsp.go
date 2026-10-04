package snapshot

import (
	"encoding/base64"
	"encoding/pem"
	"strings"
)

/**
 * ParseOCSPStaple 解码可选的 OCSP 响应，兼容 PEM、裸 base64 与裸 DER 文本三种形式。
 *
 * 三种形式在运维手工粘贴时都可能出现，因此这里逐层尝试而不是只认其中一种。
 *
 * @param raw 配置或上游返回的 OCSP 文本。
 * @return 解码后的 DER 字节与是否成功。
 */
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
