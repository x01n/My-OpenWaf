package security

import "strings"

// ForwardedForHeaderValue 把重复出现的 X-Forwarded-For 取值归一为单条链。
func ForwardedForHeaderValue(values []string) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		return strings.TrimSpace(values[0])
	}
	var b strings.Builder
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(value)
	}
	return b.String()
}

// ForwardedForHeaderValueBytes 把 Hertz 重复出现的 X-Forwarded-For 取值归一为单条链。
func ForwardedForHeaderValueBytes(values [][]byte) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		return strings.TrimSpace(string(values[0]))
	}
	var b strings.Builder
	for _, value := range values {
		item := strings.TrimSpace(string(value))
		if item == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(item)
	}
	return b.String()
}
