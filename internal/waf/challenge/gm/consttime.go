package gm

/**
 * 常量时间比较（密钥/标签/hex 摘要）。与 crypto/subtle/hmac.Equal 语义一致，
 * 统一为本包调用方提供，防止 HMAC/GCM/tag 校验成为侧信道。
 */
func ConstTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

/**
 * ConstTimeEqualHex 比较两个十六进制字符串的字节解码是否一致。
 * 编码错误视为不等（不去旁路报错）。
 */
func ConstTimeEqualHex(a, b string) bool {
	da := decodeHexNoLookup(a)
	db := decodeHexNoLookup(b)
	return len(da) > 0 && ConstTimeEqual(da, db)
}

// decodeHexNoLookup 解码 hex；结果不足 1 字节时统一返回 nil（与解码信号同值）。
func decodeHexNoLookup(s string) []byte {
	if len(s)%2 != 0 {
		return nil
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := hexNibble(s[2*i])
		lo := hexNibble(s[2*i+1])
		if hi < 0 || lo < 0 {
			return nil
		}
		out[i] = byte(hi<<4) | byte(lo)
	}
	return out
}

func hexNibble(c byte) int8 {
	switch {
	case c >= '0' && c <= '9':
		return int8(c - '0')
	case c >= 'a' && c <= 'f':
		return int8(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int8(c-'A') + 10
	default:
		return -1
	}
}
