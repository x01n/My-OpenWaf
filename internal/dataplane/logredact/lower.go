package logredact

/**
 * ToLowerASCII 是 strings.ToLower 的零分配快路径。
 * 当字符串已全部为小写 ASCII 时直接返回原 string，无需分配。
 */
func ToLowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			buf := make([]byte, len(s))
			copy(buf[:i], s[:i])
			for j := i; j < len(s); j++ {
				c := s[j]
				if c >= 'A' && c <= 'Z' {
					buf[j] = c + 0x20
				} else {
					buf[j] = c
				}
			}
			return string(buf)
		}
	}
	return s
}
