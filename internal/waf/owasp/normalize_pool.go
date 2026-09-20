package owasp

import (
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"
)

// maxNormBufCap 是归还池时允许的最大容量。超过该值的缓冲在 Put 时丢弃，
// 避免偶发超大目标（maxTargetLen 截断前）把池中对象永久抬到数万～数十万字节，
// 导致高并发峰值过后 RSS 长时间不回落。
const maxNormBufCap = 64 * 1024

// normBufPool 池化规范化路径中 strings.Builder / []byte 缓冲，
// 减少 collapseWhitespace、decodeJSEscapes、stripSQLComments 每次调用的堆分配。
var normBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

func getNormBuf() *[]byte {
	return normBufPool.Get().(*[]byte)
}

func putNormBuf(bp *[]byte) {
	if bp == nil {
		return
	}
	// 超大缓冲不回池：交给 GC，防止池被峰值污染。
	if cap(*bp) > maxNormBufCap {
		return
	}
	*bp = (*bp)[:0]
	normBufPool.Put(bp)
}

// toLowerASCII 是 strings.ToLower 的零分配快路径。
// 当字符串已全部为小写 ASCII（绝大多数 URL/query 正常流量），直接返回原 string，
// 无需分配。仅当存在大写 ASCII 字符时才分配并转换。
// 非 ASCII 字节保持原样（WAF 关注的攻击 payload 均为 ASCII 范围内的关键字）。
func toLowerASCII(s string) string {
	// 快速扫描：是否已经全小写
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			// 找到第一个大写字符，从此处开始转换
			bp := getNormBuf()
			buf := *bp
			if cap(buf) < len(s) {
				buf = make([]byte, len(s))
			} else {
				buf = buf[:len(s)]
			}
			copy(buf[:i], s[:i])
			for j := i; j < len(s); j++ {
				c := s[j]
				if c >= 'A' && c <= 'Z' {
					buf[j] = c + 0x20
				} else {
					buf[j] = c
				}
			}
			result := string(buf)
			*bp = buf
			putNormBuf(bp)
			return result
		}
	}
	return s
}

// toLowerASCIIInPlace 直接在 unsafe []byte 上做 ASCII toLower，
// 用于已经拥有独占 []byte 的场景（如 Builder buffer）。
func toLowerASCIIBytes(b []byte) {
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 0x20
		}
	}
}

// collapseWhitespacePooled 使用池化 buffer 替代每次新建 strings.Builder。
func collapseWhitespacePooled(s string) string {
	needsWork := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			needsWork = true
			break
		}
		if c == ' ' && i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t' || s[i+1] == '\n' || s[i+1] == '\r') {
			needsWork = true
			break
		}
	}
	if !needsWork {
		return s
	}
	bp := getNormBuf()
	buf := *bp
	if cap(buf) < len(s) {
		buf = make([]byte, 0, len(s))
	}
	buf = buf[:0]
	inSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' && (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v') {
			if !inSpace {
				buf = append(buf, ' ')
				inSpace = true
			}
		} else {
			buf = append(buf, c)
			inSpace = false
		}
	}
	result := string(buf)
	*bp = buf
	putNormBuf(bp)
	return result
}

// stripSQLCommentsPooled 使用池化 buffer 替代每次新建 strings.Builder。
// 常见攻击样本尾部只有 `--`/`#` 注释且无后续保留内容时，直接返回 s[:start] 零拷贝。
func stripSQLCommentsPooled(s string) string {
	hasBlock := strings.Contains(s, "/*")
	hasLine := strings.Contains(s, "#") || strings.Contains(s, "--")
	if !hasBlock && !hasLine {
		return s
	}
	start, ok := firstStrippableSQLCommentIndex(s, hasBlock, hasLine)
	if !ok {
		return s
	}
	// 快路径：从 start 起仅为一条行注释且吃到串尾 → 结果就是前缀。
	if isSQLLineCommentStart(s, start) && strings.IndexAny(s[start:], "\r\n") < 0 {
		return s[:start]
	}
	// 快路径：从 start 起为一条块注释且注释结束即串尾 → 结果就是前缀。
	if start+1 < len(s) && s[start] == '/' && s[start+1] == '*' &&
		!(start+2 < len(s) && s[start+2] == '!') {
		if end := strings.Index(s[start+2:], "*/"); end >= 0 {
			after := start + 2 + end + 2
			if after == len(s) {
				return s[:start]
			}
		}
	}
	bp := getNormBuf()
	buf := *bp
	if cap(buf) < len(s) {
		buf = make([]byte, 0, len(s))
	}
	buf = buf[:0]
	buf = append(buf, s[:start]...)
	i := start
	for i < len(s) {
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			if i+2 < len(s) && s[i+2] == '!' {
				buf = append(buf, s[i])
				i++
				continue
			}
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				buf = append(buf, s[i])
				i++
				continue
			}
			i = i + 2 + end + 2
		} else if isSQLLineCommentStart(s, i) {
			end := strings.IndexAny(s[i:], "\r\n")
			if end < 0 {
				break
			}
			i = i + end
		} else {
			buf = append(buf, s[i])
			i++
		}
	}
	// 若剥离后内容恰好等于原前缀（无中间注释需拼接），零拷贝返回。
	if len(buf) == start {
		same := true
		for j := 0; j < start; j++ {
			if buf[j] != s[j] {
				same = false
				break
			}
		}
		if same {
			*bp = buf
			putNormBuf(bp)
			return s[:start]
		}
	}
	result := string(buf)
	*bp = buf
	putNormBuf(bp)
	return result
}

// decodeJSEscapesPooled 使用池化 buffer 替代每次新建 strings.Builder。
func decodeJSEscapesPooled(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	bp := getNormBuf()
	buf := *bp
	if cap(buf) < len(s) {
		buf = make([]byte, 0, len(s))
	}
	buf = buf[:0]
	i := 0
	for i < len(s) {
		if s[i] != '\\' || i+1 >= len(s) {
			buf = append(buf, s[i])
			i++
			continue
		}
		consumed, next := appendOneJSEscape(buf, s, i)
		if consumed > 0 {
			buf = next
			i += consumed
		} else {
			buf = append(buf, s[i])
			i++
		}
	}
	result := string(buf)
	*bp = buf
	putNormBuf(bp)
	return result
}

// appendOneJSEscape 解析 s[i] 处的一个 JS 转义序列，并把解码结果追加到 dst。
// 返回消耗的输入字节数与追加后的切片；consumed=0 表示不是有效转义，此时 dst 原样返回。
// 结果直接 append 到调用方缓冲，避免每个转义序列产生一次逃逸的 []byte 分配。
func appendOneJSEscape(dst []byte, s string, i int) (consumed int, out []byte) {
	if i+1 >= len(s) || s[i] != '\\' {
		return 0, dst
	}
	switch s[i+1] {
	case 'x', 'X':
		if i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				return 4, append(dst, byte(v))
			}
		}
	case 'u', 'U':
		if i+2 < len(s) && s[i+2] == '{' {
			end := strings.IndexByte(s[i+3:], '}')
			if end > 0 && end <= 6 {
				hex := s[i+3 : i+3+end]
				if v, err := strconv.ParseUint(hex, 16, 32); err == nil {
					return 3 + end + 1, utf8.AppendRune(dst, rune(v))
				}
			}
		} else if i+5 < len(s) {
			if v, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
				return 6, utf8.AppendRune(dst, rune(v))
			}
		}
	default:
		if s[i+1] >= '0' && s[i+1] <= '7' {
			end := i + 2
			for end < len(s) && end < i+4 && s[end] >= '0' && s[end] <= '7' {
				end++
			}
			if v, err := strconv.ParseUint(s[i+1:end], 8, 8); err == nil {
				return end - i, append(dst, byte(v))
			}
		}
	}
	return 0, dst
}

// truncateTarget 替代 string concat 实现 maxTargetLen 截断。
// 保留头 maxTargetLen 字节 + 空格 + 尾 maxTargetLen 字节。
func truncateTarget(s string) string {
	tail := s[len(s)-maxTargetLen:]
	bp := getNormBuf()
	buf := *bp
	needed := maxTargetLen + 1 + maxTargetLen
	if cap(buf) < needed {
		buf = make([]byte, 0, needed)
	}
	buf = buf[:0]
	buf = append(buf, s[:maxTargetLen]...)
	buf = append(buf, ' ')
	buf = append(buf, tail...)
	result := unsafe.String(unsafe.SliceData(buf), len(buf))
	// 必须复制出来，因为 buf 要归还池
	result = strings.Clone(result)
	*bp = buf
	putNormBuf(bp)
	return result
}
