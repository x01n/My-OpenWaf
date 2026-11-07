package owasp

import (
	"encoding/base64"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"
)

func unescapeURLComponent(s string, queryPlusAsSpace bool) (string, error) {
	if queryPlusAsSpace {
		if strings.IndexByte(s, '%') < 0 && strings.IndexByte(s, '+') < 0 {
			return s, nil // 无 %/+ 时 QueryUnescape 必返回原串且 err==nil，零拷贝短路
		}
		return url.QueryUnescape(s)
	}
	if strings.IndexByte(s, '%') < 0 {
		return s, nil
	}
	return url.PathUnescape(s)
}

// unescapeURLComponentTolerant 是 unescapeURLComponent 的容错版本：遇到非法
// 百分号序列（`%%27`、`%zz`、末尾孤立 `%`）时保留该字节并继续解码其余部分，
// 而不是整串放弃。
//
// url.QueryUnescape/PathUnescape 对任何一个非法序列都返回 error 并丢弃全部
// 解码结果。攻击者只要在注入串任意位置插入一个 `%%`，整条载荷就能以未解码
// 形态穿过全部规则——全语料里 `/**/` 盲注家族有相当比例的样本正是这样构造的。
//
// 容错语义与编码器一致：合法 %XX 解成对应字节，`+` 在 query 语义下解成空格，
// 解码产生的 '+' 不再二次解释。非法序列只保留其首字节 `%`，后续字符按普通
// 字节继续扫描（`%%27` → `%` + `'`）。
func unescapeURLComponentTolerant(s string, plusAsSpace bool) string {
	if out, err := unescapeURLComponent(s, plusAsSpace); err == nil {
		return out
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) && isHexByte(s[i+1]) && isHexByte(s[i+2]) {
			b.WriteByte(unhexNibble(s[i+1])<<4 | unhexNibble(s[i+2]))
			i += 2
			continue
		}
		if c == '+' && plusAsSpace {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func decodePercentU(s string) string {
	if !strings.Contains(s, "%u") {
		return s
	}
	parts := strings.Split(s, "%u")
	if len(parts) < 2 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(parts[0])
	for _, part := range parts[1:] {
		if len(part) < 4 {
			b.WriteString("%u")
			b.WriteString(part)
			continue
		}
		code, err := strconv.ParseUint(part[:4], 16, 16)
		if err != nil || code > 0xFF {
			b.WriteString("%u")
			b.WriteString(part)
			continue
		}
		b.WriteByte(byte(code))
		b.WriteString(part[4:])
	}
	return b.String()
}

// normalize 依次执行多轮 URL 解码、HTML 实体解码、JS 转义解码、小写化与空白折叠。
func normalize(s string) string {
	return normalizeTarget(s, true)
}

func normalizeTarget(s string, queryPlusAsSpace bool) string {
	s, wideTerminated := normalizeBeforeSQLComments(s, queryPlusAsSpace)
	// 剥离行内 SQL/C 风格注释，破解注释拆分绕过。
	// 空串替换会拼接相邻 token：sel/**/ect → select、un/**/ion → union。
	s = stripSQLCommentsPooled(s)
	s = collapseWhitespacePooled(s, wideTerminated)
	return s
}

// normalizeSQLCommentsAsSpaces 与 normalizeTarget 的唯一差别是块注释的替换物：
// 这里把 /*...*/ 折成单个空格而不是删除。
//
// 两种语义都是 SQL 解析器的真实行为：`sel/**/ect` 靠「注释可贯穿关键字」被
// 识别，`'/**/and/**/1` 则依赖「注释等价空白」把 and 与数字分开。只保留空串
// 拼接会让后者粘成 `'and1`，and/or/like/when 等两侧规则全部失效，这是
// `/**/` 全分隔注入家族（如 /agc/timeclock.php 的 64 条样本）的系统性绕过面。
// 调用方在 normalizeTarget 未产生 SQLi 命中时用本视图补扫，两种语义互不覆盖。
func normalizeSQLCommentsAsSpaces(s string, queryPlusAsSpace bool) string {
	s, wideTerminated := normalizeBeforeSQLComments(s, queryPlusAsSpace)
	s = stripSQLCommentsAsSpacesPooled(s)
	s = collapseWhitespacePooled(s, wideTerminated)
	return s
}

// hasSQLCommentMarker 判断原始目标是否出现 SQL 块注释起始标记（含 URL 编码形态）。
//
// 仅作为「是否值得生成注释垫空白视图」的廉价门控：命中与否都不直接决定检测
// 结果，真正的解码与判定在 normalizeSQLCommentsAsSpaces 与 SQLi 规则表里完成。
// 编码形态只需区分斜杠与星号的百分号编码同时出现——`%2F%2A%2A%2F` 是该家族
// 的常见写法，混合形态 `/`+`%2A` 也由此覆盖。
func hasSQLCommentMarker(raw string) bool {
	if strings.Contains(raw, "/*") {
		return true
	}
	if !strings.Contains(raw, "%") {
		return false
	}
	hasSlash := strings.Contains(raw, "%2f") || strings.Contains(raw, "%2F")
	hasStar := strings.Contains(raw, "%2a") || strings.Contains(raw, "%2A")
	return hasSlash && hasStar
}

// normalizeBeforeSQLComments 执行注释剥离之前的全部归一化步骤。
//
// 返回值 wideTerminated 供 collapseWhitespacePooled 决定是否保留归一化产生的
// 真实换行（CRLF 规则的唯一证据），必须在宽字符行终止符归一之前采样。
func normalizeBeforeSQLComments(s string, queryPlusAsSpace bool) (string, bool) {
	// UTF-7 预解码：query/form 上下文里 unescapeURLComponent 会把 '+' 解成空格，
	// 等 URL 解码做完再解 UTF-7 时 +ADw- 等标记已被破坏（实测
	// "+ADwAIQ-DOCTYPE foo+AFs" → " adwaiq-doctype foo afs"），UTF-7 编码的
	// XML/XSS 载荷因此整体漏检。故在 URL 解码之前先解一次。
	// 门限：仅当解码结果真的产出标记字符（< > " & ; ! / [ ]）时才采用，
	// 否则形如 "1+AND+1=1" 的查询值会被误当作 UTF-7 解成乱码，反而丢掉
	// "+ 当空格" 的 SQLi 形态。
	if strings.Contains(s, "+A") {
		if dec := decodeUTF7Sequences(s); dec != s && containsAnyRuneASCII(dec, "<>\"&;!/[]") {
			s = dec
		}
	}
	// U+2215（∕）在 Java File 等解析器中视为路径分隔符，归一为 ASCII
	// 斜杠，避免 its 变体绕过下方的路径穿越电池。
	if strings.ContainsRune(s, '∕') {
		s = strings.ReplaceAll(s, "∕", "/")
	}
	// overlong UTF-8 百分号编码序列 → 真实字符（一种绕过手法）。
	if strings.Contains(s, "%") && containsOverlongUTF8Escape(s) {
		s = normalizeOverlongUTF8Escapes(s)
	}
	for i := range 3 {
		// 用容错解码：非法百分号序列只保留该字节，不放弃整串。
		// 攻击者插入一个 %% 即可让严格解码整串失效，这条路径必须能继续解码。
		var decoded string
		if i == 0 {
			decoded = unescapeURLComponentTolerant(s, queryPlusAsSpace)
		} else {
			decoded = unescapeURLComponentTolerant(s, false)
		}
		if decoded == s {
			break
		}
		hadOverlongEscape := strings.Contains(s, "%") && containsOverlongUTF8Escape(s)
		s = decoded
		if hadOverlongEscape {
			s = normalizeOverlongUTF8Escapes(s)
		}
	}
	// 多层 URL 解码后仍以百分号形式暴露的序列继续归一。裸二进制字节对
	// 留待文本目标扫描，不在通用归一化阶段改写。
	if strings.Contains(s, "%") && containsOverlongUTF8Escape(s) {
		s = normalizeOverlongUTF8Escapes(s)
	}
	if shouldDecodeHTMLEntities(s) {
		// 多轮 HTML 实体解码。
		for range 2 {
			decoded := html.UnescapeString(s)
			if decoded == s {
				break
			}
			s = decoded
		}
	}
	// JavaScript 转义序列解码：\xNN、\uXXXX、\u{XXXX}、\NNN（八进制）。
	// 可破解 window['\x61\x6c\x65\x72\x74'] → window['alert'] 这类混淆。
	if strings.Contains(s, "\\") {
		s = decodeJSEscapesPooled(s)
	}
	// JS 转义之后的 URL 解码：JS 转义可能产出百分号编码字符
	// （如 %28 → %28 → '('）。多轮处理以覆盖双重/三重编码。
	for range 3 {
		if !strings.Contains(s, "%") {
			break
		}
		d := unescapeURLComponentTolerant(s, false)
		if d == s {
			break
		}
		hadOverlongEscape := containsOverlongUTF8Escape(s)
		s = d
		if hadOverlongEscape {
			s = normalizeOverlongUTF8Escapes(s)
		}
	}
	// UTF-7 解码：+ADw- → <、+AD4- → > 等（用于 charset=UTF-7 的 XSS 攻击）。
	if strings.Contains(s, "+A") {
		s = decodeUTF7Sequences(s)
	}
	// 末次归一只处理仍以百分号编码的 overlong 字节，避免把二进制内容中
	// 随机出现的 0xC0 0xAE/AF 字节对改写成文本。
	if strings.Contains(s, "%") && containsOverlongUTF8Escape(s) {
		s = normalizeOverlongUTF8Escapes(s)
	}
	// 宽字符行终止符归一：部分客户端与中间件按 Latin-1 截断 UTF-8 字符，
	// 低 7 位等于 0x0A/0x0D 的非 ASCII 字符因此等价于 LF/CR
	// （%E5%98%8D 嘍 → \r、%E5%98%8A 嘊 → \n，CRLF 头注入的常见绕过）。
	// 该归一产生的换行是 CRLF 规则唯一可用的证据，必须在后续空白折叠中保留。
	wideTerminated := containsWideLineTerminator(s)
	s = normalizeWideLineTerminators(s)
	s = normalizeURLSchemeControls(s)
	s = toLowerASCII(s)
	// %uXXXX（IIS 风格 Unicode 百分号编码）：按十六进制码点解码，
	// 单字节码点还原为对应字符，让 XSS/SQLi 族看到载荷真相。
	if strings.Contains(s, "%u") {
		s = decodePercentU(s)
	}
	// 覆盖时把 U+2215 变异为斜杠的路径穿越注意点已在前段处理。
	// 零字节剥离（而非替换空格）：<scr\x00ipt> 变体去掉零字节后还原
	// <script 形态供 xss:001 命中；替换空格会让 <scr ipt 无法命中
	// 且下方 collapseWhitespace 会把它变成 <scr ipt（单词断裂）。
	s = strings.ReplaceAll(s, "\x00", "")
	// 内嵌标签混淆剥离：autof<x>ocus → autofocus、alert<x>(1) → alert(1)
	//（HTML 解析器把未知标签 <x> 视为文本丢弃，攻击者用它拆分事件名/
	// 函数名绕过检测）。必须成对剥离（<x> 与 </x> 或 </x> 单闭），
	// 自然文本中的 <x> 极少且此处只剥两字符短标签。
	s = stripInlineConfusionTags(s)
	return s, wideTerminated
}

var reInlineConfusionTag = regexp.MustCompile(`</?[a-z]{1,2}>`)

// normalizeOverlongUTF8Escapes 把 overlong UTF-8 编码归一为等价 ASCII。
//
// 支持百分号分隔形态（%C0%AE）、紧凑形态（%C0AE）与多层 URL 解码后暴露的
// 字节对形态（0xC0 0xAE）。overlong 字节对在合法 UTF-8 URL 编码中不出现，
// 只在刻意拼接的攻击载荷中出现，替换无误报面。
//
// @param s 待归一化文本。
// @return 归一化后的文本；无 overlong 形态时原样返回。
func normalizeOverlongUTF8Escapes(s string) string {
	if strings.Contains(s, "%") && containsOverlongUTF8Escape(s) {
		s = reOverlongDot.ReplaceAllString(s, ".")
		s = reOverlongSlash.ReplaceAllString(s, "/")
		s = reOverlongBackslash.ReplaceAllString(s, "\\")
		// 紧凑形态：%C0AE（百分号后四 hex 无 % 分隔的拼接编码）。
		s = reOverlongDotCompact.ReplaceAllString(s, ".")
		s = reOverlongSlashCompact.ReplaceAllString(s, "/")
		// < 与 > 的 overlong 编码（XSS 绕过中常见）。
		s = reOverlongLT.ReplaceAllString(s, "<")
		s = reOverlongGT.ReplaceAllString(s, ">")
	}
	// 字节形态 overlong 对（多层 URL 解码后 %C0 已变为 0xC0 字节 +
	// ASCII 尾字符，如 %25C0AE 一层解码产物）：0xC0 0xAE → .、
	// 0xC0 0xAF → /。检查在大写 AE/AF 前先剥去，避免漏掉大小写
	// 混写（URL 编码尾字母常任意大小写）。
	for _, c := range []struct{ from, to string }{
		{"\xc0\xae", "."}, {"\xc0\xAE", "."},
		{"\xc0\xaf", "/"}, {"\xc0\xAF", "/"},
		{"\xc0ae", "."}, {"\xc0AE", "."},
		{"\xc0af", "/"}, {"\xc0AF", "/"},
	} {
		if strings.Contains(s, c.from) {
			s = strings.ReplaceAll(s, c.from, c.to)
		}
	}
	return s
}

// normalizeWideLineTerminators 把「低 7 位等于 CR/LF」的非 ASCII 字符归一
// 为真实换行。
//
// 依据是部分客户端/中间件在处理非 ASCII 字符时按 Latin-1 截断取低字节：
// U+560D（嘍，%E5%98%8D）因此等价于 \r，U+560A（嘊，%E5%98%8A）等价于 \n。
// 这是 CRLF 响应头注入的公开绕过手法。只映射非 ASCII 字符，ASCII 文本不受
// 影响；CRLF 规则仍要求换行后出现响应头名，单字符不会独立触发告警。
//
// @param s 待归一化文本。
// @return 归一化后的文本；无相关字符时原样返回。
// containsWideLineTerminator 判断文本是否含有低 7 位等于 CR/LF 的宽字符。
// 仅用于决定归一后是否保留换行证据，不参与其他判定。
// containsWideLineTerminator 判断是否含 U+560D/U+560A。
//
// 两者 UTF-8 编码固定为 E5 98 8D / E5 98 8A，用字节序列查找比 range
// 逐 rune 解码快得多；E5 不可能是续字节，因此字节命中必对应 range
// 能解出的同一码点（等价性由 wide_line_terminator_equiv_test.go 固定）。
func containsWideLineTerminator(s string) bool {
	return strings.Contains(s, "\xe5\x98\x8d") || strings.Contains(s, "\xe5\x98\x8a")
}

func normalizeWideLineTerminators(s string) string {
	if !containsWideLineTerminator(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case 0x560D:
			b.WriteByte('\r')
			continue
		case 0x560A:
			b.WriteByte('\n')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// containsAnyRuneASCII 判断 s 是否至少包含 chars 中的一个 ASCII 字节。
func containsAnyRuneASCII(s, chars string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(chars, s[i]) >= 0 {
			return true
		}
	}
	return false
}

// stripInlineConfusionTags 移除 HTML 解析器会当作未知元素丢弃的短行内标签
// （<x>、<a>、</x> 等）。攻击者把它们插进事件名（autof<x>ocus）或
// 调用点（alert<x>(1)）以绕过正则检测；移除后即可还原原始 token。
func stripInlineConfusionTags(s string) string {
	if !strings.Contains(s, "<") {
		return s
	}
	return reInlineConfusionTag.ReplaceAllString(s, "")
}

func shouldDecodeHTMLEntities(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '&' {
			continue
		}
		if i+1 >= len(s) {
			return false
		}
		next := s[i+1]
		if next == '#' {
			return true
		}
		if !isHTMLEntityNameByte(next) {
			continue
		}
		start := i + 1
		end := start + 1
		for end < len(s) && isHTMLEntityNameByte(s[end]) {
			end++
		}
		if end < len(s) && s[end] == ';' {
			return true
		}
		if hasSemicolonlessHTMLEntityPrefix(s[start:end]) {
			return true
		}
		i = end - 1
	}
	return false
}

func isHTMLEntityNameByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func hasSemicolonlessHTMLEntityPrefix(name string) bool {
	switch {
	case strings.HasPrefix(name, "aacute"),
		strings.HasPrefix(name, "Aacute"),
		strings.HasPrefix(name, "Acirc"),
		strings.HasPrefix(name, "acirc"),
		strings.HasPrefix(name, "acute"),
		strings.HasPrefix(name, "aelig"),
		strings.HasPrefix(name, "AElig"),
		strings.HasPrefix(name, "Agrave"),
		strings.HasPrefix(name, "agrave"),
		strings.HasPrefix(name, "AMP"),
		strings.HasPrefix(name, "amp"),
		strings.HasPrefix(name, "Aring"),
		strings.HasPrefix(name, "aring"),
		strings.HasPrefix(name, "atilde"),
		strings.HasPrefix(name, "Atilde"),
		strings.HasPrefix(name, "Auml"),
		strings.HasPrefix(name, "auml"),
		strings.HasPrefix(name, "brvbar"),
		strings.HasPrefix(name, "Ccedil"),
		strings.HasPrefix(name, "ccedil"),
		strings.HasPrefix(name, "cedil"),
		strings.HasPrefix(name, "cent"),
		strings.HasPrefix(name, "COPY"),
		strings.HasPrefix(name, "copy"),
		strings.HasPrefix(name, "curren"),
		strings.HasPrefix(name, "deg"),
		strings.HasPrefix(name, "divide"),
		strings.HasPrefix(name, "Eacute"),
		strings.HasPrefix(name, "eacute"),
		strings.HasPrefix(name, "Ecirc"),
		strings.HasPrefix(name, "ecirc"),
		strings.HasPrefix(name, "egrave"),
		strings.HasPrefix(name, "Egrave"),
		strings.HasPrefix(name, "ETH"),
		strings.HasPrefix(name, "eth"),
		strings.HasPrefix(name, "euml"),
		strings.HasPrefix(name, "Euml"),
		strings.HasPrefix(name, "frac12"),
		strings.HasPrefix(name, "frac14"),
		strings.HasPrefix(name, "frac34"),
		strings.HasPrefix(name, "GT"),
		strings.HasPrefix(name, "gt"),
		strings.HasPrefix(name, "iacute"),
		strings.HasPrefix(name, "Iacute"),
		strings.HasPrefix(name, "icirc"),
		strings.HasPrefix(name, "Icirc"),
		strings.HasPrefix(name, "iexcl"),
		strings.HasPrefix(name, "igrave"),
		strings.HasPrefix(name, "Igrave"),
		strings.HasPrefix(name, "iquest"),
		strings.HasPrefix(name, "iuml"),
		strings.HasPrefix(name, "Iuml"),
		strings.HasPrefix(name, "laquo"),
		strings.HasPrefix(name, "LT"),
		strings.HasPrefix(name, "lt"),
		strings.HasPrefix(name, "macr"),
		strings.HasPrefix(name, "micro"),
		strings.HasPrefix(name, "middot"),
		strings.HasPrefix(name, "nbsp"),
		strings.HasPrefix(name, "not"),
		strings.HasPrefix(name, "Ntilde"),
		strings.HasPrefix(name, "ntilde"),
		strings.HasPrefix(name, "oacute"),
		strings.HasPrefix(name, "Oacute"),
		strings.HasPrefix(name, "Ocirc"),
		strings.HasPrefix(name, "ocirc"),
		strings.HasPrefix(name, "ograve"),
		strings.HasPrefix(name, "Ograve"),
		strings.HasPrefix(name, "ordf"),
		strings.HasPrefix(name, "ordm"),
		strings.HasPrefix(name, "oslash"),
		strings.HasPrefix(name, "Oslash"),
		strings.HasPrefix(name, "otilde"),
		strings.HasPrefix(name, "Otilde"),
		strings.HasPrefix(name, "ouml"),
		strings.HasPrefix(name, "Ouml"),
		strings.HasPrefix(name, "para"),
		strings.HasPrefix(name, "plusmn"),
		strings.HasPrefix(name, "pound"),
		strings.HasPrefix(name, "quot"),
		strings.HasPrefix(name, "QUOT"),
		strings.HasPrefix(name, "raquo"),
		strings.HasPrefix(name, "reg"),
		strings.HasPrefix(name, "REG"),
		strings.HasPrefix(name, "sect"),
		strings.HasPrefix(name, "shy"),
		strings.HasPrefix(name, "sup1"),
		strings.HasPrefix(name, "sup2"),
		strings.HasPrefix(name, "sup3"),
		strings.HasPrefix(name, "szlig"),
		strings.HasPrefix(name, "thorn"),
		strings.HasPrefix(name, "THORN"),
		strings.HasPrefix(name, "times"),
		strings.HasPrefix(name, "uacute"),
		strings.HasPrefix(name, "Uacute"),
		strings.HasPrefix(name, "Ucirc"),
		strings.HasPrefix(name, "ucirc"),
		strings.HasPrefix(name, "Ugrave"),
		strings.HasPrefix(name, "ugrave"),
		strings.HasPrefix(name, "uml"),
		strings.HasPrefix(name, "Uuml"),
		strings.HasPrefix(name, "uuml"),
		strings.HasPrefix(name, "yacute"),
		strings.HasPrefix(name, "Yacute"),
		strings.HasPrefix(name, "yen"),
		strings.HasPrefix(name, "yuml"):
		return true
	}
	return false
}

// collapseWhitespace 把连续空白折叠为单个空格。
// 对这种简单场景比 regexp 更快。
func normalizeURLSchemeControls(s string) string {
	if !strings.ContainsAny(s, "\t\r\n") {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if !isASCIIAlpha(s[i]) || i > 0 && isURLSchemeByte(s[i-1]) {
			b.WriteByte(s[i])
			i++
			continue
		}

		end := i + 1
		hasControl := false
		for end < len(s) {
			c := s[end]
			if isURLSchemeByte(c) {
				end++
				continue
			}
			if c == '\t' || c == '\r' || c == '\n' {
				hasControl = true
				end++
				continue
			}
			break
		}
		if !hasControl || end >= len(s) || s[end] != ':' {
			b.WriteByte(s[i])
			i++
			continue
		}

		var scheme strings.Builder
		scheme.Grow(end - i)
		for _, c := range []byte(s[i:end]) {
			if c != '\t' && c != '\r' && c != '\n' {
				scheme.WriteByte(c)
			}
		}
		normalizedScheme := strings.ToLower(scheme.String())
		if !isExecutableURLSchemeContext(s, i, end+1, normalizedScheme) {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteString(scheme.String())
		i = end
	}
	return b.String()
}

func isExecutableURLSchemeContext(s string, start, valueStart int, scheme string) bool {
	switch scheme {
	case "javascript", "vbscript", "data":
	default:
		return false
	}

	before := start - 1
	for before >= 0 && (s[before] == ' ' || s[before] == '\t' || s[before] == '\r' || s[before] == '\n') {
		before--
	}
	if before >= 0 {
		switch s[before] {
		case '=':
			return true
		case '\'', '"':
			before--
			for before >= 0 && (s[before] == ' ' || s[before] == '\t' || s[before] == '\r' || s[before] == '\n') {
				before--
			}
			if before >= 0 && s[before] == '=' {
				return true
			}
		case '(':
			nameEnd := before
			nameStart := nameEnd
			for nameStart > 0 && isASCIIAlpha(s[nameStart-1]) {
				nameStart--
			}
			if strings.EqualFold(s[nameStart:nameEnd], "url") {
				return true
			}
		}
	}

	value := strings.TrimLeft(s[valueStart:], " \t\r\n")
	if scheme == "data" {
		lower := strings.ToLower(value)
		return strings.HasPrefix(lower, "text/html") || strings.HasPrefix(lower, "image/svg")
	}
	if value == "" {
		return false
	}
	if strings.ContainsRune("([{'\"`=!", rune(value[0])) {
		return true
	}
	end := 0
	for end < len(value) && (isASCIILetterOrDigit(value[end]) || value[end] == '_' || value[end] == '$') {
		end++
	}
	if end == 0 || end >= len(value) {
		return false
	}
	return strings.ContainsRune("(.[=;", rune(value[end]))
}

func isASCIIAlpha(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isURLSchemeByte(c byte) bool {
	return isASCIILetterOrDigit(c) || c == '+' || c == '-' || c == '.'
}

func collapseWhitespace(s string) string {
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
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' && (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v') {
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
		} else {
			b.WriteByte(c)
			inSpace = false
		}
	}
	return b.String()
}

// decodeUTF7Sequences 还原 UTF-7 编码字符（+ADw- → <、+AD4- → > 等）。
// 用于 charset=UTF-7 的 XSS 攻击：+ADw-script+AD4-alert(1)+ADw-/script+AD4-
var reUTF7 = regexp.MustCompile(`\+([A-Za-z0-9+/]{2,8})-?`)

func decodeUTF7Sequences(s string) string {
	return reUTF7.ReplaceAllStringFunc(s, func(m string) string {
		// 剥去前导 + 与尾部 -
		encoded := strings.TrimPrefix(m, "+")
		encoded = strings.TrimSuffix(encoded, "-")
		// 补齐到 4 的倍数
		for len(encoded)%4 != 0 {
			encoded += "="
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(decoded) == 0 {
			return m
		}
		// UTF-7 基于 UTF-16BE，按对转换为字符。
		var out strings.Builder
		for i := 0; i+1 < len(decoded); i += 2 {
			r := rune(decoded[i])<<8 | rune(decoded[i+1])
			if r > 0 && r < 0xFFFF {
				out.WriteRune(r)
			}
		}
		if out.Len() == 0 {
			return m
		}
		return out.String()
	})
}

// decodeHexEscapes 把 \xNN 十六进制转义序列替换为其字节值。
// 处理 \x41\x42 → AB 这类可能出现在 JavaScript 字符串上下文之外的
// 原始载荷（如 shell 参数、HTTP 请求头）中的绕过形态。
var reHexEscape = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

func decodeHexEscapes(s string) string {
	if !strings.Contains(s, "\\x") {
		return s
	}
	return reHexEscape.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[2:4], 16, 8)
		if err != nil {
			return m
		}
		return string(rune(v))
	})
}

// normalizeWithDecode 在归一化的同时尝试对可疑 token 做 base64 解码。
// 递归限制为 3 层、每层最多 5 个 token、解码后总预算 32KB，以约束 CPU 开销。
func normalizeWithDecode(raw string) string {
	return normalizeWithDecodeTarget(raw, true)
}

func normalizeWithDecodeTarget(raw string, queryPlusAsSpace bool) string {
	if needsDecoding(raw) {
		if strings.Contains(raw, "\\x") {
			hexDecoded := decodeHexEscapes(raw)
			if hexDecoded != raw {
				raw = hexDecoded
			}
		}
	}

	s := normalizeTarget(raw, queryPlusAsSpace)
	if len(s) < 8 || !hasLikelyBase64Candidate(s) && (raw == s || !hasLikelyBase64Candidate(raw)) {
		return s
	}
	urlDecoded := raw
	if strings.Contains(raw, "%") {
		for i := range 3 {
			var d string
			var err error
			if i == 0 {
				d, err = unescapeURLComponent(urlDecoded, queryPlusAsSpace)
			} else {
				d, err = url.PathUnescape(urlDecoded)
			}
			if err != nil || d == urlDecoded {
				break
			}
			urlDecoded = d
		}
	}
	jsDecoded := ""
	if strings.Contains(urlDecoded, "\\") {
		jsDecoded = decodeJSEscapesPooled(urlDecoded)
		if jsDecoded == urlDecoded || jsDecoded == raw || jsDecoded == s {
			jsDecoded = ""
		}
	}

	const maxTotalBytes = 32768
	const maxDepth = 3

	// acc 累积「归一化串 + 各层解码结果」。仅在首个 base64 token 真正解出内容时
	// 才从 normBufPool 取缓冲，避免绝大多数无解码结果的请求付出取还成本。
	var accPtr *[]byte
	var acc []byte
	var seen base64TokenSeen
	found := false
	totalBytes := 0
	attemptsRemaining := 2 * ((len(raw) + len(s) + len(urlDecoded) + len(jsDecoded) + maxTotalBytes + 7) / 8)

	var decodeSource func(src string, depth int) bool
	decodeSource = func(src string, depth int) bool {
		if depth > maxDepth || totalBytes >= maxTotalBytes || attemptsRemaining <= 0 {
			return false
		}
		stop := false
		forEachBase64TokenIndex(src, -1, func(start, end int) bool {
			tok := src[start:end]
			if seen.mark(tok) {
				return true
			}
			if attemptsRemaining <= 0 {
				stop = true
				return false
			}
			attemptsRemaining--
			decoded := decodeBase64IfSuspicious(tok)
			if decoded == "" && start > 0 && isURLSafeBase64LeadByte(src[start-1]) {
				if attemptsRemaining <= 0 {
					stop = true
					return false
				}
				attemptsRemaining--
				decoded = decodeBase64IfSuspicious(src[start-1 : end])
			}
			if decoded == "" {
				return true
			}
			remaining := maxTotalBytes - totalBytes
			if len(decoded) > remaining {
				decoded = decoded[:remaining]
			}
			totalBytes += len(decoded)
			if !found {
				accPtr = getNormBuf()
				acc = *accPtr
				if cap(acc) < len(s)+256 {
					acc = make([]byte, 0, len(s)+256)
				}
				acc = append(acc[:0], s...)
				found = true
			}
			normalizedDecoded := normalize(decoded)
			acc = append(acc, ' ')
			acc = append(acc, normalizedDecoded...)

			nextJS := ""
			nextNormalizedJS := ""
			if strings.Contains(decoded, "\\") {
				nextJS = decodeJSEscapesPooled(decoded)
				if nextJS != decoded {
					nextNormalizedJS = normalize(nextJS)
					acc = append(acc, ' ')
					acc = append(acc, nextNormalizedJS...)
				} else {
					nextJS = ""
				}
			}
			if nextJS != "" {
				stop = decodeSource(nextJS, depth+1)
			}
			if !stop && nextNormalizedJS != "" {
				stop = decodeSource(nextNormalizedJS, depth+1)
			}
			if !stop {
				stop = decodeSource(decoded, depth+1)
			}
			if stop || totalBytes >= maxTotalBytes {
				stop = true
				return false
			}
			return true
		})
		return stop
	}

	stopped := decodeSource(raw, 1)
	if !stopped && s != raw {
		stopped = decodeSource(s, 1)
	}
	if !stopped && urlDecoded != raw && urlDecoded != s {
		stopped = decodeSource(urlDecoded, 1)
	}
	if !stopped && jsDecoded != "" {
		decodeSource(jsDecoded, 1)
	}

	if found {
		// 必须复制：acc 底层数组随即归还池，返回值不得指向池化缓冲。
		result := string(acc)
		*accPtr = acc
		putNormBuf(accPtr)
		return result
	}
	return s
}

func nextDecodedXSSHit(raw string, queryPlusAsSpace bool, threshold int) (OWASPHit, string, bool) {
	if len(raw) < 8 || !hasLikelyBase64Candidate(raw) {
		return OWASPHit{}, "", false
	}
	// hasLikelyBase64Candidate 为真必然存在 ≥8 连续 base64 字节，
	// 即蕴含 hasBase64Candidate；该包含关系由
	// TestLemmaLikelyImpliesBase64 固定，无需再扫一遍。

	const maxTotalBytes = 64 * 1024
	const maxDepth = 3

	var seen base64TokenSeen
	totalBytes := 0
	attemptsRemaining := 2 * ((len(raw) + maxTotalBytes + 7) / 8)
	var scanSource func(string, int) (OWASPHit, string, bool)
	scanSource = func(src string, depth int) (OWASPHit, string, bool) {
		if depth > maxDepth || totalBytes >= maxTotalBytes || attemptsRemaining <= 0 {
			return OWASPHit{}, "", false
		}
		var foundHit OWASPHit
		var foundTarget string
		found := false
		forEachBase64TokenIndex(src, -1, func(start, end int) bool {
			tok := src[start:end]
			if seen.mark(tok) {
				return true
			}
			if attemptsRemaining <= 0 {
				return false
			}
			attemptsRemaining--
			decoded := decodeBase64IfSuspicious(tok)
			if decoded == "" && start > 0 && isURLSafeBase64LeadByte(src[start-1]) {
				if attemptsRemaining <= 0 {
					return false
				}
				attemptsRemaining--
				decoded = decodeBase64IfSuspicious(src[start-1 : end])
			}
			if decoded == "" {
				return true
			}
			remaining := maxTotalBytes - totalBytes
			if len(decoded) > remaining {
				decoded = decoded[:remaining]
			}
			totalBytes += len(decoded)

			normalized := normalize(decoded)
			if hit, ok := nextXSSHit(normalized, threshold, nil); ok {
				foundHit, foundTarget, found = hit, normalized, true
				return false
			}

			jsDecoded := ""
			if strings.Contains(decoded, "\\") {
				jsDecoded = decodeJSEscapesPooled(decoded)
				if jsDecoded != decoded {
					normalizedJS := normalize(jsDecoded)
					if hit, ok := nextXSSHit(normalizedJS, threshold, nil); ok {
						foundHit, foundTarget, found = hit, normalizedJS, true
						return false
					}
				} else {
					jsDecoded = ""
				}
			}

			if jsDecoded != "" {
				if hit, target, ok := scanSource(jsDecoded, depth+1); ok {
					foundHit, foundTarget, found = hit, target, true
					return false
				}
			}
			if hit, target, ok := scanSource(decoded, depth+1); ok {
				foundHit, foundTarget, found = hit, target, true
				return false
			}
			return totalBytes < maxTotalBytes
		})
		return foundHit, foundTarget, found
	}

	sources := []string{raw}
	urlDecoded := raw
	if strings.Contains(raw, "%") || queryPlusAsSpace && strings.Contains(raw, "+") {
		if decoded, err := unescapeURLComponent(raw, queryPlusAsSpace); err == nil && decoded != raw {
			urlDecoded = decoded
			sources = append(sources, decoded)
		}
	}
	if strings.Contains(urlDecoded, "\\") {
		if decoded := decodeJSEscapesPooled(urlDecoded); decoded != urlDecoded {
			sources = append(sources, decoded)
		}
	}
	for _, source := range sources {
		if hit, target, ok := scanSource(source, 1); ok {
			return hit, target, true
		}
	}
	return OWASPHit{}, "", false
}

func containsOverlongUTF8Escape(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		first := lowerASCIIByte(s[i+1])
		second := lowerASCIIByte(s[i+2])
		switch first {
		case 'c':
			if second == '0' || second == '1' {
				return true
			}
		case 'e':
			if second == '0' {
				return true
			}
		case 'f':
			if second == '0' || second == '8' || second == 'c' {
				return true
			}
		}
	}
	return false
}

// hasBase64Candidate 快速判断字符串是否可能含 base64 token。
// 判据为 8 个以上连续 base64 字符，比正则便宜得多。
func hasBase64Candidate(s string) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '+' ||
			c == '/' ||
			c == '-' ||
			c == '_' {
			run++
			if run >= 8 {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// hasLikelyBase64Candidate 收紧快路径候选过滤，使普通小写单词与
// 百分号编码分隔符不进入开销较大的 base64 展开路径。
func hasLikelyBase64Candidate(s string) bool {
	lowerRun := 0
	maxLowerRun := 0
	run := 0
	hasNonLower := false
	inBase64Mode := false

	commitLowerRun := func() {
		if lowerRun > maxLowerRun {
			maxLowerRun = lowerRun
		}
		lowerRun = 0
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inBase64Mode {
			if c >= 'a' && c <= 'z' {
				lowerRun++
				if lowerRun >= 16 {
					return true
				}
				continue
			}
			if c == '%' {
				commitLowerRun()
				if maxLowerRun >= 12 {
					return true
				}
				inBase64Mode = true
				continue
			}
			if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '-' || c == '_' {
				commitLowerRun()
				if maxLowerRun >= 12 {
					return true
				}
				inBase64Mode = true
				run = 1
				hasNonLower = true
				if run >= 8 && (hasNonLower || run >= 12) {
					return true
				}
				continue
			}
			commitLowerRun()
			continue
		}
		if c == '%' && i+2 < len(s) && isHexByte(s[i+1]) && isHexByte(s[i+2]) {
			run = 0
			hasNonLower = false
			i += 2
			continue
		}
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '+' ||
			c == '/' ||
			c == '-' ||
			c == '_' {
			run++
			if c < 'a' || c > 'z' {
				hasNonLower = true
			}
			if run >= 8 && (hasNonLower || run >= 12) {
				return true
			}
			continue
		}
		run = 0
		hasNonLower = false
	}
	if !inBase64Mode {
		if lowerRun > maxLowerRun {
			maxLowerRun = lowerRun
		}
		return maxLowerRun >= 16
	}
	return false
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func isURLSafeBase64LeadByte(b byte) bool {
	return b == '-' || b == '_'
}

var reBase64Token = regexp.MustCompile(`[A-Za-z0-9+/]{8,}={0,2}`)

// base64TokenSeenLinearLimit 是 base64TokenSeen 保持线性查找的最大项数。
const base64TokenSeenLinearLimit = 16

// base64TokenSeen 是 base64 展开过程中的 token 去重表。
//
// 单次展开涉及的 token 通常只有 1～3 个，map 的哈希与桶分配成本高于
// 固定数组的线性比较；前 base64TokenSeenLinearLimit 项不产生任何分配，
// 病态输入（大量短 token）溢出后退化为 map，保证最坏情况仍是一次查找。
type base64TokenSeen struct {
	list [base64TokenSeenLinearLimit]string
	n    int
	set  map[string]bool
}

// mark 记录 token 并返回它此前是否已经出现过。
//
// @param tok 待记录的 base64 token（src 的子串，调用方保证生命周期）。
// @return true 表示该 token 已处理过，调用方应跳过。
func (t *base64TokenSeen) mark(tok string) bool {
	for i := 0; i < t.n; i++ {
		if t.list[i] == tok {
			return true
		}
	}
	if t.set != nil {
		if t.set[tok] {
			return true
		}
		t.set[tok] = true
		return false
	}
	if t.n < base64TokenSeenLinearLimit {
		t.list[t.n] = tok
		t.n++
		return false
	}
	t.set = make(map[string]bool, base64TokenSeenLinearLimit*2)
	for i := 0; i < t.n; i++ {
		t.set[t.list[i]] = true
	}
	t.list = [base64TokenSeenLinearLimit]string{}
	t.n = 0
	t.set[tok] = true
	return false
}

func forEachBase64TokenIndex(src string, limit int, fn func(start, end int) bool) {
	if limit == 0 {
		return
	}
	count := 0
	for i := 0; i < len(src); {
		for i < len(src) && !isBase64TokenByte(src[i]) {
			i++
		}
		start := i
		for i < len(src) && isBase64TokenByte(src[i]) {
			i++
		}
		if i-start < 8 {
			continue
		}
		end := i
		for end < len(src) && end-i < 2 && src[end] == '=' {
			end++
		}
		count++
		if !fn(start, end) {
			return
		}
		if count >= limit && limit > 0 {
			return
		}
		i = end
	}
}

var base64TokenByteTable [256]byte

func init() {
	for c := byte('A'); c <= 'Z'; c++ {
		base64TokenByteTable[c] = 1
	}
	for c := byte('a'); c <= 'z'; c++ {
		base64TokenByteTable[c] = 1
	}
	for c := byte('0'); c <= '9'; c++ {
		base64TokenByteTable[c] = 1
	}
	for _, c := range []byte{'+', '/', '-', '_'} {
		base64TokenByteTable[c] = 1
	}
}

func isBase64TokenByte(b byte) bool {
	return base64TokenByteTable[b] != 0
}

// stripSQLComments 移除字符串中的 /* ... */ 行内注释，破解注释拆分绕过
// （如 sel/**/ect → select）。MySQL 版本相关注释 /*!50000...*/ 刻意保留：
// 其中含可执行 SQL，且由规则 owasp:sqli:020 匹配。
func stripSQLComments(s string) string {
	hasBlock := strings.Contains(s, "/*")
	hasLine := strings.Contains(s, "#") || strings.Contains(s, "--")
	if !hasBlock && !hasLine {
		return s
	}
	start, ok := firstStrippableSQLCommentIndex(s, hasBlock, hasLine)
	if !ok {
		return s
	}
	var buf strings.Builder
	buf.Grow(len(s))
	buf.WriteString(s[:start])
	i := start
	for i < len(s) {
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			if i+2 < len(s) && s[i+2] == '!' {
				buf.WriteByte(s[i])
				i++
				continue
			}
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				buf.WriteByte(s[i])
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
			buf.WriteByte(s[i])
			i++
		}
	}
	return buf.String()
}

func firstStrippableSQLCommentIndex(s string, hasBlock, hasLine bool) (int, bool) {
	i := 0
	for i < len(s) {
		if hasBlock && i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			if i+2 < len(s) && s[i+2] == '!' {
				i++
				continue
			}
			if strings.Contains(s[i+2:], "*/") {
				return i, true
			}
		}
		if hasLine && isSQLLineCommentStart(s, i) {
			return i, true
		}
		i++
	}
	return 0, false
}

func isSQLLineCommentStart(s string, i int) bool {
	return (s[i] == '#' &&
		(i == 0 || (s[i-1] != '=' && s[i-1] != '/' && s[i-1] != '?' && s[i-1] != '&' && s[i-1] != '"' && s[i-1] != '\'')) &&
		(i+1 >= len(s) || s[i+1] == ' ' || s[i+1] == '\t' || s[i+1] == '\n' || s[i+1] == '\r')) ||
		(i+1 < len(s) && s[i] == '-' && s[i+1] == '-' &&
			(i+2 >= len(s) || s[i+2] == ' ' || s[i+2] == '\t' || s[i+2] == '\n' || s[i+2] == '\r'))
}

var (
	reOverlongDot       = regexp.MustCompile(`(?i)%c0%ae`)
	reOverlongSlash     = regexp.MustCompile(`(?i)%c0%af`)
	reOverlongBackslash = regexp.MustCompile(`(?i)%c1%9c`)
	// 紧凑形态（百分号后四 hex 无分隔）：%C0AE→.、%C0AF→/。
	reOverlongDotCompact   = regexp.MustCompile(`(?i)%c0ae`)
	reOverlongSlashCompact = regexp.MustCompile(`(?i)%c0af`)
	// <（U+003C）的 overlong UTF-8 编码，用于绕过 XSS 过滤。
	// 2 字节：C0 BC，3 字节：E0 80 BC，4 字节：F0 80 80 BC，5 字节：F8 80 80 80 BC，6 字节：FC 80 80 80 80 BC
	reOverlongLT = regexp.MustCompile(`(?i)(%c0%bc|%e0%80%bc|%f0%80%80%bc|%f8%80%80%80%bc|%fc%80%80%80%80%bc)`)
	// >（U+003E）的 overlong UTF-8 编码。
	reOverlongGT = regexp.MustCompile(`(?i)(%c0%be|%e0%80%be|%f0%80%80%be)`)
)

func decodeBase64IfSuspicious(s string) string {
	if len(s) < 8 {
		return ""
	}
	// 前导 '/' 剥除：URL 路径位 b64 载荷（如 /SEG）长度 %4=1 会直接
	// 解码失败；剥掉前导 '/' 后按纯 token 重试（攻击者在路径上放 b64
	// 载荷的典型形态）。仅在首字符确为 '/' 且剩余部分仍 ≥8 时剥。
	if s[0] == '/' && len(s) > 9 {
		if dec := decodeBase64IfSuspicious(s[1:]); dec != "" {
			return dec
		}
		return ""
	}
	// 结构非法时四种变体必然全部解码失败，原路径返回空。
	if !base64StructOK(s) {
		return ""
	}
	// 可打印比例必然不达标时，原路径只会尝试剥掉一个非字母数字前导字符。
	if !base64LikelyPrintable(s) {
		if len(s) > 8 && !isBase64AlphaNum(s[0]) {
			return decodeBase64IfSuspicious(s[1:])
		}
		return ""
	}
	var decoded []byte
	var err error
	if len(s) <= 256 {
		var buf [192]byte
		decoded, err = decodeBase64WithBuffer(s, buf[:])
	} else {
		decoded, err = decodeBase64String(s)
	}
	if err != nil {
		return ""
	}
	if len(decoded) == 0 {
		return ""
	}
	printable := 0
	for _, b := range decoded {
		if (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r' {
			printable++
		}
	}
	ratio := float64(printable) / float64(len(decoded))
	minRatio := 0.70
	if len(s) >= 20 {
		minRatio = 0.50
	}
	if ratio < minRatio {
		if len(s) > 8 && !isBase64AlphaNum(s[0]) {
			return decodeBase64IfSuspicious(s[1:])
		}
		return ""
	}
	return string(decoded)
}

func decodeBase64WithBuffer(s string, dst []byte) ([]byte, error) {
	n, err := base64.StdEncoding.Decode(dst, []byte(s))
	if err != nil {
		n, err = base64.RawStdEncoding.Decode(dst, []byte(s))
		if err != nil {
			if !strings.ContainsAny(s, "-_") {
				return nil, err
			}
			n, err = base64.URLEncoding.Decode(dst, []byte(s))
			if err != nil {
				n, err = base64.RawURLEncoding.Decode(dst, []byte(s))
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return dst[:n], nil
}

func decodeBase64String(s string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			if !strings.ContainsAny(s, "-_") {
				return nil, err
			}
			decoded, err = base64.URLEncoding.DecodeString(s)
			if err != nil {
				decoded, err = base64.RawURLEncoding.DecodeString(s)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return decoded, nil
}

func isBase64AlphaNum(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// base64CharValue 把 base64 字符映射为 6 位值，非法字符为 -1。
// 同时接受标准（+/）与 URL 安全（-_）两种字母表：解码路径会按变体依次尝试。
var base64CharValue = func() (t [256]int8) {
	for i := range t {
		t[i] = -1
	}
	for c := byte('A'); c <= 'Z'; c++ {
		t[c] = int8(c - 'A')
	}
	for c := byte('a'); c <= 'z'; c++ {
		t[c] = int8(c - 'a' + 26)
	}
	for c := byte('0'); c <= '9'; c++ {
		t[c] = int8(c - '0' + 52)
	}
	t['+'] = 62
	t['/'] = 63
	t['-'] = 62
	t['_'] = 63
	return
}()

// base64StructOK 判定 s 是否至少能被一种 base64 变体解码。
//
// 原路径对同一 token 依次尝试 Std/RawStd/URL/RawURL 四种编码，全部失败
// 才返回空。这里一次性判定「存在可解码变体」这一必要条件，把绝大多数
// URL 路径片段（len%4==1）、混合字母表、非法填充挡在四次解码之前。
//
// @param s 待判定的 token（已限定为 base64 字符集内的连续片段）。
// @return 是否存在可解码变体。
func base64StructOK(s string) bool {
	p := len(s)
	pad := 0
	for p > 0 && s[p-1] == '=' {
		p--
		pad++
	}
	if p == 0 || pad > 2 {
		return false
	}
	// RawStd/RawURL 不接受 len%4==1；带填充时必须 4 字节对齐。
	if p%4 == 1 || pad > 0 && len(s)%4 != 0 {
		return false
	}
	stdOK, urlOK := true, true
	for i := 0; i < p; i++ {
		c := s[i]
		if !isBase64TokenByte(c) {
			return false
		}
		if c == '-' || c == '_' {
			stdOK = false
		}
		if c == '+' || c == '/' {
			urlOK = false
		}
	}
	return stdOK || urlOK
}

// isPrintableBase64Byte 与 decodeBase64IfSuspicious 的可打印口径完全一致。
func isPrintableBase64Byte(b byte) bool {
	return (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r'
}

// base64LikelyPrintable 判定 s 是否可能解出满足可打印比例下限的内容。
//
// 原判定为 printable/total ≥ 70%（len<20）或 ≥ 50%，浮点比较。这里改用
// 69%/49% 的整数阈值：更宽松的阈值保证真实可打印结果绝不会被判否，
// 因此本函数返回 false 时原路径必然落入「剥首字符」分支。
//
// @param s 结构合法的 base64 token。
// @return 是否可能满足可打印比例下限。
func base64LikelyPrintable(s string) bool {
	p := len(s)
	for p > 0 && s[p-1] == '=' {
		p--
	}
	if p < 2 || p%4 == 1 {
		return false
	}
	total := (p/4)*3 + [4]int{0, 0, 1, 2}[p%4]
	if total == 0 {
		return false
	}
	limit := 490 * total
	if len(s) < 20 {
		limit = 690 * total
	}
	printable := 0
	remaining := total
	full := p - p%4
	for i := 0; i < full; i += 4 {
		v0 := base64CharValue[s[i]]
		v1 := base64CharValue[s[i+1]]
		v2 := base64CharValue[s[i+2]]
		v3 := base64CharValue[s[i+3]]
		if v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0 {
			return false
		}
		if isPrintableBase64Byte(byte(v0)<<2 | byte(v1)>>4) {
			printable++
		}
		if isPrintableBase64Byte(byte(v1)<<4 | byte(v2)>>2) {
			printable++
		}
		if isPrintableBase64Byte(byte(v2)<<6 | byte(v3)) {
			printable++
		}
		remaining -= 3
		if printable*1000+remaining*1000 < limit {
			return false
		}
	}
	switch p - full {
	case 2:
		v0 := base64CharValue[s[full]]
		v1 := base64CharValue[s[full+1]]
		if v0 < 0 || v1 < 0 {
			return false
		}
		if isPrintableBase64Byte(byte(v0)<<2 | byte(v1)>>4) {
			printable++
		}
	case 3:
		v0 := base64CharValue[s[full]]
		v1 := base64CharValue[s[full+1]]
		v2 := base64CharValue[s[full+2]]
		if v0 < 0 || v1 < 0 || v2 < 0 {
			return false
		}
		if isPrintableBase64Byte(byte(v0)<<2 | byte(v1)>>4) {
			printable++
		}
		if isPrintableBase64Byte(byte(v1)<<4 | byte(v2)>>2) {
			printable++
		}
	}
	return printable*1000 >= limit
}

func needsDecoding(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%', '\\', '&':
			return true
		case '+':
			if i+2 < len(s) && s[i+1] == 'A' {
				return true
			}
		}
	}
	return false
}

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
// keepLineTerminators 为 true 时保留 CR/LF：宽字符行终止符归一产生的换行是
// CRLF 规则唯一可用的证据，折叠成空格会让规则失效；其余空白仍按原语义折叠。
func collapseWhitespacePooled(s string, keepLineTerminators bool) string {
	needsWork := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\t' || c == '\f' || c == '\v' {
			needsWork = true
			break
		}
		if c == '\n' || c == '\r' {
			if !keepLineTerminators {
				needsWork = true
				break
			}
			continue
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
		if keepLineTerminators && (c == '\n' || c == '\r') {
			buf = append(buf, c)
			inSpace = false
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
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
	return stripSQLCommentsPooledMode(s, false)
}

// stripSQLCommentsAsSpacesPooled 与 stripSQLCommentsPooled 相同，但把块注释
// 替换为单个空格而不是删除：`'/**/and/**/1` → `' and 1`。
//
// 只在「注释等价空白」语义下才会命中（and/or/like/case when 两侧的边界规则），
// 行注释（--/#）仍按删除处理——它吞掉行尾内容，不产生 token 间隔。
func stripSQLCommentsAsSpacesPooled(s string) string {
	return stripSQLCommentsPooledMode(s, true)
}

// stripSQLCommentsPooledMode 是带替换语义开关的实现体。
//
// spacing=false：删除注释（拆字绕过，sel/**/ect → select）。
// spacing=true：块注释折成单空格（空白绕过，'/**/and/**/1 → ' and 1）。
//
// 两种模式的零拷贝快路径只在删除语义下成立：垫空格会改变长度，无法直接
// 复用原串前缀。
func stripSQLCommentsPooledMode(s string, spacing bool) string {
	hasBlock := strings.Contains(s, "/*")
	hasLine := strings.Contains(s, "#") || strings.Contains(s, "--")
	if !hasBlock && !hasLine {
		return s
	}
	start, ok := firstStrippableSQLCommentIndex(s, hasBlock, hasLine)
	if !ok {
		return s
	}
	if !spacing {
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
			if spacing && len(buf) > 0 && buf[len(buf)-1] != ' ' {
				buf = append(buf, ' ')
			}
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
	if !spacing {
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
	}
	// 垫空格模式可能留下尾随空格（注释在串尾），折叠空白不会去掉首尾，
	// 这里显式裁掉，避免 `$` 锚定规则漏判。
	if spacing {
		for len(buf) > 0 && buf[len(buf)-1] == ' ' {
			buf = buf[:len(buf)-1]
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
