package owasp

import (
	"strings"
	"unicode/utf8"
)

// binaryTargetRatioThreshold 是判定扫描目标为二进制数据的非文本字符占比阈值。
// 依据 blazehttp 基准实测：正常文本目标（含中文 UTF-8）占比接近 0，
// 而触发误报的压缩流 / PDF 目标占比约 0.54。
const binaryTargetRatioThreshold = 0.30

// binaryTargetMinLen 是启用二进制判定的最小目标长度。
// 短目标（路径、查询参数、头部值）不可能是二进制 body，
// 且样本过小时占比统计不稳定，直接跳过判定。
const binaryTargetMinLen = 256

// binaryTargetMinCmdScore 是二进制目标上命令注入规则被采信所需的单条最低分值。
// 低于该分值的规则（owasp:cmd:002、owasp:cmd:010 等短模式）在随机字节流中
// 碰撞概率过高；反引号紧跟命令词的 owasp:cmd:024 等 5 分规则不受影响。
const binaryTargetMinCmdScore = 5

/**
 * isBinaryScanTarget 判断归一化后的扫描目标是否为二进制数据。
 *
 * 统计无效 UTF-8 序列与 C0 控制字符（\t \n \r 除外）的占比。压缩流、PDF、
 * 图片等二进制 body 中，短模式（如 `';x` 或一对反引号夹带两字母命令词）的
 * 随机碰撞概率极高，此类目标上的低置信度命中不构成攻击证据；而真实注入
 * payload 无论如何编码，解码归一化后仍是可打印文本，占比接近 0。
 *
 * @param s 归一化后的扫描目标
 * @return 目标为二进制数据时返回 true
 */
func isBinaryScanTarget(s string) bool {
	if len(s) < binaryTargetMinLen {
		return false
	}
	bad, total := 0, 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		total++
		switch {
		case r == utf8.RuneError && size == 1:
			bad++
		case r < 0x20 && r != '\t' && r != '\n' && r != '\r':
			bad++
		}
		i += size
	}
	if total == 0 {
		return false
	}
	return float64(bad) >= float64(total)*binaryTargetRatioThreshold
}

var cleanCharSet [256]bool

func init() {
	for c := byte('a'); c <= 'z'; c++ {
		cleanCharSet[c] = true
	}
	for c := byte('A'); c <= 'Z'; c++ {
		cleanCharSet[c] = true
	}
	for c := byte('0'); c <= '9'; c++ {
		cleanCharSet[c] = true
	}
	for _, c := range []byte{'-', '_', '.', ' ', ',', '@'} {
		cleanCharSet[c] = true
	}
}

func isCleanTarget(s string) bool {
	if len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !cleanCharSet[s[i]] {
			return false
		}
	}
	return true
}

func isCleanPathTarget(s string) bool {
	if len(s) == 0 || len(s) > 256 || hasSuspiciousBase64PathSegment(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '/' || c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return !hasPlainTargetAttackKeyword(s)
}

// isCleanPlainQueryTarget 判断 query 是否可安全跳过整轮正则扫描。
//
// 仅由小写字母、数字与 -_ . = & 构成的查询串通常无攻击面，但
// `cmd=whoami`、`x=shell_exec` 这类「参数值即命令词」的探测串同样
// 只含这些字符，必须显式排除，否则会被 clean 快路径整体跳过。
func isCleanPlainQueryTarget(s string) bool {
	if len(s) == 0 || len(s) > 512 || !strings.Contains(s, "=") {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == '=' || c == '&':
		default:
			return false
		}
	}
	if hasPlainTargetAttackKeyword(s) {
		return false
	}
	return !hasParamValueCommandWordFold(s)
}

func hasSuspiciousBase64PathSegment(s string) bool {
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '/' {
			continue
		}
		if isSuspiciousBase64PathSegment(s[start:i]) {
			return true
		}
		start = i + 1
	}
	return false
}

func isSuspiciousBase64PathSegment(segment string) bool {
	if len(segment) < 8 || len(segment) > 256 || strings.Contains(segment, ".") {
		return false
	}
	// 长度修正：8-15 字符的短 b64 段（含 (alert)(1) 类短载荷的 b64 形态）
	// 用 hasLikelyBase64Candidate 判定，避免 cleanPath 快路径把短攻击
	// 载荷跳过；≥16 的段沿用全 b64 字节判定。
	if len(segment) < 16 {
		return hasLikelyBase64Candidate(segment)
	}
	for i := 0; i < len(segment); i++ {
		if !isBase64TokenByte(segment[i]) {
			return false
		}
	}
	return true
}

func hasPlainTargetAttackKeyword(s string) bool {
	for i := 0; i < len(s); i++ {
		switch lowerASCIIByte(s[i]) {
		case '.':
			if hasASCIIFoldAt(s, i, "..") || hasASCIIFoldAt(s, i, ".git") {
				return true
			}
		case 'a':
			if hasASCIIFoldAt(s, i, "alter") || hasASCIIFoldAt(s, i, "and1=1") {
				return true
			}
		case 'b':
			if hasASCIIFoldAt(s, i, "benchmark") || hasASCIIFoldAt(s, i, "boot.ini") {
				return true
			}
		case 'c':
			if hasASCIIFoldAt(s, i, "curl") {
				return true
			}
		case 'd':
			if hasASCIIFoldAt(s, i, "delete") || hasASCIIFoldAt(s, i, "drop") {
				return true
			}
		case 'e':
			if hasASCIIFoldAt(s, i, "etc/") {
				return true
			}
		case 'i':
			if hasASCIIFoldAt(s, i, "insert") {
				return true
			}
		case 'j':
			if hasASCIIFoldAt(s, i, "jndi") || hasASCIIFoldAt(s, i, "javascript") {
				return true
			}
		case 'l':
			if hasASCIIFoldAt(s, i, "localhost") || hasASCIIFoldAt(s, i, "ldap") {
				return true
			}
		case 'm':
			if hasASCIIFoldAt(s, i, "meta-inf") {
				return true
			}
		case 'o':
			if hasASCIIFoldAt(s, i, "onclick") ||
				hasASCIIFoldAt(s, i, "onload") ||
				hasASCIIFoldAt(s, i, "onerror") ||
				hasASCIIFoldAt(s, i, "or1=1") {
				return true
			}
		case 'p':
			if hasASCIIFoldAt(s, i, "passwd") {
				return true
			}
		case 's':
			if hasASCIIFoldAt(s, i, "select") ||
				hasASCIIFoldAt(s, i, "sleep") ||
				hasASCIIFoldAt(s, i, "script") ||
				hasASCIIFoldAt(s, i, "shell_exec") {
				return true
			}
		case 't':
			if hasASCIIFoldAt(s, i, "truncate") {
				return true
			}
		case 'u':
			if hasASCIIFoldAt(s, i, "union") || hasASCIIFoldAt(s, i, "update") {
				return true
			}
		case 'w':
			if hasASCIIFoldAt(s, i, "waitfor") ||
				hasASCIIFoldAt(s, i, "whoami") ||
				hasASCIIFoldAt(s, i, "wget") ||
				hasASCIIFoldAt(s, i, "web-inf") ||
				hasASCIIFoldAt(s, i, "win.ini") {
				return true
			}
		case '_':
			if hasASCIIFoldAt(s, i, "__") {
				return true
			}
		case '1':
			if hasASCIIFoldAt(s, i, "127.0.") || hasASCIIFoldAt(s, i, "169.254") {
				return true
			}
		}
	}
	return false
}

var suspiciousCharSet [256]bool

func init() {
	for _, c := range []byte{'\'', '"', '<', '>', '(', ')', '{', '}', '[', ']', ';', '|', '`', '$', '\\', '-', '#', '!', '&', '*', '%', '=', '.', '/', ':'} {
		suspiciousCharSet[c] = true
	}
}

// hasSuspiciousContent 是 O(n) 的快速预判：判断字符串是否可能命中任何 OWASP 正则。
// 干净字符串直接返回 false，跳过整轮正则检测。
func hasSuspiciousContent(s string) bool {
	for i := 0; i < len(s); i++ {
		if suspiciousCharSet[s[i]] {
			return true
		}
	}
	// 兜底：在纯字母数字串中查找 SQL/攻击关键词。
	// 用于捕获 "1 UNION SELECT NULL FROM users" 这类请求体注入载荷——
	// 按 '=' 切分后提取出的值不含任何特殊字符。
	return hasSuspiciousKeywords(s)
}

// JavaSerializationMagic 是 Java 原生序列化流头：ObjectStreamConstants 的
// STREAM_MAGIC（0xACED）与 STREAM_VERSION（0x0005），即 ObjectOutputStream
// 写出的前 4 个字节。
//
// 该 4 字节序列在 HTTP 请求体（图片、压缩包、Protobuf、multipart 上传）中
// 不存在随机碰撞，出现即代表 Java 序列化对象流，属于反序列化攻击面。
// 注意归一化会剥离 NUL 字节（0x00），因此判定必须在归一化之前的原始目标上
// 进行；本常量同时供请求体目标抽取阶段复用，避免两处字面量漂移。
const JavaSerializationMagic = "\xac\xed\x00\x05"

func hasSuspiciousKeywords(s string) bool {
	if s == "" {
		return false
	}
	bm := scanIndicatorMask(s, &suspKeywordMaskTable)
	for i := range suspKeywordGroups {
		g := &suspKeywordGroups[i]
		if bm&g.need != g.need {
			continue
		}
		for _, w := range g.words {
			if strings.Contains(s, w) {
				return true
			}
		}
	}
	return false
}

// sqliIndicatorLiterals 是 hasSQLiIndicator 的全部判定项。
//
// 每一项都是「出现即判定为可疑 SQL 构造」的字面量；原实现按必备字节
// 分组，只有组内首字节出现时才逐条做子串查找。分组只是性能优化，
// 语义上是纯 OR，故整体折叠为统合自动机中的一个位集合。
var sqliIndicatorLiterals = []string{
	// 引号：任意引号都值得进入 SQLi 正则。
	"'", `"`,
	// 布尔/子句形态。
	" or ", " and ", "group by", "order by", "case when", "having ",
	" like ", "to program", "select case",
	// 函数调用形态。
	"sleep(", "benchmark(", "substr(", "substring(", "ascii(", "ord(",
	"length(", "count(", "version(", "if(", "if (", "concat(", "char(",
	"chr(", " cast(", " convert(", "json_extract(",
	// 元数据与文件操作形态。
	"information_schema", "load_file", "xp_", "utl_http", "utl_inaddr",
	"utl_file", "dbms_", "group_concat",
	// 注释与字面量形态。
	"--", "/*", "0x", "@@",
	// 关键字形态。
	"select", "union", "update", "updatexml", "insert", "delete", "drop",
	"dumpfile", "alter", "truncate", "waitfor", "outfile", "extractvalue",
	"procedure",
	// 关键字内插尖括号的拆字形态：原文不含完整的 union/select/and，
	// 只有在此登记后才会进入 SQLi 正则（规则 owasp:sqli:060）。
	"a<>nd", "un<>ion", "sel<>ect",
}

// hasSQLiIndicator 判断目标串是否含有可疑 SQL 构造。
//
// @param s    检测目标串。
// @param gate 该目标已构建的统合扫描证据；省略时按 s 现场构建。
// @return 是否命中任一 SQLi 指示字面量。
func hasSQLiIndicator(s string, gate ...*scanGate) bool {
	if s == "" {
		return false
	}
	return firstGate(s, gate).hits.Intersects(&sqliIndicatorBits)
}

func hasJavascriptLettersScan(s string) bool {
	var seen uint32
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'j':
			seen |= 1 << 0
		case 'a':
			seen |= 1 << 1
		case 'v':
			seen |= 1 << 2
		case 's':
			seen |= 1 << 3
		case 'c':
			seen |= 1 << 4
		case 'r':
			seen |= 1 << 5
		case 'i':
			seen |= 1 << 6
		case 'p':
			seen |= 1 << 7
		case 't':
			seen |= 1 << 8
		case ':':
			seen |= 1 << 9
		}
		if seen == 0b00000011_11111111 {
			return true
		}
	}
	return false
}

var xssIndicatorLiteralBytes = []string{
	"javascript:",
	"vbscript:",
	"document.",
	"document[",
	"innerhtml",
	"eval(",
	"settimeout(",
	"setinterval(",
	"data:text/html",
	"fromcharcode",
	"window.",
	"window[",
	"fetch(",
	"xmlhttprequest",
	"expression(",
	"srcdoc",
	"{{",
	"self[",
	"top[",
	"parent[",
	"frames[",
	"globalthis[",
	"this[",
	"alert(",
	"alert'",
	"prompt(",
	"confirm(",
	".source",
	"atob(",
	"alert.",
	"prompt.",
	"confirm.",
	// 反引号实参直连调用（prompt`1` 家族）：xss:069 电池的必要门字面。
	"alert`",
	"prompt`",
	"confirm`",
	"data:image/svg",
	"+{}",
	"+[]",
	"(![",
	"constructor.constructor",
	"constructor.prototype[",
	"onclick",
	"onload",
	"onerror",
	"onmouse",
	"onfocus",
	"onblur",
	"onkey",
	"onsubmit",
	"onchange",
	"oninput",
	"ondrag",
	"ondrop",
	"oncopy",
	"oncut",
	"onpaste",
	"ontoggle",
	"onpointer",
	"onanimation",
	"onscroll",
	"onwheel",
	"onresize",
	"onunload",
	"onhash",
	"onbefore",
	"ondblclick",
	"oncontextmenu",
	"onmessage",
	"onpopstate",
	"ontouch",
	"ontransition",
	"onfullscreen",
	"onselect",
	"oninvalid",
	"onauxclick",
	"onafterscriptexecute",
}

// xssIndicatorExtraLiterals 是 hasXSSIndicator 中不走字面量表的直通形态。
//
// 这些形态在自然文本中几乎不出现（"?"、")(" 不是词内字符组合），
// 门级放行保证对应规则电池可达；与 xssIndicatorLiteralBytes 一起
// 在统合自动机里折叠为 xssIndicatorBits。
var xssIndicatorExtraLiterals = []string{
	"<",
	"alert?.", "prompt?.", "confirm?.",
	"alert)(", "prompt)(", "confirm)(",
	"function(",
}

// hasXSSIndicator 判断目标串是否命中任一 XSS 指示条件。
//
// 原实现对 76 条字面量逐条执行 strings.Index，并配合若干直通形态，
// 实测占 OWASP 扫描 CPU 的 7.6%。这些条件全部是「命中即返回 true」的
// OR 关系，因此在统合自动机里被折叠成单个位集合：一次 Intersects
// 即完成全部判定。
//
// @param s    检测目标串。
// @param gate 该目标已构建的统合扫描证据；省略时按 s 现场构建。
// @return 是否命中任一 XSS 指示条件。
func hasXSSIndicator(s string, gate ...*scanGate) bool {
	return firstGate(s, gate).hits.Intersects(&xssIndicatorBits)
}

// cmdIndicatorLiterals 是 hasCmdIndicator 中无附加条件的判定项。
var cmdIndicatorLiterals = []string{
	"$(", "${", "$@", "$'",
	"&&", ">>", "%00", "\x00", "\n", "\r",
	"wget ", "curl ", "export -f", "env -i",
	"<!--#", "cmd.exe", "powershell", "pwsh", "`",
}

// cmdWordIndicatorLiterals 是必须与 shell 命令词同时出现才成立的包装器形态。
//
// 单独出现 xargs/nohup/export 等词在运维文本里十分常见，只有目标串
// 同时含真实命令词时才视为命令注入证据。
var cmdWordIndicatorLiterals = []string{
	"xargs", "nohup", "timeout ", "setsid", "stdbuf", "export",
	"localhost", "127.0.0.1",
}

// hasCmdIndicator 判断目标串是否含有命令注入指示特征。
//
// 无条件项折叠进统合自动机；带附加条件的形态（分隔符 + 命令词、
// 引号拆词、包装器 + 命令词）保留结构化判定。
//
// @param s    检测目标串。
// @param gate 该目标已构建的统合扫描证据；省略时按 s 现场构建。
// @return 是否命中任一命令注入指示条件。
func hasCmdIndicator(s string, gate ...*scanGate) bool {
	if s == "" {
		return false
	}
	g := firstGate(s, gate)
	if g.hits.Intersects(&cmdIndicatorBits) {
		return true
	}
	// 分隔符后跟命令词：x=1; cat /etc/passwd。
	if strings.ContainsAny(s, "|;`") && hasCmdCommandWord(s) {
		return true
	}
	// 参数值以命令词开头：cmd=whoami、ppp=uname -a、ppp=bash /tmp/x。
	// 该类目标不含分隔符，必须由参数位置识别，否则 cmd 家族会被整体剪枝。
	if strings.Contains(s, "=") && hasParamValueCommandWord(s) {
		return true
	}
	// 引号/反斜杠插入拆词：c'a't /etc/passwd。
	if strings.ContainsAny(s, "'\"\\") && hasSplitCommandWord(s) {
		return true
	}
	// 输出重定向 + 相对路径穿越（SCM=Subversion&client=echo xxx// > ../../www/x.txt）：
	// 该形态不含分隔符与等号，但「命令词 + > + ../」是写 webshell 的强组合。
	if strings.Contains(s, ">") && strings.Contains(s, "../") && hasCmdCommandWord(s) {
		return true
	}
	// 包装器形态 + 命令词。
	return g.hits.Intersects(&cmdWordIndicatorBits) && hasCmdCommandWord(s)
}

func hasCmdCommandWord(s string) bool {
	for i := 0; i < len(s); {
		for i < len(s) && !isCmdWordByte(s[i]) {
			i++
		}
		start := i
		for i < len(s) && isCmdWordByte(s[i]) {
			i++
		}
		if start < i && isShellCommandWord(s[start:i], false) {
			return true
		}
	}
	return false
}

// hasParamValueCommandWord 判断是否存在「参数名=命令词」形态
// （cmd=whoami、ppp=uname -a、ppp=bash /tmp/x）。
//
// 仅用于 cmd 家族的指示器前置：命令词必须位于 `=` 之后的首个 token，
// 且后面紧跟空白/串尾/`&`/`;`，避免 `lang=javascript` 这类长词误触发。
//
// @param s 检测目标串。
// @return 是否存在参数值命令词形态。
func hasParamValueCommandWord(s string) bool {
	return paramValueCommandWord(s, false)
}

// hasParamValueCommandWordFold 是 hasParamValueCommandWord 的 ASCII
// 大小写不敏感版本，供查询串 clean 快路径判定使用（原始 query 保持原大小写）。
//
// @param s 检测目标串。
// @return 是否存在参数值命令词形态（忽略 ASCII 大小写）。
func hasParamValueCommandWordFold(s string) bool {
	return paramValueCommandWord(s, true)
}

// paramValueCommandWord 实现参数值命令词判定。
//
// @param s    检测目标串。
// @param fold 是否执行 ASCII 大小写不敏感比较。
// @return 是否存在「= 命令词」形态。
func paramValueCommandWord(s string, fold bool) bool {
	for start := 0; ; {
		idx := strings.IndexByte(s[start:], '=')
		if idx < 0 {
			return false
		}
		idx += start
		i := idx + 1
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '+') {
			i++
		}
		wordStart := i
		for i < len(s) {
			c := s[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || (fold && c >= 'A' && c <= 'Z') {
				i++
				continue
			}
			break
		}
		if wordStart < i {
			word := s[wordStart:i]
			if isShellCommandWord(word, fold) || equalASCIIFold(word, "zsh") ||
				equalASCIIFold(word, "dash") || equalASCIIFold(word, "export") ||
				equalASCIIFold(word, "shell_exec") {
				if i == len(s) || s[i] == ' ' || s[i] == '\t' || s[i] == '&' || s[i] == ';' || s[i] == '+' {
					return true
				}
			}
		}
		start = idx + 1
	}
}

func hasSplitCommandWord(s string) bool {
	seps := 0
	for i := 1; i+1 < len(s); i++ {
		c := s[i]
		if c != '\'' && c != '"' && c != '\\' {
			continue
		}
		if isASCIILetter(s[i-1]) && isASCIILetter(s[i+1]) {
			seps++
			if seps >= 2 {
				return true
			}
		}
	}
	return false
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isCmdWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// isShellCommandWord 判断 s 是否为已知 shell 命令词（仅小写字母+数字）。
// fold=false 执行精确小写比较（等价于原 isShellCommandWord）；
// fold=true 执行 ASCII case-fold 逐词比较（等价于原 isShellCommandWordASCIIFold）。
// 两路等价性由 TestShellCommandWordMergeLock 锁定。
func isShellCommandWord(s string, fold bool) bool {
	if !fold {
		return isShellCommandWordExact(s)
	}
	switch len(s) {
	case 2, 3, 4, 5, 6, 7, 8:
	default:
		return false
	}
	for _, w := range shellCommandWordsFold {
		if equalASCIIFold(s, w) {
			return true
		}
	}
	return false
}

// isShellCommandWordExact 是 fold=false 的精确小写判定（原 isShellCommandWord 原体）。
func isShellCommandWordExact(s string) bool {
	switch len(s) {
	case 2:
		switch s {
		case "id", "ls", "ps", "nc", "sh", "rm", "dd", "cp", "mv", "od", "wc":
			return true
		}
	case 3:
		switch s {
		case "cat", "pwd", "php", "dig", "awk", "sed", "set", "xxd", "tee", "ssh":
			return true
		}
	case 4:
		switch s {
		case "wget", "curl", "bash", "echo", "ping", "kill", "perl", "ruby", "node", "java", "find", "grep", "head", "tail", "more", "less", "sort":
			return true
		}
	case 5:
		switch s {
		case "uname", "touch", "chmod", "chown", "mkdir", "sleep":
			return true
		}
	case 6:
		switch s {
		case "whoami", "python", "base64", "printf", "getent":
			return true
		}
	case 7:
		switch s {
		case "tcpdump", "netstat":
			return true
		}
	case 8:
		switch s {
		case "nslookup", "hostname", "ifconfig", "ipconfig":
			return true
		}
	}
	return false
}

// shellCommandWordsFold 是原 isShellCommandWordASCIIFold 的完整词集。
var shellCommandWordsFold = []string{
	"id", "ls", "ps", "nc", "sh", "rm",
	"cat", "pwd", "php", "awk", "sed", "set", "ssh",
	"wget", "curl", "bash", "echo", "ping", "perl", "ruby", "node", "java", "find", "grep",
	"uname", "touch", "chmod", "chown", "mkdir", "sleep", "printf",
	"whoami", "python", "base64", "tcpdump", "getent",
	"nslookup", "hostname", "ifconfig", "ipconfig", "netstat",
}

// suspKeywordMaskTable 为每个首字母（以及空格）分配一个位。
//
// 原实现只按空格分组：只要目标串出现一个空格，就会顺序跑完 16 条
// strings.Contains。改成按「关键词首字母」分组后，缺该首字母的分组直接跳
// 过子串查找，语义(21 条 Contains 的 OR)完全不变，只是把不可能命中的查找
// 剪掉。
const (
	skSP uint32 = 1 << iota // ' '：所有带尾随空格的 SQL 关键词的共同必要字节
	skS                     // 's'：select / sleep
	skU                     // 'u'：union / update
	skI                     // 'i'：insert
	skD                     // 'd'：delete / drop / database
	skO                     // 'o'： or
	skA                     // 'a'： and / alter
	skE                     // 'e'：exec
	skT                     // 't'： table / truncate
	skF                     // 'f'： from
	skW                     // 'w'： where / waitfor
	skL                     // 'l'： like
	skH                     // 'h'： having / schema
	skB                     // 'b'：benchmark
)

var suspKeywordMaskTable = buildIndicatorMaskTable(map[string]uint32{
	" ": skSP,
	"s": skS,
	"u": skU,
	"i": skI,
	"d": skD,
	"o": skO,
	"a": skA,
	"e": skE,
	"t": skT,
	"f": skF,
	"w": skW,
	"l": skL,
	"h": skH,
	"b": skB,
})

// suspKeywordGroup 是一组共享必要条件字节位的关键词。
// need 中的每一位都必须在目标串里出现过，组内关键词才值得逐个查找。
type suspKeywordGroup struct {
	need  uint32
	words []string
}

// suspKeywordGroups 的顺序只影响多个关键词同时命中时的短路顺序，不影响结果。
var suspKeywordGroups = []suspKeywordGroup{
	{skSP | skS, []string{"select ", "sleep "}},
	{skSP | skU, []string{"union ", "update "}},
	{skSP | skI, []string{"insert "}},
	{skSP | skD, []string{"delete ", "drop "}},
	{skSP | skO, []string{" or "}},
	{skSP | skA, []string{" and ", "alter "}},
	{skSP | skE, []string{"exec "}},
	{skSP | skT, []string{" table "}},
	{skSP | skF, []string{" from "}},
	{skSP | skW, []string{" where "}},
	{skSP | skL, []string{" like "}},
	{skSP | skH, []string{" having "}},
	{skT, []string{"truncate"}},
	{skW, []string{"waitfor"}},
	{skH, []string{"schema"}},
	{skD, []string{"database"}},
	{skB, []string{"benchmark"}},
}

// buildIndicatorMaskTable 把“字节→掩码位”映射物化为 256 槽查找表。
func buildIndicatorMaskTable(groups map[string]uint32) (t [256]uint32) {
	for bs, v := range groups {
		for i := 0; i < len(bs); i++ {
			t[bs[i]] |= v
		}
	}
	return t
}

// scanIndicatorMask 单次扫描输入串，返回所有出现过的必备字节掩码。
func scanIndicatorMask(s string, table *[256]uint32) uint32 {
	var bm uint32
	for i := 0; i < len(s); i++ {
		bm |= table[s[i]]
	}
	return bm
}

// webshellIndicatorLiterals 是 hasWebshellIndicator 的全部判定项。
//
// 原实现按必备字节分组做子串查找，分组只是性能优化，语义是纯 OR。
var webshellIndicatorLiterals = []string{
	// PHP/JS 危险函数调用。
	"eval(", "assert(", "system(", "exec(", "popen(", ".exec(",
	"gzinflate(", "hex2bin(", "include(", "require(",
	// 高危内置函数与文件写入。
	"shell_exec", "base64_decode", "str_rot13(", "create_function(",
	"preg_replace(", "call_user_func", "file_put_contents",
	"include_once(", "require_once(", "__import__(",
	// 服务端代码标签。
	"<?php", "<? ", "<java.", "<%eval", "<%execute",
	// 运行时反射与容器特有入口。
	"runtime.getruntime", "cmd.exe", "os.system", "response.write",
	"server.execute", "connector.minimal",
	// ThinkPHP 与 PHP 流包装器。
	"#post_render", "#pre_render", "#lazy_builder", "\\think\\",
	"php://", "data://text/", ">shell.",
	// 其它语言入口。
	"passthru", "subprocess", "invokefunction",
}

// hasWebshellIndicator 判断目标串是否含有 WebShell 指示特征。
//
// @param s    检测目标串。
// @param gate 该目标已构建的统合扫描证据；省略时按 s 现场构建。
// @return 是否命中任一 WebShell 指示字面量。
func hasWebshellIndicator(s string, gate ...*scanGate) bool {
	if s == "" {
		return false
	}
	return firstGate(s, gate).hits.Intersects(&webshellIndicatorBits)
}

// revshellIndicatorLiterals 是 hasRevShellIndicator 的全部判定项。
//
// 与 webshell 指示器同理：原实现的分组只是性能优化，语义是纯 OR。
var revshellIndicatorLiterals = []string{
	"| bash", "|bash", "| sh", "|sh",
	"bash -i", "python -c", "python3 -c", "perl -e", " telnet ", " socket",
	"invoke-expression", "-e /bin/", "ruby -rsocket",
	"/dev/tcp",
	"mkfifo",
	"downloadstring",
	"socat ",
	"ncat ",
}

// hasRevShellIndicator 判断目标串是否含有反弹 Shell 指示特征。
//
// @param s    检测目标串。
// @param gate 该目标已构建的统合扫描证据；省略时按 s 现场构建。
// @return 是否命中任一反弹 Shell 指示字面量。
func hasRevShellIndicator(s string, gate ...*scanGate) bool {
	if s == "" {
		return false
	}
	return firstGate(s, gate).hits.Intersects(&revshellIndicatorBits)
}

// hasPathTravIndicator 在字符串含路径遍历序列或指向敏感系统文件时返回 true。
func hasPathTravIndicator(s string) bool {
	return strings.Contains(s, "..") ||
		strings.Contains(s, "%2e%2e") ||
		strings.Contains(s, "%252e") ||
		strings.Contains(s, "%252f") ||
		strings.Contains(s, "etc/") ||
		strings.Contains(s, "/proc/") ||
		strings.Contains(s, "win.ini") ||
		strings.Contains(s, "boot.ini") ||
		strings.Contains(s, "..;") ||
		strings.Contains(s, "web-inf") ||
		strings.Contains(s, "meta-inf") ||
		strings.Contains(s, "c$")
}

// owaspPatternGate 是单条规则的必要条件门。
//
// musts 必须全部出现；anyOf / anyOf2 非空时各自至少要出现一个（两组相互
// 独立，用于表达多个 OR 组之间的 AND）；fold 为真时按 ASCII 大小写折叠比较。
// 所有条件都取自正则本身可命中的必要条件，因此门未通过即不可能命中，
// 不会引入漏检。
type owaspPatternGate struct {
	musts  []string
	anyOf  []string
	anyOf2 []string
	anyOf3 []string
	fold   bool
	// check 是字面量门无法表达的额外必要条件（如位置关系）。
	// 为 nil 时不施加额外约束。
	check func(string) bool
}

// passes 判定单条门：musts 全中，且每个非空 anyOf 组至少命中一个。
func (g owaspPatternGate) passes(s string) bool {
	if g.check != nil && !g.check(s) {
		return false
	}
	for _, m := range g.musts {
		if !g.contains(s, m) {
			return false
		}
	}
	if !g.anyContained(s, g.anyOf) {
		return false
	}
	if !g.anyContained(s, g.anyOf2) {
		return false
	}
	return g.anyContained(s, g.anyOf3)
}

// contains 按门的 fold 设置选择精确或 ASCII 折叠比较。
func (g owaspPatternGate) contains(s, m string) bool {
	if g.fold {
		return containsASCIIFold(s, m)
	}
	return strings.Contains(s, m)
}

// anyContained 判定 needles 为空（不约束）或至少有一个出现在 s 中。
func (g owaspPatternGate) anyContained(s string, needles []string) bool {
	if len(needles) == 0 {
		return true
	}
	for _, m := range needles {
		if g.contains(s, m) {
			return true
		}
	}
	return false
}

// crlfHeaderNames 是 crlf:001/007/009 三条正则中响应头名分支的必要子串集合。
//
// 三条正则的头部片断都是 (set-cookie|location|content-type|x-[\w-]+)，因此
// 目标串必然包含其中至少一个子串。族指示器为覆盖真实攻击面必须保留 \r/\n
// 这类极宽的字面（否则任何含换行的载荷都要额外判族），但这些宽字面会让
// 内含换行与冒号的普通 JSON/表单正文通过族门后跑完整组正则。补上本组后，
// 不含响应头名的良性正文在门这一层就结束，不进入正则引擎。
var crlfHeaderNames = []string{"set-cookie", "location", "content-type", "x-"}

var owaspPatternGates = map[string]owaspPatternGate{
	"owasp:xxe:004":     {musts: []string{"%", ";"}},
	"owasp:ldap:004":    {musts: []string{"(|", "*", "="}},
	"owasp:nosql:014":   {musts: []string{"$", "{"}},
	"owasp:ssti:015":    {musts: []string{"{", ":", "("}},
	"owasp:ssti:016":    {musts: []string{"{", ":", "(", "}"}},
	"owasp:jndi:003":    {musts: []string{"${", "}"}},
	"owasp:graphql:006": {musts: []string{"query", ":"}},
	"owasp:graphql:007": {musts: []string{"@", "(", "if", ":", "$"}},

	// CRLF / 响应拆分族：全部正则以「换行锚点 + 响应头或协议命令」为结构，
	// 而族指示器含 location:/content-type:/fetch/quit 这类宽字面，会让整组
	// 正则在没有任何换行输入的良性目标上反复执行。下面把每条正则的锚点
	// 前移成独立的必要条件门，门不通过时直接跳过正则执行。
	"owasp:crlf:001": {musts: []string{":"}, anyOf: []string{"\r", "\n"}, anyOf2: crlfHeaderNames},
	"owasp:crlf:004": {musts: []string{"\r\n\r\n"}},
	"owasp:crlf:007": {musts: []string{":"}, anyOf: []string{"%0a", "%0d"}, anyOf2: crlfHeaderNames, fold: true},
	"owasp:crlf:009": {musts: []string{":"}, anyOf: []string{"%0a", "%0d"}, anyOf2: crlfHeaderNames, fold: true},
	"owasp:crlf:008": {anyOf: []string{"@", "rcpt", "quit", "capability", "fetch", "select", "login", "logout", "noop"}, check: crlf008Gate},
	"owasp:crlf:010": {anyOf: []string{"rcpt", "quit", "capability", "fetch", "select", "login", "logout", "noop"}, check: crlf010Gate},

	// SSRF 族：这些条件原本是 shouldScanSSRFPattern 的 switch 分支，
	// 逐规则重复扫描同一目标串。它们都是「正则命中则必然出现」的字面量，
	// 前移成门控后运行期不再产生额外字符串扫描。
	"owasp:ssrf:004": {musts: []string{"10."}, check: hasSSRFPrivate10},
	"owasp:ssrf:005": {musts: []string{"172."}},
	"owasp:ssrf:006": {musts: []string{"192.168."}},
	"owasp:ssrf:007": {anyOf: []string{"127.", "localhost"}},
	"owasp:ssrf:008": {anyOf: []string{"::1", "[::", "0.0.0.0"}},
	"owasp:ssrf:009": {musts: []string{"0x"}},
	"owasp:ssrf:010": {anyOf: []string{"file://", "gopher://", "dict://", "ldap://", "sftp://", "tftp://", "php://", "expect://", "phar://"}},
	"owasp:ssrf:011": {anyOf: []string{"http://", "https://"}},
	"owasp:ssrf:020": {anyOf: []string{"0177.", "http://0", "https://0"}},
	"owasp:ssrf:021": {anyOf: []string{".nip.io", ".xip.io", ".sslip.io"}},
	"owasp:ssrf:023": {anyOf: []string{"http://", "https://"}},

	// XSS 族：这些条件原本是 shouldScanXSSPattern 中逐规则重复扫描
	// 目标串的 switch 分支。全部转成必要条件门控，运行期零额外扫描。
	"owasp:xss:002": {musts: []string{"="}, check: hasOnEventHandler},
	"owasp:xss:011": {musts: []string{"("}, anyOf: []string{"'", `"`}, anyOf2: []string{"eval", "settimeout", "setinterval", "function"}},
	"owasp:xss:013": {musts: []string{"&#", "script"}},
	"owasp:xss:014": {musts: []string{"<", "on", "="}},
	"owasp:xss:015": {musts: []string{"="}, anyOf: []string{"<embed", "<object"}, anyOf2: []string{"data", "src"}},
	"owasp:xss:019": {musts: []string{"(", "http"}, anyOf: []string{"fetch", "xmlhttprequest"}},
	"owasp:xss:030": {musts: []string{"["}, check: hasXSSWindowQuotedBracket},
	"owasp:xss:031": {musts: []string{"[", "]"}, anyOf: []string{"'", `"`, "`"}, anyOf2: []string{"alert", "eval", "prompt", "confirm", "settimeout", "setinterval", "atob", "btoa", "fetch", "open", "execscript"}},
	"owasp:xss:034": {musts: []string{"+A"}},
	"owasp:xss:042": {musts: []string{"href"}, anyOf: []string{"<animate", "<set", "<animatetransform"}},
	"owasp:xss:045": {musts: []string{"("}, anyOf: []string{"alert", "confirm", "prompt"}},
	"owasp:xss:056": {musts: []string{":", "j", "p", "t"}},
	"owasp:xss:058": {anyOf3: []string{"name", "id"}, anyOf: []string{"document", "window", "location", "navigator", "top", "self", "frames"}, anyOf2: []string{"<form", "<input", "<img", "<a", "<embed", "<object"}},
	"owasp:xss:061": {anyOf: []string{"<math", "<svg"}, anyOf2: []string{"<style", "<mglyph", "<malignmark"}},
	"owasp:xss:063": {musts: []string{"on", "="}, anyOf: []string{"<animate", "<animatetransform", "<set"}},
	"owasp:xss:065": {musts: []string{"<", ">"}, anyOf: []string{"sanitize", "purify", "dompurify"}},
	"owasp:xss:068": {musts: []string{"new", "function"}, anyOf: []string{"'", `"`}},
	"owasp:xss:069": {musts: []string{"`"}, anyOf: []string{"alert", "prompt", "confirm"}},
	"owasp:xss:070": {musts: []string{"?."}},

	// CMD 族：正则要求 https?:// 或明确的回连目标，前移成必要条件门，
	// 避免 User-Agent 中的 curl/wget 版本串触发整串正则扫描。
	"owasp:cmd:005": {check: hasCurlWgetURL},
	"owasp:cmd:030": {check: hasCurlWgetDownloadTarget},

	// SQLi 族：把每条正则的必然字面量前移成位集合门。这些规则原本只靠
	// hint（多数为 select）放行，长目标上逐条跑正则会累积成主要开销。
	"owasp:sqli:005": {anyOf: []string{"--", "/*"}},
	"owasp:sqli:013": {musts: []string{"("}},
	"owasp:sqli:019": {musts: []string{"by"}},
	"owasp:sqli:021": {musts: []string{"(", ","}},
	"owasp:sqli:028": {musts: []string{"=", "("}},
	"owasp:sqli:031": {musts: []string{"("}, anyOf: []string{"=", "in"}},
	"owasp:sqli:032": {musts: []string{"by"}},
	"owasp:sqli:038": {musts: []string{"from"}, anyOf: []string{"--", ";", "/*", "where", "union"}},
	"owasp:sqli:041": {musts: []string{"("}, anyOf: []string{"cast", "convert"}},
	"owasp:sqli:046": {musts: []string{"("}},
	"owasp:sqli:047": {musts: []string{"*", "from"}},
}

func owaspPatternGatePass(p owaspPattern, s string) bool {
	if p.hint != "" && !strings.Contains(s, p.hint) {
		return false
	}
	if g, ok := owaspPatternGates[p.id]; ok {
		return g.passes(s)
	}
	return true
}

var jndiUnicodeEscQ = string([]byte{92, 117, 48, 48, 50, 52, 92, 117, 48, 48, 55})

// crlf008Gate 补足 crlf:008 的行首锚必要条件。
//
// 该正则以 (?:^|[\r\n]) 开头：每个分支都必须从串首或换行之后开始。
// 目标不含换行时只剩串首分支，此时只需检查串首（跳过空格/制表符）
// 的首字节就能判定是否可能命中，无需让正则引擎对整串逐位置尝试。
//
// @param s 已小写化的检测目标。
// @return 是否可能命中 crlf:008。
func crlf008Gate(s string) bool {
	if !strings.ContainsAny(s, "\r\n") {
		return crlf008HeadOK(s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\r' && c != '\n' {
			continue
		}
		if crlf008HeadOK(s[i+1:]) {
			return true
		}
	}
	return false
}

// crlf008HeadOK 判定 crlf:008 在某个行首（含串首）是否可能开始匹配。
//
// @param t 行首起的剩余串。
// @return 该行首是否可能开始匹配。
func crlf008HeadOK(t string) bool {
	for len(t) > 0 && (t[0] == ' ' || t[0] == '\t') {
		t = t[1:]
	}
	if t == "" {
		return false
	}
	switch t[0] {
	case 't', 'c', 'b', 's', 'r', 'q':
		// to/cc/bcc/subject、rcpt、quit 分支。
		return true
	case 'v':
		// v<数字> 形式的 IMAP/SMTP 协议命令。
		return len(t) > 1 && t[1] >= '0' && t[1] <= '9'
	}
	return false
}

// crlfProtoVerbs 是 crlf:008/010 中 v<数字> 之后允许的协议命令词。
var crlfProtoVerbs = []string{"capability", "fetch", "select", "login", "logout", "noop"}

// crlf010Gate 补足 crlf:010 的协议命令结构必要条件。
//
// 正则的每个分支都要求 rcpt to / quit，或 v<2~3 位数字> 后跟空白与
// IMAP/SMTP 协议命令词。目标不含这些结构时不可能命中。
//
// @param s 已小写化的检测目标。
// @return 是否可能命中 crlf:010。
func crlf010Gate(s string) bool {
	if strings.Contains(s, "rcpt") || strings.Contains(s, "quit") {
		return true
	}
	return hasVersionProtoCommand(s)
}

// hasVersionProtoCommand 扫描 v<2~3 位数字> + 空白 + 协议命令词形态。
//
// @param s 已小写化的检测目标。
// @return 是否存在该形态。
func hasVersionProtoCommand(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != 'v' {
			continue
		}
		if i > 0 {
			prev := s[i-1]
			// 正则要求 v 前是空白或串首。
			if !isRegexpSpaceByte(prev) {
				continue
			}
		}
		j := i + 1
		digits := 0
		for j < len(s) && s[j] >= '0' && s[j] <= '9' && digits <= 3 {
			j++
			digits++
		}
		if digits < 2 || digits > 3 || j >= len(s) {
			continue
		}
		// Go regexp 的 \s 为 [\t\n\f\r ]。
		if !isRegexpSpaceByte(s[j]) {
			continue
		}
		for j < len(s) && isRegexpSpaceByte(s[j]) {
			j++
		}
		rest := s[j:]
		for _, v := range crlfProtoVerbs {
			if strings.HasPrefix(rest, v) {
				return true
			}
		}
	}
	return false
}

// isRegexpSpaceByte 判断 b 是否属于 Go regexp 的 \s 字符集 [\t\n\f\r ]。
func isRegexpSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\f' || b == '\r'
}

// xssOnEventNames 是 xss:002 正则中全部 on* 事件名。
//
// 每一项都对应正则的一个 alternation 分支；手写预检必须完整覆盖，
// 否则会漏掉该事件名的 XSS 载荷。
var xssOnEventNames = []string{
	"error", "load", "click", "dblclick", "auxclick",
	"mouseover", "mouseout", "mousedown", "mouseup", "mouseenter",
	"mouseleave", "mousemove", "mousewheel",
	"focus", "focusin", "blur", "change", "submit", "toggle", "input",
	"keydown", "keyup", "keypress",
	"drag", "dragstart", "dragend", "dragover", "dragenter", "dragleave",
	"drop", "copy", "cut", "paste",
	"pointerover", "pointerdown", "pointerup", "pointercancel",
	"pointermove", "pointerenter", "pointerleave",
	"animationstart", "animationend", "animationiteration",
	"transitionend", "transitionstart", "transitionrun", "transitioncancel",
	"scroll", "wheel", "resize", "contextmenu", "message", "hashchange",
	"popstate", "beforeunload", "unload", "invalid", "select",
	"fullscreenchange", "touchstart", "touchend", "touchmove",
	"touchcancel", "beforeinput", "show",
}

// xssOnEventByFirst 按首字母索引事件名，避免在每个 on 位置遍历全部候选。
var xssOnEventByFirst = func() [256][]string {
	var m [256][]string
	for _, n := range xssOnEventNames {
		m[n[0]] = append(m[n[0]], n)
	}
	return m
}()

// hasOnEventHandler 检测 \bon(<event>)\s*= 形态。
//
// 该正则的 \b 前缀会阻止 regexp 引擎提取 "on" 字面量前缀，导致在长目标
// 上逐位置回溯。这里用单次线性扫描定位 on，再按首字母查事件名。
//
// @param s 已小写化的检测目标。
// @return 是否存在 on* 事件处理器赋值形态。
func hasOnEventHandler(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != 'o' || s[i+1] != 'n' {
			continue
		}
		if i > 0 {
			prev := s[i-1]
			if isASCIILetterOrDigit(prev) || prev == '_' {
				continue
			}
		}
		j := i + 2
		for _, name := range xssOnEventByFirst[s[j]] {
			if !strings.HasPrefix(s[j:], name) {
				continue
			}
			k := j + len(name)
			for k < len(s) && isRegexpSpaceByte(s[k]) {
				k++
			}
			if k < len(s) && s[k] == '=' {
				return true
			}
		}
	}
	return false
}

// xssWindowWords 是 xss:030/052 正则中的全局对象词集合。
var xssWindowWords = []string{"window", "self", "top", "parent", "frames", "globalthis", "this"}

// xssBracketQuoted 是 xss:030 中 [ 之后允许的引号字符集。
var xssBracketQuoted = func() (t [256]bool) {
	t['\''] = true
	t['"'] = true
	t['`'] = true
	return
}()

// xssBracketExpr 是 xss:052 中 [ 之后允许的表达式起始字符集。
var xssBracketExpr = func() (t [256]bool) {
	for _, c := range []byte{'(', '/', '!', '+', '['} {
		t[c] = true
	}
	return
}()

// hasXSSWindowQuotedBracket 检测 xss:030 的必要形态：
// 全局对象词 + 可选空白 + [ + 可选空白 + 引号。
//
// @param s 已小写化的检测目标。
// @return 是否存在该形态。
func hasXSSWindowQuotedBracket(s string) bool {
	return hasXSSWindowBracket(s, &xssBracketQuoted)
}

// hasXSSWindowExprBracket 检测 xss:052 的必要形态：
// 全局对象词 + 可选空白 + [ + 可选空白 + 表达式起始字符。
//
// @param s 已小写化的检测目标。
// @return 是否存在该形态。
func hasXSSWindowExprBracket(s string) bool {
	return hasXSSWindowBracket(s, &xssBracketExpr)
}

// hasXSSWindowBracket 扫描「全局对象词 + [ + allowed 中字符」形态。
//
// 正则以 \b(window|self|...) 开头，无法提取字面量前缀；这里按首字母
// 过滤候选位置，再逐词做前缀比较。
//
// @param s       已小写化的检测目标。
// @param allowed [ 之后允许的字符表。
// @return 是否存在该形态。
func hasXSSWindowBracket(s string, allowed *[256]bool) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'w', 's', 't', 'p', 'f', 'g':
		default:
			continue
		}
		if i > 0 {
			prev := s[i-1]
			if isASCIILetterOrDigit(prev) || prev == '_' {
				continue
			}
		}
		for _, w := range xssWindowWords {
			if !strings.HasPrefix(s[i:], w) {
				continue
			}
			j := i + len(w)
			for j < len(s) && isRegexpSpaceByte(s[j]) {
				j++
			}
			if j >= len(s) || s[j] != '[' {
				continue
			}
			j++
			for j < len(s) && isRegexpSpaceByte(s[j]) {
				j++
			}
			if j < len(s) && allowed[s[j]] {
				return true
			}
		}
	}
	return false
}

// hasSSRFPrivate10 检查 ssrf:004 的必要形态：
// / 或 @ 后紧跟 10.<d{1,3}>.<d{1,3}>.<d{1,3}>。
//
// 正则的 (https?://|ftps?://|[/@]) 前缀后一个字符必为 / 或 @，
// 因此只需检查 10. 的前一字节，无需让正则引擎在整串上逐位置回溯。
//
// @param s 已小写化的检测目标。
// @return 是否存在该形态。
func hasSSRFPrivate10(s string) bool {
	const lit = "10."
	for off := 0; off < len(s); {
		j := strings.Index(s[off:], lit)
		if j < 0 {
			return false
		}
		p := off + j
		if p > 0 {
			c := s[p-1]
			if (c == '/' || c == '@') && ssrfIPv4DigitGroupsOK(s, p+len(lit), 3) {
				return true
			}
		}
		off = p + 1
	}
	return false
}

// ssrfIPv4DigitGroupsOK 判断从 i 起是否有 n 组 1~3 位十进制数字，
// 组间以点号分隔。
//
// @param s 已小写化的检测目标。
// @param i 起始字节下标。
// @param n 需要的数字组数。
// @return 是否匹配。
func ssrfIPv4DigitGroupsOK(s string, i, n int) bool {
	for g := 0; g < n; g++ {
		digits := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' && digits < 4 {
			i++
			digits++
		}
		if digits == 0 || digits > 3 {
			return false
		}
		if g < n-1 {
			if i >= len(s) || s[i] != '.' {
				return false
			}
			i++
		}
	}
	return true
}

// 族 token。
const (
	famSSRF int32 = iota
	famPathTrav
	famXXE
	famLDAP
	famNoSQLi
	famTemplate
	famJNDI
	famCRLF
	famDeser
	famEL
	famGraphQL
	famCount // 非 token；族循环上界
)

type acFamilyNeedles struct {
	name      string
	orNeedles []string // 纯 OR 判定字面量（族自动机）
	andLeft   []string // AND 链左臂（模板族：constructor）
	andRight  []string // AND 链右臂（模板族：{{|${|<%）
	gateOnly  []string // 只进总表的必要条件字面
}

var owaspACFamilies = [famCount]acFamilyNeedles{
	famSSRF: {
		// hasSSRFIndicator（detectors_injection.go，19 条纯 OR）
		name: "ssrf",
		orNeedles: []string{
			"://", "169.254.169.254", "metadata.google", "100.100.100.200",
			"x-aws-ec2-metadata", "localhost", "127.0.", "127.1", "::ffff:", "::1",
			"0x7f", "0x7f000001", "0x0a0a0a0a", "unix:", "0177.0",
			".nip.io", ".xip.io", ".sslip.io", "2130706433",
		},
	},
	famPathTrav: {
		// hasPathTravIndicator（indicators.go，11 条纯 OR）
		name: "path_trav",
		orNeedles: []string{
			"..", "%2e%2e", "%252e", "%252f", "etc/", "/proc/",
			"win.ini", "boot.ini", "..;", "web-inf", "meta-inf",
			"c$", "admin$", "ipc$",
		},
	},
	famXXE: {
		name: "xxe",
		orNeedles: []string{
			"<!doctype", "<!entity", "!entity", "xsi:", " system ",
			" public ", "xi:include", "xs:include", "xs:import",
			"xs:schemalocation", "file://", "expect://", "php://",
		},
		gateOnly: []string{"%"},
	},
	famLDAP: {
		name: "ldap",
		orNeedles: []string{
			")(", "objectclass", ")(|", ")(&",
			// LDAP 属性 OID（userPassword 2.5.13.18 / uniqueMember
			// 2.5.4.31 等 LDAP-X.500 标准属性值）；纯数字加点的形态
			// 只出现在 OID/版本号语境，误报极低。
			"2.5.13.18",
		},
	},
	famNoSQLi: {
		name: "nosqli",
		orNeedles: []string{
			"$where", "$ne", "$gt", "$lt", "$gte", "$lte", "$regex",
			"$or", "$and", "$exists", "$lookup", "$function", "$accumulator",
			"$match", "/_all_docs", "/_find", "/_view/", "allow filtering",
			"evalsha", "eval ", "this.",
			// HTML 实体转义后的 $or（&#36; 形态经实体解码还原，$apos;or
			// 半实体形态则原样保留），配合 nosql:005 的 `$or[:[]` 需在
			// 门内可见。只在实体上下文（$apos;）出现，非转义输入不会拼出。
			"$apos;or",
			"injection.", "new date",
		},
	},
	famTemplate: {
		// hasTemplateInjectionIndicator（detectors_injection.go，14 条纯 OR +
		// AND 链 constructor && ({{|${|<%)；三条括号标记也是纯 OR 项）
		name: "template",
		orNeedles: []string{
			"{{", "${", "<%", "__class__", "__proto__", "__subclasses__",
			"__builtins__", "__import__", "getclass(", "java.lang.",
			"process.env", "{php}", "$self.", "{dede:", "#{",
		},
		andLeft:  []string{"constructor"},
		andRight: []string{"{{", "${", "<%"},
	},
	famJNDI: {
		// hasJNDIIndicator（detectors_encoding.go，8 条纯 OR；末条为 12 字节
		// ASCII 序列，用 jndiUnicodeEscQ 构建（见其注释））
		name: "jndi",
		orNeedles: []string{
			"jndi:", "${lower", "${upper", "${env:", "${sys:", "${java:",
			"${base64:", jndiUnicodeEscQ,
		},
	},
	famCRLF: {
		name: "crlf",
		orNeedles: []string{
			"%0d", "%0a", "\r", "\n", "set-cookie:", "location:", "content-type:",
			"rcpt to:", "capability", "fetch", "quit",
		},
	},
	famDeser: {
		// hasDeserializationIndicator（detectors_encoding.go，20 条 Contains
		// 纯 OR，含 Java 序列化魔数（0xAC 0xED 0x00 0x05 四字节），
		// 另外两条 PHP 序列化状态机由网关在回放层原样调用，
		// "o:"/"s:" 是它们的必要条件字面）
		name: "deser",
		orNeedles: []string{
			"\xac\xed\x00\x05", "aced0005", "ro0ab", "ysoserial", "aaeaaad//", "nd_func",
			"objectinputstream", "xstream", "<sorted-set", "<tree-map",
			"<dynamic-proxy", "java.util", "javax.", "jdk.",
			"com.sun.org.apache.xalan", "org.apache.commons.collections",
			"readobject", "deserializ",
			// PHP gadget 类名：Craft CMS 反序列化链（CVE-2023-41892）与
			// ThinkPHP _method=__construct 过滤器注入的入口字面量。
			"guzzlehttp", "__construct",
		},
		gateOnly: []string{"o:", "s:"},
	},
	famEL: {
		name: "el",
		orNeedles: []string{
			"#{t(", "${t(", "${", "java.lang.", "getclass()", "getruntime",
			"getdeclaredmethods", "#rt", "@java.", "#context", "%{#",
			"new java.", "newjava.",
			// Spring4Shell 数据绑定链（CVE-2022-22965）：
			// class.module.classLoader.resources... 不含 EL 定界符，
			// 必须由独立字面量放行（owasp:el:015）。
			"classloader.resources",
			// YAML 反序列化 RCE 载荷头（!!python/object/new:exec 等）：
			// 该类文本形态归 EL 族拦（owasp:el:014）。!! 双叹号缩写词在自然
			// 语言与常见 URL/form 输入中不出现，误报可忽略，防总表负短路。
			"!!",
		},
	},
	famGraphQL: {
		// hasGraphQLIndicator（detectors_injection.go，4 条纯 OR）
		name: "graphql",
		orNeedles: []string{
			"__schema", "__type", "__typename", "introspectionquery",
		},
	},
}

// hasACIndicator 判定族指示器是否命中。
//
// 生产热路径由 scanGate.family 使用预计算的位集合，本函数只在需要独立判定
// 单个族（测试、离线工具）时使用，会为目标串执行一次统合扫描。
func hasACIndicator(fam int32, s string) bool {
	return scanGateOf(s).family(fam, s)
}
