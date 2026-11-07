package owasp

import (
	"path/filepath"
	"regexp"
	"strings"

	"My-OpenWaf/internal/core/score"
)

var dangerousExtensions = map[string]bool{
	".php":      true,
	".php3":     true,
	".php4":     true,
	".php5":     true,
	".phtml":    true,
	".pht":      true,
	".phar":     true,
	".shtml":    true,
	".shtm":     true,
	".stm":      true,
	".jsp":      true,
	".jspx":     true,
	".asp":      true,
	".aspx":     true,
	".cer":      true,
	".cfm":      true,
	".exe":      true,
	".sh":       true,
	".bat":      true,
	".cmd":      true,
	".ps1":      true,
	".dll":      true,
	".so":       true,
	".war":      true,
	".jar":      true,
	".pl":       true,
	".py":       true,
	".rb":       true,
	".htaccess": true,
}

func normalizeUploadFilename(filename string) string {
	for {
		ext := filepath.Ext(filename)
		if ext == "" {
			return filename
		}
		base := filename[:len(filename)-len(ext)]
		trimmed := strings.TrimRight(base, " \t;:")
		if trimmed == base {
			return filename
		}
		filename = trimmed + ext
	}
}

func checkFileUpload(filename, contentType string) (OWASPHit, bool) {
	if filename == "" {
		return OWASPHit{}, false
	}
	lower := strings.ToLower(filename)

	// 文件名中的空字节注入。
	if strings.Contains(lower, "\x00") || strings.Contains(lower, "%00") {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:001", Score: 6,
			Desc: "文件名中包含空字节"}, true
	}

	// 文件名中的路径遍历（如 ../../tmp/shell.php）
	if strings.Contains(lower, "../") || strings.Contains(lower, "..\\") {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:006", Score: 6,
			Desc: "文件名中包含路径遍历"}, true
	}

	// 归一化用于伪装可执行扩展名的空格与后缀分隔符。
	normalized := normalizeUploadFilename(lower)

	// 双扩展名，例如 shell.php.jpg、shell.php .jpg 或 shell.php;.jpg。
	ext := filepath.Ext(normalized)
	if ext != "" {
		withoutExt := normalized[:len(normalized)-len(ext)]
		secondExt := filepath.Ext(withoutExt)
		if secondExt != "" && dangerousExtensions[secondExt] {
			return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:002", Score: 5,
				Desc: "双扩展名上传：" + secondExt + ext}, true
		}
	}

	if dangerousExtensions[ext] {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:003", Score: 5,
			Desc: "危险文件扩展名：" + ext}, true
	}

	// 同时检查未归一化的原始扩展名。
	origExt := filepath.Ext(lower)
	if origExt != ext && dangerousExtensions[origExt] {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:003", Score: 5,
			Desc: "危险文件扩展名：" + origExt}, true
	}

	// .htaccess 覆写尝试
	if strings.HasSuffix(lower, ".htaccess") || lower == ".htaccess" {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:004", Score: 5,
			Desc: "htaccess 覆写尝试"}, true
	}

	// Content-Type 与图片扩展名不匹配
	if (origExt == ".jpg" || origExt == ".jpeg" || origExt == ".png" || origExt == ".gif") &&
		contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "image/") {
		return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:005", Score: 3,
			Desc: "图片文件的 content-type 不匹配"}, true
	}

	// Content-Type 不匹配：可执行扩展名搭配图片 Content-Type（绕过尝试）。
	// 攻击者可能上传 shell.php 并声明 Content-Type: image/jpeg，以绕过服务端检查。
	if contentType != "" && strings.HasPrefix(strings.ToLower(contentType), "image/") {
		execExts := map[string]bool{
			".php": true, ".php3": true, ".php4": true, ".php5": true, ".phtml": true, ".pht": true,
			".jsp": true, ".jspx": true, ".asp": true, ".aspx": true, ".cfm": true,
			".shtml": true, ".shtm": true, ".stm": true,
		}
		if execExts[origExt] || execExts[ext] {
			return OWASPHit{Category: CatFileUpload, RuleID: "owasp:upload:007", Score: 5,
				Desc: "可执行扩展名伪装为图片 content-type"}, true
		}
	}

	return OWASPHit{}, false
}

// hasJNDIIndicator 在字符串含 JNDI/Log4Shell 风格注入标记时返回 true。
func hasJNDIIndicator(s string) bool {
	return strings.Contains(s, "jndi:") ||
		strings.Contains(s, "${lower") ||
		strings.Contains(s, "${upper") ||
		strings.Contains(s, "${env:") ||
		strings.Contains(s, "${sys:") ||
		strings.Contains(s, "${java:") ||
		strings.Contains(s, "${base64:") ||
		strings.Contains(s, "\\u0024\\u007") // Unicode 转义的 ${
}

var jndiPatterns = []owaspPattern{
	{regexp.MustCompile(`\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)s?://`), 6, "owasp:jndi:001", "jndi:"},
	{regexp.MustCompile(`\$\{(lower|upper|env|sys|java|base64):.*\}`), 4, "owasp:jndi:002", ""},
	{regexp.MustCompile(`\$\{.*\$\{.*\}\}`), 3, "owasp:jndi:003", ""},
	{regexp.MustCompile(`\$\{(env|sys):.*\}`), 4, "owasp:jndi:004", ""},
	// 拆字符 / 混淆的 JNDI：${j${::-n}d${::-i}:...}
	{regexp.MustCompile(`\$\{[^}]*j[^}]*\$\{[^}]*\}[^}]*n[^}]*d[^}]*i\s*:`), 5, "owasp:jndi:005", "jndi"},
	// URL 编码的 JNDI：%24%7Bjndi:
	{regexp.MustCompile(`%24%7[bB]jndi\s*%3[aA]`), 5, "owasp:jndi:006", "%24%7"},
	// Unicode 转义的 JNDI：\u0024\u007bjndi:
	{regexp.MustCompile(`\\u0024\\u007[bB]jndi`), 5, "owasp:jndi:007", "\u0024"},
}

func checkJNDI(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !gate.family(famJNDI, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range jndiPatterns {
		if !gate.patternGate(p, s) {
			continue
		}
		if p.re.MatchString(s) {
			if acc == nil {
				acc = acquireOWASPAcc(threshold)
			}
			acc.Add(p.id, p.score)
			if acc.Exceeded() {
				id, total := acc.Attribution()
				return OWASPHit{Category: CatJNDI, RuleID: id, Score: total, Desc: "JNDI/Log4Shell 注入特征"}, true
			}
		}
	}
	return OWASPHit{}, false
}

var reRFC2047EncodedWord = regexp.MustCompile(`=\?[^?\s()<>@,;:"/\[\]?.=]+\?[bBqQ]\?([^?]*)\?=`)

var crlfPatterns = []owaspPattern{
	{regexp.MustCompile(`[\r\n]+\s*(set-cookie|location|content-type|x-[\w-]+)\s*:`), 6, "owasp:crlf:001", ""},
	{regexp.MustCompile(`%0d%0a\s*(set-cookie|location|content-type)\s*:`), 6, "owasp:crlf:002", "%0d%0a"},
	{regexp.MustCompile(`%0d%0a%0d%0a`), 5, "owasp:crlf:003", "%0d%0a%0d%0a"},
	{regexp.MustCompile(`\r\n\r\n`), 4, "owasp:crlf:004", ""},
	// 乱序双编码 CRLF（%25%30%41%25%30%44Set-cookie、%25%30%44%25%30%41… 与
	// 各单编码组合）：%0[ad] 对必须后跟响应头名才算注入。裸编码换行对在
	// 表单/JSON 数据体（如 %0D%0D%3A%0A%5B 格式化 JSON）中高频出现且无
	// 响应拆分后果，不能作为独立告警面。
	{regexp.MustCompile(`%0[ad]%0[ad]\s*(set-cookie|location|content-type|x-[\w-]+)\s*:`), 4, "owasp:crlf:007", ""},
	// 单层残余编码 CRLF 后紧跟响应/邮件头（%25%30%41Set-cookie 经一次
	// PathUnescape 后残余 %0a/Set-cookie 形态）。
	{regexp.MustCompile(`%0[ad]\s*(set-cookie|location|content-type)\s*:`), 4, "owasp:crlf:009", ""},
	// 邮件头 / 协议命令注入：行首（或换行后）出现 to:/cc:/bcc:/subject: 带
	// 邮箱接收方、RCPT TO: 送达命令、裸 QUIT 会话终止，或 IMAP/SMTP 协议命令
	// （V100 CAPABILITY、V101 FETCH 等）。协议词限行边界（双锁），自然文本
	// 行首 "quit" 仅当整行只含该词才命中。
	//
	// 不使用 (?i)：本检测的全部输入都经过 normalizeTarget 的 toLowerASCII，
	// 已是小写；带 (?i) 会让 regexp 把每个字符类展开成大小写对，
	// NFA 状态数翻倍，直接抬高这条长正则的执行成本。
	{regexp.MustCompile(`(?:^|[\r\n])[ \t]*(?:(?:to|cc|bcc|subject)\s*:\s*\S+@\S+|rcpt\s+to\s*:|quit[ \t]*(?:[\r\n]|$)|v\d+\s+(?:capability|fetch|select|login|logout|noop)\b)`), 4, "owasp:crlf:008", ""},
	// 空白折叠后的协议命令：base64/URL 解码出的 \r\nV100 CAPABILITY 等经
	// normalize 折叠为 " v100 capability ..."，行界锁失效。折叠后的行首
	// 由空白分隔词锚定：v\d{2,3} 必须紧跟协议命令词，且前一个是空格
	//（原行界位置）或串首。同上，不使用 (?i)。
	{regexp.MustCompile(`(?:^|[\s])(?:v\d{2,3}\s+(?:capability|fetch|select|login|logout|noop)\b|(?:rcpt\s+to|quit)\s*(?:[;:\s]|$))`), 4, "owasp:crlf:010", ""},
}

func hasCRLFIndicator(s string) bool {
	return strings.Contains(s, "%0d") ||
		strings.Contains(s, "%0a") ||
		strings.Contains(s, "\r") ||
		strings.Contains(s, "\n") ||
		strings.Contains(s, "set-cookie:") ||
		strings.Contains(s, "location:") ||
		strings.Contains(s, "content-type:") ||
		strings.Contains(s, "rcpt to:") ||
		strings.Contains(s, "capability") ||
		strings.Contains(s, "fetch") ||
		strings.Contains(s, "quit")
}

func hasDeserializationIndicator(s string) bool {
	return strings.Contains(s, "\xac\xed\x00\x05") ||
		strings.Contains(s, "aced0005") ||
		strings.Contains(s, "ro0ab") ||
		hasPHPSerializedObjectIndicator(s) ||
		hasPHPSerializedStringPairIndicator(s) ||
		strings.Contains(s, "ysoserial") ||
		strings.Contains(s, "aaeaaad//") ||
		strings.Contains(s, "nd_func") ||
		strings.Contains(s, "objectinputstream") ||
		strings.Contains(s, "xstream") ||
		strings.Contains(s, "<sorted-set") ||
		strings.Contains(s, "<tree-map") ||
		strings.Contains(s, "<dynamic-proxy") ||
		strings.Contains(s, "java.util") ||
		strings.Contains(s, "javax.") ||
		strings.Contains(s, "jdk.") ||
		strings.Contains(s, "com.sun.org.apache.xalan") ||
		strings.Contains(s, "org.apache.commons.collections") ||
		strings.Contains(s, "readobject") ||
		strings.Contains(s, "deserializ") ||
		// PHP gadget 类名：Craft CMS 反序列化链（CVE-2023-41892）与
		// ThinkPHP _method=__construct 过滤器注入的入口字面量。
		strings.Contains(s, "guzzlehttp") ||
		strings.Contains(s, "__construct")
}

func hasPHPSerializedObjectIndicator(s string) bool {
	for i := 0; i+3 < len(s); i++ {
		if s[i] != 'o' || s[i+1] != ':' {
			continue
		}
		j := i + 2
		if j >= len(s) || !isASCIIDigitByte(s[j]) {
			continue
		}
		for j < len(s) && isASCIIDigitByte(s[j]) {
			j++
		}
		if j+1 < len(s) && s[j] == ':' && s[j+1] == '"' {
			return true
		}
	}
	return false
}

func hasPHPSerializedStringPairIndicator(s string) bool {
	for i := 0; i+5 < len(s); i++ {
		if s[i] != 's' || s[i+1] != ':' {
			continue
		}
		j := i + 2
		if j >= len(s) || !isASCIIDigitByte(s[j]) {
			continue
		}
		for j < len(s) && isASCIIDigitByte(s[j]) {
			j++
		}
		if j+1 >= len(s) || s[j] != ':' || s[j+1] != '"' {
			continue
		}
		contentStart := j + 2
		for endQuote := contentStart; endQuote < len(s); endQuote++ {
			if s[endQuote] != '"' {
				continue
			}
			next := endQuote + 1
			if next+3 >= len(s) || s[next] != ';' || s[next+1] != 's' || s[next+2] != ':' {
				break
			}
			k := next + 3
			if k >= len(s) || !isASCIIDigitByte(s[k]) {
				break
			}
			for k < len(s) && isASCIIDigitByte(s[k]) {
				k++
			}
			if k < len(s) && s[k] == ':' {
				return true
			}
			break
		}
	}
	return false
}

func checkCRLF(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	// 本组正则在归一化前提下已去掉 (?i)（检测主循环传入的是 normalizeTarget
	// 的小写结果）。在此就地统一大小写，使函数契约不依赖调用方：
	// 输入非小写时重建门控，避免位集合与目标串大小写不一致导致漏判。
	if lower := toLowerASCII(s); lower != s {
		s, gate = lower, nil
	}
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !gate.family(famCRLF, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则；
	// FP 抑制器前移到 Add 之前，被抑制的规则既不计分也不参与归因。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range crlfPatterns {
		if !gate.patternGate(p, s) {
			continue
		}
		if !p.re.MatchString(s) {
			continue
		}
		if isCRLFFalsePositive(s, p.id) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatCRLF, RuleID: id, Score: total, Desc: "CRLF 注入 / HTTP 响应拆分"}, true
		}
	}
	// RFC-2047 编码头注入：=?charset?B|Q?payload?= 形态仅当 payload 同时存在
	// CR/LF（裸字节或 %0d/%0a 编码）时才算注入——否则只是合法编码头措辞。
	if strings.Contains(s, "=?") {
		if m := reRFC2047EncodedWord.FindStringSubmatch(s); m != nil && strings.ContainsAny(m[1], "\r\n") {
			return OWASPHit{Category: CatCRLF, RuleID: "owasp:crlf:006", Score: 3, Desc: "RFC-2047 编码头内嵌换行注入"}, true
		}
	}
	return OWASPHit{}, false
}

// hasELIndicator 在字符串含足以支撑跑完整 EL 正则组的表达式语言
// （Spring EL、OGNL、SpEL）注入标记时返回 true。
func hasELIndicator(s string) bool {
	return strings.Contains(s, "#{t(") ||
		strings.Contains(s, "${t(") ||
		strings.Contains(s, "${") ||
		strings.Contains(s, "java.lang.") ||
		strings.Contains(s, "getclass()") ||
		strings.Contains(s, "getruntime") ||
		strings.Contains(s, "getdeclaredmethods") ||
		strings.Contains(s, "#rt") ||
		strings.Contains(s, "@java.") ||
		strings.Contains(s, "#context") ||
		strings.Contains(s, "%{#") ||
		strings.Contains(s, "new java.") ||
		strings.Contains(s, "newjava.") ||
		// Spring4Shell 数据绑定链（class.module.classLoader.resources...）：
		// 该形态不含任何 EL 定界符，必须由独立字面量放行。
		strings.Contains(s, "classloader.resources") ||
		// YAML 反序列化 RCE 载荷头（!!python/object/new:exec 等）：
		// 双叹号在自然语言与常见 URL/form 输入中不出现，误报可忽略。
		strings.Contains(s, "!!")
}

var exprLangPatterns = []owaspPattern{
	// Spring 表达式语言
	{regexp.MustCompile(`#\{t\(java\.lang\.`), 6, "owasp:el:001", "java.lang."},
	{regexp.MustCompile(`\$\{t\(java\.lang\.`), 6, "owasp:el:002", "java.lang."},
	// OGNL
	{regexp.MustCompile(`%\{.*getclass\(\)`), 5, "owasp:el:003", "getclass()"},
	{regexp.MustCompile(`\(#rt\s*=\s*@java\.lang\.runtime\)`), 6, "owasp:el:004", "@java.lang.runtime"},
	// 通用类/运行时访问
	{regexp.MustCompile(`java\.lang\.(runtime|processbuilder|class|system)`), 4, "owasp:el:005", "java.lang."},
	{regexp.MustCompile(`getruntime\(\)\s*\.\s*exec\s*\(`), 5, "owasp:el:006", "getruntime()"},
	// Struts2 OGNL：%{#context['com.opensymphony...
	{regexp.MustCompile(`%\{#context\[`), 5, "owasp:el:007", "%{#context"},
	// OGNL 重定向/动作：redirect:${...} 或 action:${...}
	{regexp.MustCompile(`(redirect|action)\s*:\s*\$\{`), 5, "owasp:el:008", ""},
	// OGNL 静态方法调用：@class@method
	{regexp.MustCompile(`@java\.\w+\.\w+@\w+`), 5, "owasp:el:009", "@java."},
	// java.net.URL / new java 构造
	{regexp.MustCompile(`\bnew\s*java\.\w+\.`), 4, "owasp:el:010", "java."},
	// OGNL #context.get / #req=#context
	{regexp.MustCompile(`#(req|request|response|session|application|context)\s*[=.]`), 5, "owasp:el:011", ""},
	// OGNL 反射链：getDeclaredMethods + invoke
	{regexp.MustCompile(`getdeclaredmethods\b.*\.invoke\s*\(`), 5, "owasp:el:012", "getdeclaredmethods"},
	// OGNL 反射链：getClass().forName() 或 Class.forName()
	{regexp.MustCompile(`(getclass\(\)|class)\s*\.\s*forname\s*\(`), 4, "owasp:el:013", "forname"},
	// YAML 反序列化 RCE 载荷头（!!python/object/new:exec / !!javax.script.ScriptEngineManager
	// 等）：与 deser 族的序列化字节/协议形态（rO0AB、%ac%ed、PHP o: 等）互不重叠，
	// 文本形态必须由 EL 族拦。gotestwaf rce 载荷 !!python/… 命中。
	{regexp.MustCompile(`!!(?:python|ruby|perl|node|java|yaml|yml|javax|org|com)[/\w.:]*`), 4, "owasp:el:014", "!!"},
	// Spring4Shell（CVE-2022-22965）数据绑定链：通过 class.module.classLoader
	// 访问 Tomcat AccessLogValve 的 resources.context 属性写入 webshell。
	// 仅匹配必须实际落到 resources 节点的利用形态；侦察阶段常见的
	// `class.module.classLoader.DefaultAssertionStatus=` 空探测不触发，
	// 避免把参数名探针计入误报。全语料黑 46 / 白 0（同前缀白样本
	// 仅带 DefaultAssertionStatus，不含 resources）。
	{regexp.MustCompile(`\bclass\s*\.\s*(?:module\s*\.\s*)?classloader\s*\.\s*resources`), 6, "owasp:el:015", "classloader.resources"},
}

func checkExprLang(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !gate.family(famEL, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则；
	// FP 抑制器前移到 Add 之前，被抑制的规则既不计分也不参与归因。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range exprLangPatterns {
		if !gate.patternGate(p, s) {
			continue
		}
		if !p.re.MatchString(s) {
			continue
		}
		if isELFalsePositive(s, p.id) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatExprLang, RuleID: id, Score: total, Desc: "表达式语言注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

var deserialPatterns = []owaspPattern{
	// Java 序列化魔数
	{regexp.MustCompile(`\xac\xed\x00\x05`), 6, "owasp:deser:001", ""},
	// 十六进制编码的 Java 序列化：aced0005（URL 参数中常见）
	{regexp.MustCompile(`aced0005`), 6, "owasp:deser:008", "aced0005"},
	// PHP 序列化
	{regexp.MustCompile(`o:\d+:"[^"]+"`), 4, "owasp:deser:002", "o:"},
	// URL 参数中的 PHP 序列化：s:11:"key";s:16:"value"
	{regexp.MustCompile(`s:\d+:"[^"]*";s:\d+:`), 4, "owasp:deser:009", ""},
	// Python pickle
	{regexp.MustCompile(`c(os|posix|nt)\n(system|popen)`), 5, "owasp:deser:003", ""},
	// .NET ViewState
	{regexp.MustCompile(`__viewstate.*ysoserial`), 5, "owasp:deser:004", ""},
	// Ruby Marshal——要求版本字节 + 类型标识，避免命中随机二进制
	{regexp.MustCompile(`\x04\x08[\x30\x49\x5b\x6f\x7b]`), 3, "owasp:deser:005", ""},
	// .NET BinaryFormatter / LosFormatter 魔数
	{regexp.MustCompile(`aaeaaad//`), 5, "owasp:deser:006", "aaeaaad//"},
	// Node.js serialize-javascript RCE 模式
	{regexp.MustCompile(`\{"rce":\s*"_\$\$nd_func\$\$_`), 5, "owasp:deser:007", "nd_func"},
	// Java 序列化 base64 魔数：rO0AB（\xac\xed\x00\x05 的 base64）
	{regexp.MustCompile(`ro0ab`), 5, "owasp:deser:010", "ro0ab"},
	// .NET ViewState base64 标记
	{regexp.MustCompile(`javax\.faces\.viewstate\s*=\s*ro0ab`), 6, "owasp:deser:011", "ro0ab"},
	// 原始 Java 序列化魔数字节（URL 编码或十六进制）
	{regexp.MustCompile(`(%ac%ed|aced0005)`), 5, "owasp:deser:012", ""},
	// XStream gadget 链
	{regexp.MustCompile(`<(sorted-set|tree-map|java\.util|dynamic-proxy|javax\.\w+\.|jdk\.\w+\.)`), 5, "owasp:deser:013", ""},
	// Java ObjectInputStream——用于反序列化不可信数据
	{regexp.MustCompile(`\bobjectinputstream\b`), 4, "owasp:deser:014", "objectinputstream"},
	// Apache Xalan gadget 链（CVE-2022-34169 等）
	{regexp.MustCompile(`com\.sun\.org\.apache\.xalan\b`), 5, "owasp:deser:015", "com.sun.org.apache.xalan"},
	// Apache Commons Collections gadget 链（被广泛利用）
	{regexp.MustCompile(`org\.apache\.commons\.collections\b`), 5, "owasp:deser:016", "org.apache.commons.collections"},
	// 可疑序列化上下文中的 java.util.HashMap（gadget 触发类）
	{regexp.MustCompile(`java\.util\.hashmap\b.{0,100}(aced|ro0ab|serial|objectinput|readobject|deserializ)`), 5, "owasp:deser:017", ""},
	// PHP 反序列化链的 Guzzle FnStream gadget（Craft CMS CVE-2023-41892 等）。
	// 类名只在攻击载荷与库源码中出现；JSON 编码层会把反斜杠转义为 1-2 个，
	// 故按反斜杠数量区间匹配。全语料黑 97 / 白 0。
	{regexp.MustCompile(`guzzlehttp\\{1,2}psr7\\{1,2}fnstream`), 6, "owasp:deser:018", "guzzlehttp"},
	// ThinkPHP 5.x 的 _method=__construct 过滤器注入：表单值恰为 __construct。
	// 该值是 PHP 魔术方法名，正常业务参数值不使用；全语料黑 13 / 白 0。
	{regexp.MustCompile(`^__construct$`), 4, "owasp:deser:019", "__construct"},
}

func checkDeserialization(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	// 直接检查二进制 Java 序列化魔数字节
	if strings.Contains(s, "\xac\xed\x00\x05") {
		return OWASPHit{Category: CatDeserial, RuleID: "owasp:deser:001", Score: 5, Desc: "Java 序列化魔数"}, true
	}
	if !gate.family(famDeser, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则；
	// FP 抑制器前移到 Add 之前，被抑制的规则既不计分也不参与归因。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range deserialPatterns {
		if !gate.patternGate(p, s) {
			continue
		}
		if !p.re.MatchString(s) {
			continue
		}
		if isDeserFalsePositive(s, p.id) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatDeserial, RuleID: id, Score: total, Desc: "反序列化攻击特征"}, true
		}
	}
	return OWASPHit{}, false
}
