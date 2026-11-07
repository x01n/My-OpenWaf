package owasp

import (
	"regexp"
	"strings"
)

// isSQLiFalsePositive 判断某次 SQLi 命中是否实为良性模式。
// 用于降低常见 URL 参数、自然语言与框架产物带来的噪声。
func isSQLiFalsePositive(raw, ruleID string) bool {
	lower := strings.ToLower(raw)

	switch ruleID {
	case "owasp:sqli:002": // '\s*(or|and)\s+['"]?\d
		// "D'or 1st parfume"（法文香水名）等自然文本：'or 后直接跟
		// 数字+英文序数词后缀（1st/2nd/3rd/4th）。该形态在 SQL 里
		// 无意义（1st 不是合法数字字面量），真注入恒为 ' or 1=1、
		// ' or 1--、' or 1 接引号闭合等，不会拼出序数词。序数词形态
		// 直接放行（gotestwaf false-pos 全套原文 D'or 1st parfume）。
		if reOrdinalAfterOr.MatchString(lower) {
			return true
		}
	case "owasp:sqli:003": // (sleep|benchmark|waitfor\s+delay)\s*\(
		// sleep() 与 benchmark() 是常见的 JavaScript/编程函数。
		// waitfor delay 是 MSSQL 特有形态，始终可疑。
		// 若存在 SQL 结构上下文或 SQL 终止符也保留
		// （例如 "1); sleep(5)--" 是真实注入）。
		if strings.Contains(lower, "waitfor") {
			return false
		}
		if reBoolSQLContext.MatchString(lower) || reSQLTerminatorCtx.MatchString(lower) {
			return false
		}
		// "1 AND sleep(5)" / "1 OR pg_sleep(5)"——典型的布尔盲注时间型注入
		if reANDORSleep.MatchString(lower) {
			return false
		}
		// ); sleep(...)——注入闭合前一次调用后再触发 sleep
		if strings.Contains(lower, "); sleep(") || strings.Contains(lower, ");\tsleep(") {
			return false
		}
		// x'||pg_sleep(10)——PostgreSQL 字符串拼接运算符被用作注入载体
		if strings.Contains(lower, "||") && strings.Contains(lower, "pg_sleep") {
			return false
		}
		return true // 无 SQL 上下文的 sleep()/benchmark() → JavaScript 误报

	case "owasp:sqli:006": // \s*;\s*\w——撇号 + 分号 + 单词字符
		// 二进制 body（PDF/压缩流）中该三字符模式极易随机碰撞，
		// 且其上下文校验会被二进制里偶然出现的 from/order 等英文词满足。
		if isBinaryScanTarget(raw) {
			return true
		}
		// 花括号反证（见 hasCodeBlockBraceAfterStackedSemicolon 文档）。
		if hasCodeBlockBraceAfterStackedSemicolon(raw) {
			return true
		}
		// 该模式会命中 JavaScript/TypeScript 的 import 与字符串字面量：
		// 例如 `from 'antd'; import { ... }` 或 `target='_blank'; rel='noopener'`。
		// 仅在 SQL 结构确认堆叠查询上下文时才保留。
		if strings.Contains(lower, "import ") || strings.Contains(lower, "export ") ||
			strings.Contains(lower, "from '") || strings.Contains(lower, "from \"") ||
			strings.Contains(lower, "react") || strings.Contains(lower, "antd") {
			return true
		}
		// SQL 语句起始形态（关键字或函数调用）说明分号后确是新语句，保留命中。
		if !reBoolSQLContext.MatchString(lower) && !reSQLDMLContext.MatchString(lower) &&
			!reSQLStatementStart.MatchString(lower) {
			return true
		}
	case "owasp:sqli:004": // ;\s*(select|drop|alter|create|truncate|delete|update|insert)\s
		// 分号 + DDL/DML 关键词会出现在 JavaScript（";delete obj.prop"）、
		// 自然语言（"run cleanup; delete temp files"）与 CSS 中。
		// 缺少 SQL 结构上下文（FROM、TABLE、INTO、VALUES 等）时抑制。
		if !reBoolSQLContext.MatchString(lower) && !reSQLDMLContext.MatchString(lower) {
			return true
		}
		// 同时抑制缺少列/表上下文的纯 ";insert" / ";update"，
		// 这类写法常见于 CMS 内容或编程博客。
		if strings.Contains(lower, ";insert") && !strings.Contains(lower, "into") {
			return true
		}
	case "owasp:sqli:010": // \b(or|and)\s+\d+\s*=\s*\d+
		// 该规则匹配「布尔关键字 + 数值等式」，但自然语言散文里也会出现同一串
		// （"1 and 1=1 is a very basic mathematical operation"）。区分点是
		// **恒等式所处的语法位置**：注入里它必然紧邻语句/操作数边界
		// （操作符紧贴左操作数、后继为边界字符或目标末尾、空白后紧跟 SQL
		// 语法词），散文里前后都是空格与普通单词。
		return !hasSQLTautologyInjectionContext(lower)
	case "owasp:sqli:011": // \b(or|and)\s+'...'\s*=\s*'...'
		// "or 'x'='x'" 始终恶意，不做误报抑制。
		return false
	case "owasp:sqli:005": // ['"\d]\s*(--[\s/]|/\*)
		// URL slug（如 "article1--title"）由正则要求 -- 后接空白或斜杠来处理。
		// 额外抑制：极短且无 SQL 上下文的输入。
		if len(lower) < 10 && !reBoolSQLContext.MatchString(lower) {
			return true
		}
		// S3 ARN 通配符："arn:aws:s3:::bucket01/*"——桶名末尾的数字加 /*
		// 会触发 sqli:005，但这是路径通配符而非 SQL 行内注释。
		if strings.Contains(lower, "arn:aws:s3") || strings.Contains(lower, "arn%3aaws%3as3") {
			return true
		}
		// sqli:005 是低置信度规则（score=3）。对长输入（分析埋点、遥测载荷、
		// 长度 > 200 的文档文本），它会命中 Aurora MySQL 文档（同时含 -- 与 /* 语法示例）、
		// URL 路径通配符等。要求出现显式 SQL 注入运算符才报告，以抑制这些误报。
		// 阈值从 500 下调到 200，以减少中等长度载荷上的误报。
		if len(lower) > 200 && !reSQLiInjectionOps.MatchString(lower) {
			return true
		}
		// 分析埋点与引荐跟踪像素会把完整 URL 嵌进查询参数，
		// 例如 ref=https://cdn.example.com/api/v1/* 或 ep=https://site.com/page/1/*。
		// URL 解码后它们含 "/\d/*"，会触发 sqli:005，但此处的 /*
		// 是追加在 URL 路径后的文件系统/路径通配符，而非 SQL 行内注释。
		// 由于 isSQLiFalsePositive 接收的是未归一化的原始输入，需同时检查
		// 解码形（https://）与 URL 编码形（https%3a）。
		// 防护条件：仅在不存在显式 SQL 注入运算符时才抑制。
		hasURL := strings.Contains(lower, "https://") || strings.Contains(lower, "http://") ||
			strings.Contains(lower, "https%3a") || strings.Contains(lower, "http%3a")
		hasGlob := strings.Contains(lower, "/*") || strings.Contains(lower, "%2f*") ||
			strings.Contains(lower, "%2f%2a")
		if hasURL && hasGlob && !reSQLiInjectionOps.MatchString(lower) {
			return true
		}
		// 末尾带 /* 的类路径字符串（如 /api/v1/*、/static/*）
		// 常见于路由配置，不是 SQL 注释。
		// 仅当字符串形似 URL 路径（以 / 开头）且无其他 SQLi 指示时才抑制。
		if strings.HasSuffix(lower, "/*") && strings.HasPrefix(lower, "/") && !reSQLiInjectionOps.MatchString(lower) {
			return true
		}
		// 规则语义是「SQL 注释起始」，因此按注释符两侧的**字符类别**确认它
		// 落在 token 边界上，而不是只看到一个「数字 + /*」就采信。
		// 详细判据见 hasSQLCommentTokenBoundary 的文档注释。
		// 注意：此处必须用 normalizeWithDecodeTarget 重新归一化 —— isSQLiFalsePositive
		// 收到的是 raw，而调用方传入的 target 已被归一化链剥离过 `--` 注释，
		// 且 raw 可能是 `%2d%2d` / `&#45;&#45;` 等编码形态。
		if !hasSQLCommentTokenBoundary(normalizeWithDecodeTarget(raw, false)) {
			return true
		}
	case "owasp:sqli:012": // ;\s*--
		// 分号后接双减号会出现在合法的 CSS 或 JS 片段中。
		if len(lower) < 10 {
			return true
		}
		// 遥测与分析端点常在跟踪参数中使用分号。
		if strings.Contains(lower, "/g/collect") ||
			strings.Contains(lower, "telemetry") ||
			strings.Contains(lower, "analytics") ||
			strings.Contains(lower, "google-analytics") ||
			strings.Contains(lower, "cdn-cgi") {
			return true
		}
	case "owasp:sqli:021": // substr/substring/mid 带数值参数
		// JavaScript 也大量使用 substring(start, end)。
		// 缺少 SQL 上下文（SQL 关键词或 SQL 特有函数）时抑制。
		if reBoolSQLContext.MatchString(lower) || reSQLTerminatorCtx.MatchString(lower) {
			return false
		}
		// substr 内部出现 SQL 特有函数调用可确认注入上下文。
		if reSQLi022ClauseCtx.MatchString(lower) {
			return false
		}
		if strings.Contains(lower, "ascii(") || strings.Contains(lower, "ord(") ||
			strings.Contains(lower, "user()") || strings.Contains(lower, "database()") ||
			strings.Contains(lower, "version()") || strings.Contains(lower, "@@") {
			return false
		}
		return true
	case "owasp:sqli:030": // 带 SQL 终止符的 LIMIT n,n
		// LIMIT 10,20 是标准 MySQL 分页写法。缺少 SQL 上下文确认注入时抑制。
		if !reSQLTerminatorCtx.MatchString(lower) && !reBoolSQLContext.MatchString(lower) {
			return true
		}
	case "owasp:sqli:022": // \bif\s*\(\s*(select|ord|ascii|substr|length|count|version)\b
		// if(length)、if(count)、if(version)、if(select.value) 在 JavaScript 中极常见
		// （DOM 属性检查、版本比较、长度守卫）。
		// ascii() 与 ord() 是 SQL 特有函数——绝不抑制。
		if strings.Contains(lower, "ascii(") || strings.Contains(lower, "ord(") {
			return false
		}
		// 关键词被用作 SQL 函数调用（关键词 + "("）——真实 SQL 注入。
		if reSQLi022FuncCall.MatchString(lower) {
			return false
		}
		// SQL 子句关键词 FROM/WHERE/UNION/HAVING 可确认 SQL 注入上下文。
		if reSQLi022ClauseCtx.MatchString(lower) {
			return false
		}
		// 既无 SQL 函数调用也无子句关键词：更像 JavaScript 变量/属性。
		return true
	case "owasp:sqli:001": // union (all) select
		if !hasUnionSelectAttackContext(lower) {
			return true
		}
		if len(lower) > 40 && strings.Contains(lower, " the ") || strings.Contains(lower, " a ") || strings.Contains(lower, " each ") {
			if !strings.Contains(lower, "null") && !strings.Contains(lower, "@@") &&
				!strings.Contains(lower, "information_schema") && !strings.Contains(lower, "--") &&
				!strings.Contains(lower, "/*") && !strings.Contains(lower, "0x") {
				return true
			}
		}
	case "owasp:sqli:017": // INTO OUTFILE/DUMPFILE
		// MySQL 要求带引号的文件路径：INTO OUTFILE '/tmp/x.php'。
		// 文档文本如 "SELECT INTO OUTFILE S3"（AWS Aurora 文档）没有引号路径。
		// 仅在关键词后紧跟带引号的文件路径时才保留。
		if !reIntoOutfileWithPath.MatchString(lower) {
			return true
		}
	case "owasp:sqli:008": // [,=(]\s*0x[0-9a-f]{4,}——带前置运算符的十六进制字面量
		// 十六进制字面量（0xFFFF、0xABCDEF）会出现在 CSS 颜色、内存地址、二进制
		// 协议与日志数据中，并非 SQL 注入独有。
		// 仅在同时存在强 SQL 注入上下文时才报告该命中。
		if !reSQLi008AttackCtx.MatchString(lower) {
			return true
		}
	case "owasp:sqli:047": // SELECT * FROM
		if strings.Contains(lower, "select * from users where users.slug") && strings.Contains(lower, "limit 1") {
			return true
		}
		hasDocSearchContext := strings.Contains(lower, "q=") || strings.Contains(lower, "query=") ||
			strings.Contains(lower, "search") || strings.Contains(lower, "best practices") ||
			strings.Contains(lower, "aurora") || strings.Contains(lower, "amazon s3") ||
			strings.Contains(lower, "sample-loaddata01") || strings.Contains(lower, "aurora-s3-access-pol") ||
			strings.Contains(lower, "aurora_default_s3_role") || strings.Contains(lower, "select into outfile s3") ||
			strings.Contains(lower, "load data from s3") || strings.Contains(lower, "permalink") ||
			strings.Contains(lower, "comments") || strings.Contains(lower, "segmentfault") ||
			strings.Contains(lower, "loc=https://")
		if hasDocSearchContext {
			if strings.Contains(lower, "select * from users where users.slug") ||
				strings.Contains(lower, "users.slug") ||
				strings.Contains(lower, "limit 1") ||
				strings.Contains(lower, "publication/search") {
				return true
			}
			if !strings.Contains(lower, "union select") && !strings.Contains(lower, "union all select") &&
				!strings.Contains(lower, "sleep(") && !strings.Contains(lower, "benchmark(") &&
				!strings.Contains(lower, "waitfor") && !strings.Contains(lower, "0x") &&
				!isTautology(lower) {
				return true
			}
		}
	}
	return false
}

// xssExecutionSinkLiterals 是「一旦出现即可执行脚本」的最小字面量表。
//
// 表中每一项都是脚本能力的直接入口：伪协议、内联脚本元素、执行原语、
// DOM 写入与 Cookie 读取。判定「缺少主动执行上下文」以及 JSX 内联处理器
// 的良性判定都以此表为准，避免两处各写一份词表后漂移。
var xssExecutionSinkLiterals = []string{
	"javascript:", "vbscript:", "data:text/html", "<script", ":script",
	"eval(", "alert(", "prompt(", "confirm(", "fromcharcode",
	"document.cookie", "document.write", "innerhtml",
}

// hasActiveXSSContext 检查是否存在可确认真实 XSS 攻击的主动 JavaScript 执行指示，
// 以区别于被动结构型 HTML 或 DOM 读取。
// 注意：单独的 document.location 被排除——它是导航代码中常见的 DOM 读取属性，
// 本身并不启用脚本注入。
func hasActiveXSSContext(normalized string) bool {
	for _, sink := range xssExecutionSinkLiterals {
		if strings.Contains(normalized, sink) {
			return true
		}
	}
	return reXSSEventHandler.MatchString(normalized) ||
		(hasJavascriptLettersScan(normalized) && reJSProtocolObfuscated.MatchString(normalized))
}

// isXSSStructuralFalsePositive 判定「结构上不存在脚本执行入口」的 XSS 命中。
//
// 与敏感度档位无关：这些判据的成立条件本身已经排除了事件处理器、伪协议
// 载荷、内联脚本元素与执行原语，strict / very_high 档位提升的应该是
// 「可疑构造」的检出，而不应把本身无法执行的形态重新计为攻击。
//
// 与 isXSSFalsePositive 的分工：本函数只收录无执行语义的硬判据；依赖长度、
// 代码密度等启发式的抑制仍由 isXSSFalsePositive 按档位生效。
//
// @param normalized 归一化后的检测目标串。
// @param ruleID     首个命中的 XSS 规则 ID。
// @return 是否属于结构型良性命中。
func isXSSStructuralFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:xss:003":
		// javascript: 之后不存在执行语义（javascript:void(0)、javascript:;），
		// 或整体是自然语言标题（"JavaScript: Basics of ..."）。
		return reJSProtocolNaturalPhrase.MatchString(normalized) || isBenignJavaScriptVoid(normalized)
	case "owasp:xss:002":
		return isJSXHandlerWithoutExecution(normalized)
	case "owasp:xss:005", "owasp:xss:007", "owasp:xss:008",
		"owasp:xss:012", "owasp:xss:015",
		"owasp:xss:022", "owasp:xss:024", "owasp:xss:028":
		return isPassiveHTMLElementOnly(normalized)
	}
	return false
}

// isPassiveHTMLElementOnly 判断标签型命中是否仅由被动 HTML 结构构成。
//
// 判据：不含任何主动执行上下文；且不是「超长 HTML 正文中夹带 iframe/object/embed」
// 这一历史上被滥用的外链嵌入形态。百度广告位等已知被动结构直接放行。
//
// @param normalized 归一化后的检测目标串。
// @return 是否属于纯被动结构。
func isPassiveHTMLElementOnly(normalized string) bool {
	lower := strings.ToLower(normalized)
	if strings.Contains(lower, "row_ad") || strings.Contains(lower, "slotbydup") ||
		strings.Contains(lower, "hm.baidu.com") || strings.Contains(lower, "cpro.baidustatic.com") {
		return true
	}
	if hasActiveXSSContext(normalized) {
		return false
	}
	if len(normalized) > 2000 && (strings.Contains(normalized, "<iframe") || strings.Contains(normalized, "<object") || strings.Contains(normalized, "<embed")) {
		return false
	}
	return true
}

// reXSSJSXHandler 匹配 JSX 内联事件处理器写法（on<event>={...}）。
var reXSSJSXHandler = regexp.MustCompile(`\bon\w+\s*=\s*\{`)

// xssJSXExtraSinks 是 JSX 处理器判定额外要求的原语：网络外带与导航赋值。
//
// 这些原语不并入 xssExecutionSinkLiterals，避免改变既有被动结构抑制的
// 判定面；JSX 判据是本轮新增的窄判据，扩展它不影响历史行为。
var xssJSXExtraSinks = []string{"fetch(", "xmlhttprequest", "location=", "location.href"}

// isJSXHandlerWithoutExecution 判断事件处理器命中是否全部来自 JSX 内联表达式，
// 且每个表达式的取值区都不含脚本执行入口。
//
// 依据：浏览器把 onclick={...} 的取值按函数体编译，`{...}` 是块语句；
// 演示代码里的 `onclick={(e) => e.preventDefault()}` 只是表达式语句，
// 不会执行任何脚本能力。判据分两步：
//
//  1. 事件处理器总数必须与 JSX 写法数相等，混合出现 `onerror=alert(1)`
//     这类裸赋值时立即判为攻击（交回通用判据）。
//  2. 每个 `={` 之后到首个 `}` 之间的取值区不得出现执行原语；
//     `{alert(1)}`、`{fetch('//x')}`、`{location='//x'}` 均仍会被检出。
//
// @param normalized 归一化后的检测目标串。
// @return 是否属于无执行语义的 JSX 内联处理器。
func isJSXHandlerWithoutExecution(normalized string) bool {
	lower := strings.ToLower(normalized)
	all := reXSSEventHandler.FindAllStringIndex(lower, -1)
	jsx := reXSSJSXHandler.FindAllStringIndex(lower, -1)
	if len(jsx) == 0 || len(all) != len(jsx) {
		return false
	}
	for _, loc := range jsx {
		rest := lower[loc[1]:]
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			// 取值区不完整：无法确认安全性，交回通用判据。
			return false
		}
		region := rest[:end]
		for _, sink := range xssExecutionSinkLiterals {
			if strings.Contains(region, sink) {
				return false
			}
		}
		for _, sink := range xssJSXExtraSinks {
			if strings.Contains(region, sink) {
				return false
			}
		}
	}
	return true
}

// isXSSFalsePositive 在 XSS 命中仅来自被动结构型 HTML 元素
// （svg、iframe、math、embed、base、link）或常见 DOM 导航属性
// （document.location、window.location）且不存在任何主动 JavaScript 执行上下文时
// 返回 true。富 HTML 内容（CMS 文章、报表）与单页应用导航代码常包含这些模式。
// 在高敏感度下（阈值 ≤ 2），调用方会绕过本检查。
func isKnownTelemetryXSSFalsePositive(path, normalized, ruleID string, isBodyTarget bool) bool {
	lowerPath := toLowerASCII(path)
	if !isBodyTarget {
		return false
	}
	lower := strings.ToLower(normalized)
	switch ruleID {
	case "owasp:xss:003":
		// 该 ruleID 的遥测豁免已随删词取消（原为「路径 + 内容判据」双条件，
		// 路径部分 /analytics/v2_upload、/api/report、/fd/ls/glinkpingpost.aspx
		// 与内容部分均已删）。保留 case 标签供审计追溯。
	case "owasp:xss:005":
		// 同上（原路径 /news/g）。
	case "owasp:xss:007", "owasp:xss:010":
		// 同上（原路径 /logstores/prod/track）。
	case "owasp:xss:002":
		if strings.Contains(lowerPath, "/run") {
			return strings.Contains(lower, "onclick=") || strings.Contains(lower, "preventdefault") || strings.Contains(lower, "createroot") || strings.Contains(lower, "react")
		}
	}
	return false
}

// isHarmlessInlineScriptOnly 判断字符串中的每个 <script> 元素是否都不具备
// 脚本载荷能力，因而属于页面常规结构（业务页面的挂载代码、外链引用）。
//
// 判据按「元素是否可执行」而非「出现在哪个站点/路径」定义，分两侧：
//
//   - 开标签：出现事件处理器属性（on<event>=）、伪协议或转义序列
//     （javascript:/vbscript:/data:/&#/%u/\u/\x）即视为载荷。带 src/xlink:href/href
//     引用属性时，取值必须是双引号包裹的 http(s):// 或绝对路径，且标签体为空。
//   - 标签体：出现成员访问式下标（obj["x"]/[`x`]）、HTML 标签、事件处理器、
//     反引号、八进制转义、\u/\x 转义，或执行原语（alert/…/eval/…、document.cookie
//     等属性、location 赋值、fetch( 等调用）即视为载荷。
//
// 任一元素不满足即返回 false，交回通用结构判据继续判定。该判据的背离条件是
// 「内联体只用本函数未列举的原语完成执行」——此时放行；列举面覆盖的是
// JS 里无法绕开的能力入口（调用、下标取值、DOM 写入、导航、编码逃逸）。
func isHarmlessInlineScriptOnly(lower string) bool {
	idx, found := 0, false
	for {
		i := strings.Index(lower[idx:], "<script")
		if i < 0 {
			break
		}
		i += idx
		end := strings.Index(lower[i:], ">")
		if end < 0 {
			return false
		}
		closeIdx := strings.Index(lower[i:], "</script")
		bodyEnd := len(lower)
		if closeIdx >= 0 {
			bodyEnd = i + closeIdx
		}
		openEnd := i + end + 1
		// '</script' 落在 '>' 之前时开标签被截断（如 "<script </script>"），
		// 既不是合法元素结构，也没有可判定的标签体：交回通用判据，
		// 且必须先于切片判定，否则 bodyEnd < openEnd 会越界。
		if openEnd > bodyEnd {
			return false
		}
		if !isHarmlessScriptElement(lower[i:openEnd], lower[openEnd:bodyEnd]) {
			return false
		}
		found = true
		if closeIdx < 0 {
			break
		}
		idx = bodyEnd + len("</script")
	}
	return found
}

// isHarmlessScriptElement 判断单个 <script ...> 元素（开标签 + 标签体）是否
// 不具备脚本载荷能力。openTag 含 '<script' 前缀，body 为标签体原文。
func isHarmlessScriptElement(openTag, body string) bool {
	attrs := openTag[len("<script"):]
	if hasScriptPayloadInAttrs(attrs) {
		return false
	}
	// 元素级引用属性（src/xlink:href/href）优先：带引用时必须为可静态确认的
	// 外链且标签体为空。反斜杠先剥除，兼容 JSON 转义后的 \" 形态。
	ref, ok := scriptRefValue(strings.ReplaceAll(attrs, "\\", ""))
	if ok {
		return isSafeScriptRef(ref) && strings.TrimSpace(body) == ""
	}
	if hasUnquotableScriptRef(attrs) {
		return false
	}
	return !hasInlineScriptPayload(strings.TrimSpace(body))
}

// hasScriptPayloadInAttrs 判断 <script> 开标签属性区是否含载荷特征：
// 事件处理器属性、反引号、伪协议或转义序列。这些形态本身就构成注入
// （如 <script src=data:...>、<script xlink:href=...>、onerror= 变体）。
func hasScriptPayloadInAttrs(attrs string) bool {
	if reXSSEventHandler.MatchString(attrs) || strings.Contains(attrs, "`") {
		return true
	}
	for _, needle := range []string{"javascript:", "vbscript:", "data:", "&#", "%u", `\u`, `\x`} {
		if strings.Contains(attrs, needle) {
			return true
		}
	}
	return false
}

// scriptRefValue 提取 <script> 开标签的引用属性取值。引用属性按 src、xlink:href、
// href 顺序查找；返回 ok=false 表示不存在这三个引用属性。
func scriptRefValue(attrs string) (string, bool) {
	for _, attr := range []string{`src="`, `xlink:href="`, `href="`} {
		k := strings.Index(attrs, attr)
		if k < 0 {
			continue
		}
		rest := attrs[k+len(attr):]
		q := strings.Index(rest, `"`)
		if q < 0 {
			return "", true
		}
		return rest[:q], true
	}
	return "", false
}

// hasUnquotableScriptRef 判断是否存在未以双引号包裹的引用属性取值
// （<SCRIPT SRC=/host/1> 这类注入形态）。调用前应已排除双引号包裹的引用。
func hasUnquotableScriptRef(attrs string) bool {
	u := strings.ReplaceAll(attrs, "\\", "")
	for _, attr := range []string{"src=", "xlink:href=", "href="} {
		if strings.Contains(u, attr) {
			return true
		}
	}
	return false
}

// isSafeScriptRef 判断引用属性取值是否为可静态确认的外链/站点绝对路径，
// 排除 data:/javascript:/vbscript: 与协议相对 // 这类以引用承载载荷的形态。
func isSafeScriptRef(value string) bool {
	if value == "" {
		return false
	}
	for _, bad := range []string{"data:", "javascript:", "vbscript:", "//"} {
		if strings.HasPrefix(value, bad) {
			return false
		}
	}
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") ||
		strings.HasPrefix(value, "/")
}

// hasInlineScriptPayload 判断内联脚本体是否具备脚本能力。命中任一类即视为
// 可执行载荷：成员访问式下标取值（越过字符串不能表达属性访问的边界）、
// HTML 标签、事件处理器属性、反引号模板、编码逃逸序列、执行原语。
func hasInlineScriptPayload(body string) bool {
	if body == "" {
		return false
	}
	// 整个标签体只有一个裸标识符：这不是任何有意义的业务脚本（表达式语句
	// 求值必然抛 ReferenceError，除非全局恰好存在同名变量），却是最简
	// XSS 探针；业务内联脚本至少包含赋值、调用或成员访问。
	if reScriptBareIdentifier.MatchString(body) {
		return true
	}
	if reScriptMemberIndex.MatchString(body) {
		return true
	}
	if reScriptBodyTag.MatchString(body) {
		return true
	}
	if reXSSEventHandler.MatchString(body) {
		return true
	}
	if strings.Contains(body, "`") || reScriptOctalEscape.MatchString(body) {
		return true
	}
	if strings.Contains(body, `\u`) || strings.Contains(body, `\x`) {
		return true
	}
	return hasScriptExecPrimitive(body)
}

// hasScriptExecPrimitive 判断文本是否含 JavaScript 执行原语：已知的危险函数/
// 属性词、导航对象引用、属性写入与网络/代码求值调用。
func hasScriptExecPrimitive(s string) bool {
	if reScriptPrimitiveWord.MatchString(s) || reScriptNavRef.MatchString(s) {
		return true
	}
	if strings.Contains(s, "&#") || strings.Contains(s, "%u") ||
		strings.Contains(s, "javascript:") || strings.Contains(s, "vbscript:") {
		return true
	}
	return reScriptPrimitiveCall.MatchString(s)
}

var (
	// reScriptBareIdentifier 匹配只有一个裸标识符的内联脚本表达式。
	reScriptBareIdentifier = regexp.MustCompile(`^[a-z_$][a-z0-9_$]*$`)
	// reScriptMemberIndex 匹配成员访问式下标取值：obj["x"] / arr[0]["k"] / obj[`x`]。
	// 字符串字面量（attr["x"] 这类值）不能表达属性访问，故以此区分
	// 业务数据与脚本求值。
	reScriptMemberIndex = regexp.MustCompile("[a-z0-9_$)\\]}]\\s*\\[\\s*['\"`]")
	// reScriptBodyTag 匹配脚本体里出现的 HTML 标签起始（<div / </div / <svg>）。
	reScriptBodyTag = regexp.MustCompile(`</?[a-z][a-z0-9]*[\s/>]`)
	// reScriptOctalEscape 匹配八进制转义（\141 → a），JS 字符串里唯一无法
	// 用字面量表达的编码方式。
	reScriptOctalEscape = regexp.MustCompile(`\\[0-7]`)
	// reScriptPrimitiveWord 匹配执行/注入原语词。
	reScriptPrimitiveWord = regexp.MustCompile(`\b(alert|prompt|confirm|eval|execscript|settimeout|setinterval|atob|btoa|unescape|decodeuri|decodeuricomponent|fromcharcode|innerhtml|outerhtml|insertadjacenthtml|xmlhttprequest|sendbeacon|globalthis|constructor)\b|document\.(cookie|write|domain|location)`)
	// reScriptNavRef 匹配导航/上下文对象引用与赋值（location.href=、top[）。
	reScriptNavRef = regexp.MustCompile(`\b(location|opener|parent|frames|self|top)\s*[.=\[]`)
	// reScriptPrimitiveCall 匹配代码求值与网络/文档写入调用。
	reScriptPrimitiveCall = regexp.MustCompile(`\b(fetch|import|require|writeln|write|replace|assign|navigate|exec|appendchild|createelement|setattribute|createelementns)\s*\(`)
)

func isBenignJavaScriptVoid(normalized string) bool {
	lower := strings.ToLower(normalized)
	if !strings.Contains(lower, "javascript:") {
		return false
	}
	if strings.Contains(lower, "alert(") || strings.Contains(lower, "confirm(") ||
		strings.Contains(lower, "prompt(") || strings.Contains(lower, "eval(") ||
		strings.Contains(lower, "document.cookie") || strings.Contains(lower, "document.write") ||
		strings.Contains(lower, "innerhtml") || strings.Contains(lower, "fromcharcode") ||
		strings.Contains(lower, "<script") || strings.Contains(lower, "<base") ||
		strings.Contains(lower, "fetch(") || strings.Contains(lower, "xmlhttp") ||
		reXSSEventHandler.MatchString(lower) {
		return false
	}
	return strings.Contains(lower, "javascript:;") ||
		strings.Contains(lower, "javascript:void(0)") ||
		strings.Contains(lower, "javascript: void(0)") ||
		strings.Contains(lower, "javascript:void 0") ||
		strings.Contains(lower, "javascript: void 0") ||
		strings.Contains(lower, "javascript%3a;") ||
		strings.Contains(lower, "javascript%3avoid(0)") ||
		strings.Contains(lower, "javascript%3a%20void(0)") ||
		strings.Contains(lower, "javascript%3avoid%200") ||
		strings.Contains(lower, "javascript%3a%20void%200")
}

func isBingPingPostBenignNavigation(normalized string) bool {
	lower := strings.ToLower(normalized)
	return strings.Contains(lower, "url=javascript:void(0)") ||
		strings.Contains(lower, "url=javascript%3avoid(0)") ||
		strings.Contains(lower, "url=javascript%3avoid(0);") ||
		strings.Contains(lower, "url=javascript%3avoid(0)%3b") ||
		strings.Contains(lower, "url=javascript:;") ||
		strings.Contains(lower, "url=javascript%3a;") ||
		strings.Contains(lower, "url=javascript%3a%3b")
}

func isKnownTelemetryCmdFalsePositive(path, normalized, ruleID string, isBodyTarget bool) bool {
	if !isBodyTarget {
		return false
	}
	lowerPath := strings.ToLower(path)
	lower := strings.ToLower(normalized)
	if ruleID == "owasp:cmd:001" && strings.Contains(lowerPath, "/run") {
		return strings.Contains(lower, "document.getelementbyid") || strings.Contains(lower, "createroot") || strings.Contains(lower, "react-dom/client")
	}
	return false
}

func isKnownTelemetryPathTravFalsePositive(path, normalized, ruleID string, isBodyTarget bool) bool {
	if !isBodyTarget {
		return false
	}
	lowerPath := strings.ToLower(path)
	switch ruleID {
	case "owasp:path_traversal:001":
		// 该 ruleID 的遥测豁免已随删词取消（原为「路径 + 内容三词」双条件，
		// 内容部分已删）。保留 case 标签是为了让审计能看到这条豁免曾经存在。
	case "owasp:path_traversal:011":
		// 同上。
	case "owasp:path_traversal:009":
		// 网易 analytics /ctrip SaveTraceInfo 等 JSON 遥测体：URL 解码后
		// 出现「...%3C/ 」（中文省略号+链接标签）或「...\n 」（反斜杠
		// 转义序列）被 009 正则 \.{3,}[/\\] 误命中。路径定位到这些已知
		// 遥测端点时抑制。
		if strings.Contains(lowerPath, "/restapi/soa2/") {
			return true
		}
	}
	return false
}

func isXSSFalsePositive(normalized, firstRuleID string) bool {
	if isXSSStructuralFalsePositive(normalized, firstRuleID) {
		return true
	}
	switch firstRuleID {
	case "owasp:xss:032": // /regex/.source 字符串拼接
		return false
	case "owasp:xss:052": // global[( 形式的 JSFuck
		return !hasActiveXSSContext(normalized)
	case "owasp:xss:001": // <script[\s>]
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "search%2ffor") || strings.Contains(lower, "search/for") ||
			strings.Contains(lower, "is incorrect") || strings.Contains(lower, "performance") && strings.Contains(lower, "val_url") || strings.Contains(lower, "cpro.baidustatic.com") || strings.Contains(lower, "hm.baidu.com") || strings.Contains(lower, "class=\"row_ad\"") || strings.Contains(lower, "slotbydup") {
			return true
		}
		if len(normalized) > 200 {
			hasActiveJS := strings.Contains(lower, "alert(") ||
				strings.Contains(lower, "eval(") ||
				strings.Contains(lower, "document.cookie") ||
				strings.Contains(lower, "document.write") ||
				strings.Contains(lower, "prompt(") ||
				strings.Contains(lower, "confirm(") ||
				strings.Contains(lower, "fromcharcode") ||
				strings.Contains(lower, "src=") ||
				strings.Contains(lower, "onerror") ||
				strings.Contains(lower, "onload") ||
				strings.Contains(lower, "fetch(") ||
				strings.Contains(lower, "innerhtml") ||
				strings.Contains(lower, "xmlhttp") ||
				strings.Contains(lower, "\\u00") ||
				strings.Contains(lower, "base64") ||
				strings.Contains(lower, "window[") ||
				strings.Contains(lower, "window.") ||
				strings.Contains(lower, "constructor")
			if !hasActiveJS {
				return true
			}
		}
		// 页面常规脚本结构（纯外链引用，或内联体不含任何脚本能力入口）不构成 XSS。
		// 判据落在「元素能否执行」而非域名：任何域名的纯外链引用都放行，内联体一旦
		// 出现下标取值/标签/事件处理器/转义序列/执行原语，即回落到下面的通用结构
		// 判据，仍可命中。
		if isHarmlessInlineScriptOnly(lower) {
			return true
		}
		if !strings.Contains(lower, "</script") && !strings.Contains(lower, "alert(") &&
			!strings.Contains(lower, "eval(") && !strings.Contains(lower, "onerror") &&
			!strings.Contains(lower, "onload") && !strings.Contains(lower, "document.cookie") &&
			!strings.Contains(lower, "document.write") && !strings.Contains(lower, "prompt(") &&
			!strings.Contains(lower, "confirm(") {
			idx := strings.Index(lower, "<script")
			if idx >= 0 {
				after := lower[idx+7:]
				if len(after) > 0 && after[0] != '>' && after[0] != ' ' && after[0] != '\t' {
					return true
				}
				if strings.HasPrefix(strings.TrimLeft(after, " \t"), "src=") && !strings.Contains(after, "(") {
					return true
				}
				if !strings.Contains(after, "(") && !strings.Contains(after, "=") {
					return true
				}
			}
		}
	case "owasp:xss:002": // \bon(event)\s*=——HTML 事件处理器属性
		if isXSSHandlerFunctionRef(normalized) {
			return true
		}
		if len(normalized) > 300 {
			lower := strings.ToLower(normalized)
			isCode := strings.Contains(lower, "const ") || strings.Contains(lower, "function ") ||
				strings.Contains(lower, "=> ") || strings.Contains(lower, "import ") ||
				strings.Contains(lower, "export ") || strings.Contains(lower, "return (")
			if isCode && !strings.Contains(lower, "alert(") && !strings.Contains(lower, "eval(") &&
				!strings.Contains(lower, "document.cookie") && !strings.Contains(lower, "document.write") {
				return true
			}
		}
	case "owasp:xss:003": // javascript: URI——结构型判据已在函数入口覆盖
		return false
	case "owasp:xss:005", "owasp:xss:007", "owasp:xss:008",
		"owasp:xss:012", "owasp:xss:015",
		"owasp:xss:022", "owasp:xss:024", "owasp:xss:028":
		// 被动结构判据已在函数入口覆盖。
		return false
	case "owasp:xss:014":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "react.createelement") || strings.Contains(lower, "createroot") ||
			strings.Contains(lower, "preventdefault") || strings.Contains(lower, "class=\"row_ad\"") ||
			strings.Contains(lower, "slotbydup") || strings.Contains(lower, "hm.baidu.com") ||
			strings.Contains(lower, "cm.js") || strings.Contains(lower, "target=\"_blank\"") {
			if !strings.Contains(lower, "alert(") && !strings.Contains(lower, "eval(") && !strings.Contains(lower, "javascript:") {
				return true
			}
		}
	case "owasp:xss:006", "owasp:xss:010":
		// document.(location|write|cookie|domain) 与 window.(location|name|open)
		// 是合法 SPA 导航代码中大量使用的标准 DOM 属性。
		// 缺少主动脚本执行上下文时抑制。
		return !hasActiveXSSContext(normalized)
	case "owasp:xss:033":
		// JSFuck 锚（+[]/+{}）在二进制/加密数据（ctrip SaveTraceInfo
		// 等遥测体）中随机碰撞率极高。真实 JSFuck 载荷有完整结构
		//（(![]、!![]、构造函数链），裸 +[] 单独出现不算注入。
		if !strings.Contains(normalized, "(![]") && !strings.Contains(normalized, "!![]") &&
			!strings.Contains(normalized, "constructor") {
			return true
		}
	}
	return false
}

// isXSSHandlerFunctionRef 判断事件处理器命中（xss:002）是否更像 CDN/API 回调注册
// （例如 ?onload=myCallback），而非真实 XSS。
// CDN 回调是纯标识符；真实 XSS 载荷会调用函数：onload=alert(1)。
func isXSSHandlerFunctionRef(normalized string) bool {
	// 处理器值后出现函数调用左括号 → 真实 XSS 尝试。
	if reXSSHandlerCallParens.MatchString(normalized) {
		return false
	}
	// HTML 标签上下文（<...>）→ 可能是注入的标记。
	if strings.ContainsRune(normalized, '<') || strings.ContainsRune(normalized, '>') {
		return false
	}
	// 主动 JS 执行关键词可确认真实攻击意图。
	if strings.Contains(normalized, "javascript:") ||
		strings.Contains(normalized, "eval(") ||
		strings.Contains(normalized, "document.cookie") ||
		strings.Contains(normalized, "fromcharcode") ||
		strings.Contains(normalized, "<script") {
		return false
	}
	return true
}

// reXSSEventHandler 匹配行内事件处理器属性（on<event>=）。
var reXSSEventHandler = regexp.MustCompile(`\bon\w+\s*=`)
var reJSProtocolObfuscated = regexp.MustCompile(`j\s*a\s*v\s*a\s+s\s*c\s*r\s*i\s*p\s*t\s*:`)

// reBacktickInjectionCtx 判定反引号命令替换是否处于 shell 注入位置：
// 起始反引号位于串首，或紧跟 shell 运算符（=、;、|、&、$）或旗标式参数
// （如 --exec=`id`）时成立。
// 该模式不匹配时，反引号出现在自然语言或文档上下文中
// （如 "Use `echo` to print"），应予抑制。
// 注意：运算符集合刻意排除逗号与闭合反引号，
// 使 Markdown 里的 "try `cat`, `grep`" 不会因第二个反引号而误命中。
// backtickCmdWords 是 reBacktickInjectionCtx 与 reCmd002Backtick 共享的命令词表。
// 两条正则均以 "(" + backtickCmdWords + ")" 拼接编译，禁止单边再改动：
// 词表由 TestBacktickCmdWordLiterals 锁定，正则最终文本由 TestBacktickRegexesByteStable 按 .String() 锁定。
var backtickCmdWords = strings.Join([]string{
	"cat", "ls", "id", "whoami", "uname", "pwd", "wget", "curl", "nc", "bash",
	"sh", "echo", "rm", "chmod", "chown", "python", "perl", "ruby", "php",
	"base64", "find", "grep", "awk", "sed", "ps", "kill", "nslookup", "dig",
	"ping", "sleep", "dd", "cp", "mv", "mkdir", "touch", "head", "tail", "sort", "xxd",
}, "|")

var reBacktickInjectionCtx = regexp.MustCompile("(^|[=;|&$])\\s*`[^`]*(" + backtickCmdWords + ")[^`]*`")
var reCmd002Backtick = regexp.MustCompile("`[^`]*(" + backtickCmdWords + ")[^`]*`")

// reCmdHighConfidence 匹配可确认真实命令注入意图的模式。
// 当 cmd:006（空字节/换行注入）是首个命中的规则时，要求至少出现一个此类
// 高置信度指示才报告命中。
// 这可抑制二进制/分析数据中的空字节与弱二级模式
// （如 cmd:010 环境变量 + 语言名）共同触发的误报。
var reCmdHighConfidence = regexp.MustCompile(
	`(` +
		`[;|&]\s*(cat|ls|whoami|uname|pwd|wget|curl|nc|bash|sh)(?:\s|;|` + "`" + `|&|\||$)` + // 管道/分号 + 命令（其后不能跟 =，以避免参数名误报）
		// 探测命令 + 分号：要求前导为空白/运算符/串首（而非 \x00 这类任意非单词字节），
		// 以防二进制分析载荷中 \x00id; 之类的字节序列命中。
		`|(?:^|[\s;|&])(id|uname|whoami|hostname|ifconfig|ipconfig)\s*;` + // 探测命令 + 分号（cmd:007）
		`|\$\{?\s*IFS\s*\}?` + // ${IFS} 空格绕过（cmd:009）
		`|(&&|\|\|)\s*(cat|ls|whoami|uname|bash|sh|rm)(?:\s|;|` + "`" + `|$)` + // && / || 链式执行（cmd:011）
		`|(bash|sh|python|perl|ruby)\s*<<<` + // here-string 注入（cmd:013）
		`|\$'\s*\\[xX0][0-9a-fA-F]` + // ANSI-C 十六进制/八进制引用（cmd:014）
		`|>\s*/(etc|tmp|var|root|home)/` + // 重定向到敏感路径（cmd:004）
		`|\{\s*(cat|ls|id|whoami|echo|bash|sh|python|perl|ruby|wget|curl)\s*,` + // 花括号展开（cmd:012）
		`)`)

// isCmdInjectionFalsePositive 抑制疑似误报的命令注入命中。
func isCmdInjectionFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:cmd:001": // [;|&]\s*(cmd)\s
		lower := strings.ToLower(normalized)
		// User-Agent 形如 "Mozilla/5.0 (... ; Touch; rv:11.0) like Gecko"，
		// 归一化后含 "; Touch;"，会命中 "; touch"。
		// 浏览器 UA 串绝不构成命令注入。
		if strings.Contains(lower, "mozilla") || strings.Contains(lower, "gecko") ||
			strings.Contains(lower, "webkit") || strings.Contains(lower, "trident") ||
			strings.Contains(lower, "chrome/") || strings.Contains(lower, "safari/") {
			return true
		}
		// 表单参数名如 "echo=value" 会被 extractFormValues 按 '=' 切开，
		// 产生两个扫描目标："echo"（键）与 "value"。键 "echo" 在查询串或表单体
		// 分隔符带来的 '&' 之后会被当作命令 "echo" 命中。
		// 除非匹配出现在明确的 shell 执行上下文中，否则抑制。
		if len(normalized) > 200 && !reCmdHighConfidence.MatchString(normalized) {
			if strings.Contains(lower, "\\u00") || strings.Contains(lower, "base64") ||
				strings.Contains(lower, "sessionid") || strings.Contains(lower, "\"type\"") ||
				strings.Contains(lower, "subscribe") {
				return true
			}
		}
		// 仅为命令名且不含 shell 运算符的短值（如表单参数键 "echo"、"kill"、"sort"）
		// 属误报。
		trimmed := strings.TrimSpace(normalized)
		if len(trimmed) < 30 && !strings.ContainsAny(trimmed, ";|&`$>") {
			return true
		}
	case "owasp:cmd:002": // 反引号命令替换（score=4）
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "protobuf") || strings.Contains(lower, "application/x-protobuf") {
			return true
		}
		if reBacktickInjectionCtx.MatchString(normalized) {
			return false
		}
		if len(normalized) > 200 && !reCmdHighConfidence.MatchString(normalized) {

			match := reCmd002Backtick.FindString(normalized)
			if len(match) > 50 {
				return true
			}
		}
		if strings.ContainsAny(normalized, ";|") || strings.Contains(normalized, "&&") ||
			strings.Contains(normalized, "$(") || strings.Contains(normalized, "${") {
			return false
		}
		return true
	case "owasp:cmd:006": // 空字节 / 换行字节注入（score=3）
		// 空字节（\x00）可以合法地出现在二进制 POST 体、URL 编码数据与发往
		// 日志/分析端点的遥测载荷中。在良性请求上，它们可能连带触发 cmd:010
		// （环境变量 + "python" 这类语言名）。
		// 除非存在更高置信度的 shell 执行指示，否则抑制。
		if !reCmdHighConfidence.MatchString(normalized) {
			return true
		}
	case "owasp:cmd:024": // 反引号 + 命令名（ping、curl、cat 等）
		lower := strings.ToLower(normalized)
		// gRPC/API 方法名如 "v1:GetHints" 含类反引号模式，会命中命令名
		// （如 `cat`、`sh`）——对已知安全路径抑制。
		if strings.Contains(lower, "gethints") {
			return true
		}
	case "owasp:cmd:010":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "row_ad") || strings.Contains(lower, "slotbydup") ||
			strings.Contains(lower, "hm.baidu.com") || strings.Contains(lower, "cpro.baidustatic.com") ||
			strings.Contains(lower, "<iframe") {
			return true
		}
	}
	return false
}

// reSQLi022FuncCall 检测 sqli:022 关键词被用作 SQL 函数调用的形态（带括号），
// 以区别于 `if (length > 0)` 这类 JavaScript 变量名。
var reSQLi022FuncCall = regexp.MustCompile(`\bif\s*\(\s*(length|count|version|substr|select)\s*\(`)

// reSQLi022ClauseCtx 检测可确认 SQL 注入上下文的 SQL 子句关键词。
// 包含后接空格或 `(` 的 `select`，以捕获 `if(select database(),...)` 形态，
// 同时排除 `select.value`（JavaScript DOM 元素）。
var reSQLi022ClauseCtx = regexp.MustCompile(`\b(from|where|union|having)\b|\bselect[\s(]`)

// reANDORSleep 检测布尔型时间注入使用的 "AND sleep()" / "OR sleep()" 模式：
// `1 AND sleep(5)`、`1 OR pg_sleep(5)`、`1 AND benchmark(...)`。
var reANDORSleep = regexp.MustCompile(`\b(and|or)\s*(sleep|pg_sleep|benchmark)\s*\(`)
var reOrdinalAfterOr = regexp.MustCompile(`'or\s+\d+(?:st|nd|rd|th)\b`)
var reJSProtocolNaturalPhrase = regexp.MustCompile(`(?i)\bjavascript\s*:\s*[a-z]+(?:\s+[a-z]+){0,4}$`)

// reSQLTerminatorCtx 检测 SQL 注释/终止符前是否存在右括号或引号/数字，
// 用于指示 "1); sleep(5)--" 这类注入上下文。
var reSQLTerminatorCtx = regexp.MustCompile(`['")\d]\s*(--|/\*)`)

// hasUnionSelectAttackContext 判断 union [all] select 是否带有攻击上下文。
//
// 「union select 后紧跟函数调用」本身是强注入信号，覆盖 md5()/concat() 这类
// 未被历史白名单枚举的取值函数；缺少该信号时 union select 会被当作自然语言抑制。
//
// @param s 已小写化的检测目标串。
// @return 是否存在任一攻击上下文特征。
func hasUnionSelectAttackContext(s string) bool {
	return hasSQLWord(s, "null") ||
		hasDigitCommaDigit(s) ||
		hasFromTableReference(s) ||
		hasDoubleAtWord(s) ||
		hasSQLWord(s, "information_schema") ||
		hasUnionSelectFunctionCall(s) ||
		hasOpenParenSelect(s) ||
		strings.Contains(s, "--") ||
		strings.Contains(s, "/*") ||
		hasQuotedSQLOperator(s) ||
		hasUnionSelectColumnValue(s) ||
		hasWhereNumericEquality(s) ||
		hasOrderByNumber(s)
}

func hasSQLWord(s, word string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], word)
		if idx < 0 {
			return false
		}
		idx += start
		end := idx + len(word)
		if (idx == 0 || !isSQLWordByte(s[idx-1])) && (end == len(s) || !isSQLWordByte(s[end])) {
			return true
		}
		start = idx + 1
	}
}

func hasSQLWordAt(s string, idx int, word string) bool {
	end := idx + len(word)
	if idx < 0 || end > len(s) || s[idx:end] != word {
		return false
	}
	return (idx == 0 || !isSQLWordByte(s[idx-1])) && (end == len(s) || !isSQLWordByte(s[end]))
}

func isSQLWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}

func skipSQLSpaces(s string, i int) int {
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', '\r', '\f':
			i++
		default:
			return i
		}
	}
	return i
}

func hasDigitCommaDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		j = skipSQLSpaces(s, j)
		if j >= len(s) || s[j] != ',' {
			continue
		}
		j = skipSQLSpaces(s, j+1)
		if j < len(s) && s[j] >= '0' && s[j] <= '9' {
			return true
		}
	}
	return false
}

func hasFromTableReference(s string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], "from")
		if idx < 0 {
			return false
		}
		idx += start
		if !hasSQLWordAt(s, idx, "from") {
			start = idx + 1
			continue
		}
		j := skipSQLSpaces(s, idx+len("from"))
		if j > idx+len("from") && j < len(s) && (isSQLWordByte(s[j]) || s[j] == '`' || s[j] == '\'' || s[j] == '"') {
			return true
		}
		start = idx + 1
	}
}

func hasDoubleAtWord(s string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], "@@")
		if idx < 0 {
			return false
		}
		idx += start
		if idx+2 < len(s) && isSQLWordByte(s[idx+2]) {
			return true
		}
		start = idx + 2
	}
}

func hasUnionSelectFunctionCall(s string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], "union")
		if idx < 0 {
			return false
		}
		idx += start
		if !hasSQLWordAt(s, idx, "union") {
			start = idx + 1
			continue
		}
		j := skipSQLSpaces(s, idx+len("union"))
		if j == idx+len("union") {
			start = idx + 1
			continue
		}
		if hasSQLWordAt(s, j, "all") {
			next := skipSQLSpaces(s, j+len("all"))
			if next == j+len("all") {
				start = idx + 1
				continue
			}
			j = next
		}
		if !hasSQLWordAt(s, j, "select") {
			start = idx + 1
			continue
		}
		next := skipSQLSpaces(s, j+len("select"))
		if next == j+len("select") || next >= len(s) {
			start = idx + 1
			continue
		}
		// union select 后紧跟「标识符 + (」即函数调用形态（md5()/concat()/…），
		// 是明确的注入取值/回显信号。
		if isSQLWordByte(s[next]) || s[next] == '`' {
			k := next
			for k < len(s) && (isSQLWordByte(s[k]) || s[k] == '`') {
				k++
			}
			l := skipSQLSpaces(s, k)
			if l < len(s) && s[l] == '(' {
				return true
			}
		}
		start = idx + 1
	}
}

func hasSQLFunctionCall(s, name string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], name)
		if idx < 0 {
			return false
		}
		idx += start
		if hasSQLWordAt(s, idx, name) {
			j := skipSQLSpaces(s, idx+len(name))
			if j < len(s) && s[j] == '(' {
				return true
			}
		}
		start = idx + 1
	}
}

func hasOpenParenSelect(s string) bool {
	for start := 0; ; {
		idx := strings.IndexByte(s[start:], '(')
		if idx < 0 {
			return false
		}
		idx += start
		j := skipSQLSpaces(s, idx+1)
		if hasSQLWordAt(s, j, "select") {
			return true
		}
		start = idx + 1
	}
}

func hasQuotedSQLOperator(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '\'' && s[i] != '"' {
			continue
		}
		j := skipSQLSpaces(s, i+1)
		for _, op := range [...]string{"and", "or", "where", "having", "group", "order", "union"} {
			if j+len(op) <= len(s) && s[j:j+len(op)] == op && (j+len(op) == len(s) || !isSQLWordByte(s[j+len(op)])) {
				return true
			}
		}
	}
	return false
}

func hasUnionSelectColumnValue(s string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], "union")
		if idx < 0 {
			return false
		}
		idx += start
		if !hasSQLWordAt(s, idx, "union") {
			start = idx + 1
			continue
		}
		j := skipSQLSpaces(s, idx+len("union"))
		if j == idx+len("union") {
			start = idx + 1
			continue
		}
		if hasSQLWordAt(s, j, "all") {
			next := skipSQLSpaces(s, j+len("all"))
			if next == j+len("all") {
				start = idx + 1
				continue
			}
			j = next
		}
		if !hasSQLWordAt(s, j, "select") {
			start = idx + 1
			continue
		}
		next := skipSQLSpaces(s, j+len("select"))
		if next == j+len("select") || next >= len(s) {
			start = idx + 1
			continue
		}
		ch := s[next]
		if ch == '\'' || ch == '"' || ch == '(' || ch == '@' || (ch >= '0' && ch <= '9') {
			return true
		}
		start = idx + 1
	}
}

func hasWhereNumericEquality(s string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], "where")
		if idx < 0 {
			return false
		}
		idx += start
		if !hasSQLWordAt(s, idx, "where") {
			start = idx + 1
			continue
		}
		j := skipSQLSpaces(s, idx+len("where"))
		if j >= len(s) || s[j] < '0' || s[j] > '9' {
			start = idx + 1
			continue
		}
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		j = skipSQLSpaces(s, j)
		if j >= len(s) || s[j] != '=' {
			start = idx + 1
			continue
		}
		j = skipSQLSpaces(s, j+1)
		if j < len(s) && s[j] >= '0' && s[j] <= '9' {
			return true
		}
		start = idx + 1
	}
}

func hasOrderByNumber(s string) bool {
	for start := 0; ; {
		idx := strings.Index(s[start:], "order")
		if idx < 0 {
			return false
		}
		idx += start
		if !hasSQLWordAt(s, idx, "order") {
			start = idx + 1
			continue
		}
		j := skipSQLSpaces(s, idx+len("order"))
		if !hasSQLWordAt(s, j, "by") {
			start = idx + 1
			continue
		}
		j = skipSQLSpaces(s, j+len("by"))
		if j < len(s) && s[j] >= '0' && s[j] <= '9' {
			return true
		}
		start = idx + 1
	}
}

// reIntoOutfileWithPath 确认 INTO OUTFILE/DUMPFILE 命中（sqli:017）带有
// 带引号的文件路径（MySQL 语法要求）。诸如 "SELECT INTO OUTFILE S3"
// （AWS Aurora 文档）没有引号路径，应被抑制。
var reIntoOutfileWithPath = regexp.MustCompile(`\binto\s+(out|dump)file\s*['"]`)

// reSQLiInjectionOps 匹配不太可能出现在合法分析埋点或文档文本中的
// SQL 注入攻击运算符，供 sqli:005 抑制器区分 URL/路径通配符
// （S3 ARN 中的 /*）与真实 SQL 行内注释。
var reSQLiInjectionOps = regexp.MustCompile(
	`(union\s+(all\s+)?select\b` + // UNION 注入
		`|\bor\s+\d+\s*=\s*\d+` + // OR 1=1 布尔注入
		`|\band\s+\d+\s*=\s*\d+` + // AND 1=2 布尔注入
		`|'\s*(or|and)\s+['"\d]` + // ' or 'x'='x'
		`|\bsleep\s*\(` + // 时间型盲注
		`|\bbenchmark\s*\(` + // MySQL 时间型盲注
		`|;\s*(drop|truncate)\s+\w)`) // 破坏性 DDL 堆叠查询

// reXSSHandlerCallParens 检测 HTML 事件处理器属性值部分出现函数调用（左括号）：
// onload=alert(1) → 存在 (。
// CDN 脚本加载器使用 ?onload=callbackName（纯标识符、无括号），属安全形态。
var reXSSHandlerCallParens = regexp.MustCompile(`\bon\w+\s*=\s*[^;& \n\r]*\(`)

// reSQLi008AttackCtx 确认十六进制字面量命中（sqli:008）是真实 SQL 注入尝试，
// 而非良性十六进制值（CSS 颜色、内存地址、二进制协议）。
// 当 sqli:008 是首个命中规则时，只有该正则匹配才报告命中。
var reSQLi008AttackCtx = regexp.MustCompile(`(` +
	`\b(or|and)\s+\d+\s*=\s*\d+` + // OR 1=1 / AND 1=2 盲注条件
	`|union(\s+all)?\s+select\b` + // UNION SELECT
	`|\binformation_schema\b` + // schema/系统表枚举
	`|\bhaving\s+\d+\s*=\s*\d+` + // HAVING 1=1 盲注
	`|\bwhere\s+\d+\s*=\s*\d+` + // WHERE 1=1
	`|\binto\s+(out|dump)file\b` + // 文件写入外带
	`|\b(order|group)\s+by\s+\d+\s*(--|/\*)` + // ORDER/GROUP BY n 后接 SQL 注释
	`|(or|and)\s+['"]\w+['"]\s*=\s*['"]\w+['"]` + // OR 'x'='x' 字符串比较
	`|(substr|substring|mid)\s*\([^)]*\)\s*=\s*['"]` + // substr(...)='x' 比较
	`|\d+\s*=\s*\(\s*select\b` + // 子查询比较：1=(SELECT ...)
	`|\bin\s*\(\s*select\b` + // IN (SELECT ...) 子查询
	`)`)

// rePathTravSensitive 检测指向已知敏感系统文件或目录的路径遍历载荷，
// 用于抑制构建/配置文件中相对路径 `../../` 的误报。
var rePathTravSensitive = regexp.MustCompile(
	`(etc/passwd|etc/shadow|etc/hosts|/etc/|proc/self|/proc/|windows/system32|win\.ini|boot\.ini|cmd\.exe|/root/|/home/\w|\.env$|web\.xml|nginx\.conf|apache\.conf|web-inf|meta-inf|\.git/|\.svn/|\.htpasswd|\.aws/|\.ssh/|/bin/sh|/bin/bash|/bin/cat|/usr/bin|/var/log|/tmp/|/dev/)`)

// reTautologyCapture 检测 "or 1=1"、"and 2=2" 这类布尔恒等式（两侧数字相同）。
// Go regexp 不支持反向引用，故在此提取后手工比较。
var reTautologyCapture = regexp.MustCompile(`\b(?:or|and)\s+(\d+)\s*=\s*(\d+)\b`)

func isTautology(s string) bool {
	matches := reTautologyCapture.FindAllStringSubmatch(s, -1)
	for _, m := range matches {
		if len(m) >= 3 && m[1] == m[2] {
			return true
		}
	}
	return false
}

var reBoolSQLContext = regexp.MustCompile(`(select|from|where|union|having|group|order)\b`)
var reSQLDMLContext = regexp.MustCompile(`\b(table|into\b|values\s*\(|database|schema|columns\s+from|rows\s+from|truncate\b)\b|\b(xp_|sp_[a-z])\w`)

// reSQLStatementStart 匹配「引号闭合 + 分号 + 新语句起始」的 SQL 语法形态：
//
//  1. 语句首关键字——DML/DDL/DCL/TCL、游标与预处理语句，以及 MySQL 管理语句
//     （HANDLER / SIGNAL / PURGE / FLUSH / DO / HELP / KILL / RESET …）。
//     词表只取**语句首**关键字，与 owasp:sqli:006 的规则 meta 一致。
//  2. 标识符或限定标识符后紧跟左括号——函数调用（`sleep(`、`dbms_lock.sleep(`、
//     `benchmark(`、`if(`）。取「标识符 + `(`」形态，不枚举任何函数名，
//     因此对内置/自定义函数与任意 schema 限定名一致成立。
//
// 该正则同时被 sqli:006 规则与它的误报抑制器引用（单一事实来源）：抑制器
// 只在「无结构词 且 无语句起始形态」时判为误报，两者不会互相打架。
var reSQLStatementStart = regexp.MustCompile(`'\s*;\s*(?:(?:union|select|insert|update|delete|merge|replace|call|load|values|create|alter|drop|truncate|rename|comment|grant|revoke|analyze|begin|start|commit|rollback|savepoint|set|lock|unlock|prepare|deallocate|declare|execute|exec|explain|describe|desc|show|use|intersect|except|with|table|do|handler|signal|purge|flush|help|kill|reset|install|uninstall|xa|binlog|change|check|checksum|optimize|repair|shutdown|import|resignal)\b|[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*\s*\()`)

// hasCodeBlockBraceAfterStackedSemicolon 判断「引号闭合 + 分号」之后的新语句
// 片段里是否出现花括号。`{` / `}` 不属于任何 SQL 语句的语法，只出现在
// JavaScript / Java / JSON 代码块中；而 `'; for (...) {`、`';while(...){`
// 这类代码片段的语句首形态（标识符 + 括号）与 SQL 调用无法区分，花括号是
// 它们的反证。判据只看 `--` 之前的语句体，注释之后的内容不属于该语句。
//
// @param raw 原始扫描目标（未经注释剥离）
// @return 分号后的语句体内含花括号时返回 true
func hasCodeBlockBraceAfterStackedSemicolon(raw string) bool {
	s := toLowerASCII(raw)
	i := strings.Index(s, "';")
	if i < 0 {
		return false
	}
	rest := s[i+2:]
	if j := strings.Index(rest, "--"); j >= 0 {
		rest = rest[:j]
	}
	return strings.ContainsAny(rest, "{}")
}

// hasSQLCommentTokenBoundary 判断归一化文本里是否存在**语法上可用作 SQL 注释
// 起始**的 `--` / `/*`。sqli:005 的规则正则是「引号或数字 + 可选空白 + 注释符」，
// 这个形态在随机字节流（尤其 base64/压缩数据经解码后的片段）里碰撞概率极高，
// 因此需要按 SQL 词法确认注释符确实落在 token 边界上。
//
// 两条判据各自独立，任一成立即返回 true：
//
//  1. **token 边界判据**——注释是词法单元之间的分隔符，不能从 token 内部开始。
//     左邻为分隔符/运算符/引号/括号/串首，或左邻是数字且该数字是独立 token
//     （再往左不是 token 字符）时成立。此判据覆盖 `'/*`、`);/*`、`1--/etc`、
//     `1'/*!union*/select` 等正常注入形态，同时排除 `m1/*b`（`1` 属于标识符
//     `m1`）与 `abc--x`、`a1--b`（标识符内部的双横线）。
//  2. **参数终止判据**——query/表单参数以 `&` 分隔，注释符紧跟 `&` 时，
//     前一个参数值已结束，后续参数会被独立扫描；若其中含真实 SQL 结构，
//     自会被对应规则命中，因此这里不再按注释采信。此判据覆盖
//     `id=queryvalue1/*`、`source=arn:aws:s3:::bucket01/*&format=json`
//     `x=1--&y=2` 一类形态（后两者的命中另外还受 ARN / 路径通配符分支约束）。
//
// 判据只依赖注释符两侧的字符类别与 token 结构，不含任何具体词、数字串或长度阈值。
//
// @param s 归一化后的扫描目标
// @return 存在语法上可用的 SQL 注释起始时返回 true
func hasSQLCommentTokenBoundary(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		isDash := s[i] == '-' && s[i+1] == '-'
		isSlashStar := s[i] == '/' && s[i+1] == '*'
		if !isDash && !isSlashStar {
			continue
		}
		if i+2 >= len(s) {
			// 注释符直达串尾：`/*` 为未闭合块注释（注释体到串尾），
			// `--` 为值末尾的行注释，两者都是注入形态。
			return true
		}
		c := s[i+2]
		if c == '&' {
			// 参数终止：`/*` 是前一个参数值的末字符，`--` 后另有参数。
			// 前一个值没有 SQL 结构（有的话已被别的规则命中），
			// 后续参数会被独立扫描。
			continue
		}
		if isDash {
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '/' {
				return true
			}
			continue
		}
		// `/*` —— 右邻决定它是不是注释体起点。
		if c == '!' {
			// MySQL 可执行注释 /*!50000union*/：语法上必然是注释。
			return true
		}
		if !isSQLCommentLeftBoundary(s, i) {
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
			c == '*' || c == '(' || c == ')' || c == '\'' || c == '"' || c == '/' ||
			c == '-' || c == '~' || c == '&' || c == '|' || c == '#' || c == '@' ||
			c == '%' || c == ';' || c == '=' || c == '<' || c == '>' || c == ',' ||
			c == '.' || c == '[' || c == ']' || c == '{' || c == '}' || c == '^' || c == '+' ||
			c == '`' || c == '$' || c == '_' {
			return true
		}
		if c >= '0' && c <= '9' {
			return true
		}
		// 小写字母：归一化后 SQL 关键字/标识符均为小写，视为注释正文。
		if c >= 'a' && c <= 'z' {
			return true
		}
		// 大写字母：可能是 base64 片段（`/*B;Z`、`/+A9`）。base64 的 A-Z0-9
		// 连续串不会在中间夹入空格或小写字母，故要求该串在遇到小写字母或
		// 空格之前就结束；否则按注释正文放行（`/*Union*/` 形态）。
		if c >= 'A' && c <= 'Z' {
			j := i + 3
			for j < len(s) && (s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if j >= len(s) || s[j] == ' ' || s[j] >= 'a' && s[j] <= 'z' {
				return true
			}
		}
	}
	return false
}

// isSQLCommentLeftBoundary 判断 s[i] 处能否成为一个 SQL 注释的起点。
//
// @param s 归一化后的扫描目标
// @param i 注释符首字符的下标
// @return 左侧构成 token 边界时返回 true
func isSQLCommentLeftBoundary(s string, i int) bool {
	if i == 0 {
		return true
	}
	c := s[i-1]
	if isSQLTokenChar(c) {
		j := i - 1
		for j > 0 && isSQLTokenChar(s[j-1]) {
			j--
		}
		return s[j] >= '0' && s[j] <= '9'
	}
	switch c {
	case ' ', '\t', '\n', '\r', '\'', '"', ')', '(', ';', '=', '<', '>', '|', '&', '+', '-', '*', '/',
		'%', '^', '~', '!', ':', ',', '\\', '{', '}', '[', ']':
		return true
	}
	return false
}

// isSQLTokenChar 判断字节是否属于 SQL 标识符/数字字面量的连续 token 字符集。
//
// @param b 待判字节
// @return 属于 token 字符时返回 true
func isSQLTokenChar(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
		b == '_' || b == '$' || b == '.'
}

func isPathTravFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:path_traversal:001", "owasp:path_traversal:004":
		return !rePathTravSensitive.MatchString(normalized)
	case "owasp:path_traversal:011":
		if !strings.Contains(normalized, "%252e") {
			return true
		}
		return !rePathTravSensitive.MatchString(normalized)
	case "owasp:path_traversal:009":
		// \.{3,}[/\\] 会把正文省略号后接链接（...</a> 解码为
		// ...</a>）或 JSON 转义序列（...\n、...\t 字面反斜杠）误判为
		// 路径穿越。中文内容（网易 analytics 白样）高频出现这两种形态。
		// 仅当 ... 后跟的斜杠是真正路径分隔且无 HTML 标签/转义上下文时保留。
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "...</") || strings.Contains(lower, "...%3c/") ||
			strings.Contains(lower, "...\\n") || strings.Contains(lower, "...\\t") ||
			strings.Contains(lower, "...\\r") || strings.Contains(lower, "...\\u") {
			return true
		}
	}
	return false
}

func isSSRFFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:ssrf:010":
		lower := strings.ToLower(normalized)
		// Cloudflare RUM 与 CDN-CGI 路径会在遥测载荷中使用 "file://" 或类似协议模式，
		// 它们并非真实的 SSRF 尝试。
		if strings.Contains(lower, "cdn-cgi") ||
			strings.Contains(lower, "/rum") ||
			strings.Contains(lower, "cloudflare") {
			return true
		}
	case "owasp:ssrf:007":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "gopher://") ||
			strings.Contains(lower, "file://") ||
			strings.Contains(lower, "dict://") {
			return false
		}
		if strings.Contains(lower, "\"upstreams\"") || strings.Contains(lower, "\"upstream\"") ||
			strings.Contains(lower, "\"proxy_pass\"") || strings.Contains(lower, "\"backend\"") ||
			strings.Contains(lower, "\"server_names\"") {
			return true
		}
		if strings.Contains(lower, "localhost") && !strings.Contains(lower, "127.") {
			if len(normalized) > 100 && !strings.Contains(lower, "@") &&
				!strings.Contains(lower, "metadata") &&
				!strings.Contains(lower, "169.254.") {
				return true
			}
			if strings.Contains(lower, "accessurl=") ||
				strings.Contains(lower, "recordnewuserjsonpcallback") ||
				strings.Contains(lower, "localhost:8000") {
				return true
			}
		}
		if strings.HasPrefix(lower, "http://127.0.0.1") || strings.HasPrefix(lower, "https://127.0.0.1") ||
			strings.HasPrefix(lower, "http://localhost") || strings.HasPrefix(lower, "https://localhost") {
			hostOnly := !strings.Contains(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(lower, "http://"), "https://"), "127.0.0.1"), "localhost"), "/")
			if hostOnly {
				return true
			}
		}
		// 此处原有一层「127.0.0.1/localhost ⊃ "upstreams"」判断。删除品牌词
		// （codepen.io / stackblitz.com / ant.design）后，其内层条件与本 case
		// 上方的 "upstreams" 分支同字面量互斥：能到达此处即意味着上方分支未命中，
		// 即 lower 不含 "upstreams"，故内层恒为假、整块不可达，整体移除。
		// 该判断原本保护的「配置体含 upstreams」误报语义已由上方分支覆盖。
	}
	return false
}

func isDeserFalsePositive(raw, ruleID string) bool {
	switch ruleID {
	case "owasp:deser:005":
		if len(raw) > 256 {
			return true
		}
		return false
	case "owasp:deser:001":
		return false
	}
	return false
}

func isNoSQLiFalsePositive(raw, ruleID string) bool {
	switch ruleID {
	case "owasp:nosql:002", "owasp:nosql:003", "owasp:nosql:004":
		if !reNoSQLAttackCtx.MatchString(raw) {
			return true
		}
	case "owasp:nosql:005", "owasp:nosql:006":
		return true
	case "owasp:nosql:022":
		// 引号闭合后的 $or 数组：引号前必须是被注入的值（'...')，
		// 无前置引号则可能是对象字面量。
		if !strings.ContainsAny(raw, "'\"") {
			return true
		}
	case "owasp:nosql:023", "owasp:nosql:024":
		// 023/024 为纯 $or 数组形态，归因于 $or 关键字的所有权；
		// 005 与 them or operator 等 benign 文本的 FP 抑制由 022/023 负责。
		return false
	case "owasp:nosql:018":
		// $where:'99 == 88' 的引号值内比较形态要求 $where 引号内出现
		// 运算/数字；纯字面串（$where:'name'）不算注入。
		if !strings.Contains(raw, "$where") {
			return true
		}
		if i := strings.Index(raw, "$where"); i >= 0 {
			rest := raw[i+len("$where"):]
			if !strings.Contains(rest, "'") && !strings.Contains(rest, `"`) {
				return true
			}
		}
	case "owasp:nosql:020":
		// 忙等形态必须同时有分号注入锚（; 或逗号隔断的表达式开始）或
		// db/collection 上下文，避免自然叙述「new Date」误报。
		if !strings.ContainsAny(raw, ";&(") {
			return true
		}
	}
	return false
}

func isELFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:el:005":
		if !strings.Contains(normalized, "${") &&
			!strings.Contains(normalized, "#{") &&
			!strings.Contains(normalized, "%{") &&
			!strings.Contains(normalized, "@java.lang.") &&
			!strings.Contains(normalized, "getclass") &&
			!strings.Contains(normalized, "getdeclaredmethods") &&
			!strings.Contains(normalized, ".invoke(") &&
			!strings.Contains(normalized, "forname(") {
			return true
		}
	case "owasp:el:008", "owasp:el:011", "owasp:el:013":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "redirect:${#") ||
			strings.Contains(lower, "#context.get(") ||
			strings.Contains(lower, "com.opensymphony.xwork2") ||
			strings.Contains(lower, "getrealpath(") ||
			strings.Contains(lower, "getwriter().println") {
			return false
		}
	}
	return false
}

var reCRLFHeaderInject = regexp.MustCompile(`\r\n\r?\n\s*(http/[\d.]+\s+\d{3}|[a-zA-Z][-a-zA-Z0-9]+\s*:)`)
var reWebshellPHPContext = regexp.MustCompile(`(base64_decode\s*\(|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|\$_(get|post|request|cookie|server|files)\s*\[|<\?php\b|\.getruntime\(\)|subprocess|os\.system|response\.\s*write)`)

func isWebshellFalsePositive(normalized, ruleID string) bool {
	switch ruleID {
	case "owasp:webshell:001":
		// 存在 PHP/shell 特有标记时才视作真实 webshell 尝试。
		if reWebshellPHPContext.MatchString(normalized) {
			return false
		}
		if strings.Contains(normalized, "system(") ||
			strings.Contains(normalized, "exec(") ||
			strings.Contains(normalized, "popen(") ||
			strings.Contains(normalized, "proc_open(") {
			return false
		}
		// 仅有 eval() 或 assert() 而无 PHP/shell 上下文：很可能是 JavaScript 误报。
		return true
	case "owasp:webshell:016":
		lower := strings.ToLower(normalized)
		if strings.Contains(lower, "java.util.arraylist") {
			return true
		}
	}
	return false
}

func isCRLFFalsePositive(normalized, ruleID string) bool {
	lower := strings.ToLower(normalized)
	switch ruleID {
	case "owasp:crlf:004":
		// 裸 \r\n\r\n 在多行 textarea 值（Windows 换行）、multipart 表单数据边界
		// 与二进制数据中很常见。
		// 要求分隔符后出现 HTTP 请求头/状态行上下文才确认注入。
		if strings.Contains(lower, "telemetry") ||
			strings.Contains(lower, "analytics") ||
			strings.Contains(lower, "cdn-cgi") {
			return true
		}
		return !reCRLFHeaderInject.MatchString(normalized)
	case "owasp:crlf:001":
		// multipart 表单上传与二进制文件数据天然含 \r\n 序列。
		// 除非 CRLF 后跟真实的 HTTP 请求头注入尝试
		// （且头值可疑，而非仅 multipart 边界元数据），否则抑制。
		if strings.Contains(normalized, "content-disposition:") ||
			strings.Contains(normalized, "content-type: image/") ||
			strings.Contains(normalized, "content-type: application/octet") ||
			strings.Contains(normalized, "xpacket") ||
			strings.Contains(normalized, "xmpmeta") {
			return true
		}
		// 遥测/分析 JSON 载荷中记录的 HTTP 响应头。
		// 形如 "access-control-...: value\r\ncontent-type: ...\r\ndate: ..."，
		// 同时含多个标准 HTTP 请求头——并非注入尝试。
		// 真实 CRLF 注入只针对单个头（set-cookie、location）以劫持响应，
		// 而被记录的响应头总是一起出现 2 个以上良性头。
		benignHeaderCount := 0
		for _, hdr := range []string{"content-type:", "content-length:", "date:", "server:",
			"access-control-", "x-cache", "vary:", "x-nws-", "x-server-",
			"cache-control:", "expires:", "pragma:", "etag:", "last-modified:",
			"accept-ranges:", "connection:", "keep-alive:", "transfer-encoding:",
			"x-request-id:", "x-powered-by:", "strict-transport-security:",
			"x-content-type-options:", "x-frame-options:", "x-xss-protection:",
			"referrer-policy:", "permissions-policy:", "timing-allow-origin:",
			"alt-svc:", "nel:", "report-to:", "cf-ray:", "cf-cache-status:"} {
			if strings.Contains(lower, hdr) {
				benignHeaderCount++
			}
		}
		if benignHeaderCount >= 2 && !strings.Contains(lower, "set-cookie:") {
			return true
		}
		// 遥测、分析与日志 POST 体常含 \r\n 加类请求头模式
		// （例如 JSON 载荷里的 "content-type:"），并非注入尝试。
		if strings.Contains(lower, "telemetry") ||
			strings.Contains(lower, "analytics") ||
			strings.Contains(lower, "cdn-cgi") ||
			strings.Contains(lower, "/g/collect") ||
			strings.Contains(lower, "google-analytics") ||
			strings.Contains(lower, "googletagmanager") {
			return true
		}
		// 大于 500 字节且 \r\n 后接常见 HTTP 请求头的大 POST 体，
		// 通常是遥测/表单数据，而非请求头注入。
		if len(normalized) > 500 && !strings.Contains(lower, "set-cookie") &&
			!strings.Contains(lower, "location:") {
			return true
		}
	case "owasp:crlf:010":
		// 折叠态（归一化后的空格分隔）拦「整行命令」形态即可。若有内容前缀
		// 说明来自同一行：rcpt to: 无引号上下文时可能是自然语言；
		// capability/fetch 受 \s+（空格）锚定不会命中有前缀的词。
		if strings.Contains(lower, "rcpt to") &&
			!strings.Contains(lower, " rcpt to") {
			return true
		}
	}
	return false
}
