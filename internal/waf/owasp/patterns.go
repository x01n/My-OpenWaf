package owasp

import (
	"regexp"
	"strings"
	"sync"

	"My-OpenWaf/internal/ac"
	"My-OpenWaf/internal/core/score"
	"My-OpenWaf/internal/pkg/snippet"
)

var owaspAccPool = sync.Pool{
	New: func() any { return score.NewAccumulator(0) },
}

// acquireOWASPAcc 取出一个已重置并设定阈值的累加器。
//
// @param threshold 闭区间阈值（total >= threshold 视为过阈）
// @return 可直接用于 Add 的累加器实例
func acquireOWASPAcc(threshold int) *score.Accumulator {
	acc := owaspAccPool.Get().(*score.Accumulator)
	acc.Reset()
	acc.SetThreshold(threshold)
	return acc
}

// releaseOWASPAcc 归还累加器以便复用；acc 为 nil（从未命中任何规则）时不做任何事。
//
// 归还后累加器内的 hits/dangerIDs 元素会被后续 Reset 清零，调用方不得在归还后
// 继续持有 Attribution()/Hits() 返回的切片别名。归因 ID 取自规则表常量字符串，
// 值拷贝进 OWASPHit 后可安全带出。
//
// @param acc 待归还的累加器，允许为 nil
func releaseOWASPAcc(acc *score.Accumulator) {
	if acc != nil {
		owaspAccPool.Put(acc)
	}
}

// ruleRegexIndex 由全部 *Patterns 切片构建：规则 ID 到其全部正则的映射。
// 硬编码发射点（path/upload/proto/crlf 等）不在切片中，查不到即为空片段。
var ruleRegexIndex = func() map[string][]*regexp.Regexp {
	index := make(map[string][]*regexp.Regexp, 340)
	for _, group := range allPatternRuleGroups() {
		for _, pattern := range group.patterns {
			if pattern.re == nil {
				continue
			}
			index[pattern.id] = append(index[pattern.id], pattern.re)
		}
	}
	return index
}()

/**
 * ExtractMatchSnippet 提取触发指定规则命中的内容片段。
 *
 * 该函数在收口处调用，每个请求最多执行一次，且只遍历该规则自身的正则
 * （通常一条），不在检测热路径上产生额外扫描。命中位置两侧各保留
 * snippet.ContextLen 字节，整体截断到 snippet.MaxLen；查不到规则正则
 * （硬编码发射点）或目标串为空时返回空字符串。
 *
 * @param ruleID 检测器实际发出的稳定规则 ID。
 * @param target 触发命中的规范化目标串。
 * @return 已截断的匹配片段；不适用时为空字符串。
 */
func ExtractMatchSnippet(ruleID, target string) string {
	if ruleID == "" {
		return ""
	}
	return snippet.Extract(ruleRegexIndex[ruleID], target)
}

/**
 * AttachMatchSnippet 在命中结果上补齐匹配片段，已有片段时保持原值。
 *
 * @param hit 检测层产出的命中结果。
 * @param target 产生该命中的目标串。
 * @return 片段已填充的命中结果。
 */
func AttachMatchSnippet(hit OWASPHit, target string) OWASPHit {
	if hit.Snippet != "" || target == "" {
		return hit
	}
	hit.Snippet = ExtractMatchSnippet(hit.RuleID, target)
	return hit
}

var reNoSQLAttackCtx = regexp.MustCompile(`(\[|\{|:|=)\s*\\?["']?\s*\$(ne|gt|lt|gte|lte|regex|in|nin|exists)\b|\w+\[(\$ne|\$gt|\$lt|\$regex|\$exists)\]\s*=|["']\$\w+["']\s*:\s*\{\s*["']\$(ne|gt|lt|gte|lte|regex|in|nin|exists)`)
var sqliPatterns = []owaspPattern{
	{regexp.MustCompile(`union\s*(all\s*)?select|unionselect`), 5, "owasp:sqli:001", "union"},
	{regexp.MustCompile(`'\s*(or|and)\s+['"]?\d`), 5, "owasp:sqli:002", ""},
	{regexp.MustCompile(`(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(`), 5, "owasp:sqli:003", ""},
	{regexp.MustCompile(`;\s*(select|drop|alter|create|truncate|delete|update|insert)\s`), 5, "owasp:sqli:004", ""},
	{regexp.MustCompile(`['"\d]\s*(--(?:[\s/]|$)|/\*)`), 3, "owasp:sqli:005", ""},
	// 引号闭合 + 分号 + 新语句关键字：''; G（SQL 文档正文）、''; f（JS 的 for）
	// 这类「分号后任意词字符」的形态不是注入，规则自身 meta（owasp:sqli:006
	// 「引号闭合后接分号与新语句关键字」）要求的也是语句关键字。故词表取 SQL
	// 语句首关键字（DML/DDL/DCL/TCL/游标与预处理），而非任意 \w。
	{reSQLStatementStart, 3, "owasp:sqli:006", ""},
	{regexp.MustCompile(`(chr|unhex|conv)\s*\(`), 3, "owasp:sqli:007", ""},
	{regexp.MustCompile(`[,=(]\s*0x[0-9a-f]{4,}`), 2, "owasp:sqli:008", "0x"},
	{regexp.MustCompile(`information_schema|sysobjects|sys\.\w+tables`), 5, "owasp:sqli:009", ""},
	{regexp.MustCompile(`\b(or|and)\s*\d+\s*=\s*\d+`), 5, "owasp:sqli:010", ""},
	{regexp.MustCompile(`\b(or|and)\s*['"]\w*['"]\s*=\s*['"]\w*['"]`), 5, "owasp:sqli:011", ""},
	// 「分号 + 双减号」必须确为注释截断，而不是连字符串（分隔线、multipart
	// 边界 `------WebKitFormBoundary`、ASCII 表格 `; --------`）。故要求第二个
	// 减号后不再是减号（或已到串尾）；与 owasp:sqli:005 的注释符边界惯例一致。
	{regexp.MustCompile(`;\s*--(?:[^-]|$)`), 3, "owasp:sqli:012", "--"},
	{regexp.MustCompile(`(load_file|outfile|dumpfile)\s*\(`), 5, "owasp:sqli:013", ""},
	{regexp.MustCompile(`@@(version|hostname|datadir|basedir)`), 5, "owasp:sqli:014", "@@"},
	{regexp.MustCompile(`(extractvalue|updatexml)\s*\(`), 5, "owasp:sqli:015", ""},
	{regexp.MustCompile(`group_concat\s*\(`), 5, "owasp:sqli:016", "group_concat"},
	{regexp.MustCompile(`\binto\s+(out|dump)file\b`), 5, "owasp:sqli:017", "into"},
	{regexp.MustCompile(`case\s+when\s+.*then\s+(sleep|benchmark|pg_sleep)`), 5, "owasp:sqli:018", "when"},
	{regexp.MustCompile(`\border\s+by\s+\d+\s*(--\s?|/\*|;\s*$|$)`), 5, "owasp:sqli:019", "order"},
	{regexp.MustCompile(`/\*!\d*\s*(select|union|insert|update|delete|drop|alter|where|from|and|or)\b`), 5, "owasp:sqli:020", "/*!"},
	{regexp.MustCompile(`(substr|substring|mid)\s*\(.+,\s*\d+\s*,\s*\d+\s*\)`), 4, "owasp:sqli:021", ""},
	{regexp.MustCompile(`\bif\s*\(\s*(select|ord|ascii|substr|length|count|version)\b`), 5, "owasp:sqli:022", ""},
	{regexp.MustCompile(`'\s*(\^|&|<<|>>)\s*'`), 3, "owasp:sqli:023", ""},
	{regexp.MustCompile(`\bxp_(cmdshell|regread|regwrite|loginconfig|enumdsn|availablemedia|ntsec)\b`), 6, "owasp:sqli:024", "xp_"},
	{regexp.MustCompile(`\bprocedure\s+analyse\s*\(`), 5, "owasp:sqli:025", "procedure"},
	{regexp.MustCompile(`\b(utl_http|utl_file|dbms_pipe|dbms_output)\s*\.\s*\w+`), 5, "owasp:sqli:026", ""},
	{regexp.MustCompile(`\bhaving\s+\d+\s*=\s*\d+`), 5, "owasp:sqli:027", "having"},
	{regexp.MustCompile(`\d+\s*=\s*\(\s*select\b`), 5, "owasp:sqli:028", "select"},
	{regexp.MustCompile(`'\s*like\s+'[%_]`), 5, "owasp:sqli:029", "like"},
	{regexp.MustCompile(`\blimit\s+\d+\s*,\s*\d+\s*(--|;)`), 5, "owasp:sqli:030", "limit"},
	{regexp.MustCompile(`(=\s*|\bin\s*)\(\s*select\b`), 5, "owasp:sqli:031", "select"},
	{regexp.MustCompile(`\bgroup\s+by\s+\d+(\s*,\s*\d+)*\s*(--|;|/\*|$)`), 5, "owasp:sqli:032", "group"},
	{regexp.MustCompile(`\blimit\s+\d+\s+offset\s+\d+\s*(--|;|/\*)`), 5, "owasp:sqli:033", "offset"},
	{regexp.MustCompile(`;\s*exec(?:\s+|\s*\()(?:xp_|sp_|master\.\.)\w`), 5, "owasp:sqli:034", "exec"},
	{regexp.MustCompile(`\bwaitfor\s+delay\s*['"]`), 7, "owasp:sqli:035", "waitfor"},
	{regexp.MustCompile(`\b(or|and)\s+['"]['"]\s*=\s*['"]`), 5, "owasp:sqli:036", ""},
	{regexp.MustCompile(`\bcopy\b.{0,200}\bto\s+program\b`), 5, "owasp:sqli:037", "program"},
	{regexp.MustCompile(`\bselect\b.{0,100}\bfrom\s+\w+\s*(--|;|/\*|\bwhere\s+\d+=\d+|\bunion\b)`), 5, "owasp:sqli:038", "select"},
	{regexp.MustCompile(`\b(and|or)\s*\(\s*select\b`), 5, "owasp:sqli:039", "select"},
	{regexp.MustCompile(`\bselect\s+case\s+when\b`), 5, "owasp:sqli:040", "select"},
	{regexp.MustCompile(`\bselect\s+(cast|convert)\s*\([^)]{0,80}\)\s*(from\b|,\s*\w|--)`), 5, "owasp:sqli:041", "select"},
	{regexp.MustCompile(`\bchr\s*\(\s*\d+\s*\)\s*(\+|\|\|)\s*chr\s*\(`), 5, "owasp:sqli:043", "chr"},
	{regexp.MustCompile(`utl_inaddr\s*\.\s*get_host`), 5, "owasp:sqli:044", "utl_inaddr"},
	{regexp.MustCompile(`\b(exec|execute)\s+.{0,30}\bxp_(dirtree|cmdshell|regread|fileexist|subdirs)\b`), 5, "owasp:sqli:045", "xp_"},
	{regexp.MustCompile(`\bselect\b[^;]{0,20}\(\s*select\b`), 5, "owasp:sqli:046", "select"},
	{regexp.MustCompile(`\bselect\s+\*\s+from\s+\w`), 4, "owasp:sqli:047", "select"},
	{regexp.MustCompile(`\bexec\s+master\s*\.\.\s*\w`), 5, "owasp:sqli:048", "master"},
	// Unicode 绕过：SQL 关键词中全角/半角字符交替
	{regexp.MustCompile(`[\x{FF10}-\x{FF5A}]{3,}.{0,20}(select|union|insert|update|delete)`), 5, "owasp:sqli:049", ""},
	// 嵌套注释混淆：/*/**/union/**/select/**/
	{regexp.MustCompile(`/\*[^*]*/\*.*?\*/.*?\*/`), 5, "owasp:sqli:050", "/*"},
	// MySQL 条件注释：/*!50000 UNION*/
	{regexp.MustCompile(`/\*!\d{5}\s*(union|select|insert|update|delete|drop)\b`), 6, "owasp:sqli:051", "/*!"},
	// MySQL 带版本号条件注释的变体
	{regexp.MustCompile(`/\*!\s*(union|select|concat|group_concat)\b`), 5, "owasp:sqli:052", "/*!"},
	// 全角 Unicode SQL 关键词（如 ＳＥＬＥＣＴ）
	{regexp.MustCompile(`[\x{FF33}\x{FF53}][\x{FF25}\x{FF45}][\x{FF2C}\x{FF4C}][\x{FF25}\x{FF45}][\x{FF23}\x{FF43}][\x{FF34}\x{FF54}]`), 5, "owasp:sqli:053", ""},
	// 双重 URL 编码检测：%2527（%25 = %，故 %2527 = %27 = '）
	{regexp.MustCompile(`%25(27|22|3[bB]|2[dD]2[dD])`), 5, "owasp:sqli:054", "%25"},
	// JSON 文档函数：json_extract( 在 URL/表单上下文几乎不出现于良性输入，
	// 是 MySQL/MariaDB 查询载荷的高置信度字面，单一命中即达 mid 阈。
	{regexp.MustCompile(`json_extract\s*\(`), 4, "owasp:sqli:055", "json_extract"},
	// boolean 盲注的比较形态：`and 1859 like (select count(*) ...)`、
	// `or 2306 in (select ...)`。数字字面量与 and/or 之间没有等号，
	// sqli:010（\d+\s*=\s*\d+）与 sqli:031（in (select) 需 in 紧邻括号）
	// 都覆盖不到 `N like (`，垫空白归一化后仍会漏判。分值 6 使其单条达阈。
	{regexp.MustCompile(`\b(or|and)\s+\d{1,10}\s+(like|in)\s*\(`), 6, "owasp:sqli:057", ""},
	// 盲注比较的另一形态：`and 1892 like concat(char(113)+...)`、
	// `and 9823 like benchmark(10000000,md5(...))`。like 后不是左括号而是
	// SQL 字符串构造函数，057 覆盖不到。函数表只列本家族实际出现且正常文本
	// 不会紧跟 like 的构造器。
	{regexp.MustCompile(`\b(or|and)\s+\d{1,10}\s+(like|rlike|in)\s+(concat|char|cast|convert|benchmark|md5|elt|extractvalue|substr|substring|hex|ascii|length|count|if|group_concat)\s*\(`), 6, "owasp:sqli:058", ""},
	// MySQL 专有 rlike 后接子查询：`%' rlike (select (case when ...))`。
	// rlike 只在 MySQL 方言中存在，正常查询串不会以 `rlike (select` 出现。
	{regexp.MustCompile(`\brlike\s*\(\s*select\b`), 6, "owasp:sqli:059", ""},
	// SQL 关键字内插尖括号（`a<>nd`、`un<>ion sel<>ect`）：把关键字拆成两段
	// 以绕过按完整词匹配的检测器。尖括号不是 SQL 语法的一部分，正常取值不会
	// 在关键字中间出现，故单条 5 分可直接达 mid 阈。
	{regexp.MustCompile(`\b(?:un\s*<>\s*ion|sel\s*<>\s*ect|a\s*<>\s*nd)\b`), 5, "owasp:sqli:060", "<>"},
}

var webshellPatterns = []owaspPattern{
	// 不加词边界：真实攻击常用「字母前缀 + system(」拼接绕过
	// （如 zerodiumsystem('id')，zerodium 框架 RCE 的固定 payload），
	// 子串匹配正是该类载荷的检出点。shell_exec 裸词由 webshell:028 覆盖，
	// 带括号形态仍可经 exec( 子串命中。
	{regexp.MustCompile(`(eval|assert|system|exec|passthru|popen|proc_open)\s*\(`), 4, "owasp:webshell:001", ""},
	{regexp.MustCompile(`base64_decode\s*\(`), 3, "owasp:webshell:002", "base64_decode"},
	{regexp.MustCompile(`<\?php\s`), 5, "owasp:webshell:003", "<?php"},
	{regexp.MustCompile(`runtime\.getruntime\(\)\.exec`), 5, "owasp:webshell:004", "getruntime"},
	{regexp.MustCompile(`(cmd\.exe|powershell\.exe|/bin/(ba)?sh)`), 4, "owasp:webshell:005", ""},
	{regexp.MustCompile(`\$_(get|post|request|cookie)\s*\[`), 4, "owasp:webshell:006", "$_"},
	// PHP preg_replace 带 /e 修饰符（代码执行）
	{regexp.MustCompile(`preg_replace\s*\(\s*['"]/.*?/e`), 5, "owasp:webshell:007", "preg_replace"},
	// Python subprocess / os.system 的 RCE 用法
	{regexp.MustCompile(`(subprocess\s*\.\s*(call|run|popen)|os\s*\.\s*(system|exec[lv]p?))\s*\(`), 4, "owasp:webshell:008", ""},
	// JSP/Groovy 运行时执行
	{regexp.MustCompile(`(\.exec\s*\(|\.getruntime\(\)\s*\.\s*exec)`), 5, "owasp:webshell:009", ""},
	// Perl/Ruby 的 system/exec
	{regexp.MustCompile("\\b(system|exec|open)\\s*\\(\\s*['\"]\\s*(cmd|bash|sh|powershell|nc|wget|curl)"), 4, "owasp:webshell:010", ""},
	// ASP/ASPX webshell：Response.Write / Server.Execute
	{regexp.MustCompile(`(response\s*\.\s*(write|binarywrite)|server\s*\.\s*(execute|mappath))\s*\(`), 4, "owasp:webshell:011", ""},
	// PHP create_function()——等价于 eval() 的动态代码生成
	{regexp.MustCompile(`create_function\s*\(\s*['"][^'"]{0,100}['"]\s*,`), 4, "owasp:webshell:012", "create_function"},
	// PHP 混淆包装函数，常与 eval 串联以隐藏载荷
	{regexp.MustCompile(`(gzinflate|gzuncompress|str_rot13|hex2bin|base64_decode)\s*\(\s*['"]`), 4, "owasp:webshell:013", ""},
	// PHP call_user_func 动态调用：call_user_func('system', $_GET['cmd'])
	{regexp.MustCompile(`call_user_func\s*\(\s*['"]?\s*(system|exec|passthru|shell_exec|popen|proc_open|assert)\b`), 5, "owasp:webshell:014", "call_user_func"},
	// Drupal Drupalgeddon2/3：mail[#post_render][]=exec、mail[#type]=markup
	{regexp.MustCompile(`\[\s*#\s*(post_render|pre_render|lazy_builder|markup|type)\s*\]`), 4, "owasp:webshell:015", ""},
	// Java XML 反序列化 / XStream RCE：<java.util.PriorityQueue serialization=...>
	{regexp.MustCompile(`<java\.\w+\.`), 5, "owasp:webshell:016", "<java."},
	// ThinkPHP invokefunction RCE：/index.php?s=index/\think\app/invokefunction&function=call_user_func
	{regexp.MustCompile(`invokefunction.*call_user_func|call_user_func.*invokefunction`), 5, "owasp:webshell:017", ""},
	// 不带危险函数名的通用 call_user_func——ThinkPHP/CodeIgniter 形态
	{regexp.MustCompile(`\\think\\(app|request|template|view)\b`), 5, "owasp:webshell:018", ""},
	// ASP/JSP eval 形态：<%eval、<%execute、request("cmd")
	{regexp.MustCompile(`<%\s*(eval|execute|response\.write)`), 5, "owasp:webshell:019", "<%"},
	// PHP 文件操作：file_put_contents 与 file_get_contents 组合出现
	{regexp.MustCompile(`file_put_contents\s*\(.*file_get_contents|file_get_contents\s*\(.*file_put_contents`), 5, "owasp:webshell:020", ""},
	// elFinder connector RCE：cmd=...&name=...>*.php
	{regexp.MustCompile(`\bname\s*=\s*[^&]*>\s*\w+\.(php|jsp|asp|aspx|sh)\b`), 5, "owasp:webshell:021", ""},
	// file_put_contents 或 file_get_contents 搭配 .php 文件路径
	{regexp.MustCompile(`file_put_contents\b.*\.\s*php\b`), 5, "owasp:webshell:022", "file_put_contents"},
	// body/header 中的 PHP 短标签：<?php，或 <? 后接空格/换行
	{regexp.MustCompile(`<\?\s+(echo|print|include|require|eval|assert|system|exec|passthru)\b`), 5, "owasp:webshell:023", "<?"},
	// PHP 包装器利用：php://input、php://filter、data://text/plain
	{regexp.MustCompile(`php://(input|filter|output|stdin|memory|temp)\b`), 5, "owasp:webshell:024", "php://"},
	{regexp.MustCompile(`data://text/plain\b`), 4, "owasp:webshell:025", "data://text/plain"},
	// PHP 远程文件包含：include/require 搭配远程 URL
	{regexp.MustCompile(`\b(include|require|include_once|require_once)\s*\(\s*['"]?\s*https?://`), 5, "owasp:webshell:026", ""},
	// Python 反射导入 + 危险模块：__import__('os') / __import__("subprocess")。
	// 与 webshell:008（os.system/subprocess 直接调用）互补，覆盖 Jinja2/SSTI 载荷，
	// 且不与 SQLi sleep 家族混淆（不带 '(' 的目标词不触发）。
	{regexp.MustCompile(`__import__\s*\(\s*['"]\s*(os|subprocess|sys|pty|pickle|base64|codecs|builtins|socket)\b`), 5, "owasp:webshell:027", "__import__"},
	// shell_exec 裸词同样是一句话木马/命令执行探测的强特征：
	// 攻击者常把 shell_exec 直接放进参数名或参数值等待被拼接执行。
	{regexp.MustCompile(`\bshell_exec\b`), 4, "owasp:webshell:028", "shell_exec"},
}

func checkWebshell(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !hasWebshellIndicator(s, gate) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则；
	// FP 抑制器前移到 Add 之前，被抑制的规则既不计分也不参与归因。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range webshellPatterns {
		if !gate.patternGate(p, s) {
			continue
		}
		if !p.re.MatchString(s) {
			continue
		}
		if isWebshellFalsePositive(s, p.id) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatWebshell, RuleID: id, Score: total, Desc: "WebShell/代码执行特征"}, true
		}
	}
	return OWASPHit{}, false
}

var revshellPatterns = []owaspPattern{
	{regexp.MustCompile(`bash\s+-i\s+>&?\s*/dev/tcp`), 6, "owasp:revshell:001", "/dev/tcp"},
	{regexp.MustCompile(`/dev/tcp/\d`), 5, "owasp:revshell:002", "/dev/tcp/"},
	{regexp.MustCompile(`(nc|ncat|netcat)\s+.*-e\s`), 5, "owasp:revshell:003", ""},
	{regexp.MustCompile(`python[23]?\s+-c\s+.*socket`), 4, "owasp:revshell:004", "socket"},
	{regexp.MustCompile(`(invoke-expression|iex)\s*\(\s*(new-object|downloadstring)`), 5, "owasp:revshell:005", ""},
	{regexp.MustCompile(`(curl|wget)\s+.*\|\s*(ba)?sh`), 5, "owasp:revshell:006", ""},
	{regexp.MustCompile(`mkfifo\s+/tmp/`), 4, "owasp:revshell:007", "mkfifo"},
	// Perl 反弹 shell
	{regexp.MustCompile(`perl\s+-e\s+['"].{0,300}socket`), 4, "owasp:revshell:008", "socket"},
	// Socat 反弹 shell
	{regexp.MustCompile(`socat\s+\S+\s+exec:`), 5, "owasp:revshell:009", "socat"},
	{regexp.MustCompile(`socat\s+[a-z0-9.+,:-]{0,40}tcp[a-z0-9.+,:-]{0,40}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), 4, "owasp:revshell:010", "socat"},
	// Telnet 反弹 shell：telnet 1.2.3.4 4444
	{regexp.MustCompile(`telnet\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{2,5}`), 4, "owasp:revshell:011", "telnet"},
	// Ruby 或 Node.js 基于 socket 的反弹 shell
	{regexp.MustCompile(`(ruby|node)\s+-[re]\s+['"].{0,300}socket`), 4, "owasp:revshell:012", "socket"},
}

func checkRevShell(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !hasRevShellIndicator(s, gate) {
		return OWASPHit{}, false
	}
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range revshellPatterns {
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
				return OWASPHit{Category: CatRevShell, RuleID: id, Score: total, Desc: "反弹 Shell / 远程执行特征"}, true
			}
		}
	}
	return OWASPHit{}, false
}

var xssPatterns = []owaspPattern{
	{regexp.MustCompile(`<script[;\s>/]`), 5, "owasp:xss:001", "<script"},
	// 零字节/零宽混淆的 script 标签：<scr\x00ipt> 剥零字节后 <script>，
	// 但原始形态（未剥前）也可能以 </script 结尾。独立 low-score 兜底。
	{regexp.MustCompile(`<<script[;\s>/]`), 5, "owasp:xss:071", "<script"},
	{regexp.MustCompile(`\bon(error|load|click|dblclick|auxclick|mouse(over|out|down|up|enter|leave|move|wheel)|focus(in)?|blur|change|submit|toggle|input|key(down|up|press)|drag(start|end|over|enter|leave)?|drop|copy|cut|paste|pointer(over|down|up|cancel|move|enter|leave)|animation(start|end|iteration)|transition(end|start|run|cancel)|scroll|wheel|resize|contextmenu|message|hashchange|popstate|beforeunload|unload|invalid|select|fullscreenchange|touchstart|touchend|touchmove|touchcancel|beforeinput|show)\s*=`), 5, "owasp:xss:002", "on"},
	{regexp.MustCompile(`javascript\s*:`), 5, "owasp:xss:003", "javascript"},
	{regexp.MustCompile(`<img\b[^>]*(src\s*=[^>]*\s+)?onerror\s*=`), 5, "owasp:xss:004", "<img"},
	{regexp.MustCompile(`<iframe[\s>]`), 3, "owasp:xss:005", "<iframe"},
	{regexp.MustCompile(`document\.(cookie|location|write|domain)`), 4, "owasp:xss:006", "document."},
	{regexp.MustCompile(`<svg[\s>]`), 2, "owasp:xss:007", "<svg"},
	{regexp.MustCompile(`<math[\s>]`), 2, "owasp:xss:008", "<math"},
	{regexp.MustCompile(`data:text/html`), 5, "owasp:xss:009", "data:text/html"},
	{regexp.MustCompile(`window\.(location|name|open)`), 4, "owasp:xss:010", "window."},
	{regexp.MustCompile(`\b(eval|settimeout|setinterval|function)\s*\(\s*['"]`), 5, "owasp:xss:011", "("},
	{regexp.MustCompile(`(?i)\bnew\s+function\s*\(\s*[^'"]*['"]`), 4, "owasp:xss:068", "function"},
	{regexp.MustCompile(`innerhtml\s*=`), 5, "owasp:xss:012", "innerhtml"},
	{regexp.MustCompile(`&#x?0*3c;?\s*script`), 5, "owasp:xss:013", "script"},
	{regexp.MustCompile(`<\w+\b[^>]+\bon\w+\s*=`), 5, "owasp:xss:014", "on"},
	{regexp.MustCompile(`<(embed|object)\b[^>]*(data|src)\s*=`), 3, "owasp:xss:015", "<"},
	{regexp.MustCompile(`<form\b[^>]*action\s*=\s*['"]?\s*javascript:`), 5, "owasp:xss:016", "<form"},
	{regexp.MustCompile(`string\s*\.\s*fromcharcode\s*\(`), 5, "owasp:xss:017", "fromcharcode"},
	{regexp.MustCompile(`<base\b[^>]+href\s*=\s*['"]?\s*javascript\s*:`), 5, "owasp:xss:018", "<base"},
	{regexp.MustCompile(`<base\b[^>]+href\s*=`), 3, "owasp:xss:054", "<base"},
	{regexp.MustCompile(`(fetch|xmlhttprequest)\s*\(\s*['"]https?://`), 4, "owasp:xss:019", "http"},
	{regexp.MustCompile(`vbscript\s*:`), 5, "owasp:xss:020", "vbscript"},
	{regexp.MustCompile(`\bexpression\s*\(\s*(document|window|eval|this|alert)`), 3, "owasp:xss:021", "expression"},
	{regexp.MustCompile(`\bsrcdoc\s*=`), 4, "owasp:xss:022", "srcdoc"},
	{regexp.MustCompile(`\{\{.*?(constructor|__proto__|__definegetter__).*?\}\}`), 5, "owasp:xss:023", "{{"},
	{regexp.MustCompile(`document\s*\.\s*(write|writeln)\s*\(`), 5, "owasp:xss:024", "document"},
	{regexp.MustCompile(`(location\s*\.\s*(href|assign|replace)|window\s*\.\s*open)\s*\(\s*['"]?\s*javascript\s*:`), 5, "owasp:xss:025", "javascript"},
	{regexp.MustCompile(`<details\b[^>]*\bopen\b[^>]*\bontoggle\s*=`), 5, "owasp:xss:026", "<details"},
	{regexp.MustCompile(`<input\b[^>]*\bautofocus\b[^>]*\bonfocus\s*=`), 5, "owasp:xss:027", "<input"},
	{regexp.MustCompile(`<link\b[^>]*\brel\s*=\s*['"]?\s*import\b`), 4, "owasp:xss:028", "<link"},
	{regexp.MustCompile(`<img\b[^>]*\bname\s*=\s*['"]?\s*(documentelement|body|head|domain)\b`), 4, "owasp:xss:029", "<img"},
	{regexp.MustCompile(`\b(window|self|top|parent|frames|globalthis|this)\s*\[\s*['"\x60]`), 4, "owasp:xss:030", "["},
	{regexp.MustCompile(`\[\s*['"\x60]\s*(alert|eval|prompt|confirm|settimeout|setinterval|atob|btoa|fetch|open|execscript)\s*['"\x60]\s*\]`), 5, "owasp:xss:031", "["},
	{regexp.MustCompile(`/\w+/\s*\.\s*source`), 4, "owasp:xss:032", ".source"},
	{regexp.MustCompile(`\(!(\[\]|!\[\])\)|(\+\{\}|\+\[\])`), 4, "owasp:xss:033", ""},
	{regexp.MustCompile(`\+A[A-Za-z0-9]{1,3}[-+]`), 3, "owasp:xss:034", ""},
	{regexp.MustCompile(`\bconstructor\s*\.\s*prototype\s*\[`), 4, "owasp:xss:035", "constructor"},
	{regexp.MustCompile(`<param\b[^>]*\bname\s*=\s*['"]?\s*(url|src|data|code|movie|allowscriptaccess)\b`), 4, "owasp:xss:036", "<param"},
	{regexp.MustCompile(`<(body|table|thead|tbody|tr|td|th|input)\b[^>]*\bbackground\s*=`), 3, "owasp:xss:037", "background"},
	{regexp.MustCompile(`<base\b[^>]*\btarget\s*=\s*['"]\s*[^'"]*\(.*\)`), 4, "owasp:xss:038", "<base"},
	{regexp.MustCompile(`<meta\b[^>]*\bhttp-equiv\s*=\s*['"]?(refresh|content-type|set-cookie)\b`), 4, "owasp:xss:039", "<meta"},
	{regexp.MustCompile(`<embed\b[^>]*\bcode\s*=`), 4, "owasp:xss:040", "<embed"},
	{regexp.MustCompile(`<use\b[^>]*(href|xlink:href)\s*=`), 4, "owasp:xss:041", "<use"},
	{regexp.MustCompile(`<(animate|set|animatetransform)\b[^>]*(xlink:href|href)\s*=`), 3, "owasp:xss:042", "href"},
	{regexp.MustCompile(`\bonafterscriptexecute\s*=`), 4, "owasp:xss:043", "onafterscriptexecute"},
	{regexp.MustCompile(`document\s*\[\s*['"\x60]\s*(cookie|location|domain|write|body|title|url)\b`), 4, "owasp:xss:044", "document"},
	{regexp.MustCompile(`\b(alert|confirm|prompt)\s*\(\s*[\d'"` + "`" + `]`), 5, "owasp:xss:045", "("},
	{regexp.MustCompile(`\bconstructor\s*\.\s*constructor\s*\(`), 5, "owasp:xss:046", "constructor"},
	{regexp.MustCompile(`<a\b[^>]*\bdownload\s*=`), 3, "owasp:xss:047", "download"},
	{regexp.MustCompile(`\[\s*/\w+/\s*\.\s*source\s*\+\s*/\w+/\s*\.\s*source\s*\]`), 5, "owasp:xss:048", ".source"},
	{regexp.MustCompile(`\b(eval|function)\s*\(\s*atob\s*\(`), 5, "owasp:xss:049", "atob"},
	{regexp.MustCompile(`<\w+:\s*script\b`), 5, "owasp:xss:050", "script"},
	{regexp.MustCompile(`data\s*:\s*image/svg\+xml`), 4, "owasp:xss:051", "image/svg"},
	{regexp.MustCompile(`\b(window|self|top|parent|frames|globalthis|this)\s*\[\s*[\(/!+\[]`), 4, "owasp:xss:052", "["},
	{regexp.MustCompile(`\.constructor\s*\.\s*prototype\s*\.\s*\w+\s*=`), 5, "owasp:xss:053", ".constructor"},
	{regexp.MustCompile("\\b(alert|prompt|confirm)\\s*(?:\\.\\s*(?:call|apply)\\s*\\(|\\)\\s*\\([\\d'\"`])"), 5, "owasp:xss:067", ""},
	// 模板字符串型直连调用：prompt`1`（原生反引号实参调用弹窗函数，
	// 无括号无点，绕过 xss:045/067 两分支）。
	{regexp.MustCompile("(?i)\\b(alert|prompt|confirm)\\s*`[^`]*`"), 5, "owasp:xss:069", ""},
	// 可选链直连调用：alert?.(document?.cookie)（ES2020 optional chaining
	// 调用形态，无括号直连被 ?. 阻断，绕过 xss:045/067/069）。
	{regexp.MustCompile(`\b(alert|prompt|confirm)\s*\?\.\s*\(`), 5, "owasp:xss:070", ""},
	{regexp.MustCompile(`<a\b[^>]*\bdownload\s*=\s*['"]?\s*\w+\.\w{2,5}\b`), 4, "owasp:xss:055", "download"},
	{regexp.MustCompile(`j\s*a\s*v\s*a\s+s\s*c\s*r\s*i\s*p\s*t\s*:`), 5, "owasp:xss:056", ""},
	{regexp.MustCompile(`<(body|table|thead|td|th|tr)\b[^>]*\bbackground\s*=\s*['"]?\s*(//|https?:)`), 4, "owasp:xss:057", "background"},
	// DOM Clobbering：通过 name/id 属性覆写 DOM 属性
	{regexp.MustCompile(`<(form|input|img|a|embed|object)\b[^>]*\b(name|id)\s*=\s*['"]?(document|window|location|navigator|top|self|frames)\b`), 5, "owasp:xss:058", "<"},
	// 通过 document 具名访问实施 DOM Clobbering
	{regexp.MustCompile(`<(a|area)\b[^>]*\bname\s*=\s*['"]?__proto__`), 5, "owasp:xss:059", "__proto__"},
	// mXSS 变异：noscript/noembed/noframes 内容被重新解释
	{regexp.MustCompile(`<(noscript|noembed|noframes)\b[^>]*>.*?<(script|img|svg|iframe)\b`), 5, "owasp:xss:060", "<no"},
	// math/svg 命名空间混淆导致的 mXSS
	{regexp.MustCompile(`<(math|svg)\b[^>]*>.*?<(style|mglyph|malignmark)\b`), 5, "owasp:xss:061", "<"},
	// SVG foreignObject：在 SVG 上下文内嵌 HTML
	{regexp.MustCompile(`<svg\b[^>]*>.*?<foreignobject\b`), 5, "owasp:xss:062", "foreignobject"},
	// SVG 动画事件处理器
	{regexp.MustCompile(`<(animate|animatetransform|set)\b[^>]*\bon(begin|end|repeat)\s*=`), 5, "owasp:xss:063", "on"},
	// 命名空间混淆：在 SVG 中用 xlink:href 执行 JS
	{regexp.MustCompile(`xlink:href\s*=\s*['"]?\s*javascript:`), 5, "owasp:xss:064", "xlink:href"},
	// 通过被 clobber 的属性绕过 DOMPurify
	{regexp.MustCompile(`<[^>]+(sanitize|purify|dompurify)[^>]*>`), 3, "owasp:xss:065", "<"},
	// 模板字面量 XSS：反引号字符串内的 ${...}
	{regexp.MustCompile("`[^`]*\\$\\{[^}]*(document|window|location|cookie|alert|fetch|eval)[^}]*\\}[^`]*`"), 5, "owasp:xss:066", "${"},
}

func checkXSS(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !hasXSSIndicator(s, gate) {
		return OWASPHit{}, false
	}
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range xssPatterns {
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
				return OWASPHit{Category: CatXSS, RuleID: id, Score: total, Desc: "XSS 特征"}, true
			}
		}
	}
	return OWASPHit{}, false
}

const (
	sfQ uint32 = 1 << iota // '\'' 或 '"'：hasSQLBooleanQuotedComparison / hasSQLBooleanEmptyQuotedComparison
	sfF                    // 'f'：hasSQLiIfFunctionPattern（字面量 if）
	sfH                    // 'h'：hasSQLiFunctionCallPattern("chr")
	sfN                    // 'n'：hasSQLiFunctionCallPattern("unhex")
	sfO                    // 'o'：hasSQLiFunctionCallPattern("conv")
)

var sqlifeatMaskTable = buildIndicatorMaskTable(map[string]uint32{
	"'": sfQ, `"`: sfQ,
	"f": sfF, "h": sfH, "n": sfN, "o": sfO,
})

type sqliPatternSignals struct {
	containsSelect          bool
	containsSemicolon       bool
	containsComment         bool
	containsOr              bool
	containsAnd             bool
	containsSleep           bool
	containsBenchmark       bool
	containsWaitfor         bool
	containsPGSleep         bool
	containsChr             bool
	containsInformation     bool
	containsSysobjects      bool
	containsSysDot          bool
	containsOutfile         bool
	containsDumpfile        bool
	containsLoadFile        bool
	containsInto            bool
	containsAtAt            bool
	containsExtractvalue    bool
	containsUpdatexml       bool
	containsCase            bool
	containsWhen            bool
	containsOrder           bool
	containsSubstr          bool
	containsSubstring       bool
	containsMid             bool
	containsXP              bool
	containsProcedure       bool
	containsUTL             bool
	containsDBMS            bool
	containsHaving          bool
	containsLike            bool
	containsLimit           bool
	containsOffset          bool
	containsGroup           bool
	containsCopy            bool
	containsProgram         bool
	containsUTLInaddr       bool
	containsMaster          bool
	containsFullwidthS      bool
	containsDoubleURLEncode bool
}

func collectSQLiPatternSignals(normalized string, gate ...*scanGate) sqliPatternSignals {
	if normalized == "" {
		return sqliPatternSignals{}
	}
	hits := firstGate(normalized, gate).hits
	hit := func(i int) bool { return hits.Intersects(&sqliSignalMasks[i]) }
	return sqliPatternSignals{
		containsSelect:          hit(sqliSigSelect),
		containsSemicolon:       hit(sqliSigSemicolon),
		containsComment:         hit(sqliSigComment),
		containsOr:              hit(sqliSigOr),
		containsAnd:             hit(sqliSigAnd),
		containsSleep:           hit(sqliSigSleep),
		containsBenchmark:       hit(sqliSigBenchmark),
		containsWaitfor:         hit(sqliSigWaitfor),
		containsPGSleep:         hit(sqliSigPGSleep),
		containsChr:             hit(sqliSigChr),
		containsInformation:     hit(sqliSigInformation),
		containsSysobjects:      hit(sqliSigSysobjects),
		containsSysDot:          hit(sqliSigSysDot),
		containsOutfile:         hit(sqliSigOutfile),
		containsDumpfile:        hit(sqliSigDumpfile),
		containsLoadFile:        hit(sqliSigLoadFile),
		containsInto:            hit(sqliSigInto),
		containsAtAt:            hit(sqliSigAtAt),
		containsExtractvalue:    hit(sqliSigExtractvalue),
		containsUpdatexml:       hit(sqliSigUpdatexml),
		containsCase:            hit(sqliSigCase),
		containsWhen:            hit(sqliSigWhen),
		containsOrder:           hit(sqliSigOrder),
		containsSubstr:          hit(sqliSigSubstr),
		containsSubstring:       hit(sqliSigSubstring),
		containsMid:             hit(sqliSigMid),
		containsXP:              hit(sqliSigXP),
		containsProcedure:       hit(sqliSigProcedure),
		containsUTL:             hit(sqliSigUTL),
		containsDBMS:            hit(sqliSigDBMS),
		containsHaving:          hit(sqliSigHaving),
		containsLike:            hit(sqliSigLike),
		containsLimit:           hit(sqliSigLimit),
		containsOffset:          hit(sqliSigOffset),
		containsGroup:           hit(sqliSigGroup),
		containsCopy:            hit(sqliSigCopy),
		containsProgram:         hit(sqliSigProgram),
		containsUTLInaddr:       hit(sqliSigUTLInaddr),
		containsMaster:          hit(sqliSigMaster),
		containsFullwidthS:      hit(sqliSigFullwidthS),
		containsDoubleURLEncode: hit(sqliSigDoubleURLEncode),
	}
}

// SQLi 信号在统合自动机中的位索引。
//
// 每个字段的判定项曾经是若干 strings.Contains，实测占 OWASP 扫描 CPU 的
// 4% 以上：同一个目标串被重复扫描 41 次。把全部判定项并入统合自动机后，
// 判定退化为对已有位集合的查询，代价与目标串长度无关。
const (
	sqliSigSelect = iota
	sqliSigSemicolon
	sqliSigComment
	sqliSigOr
	sqliSigAnd
	sqliSigSleep
	sqliSigBenchmark
	sqliSigWaitfor
	sqliSigPGSleep
	sqliSigChr
	sqliSigInformation
	sqliSigSysobjects
	sqliSigSysDot
	sqliSigOutfile
	sqliSigDumpfile
	sqliSigLoadFile
	sqliSigInto
	sqliSigAtAt
	sqliSigExtractvalue
	sqliSigUpdatexml
	sqliSigCase
	sqliSigWhen
	sqliSigOrder
	sqliSigSubstr
	sqliSigSubstring
	sqliSigMid
	sqliSigXP
	sqliSigProcedure
	sqliSigUTL
	sqliSigDBMS
	sqliSigHaving
	sqliSigLike
	sqliSigLimit
	sqliSigOffset
	sqliSigGroup
	sqliSigCopy
	sqliSigProgram
	sqliSigUTLInaddr
	sqliSigMaster
	sqliSigFullwidthS
	sqliSigDoubleURLEncode
	sqliSigCount
)

// sqliSignalLiterals 按上面的位索引列出各字段判定所需的字面量。
// 数组长度必须等于 sqliSigCount，由 scanGateInit 逐项建位集合。
var sqliSignalLiterals = [...][]string{
	sqliSigSelect:          {"select"},
	sqliSigSemicolon:       {";"},
	sqliSigComment:         {"--", "/*", "/*!"},
	sqliSigOr:              {"or"},
	sqliSigAnd:             {"and"},
	sqliSigSleep:           {"sleep"},
	sqliSigBenchmark:       {"benchmark"},
	sqliSigWaitfor:         {"waitfor"},
	sqliSigPGSleep:         {"pg_sleep"},
	sqliSigChr:             {"chr"},
	sqliSigInformation:     {"information_schema"},
	sqliSigSysobjects:      {"sysobjects"},
	sqliSigSysDot:          {"sys."},
	sqliSigOutfile:         {"outfile"},
	sqliSigDumpfile:        {"dumpfile"},
	sqliSigLoadFile:        {"load_file"},
	sqliSigInto:            {"into"},
	sqliSigAtAt:            {"@@"},
	sqliSigExtractvalue:    {"extractvalue"},
	sqliSigUpdatexml:       {"updatexml"},
	sqliSigCase:            {"case"},
	sqliSigWhen:            {"when"},
	sqliSigOrder:           {"order"},
	sqliSigSubstr:          {"substr"},
	sqliSigSubstring:       {"substring"},
	sqliSigMid:             {"mid"},
	sqliSigXP:              {"xp_"},
	sqliSigProcedure:       {"procedure"},
	sqliSigUTL:             {"utl_"},
	sqliSigDBMS:            {"dbms_"},
	sqliSigHaving:          {"having"},
	sqliSigLike:            {"like"},
	sqliSigLimit:           {"limit"},
	sqliSigOffset:          {"offset"},
	sqliSigGroup:           {"group"},
	sqliSigCopy:            {"copy"},
	sqliSigProgram:         {"program"},
	sqliSigUTLInaddr:       {"utl_inaddr"},
	sqliSigMaster:          {"master"},
	sqliSigFullwidthS:      {"\xef\xbd\x93", "\xef\xbc\xb3"},
	sqliSigDoubleURLEncode: {"%25"},
}

// sqliSignalMasks[i] 是第 i 个信号对应字面量的位集合，由 scanGateInit 填充。
var sqliSignalMasks [sqliSigCount]ac.Mask

// SQLi 快捷规则的字面量位集合，由 scanGateInit 填充。
var (
	sqliUnionSelectBits       ac.Mask // sqli:001：unionselect（归一化后无空格形态）
	sqliTautologyShortcutBits ac.Mask // sqli:010：and1=1 / or1=1
)

func hasHighByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0xE0 {
			return true
		}
	}
	return false
}

func shouldScanSQLiPatternWithSignals(normalized string, p owaspPattern, signals sqliPatternSignals, gate *scanGate) bool {
	if gate == nil {
		gate = scanGateOf(normalized)
	}
	if !gate.hintPass(p, normalized) {
		return false
	}
	switch p.id {
	case "owasp:sqli:002":
		return (signals.containsOr || signals.containsAnd) && strings.Contains(normalized, "'")
	case "owasp:sqli:003":
		return (signals.containsSleep || signals.containsBenchmark || signals.containsWaitfor || signals.containsPGSleep) && strings.Contains(normalized, "(")
	case "owasp:sqli:004":
		return signals.containsSemicolon && (strings.Contains(normalized, "select") || strings.Contains(normalized, "drop") || strings.Contains(normalized, "alter") || strings.Contains(normalized, "create") || strings.Contains(normalized, "truncate") || strings.Contains(normalized, "delete") || strings.Contains(normalized, "update") || strings.Contains(normalized, "insert"))
	case "owasp:sqli:005":
		return signals.containsComment && strings.ContainsAny(normalized, "'\"0123456789")
	case "owasp:sqli:006":
		return signals.containsSemicolon && strings.Contains(normalized, "'")
	case "owasp:sqli:007":
		if !hasSQLiFunctionByteHint(normalized, sfH|sfN|sfO) {
			return false
		}
		return hasSQLiFunctionCallPattern(normalized, "chr") ||
			hasSQLiFunctionCallPattern(normalized, "unhex") ||
			hasSQLiFunctionCallPattern(normalized, "conv")
	case "owasp:sqli:008":
		return hasSQLiHexLiteralPattern(normalized)
	case "owasp:sqli:009":
		return signals.containsInformation || signals.containsSysobjects || signals.containsSysDot
	case "owasp:sqli:010":
		// 布尔比较检测逐字节扫描目标串；目标不含 or/and 时不可能命中。
		if !signals.containsOr && !signals.containsAnd {
			return false
		}
		return gate.sqlBooleanNumeric(normalized)
	case "owasp:sqli:011":
		if !hasSQLiFunctionByteHint(normalized, sfQ) || (!signals.containsOr && !signals.containsAnd) {
			return false
		}
		return gate.sqlBooleanQuoted(normalized)
	case "owasp:sqli:036":
		if !hasSQLiFunctionByteHint(normalized, sfQ) || (!signals.containsOr && !signals.containsAnd) {
			return false
		}
		return gate.sqlBooleanEmptyQuoted(normalized)
	case "owasp:sqli:039":
		return (signals.containsOr || signals.containsAnd) && signals.containsSelect && strings.Contains(normalized, "(")
	case "owasp:sqli:012":
		return signals.containsSemicolon && strings.Contains(normalized, "--")
	case "owasp:sqli:013", "owasp:sqli:017":
		return signals.containsOutfile || signals.containsDumpfile || signals.containsLoadFile || signals.containsInto
	case "owasp:sqli:014":
		return signals.containsAtAt
	case "owasp:sqli:015":
		return (signals.containsExtractvalue || signals.containsUpdatexml) && strings.Contains(normalized, "(")
	case "owasp:sqli:018", "owasp:sqli:040":
		return signals.containsCase && signals.containsWhen
	case "owasp:sqli:019":
		return signals.containsOrder
	case "owasp:sqli:021":
		return (signals.containsSubstr || signals.containsSubstring || signals.containsMid) && strings.Contains(normalized, "(")
	case "owasp:sqli:022":
		if !hasSQLiFunctionByteHint(normalized, sfF) {
			return false
		}
		return hasSQLiIfFunctionPattern(normalized)
	case "owasp:sqli:023":
		return strings.Contains(normalized, "'") && (strings.ContainsAny(normalized, "^&") || strings.Contains(normalized, "<<") || strings.Contains(normalized, ">>"))
	case "owasp:sqli:024", "owasp:sqli:045":
		return signals.containsXP
	case "owasp:sqli:025":
		return signals.containsProcedure
	case "owasp:sqli:026":
		return signals.containsUTL || signals.containsDBMS
	case "owasp:sqli:027":
		return signals.containsHaving
	case "owasp:sqli:028", "owasp:sqli:031", "owasp:sqli:038", "owasp:sqli:041", "owasp:sqli:046", "owasp:sqli:047":
		return signals.containsSelect
	case "owasp:sqli:029":
		return signals.containsLike && strings.Contains(normalized, "'")
	case "owasp:sqli:030", "owasp:sqli:033":
		return signals.containsLimit || signals.containsOffset
	case "owasp:sqli:032":
		return signals.containsGroup && strings.Contains(normalized, "by")
	case "owasp:sqli:034":
		return signals.containsSemicolon && strings.Contains(normalized, "exec")
	case "owasp:sqli:035":
		return signals.containsWaitfor
	case "owasp:sqli:037":
		return signals.containsCopy || signals.containsProgram
	case "owasp:sqli:043":
		return signals.containsChr && strings.Count(normalized, "chr") >= 2 && (strings.Contains(normalized, "+") || strings.Contains(normalized, "||"))
	case "owasp:sqli:044":
		return signals.containsUTLInaddr
	case "owasp:sqli:048":
		return signals.containsMaster
	case "owasp:sqli:049", "owasp:sqli:053":
		if !hasHighByte(normalized) {
			return false
		}
		return signals.containsFullwidthS
	case "owasp:sqli:050", "owasp:sqli:051", "owasp:sqli:052":
		return signals.containsComment
	case "owasp:sqli:054":
		return signals.containsDoubleURLEncode
	default:
		return true
	}
}

func hasSQLiIfFunctionPattern(normalized string) bool {
	search := 0
	for search < len(normalized) {
		idx := strings.Index(normalized[search:], "if")
		if idx < 0 {
			return false
		}
		start := search + idx
		if !hasSQLWordAt(normalized, start, "if") {
			search = start + 1
			continue
		}
		pos := skipSQLSpaces(normalized, start+len("if"))
		if pos >= len(normalized) || normalized[pos] != '(' {
			search = start + 1
			continue
		}
		pos = skipSQLSpaces(normalized, pos+1)
		if hasSQLWordAt(normalized, pos, "select") ||
			hasSQLWordAt(normalized, pos, "ord") ||
			hasSQLWordAt(normalized, pos, "ascii") ||
			hasSQLWordAt(normalized, pos, "substr") ||
			hasSQLWordAt(normalized, pos, "length") ||
			hasSQLWordAt(normalized, pos, "count") ||
			hasSQLWordAt(normalized, pos, "version") {
			return true
		}
		search = start + 1
	}
	return false
}

func hasSQLiFunctionByteHint(normalized string, need uint32) bool {
	if normalized == "" {
		return false
	}
	if need == 0 {
		return true
	}
	bm := scanIndicatorMask(normalized, &sqlifeatMaskTable)
	return bm&need != 0
}

func hasSQLiFunctionCallPattern(normalized, name string) bool {
	search := 0
	for search < len(normalized) {
		idx := strings.Index(normalized[search:], name)
		if idx < 0 {
			return false
		}
		pos := search + idx + len(name)
		for pos < len(normalized) && isSQLiRegexpSpaceByte(normalized[pos]) {
			pos++
		}
		if pos < len(normalized) && normalized[pos] == '(' {
			return true
		}
		search += idx + 1
	}
	return false
}

func hasSQLiHexLiteralPattern(normalized string) bool {
	for i := 0; i < len(normalized); i++ {
		switch normalized[i] {
		case ',', '=', '(':
			pos := i + 1
			for pos < len(normalized) && isSQLiRegexpSpaceByte(normalized[pos]) {
				pos++
			}
			if pos+6 > len(normalized) || normalized[pos] != '0' || normalized[pos+1] != 'x' {
				continue
			}
			hexStart := pos + 2
			hexEnd := hexStart
			for hexEnd < len(normalized) && isLowerSQLHexByte(normalized[hexEnd]) {
				hexEnd++
			}
			if hexEnd-hexStart >= 4 {
				return true
			}
		}
	}
	return false
}

func isSQLiRegexpSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\f' || b == '\r'
}

func isLowerSQLHexByte(b byte) bool {
	return isASCIIDigitByte(b) || (b >= 'a' && b <= 'f')
}

func hasSQLBooleanNumericComparison(s string) bool {
	for i := 0; i < len(s); i++ {
		end, ok := sqlBooleanOperatorEndAt(s, i)
		if !ok {
			continue
		}
		j := skipSQLSpaces(s, end)
		if j >= len(s) || !isASCIIDigitByte(s[j]) {
			continue
		}
		for j < len(s) && isASCIIDigitByte(s[j]) {
			j++
		}
		j = skipSQLSpaces(s, j)
		if j >= len(s) || s[j] != '=' {
			continue
		}
		j = skipSQLSpaces(s, j+1)
		if j < len(s) && isASCIIDigitByte(s[j]) {
			return true
		}
	}
	return false
}

// hasSQLTautologyInjectionContext 判断「布尔关键字 + 数值等式」是否处在注入
// 语法位置，用于 sqli:010 的误报抑制。命中任一形态即视为注入上下文：
//
//  1. 布尔关键字与左操作数之间无空白（and1=1）——SQL 词法允许该紧贴形态，
//     散文不会把关键字粘到数字前。
//  2. 等式位于目标末尾——参数值整体即注入内容。
//  3. 等式后继字符是语句/操作数边界（& ; ' " / \ | = # 等）——参数分隔、
//     引号闭合或注释起始。
//  4. 等式后空白之后紧跟 SQL 语法词（select/union/and/… 或 -- # /* 注释符）
//     ——后续子句延续，散文里空白后接的是普通单词。
//
// 背离条件：散文若把等式紧贴标点（如 "(and 1=1)" 这类括号引用）会被判为
// 注入上下文，从而保留命中——这是有意保留的保守侧，避免为语言习惯放宽而
// 放过 "id=1 and 1=1)/*" 这类括号闭合注入。
func hasSQLTautologyInjectionContext(lower string) bool {
	for _, m := range reTautologyInjection.FindAllStringIndex(lower, -1) {
		start, end := m[0], m[1]
		opLen := len("and")
		if strings.HasPrefix(lower[start:], "or") {
			opLen = len("or")
		}
		// 1) 关键字紧贴左操作数：and1=1。
		if start+opLen < end {
			if c := lower[start+opLen]; c != ' ' && c != '\t' {
				return true
			}
		}
		// 2) 等式位于目标末尾。
		if end >= len(lower) {
			return true
		}
		// 3) 后继为语句/操作数边界字符。
		if isSQLTautologyBoundaryByte(lower[end]) {
			return true
		}
		// 4) 空白之后紧跟 SQL 语法词或注释符。
		if lower[end] == ' ' || lower[end] == '\t' {
			j := end
			for j < len(lower) && (lower[j] == ' ' || lower[j] == '\t') {
				j++
			}
			if j >= len(lower) || hasSQLGrammarAt(lower, j) {
				return true
			}
		}
	}
	return false
}

// reTautologyInjection 是 sqli:010 规则正则的等价形态，用于定位恒等式位置。
var reTautologyInjection = regexp.MustCompile(`\b(or|and)\s*\d+\s*=\s*\d+`)

// isSQLTautologyBoundaryByte 判断字节是否为 SQL 语句/操作数边界：
// 参数分隔、引号闭合、注释起始、括号或运算符号。
func isSQLTautologyBoundaryByte(b byte) bool {
	switch b {
	case '&', ';', '\'', '"', '`', '/', '\\', '|', '=', '#', '-', '*', '%',
		'<', '>', '{', '}', '[', ']', ':', '!', '?', '@', '$', '^', '~', '+', '(', ')':
		return true
	}
	return false
}

// sqlGrammarWords 是恒等式后续位置的 SQL 语法词与注释起始符。
// 空白后紧跟其中任一项即说明等式仍在 SQL 语句内部。
var sqlGrammarWords = [...]string{
	"select", "union", "from", "where", "having", "order", "group", "limit",
	"into", "values", "and", "or", "not", "sleep", "benchmark", "waitfor",
	"insert", "update", "delete", "drop", "exec", "declare", "case", "when",
	"then", "else", "end", "like", "in", "between", "exists", "all", "any",
	"distinct", "as", "join", "on", "set", "table", "database",
	"information_schema", "--", "#", "/*",
}

// hasSQLGrammarAt 判断 s[i:] 是否以 SQL 语法词或注释起始符开头（词尾需为
// 非词字节，注释符与 # 除外）。
func hasSQLGrammarAt(s string, i int) bool {
	for _, kw := range sqlGrammarWords {
		if !strings.HasPrefix(s[i:], kw) {
			continue
		}
		j := i + len(kw)
		if j >= len(s) || !isSQLWordByte(s[j]) {
			return true
		}
	}
	return false
}

func hasSQLBooleanQuotedComparison(s string) bool {
	for i := 0; i < len(s); i++ {
		end, ok := sqlBooleanOperatorEndAt(s, i)
		if !ok || end >= len(s) {
			continue
		}
		j := skipSQLSpaces(s, end)
		if j == end {
			// 无空格紧贴形态：or"1"="1"（注释剥离 / 编码解码产物）。
			// 引号紧跟布尔运算符且随后构成引号比较时视为注入；
			// 自然文本不会拼出 or"word"= 的引号比较结构。
			if s[j] != '\'' && s[j] != '"' {
				continue
			}
		}
		next, ok := scanSQLQuotedWord(s, j)
		if !ok {
			continue
		}
		j = skipSQLSpaces(s, next)
		if j >= len(s) || s[j] != '=' {
			continue
		}
		j = skipSQLSpaces(s, j+1)
		if _, ok := scanSQLQuotedWord(s, j); ok {
			return true
		}
	}
	return false
}

func hasSQLBooleanEmptyQuotedComparison(s string) bool {
	for i := 0; i < len(s); i++ {
		end, ok := sqlBooleanOperatorEndAt(s, i)
		if !ok || end >= len(s) {
			continue
		}
		j := skipSQLSpaces(s, end)
		if j == end || j+1 >= len(s) || !isSQLQuoteByte(s[j]) || !isSQLQuoteByte(s[j+1]) {
			continue
		}
		j = skipSQLSpaces(s, j+2)
		if j >= len(s) || s[j] != '=' {
			continue
		}
		j = skipSQLSpaces(s, j+1)
		if j < len(s) && isSQLQuoteByte(s[j]) {
			return true
		}
	}
	return false
}

func sqlBooleanOperatorEndAt(s string, i int) (int, bool) {
	if i > 0 && isSQLWordByte(s[i-1]) {
		return 0, false
	}
	// 用字节比较替代小切片字符串比较：该函数在三个布尔比较检测中
	// 对目标串每一字节调用一次，是 SQLi 侧的主要 flat 热点。
	if i+2 <= len(s) && s[i] == 'o' && s[i+1] == 'r' {
		return i + 2, true
	}
	if i+3 <= len(s) && s[i] == 'a' && s[i+1] == 'n' && s[i+2] == 'd' {
		return i + 3, true
	}
	return 0, false
}

func scanSQLQuotedWord(s string, i int) (int, bool) {
	if i >= len(s) || !isSQLQuoteByte(s[i]) {
		return 0, false
	}
	i++
	for i < len(s) && isSQLWordByte(s[i]) {
		i++
	}
	if i >= len(s) || !isSQLQuoteByte(s[i]) {
		return 0, false
	}
	return i + 1, true
}

func isSQLQuoteByte(b byte) bool {
	return b == '\'' || b == '"'
}

func isASCIIDigitByte(b byte) bool {
	return b >= '0' && b <= '9'
}

// sqlBooleanComparisonKinds 一次遍历同时判定三类布尔比较。
//
// 三类判定互不依赖：对每个 or/and 位置分别计算各自结论，因此返回值与
// hasSQLBooleanNumericComparison / hasSQLBooleanQuotedComparison /
// hasSQLBooleanEmptyQuotedComparison 分别调用完全一致；这三个函数保留为
// 黄金参照，由 sqlisignals_equiv_test.go 逐输入对拍。
//
// @param s 归一化目标串。
// @return numeric 数值比较、quoted 引号比较、emptyQuoted 空引号比较。
func sqlBooleanComparisonKinds(s string) (numeric, quoted, emptyQuoted bool) {
	for i := 0; i < len(s); i++ {
		end, ok := sqlBooleanOperatorEndAt(s, i)
		if !ok {
			continue
		}
		if !numeric {
			j := skipSQLSpaces(s, end)
			if j < len(s) && isASCIIDigitByte(s[j]) {
				for j < len(s) && isASCIIDigitByte(s[j]) {
					j++
				}
				j = skipSQLSpaces(s, j)
				if j < len(s) && s[j] == '=' {
					j = skipSQLSpaces(s, j+1)
					if j < len(s) && isASCIIDigitByte(s[j]) {
						numeric = true
					}
				}
			}
		}
		if (!quoted || !emptyQuoted) && end < len(s) {
			j := skipSQLSpaces(s, end)
			if !quoted {
				// 无空格紧贴形态要求紧跟引号；自然文本不会拼出
				// or"word"= 的引号比较结构。
				if j != end || isSQLQuoteByte(s[j]) {
					if next, ok := scanSQLQuotedWord(s, j); ok {
						k := skipSQLSpaces(s, next)
						if k < len(s) && s[k] == '=' {
							k = skipSQLSpaces(s, k+1)
							if _, ok := scanSQLQuotedWord(s, k); ok {
								quoted = true
							}
						}
					}
				}
			}
			if !emptyQuoted && j != end && j+1 < len(s) &&
				isSQLQuoteByte(s[j]) && isSQLQuoteByte(s[j+1]) {
				k := skipSQLSpaces(s, j+2)
				if k < len(s) && s[k] == '=' {
					k = skipSQLSpaces(s, k+1)
					if k < len(s) && isSQLQuoteByte(s[k]) {
						emptyQuoted = true
					}
				}
			}
		}
		if numeric && quoted && emptyQuoted {
			return
		}
	}
	return
}

func nextSQLiHit(normalized string, threshold int) (OWASPHit, bool) {
	return nextSQLiHitWithAccept(normalized, threshold, nil, nil)
}

// nextSQLiHitWithAccept 在规则级过滤拒绝较早归因时继续扫描同一目标。
func nextSQLiHitWithAccept(normalized string, threshold int, accept func(OWASPHit) bool, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(normalized)
	}
	// 三条快捷规则的字面量已并入统合自动机，判定退化为位测试，
	// 避免对每个 SQLi 目标重复扫描目标串。
	if gate.hit(&sqliUnionSelectBits) {
		hit := OWASPHit{Category: CatSQLi, RuleID: "owasp:sqli:001", Score: 5, Desc: "SQL 注入特征"}
		if acceptsOWASPHit(accept, hit) {
			return hit, true
		}
	}
	if gate.hit(&sqliTautologyShortcutBits) {
		hit := OWASPHit{Category: CatSQLi, RuleID: "owasp:sqli:010", Score: 5, Desc: "SQL 注入特征"}
		if acceptsOWASPHit(accept, hit) {
			return hit, true
		}
	}
	if !hasSQLiIndicator(normalized, gate) {
		return OWASPHit{}, false
	}
	signals := collectSQLiPatternSignals(normalized, gate)
	if accept == nil {
		// 未配置规则过滤时沿用累计器的首次跨阈归因与零额外分配路径。
		var acc *score.Accumulator
		defer func() { releaseOWASPAcc(acc) }()
		for _, p := range sqliPatterns {
			if !shouldScanSQLiPatternWithSignals(normalized, p, signals, gate) || !gate.patternGateMustsOnly(p) || !gate.patternGateBitsOnly(p, normalized) {
				continue
			}
			if !p.re.MatchString(normalized) || isSQLiFalsePositive(normalized, p.id) {
				continue
			}
			if acc == nil {
				acc = acquireOWASPAcc(threshold)
			}
			acc.Add(p.id, p.score)
			if acc.Exceeded() {
				id, total := acc.Attribution()
				return OWASPHit{Category: CatSQLi, RuleID: id, Score: total, Desc: "SQL 注入特征"}, true
			}
		}
		return OWASPHit{}, false
	}

	// 配置过滤后的候选以当前匹配规则作为归因；被拒绝的候选仍贡献证据，
	// 使后续规则能在更完整的累计分上重新接受判定。
	total := 0
	for _, p := range sqliPatterns {
		if !shouldScanSQLiPatternWithSignals(normalized, p, signals, gate) || !gate.patternGateMustsOnly(p) || !gate.patternGateBitsOnly(p, normalized) {
			continue
		}
		if !p.re.MatchString(normalized) || isSQLiFalsePositive(normalized, p.id) {
			continue
		}
		total += p.score
		if total < threshold {
			continue
		}
		hit := OWASPHit{Category: CatSQLi, RuleID: p.id, Score: total, Desc: "SQL 注入特征"}
		if accept(hit) {
			return hit, true
		}
	}
	return OWASPHit{}, false
}

func shouldScanXSSPattern(normalized string, p owaspPattern, gate *scanGate) bool {
	if gate == nil {
		gate = scanGateOf(normalized)
	}
	if !gate.patternGate(p, normalized) {
		return false
	}
	switch p.id {
	case "owasp:xss:033":
		// 强锚形态才放行扫描：完整 JSFuck 链（(![]、!![]、构造函数），
		// 裸 +[]/+{} 不进入电池（二进制噪声碰撞面）。
		return strings.Contains(normalized, "(![]") || strings.Contains(normalized, "(!![]") ||
			(strings.Contains(normalized, "constructor") && (strings.Contains(normalized, "+{}") || strings.Contains(normalized, "+[]")))
	case "owasp:xss:052":
		// 正则要求「全局对象词 + [ + 表达式起始字符」，手写扫描比在
		// \b(window|self|...) 上逐位置回溯更便宜。
		return hasXSSWindowExprBracket(normalized)
	case "owasp:xss:067":
		if !strings.Contains(normalized, "(") ||
			!(strings.Contains(normalized, "alert") || strings.Contains(normalized, "prompt") || strings.Contains(normalized, "confirm")) {
			return false
		}
		// alert.call/confirm.apply 走 '.'；alert)(1 走 ')(' 直连形态；
		// (alert)(1) 走 '(' 前置包裹调用形态（IIFE 风格弹窗）。
		return strings.Contains(normalized, ".") ||
			strings.Contains(normalized, "alert)(") ||
			strings.Contains(normalized, "prompt)(") ||
			strings.Contains(normalized, "confirm)(") ||
			strings.Contains(normalized, "(alert)(") ||
			strings.Contains(normalized, "(prompt)(") ||
			strings.Contains(normalized, "(confirm)(")
	default:
		return true
	}
}

func isXSSSuppressedRule(normalized, ruleID string, threshold int) bool {
	if ruleID == "owasp:xss:002" && isXSSHandlerFunctionRef(normalized) {
		return true
	}
	if ruleID == "owasp:xss:001" || ruleID == "owasp:xss:014" {
		return isXSSFalsePositive(normalized, ruleID)
	}
	// 无执行语义的结构型抑制与档位无关：strict / very_high 档提升的是
	// 可疑构造的检出，不应把 javascript:void(0)、被动 iframe/svg、JSX
	// 演示代码这类本身无法执行的形态重新计入攻击。
	if isXSSStructuralFalsePositive(normalized, ruleID) {
		return true
	}
	return threshold > 2 && isXSSFalsePositive(normalized, ruleID)
}

func nextXSSHit(normalized string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(normalized)
	}
	if !hasXSSIndicator(normalized, gate) {
		return OWASPHit{}, false
	}
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range xssPatterns {
		if !shouldScanXSSPattern(normalized, p, gate) {
			continue
		}
		if !p.re.MatchString(normalized) {
			continue
		}
		if isXSSSuppressedRule(normalized, p.id, threshold) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatXSS, RuleID: id, Score: total, Desc: "XSS 特征"}, true
		}
	}
	return OWASPHit{}, false
}

func NormalizeForDebug(raw string) string { return normalizeWithDecode(raw) }
func IsOpaqueEncodedAttackBodyForDebug(raw, normalized string, headers map[string]string, threshold int) bool {
	return isOpaqueEncodedAttackBody(raw, normalized, headers, threshold)
}

func isOpaqueEncodedAttackBody(raw, normalized string, headers map[string]string, threshold int) bool {
	raw = strings.TrimSpace(raw)
	if threshold > 4 {
		return false
	}
	if len(raw) < 1024 || len(raw) > 8192 {
		return false
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") && strings.TrimSpace(v) != "" {
			return false
		}
	}
	if strings.ContainsAny(raw, " \r\n") {
		return false
	}
	compact := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(raw, "\r", ""), "\n", ""), " ", "")
	if len(compact) < 1024 || len(compact)%4 != 0 {
		return false
	}
	if !reBase64Token.MatchString(compact) {
		return false
	}
	plusSlash := strings.Count(compact, "+") + strings.Count(compact, "/")
	return plusSlash >= 16
}

var pathTravPatterns = []owaspPattern{
	{regexp.MustCompile(`(\.\./){2,}`), 4, "owasp:path_traversal:001", "../"},
	{regexp.MustCompile(`(etc/passwd|etc/shadow|win\.ini|boot\.ini)`), 5, "owasp:path_traversal:002", ""},
	{regexp.MustCompile(`%2e%2e[/\\]`), 4, "owasp:path_traversal:003", "%2e%2e"},
	{regexp.MustCompile(`\.\.[/\\]\.\.[/\\]`), 4, "owasp:path_traversal:004", ".."},
	{regexp.MustCompile(`\.\.;[/\\]`), 4, "owasp:path_traversal:005", "..;"},
	{regexp.MustCompile(`/proc/self/(environ|cmdline|fd|maps|status|exe|cwd|root)`), 5, "owasp:path_traversal:006", "/proc/self/"},
	{regexp.MustCompile(`\.\.(%00|\x00)`), 5, "owasp:path_traversal:007", ".."},
	{regexp.MustCompile(`\.\.[/\\].*(windows[/\\]system32|windows[/\\]win\.ini|cmd\.exe|system\.ini)`), 5, "owasp:path_traversal:008", ".."},
	{regexp.MustCompile(`\.{3,}[/\\]`), 4, "owasp:path_traversal:009", "..."},
	{regexp.MustCompile(`(^|[/\\])\.\.[/\\](etc[/\\](passwd|shadow|hosts|hostname|group)|proc[/\\]version|root[/\\]|var[/\\]log[/\\])`), 5, "owasp:path_traversal:010", ".."},
	{regexp.MustCompile(`(%252e|%252f|%255c){2,}`), 4, "owasp:path_traversal:011", "%25"},
	{regexp.MustCompile(`(\.\.\\){2,}`), 4, "owasp:path_traversal:012", ""},
	{regexp.MustCompile(`\.\.[/\\].*(web-inf|meta-inf|web\.xml|struts\.xml|applicationcontext\.xml)`), 5, "owasp:path_traversal:013", ".."},
	{regexp.MustCompile(`(web-inf|meta-inf)[/\\]web\.xml`), 5, "owasp:path_traversal:014", ""},
	{regexp.MustCompile(`\.\.[/\\]*(\.git[/\\]|\.env|\.htpasswd|\.aws[/\\]|\.ssh[/\\]|config\.php|settings\.py|\.ds_store)`), 4, "owasp:path_traversal:015", ".."},
	{regexp.MustCompile(`\.\.[/\\](admin|login|manager|console|config|passwd|shadow|private)`), 4, "owasp:path_traversal:016", ".."},
	{regexp.MustCompile(`(?:^|[/\\])\s*\.{3,}[ \t]*[/\\]`), 4, "owasp:path_traversal:017", "..."},
	{regexp.MustCompile(`\.\.\s+[/\\]`), 3, "owasp:path_traversal:018", ".."},
	// UNC 管理共享路径：\\host\c$、\\host\admin$ 等 Windows 管理共享访问。
	// 已有 c$ 门字面（hasPathTravIndicator/famPathTrav 同步），电池自锁
	// 反斜杠 + 盘符 + 美元符的强形态。
	{regexp.MustCompile(`\\\\[\w.:-]+\\(?:[a-zA-Z]|admin|ipc)\$`), 4, "owasp:path_traversal:019", "c$"},
	// 点段前缀绕过的 Java Web 配置访问（/.//WEB-INF、./WEB-INF）：
	// 用 /./ 或 .// 替代 ../ 规避上级目录规则，是目录规范化的经典绕过。
	// 全语料黑 17 / 白 0。
	{regexp.MustCompile(`(?:^|/)\./+web-inf`), 5, "owasp:path_traversal:020", "web-inf"},
}

func checkPathTraversal(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !gate.family(famPathTrav, s) {
		return OWASPHit{}, false
	}
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range pathTravPatterns {
		if !gate.patternGate(p, s) {
			continue
		}
		if !p.re.MatchString(s) {
			continue
		}
		if isPathTravFalsePositive(s, p.id) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatPathTrav, RuleID: id, Score: total, Desc: "路径遍历特征"}, true
		}
	}
	return OWASPHit{}, false
}
