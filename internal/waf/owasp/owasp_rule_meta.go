package owasp

// ruleMeta carries the human-readable metadata for one built-in detector rule.
type ruleMeta struct {
	name string
	desc string
}

// mergeRuleMeta merges the per-category metadata tables into the destination
// map. The category split only exists to keep each map literal readable; the
// lookup path is unchanged: registerPatternRules queries builtinRuleMeta only.
func mergeRuleMeta(dst map[string]ruleMeta, srcs ...map[string]ruleMeta) {
	for _, src := range srcs {
		for k, v := range src {
			dst[k] = v
		}
	}
}

// builtinRuleMeta 是内置检测规则中文元信息的唯一来源，键为检测器实际
// 发出的稳定 RuleID。registerPatternRules 直接读取本表填充
// DefaultOWASPRegistry 的 Name/Description，因此管理端规则目录展示的
// 名称与说明都来自这里，不存在第二份可漂移的映射。
//
// 若向任一 *Patterns 切片新增 pattern 而未在此登记，该规则会退化为
// 类别级描述 + 编号 + 分值的自动拼接；
// TestBuiltinRuleMetaCoversAllPatterns 会双向拦截缺失与失效条目。
//
// 本表底层按类别拆分为多个 xxxRuleMeta 字面量，运行时在此合并，
// 键查找路径保持不变。以下规则 ID 为硬编码发射点而非 patterns 切片
// 成员，其备注由 catalog.go 单独维护、不进入本表（deser:012 除外）：
// owasp:path:001-017（owasp.go:724-800）、owasp:upload:001-007
// （owasp_extended.go:730-802）、owasp:proto:001-010
// （owasp_extended.go:1107-1195）、owasp:crlf:005（owasp.go:234-239）。
// owasp:deser:012 虽在 owasp.go:311-318 有硬编码发射点，但它同时是
// deserialPatterns 切片成员（owasp_extended.go:1067），必须在此登记。
var builtinRuleMeta = func() map[string]ruleMeta {
	m := make(map[string]ruleMeta, 340)
	mergeRuleMeta(m,
		sqliRuleMeta,
		xssRuleMeta,
		webshellRuleMeta,
		revshellRuleMeta,
		cmdInjectRuleMeta,
		ssrfRuleMeta,
		xxeRuleMeta,
		ldapRuleMeta,
		nosqliRuleMeta,
		sstiRuleMeta,
		jndiRuleMeta,
		crlfRuleMeta,
		elRuleMeta,
		deserRuleMeta,
		graphqlRuleMeta,
		pathTravRuleMeta,
	)
	return m
}()

var sqliRuleMeta = map[string]ruleMeta{
	// SQL 注入
	"owasp:sqli:001": {"SQL UNION 联合查询注入", "使用 UNION SELECT 追加攻击者控制的返回结果集"},
	"owasp:sqli:002": {"SQL 引号布尔注入", "引号闭合后接 OR/AND 与数值型操作数的注入"},
	"owasp:sqli:003": {"SQL 时间型盲注", "使用 SLEEP、BENCHMARK、WAITFOR DELAY 或 PG_SLEEP 等延时函数"},
	"owasp:sqli:004": {"SQL 多语句堆叠注入", "分号后接 SELECT/DROP/ALTER/CREATE/TRUNCATE/DELETE/UPDATE/INSERT"},
	"owasp:sqli:005": {"SQL 注释截断", "字面量或数字后接行内或行注释以截断原始 SQL"},
	"owasp:sqli:006": {"SQL 引号分号注入", "引号闭合后接分号与新语句关键字的注入"},
	"owasp:sqli:007": {"SQL 字符编码函数", "使用 CHR、UNHEX 或 CONV 重组字符串绕过输入过滤"},
	"owasp:sqli:008": {"SQL 十六进制字面量载荷", "在操作符或参数位置出现的长十六进制字面量"},
	"owasp:sqli:009": {"SQL 元数据枚举", "访问 INFORMATION_SCHEMA、SYSOBJECTS 或 sys.*tables 元数据"},
	"owasp:sqli:010": {"SQL 数值恒等式", "OR/AND 与常量数值等式如 1=1"},
	"owasp:sqli:011": {"SQL 字符串恒等式", "OR/AND 与常量字符串等式如 'a'='a'"},
	"owasp:sqli:012": {"SQL 语句截断", "分号后紧接行注释截断 SQL 语句"},
	"owasp:sqli:013": {"SQL 文件读写函数", "通过 LOAD_FILE、OUTFILE 或 DUMPFILE 访问文件系统"},
	"owasp:sqli:014": {"SQL Server 变量探测", "通过 @@version、@@hostname、@@datadir 或 @@basedir 读取服务器信息"},
	"owasp:sqli:015": {"SQL XML 报错数据外带", "使用 EXTRACTVALUE 或 UPDATEXML 通过 XML 错误回显数据"},
	"owasp:sqli:016": {"SQL GROUP_CONCAT 数据汇聚", "使用 GROUP_CONCAT 将多行结果合并到单一返回字段"},
	"owasp:sqli:017": {"SQL INTO OUTFILE 数据外带", "使用 INTO OUTFILE 或 INTO DUMPFILE 将查询结果写入磁盘"},
	"owasp:sqli:018": {"SQL CASE WHEN 时间盲注", "CASE WHEN ... THEN 分支中嵌入延时函数"},
	"owasp:sqli:019": {"SQL ORDER BY 列探测", "ORDER BY 顺序字段后接注释或语句终止符"},
	"owasp:sqli:020": {"MySQL 版本注释注入", "使用 MySQL /*!...*/ 可执行注释包裹 SQL 关键字"},
	"owasp:sqli:021": {"SQL 子串提取", "使用 SUBSTR、SUBSTRING 或 MID 配合偏移与长度参数"},
	"owasp:sqli:022": {"SQL 条件型盲注", "IF() 的判断条件为 SELECT、ORD、ASCII、SUBSTR、LENGTH、COUNT 或 VERSION"},
	"owasp:sqli:023": {"SQL 位运算符注入", "在引号操作数间使用按位 XOR、AND 或移位运算"},
	"owasp:sqli:024": {"SQL Server 扩展存储过程滥用", "调用 xp_cmdshell、xp_regread、xp_regwrite 等 xp_ 系列过程"},
	"owasp:sqli:025": {"MySQL PROCEDURE ANALYSE 滥用", "使用 PROCEDURE ANALYSE 进行基于报错的数据提取"},
	"owasp:sqli:026": {"Oracle PL/SQL 包滥用", "调用 UTL_HTTP、UTL_FILE、DBMS_PIPE 或 DBMS_OUTPUT 等包"},
	"owasp:sqli:027": {"SQL HAVING 恒等式", "HAVING 子句中的常量数值等式"},
	"owasp:sqli:028": {"SQL 等值子查询注入", "数值与嵌套 SELECT 子查询的等值比较"},
	"owasp:sqli:029": {"SQL LIKE 通配符注入", "引号闭合后接 LIKE 通配符操作数"},
	"owasp:sqli:030": {"SQL LIMIT 子句注入", "LIMIT offset,count 后接注释或语句分隔符"},
	"owasp:sqli:031": {"SQL IN 子查询注入", "等值或 IN 操作符后接嵌套 SELECT"},
	"owasp:sqli:032": {"SQL GROUP BY 顺序注入", "GROUP BY 顺序字段列表后接注释或分隔符"},
	"owasp:sqli:033": {"PostgreSQL LIMIT OFFSET 注入", "LIMIT ... OFFSET 组合后接注释或分隔符"},
	"owasp:sqli:034": {"SQL Server EXEC 过程调用", "堆叠的 EXEC 调用 xp_、sp_ 或 master.. 系列过程"},
	"owasp:sqli:035": {"SQL Server WAITFOR DELAY 注入", "使用 WAITFOR DELAY 引号时间间隔进行时间型盲注"},
	"owasp:sqli:036": {"SQL 空字符串恒等式", "OR/AND 比较两个空字符串的恒等式"},
	"owasp:sqli:037": {"PostgreSQL COPY TO PROGRAM 命令执行", "COPY ... TO PROGRAM 通过数据库执行操作系统命令"},
	"owasp:sqli:038": {"SQL SELECT FROM 注入", "SELECT ... FROM 表后接注释、恒等式或 UNION"},
	"owasp:sqli:039": {"SQL 布尔子查询注入", "AND/OR 的操作数为括号包裹的 SELECT"},
	"owasp:sqli:040": {"SQL SELECT CASE WHEN 注入", "SELECT 投影中嵌入 CASE WHEN 条件分支"},
	"owasp:sqli:041": {"SQL CAST/CONVERT 注入", "SELECT 中使用 CAST 或 CONVERT 进行类型混淆数据提取"},
	"owasp:sqli:043": {"SQL CHR 拼接混淆", "链式 CHR() 调用拼接以重组字符串字面量"},
	"owasp:sqli:044": {"Oracle UTL_INADDR 带外通道", "使用 UTL_INADDR.GET_HOST_* 进行带外 DNS 数据外带"},
	"owasp:sqli:045": {"SQL Server xp_ 过程执行", "EXEC 或 EXECUTE 调用 xp_dirtree、xp_cmdshell、xp_regread、xp_fileexist 或 xp_subdirs"},
	"owasp:sqli:046": {"SQL 嵌套 SELECT 注入", "SELECT 后紧接括号包裹的嵌套 SELECT"},
	"owasp:sqli:047": {"SQL 通配符表转储", "SELECT * FROM 表用于完整表数据转储"},
	"owasp:sqli:048": {"SQL Server master 数据库访问", "通过 EXEC master.. 进入 master 数据库访问"},
	"owasp:sqli:049": {"SQL 全角字符绕过", "SQL 关键字前出现一段全角字符"},
	"owasp:sqli:050": {"SQL 嵌套注释混淆", "嵌套 /* */ 注释块用于拆分关键字"},
	"owasp:sqli:051": {"MySQL 条件注释注入", "MySQL /*!NNNNN 关键字*/ 五位数版本条件注释"},
	"owasp:sqli:052": {"MySQL 行内注释关键字", "MySQL /*! 注释 */ 包裹 UNION、SELECT、CONCAT 或 GROUP_CONCAT"},
	"owasp:sqli:053": {"SQL 全角 SELECT 关键字", "使用全角字符拼写 SELECT 以绕过关键字匹配"},
	"owasp:sqli:054": {"SQL 双重 URL 编码绕过", "双重编码的引号、分号或注释序列如 %2527"},
}

var xssRuleMeta = map[string]ruleMeta{
	// XSS 跨站脚本
	"owasp:xss:001": {"XSS - script 标签注入", "出现 <script> 标签起始标记，可直接执行脚本的经典向量"},
	"owasp:xss:002": {"XSS - 内联事件处理器", "HTML 属性位置绑定 onload/onclick/onerror 等大量内联事件处理器"},
	"owasp:xss:003": {"XSS - javascript 伪协议", "URL 位置出现 javascript: 伪协议可直接执行代码"},
	"owasp:xss:004": {"XSS - img src 空值触发 onerror", "<img> 源码置空后借 onerror 立即执行脚本的向量"},
	"owasp:xss:005": {"XSS - iframe 内嵌", "出现 <iframe> 标签起始标记，用于嵌入恶意页面"},
	"owasp:xss:006": {"XSS - document 敏感属性", "脚本直接引用 document.cookie、location 或 write 窃取/改写页面"},
	"owasp:xss:007": {"XSS - SVG 元素注入", "出现 <svg> 标签起始标记，SVG 上下文可承载脚本与事件"},
	"owasp:xss:008": {"XSS - MathML 元素注入", "出现 <math> 标签起始标记，math 命名空间可承载事件向量"},
	"owasp:xss:009": {"XSS - data 文本 HTML 载荷", "使用 data:text/html 数据 URI 嵌入完整 HTML 文档"},
	"owasp:xss:010": {"XSS - window 对象操纵", "脚本引用 window.location、name 或 open 改变导航行为"},
	"owasp:xss:011": {"XSS - 字符串动态执行", "eval/setTimeout/setInterval 首位参数以字符串开头，动态执行代码"},
	"owasp:xss:012": {"XSS - innerHTML 赋值", "对 innerHTML 赋值注入 HTML，常见 DOM 型 XSS 汇点"},
	"owasp:xss:013": {"XSS - HTML 实体编码 script", "实体编码的 < 或 &#60 开头后接 script，绕过输入过滤"},
	"owasp:xss:014": {"XSS - 标签属性内联事件", "任意 HTML 标签属性区内出现 on* 事件处理器绑定"},
	"owasp:xss:015": {"XSS - embed/object 外部资源", "<embed>/<object> 标签带 data 或 src 加载外部可控资源"},
	"owasp:xss:016": {"XSS - form action 伪协议", "<form> 的 action 指向 javascript: 伪协议执行代码"},
	"owasp:xss:017": {"XSS - fromCharCode 字符串混淆", "使用 String.fromCharCode 拼装字符串绕过过滤"},
	"owasp:xss:018": {"XSS - base href 伪协议", "<base> 的 href 指向 javascript: 伪协议篡改基准 URL"},
	"owasp:xss:019": {"XSS - fetch/XHR 跨域外带", "fetch 或 XMLHttpRequest 以 http(s) URL 将数据外带到远端"},
	"owasp:xss:020": {"XSS - vbscript 伪协议", "URL 位置出现 vbscript: 伪协议（旧版 IE 执行向量）"},
	"owasp:xss:021": {"XSS - expression 表达式调用", "expression() 中引用 document、window 或 eval（旧版 IE 向量）"},
	"owasp:xss:022": {"XSS - iframe srcdoc 注入", "iframe 的 srcdoc 属性承载内联 HTML 文档"},
	"owasp:xss:023": {"XSS - 模板原型链探测", "模板插值中访问 constructor、__proto__ 或 __defineGetter__"},
	"owasp:xss:024": {"XSS - document.write 调用", "脚本调用 document.write/writeln 将字符串写入文档"},
	"owasp:xss:025": {"XSS - location 跳转伪协议", "location.href、assign 或 window.open 指向 javascript: 伪协议"},
	"owasp:xss:026": {"XSS - details ontoggle 触发", "<details open> 配合 ontoggle 事件在展开时自动执行"},
	"owasp:xss:027": {"XSS - input autofocus 触发 onfocus", "<input autofocus> 配合 onfocus 事件在聚焦时自动执行"},
	"owasp:xss:028": {"XSS - link 标签导入资源", "<link rel=\"import\"> 加载外部 HTML 资源"},
	"owasp:xss:029": {"XSS - 元素 name 覆盖 DOM 属性", "img/input 等的 name 属性覆盖 document、body 等 DOM 引用（DOM Clobbering）"},
	"owasp:xss:030": {"XSS - 方括号属性访问", "window/self/top 等对象以方括号加字符串访问属性绕过过滤"},
	"owasp:xss:031": {"XSS - 方括号索引危险函数", "方括号中拼出 alert、eval、fetch 等敏感全局函数的名称"},
	"owasp:xss:032": {"XSS - 正则 source 提取", "从正则的字面量取 .source 拼装字符串回收过滤后的字符"},
	"owasp:xss:033": {"XSS - JSFuck 无字母混淆", "!([])/+{} 等 JSFuck 风格构造，不用字母数字拼出代码"},
	"owasp:xss:034": {"XSS - 代数运算混淆", "+A1- 形式的代数运算构造，JSFuck 式字符合成技巧"},
	"owasp:xss:035": {"XSS - constructor.prototype 索引", "constructor.prototype 加方括号访问原型链属性"},
	"owasp:xss:036": {"XSS - param 插件参数注入", "<param> 的 name 为 url、src、data、movie 等插件资源参数"},
	"owasp:xss:037": {"XSS - 元素 background 注入", "body/table/td 等元素的 background 属性引用外部资源"},
	"owasp:xss:038": {"XSS - base target 函数载荷", "<base> 的 target 属性值内带有括号调用的可疑载荷"},
	"owasp:xss:039": {"XSS - meta refresh 跳转注入", "<meta> 的 http-equiv 为 refresh、content-type 或 set-cookie"},
	"owasp:xss:040": {"XSS - embed code 参数注入", "<embed> 的 code 属性指向外部程序代码"},
	"owasp:xss:041": {"XSS - SVG use href 引用", "<use> 元素通过 href 或 xlink:href 引用外部资源"},
	"owasp:xss:042": {"XSS - SVG 动画资源引用", "SVG animate/set 元素的 href 或 xlink:href 加载外部资源"},
	"owasp:xss:043": {"XSS - onafterscriptexecute 事件", "绑定 onafterscriptexecute 事件处理器借脚本执行时机触发"},
	"owasp:xss:044": {"XSS - document 方括号属性访问", "document[字符串形式访问 cookie、domain、write 等敏感成员"},
	"owasp:xss:045": {"XSS - 弹窗函数直接调用", "alert/confirm/prompt 以数字或引号参数直接调用证明注入成立"},
	"owasp:xss:046": {"XSS - constructor 链式调用", "constructor.constructor() 恢复 Function 构造器执行任意代码"},
	"owasp:xss:047": {"XSS - a 标签 download 属性", "<a download> 强制浏览器下载引用资源"},
	"owasp:xss:048": {"XSS - 正则 source 拼接", "方括号内拼接两个正则的 .source 拼出危险字符串"},
	"owasp:xss:049": {"XSS - atob 解码后 eval", "eval 或 function 包裹 atob() 解码执行 Base64 载荷"},
	"owasp:xss:050": {"XSS - 命名空间前缀 script", "带命名空间前缀的标签如 <x:script> 在 HTML 解析时落为脚本标签"},
	"owasp:xss:051": {"XSS - SVG 图片数据 URI", "data:image/svg+xml 数据 URI 内可嵌入可执行 SVG 内容"},
	"owasp:xss:052": {"XSS - 对象方括号运算符索引", "window 等对象以方括号加运算符拼装属性名绕过过滤"},
	"owasp:xss:053": {"XSS - 原型链属性覆写", "constructor.prototype 加属性名赋值向原型链注入属性"},
	"owasp:xss:054": {"XSS - base href 劫持", "<base href> 不改写协议也能劫持后续相对 URL 的解析目标"},
	"owasp:xss:055": {"XSS - download 指定文件名", "<a download> 携带带扩展名的文件名强制另存为"},
	"owasp:xss:056": {"XSS - 空白分隔伪协议", "字母间插入空白的 j a v a s c r i p t: 伪协议变体"},
	"owasp:xss:057": {"XSS - 背景属性站外引用", "background 属性引用 // 或 http(s) 站外地址加载资源"},
	"owasp:xss:058": {"XSS - DOM Clobbering 元素命名", "form/input/img/a 等元素的 name 或 id 覆盖 window/document 等 DOM 对象"},
	"owasp:xss:059": {"XSS - name 覆盖原型对象", "a/area 元素的 name 设为 __proto__ 覆写原型链对象"},
	"owasp:xss:060": {"XSS - 低解析标签内容突变", "noscript/noembed/noframes 内嵌 script/img 等标签利用解析突变逃逸（mXSS）"},
	"owasp:xss:061": {"XSS - 命名空间混淆 shell", "math/svg 内嵌 style/mglyph 等元素利用命名空间混淆执行（mXSS）"},
	"owasp:xss:062": {"XSS - SVG foreignObject 嵌入", "SVG 的 foreignObject 将 HTML 内容嵌入 SVG 上下文执行脚本"},
	"owasp:xss:063": {"XSS - SVG 动画事件", "SVG animate/set 元素绑定 onbegin、onend 等动画事件处理器"},
	"owasp:xss:064": {"XSS - xlink:href 伪协议", "SVG 的 xlink:href 指向 javascript: 伪协议执行代码"},
	"owasp:xss:065": {"XSS - 净化器探测载荷", "标签或属性区出现 sanitize/purify/dompurify 字样，疑似探测净化配置"},
	"owasp:xss:066": {"XSS - 模板字符串插值", "反引号模板字符串内 ${...} 引用 document、alert、fetch 等敏感对象"},
	"owasp:xss:067": {"XSS - 弹窗函数 call/apply 借调", "alert/confirm/prompt 以 call/apply 方式借调执行绕过过滤"},
	"owasp:xss:068": {"XSS - Function 构造器", "new Function(\"字符串\") 构造器把字符串编译为可执行函数体"},
}

var webshellRuleMeta = map[string]ruleMeta{
	// WebShell
	"owasp:webshell:001": {"WebShell - PHP 命令执行函数", "eval、assert、system、exec 等 PHP 危险函数被直接调用"},
	"owasp:webshell:002": {"WebShell - base64_decode 解码", "调用 base64_decode 还原被编码的载荷，常见于一句话木马"},
	"owasp:webshell:003": {"WebShell - PHP 代码片段", "出现 <?php 起始标记，请求中嵌入可执行 PHP 代码"},
	"owasp:webshell:004": {"WebShell - Java 运行时命令执行", "链式调用 Runtime.getRuntime().exec 执行系统命令"},
	"owasp:webshell:005": {"WebShell - 系统解释器引用", "载荷引用 cmd.exe、powershell.exe 或 /bin/sh 等系统解释器"},
	"owasp:webshell:006": {"WebShell - PHP 超全局取值", "$_GET、$_POST、$_REQUEST 等超全局数组被取出后执行"},
	"owasp:webshell:007": {"WebShell - preg_replace e 修饰符", "preg_replace 使用已废弃的 /e 修饰符把替换串当作代码执行"},
	"owasp:webshell:008": {"WebShell - Python 进程调用", "调用 subprocess 或 os.system 等 Python 进程执行接口"},
	"owasp:webshell:009": {"WebShell - 对象 exec 方法调用", "对象以 .exec() 形式调用命令执行方法（JSP/Groovy 等）"},
	"owasp:webshell:010": {"WebShell - 解释器带命令参数", "system/exec/open 等调用以 cmd、bash、nc 等命令字面量开头"},
	"owasp:webshell:011": {"WebShell - ASP 输出与执行接口", "调用 Response.Write、Server.Execute 等 ASP/ASPX 服务端接口"},
	"owasp:webshell:012": {"WebShell - create_function 动态函数", "create_function 以字符串参数动态创建函数，等价于 eval"},
	"owasp:webshell:013": {"WebShell - PHP 混淆包装函数", "gzinflate、str_rot13、hex2bin 等包装函数还原混淆载荷"},
	"owasp:webshell:014": {"WebShell - call_user_func 动态调用", "call_user_func 以 system、exec 等敏感函数为回调动态执行"},
	"owasp:webshell:015": {"WebShell - Drupal 渲染数组注入", "载荷构造 #post_render、#type 等 Drupal 渲染数组键触发 RCE"},
	"owasp:webshell:016": {"WebShell - Java 对象序列化标签", "出现 <java.*> 标签包裹的 Java 对象序列化/XStream 载荷"},
	"owasp:webshell:017": {"WebShell - invokefunction 链调用", "ThinkPHP invokefunction 与 call_user_func 组合的远程调用链"},
	"owasp:webshell:018": {"WebShell - ThinkPHP 控制器引用", "引用 \think\app、request 等 ThinkPHP 命名空间类，框架类 RCE 前奏"},
	"owasp:webshell:019": {"WebShell - ASP/JSP 脚本标记", "<% eval、<%execute 等 ASP/JSP 脚本片段嵌入请求"},
	"owasp:webshell:020": {"WebShell - PHP 文件读写串联", "file_put_contents 与 file_get_contents 串联实现文件落地"},
	"owasp:webshell:021": {"WebShell - 参数名写文件绕过", "name 参数值通过 > 重定向拼接可执行扩展名写入文件"},
	"owasp:webshell:022": {"WebShell - PHP 文件路径写入", "file_put_contents 朝向 .php 结尾的路径写入恶意代码"},
	"owasp:webshell:023": {"WebShell - PHP 短标签代码", "<? 短开标签后紧跟 echo、include、eval 等 PHP 代码"},
	"owasp:webshell:024": {"WebShell - PHP 流包装器", "使用 php://input、php://filter 等流包装器获读请求体或代码"},
	"owasp:webshell:025": {"WebShell - data 文本载荷", "data://text/plain 数据 URI 承载可执行文本载荷"},
	"owasp:webshell:026": {"WebShell - 远程文件包含", "include/require 引用 http(s) 远程 URL，实现远程文件包含"},
	"owasp:webshell:027": {"WebShell - Python 反射导入执行", "__import__ 导入 os/subprocess 等危险模块，常见于 Jinja2/SSTI 载荷"},
}

var revshellRuleMeta = map[string]ruleMeta{
	// 反弹 Shell
	"owasp:revshell:001": {"反弹 Shell - bash 交互式反向连接", "bash -i 配合 >&/dev/tcp 建立交互式反向连接"},
	"owasp:revshell:002": {"反弹 Shell - dev/tcp 伪设备", "载荷引用 /dev/tcp/<数字> 伪设备建立 TCP 反向通道"},
	"owasp:revshell:003": {"反弹 Shell - netcat 带 -e 参数", "nc/ncat 以 -e 参数启动反向连接并直接派生 shell"},
	"owasp:revshell:004": {"反弹 Shell - Python socket 脚本", "python -c 内联脚本引用 socket 模块建立反向连接"},
	"owasp:revshell:005": {"反弹 Shell - PowerShell 下载执行", "Invoke-Expression/IEX 包裹 New-Object 或 DownloadString 远程执行"},
	"owasp:revshell:006": {"反弹 Shell - 下载管道执行", "curl/wget 下载的内容经管道直接交给 sh/bash 执行"},
	"owasp:revshell:007": {"反弹 Shell - mkfifo 管道", "在 /tmp 下创建命名管道 mkfifo 搭建反向通道"},
	"owasp:revshell:008": {"反弹 Shell - Perl socket 脚本", "perl -e 内联脚本引用 socket 建立反向连接"},
	"owasp:revshell:009": {"反弹 Shell - socat exec 派生", "socat 后接目标地址并带 exec: 派生 shell 反向连接"},
	"owasp:revshell:010": {"反弹 Shell - socat TCP 目标", "socat 的参数中携带 tcp 与四段式 IPv4 地址"},
	"owasp:revshell:011": {"反弹 Shell - telnet 反向会话", "telnet 直接连接公网 IP 与端口建立反向会话"},
	"owasp:revshell:012": {"反弹 Shell - Ruby/Node socket 脚本", "ruby 或 node 以 -r/-e 参数内联 socket 脚本反向连接"},
}

var cmdInjectRuleMeta = map[string]ruleMeta{
	// 命令注入
	"owasp:cmd:001": {"命令注入 - 分隔符衔接命令", "分号、管道或 & 后紧跟 ls、cat、whoami 等系统命令"},
	"owasp:cmd:002": {"命令注入 - 反引号命令替换", "反引号内包裹 cat、ls、whoami 等系统命令"},
	"owasp:cmd:003": {"命令注入 - 美元括号命令替换", "$(...) 内包裹 cat、ls 等系统命令做子命令替换"},
	"owasp:cmd:004": {"命令注入 - 输出重定向系统路径", "> 或 >> 将输出重定向到 /etc、/tmp 等系统目录"},
	"owasp:cmd:005": {"命令注入 - wget/curl 远程下载", "分隔符位置的 wget 或 curl 直接下载远程 URL"},
	"owasp:cmd:006": {"命令注入 - 空字节换行截断", "%00 空字节或 %0a/%0d 换行截断命令上下文"},
	"owasp:cmd:007": {"命令注入 - 探测命令加分号", "id、uname、whoami 等探测命令后紧跟分号"},
	"owasp:cmd:008": {"命令注入 - 管道衔接命令", "管道符 | 后紧跟 cat、ls 等系统命令"},
	"owasp:cmd:009": {"命令注入 - IFS 空白替代", "使用 ${IFS} 替代空格拆分命令参数绕过过滤"},
	"owasp:cmd:010": {"命令注入 - 环境变量前缀命令", "VAR=val 环境变量赋值后紧跟 cat、id 等系统命令"},
	"owasp:cmd:011": {"命令注入 - 逻辑符衔接命令", "&& 或 || 后紧跟 cat、ls、rm 等系统命令"},
	"owasp:cmd:012": {"命令注入 - 花括号展开", "{cat,/etc/passwd} 花括号展开绕过空格检测"},
	"owasp:cmd:013": {"命令注入 - here-string 注入", "bash、python 等解释器后接 <<< 传入内联命令串"},
	"owasp:cmd:014": {"命令注入 - ANSI-C 引号转义", "$' 后跟 \\x 十六进制或 \\0 八进制转义（$'\\x61'）拼出命令字符"},
	"owasp:cmd:015": {"命令注入 - 解码管道执行", "base64 -d、dd 或 tee 的输出经管道送给 shell 执行"},
	"owasp:cmd:016": {"命令注入 - 换行衔接命令", "换行或回车符后紧跟 cat、ls 等系统命令"},
	"owasp:cmd:017": {"命令注入 - SSI 服务端包含", "<!--#exec、#include 等 SSI 服务端包含指令执行命令"},
	"owasp:cmd:018": {"命令注入 - 反引号拆分命令名", "wh``oami 等用空反引号拆分命令名绕过检测"},
	"owasp:cmd:019": {"命令注入 - touch/rm 路径操作", "分隔符后对 / 开头的路径执行 touch 或 rm 作为 RCE 证明"},
	"owasp:cmd:020": {"命令注入 - Git 参数注入", "--open-files-in-pager、--exec 等 Git 分支参数注入执行命令"},
	"owasp:cmd:021": {"命令注入 - 精确 IFS 写法", "${ifs} 小写精确写法替换空格拆分命令参数"},
	"owasp:cmd:022": {"命令注入 - 参数上下文子命令", "$(...) 形式的子命令替换出现在参数值上下文中"},
	"owasp:cmd:023": {"命令注入 - 词内反引号拆分", "命令词中间插入反引号对（wh``oami）拆字绕过检测"},
	"owasp:cmd:024": {"命令注入 - 反引号起始命令执行", "反引号后紧跟 ping、curl、whoami 等系统命令执行"},
	"owasp:cmd:025": {"命令注入 - 特殊变量拆分命令名", "who$@ami、c$@at 等在命令词内插入 $@ 绕过词匹配"},
	"owasp:cmd:026": {"命令注入 - IFS 切词接目标", "cat${IFS}/etc/passwd、ls${ifs}-la 用字段分隔符变量替代空格"},
	"owasp:cmd:027": {"命令注入 - bash 函数导出", "export -f 导出 shell 函数后紧跟分号调用注入命令"},
	"owasp:cmd:028": {"命令注入 - env 清空环境执行", "env -i 清空环境变量后启动 sh、bash、python 等解释器"},
	"owasp:cmd:029": {"命令注入 - 引号反斜杠拆字", "w'h'o'a'm'i、c\\a\\t 引号或反斜杠逐字符拆分命令名"},
	"owasp:cmd:030": {"命令注入 - 无协议本地下载", "curl/wget 直接指向 localhost、127.0.0.1 或脚本文件名下载执行"},
	"owasp:cmd:031": {"命令注入 - 绝对路径子命令", "$(/bin/cat ...) 或 $(busybox wget ...) 绝对路径封装的子命令替换"},
	"owasp:cmd:032": {"命令注入 - ANSI-C 连续转义串", "$'\\x63\\x61\\x74' ANSI-C 引号内三组以上十六进制转义拼装命令"},
	"owasp:cmd:033": {"命令注入 - 执行包装词衔接解释器", "xargs sh -c、timeout bash -c、nohup python -c 等包装词启动解释器"},
	"owasp:cmd:034": {"命令注入 - Windows 命令启动器", "cmd.exe /c、powershell -enc、pwsh -c 显式启动 Windows 命令解释器"},
}

var ssrfRuleMeta = map[string]ruleMeta{
	// SSRF
	"owasp:ssrf:001": {"SSRF - 云元数据地址段", "访问 169.254.169.254 链路本地地址，指向 AWS/Azure/GCP 元数据服务"},
	"owasp:ssrf:002": {"SSRF - GCP 元数据域名", "访问 metadata.google.internal 解析 GCP 内部元数据服务"},
	"owasp:ssrf:003": {"SSRF - 阿里云元数据地址", "访问 100.100.100.200 阿里云内部元数据服务地址"},
	"owasp:ssrf:004": {"SSRF - 10 段私网地址", "URL 或路径中引用 10.x 私网地址段访问内网"},
	"owasp:ssrf:005": {"SSRF - 172.16 段私网地址", "URL 或路径中引用 172.16-31 私网地址段访问内网"},
	"owasp:ssrf:006": {"SSRF - 192.168 段私网地址", "URL 或路径中引用 192.168.x 私网地址段访问内网"},
	"owasp:ssrf:007": {"SSRF - 回环地址请求", "URL 引用 127.x 或 localhost 回环地址访问本机服务"},
	"owasp:ssrf:008": {"SSRF - IPv6 回环与零地址", "URL 引用 [::1]、[::] 或 0.0.0.0 回环与零地址"},
	"owasp:ssrf:009": {"SSRF - 十六进制 IP 编码", "URL 中以 0x 十六进制整数形式编码 IP 地址绕过过滤"},
	"owasp:ssrf:010": {"SSRF - 危险协议 scheme", "使用 file://、gopher://、dict://、expect:// 等危险协议 scheme"},
	"owasp:ssrf:011": {"SSRF - 十进制 IP 编码", "URL 中以 8-10 位十进制整数编码 IP 如 2130706433"},
	"owasp:ssrf:012": {"SSRF - IPv6 映射私网 IPv4", "::ffff: 前缀映射 127./10./192.168. 等私网 IPv4 地址"},
	"owasp:ssrf:013": {"SSRF - IMDSv2 令牌头", "出现 x-aws-ec2-metadata-token 头，SSRF 获取令牌的攻击链"},
	"owasp:ssrf:014": {"SSRF - Unix 套接字路径", "unix: 前缀引用长路径 Unix 套接字访问本机服务"},
	"owasp:ssrf:015": {"SSRF - IMDS 实例元数据", "169.254.169.254 后跟 /metadata/instance 获取云实例元数据"},
	"owasp:ssrf:016": {"SSRF - GCP 元数据 API", "metadata.google.internal 后跟 computeMetadata 或 v1/ 元数据 API"},
	"owasp:ssrf:017": {"SSRF - IMDSv2 令牌申请", "PUT 请求携带 169.254.169.254 并指向 /api/token 申请访问令牌"},
	"owasp:ssrf:018": {"SSRF - DigitalOcean 元数据", "169.254.169.254 后跟 /metadata/v1 获取 DigitalOcean 元数据"},
	"owasp:ssrf:019": {"SSRF - Oracle 云元数据", "169.254.169.254 后跟 opc/v1 或 v2 获取 OCI 元数据"},
	"owasp:ssrf:020": {"SSRF - 八进制 IP 编码", "URL 中以 0177.0.0.1 形式八进制编码 IP 绕过过滤"},
	"owasp:ssrf:021": {"SSRF - 重绑定域名后缀", "内网 IP 拼配 .nip.io/.xip.io/.sslip.io 域名做 DNS 重绑定"},
	"owasp:ssrf:022": {"SSRF - URL 内 IPv6 映射", "URL 中以 [::ffff:1.2.3.4] 形式承载映射后的 IPv4 地址"},
	"owasp:ssrf:023": {"SSRF - 九位十进制 IP", "URL 中以 9-10 位十进制整数编码 IP 如 2130706433"},
	"owasp:ssrf:024": {"SSRF - 裸括号 IPv6 回环", "无 scheme 前缀的 [::1] 括号 IPv6 回环地址（JSON 字段值、路径参数等上下文）"},
}

var xxeRuleMeta = map[string]ruleMeta{
	// XXE
	"owasp:xxe:001": {"XXE - 内联 DTD 声明", "<!DOCTYPE 声明内带 [ 内联 DTD 子集，可声明外部实体"},
	"owasp:xxe:002": {"XXE - SYSTEM 外部实体", "<!ENTITY 后接 SYSTEM 关键字引用外部资源"},
	"owasp:xxe:003": {"XXE - PUBLIC 外部实体", "<!ENTITY 后接 PUBLIC 关键字引用外部资源"},
	"owasp:xxe:004": {"XXE - 参数实体引用", "%-字符-; 形式的参数实体引用，用于二次展开与带外回传"},
	"owasp:xxe:005": {"XXE - SYSTEM 危险协议", "SYSTEM 声明的 URI 使用了 file、http、expect 等危险协议"},
	"owasp:xxe:006": {"XXE - 盲注参数实体", "<!ENTITY % 声明的参数实体，用于盲注外部实体外带"},
	"owasp:xxe:007": {"XXE - XInclude 注入", "<xi:include> 后带 href 属性引用外部文档内容"},
	"owasp:xxe:008": {"XXE - xsi schemaLocation 注入", "xsi:schemaLocation 或 noNamespaceSchemaLocation 属性指向站外 schema 资源"},
	"owasp:xxe:009": {"XXE - 参数实体引用链", "两个以上参数实体引用连续外带（%pe;%xx;），递归展开放大器形态"},
}

var ldapRuleMeta = map[string]ruleMeta{
	// LDAP 注入
	"owasp:ldap:001": {"LDAP 注入 - 括号闭合 OR 分支", ")(| 闭合原过滤器括号并追加 OR 分支放宽查询"},
	"owasp:ldap:002": {"LDAP 注入 - objectClass 通配探测", "*)(objectclass= 闭合后注入 objectClass 通配枚举条目"},
	"owasp:ldap:003": {"LDAP 注入 - 括号闭合 AND 分支", ")(& 闭合原过滤器括号并追加 AND 分支改写语义"},
	"owasp:ldap:004": {"LDAP 注入 - OR 通配枚举", "(|(attr=*)) 形式的 OR 分支以通配符枚举全部条目"},
	"owasp:ldap:005": {"LDAP 注入 - admin 通配探测", "admin*)( 闭合后以通配符探测 admin 前缀条目"},
	"owasp:ldap:006": {"LDAP 注入 - 括号闭合 NOT 分支", ")(!( 闭合原过滤器并追加 NOT 分支取反条件"},
	"owasp:ldap:007": {"LDAP 注入 - uid 通配枚举", "(|(uid=*)) 多层 OR 分支以 uid 通配符枚举条目"},
	"owasp:ldap:008": {"LDAP 注入 - 属性拼接 mail 枚举", "attr=* 后接 (mail=*) 把通配枚举扩展到 mail 属性"},
}

var nosqliRuleMeta = map[string]ruleMeta{
	// NoSQL 注入
	"owasp:nosql:001": {"NoSQL 注入 - $where 操作符", "出现 MongoDB 的 $where 操作符，可执行 JavaScript 表达式"},
	"owasp:nosql:002": {"NoSQL 注入 - $ne 操作符", "使用 $ne 不等操作符改写查询条件绕过过滤"},
	"owasp:nosql:003": {"NoSQL 注入 - $gt 操作符", "使用 $gt 大于操作符改写查询条件枚举数据"},
	"owasp:nosql:004": {"NoSQL 注入 - $regex 操作符", "使用 $regex 正则操作符注入正则检索条件"},
	"owasp:nosql:005": {"NoSQL 注入 - $or 数组注入", "$or 后接数组结构注入多条备选查询条件"},
	"owasp:nosql:006": {"NoSQL 注入 - $exists 操作符", "使用 $exists 操作符探测字段存在性枚举结构"},
	"owasp:nosql:007": {"NoSQL 注入 - $lookup 聚合注入", "$lookup 后接对象注入聚合管道联表操作"},
	"owasp:nosql:008": {"NoSQL 注入 - this 字段比较", "以 this.字段 加等值比较的形式在表达式里探测字段"},
	"owasp:nosql:009": {"NoSQL 注入 - $function 函数注入", "$function 后接对象注入服务端 JavaScript 函数执行"},
	"owasp:nosql:010": {"NoSQL 注入 - $accumulator 聚合注入", "$accumulator 后接对象注入聚合累加器函数"},
	"owasp:nosql:011": {"NoSQL 注入 - CouchDB 视图入口", "访问 /_all_docs、/_find 或 /_view/ CouchDB 内部 API"},
	"owasp:nosql:012": {"NoSQL 注入 - Redis EVAL 脚本", "EVAL/EVALSHA 后接引号脚本，Redis 协议注入执行 Lua"},
	"owasp:nosql:013": {"NoSQL 注入 - CQL 条件放行", "出现 ALLOW FILTERING 放宽 Cassandra CQL 查询限制"},
	"owasp:nosql:014": {"NoSQL 注入 - 字段级操作符对象", "字段名后接 { $ne、$gt 等对象值注入操作符条件"},
	"owasp:nosql:015": {"NoSQL 注入 - 方括号操作符参数", "查询参数以 key[$ne] 等形式在方括号中注入操作符"},
	"owasp:nosql:016": {"NoSQL 注入 - $match 聚合注入", "$match 后接对象注入聚合流水线过滤条件"},
	"owasp:nosql:017": {"NoSQL 注入 - $where 代码载荷", "$where 值内携带 sleep、function、return 或 this. 代码片段"},
}

var sstiRuleMeta = map[string]ruleMeta{
	// 模板注入（SSTI）
	"owasp:ssti:001": {"SSTI - 双花括号算术探测", "{{ 数字 运算符 数字 }} 算术表达式用于探测 Jinja2/Django 上下文"},
	"owasp:ssti:002": {"SSTI - Jinja2 config 对象读取", "{{ config. 读取 Jinja2 全局 config 对象中的配置数据"},
	"owasp:ssti:003": {"SSTI - 字符串 __class__ 遍历", "{{ 'x'.__class__ }} 从字符串对象出发遍历 Python 类层级"},
	"owasp:ssti:004": {"SSTI - 美元花括号算术探测", "${ 数字 运算符 数字 } 算术表达式探测 FreeMarker/Velocity 上下文"},
	"owasp:ssti:005": {"SSTI - getClass 反射遍历", "${...getClass()} 从对象反射出发遍历 Java 类层级"},
	"owasp:ssti:006": {"SSTI - ERB/JSP 表达式标记", "<%= ... %> 表达式输出标记直接执行服务端模板代码"},
	"owasp:ssti:007": {"SSTI - Smarty php 标签", "{php}...{/php} Smarty 标签直接执行 PHP 代码"},
	"owasp:ssti:008": {"SSTI - Python dunder 属性", "__subclasses__、__builtins__ 等双下划线属性遍历实现 RCE"},
	"owasp:ssti:009": {"SSTI - Pebble 反射调用", "{{...getClass/forName 等调用触及 Pebble 模板的反射接口"},
	"owasp:ssti:010": {"SSTI - JSON 键原型污染", "JSON 键名直接使用 __proto__ 污染对象原型链"},
	"owasp:ssti:011": {"SSTI - JSON 键 constructor 污染", "{\"constructor\":{\"prototype\":...}} 形式污染构造器原型"},
	"owasp:ssti:012": {"SSTI - EJS 服务端代码", "<% 标记内引用 process.env、require() 或 global 访问 Node 环境"},
	"owasp:ssti:013": {"SSTI - Handlebars 助手函数", "{{lookup、{{with、{{each 等 Handlebars 助手被用于上下文访问"},
	"owasp:ssti:014": {"SSTI - Tornado/Mako self 模块", "${self.module 等形式访问 Tornado/Mako 模板内部模块"},
	"owasp:ssti:015": {"SSTI - ThinkPHP 标签调用", "{xx/xx:xx( 形式调用 ThinkPHP 模板的函数标签"},
	"owasp:ssti:016": {"SSTI - 通用标签函数调用", "{a_b:c_d(...)} 通用模板标签后带函数调用的注入形式"},
	"owasp:ssti:017": {"SSTI - DedeCMS runphp 标签", "{dede:标签中携带 runphp 属性在织梦模板中执行 PHP"},
}

var jndiRuleMeta = map[string]ruleMeta{
	// JNDI 注入
	"owasp:jndi:001": {"JNDI 注入 - 远程查找协议", "${jndi:ldap/rmi/... 前缀直接发起远程 JNDI 查找"},
	"owasp:jndi:002": {"JNDI 注入 - 查找修饰键", "${lower:、${upper:、${env: 等 Log4j 查找修饰键被引用"},
	"owasp:jndi:003": {"JNDI 注入 - 嵌套查找占位符", "查找内再嵌 ${${...}} 嵌套占位符逐层解析出 JNDI 键"},
	"owasp:jndi:004": {"JNDI 注入 - env/sys 查找", "${env: 或 ${sys: 查找读取环境变量与系统属性"},
	"owasp:jndi:005": {"JNDI 注入 - 字符拆分混淆", "${j${::-n}d${::-i}: 拆分 jndi 字母穿插占位符绕过过滤"},
	"owasp:jndi:006": {"JNDI 注入 - URL 编码载荷", "%24%7Bjndi%3A 百分号编码后的 JNDI 前缀"},
	"owasp:jndi:007": {"JNDI 注入 - Unicode 转义载荷", "\\u0024\\u007b 形式 Unicode 转义书写的 ${jndi 前缀"},
}

var crlfRuleMeta = map[string]ruleMeta{
	// CRLF 注入
	"owasp:crlf:001": {"CRLF 注入 - 裸换行响应头注入", "裸 CRLF 后紧跟 Set-Cookie、Location 等响应头名实现响应拆分"},
	"owasp:crlf:002": {"CRLF 注入 - 编码换行响应头注入", "%0d%0a 后紧跟 Set-Cookie、Location 或 Content-Type 头名"},
	"owasp:crlf:003": {"CRLF 注入 - 双重编码换行", "%0d%0a%0d%0a 连续两个编码换行结束头部区开启响应体"},
	"owasp:crlf:004": {"CRLF 注入 - 裸双换行", "\\r\\n\\r\\n 连续两个裸换行结束头部区开启响应体"},
}

var elRuleMeta = map[string]ruleMeta{
	// 表达式语言注入（EL/OGNL/SpEL）
	"owasp:el:001": {"表达式注入 - SpEL T() 类型引用", "#{T(java.lang.xxx)} SpEL 的 T() 运算符引用 Java 类"},
	"owasp:el:002": {"表达式注入 - ${T()} 类型引用", "${T(java.lang.xxx)} 花括号形式引用 Java 类"},
	"owasp:el:003": {"表达式注入 - OGNL getClass 调用", "%{...getClass()} OGNL 表达式反射获取类对象"},
	"owasp:el:004": {"表达式注入 - OGNL Runtime 绑定", "(#rt=@java.lang.runtime) 把 Runtime 静态对象绑定到变量"},
	"owasp:el:005": {"表达式注入 - Java 危险类引用", "引用 java.lang.Runtime、ProcessBuilder、Class、System 等关键类"},
	"owasp:el:006": {"表达式注入 - Runtime exec 链", "getRuntime().exec() 反射链调用系统命令"},
	"owasp:el:007": {"表达式注入 - Struts2 context 访问", "%{#context[ 访问 Struts2 OGNL 的 context 对象栈"},
	"owasp:el:008": {"表达式注入 - redirect/action 前缀", "redirect: 或 action: 前缀后跟 ${ 表达式触发求值"},
	"owasp:el:009": {"表达式注入 - OGNL 静态方法调用", "@java.xxx.xxx@xxx 静态方法调用语法直接引用 Java 类"},
	"owasp:el:010": {"表达式注入 - new 实例化 Java 类", "new java.xxx 直接实例化 Java 类对象"},
	"owasp:el:011": {"表达式注入 - OGNL 对象引用", "#request、#session、#context 等 OGNL 预置对象被引用"},
	"owasp:el:012": {"表达式注入 - 反射调用链", "getDeclaredMethods 后接 .invoke() 反射链调用任意方法"},
	"owasp:el:013": {"表达式注入 - forName 类加载", "getClass().forName() 或 Class.forName() 动态加载类"},
}

var deserRuleMeta = map[string]ruleMeta{
	// 反序列化攻击
	"owasp:deser:001": {"反序列化 - Java 序列化魔数", "出现 AC ED 00 05 原始 Java 对象序列化魔数字节"},
	"owasp:deser:002": {"反序列化 - PHP 对象序列化", "o:数字:\"类名\" PHP 序列化对象字面量"},
	"owasp:deser:003": {"反序列化 - Python pickle 系统调用", "pickle 字节流中引用 os/posix 的 system 或 popen 内置函数"},
	"owasp:deser:004": {"反序列化 - ViewState ysoserial", "__VIEWSTATE 与 ysoserial 载荷同时出现"},
	"owasp:deser:005": {"反序列化 - Ruby Marshal 魔数", "x04 x08 后跟类型字节的 Ruby Marshal 序列化前缀"},
	"owasp:deser:006": {"反序列化 - .NET LosFormatter 魔数", "AAEAAAD 开头 Base64 编码的 .NET BinaryFormatter 载荷"},
	"owasp:deser:007": {"反序列化 - Node serialize RCE", "{\"rce\":\"_$$ND_FUNC$$_ 序列化键标识 Node 远程代码执行载荷"},
	"owasp:deser:008": {"反序列化 - 十六进制 Java 魔数", "存在 aced0005 十六进制形式的 Java 序列化魔数"},
	"owasp:deser:009": {"反序列化 - PHP 键值对序列化", "s:数字:\"...\";s:数字: 成对出现的 PHP 序列化字符串"},
	"owasp:deser:010": {"反序列化 - Base64 Java 魔数", "存在 rO0AB Base64 编码的 Java 序列化魔数前缀"},
	"owasp:deser:011": {"反序列化 - Faces ViewState 魔数", "javax.faces.ViewState 参数值为 rO0AB 开头的序列化载荷"},
	"owasp:deser:012": {"反序列化 - 编码 Java 魔数", "百分号或十六进制编码的 AC ED 00 05 Java 序列化魔数"},
	"owasp:deser:013": {"反序列化 - XStream 链类名", "<sorted-set>、<java.util.*> 等 XStream 别名包装的 gadget 链"},
	"owasp:deser:014": {"反序列化 - ObjectInputStream 引用", "提及 ObjectInputStream 类，用于反序列化不可信数据"},
	"owasp:deser:015": {"反序列化 - Apache Xalan 链", "引用 com.sun.org.apache.xalan 类，CVE-2022-34169 一类链"},
	"owasp:deser:016": {"反序列化 - Commons Collections 链", "引用 org.apache.commons.collections，最常被利用的链"},
	"owasp:deser:017": {"反序列化 - HashMap 序列化上下文", "java.util.HashMap 与序列化、readObject 等标记同时出现"},
}

var graphqlRuleMeta = map[string]ruleMeta{
	// GraphQL 内省/注入
	"owasp:graphql:001": {"GraphQL - query __schema 内省", "query 查询体内引用 __schema 内省字段枚举完整模式"},
	"owasp:graphql:002": {"GraphQL - query __type 内省", "query 查询体内引用 __type 内省字段获取类型明细"},
	"owasp:graphql:003": {"GraphQL - introspectionQuery 变量", "出现名为 IntrospectionQuery 的内省查询变量"},
	"owasp:graphql:004": {"GraphQL - 直连 __schema 字段", "查询体以 { 直接引用 __schema 字段绕过 query 关键字检查"},
	"owasp:graphql:005": {"GraphQL - 直连 __type 字段", "查询体以 { 直接引用 __type 字段绕过 query 关键字检查"},
	"owasp:graphql:006": {"GraphQL - 批量操作数组", "请求为 [{\"query\":...}] 数组形式批量执行多个操作"},
	"owasp:graphql:007": {"GraphQL - @skip/@include 变量注入", "@skip 或 @include 指令以 $变量 作为 if 条件注入"},
	"owasp:graphql:008": {"GraphQL - subscription 订阅滥用", "subscription 关键字发起订阅操作常驻通道探测变更"},
}

var pathTravRuleMeta = map[string]ruleMeta{
	// 路径穿越
	"owasp:path_traversal:001": {"路径穿越 - 连续上级目录", "../ 连续两层以上跳出当前目录层级"},
	"owasp:path_traversal:002": {"路径穿越 - 系统敏感文件", "引用 etc/passwd、win.ini 等系统敏感文件路径"},
	"owasp:path_traversal:003": {"路径穿越 - 部分编码上级目录", "%2e%2e 编码形式书写 ../ 或 ..\\ 序列"},
	"owasp:path_traversal:004": {"路径穿越 - 双上级目录段", "../.. 两段上级目录跨越两级文件系统路径"},
	"owasp:path_traversal:005": {"路径穿越 - 分号上级目录", "..; 分号形式上级目录序列跨越路径"},
	"owasp:path_traversal:006": {"路径穿越 - proc 自身入口", "引用 /proc/self/environ、cmdline 等进程自身入口"},
	"owasp:path_traversal:007": {"路径穿越 - 空字节截断", "..%00 形式上级目录后接空字节截断路径"},
	"owasp:path_traversal:008": {"路径穿越 - Windows 系统文件", ".. 后引用 windows/system32、cmd.exe 等系统文件"},
	"owasp:path_traversal:009": {"路径穿越 - 长点序列", "四个以上连续点号模拟上级目录序列"},
	"owasp:path_traversal:010": {"路径穿越 - 绝对敏感路径", "/../ 后接 etc、proc 等路径起点构建绝对路径穿越"},
	"owasp:path_traversal:011": {"路径穿越 - 双重编码序列", "%252e、%252f 双重百分号编码的穿越字符序列"},
	"owasp:path_traversal:012": {"路径穿越 - 反斜杠上级目录", "..\\ 连续两层以上的 Windows 风格穿越序列"},
	"owasp:path_traversal:013": {"路径穿越 - Java Web 配置", "跨出目录并引用 WEB-INF、web.xml 等 Java Web 配置"},
	"owasp:path_traversal:014": {"路径穿越 - 直接 web.xml 引用", "以 web-inf 或 meta-inf 目录直接拼 web.xml 路径"},
	"owasp:path_traversal:015": {"路径穿越 - 源码与配置外带", "引用 .git、.env、.htpasswd、config.php 等敏感文件路径"},
	"owasp:path_traversal:016": {"路径穿越 - 越权管理目录", ".. 后接 admin、config、manager 等管理目录路径"},
	"owasp:path_traversal:017": {"路径穿越 - 躯干点段序列", "以斜杠分隔的整段仅由三个以上点号构成（.../），对齐白名单侧尾随点丢弃等价检测"},
	"owasp:path_traversal:018": {"路径穿越 - 点空白斜杠序列", ".. 与斜杠间夹空白（.. /、..\\space）的穿越序列变异"},
}
