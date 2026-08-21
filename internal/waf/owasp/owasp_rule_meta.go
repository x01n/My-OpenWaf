package owasp

// ruleMeta carries the human-readable metadata for one built-in detector rule.
type ruleMeta struct {
	name string
	desc string
}

// builtinRuleMeta 是内置检测规则中文元信息的唯一来源，键为检测器实际
// 发出的稳定 RuleID。registerSQLiRules 直接读取本表填充
// DefaultOWASPRegistry 的 Name/Description，因此管理端规则目录展示的
// 名称与说明都来自这里，不存在第二份可漂移的映射。
//
// 向任一 *Patterns 切片新增 pattern 而未在此登记，会让该规则的名称为空；
// TestBuiltinRuleMetaCoversSQLiPatterns 会拦截这种情况。
var builtinRuleMeta = map[string]ruleMeta{
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
