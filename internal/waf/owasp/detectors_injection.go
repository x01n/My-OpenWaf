package owasp

import (
	"regexp"
	"strings"

	"My-OpenWaf/internal/core/score"
)

// hasSSRFIndicator 在字符串含 URL scheme 或已知私网/云内网地址
// （可能构成 SSRF 载荷）时返回 true。
// 借此避免对每个干净请求都跑 13 条 SSRF 正则。
func hasSSRFIndicator(s string) bool {
	return strings.Contains(s, "://") ||
		strings.Contains(s, "169.254.169.254") ||
		strings.Contains(s, "metadata.google") ||
		strings.Contains(s, "100.100.100.200") ||
		strings.Contains(s, "x-aws-ec2-metadata") ||
		strings.Contains(s, "localhost") ||
		strings.Contains(s, "127.0.") ||
		strings.Contains(s, "127.1") ||
		strings.Contains(s, "::ffff:") ||
		strings.Contains(s, "::1") ||
		strings.Contains(s, "0x7f") ||
		strings.Contains(s, "0x7f000001") ||
		strings.Contains(s, "0x0a0a0a0a") ||
		strings.Contains(s, "unix:") ||
		strings.Contains(s, "0177.0") ||
		strings.Contains(s, ".nip.io") ||
		strings.Contains(s, ".xip.io") ||
		strings.Contains(s, ".sslip.io") ||
		strings.Contains(s, "2130706433")
}

var ssrfPatterns = []owaspPattern{
	// 云元数据端点
	{regexp.MustCompile(`169\.254\.169\.254`), 6, "owasp:ssrf:001", "169.254.169.254"}, // AWS/Azure/GCP 元数据
	{regexp.MustCompile(`metadata\.google\.internal`), 6, "owasp:ssrf:002", "metadata.google.internal"},
	{regexp.MustCompile(`100\.100\.100\.200`), 6, "owasp:ssrf:003", "100.100.100.200"}, // 阿里云
	// 私网地址段——配合新阈值提升到 5 分
	{regexp.MustCompile(`(https?://|ftps?://|[/@])10\.\d{1,3}\.\d{1,3}\.\d{1,3}`), 5, "owasp:ssrf:004", ""},
	{regexp.MustCompile(`(https?://|ftps?://|[/@])172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}`), 5, "owasp:ssrf:005", ""},
	{regexp.MustCompile(`(https?://|ftps?://|[/@])192\.168\.\d{1,3}\.\d{1,3}`), 5, "owasp:ssrf:006", "192.168."},
	// Localhost variants（含 BSD inet_aton 1-2 段缩写形态：127.1、127.1.8）
	{regexp.MustCompile(`(https?://|[/@])(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|127(\.\d{1,3}){0,2})(:\d+|/)`), 5, "owasp:ssrf:007", ""},
	{regexp.MustCompile(`(https?://|[/@])(\[::1\]|\[::\]|0\.0\.0\.0)(:\d+|/)`), 5, "owasp:ssrf:008", ""},
	// 无 scheme 前缀的括号 IPv6 回环/零地址（JSON 字段值如 {"host":"[::1]"}）。
	// 标注版：该形态未经实弹验证、仅静态可判（未构链到 Ipv4/opaque 场外链接），勿当作已实证规则。
	{regexp.MustCompile(`[:'"=]\s*\[::1\](?::\d+)?(?:\s|$|["'},])`), 4, "owasp:ssrf:024", "[::1]"},
	// DNS rebinding / encoding bypasses（http(s) 前缀可有可无：0x7f000001 裸段落同样判）
	{regexp.MustCompile(`https?://\s*0x[0-9a-f]{8}\b`), 5, "owasp:ssrf:009", ""},
	// file:// / gopher:// / dict:// 协议
	{regexp.MustCompile(`(file|gopher|dict|ldap|sftp|tftp|php|expect|phar)://`), 5, "owasp:ssrf:010", ""},
	// 十进制/八进制 IP 编码（如 http://2130706433 = 127.0.0.1）
	{regexp.MustCompile(`https?://\d{8,10}(/|$|\s|:)`), 5, "owasp:ssrf:011", ""},
	// IPv6 映射的 IPv4 私网地址
	{regexp.MustCompile(`::ffff:(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)`), 5, "owasp:ssrf:012", "::ffff:"},
	// AWS IMDSv2 令牌请求头（SSRF 利用链的一环）
	{regexp.MustCompile(`x-aws-ec2-metadata-token`), 5, "owasp:ssrf:013", "x-aws-ec2-metadata-token"},
	// Unix socket SSRF（CVE-2023-46809 形态）：unix:path|http://...
	{regexp.MustCompile(`\bunix:[^\s]{10,}`), 4, "owasp:ssrf:014", "unix:"},
	// Azure 实例元数据服务（IMDS）
	{regexp.MustCompile(`169\.254\.169\.254.{0,50}metadata/instance`), 6, "owasp:ssrf:015", "169.254.169.254"},
	// 带 flavor 请求头的 GCP 元数据
	{regexp.MustCompile(`metadata\.google\.internal.{0,50}(computemetadata|v1/)`), 6, "owasp:ssrf:016", "metadata.google.internal"},
	// AWS IMDSv2 令牌 PUT 请求模式
	{regexp.MustCompile(`put.{0,100}169\.254\.169\.254.{0,50}api/token`), 6, "owasp:ssrf:017", "169.254.169.254"},
	// DigitalOcean 元数据端点
	{regexp.MustCompile(`169\.254\.169\.254.{0,50}/metadata/v1`), 5, "owasp:ssrf:018", "169.254.169.254"},
	// Oracle Cloud IMDS
	{regexp.MustCompile(`169\.254\.169\.254.{0,50}opc/v[12]/`), 5, "owasp:ssrf:019", "169.254.169.254"},
	// 八进制 IP 绕过：http://0177.0.0.1/（八进制的 127.0.0.1）
	{regexp.MustCompile(`https?://0[0-7]{1,3}\.0{0,3}\.0{0,3}\.[0-7]{1,3}(/|$|\s|:)`), 5, "owasp:ssrf:020", ""},
	// DNS 重绑定服务：*.nip.io、*.xip.io、*.sslip.io 指向内网地址
	{regexp.MustCompile(`(127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\.(nip|xip|sslip)\.io\b`), 5, "owasp:ssrf:021", ""},
	// URL 上下文中的 IPv6 映射 IPv4：http://[::ffff:127.0.0.1]/
	{regexp.MustCompile(`https?://\[::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]`), 5, "owasp:ssrf:022", "::ffff:"},
	// URL 中的十进制 IP：http://2130706433/（127.0.0.1）、http://3232235521/（192.168.0.1）
	{regexp.MustCompile(`https?://\d{9,10}\b`), 4, "owasp:ssrf:023", ""},
}

func shouldScanSSRFPattern(s string, p owaspPattern, gate *scanGate) bool {
	if gate == nil {
		gate = scanGateOf(s)
	}
	// 每条 SSRF 规则的必要字面量已在 owaspPatternGates 中前移成门控，
	// 不再逐规则 strings.Contains。
	return gate.patternGate(p, s)
}

func checkSSRF(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !gate.family(famSSRF, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	// SSRF 无独立抑制器（isSSRFFalsePositive 由调用方执行），此处只做归因替换。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range ssrfPatterns {
		if !shouldScanSSRFPattern(s, p, gate) {
			continue
		}
		if !p.re.MatchString(s) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatSSRF, RuleID: id, Score: total, Desc: "SSRF 特征"}, true
		}
	}
	return OWASPHit{}, false
}

var cmdInjectPatterns = []owaspPattern{
	// 管道 / 分号 / 反引号 / $() 命令拼接。
	// 使用 (?:[\s;|&`]|$) 而非 \b，避免命中 URL 的 key=value 参数：
	// "a=1;id=123" → ";id" 后跟 "=" → 不命中。
	// "host=x;id" 位于串尾 → 通过 $ 命中。
	// 字符类含 `+`：请求体/查询里的 `+` 是 URL 编码的空格（后端会解码），
	// `|getent+hosts+example.com` 因此必须视作命令词边界，否则整条载荷漏检。
	{regexp.MustCompile("[;|&]\\s*(ls|cat|id|whoami|uname|pwd|ps|wget|curl|nc|bash|sh|echo|rm|chmod|chown|ping|touch|kill|python|perl|ruby|php|node|java|nslookup|dig|ssh|tcpdump|printf|netstat|getent|set)(?:[\\s;|&`+]|$)"), 5, "owasp:cmd:001", ""},
	// 反引号命令替换——要求反引号内处于命令位置的是已知 shell 命令
	// （避免 Markdown/散文误报）。
	// 判据由「体内任意位置出现命令词」收紧为「命令词位于命令位置」，两条通用约束：
	//   1) 词边界 \b —— 命令词后必须是非单词字符，避免自然语言词内命中（typing→ping）；
	//   2) 命令词位于体内开头（至多 4 个空白前缀）—— shell 命令替换的执行语义要求
	//      命令词处于命令位置；命令名前的变量赋值/重定向等前缀形态由 cmd:010 等规则覆盖。
	// 体内长度上界 200 字节：真实命令替换是可执行命令 + 参数，合理长度远小于此；
	// 无上界时任意长的 Markdown 反引号片段/随机数据只要含命令词子串即命中。
	{regexp.MustCompile("`\\s{0,4}(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|echo|rm|chmod|chown|python|perl|ruby|php|base64|find|grep|awk|sed|ps|kill|nslookup|dig|ping|sleep|dd|cp|mv|mkdir|touch|head|tail|sort|xxd)\\b[^`]{0,200}`"), 3, "owasp:cmd:002", ""},
	// 参数上下文子命令替换：$() 形态。
	{regexp.MustCompile(`\$\([^)]*\b(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|echo|rm|chmod|chown|python|perl|ruby|php|base64|dd|nslookup|dig|ping|sleep|kill|find|grep|awk|sed|head|tail|wc|sort|xxd|od)\b`), 4, "owasp:cmd:003", ""},
	// 典型的重定向注入
	{regexp.MustCompile(`(>|>>)\s*/(etc|tmp|var|root|home)/`), 4, "owasp:cmd:004", ">"},
	// 显式命令执行
	{regexp.MustCompile(`(^|[\s;|&])(wget|curl)\s+https?://`), 3, "owasp:cmd:005", ""},
	// 空字节 / 换行注入（含 URL 解码后产出的真实换行/CR 字节）
	{regexp.MustCompile(`%00|\x00|%0[aAdD]|\x0a|\x0d`), 3, "owasp:cmd:006", ""},
	// 后接分号的常见探测命令
	{regexp.MustCompile(`\b(id|uname|whoami|hostname|ifconfig|ipconfig)\s*;`), 3, "owasp:cmd:007", ""},
	// 管道接到 shell 命令——同样用 (?:[\s;|&`]|$) 修正以避免 URL 参数误报；
	// `+` 同 cmd:001，代表 URL 编码的空格。
	{regexp.MustCompile("\\|+\\s*(cat|ls|id|whoami|uname|pwd|ps|wget|curl|nc|bash|sh|ping|nslookup|dig|echo|head|tail|more|less|find|grep|awk|sed|base64|python|perl|ruby|php|node|java|ssh|tcpdump|printf|netstat|getent|set)(?:[\\s;|&`+]|$)"), 5, "owasp:cmd:008", ""},
	// ${IFS} 空格绕过（过滤器绕过中常见）
	{regexp.MustCompile(`\$\{?\s*ifs\s*\}?`), 4, "owasp:cmd:009", "ifs"},
	// 环境变量前缀 + 命令执行：VAR=val command
	{regexp.MustCompile(`\b\w+=\S+\s+(cat|id|whoami|curl|wget|bash|sh|python|perl|ruby|php)\b`), 3, "owasp:cmd:010", ""},
	// 用 && 或 || 串联的命令
	{regexp.MustCompile("(&&|\\|\\|)\\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|rm|chmod|ssh|tcpdump|printf|netstat)(?:[\\s;|&`]|$)"), 4, "owasp:cmd:011", ""},
	// Bash 花括号展开：{cat,/etc/passwd}——可绕过空格检测
	{regexp.MustCompile(`\{\s*(cat|ls|id|whoami|echo|bash|sh|python|perl|ruby|wget|curl)\s*,`), 4, "owasp:cmd:012", "{"},
	// here-string 注入：bash<<<'command'
	{regexp.MustCompile(`(bash|sh|python|perl|ruby)\s*<<<`), 4, "owasp:cmd:013", ""},
	// ANSI-C 十六进制/八进制引用：$'\x63\x61\x74'
	{regexp.MustCompile(`\$'\s*\\[xX0][0-9a-fA-F]`), 4, "owasp:cmd:014", "$'"},
	// tee / dd / base64 管道接 shell——另一种命令执行链
	{regexp.MustCompile(`(base64\s+-d|dd\s+if=|tee\s+/tmp)\s*\|`), 4, "owasp:cmd:015", ""},
	// 换行/CR 分隔的命令注入（%0a / %0d 绕过基于分号的过滤）
	{regexp.MustCompile("[\\r\\n]\\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php|echo|rm|chmod|kill|nslookup|dig|ping|sleep|find|awk|sed)(?:[\\s;|&`]|$)"), 4, "owasp:cmd:016", ""},
	// 服务端包含（SSI）注入：<!--#exec cmd="..."--> 与 <!--#include virtual="..."-->
	{regexp.MustCompile(`<!--\s*#\s*(exec|include|echo|config|fsize|flastmod)\b`), 5, "owasp:cmd:017", "<!--"},
	// 反引号拼接绕过：wh``oami、c``at、i``d——空反引号把命令名切开
	{regexp.MustCompile("(?:^|[;|&\\s])(w``?h``?o``?a``?m``?i|i``d|c``?a``?t|u``?n``?a``?m``?e)(?:[\\s;|&`]|$)"), 4, "owasp:cmd:018", ""},
	// 带路径的 touch/rm——以创建/删除文件作为 RCE 证据
	{regexp.MustCompile(`[;|&]\s*(?:touch|rm)\s+/`), 5, "owasp:cmd:019", "touch"},
	// Git 参数注入：--open-files-in-pager、--upload-pack、--exec 等
	{regexp.MustCompile(`--(?:open-files-in-pager|upload-pack|exec|receive-pack)\s*=`), 5, "owasp:cmd:020", "--"},
	// shell 命令注入中用 ${IFS} 替代空格。
	{regexp.MustCompile(`\$\{ifs\}`), 5, "owasp:cmd:021", ""},
	// 参数值上下文中执行 $(command) 子 shell。
	{regexp.MustCompile(`\$\(\s*\w+[\s$]`), 4, "owasp:cmd:022", ""},
	// 命令内插入空反引号的拆分绕过：wh``oami、ca``t。
	{regexp.MustCompile("\\b\\w+``\\w+\\b"), 4, "owasp:cmd:023", ""},
	// 反引号命令执行：`ping ...`、`touch ...`、`whoami`
	{regexp.MustCompile("`\\s*(ping|curl|wget|whoami|id|cat|ls|touch|rm|chmod|nc|nslookup|dig|python|perl|ruby|php|bash|sh|uname|ssh|tcpdump|printf|netstat|pwd|echo|ps|sleep)\\b"), 5, "owasp:cmd:024", ""},
	// $@ / $$ 特殊变量插入命令名拆分：who$@ami、c$@at、l$@s、cur$@l（CRS 932200 类插值逃逸）。
	// 前缀含 '='：URL 参数值形态 key=who$@ami 同样覆盖。
	{regexp.MustCompile("(?:^|[\\s;|&`=])(?:w(?:h\\$@)?o\\$@a\\$@mi|who\\$@ami|i\\$@d|c\\$@at|l\\$@s|pw\\$@d|un\\$@ame|ba\\$@sh|s\\$@h|cu\\$@rl|wg\\$@et)(?:[\\s;|&`]|$)"), 4, "owasp:cmd:025", "$@"},
	// 命令名后紧接 ${IFS}/$IFS 变体切词并带目标：cat${IFS}/etc/passwd、ls${ifs}-la。
	{regexp.MustCompile("(?:^|[\\s;|&`])(?:cat|ls|id|whoami|sh|bash|wget|curl|nc|touch|rm|chmod|env)\\s*\\$[{(]?\\s*(?:IFS|ifs)\\s*[})]?(?:/|-[a-z])"), 5, "owasp:cmd:026", "ifs"},
	// bash 函数导出后调用：export -f fn; fn（函数体携带注入命令后于分号处触发）。
	// 前缀含 '='：URL 参数值形态 key=export -f fn;fn 覆盖。
	{regexp.MustCompile("(?:^|[\\s;|&`=])export\\s+-f\\s+\\w+\\s*;"), 5, "owasp:cmd:027", "export"},
	// env -i 清空环境后启动解释器/命令：env -i sh -c 'id'、env -i bash。
	// 前缀含 '='：URL 参数值形态 key=env -i python -c ... 覆盖。
	{regexp.MustCompile("(?:^|[\\s;|&`=])env\\s+-i\\s+(?:-\\S+\\s+)*(?:sh|bash|zsh|dash|python|perl|ruby|php|cat|nc|wget|curl)(?:[\\s;|&`]|$)"), 5, "owasp:cmd:028", "env -i"},
	// 单引号/双引号/反斜杠逐字符拆分命令名：w'h'o'a'm'i、c\a\t、l"s"（CRS 932230 逃逸形态）。
	// 前缀含 '='：URL 参数值形态 key=w'h'o'a'm'i 覆盖。
	{regexp.MustCompile("(?:^|[\\s;|&`=])(?:w['\"\\\\]h['\"\\\\]o['\"\\\\]a['\"\\\\]m['\"\\\\]i|c['\"\\\\]a['\"\\\\]t|i['\"\\\\]d|l['\"\\\\]s|w['\"\\\\]g['\"\\\\]e['\"\\\\]t)(?:[\\s;|&`]|$)"), 4, "owasp:cmd:029", ""},
	// curl/wget 无协议或本地目标下载：curl localhost/1.sh、wget -qO- //host/x、curl 127.0.0.1:8000/。
	// 前缀含 '='：URL 参数值形态 key=curl -s localhost:8000/x.sh 覆盖。
	{regexp.MustCompile("(?:^|[\\s;|&`=])(?:curl|wget)(?:\\s+-\\S+)*\\s+(?:localhost(?::\\d+)?/|127\\.0\\.0\\.1(?::\\d+)?/|0\\.0\\.0\\.0(?::\\d+)?/|\\[?::1\\]?(?::\\d+)?/|//[a-z0-9._-]+/|[a-z0-9._-]+\\.(?:sh|py|pl|rb|php)(?:[\\s;|&`]|$))"), 4, "owasp:cmd:030", ""},
	// $() 内绝对路径或 busybox 工具启动子命令：$(/bin/cat /etc/passwd)、$(busybox wget ...)。
	{regexp.MustCompile(`\$\(\s*(?:/bin/|/usr/bin/|/sbin/|/usr/sbin/|busybox\s+)[^\s)]{1,64}`), 4, "owasp:cmd:031", "$("},
	// ANSI-C 引号载荷解码后形态：normalize 已把 \xHH 还原为字符，
	// 此处匹配 $'<解码命令词><分隔/路径>（如 $'\x63\x61\x74...' → $'cat /etc/passwd'）。
	{regexp.MustCompile(`\$'\s*(?:cat|ls|id|whoami|uname|pwd|sh|bash|python|perl|ruby|php|nc|wget|curl|rm|chmod|ssh|tcpdump|printf|netstat)(?:[\s;|&` + "`" + `=]|/)`), 5, "owasp:cmd:032", "$'"},
	// 执行包装词衔接解释器：xargs sh -c、timeout 5 bash -c、nohup python -c。
	// 前缀含 '='：URL 参数值形态 key=xargs sh -c 'id' 覆盖。
	{regexp.MustCompile("(?:^|[\\s;|&`=])(?:xargs|nohup|timeout|setsid|stdbuf)(?:\\s+-\\S+)*\\s+(?:sh|bash|zsh|dash|python|perl|ruby|php|nc)(?:\\s+-c|\\s+-e|\\s+|$|[;|&`])"), 4, "owasp:cmd:033", ""},
	// PowerShell/cmd 显式启动器：cmd /c、powershell -enc、pwsh -e（Windows 向量，Linux 反代场景同样值得拦截）。
	// 前缀含 '='：URL 参数值形态 key=powershell -enc ... 覆盖。
	{regexp.MustCompile("(?i)(?:^|[\\s;|&`=])(?:cmd\\.exe|powershell(?:\\.exe)?|pwsh)\\s+(?:/c|-c|-enc|-encod|-e|/k)"), 5, "owasp:cmd:034", ""},
	// \bset\s+/a 形态：cmd 批处理 set /a 算术形态（词头含空格的 shell 命令
	// truncate 判法无法带空格匹配命令词，故 battery 独立补记）。
	// score 5 单命中；反向样例 set alone、Let's set…、set /x 均不误报。
	{regexp.MustCompile(`\bset\s+/a`), 5, "owasp:cmd:035", "set /a"},
	// PHP 变量函数调用 ${@func(...)}：`${` + `@` + 函数名 + 实参括号。
	// 与 cmd:003 的 $() 形态互补（gotestwaf cmd=${@print(md5(31337))} 正是此
	// 语法）。hint `${@` 作为前置剪枝；`${@` 在自然文本与常见模板
	// （EL/OGNL/JS 模板串）中都不是合法表达式前缀，误报面可忽略。
	{regexp.MustCompile(`\$\{\s*@\s*\w+\s*\(`), 5, "owasp:cmd:036", "${@"},
	// 参数值直接是裸命令词（cmd=whoami、mdc=uname）——正常业务参数值
	// 极少使用 whoami、ifconfig 等指令名；语言名（php/java）与短歧义词
	// （id/ls/ps）不在此列，避免 lang=java 这类正常取值误报。
	{regexp.MustCompile(`(?:^|[?&;|])\w+=\s*(?:whoami|uname|ifconfig|netstat|chmod|chown|mkdir|export)\b`), 4, "owasp:cmd:037", ""},
	// 参数值以命令词 + 实参开头（cmd=cat /etc/passwd、ppp=uname -a）。
	// 实参必须是可识别的命令参数形态：URL、绝对/相对路径（/ .）、选项
	// （-x/--x）、变量（$）、引号、函数调用（md5(）、带扩展名的文件名
	// （x.txt）或完整数字命令（sleep 5）。只要求空白会把自然语言参数
	// （dt=php - mysql 标题、area=sh 后续协议文本、ls 300 lexus）误判为
	// 命令；`-` 后必须紧跟选项字符，数字后必须是结束边界。全语料统计
	// 白侧 3 条均为扫描器噪声。
	{regexp.MustCompile(`(?:^|[?&;|])\w+=\s*(?:id|bash|sh|zsh|dash|cat|ls|pwd|wget|curl|nc|echo|python|perl|php|node|java|ps|find|grep|sleep|kill|rm|env)\s+(?:https?://|/|-[-\w]|\.|\$|'|"|[\w.-]{1,32}\(|[\w-]{1,32}\.[a-z0-9]{1,5}\b|\d+(?:$|[&;|]))`), 4, "owasp:cmd:038", ""},
	// 解释器直接执行绝对路径脚本（bash /tmp/x、sh /tmp/jaws）：落地即执行，
	// 与 cmd:001 的「分隔符 + 命令词」互补，覆盖参数值内联形态。
	{regexp.MustCompile(`(?:^|[\s;|&=])(?:bash|sh|zsh|dash)\s+/`), 4, "owasp:cmd:039", ""},
	// 命令输出哈希/编码回显探测（echo -n 999|md5sum、xxd|base64），
	// 用于无回显 RCE 的结果验证。
	{regexp.MustCompile(`\|\s*(?:md5sum|sha1sum|sha256sum|base64)\b`), 4, "owasp:cmd:040", ""},
	// SCM 客户端参数注入写 webshell（ZenTao：SCM=Subversion&client=echo <串>// > ../../www/x.txt）：
	// 回显内容后接 // 与相对路径重定向是该利用链的固定构造。全语料黑 16 / 白 0。
	{regexp.MustCompile(`(?:^|[\s;|&])echo\s+[^\s<>|&;]{4,}//\s*>\s*\.\./`), 5, "owasp:cmd:041", ""},
}

func shouldScanCmdPattern(s string, p owaspPattern, gate *scanGate) bool {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !gate.hintPass(p, s) || !gate.patternGateBitsOnly(p, s) {
		return false
	}
	if strings.IndexByte(s, '`') < 0 {
		switch p.id {
		case "owasp:cmd:002", "owasp:cmd:018", "owasp:cmd:023", "owasp:cmd:024":
			return false
		}
	}
	switch p.id {
	case "owasp:cmd:001":
		return hasShellCommandAfterCmdSeparator(s)
	case "owasp:cmd:002", "owasp:cmd:024":
		return strings.Contains(s, "`")
	case "owasp:cmd:003", "owasp:cmd:022":
		return strings.Contains(s, "$(")
	case "owasp:cmd:004":
		return strings.Contains(s, ">") && strings.Contains(s, "/")
	case "owasp:cmd:006":
		return strings.Contains(s, "%00") || strings.Contains(s, "\x00") || strings.Contains(s, "%0a") || strings.Contains(s, "%0d") || strings.Contains(s, "\x0a") || strings.Contains(s, "\x0d")
	case "owasp:cmd:007":
		return hasDiscoveryCommandBeforeSemicolon(s)
	case "owasp:cmd:008":
		return hasShellCommandAfterPipe(s)
	case "owasp:cmd:015":
		return hasPipeAfterCmdOutputTransform(s)
	case "owasp:cmd:010":
		return hasEnvAssignmentBeforeCommand(s)
	case "owasp:cmd:011":
		return hasShellCommandAfterLogicalSeparator(s)
	case "owasp:cmd:013":
		return strings.Contains(s, "<<<")
	case "owasp:cmd:014":
		return strings.Contains(s, "$'")
	case "owasp:cmd:016":
		return strings.ContainsAny(s, "\r\n")
	case "owasp:cmd:018":
		return hasEmptyBacktickSplit(s)
	case "owasp:cmd:023":
		// 收紧为「去掉空反引号对后构成命令词」（拆字绕过形态）。原前置
		// hasEmptyBacktickSplit 与正则 \b\w+``\w+\b 等价（都只要求存在一对空
		// 反引号），对两侧内容无任何要求，随机数据凑出 x``y 即命中。
		return backtickPairCommandWord(s)
	case "owasp:cmd:019":
		return strings.Contains(s, "touch") || strings.Contains(s, "rm")
	case "owasp:cmd:020":
		return strings.Contains(s, "--")
	case "owasp:cmd:021":
		return strings.Contains(s, "${ifs}")
	case "owasp:cmd:025":
		return strings.Contains(s, "$@")
	case "owasp:cmd:026":
		return strings.Contains(s, "ifs")
	case "owasp:cmd:027":
		return strings.Contains(s, "export")
	case "owasp:cmd:028":
		return strings.Contains(s, "env -i")
	case "owasp:cmd:029":
		return hasSplitCmdWord(s)
	case "owasp:cmd:033":
		if !containsAnyCmdWord(s, "xargs", "nohup", "timeout", "setsid", "stdbuf") {
			return false
		}
		return containsAnyCmdWord(s, "sh", "bash", "zsh", "dash", "python", "perl", "ruby", "php", "nc")
	case "owasp:cmd:034":
		return containsASCIIFoldAny(s,
			"cmd.exe", "powershell.exe", "powershell", "pwsh")
	case "owasp:cmd:035":
		return strings.Contains(s, "set") && strings.Contains(s, "/a")
	case "owasp:cmd:036":
		return strings.Contains(s, "${@")
	case "owasp:cmd:031":
		return strings.Contains(s, "$(")
	case "owasp:cmd:032":
		return strings.Contains(s, "$'")
	default:
		return true
	}
}

func hasScanIndexOfSplits(s string) bool {
	for i := 1; i+1 < len(s); i++ {
		c := s[i]
		if c != '\'' && c != '"' && c != '\\' {
			continue
		}
		if isASCIILetter(s[i-1]) && isASCIILetter(s[i+1]) {
			return true
		}
	}
	return false
}

// splitCmdWords 是 cmd:029 正则中的拆字命令词集合。
var splitCmdWords = []string{"whoami", "cat", "id", "ls", "wget"}

// hasSplitCmdWord 检测界字符包围的拆字命令词（形如 w'h'o'a'm'i）。
//
// cmd:029 的正则以 (?:^|[\s;|&`=]) 开头、以 (?:[\s;|&`]|$) 结尾，
// 无法提取字面量前缀，会在大目标上逐位置回溯。这里用单次线性扫描
// 判定同样的必要条件，把正则留给真正可能的候选。
//
// @param s 已小写化的检测目标。
// @return 是否存在拆字命令词形态。
func hasSplitCmdWord(s string) bool {
	for i := 0; i < len(s); i++ {
		if i > 0 && !isCmdPreBoundary(s[i-1]) {
			continue
		}
		switch s[i] {
		case 'w', 'c', 'i', 'l':
		default:
			continue
		}
		for _, w := range splitCmdWords {
			if splitCmdWordAt(s, i, w) {
				return true
			}
		}
	}
	return false
}

// splitCmdWordAt 判断 s[i:] 是否以 word 的拆字形式开头。
//
// 拆字形式要求词内每个字母之间至少一个 ' " \ 分隔符，且词后是
// 命令行后界（空白、; | & ` 或串尾）。
//
// @param s    已小写化的检测目标。
// @param i    候选起始下标。
// @param word 待匹配的命令词。
// @return 是否匹配。
func splitCmdWordAt(s string, i int, word string) bool {
	for k := 0; k < len(word); k++ {
		if i >= len(s) || s[i] != word[k] {
			return false
		}
		i++
		if k == len(word)-1 {
			break
		}
		if i >= len(s) {
			return false
		}
		if c := s[i]; c != '\'' && c != '"' && c != '\\' {
			return false
		}
		for i < len(s) {
			c := s[i]
			if c != '\'' && c != '"' && c != '\\' {
				break
			}
			i++
		}
	}
	return i >= len(s) || isCmdPostBoundary(s[i])
}

// isCmdPreBoundary 判断 b 是否属于 cmd 族正则的命令前界
// (?:^|[\s;|&`=])。
func isCmdPreBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\f', ';', '|', '&', '`', '=':
		return true
	}
	return false
}

// isCmdPostBoundary 判断 b 是否属于 cmd 族正则的命令后界
// (?:[\s;|&`]|$)。
func isCmdPostBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\f', ';', '|', '&', '`':
		return true
	}
	return false
}

// hasCurlWgetURL 检测 cmd:005 的必要形态：
// 命令前界 + wget/curl + 空白 + https?://。
//
// @param s 已小写化的检测目标。
// @return 是否存在该形态。
func hasCurlWgetURL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != 'c' && c != 'w' {
			continue
		}
		if i > 0 && !isCmdPreBoundary(s[i-1]) {
			continue
		}
		lit := "wget"
		if c == 'c' {
			lit = "curl"
		}
		if !strings.HasPrefix(s[i:], lit) {
			continue
		}
		j := i + len(lit)
		if j >= len(s) || !isRegexpSpaceByte(s[j]) {
			continue
		}
		for j < len(s) && isRegexpSpaceByte(s[j]) {
			j++
		}
		if strings.HasPrefix(s[j:], "http://") || strings.HasPrefix(s[j:], "https://") {
			return true
		}
	}
	return false
}

// cmdDownloadTargets 是 cmd:030 正则中的回连目标必要子串。
var cmdDownloadTargets = []string{
	"localhost", "127.0.0.1", "0.0.0.0", "::1", "//", ".sh", ".py", ".pl", ".rb", ".php",
}

// hasCurlWgetDownloadTarget 检测 cmd:030 的必要形态：
// 命令前界 + wget/curl + 空白，且后续存在明确的下载/回连目标。
//
// @param s 已小写化的检测目标。
// @return 是否存在该形态。
func hasCurlWgetDownloadTarget(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != 'c' && c != 'w' {
			continue
		}
		if i > 0 && !isCmdPreBoundary(s[i-1]) {
			continue
		}
		lit := "wget"
		if c == 'c' {
			lit = "curl"
		}
		if !strings.HasPrefix(s[i:], lit) {
			continue
		}
		j := i + len(lit)
		if j >= len(s) || !isRegexpSpaceByte(s[j]) {
			continue
		}
		rest := s[j:]
		for _, t := range cmdDownloadTargets {
			if strings.Contains(rest, t) {
				return true
			}
		}
	}
	return false
}

// hasEmptyBacktickSplit 判断 s 是否含两个相邻反引号，
// 即 cmd:018/023 所依赖的空反引号分隔形态。
func hasEmptyBacktickSplit(s string) bool {
	return strings.Contains(s, "``")
}

// backtickPairCommandWord 判断 s 中是否存在「移除空反引号对后构成命令词」的
// 拆字绕过形态（cmd:023 的目标形态，如 wh+双反引号+oami 即 whoami）。
//
// 判据是「把空反引号对全部移除后，该词是否为已知 shell 命令词」（词表与
// cmd:018/isShellCommandWord 同源），且空反引号对两侧必须紧邻词字符（与
// cmd:023 正则的词边界形态一致）。因此随机数据里凑出的 x+双反引号+y 不再
// 命中：它们移掉反引号后不是任何命令词；而拆字绕过形态仍然命中。
func backtickPairCommandWord(s string) bool {
	isWordByte := func(b byte) bool {
		return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
	}
	for i := 0; i < len(s); {
		if !isWordByte(s[i]) && s[i] != '`' {
			i++
			continue
		}
		start := i
		for i < len(s) && (isWordByte(s[i]) || s[i] == '`') {
			i++
		}
		run := s[start:i]
		// 形态前提：存在一对「两侧都紧邻词字符」的空反引号对（与正则
		// \b\w+``\w+\b 的命中形态一致），否则本段不是拆字候选。
		hasPair := false
		for k := 0; k+1 < len(run); k++ {
			if run[k] == '`' && run[k+1] == '`' && k > 0 && isWordByte(run[k-1]) &&
				k+2 < len(run) && isWordByte(run[k+2]) {
				hasPair = true
				break
			}
		}
		if !hasPair {
			continue
		}
		// 去掉该词里的全部反引号（含外层反引号命令替换的包裹）后仍是已知
		// 命令词，才是拆字绕过；随机拼接出来的 mK``cuK 去掉后不是命令词。
		if isShellCommandWord(strings.ReplaceAll(run, "`", ""), true) {
			return true
		}
	}
	return false
}

func containsAnyCmdWord(s string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func containsASCIIFoldAny(s string, words ...string) bool {
	for _, w := range words {
		if containsASCIIFold(s, w) {
			return true
		}
	}
	return false
}

func hasDiscoveryCommandBeforeSemicolon(s string) bool {
	for semi := strings.IndexByte(s, ';'); semi >= 0; {
		start := semi - 1
		for start >= 0 && (s[start] == ' ' || s[start] == '\t') {
			start--
		}
		end := start + 1
		for start >= 0 && isCmdWordByte(s[start]) {
			start--
		}
		word := s[start+1 : end]
		switch word {
		case "id", "uname", "whoami", "hostname", "ifconfig", "ipconfig":
			return true
		}
		next := semi + 1
		if next >= len(s) {
			return false
		}
		rest := s[next:]
		nextSemi := strings.IndexByte(rest, ';')
		if nextSemi < 0 {
			return false
		}
		semi = next + nextSemi
	}
	return false
}

func hasEnvAssignmentBeforeCommand(s string) bool {
	for eq := strings.IndexByte(s, '='); eq >= 0; {
		if hasEnvAssignmentCommandAfter(s, eq+1) {
			return true
		}
		next := eq + 1
		if next >= len(s) {
			return false
		}
		rest := s[next:]
		nextEq := strings.IndexByte(rest, '=')
		if nextEq < 0 {
			return false
		}
		eq = next + nextEq
	}
	return false
}

func hasEnvAssignmentCommandAfter(s string, offset int) bool {
	i := offset
	for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\r' && s[i] != '\n' && s[i] != '&' && s[i] != ';' && s[i] != '|' {
		i++
	}
	if i == offset || i >= len(s) {
		return false
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	start := i
	for i < len(s) && isCmdWordByte(s[i]) {
		i++
	}
	if start == i {
		return false
	}
	switch s[start:i] {
	case "cat", "id", "whoami", "curl", "wget", "bash", "sh", "python", "perl", "ruby", "php":
		return true
	default:
		return false
	}
}

func hasPipeAfterCmdOutputTransform(s string) bool {
	if strings.IndexByte(s, '|') < 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'b':
			if hasWordSpaceThenPrefixBeforePipe(s, i, "base64", "-d") {
				return true
			}
		case 'd':
			if hasWordSpaceThenPrefixBeforePipe(s, i, "dd", "if=") {
				return true
			}
		case 't':
			if hasWordSpaceThenPrefixBeforePipe(s, i, "tee", "/tmp") {
				return true
			}
		}
	}
	return false
}

func hasWordSpaceThenPrefixBeforePipe(s string, offset int, word, next string) bool {
	if offset > 0 && isCmdWordByte(s[offset-1]) {
		return false
	}
	if len(s)-offset < len(word) || s[offset:offset+len(word)] != word {
		return false
	}
	i := offset + len(word)
	if i >= len(s) || (s[i] != ' ' && s[i] != '\t' && s[i] != '\r' && s[i] != '\n') {
		return false
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	if len(s)-i < len(next) || s[i:i+len(next)] != next {
		return false
	}
	return strings.Contains(s[i+len(next):], "|")
}

func hasShellCommandAfterCmdSeparator(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ';', '|', '&':
			if hasShellCommandAtCmdOffset(s, i+1) {
				return true
			}
		}
	}
	return false
}

func hasShellCommandAfterPipe(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '|' && hasShellCommandAtCmdOffset(s, i+1) {
			return true
		}
	}
	return false
}

func hasShellCommandAfterLogicalSeparator(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if ((s[i] == '&' && s[i+1] == '&') || (s[i] == '|' && s[i+1] == '|')) && hasShellCommandAtCmdOffset(s, i+2) {
			return true
		}
	}
	return false
}

func hasShellCommandAtCmdOffset(s string, i int) bool {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	start := i
	for i < len(s) && isCmdWordByte(s[i]) {
		i++
	}
	if start == i || !isShellCommandWord(s[start:i], false) {
		return false
	}
	// `+` 是 URL 编码的空格（查询串与表单值中常见），必须视为命令词边界，
	// 否则 `|getent+hosts+example.com` 这类载荷会在只扫描原串时漏检。
	return i == len(s) || s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n' || s[i] == ';' || s[i] == '|' || s[i] == '&' || s[i] == '`' || s[i] == '+'
}

func checkCmdInjection(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !hasCmdIndicator(s, gate) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则；
	// FP 抑制器前移到 Add 之前，被抑制的规则既不计分也不参与归因。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	binaryChecked, binaryTarget := false, false
	for _, p := range cmdInjectPatterns {
		if !shouldScanCmdPattern(s, p, gate) {
			continue
		}
		if !p.re.MatchString(s) {
			continue
		}
		// 二进制 body（压缩流、PDF、图片）中，低分短模式的随机碰撞概率极高：
		// owasp:cmd:002 的 `[^`]*` 无长度上界且命令词无词边界，owasp:cmd:010
		// 的 \w+=\S+ 同理。此类目标只接受高置信度规则（如反引号紧跟命令词的
		// owasp:cmd:024），真实攻击载荷仍能检出。
		if p.score < binaryTargetMinCmdScore {
			if !binaryChecked {
				binaryTarget = isBinaryScanTarget(s)
				binaryChecked = true
			}
			if binaryTarget {
				continue
			}
		}
		if isCmdInjectionFalsePositive(s, p.id) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatCmdInject, RuleID: id, Score: total, Desc: "命令注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

func hasXXEIndicator(s string) bool {
	return strings.Contains(s, "<!doctype") ||
		strings.Contains(s, "<!entity") ||
		strings.Contains(s, "!entity") ||
		strings.Contains(s, "xsi:") ||
		reParamEntityChain.MatchString(s) ||
		strings.Contains(s, " system ") ||
		strings.Contains(s, " public ") ||
		strings.Contains(s, "xi:include") ||
		strings.Contains(s, "file://") ||
		strings.Contains(s, "expect://") ||
		strings.Contains(s, "php://")
}

var reParamEntityChain = regexp.MustCompile(`%\w+;\s*%\w+;`)

var xxePatterns = []owaspPattern{
	{regexp.MustCompile(`<!doctype[^>]{1,100}\[`), 5, "owasp:xxe:001", "<!doctype"},
	{regexp.MustCompile(`<!entity\s+\w+\s+system`), 6, "owasp:xxe:002", "<!entity"},
	{regexp.MustCompile(`<!entity\s+\w+\s+public`), 6, "owasp:xxe:003", "<!entity"},
	// 参数实体展开（排除常见 HTML 实体）
	{regexp.MustCompile(`%\w+;`), 2, "owasp:xxe:004", ""},
	// 参数实体连续引用链（%pe;%xx;）：外层实体展开又引内层实体，
	// 经典的带外外带放大器结构。
	{reParamEntityChain, 4, "owasp:xxe:009", "%"},
	{regexp.MustCompile(`system\s+['"](file|http|ftp|php|expect|data)://`), 5, "owasp:xxe:005", "system"},
	// 通过参数实体外带的盲注 OOB XXE
	{regexp.MustCompile(`<!entity\s+%\s+\w+\s+system`), 6, "owasp:xxe:006", "<!entity"},
	// XInclude 注入
	{regexp.MustCompile(`<xi:include\s+.*href\s*=`), 5, "owasp:xxe:007", "xi:include"},
	// xsi:schemaLocation / xsi:noNamespaceSchemaLocation 属性注入：
	// schemaLocation 指向 attacker 的 .xsd 时校验器据此拉取外部资源。
	{regexp.MustCompile(`(?i)xsi:(nonamespace)?schemalocation\s*=`), 4, "owasp:xxe:008", "xsi:"},
	// XSD schema 外部载荷：xs:include / xs:import / xs:schemaLocation。
	{regexp.MustCompile(`(?i)xs:(include|import|schemalocation)\b`), 4, "owasp:xxe:010", "xs:"},
	// 外部 DTD 声明：DOCTYPE + SYSTEM 标识符（<!DOCTYPE x SYSTEM "//x/x">）。
	// 与 xxe:001 的 [ 内联子集不同，外部 system 标识符单独形态。
	{regexp.MustCompile(`(?i)<!doctype\s+\w+\s+system\s+['"]`), 5, "owasp:xxe:011", "<!doctype"},
	// 外部 DTD 声明：DOCTYPE + PUBLIC 双标识符（<!DOCTYPE x PUBLIC "-//B/A/EN"
	// "http://attacker/x.dtd">）。公开标识符只是名称，真正的载荷在第二个
	// 系统标识符；只要它指向 http(s)/ftp/file 就应视为外部实体引入。
	// 标准 HTML/XHTML 的 W3C 公开标识符在 checkXXE 中单独豁免。
	{regexp.MustCompile(`(?i)<!doctype\s+[^\s>\[]+\s+public\s+["'][^"']*["']\s*["'](?:https?|ftp|file)://`), 5, "owasp:xxe:012", "<!doctype"},
}

// rePublicW3CDTD 匹配 PUBLIC 标识符指向 W3C 标准 DTD 的 DOCTYPE 声明。
// 前端框架与静态页面会原样保留 <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0
// Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">，
// 这类声明不引入攻击者可控实体，不应按 XXE 处理。
var rePublicW3CDTD = regexp.MustCompile(`(?i)<!doctype\s+[^\s>\[]+\s+public\s+["'][^"']*["']\s*["']https?://(?:www\.)?w3\.org/`)

func checkXXE(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !gate.family(famXXE, s) {
		return OWASPHit{}, false
	}
	// 抑制大型 JSON/分析载荷中的 XXE 检测：这些载荷含序列化的
	// HTML（<!DOCTYPE html>）但不含真正的 XML 实体声明。
	// 真实 XXE 攻击需要在 DTD 上下文中出现 <!ENTITY 或 SYSTEM/PUBLIC 关键词。
	// 因此使用精确模式："<!entity"（DTD 声明）、" system " 或 " public "（DTD 关键词），
	// 而非 "system" 这类会命中 JSON 属性名 ":systemId" 的子串。
	if len(s) > 500 {
		lower := strings.ToLower(s)
		hasEntity := strings.Contains(lower, "<!entity") || strings.Contains(lower, "!entity")
		hasSystem := strings.Contains(lower, " system ") || strings.Contains(lower, " system\"") || strings.Contains(lower, " system'")
		hasPublic := strings.Contains(lower, " public ") || strings.Contains(lower, " public\"") || strings.Contains(lower, " public'")
		hasXInclude := strings.Contains(lower, "xi:include")
		hasXSI := strings.Contains(lower, "xsi:")
		if !hasEntity && !hasSystem && !hasPublic && !hasXInclude && !hasXSI {
			return OWASPHit{}, false
		}
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range xxePatterns {
		if !gate.patternGate(p, s) {
			continue
		}
		if p.id == "owasp:xxe:012" && rePublicW3CDTD.MatchString(s) {
			// W3C 标准 HTML/XHTML 公开标识符不是外部实体引入。
			continue
		}
		if p.re.MatchString(s) {
			if acc == nil {
				acc = acquireOWASPAcc(threshold)
			}
			acc.Add(p.id, p.score)
			if acc.Exceeded() {
				id, total := acc.Attribution()
				return OWASPHit{Category: CatXXE, RuleID: id, Score: total, Desc: "XML 外部实体特征"}, true
			}
		}
	}
	return OWASPHit{}, false
}

// hasLDAPInjectionIndicator 在字符串含 LDAP 注入载荷特有的过滤器结构字符时返回 true。
func hasLDAPInjectionIndicator(s string) bool {
	return strings.Contains(s, ")(") ||
		strings.Contains(s, "objectclass") ||
		strings.Contains(s, ")(|") ||
		strings.Contains(s, ")(&")
}

var ldapiPatterns = []owaspPattern{
	{regexp.MustCompile(`\)\(\|`), 4, "owasp:ldap:001", ""},
	{regexp.MustCompile(`\*\)\(objectclass\s*=`), 5, "owasp:ldap:002", "objectclass"},
	{regexp.MustCompile(`\)\(\&`), 4, "owasp:ldap:003", ""},
	{regexp.MustCompile(`\(\|\(\w+\s*=\s*\*\)`), 4, "owasp:ldap:004", ""},
	{regexp.MustCompile(`admin\*\)\(`), 5, "owasp:ldap:005", "admin"},
	{regexp.MustCompile(`\)\(!\(`), 4, "owasp:ldap:006", ""},
	{regexp.MustCompile(`\(\|\s*\(uid=\*\)\s*\(\|`), 4, "owasp:ldap:007", "uid"},
	{regexp.MustCompile(`\(\w+\s*=\s*\*\)\s*\(mail=\*\)`), 4, "owasp:ldap:008", "mail"},
	// LDAP 属性 OID（userPassword 2.5.13.18 形态）。
	{regexp.MustCompile(`2\.5\.13\.18`), 4, "owasp:ldap:011", ""},
}

func checkLDAPInjection(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !gate.family(famLDAP, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range ldapiPatterns {
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
				return OWASPHit{Category: CatLDAPI, RuleID: id, Score: total, Desc: "LDAP 注入特征"}, true
			}
		}
	}
	return OWASPHit{}, false
}

var nosqliPatterns = []owaspPattern{
	{regexp.MustCompile(`\$where\b`), 5, "owasp:nosql:001", ""},
	{regexp.MustCompile(`\$ne\b`), 3, "owasp:nosql:002", ""},
	{regexp.MustCompile(`\$gt\b`), 3, "owasp:nosql:003", ""},
	{regexp.MustCompile(`\$regex\b`), 4, "owasp:nosql:004", ""},
	{regexp.MustCompile(`\$or\b\s*:\s*\[`), 3, "owasp:nosql:005", ""},
	{regexp.MustCompile(`['"]\s*,\s*\$or\s*:\s*\[`), 5, "owasp:nosql:022", "$or"},
	{regexp.MustCompile(`\$or\s*:\s*\[\s*\{[^}]*\$`), 5, "owasp:nosql:023", "$or"},
	{regexp.MustCompile(`\$or\s*:\s*\[\s*[{}]`), 4, "owasp:nosql:024", "$or"},
	{regexp.MustCompile(`\$where\s*:\s*['"][^'"]*[!=<>=+\-*\/%\d]`), 4, "owasp:nosql:018", ""},
	{regexp.MustCompile(`\binjection\.(?:insert|remove|update|find|delete|drop)\s*\(`), 5, "owasp:nosql:019", "injection."},
	{regexp.MustCompile(`\b(?:do\s*\{|while\s*\(\s*new\s+date\s*\(|var\s+date\s*=\s*new\s+date)`), 4, "owasp:nosql:020", "new date"},
	{regexp.MustCompile(`\$where\s*:\s*\{[^}]{0,100}\$function\b`), 5, "owasp:nosql:021", "$where"},
	{regexp.MustCompile(`\$exists\b`), 3, "owasp:nosql:006", ""},
	// MongoDB 聚合管道注入
	{regexp.MustCompile(`\$lookup\b\s*:\s*\{`), 4, "owasp:nosql:007", ""},
	// $where 上下文中基于 JavaScript 的 NoSQL 注入
	{regexp.MustCompile(`this\.\w+\s*(==|!=|===|!==)\s*['"]`), 3, "owasp:nosql:008", ""},
	// MongoDB $function 运算符注入
	{regexp.MustCompile(`\$function\b\s*:\s*\{`), 5, "owasp:nosql:009", ""},
	// MongoDB $accumulator 运算符注入
	{regexp.MustCompile(`\$accumulator\b\s*:\s*\{`), 4, "owasp:nosql:010", ""},
	// CouchDB _all_docs / _find / _view 注入
	{regexp.MustCompile(`(/_all_docs|/_find|/_view/)\b`), 4, "owasp:nosql:011", ""},
	// Redis 协议注入：EVAL / EVALSHA 命令
	{regexp.MustCompile(`\b(eval|evalsha)\s+['"]`), 4, "owasp:nosql:012", ""},
	// Cassandra CQL 注入：ALLOW FILTERING
	{regexp.MustCompile(`\ballow\s+filtering\b`), 3, "owasp:nosql:013", "filtering"},
	{regexp.MustCompile(`["']?\$\w+["']?\s*:\s*\{\s*["']?\$(?:ne|gt|lt|gte|lte|regex|in|nin|exists)\b`), 5, "owasp:nosql:014", ""},
	{regexp.MustCompile(`(?:^|[?&\s])\w+\[(?:\$ne|\$gt|\$lt|\$regex|\$exists)\]\s*=`), 5, "owasp:nosql:015", ""},
	{regexp.MustCompile(`["']?\$match["']?\s*:\s*\{`), 4, "owasp:nosql:016", ""},
	{regexp.MustCompile(`\$where\s*:\s*['"][^'"]{0,120}(?:sleep|function|return|this\.)`), 5, "owasp:nosql:017", ""},
	// 认证绕过形态：把字段值替换成比较操作符对象，如 {"code": {"$gt": 0}}、
	// {"resetToken": {"$ne": null}}。仅配合 0/null/空串时才是「匹配任意值」
	// 的绕过语义；真实范围查询（$gt=5）不在本规则范围内。JSON 提取器会为
	// `$` 开头的键额外产出 `k=v` 组合 target，规则匹配该形态。
	{regexp.MustCompile(`^\$(?:gt|gte|lt|lte|ne|eq|in|nin)=(?:0|null)?$`), 5, "owasp:nosql:025", "$"},
}

func hasNoSQLiIndicator(s string) bool {
	return strings.Contains(s, "$where") ||
		strings.Contains(s, "$ne") ||
		strings.Contains(s, "$gt") ||
		strings.Contains(s, "$lt") ||
		strings.Contains(s, "$gte") ||
		strings.Contains(s, "$lte") ||
		strings.Contains(s, "$regex") ||
		strings.Contains(s, "$or") ||
		strings.Contains(s, "$and") ||
		strings.Contains(s, "$exists") ||
		strings.Contains(s, "$lookup") ||
		strings.Contains(s, "$function") ||
		strings.Contains(s, "$accumulator") ||
		strings.Contains(s, "$match") ||
		strings.Contains(s, "/_all_docs") ||
		strings.Contains(s, "/_find") ||
		strings.Contains(s, "/_view/") ||
		strings.Contains(s, "allow filtering") ||
		strings.Contains(s, "evalsha") ||
		strings.Contains(s, "eval ") ||
		strings.Contains(s, "this.")
}

func checkNoSQLi(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !gate.family(famNoSQLi, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径）：此处原先已按「过阈当前规则」
	// 归因，L1 接线后由 Attribution() 统一提供，语义与原先一致（阈值只在累加器上
	// 判定一次，不存在 SetThreshold 改写归因的窗口）。FP 抑制器前移到 Add 之前。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range nosqliPatterns {
		if !gate.patternGate(p, s) {
			continue
		}
		if !p.re.MatchString(s) {
			continue
		}
		if isNoSQLiFalsePositive(s, p.id) {
			continue
		}
		if acc == nil {
			acc = acquireOWASPAcc(threshold)
		}
		acc.Add(p.id, p.score)
		if acc.Exceeded() {
			id, total := acc.Attribution()
			return OWASPHit{Category: CatNoSQLi, RuleID: id, Score: total, Desc: "NoSQL 注入特征"}, true
		}
	}
	return OWASPHit{}, false
}

var tmplInjectPatterns = []owaspPattern{
	// Jinja2 / Django / Twig
	{regexp.MustCompile(`\{\{\s*\d+\s*[\*\+\-/]\s*['"]?\d+['"]?\s*\}\}`), 5, "owasp:ssti:001", ""},
	{regexp.MustCompile(`\{\{\s*config\.`), 5, "owasp:ssti:002", "config."},
	{regexp.MustCompile(`\{\{\s*['"]\w*['"]\.__class__`), 6, "owasp:ssti:003", "__class__"},
	// ${...} Freemarker / Velocity / JSP EL
	{regexp.MustCompile(`\$\{\s*\d+\s*[\*\+\-/]\s*\d+\s*\}`), 5, "owasp:ssti:004", ""},
	{regexp.MustCompile(`\$\{.*?getclass\(\)`), 6, "owasp:ssti:005", "getclass()"},
	// <%= ... %> ERB / JSP
	{regexp.MustCompile(`<%=.*?%>`), 3, "owasp:ssti:006", ""},
	// Smarty {php}...{/php} 模板执行
	{regexp.MustCompile(`\{/?php\}`), 5, "owasp:ssti:007", "{php}"},
	// Python dunder 属性遍历（__subclasses__、__builtins__、__import__）
	{regexp.MustCompile(`__(subclasses|builtins|globals|import|init|reduce)__`), 5, "owasp:ssti:008", "__"},
	// Pebble 模板引擎：beans / getClass 访问
	{regexp.MustCompile(`\{\{.*\.(getclass|forname|getmethod|invoke)\(`), 5, "owasp:ssti:009", ""},
	// 通过 JSON 键注入实施 JavaScript 原型污染
	{regexp.MustCompile(`["'\[\{]__proto__["'\]\}]`), 5, "owasp:ssti:010", "__proto__"},
	// constructor 原型污染：{"constructor":{"prototype":...}}
	{regexp.MustCompile(`["']constructor["']\s*:\s*\{`), 5, "owasp:ssti:011", "constructor"},
	// EJS 模板 RCE：<%- process.env / require(...)  %>
	{regexp.MustCompile(`<%[-=]?\s*(process\s*\.\s*env|require\s*\(|global\s*\[)`), 5, "owasp:ssti:012", ""},
	// Handlebars/Mustache：{{lookup this ...}} 或 {{#with (...)}}
	// 分值降为 2：这些 helper 会出现在合法 Handlebars 模板中。
	{regexp.MustCompile(`\{\{\s*(lookup|with|each|log)\s+`), 2, "owasp:ssti:013", ""},
	// Tornado / Mako：${self.module / caller.body}
	{regexp.MustCompile(`\$\{self\.(module|template|loader|init_code)\b`), 5, "owasp:ssti:014", "."},
	// ThinkPHP 模板注入：{pbohome/Indexot:if(...)} 或 {pboot:if(...)}
	{regexp.MustCompile(`\{[a-z]+[:/][a-z]+:[a-z]+\(`), 5, "owasp:ssti:015", ""},
	// 带函数调用的通用模板标签：{tag:function(...)}
	{regexp.MustCompile(`\{[a-z_]+:[a-z_]+\([^}]{0,200}\)\}`), 4, "owasp:ssti:016", ""},
	// DedeCMS 模板注入：{dede:field name='source' runphp='yes'}
	{regexp.MustCompile(`\{dede:\w+\s+[^}]*runphp`), 5, "owasp:ssti:017", "{dede:"},
	// #{16*8787}：SPEL/JEXL 风格数字算术模板注入（`#{` → `\d+ 运算 \d+`）。
	{regexp.MustCompile(`#\{\s*\d+\s*[*+\-/]\s*\d+\s*\}`), 4, "owasp:ssti:018", "#{"},
	// ${ ex("id") }：FreeMarker/Velocity 模板插值函数调用（`${` 内非引号
	// 词根直接 `(`）。
	{regexp.MustCompile(`\$\{\s*['"\w.]+\s*\(`), 4, "owasp:ssti:019", "${"},
	// ${ex} 无空格紧密拼接：FreeMarker/EL 模板孤立变量调用
	//（$/{ 由 normalize 的 unicode 解码还原为 ${）。
	{regexp.MustCompile(`\$\{[\w.]+\(`), 4, "owasp:ssti:020", "${"},
	// 嵌套 `${${` 参数展开混淆：bash/FreeMarker 风格的两层以上展开。语料
	// 44 条模板注入黑样本中 30 条为该形态（path 或 User-Agent 等请求头承载，
	// 展开后指向 `ldap://<子域>.p.<域>` 的 JNDI 回调地址），全语料 140572 条
	// 白侧命中 0。既有 jndi:003（`${.*${.*}`）因非贪婪通配不跨越内层 `}` 而
	// 漏掉该形态；本规则只认「`${` 紧接着 `$` + `{`」这一确定书写形式，
	// 不引入通配回溯。
	{regexp.MustCompile(`\$\{\$\{`), 5, "owasp:ssti:021", "${${"},
}

// hasTemplateInjectionIndicator 在字符串含模板注入特有标记时返回 true，
// 对不含可疑内容的字符串跳过 14 条 SSTI 正则。
func hasTemplateInjectionIndicator(s string) bool {
	return strings.Contains(s, "{{") ||
		strings.Contains(s, "${") ||
		strings.Contains(s, "<%") ||
		strings.Contains(s, "__class__") ||
		strings.Contains(s, "__proto__") ||
		strings.Contains(s, "__subclasses__") ||
		strings.Contains(s, "__builtins__") ||
		strings.Contains(s, "__import__") ||
		// constructor 仅出现在模板上下文（{{...constructor...}}）
		(strings.Contains(s, "constructor") && (strings.Contains(s, "{{") || strings.Contains(s, "${") || strings.Contains(s, "<%"))) ||
		strings.Contains(s, "getclass(") ||
		strings.Contains(s, "java.lang.") ||
		strings.Contains(s, "process.env") ||
		strings.Contains(s, "{php}") ||
		strings.Contains(s, "$self.") ||
		strings.Contains(s, "{dede:") ||
		// #{ 算术模板注入起点（#{16*8787} 形态）。
		strings.Contains(s, "#{")
}

func checkTemplateInjection(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !gate.family(famTemplate, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range tmplInjectPatterns {
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
				return OWASPHit{Category: CatTmplInject, RuleID: id, Score: total, Desc: "模板注入特征"}, true
			}
		}
	}
	return OWASPHit{}, false
}

func checkProtocolViolation(headers map[string]string, _ int) (OWASPHit, bool) {
	if len(headers) == 0 {
		return OWASPHit{}, false
	}

	cl := ""
	te := ""
	oversizedHeader := ""
	for k, v := range headers {
		if cl == "" && equalASCIIFold(k, "content-length") {
			cl = v
		}
		if te == "" && equalASCIIFold(k, "transfer-encoding") {
			te = v
		}
		if oversizedHeader == "" && len(k)+len(v) > 8192 {
			oversizedHeader = k
		}
	}

	// HTTP 请求走私：Content-Length 与 Transfer-Encoding 同时出现。
	if cl != "" && te != "" && containsASCIIFold(te, "chunked") {
		return OWASPHit{
			Category: CatProtoViol, RuleID: "owasp:proto:001", Score: 6,
			Desc: "请求走私：CL+TE 冲突",
		}, true
	}

	// 重复 Content-Length 检测（粗略）。
	if strings.ContainsAny(cl, ",;") {
		return OWASPHit{
			Category: CatProtoViol, RuleID: "owasp:proto:002", Score: 5,
			Desc: "重复的 content-length 头",
		}, true
	}

	// 请求头长度异常（可能是缓冲区溢出探测）。
	if oversizedHeader != "" {
		return OWASPHit{
			Category: CatProtoViol, RuleID: "owasp:proto:003", Score: 4,
			Desc: "超长请求头：" + oversizedHeader,
		}, true
	}

	return OWASPHit{}, false
}

// checkMethodViolation 标记常被滥用的异常 HTTP 方法。
// 带 Origin 与 Access-Control-Request-Method 的 CORS 预检 OPTIONS 请求
// 会被排除为合法流量。
func checkMethodViolation(method string, headers map[string]string) (OWASPHit, bool) {
	switch strings.ToUpper(method) {
	case "TRACE", "TRACK":
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:004", Score: 5,
			Desc: "危险 HTTP 方法：" + method}, true
	case "CONNECT":
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:005", Score: 5,
			Desc: "CONNECT 方法（隧道）"}, true
	case "DEBUG":
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:006", Score: 5,
			Desc: "DEBUG 方法（ASP.NET 诊断）"}, true
	case "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK":
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:007", Score: 4,
			Desc: "WebDAV 方法：" + method}, true
	case "PATCH":
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:008", Score: 3,
			Desc: "PATCH 方法（不常见）"}, true
	case "OPTIONS":
		// 放行 CORS 预检请求（含 Origin + Access-Control-Request-Method）。
		origin := ""
		acrm := ""
		for k, v := range headers {
			lk := strings.ToLower(k)
			if lk == "origin" {
				origin = v
			}
			if lk == "access-control-request-method" {
				acrm = v
			}
		}
		if origin != "" && acrm != "" {
			// 合法 CORS 预检——不可疑。
			return OWASPHit{}, false
		}
		return OWASPHit{Category: CatProtoViol, RuleID: "owasp:proto:009", Score: 3,
			Desc: "OPTIONS 方法（非 CORS 预检）"}, true
	}
	return OWASPHit{}, false
}

// hasGraphQLIndicator 在字符串含 GraphQL 内省或注入标记时返回 true。
func hasGraphQLIndicator(s string) bool {
	return strings.Contains(s, "__schema") ||
		strings.Contains(s, "__type") ||
		strings.Contains(s, "__typename") ||
		strings.Contains(s, "introspectionquery")
}

var graphqlPatterns = []owaspPattern{
	// GraphQL 内省查询，带 query 关键词上下文。
	// 放宽 {0,200} 至 . 通配：强信号是 __schema/__type 本身，别名形态
	// （query { wuhu:__schema { ... } }）下早前的 [^}] 约束会漏检。
	{regexp.MustCompile(`\bquery\b.{0,200}__schema\b`), 6, "owasp:graphql:001", "__schema"},
	{regexp.MustCompile(`\bquery\b.{0,200}__type\b`), 5, "owasp:graphql:002", "__type"},
	{regexp.MustCompile(`\bintrospectionquery\b`), 5, "owasp:graphql:003", "introspectionquery"},
	// GraphQL 请求体中直接访问 __schema（如 {"query":"{ __schema { ... } }"}）
	{regexp.MustCompile(`\{\s*__schema\b`), 5, "owasp:graphql:004", "__schema"},
	// __typename 是 Apollo 客户端查询与 GraphQL spec 元字段的常态用法，
	// 不作为注入特征（见 path_traversal:017/ssrf:009 的误报修复口径）。
	{regexp.MustCompile(`\{\s*__type\b`), 5, "owasp:graphql:005", "__type"},
	// GraphQL 批量攻击：operation 数组
	{regexp.MustCompile(`\[\s*\{\s*"query"\s*:`), 4, "owasp:graphql:006", ""},
	// GraphQL 指令滥用：@skip/@include 携带变量注入
	{regexp.MustCompile(`@(skip|include)\s*\(\s*if\s*:\s*\$`), 3, "owasp:graphql:007", ""},
	// GraphQL 订阅滥用
	{regexp.MustCompile(`\bsubscription\b\s*\{`), 3, "owasp:graphql:008", "subscription"},
}

func checkGraphQLi(s string, threshold int, gate *scanGate) (OWASPHit, bool) {
	if gate == nil {
		gate = scanGateOf(s)
	}
	if !gate.family(famGraphQL, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range graphqlPatterns {
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
				return OWASPHit{Category: CatGraphQLi, RuleID: id, Score: total, Desc: "GraphQL 内省/注入特征"}, true
			}
		}
	}
	return OWASPHit{}, false
}
