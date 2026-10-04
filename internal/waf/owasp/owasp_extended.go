package owasp

import (
	"path/filepath"
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

func shouldScanSSRFPattern(s string, p owaspPattern) bool {
	if p.hint != "" && !strings.Contains(s, p.hint) {
		return false
	}
	switch p.id {
	case "owasp:ssrf:004":
		return strings.Contains(s, "10.")
	case "owasp:ssrf:005":
		return strings.Contains(s, "172.")
	case "owasp:ssrf:006":
		return strings.Contains(s, "192.168.")
	case "owasp:ssrf:007":
		return strings.Contains(s, "127.") || strings.Contains(s, "localhost")
	case "owasp:ssrf:008":
		return strings.Contains(s, "::1") || strings.Contains(s, "[::") || strings.Contains(s, "0.0.0.0")
	case "owasp:ssrf:009":
		return strings.Contains(s, "0x")
	case "owasp:ssrf:010":
		return strings.Contains(s, "file://") || strings.Contains(s, "gopher://") || strings.Contains(s, "dict://") || strings.Contains(s, "ldap://") || strings.Contains(s, "sftp://") || strings.Contains(s, "tftp://") || strings.Contains(s, "php://") || strings.Contains(s, "expect://") || strings.Contains(s, "phar://")
	case "owasp:ssrf:011", "owasp:ssrf:023":
		return strings.Contains(s, "http://") || strings.Contains(s, "https://")
	case "owasp:ssrf:020":
		return strings.Contains(s, "0177.") || strings.Contains(s, "http://0") || strings.Contains(s, "https://0")
	case "owasp:ssrf:021":
		return strings.Contains(s, ".nip.io") || strings.Contains(s, ".xip.io") || strings.Contains(s, ".sslip.io")
	default:
		return true
	}
}

func checkSSRF(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famSSRF, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	// SSRF 无独立抑制器（isSSRFFalsePositive 由调用方执行），此处只做归因替换。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range ssrfPatterns {
		if !shouldScanSSRFPattern(s, p) {
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
	{regexp.MustCompile("[;|&]\\s*(ls|cat|id|whoami|uname|pwd|ps|wget|curl|nc|bash|sh|echo|rm|chmod|chown|ping|touch|kill|python|perl|ruby|php|node|java|nslookup|dig|ssh|tcpdump|printf|netstat|getent|set)(?:[\\s;|&`]|$)"), 5, "owasp:cmd:001", ""},
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
	// 管道接到 shell 命令——同样用 (?:[\s;|&`]|$) 修正以避免 URL 参数误报
	{regexp.MustCompile("\\|+\\s*(cat|ls|id|whoami|uname|pwd|ps|wget|curl|nc|bash|sh|ping|nslookup|dig|echo|head|tail|more|less|find|grep|awk|sed|base64|python|perl|ruby|php|node|java|ssh|tcpdump|printf|netstat|getent|set)(?:[\\s;|&`]|$)"), 5, "owasp:cmd:008", ""},
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
	{regexp.MustCompile("`\\s*(ping|curl|wget|whoami|id|cat|ls|touch|rm|chmod|nc|nslookup|dig|python|perl|ruby|php|bash|sh|uname|ssh|tcpdump|printf|netstat)\\b"), 5, "owasp:cmd:024", ""},
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
}

func shouldScanCmdPattern(s string, p owaspPattern) bool {
	if p.hint != "" && !strings.Contains(s, p.hint) {
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
	case "owasp:cmd:005":
		return strings.Contains(s, "wget") || strings.Contains(s, "curl")
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
		return hasScanIndexOfSplits(s)
	case "owasp:cmd:030":
		return strings.Contains(s, "curl") || strings.Contains(s, "wget")
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
	return i == len(s) || s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n' || s[i] == ';' || s[i] == '|' || s[i] == '&' || s[i] == '`'
}

func checkCmdInjection(s string, threshold int) (OWASPHit, bool) {
	if !hasCmdIndicator(s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则；
	// FP 抑制器前移到 Add 之前，被抑制的规则既不计分也不参与归因。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	binaryChecked, binaryTarget := false, false
	for _, p := range cmdInjectPatterns {
		if !shouldScanCmdPattern(s, p) {
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
}

func checkXXE(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famXXE, s) {
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
		if !owaspPatternGatePass(p, s) {
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

func checkLDAPInjection(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famLDAP, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range ldapiPatterns {
		if !owaspPatternGatePass(p, s) {
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

func checkNoSQLi(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famNoSQLi, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径）：此处原先已按「过阈当前规则」
	// 归因，L1 接线后由 Attribution() 统一提供，语义与原先一致（阈值只在累加器上
	// 判定一次，不存在 SetThreshold 改写归因的窗口）。FP 抑制器前移到 Add 之前。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range nosqliPatterns {
		if !owaspPatternGatePass(p, s) {
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

func checkTemplateInjection(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famTemplate, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range tmplInjectPatterns {
		if !owaspPatternGatePass(p, s) {
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

func checkJNDI(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famJNDI, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range jndiPatterns {
		if !owaspPatternGatePass(p, s) {
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
	{regexp.MustCompile(`\r\n\s*(set-cookie|location|content-type|x-[\w-]+)\s*:`), 6, "owasp:crlf:001", ""},
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
	{regexp.MustCompile(`(?i)(?:^|[\r\n])[ \t]*(?:(?:to|cc|bcc|subject)\s*:\s*\S+@\S+|rcpt\s+to\s*:|quit[ \t]*(?:[\r\n]|$)|v\d+\s+(?:capability|fetch|select|login|logout|noop)\b)`), 4, "owasp:crlf:008", ""},
	// 空白折叠后的协议命令：base64/URL 解码出的 \r\nV100 CAPABILITY 等经
	// normalize 折叠为 " v100 capability ..."，行界锁失效。折叠后的行首
	// 由空白分隔词锚定：v\d{2,3} 必须紧跟协议命令词，且前一个是空格
	//（原行界位置）或串首。
	{regexp.MustCompile(`(?i)(?:^|[\s])(?:v\d{2,3}\s+(?:capability|fetch|select|login|logout|noop)\b|(?:rcpt\s+to|quit)\s*(?:[;:\s]|$))`), 4, "owasp:crlf:010", ""},
}

func hasCRLFIndicator(s string) bool {
	return strings.Contains(s, "%0d") ||
		strings.Contains(s, "%0a") ||
		strings.Contains(s, "\r") ||
		strings.Contains(s, "\n") ||
		strings.Contains(s, "set-cookie:") ||
		strings.Contains(s, "location:") ||
		strings.Contains(s, "content-type:")
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
		strings.Contains(s, "deserializ")
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

func checkCRLF(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famCRLF, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则；
	// FP 抑制器前移到 Add 之前，被抑制的规则既不计分也不参与归因。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range crlfPatterns {
		if !owaspPatternGatePass(p, s) {
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
}

func checkExprLang(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famEL, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则；
	// FP 抑制器前移到 Add 之前，被抑制的规则既不计分也不参与归因。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range exprLangPatterns {
		if !owaspPatternGatePass(p, s) {
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
}

func checkDeserialization(s string, threshold int) (OWASPHit, bool) {
	// 直接检查二进制 Java 序列化魔数字节
	if strings.Contains(s, "\xac\xed\x00\x05") {
		return OWASPHit{Category: CatDeserial, RuleID: "owasp:deser:001", Score: 5, Desc: "Java 序列化魔数"}, true
	}
	if !hasACIndicator(famDeser, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则；
	// FP 抑制器前移到 Add 之前，被抑制的规则既不计分也不参与归因。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range deserialPatterns {
		if !owaspPatternGatePass(p, s) {
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

func checkGraphQLi(s string, threshold int) (OWASPHit, bool) {
	if !hasACIndicator(famGraphQL, s) {
		return OWASPHit{}, false
	}
	// 归因交由 score.Accumulator（「首次跨阈」口径），不再取首个命中规则。
	var acc *score.Accumulator
	defer func() { releaseOWASPAcc(acc) }()
	for _, p := range graphqlPatterns {
		if !owaspPatternGatePass(p, s) {
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
