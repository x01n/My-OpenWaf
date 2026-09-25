package owasp

import (
	"regexp"
	"strings"
	"testing"
)

// backtickCmdWordLiteralList 是 backtickCmdWords 的期望词序列表（与旧正则字面量一致）。
// 由 TestBacktickCmdWordLiterals 逐项校验，与 TestBacktickRegexesByteStable 一起封闭词表漂移。
var backtickCmdWordLiteralList = []string{
	"cat", "ls", "id", "whoami", "uname", "pwd", "wget", "curl", "nc", "bash",
	"sh", "echo", "rm", "chmod", "chown", "python", "perl", "ruby", "php",
	"base64", "find", "grep", "awk", "sed", "ps", "kill", "nslookup", "dig",
	"ping", "sleep", "dd", "cp", "mv", "mkdir", "touch", "head", "tail", "sort", "xxd",
}

// 以下两个常量是重构前两条反引号正则的 .String() canonical 文本（Go regexp 输出），
// 由 go run 一次性打印后抄录，用于逐字节锁定拼装结果。
const backtickCtxCanonical = `(^|[=;|&$])\s*` + "`" + `[^` + "`" + `]*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|echo|rm|chmod|chown|python|perl|ruby|php|base64|find|grep|awk|sed|ps|kill|nslookup|dig|ping|sleep|dd|cp|mv|mkdir|touch|head|tail|sort|xxd)[^` + "`" + `]*` + "`"
const backtick002Canonical = "`" + `[^` + "`" + `]*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|echo|rm|chmod|chown|python|perl|ruby|php|base64|find|grep|awk|sed|ps|kill|nslookup|dig|ping|sleep|dd|cp|mv|mkdir|touch|head|tail|sort|xxd)[^` + "`" + `]*` + "`"

func TestBacktickCmdWordLiterals(t *testing.T) {
	got := strings.Split(backtickCmdWords, "|")
	if len(got) != len(backtickCmdWordLiteralList) {
		t.Fatalf("backtickCmdWords 词数 = %d，期望 %d", len(got), len(backtickCmdWordLiteralList))
	}
	for i, w := range backtickCmdWordLiteralList {
		if got[i] != w {
			t.Fatalf("backtickCmdWords[%d] = %q，期望 %q", i, got[i], w)
		}
	}
	// 词表内不允许重复：重复会导致正则出现两个相同分支（行为不变但属漂移信号）。
	seen := map[string]bool{}
	for _, w := range got {
		if seen[w] {
			t.Fatalf("backtickCmdWords 出现重复词 %q", w)
		}
		seen[w] = true
	}
}

func TestBacktickRegexesByteStable(t *testing.T) {
	if got := reBacktickInjectionCtx.String(); got != backtickCtxCanonical {
		t.Fatalf("reBacktickInjectionCtx 编译文本漂移：\n got=%q\nwant=%q", got, backtickCtxCanonical)
	}
	if got := reCmd002Backtick.String(); got != backtick002Canonical {
		t.Fatalf("reCmd002Backtick 编译文本漂移：\n got=%q\nwant=%q", got, backtick002Canonical)
	}
	// 既然文本逐字节相同，两条正则的对象也应同构（同程序内重建比较，纯防御性断言）。
	if a, b := reBacktickInjectionCtx.String(), regexp.MustCompile(backtickCtxCanonical).String(); a != b {
		t.Fatal("reBacktickInjectionCtx 与 canonical 重编译不一致")
	}
}

// TestShellCommandWordMergeLock 锁定合并后的 isShellCommandWord 两路等价：
//   - fold=false 与精确词表（原 isShellCommandWord）一致，大写变体必须拒绝；
//   - fold=true 与原 isShellCommandWordASCIIFold 一致：fold 词的小写与大小写混合变体命中，
//     精确词表中 fold 词集之外的词（dd/cp/mv/od/wc/dig/xxd/tee/kill/head/tail/more/less/sort）
//     即使在 fold=true 下也不得命中。
func TestShellCommandWordMergeLock(t *testing.T) {
	exactWords := []string{
		"id", "ls", "ps", "nc", "sh", "rm", "dd", "cp", "mv", "od", "wc",
		"cat", "pwd", "php", "dig", "awk", "sed", "xxd", "tee",
		"wget", "curl", "bash", "echo", "ping", "kill", "perl", "ruby", "node", "java", "find", "grep", "head", "tail", "more", "less", "sort",
		"uname", "touch", "chmod", "chown", "mkdir", "sleep",
		"whoami", "python", "base64",
		"nslookup", "hostname", "ifconfig", "ipconfig",
	}
	exactOnly := map[string]bool{
		"dd": true, "cp": true, "mv": true, "od": true, "wc": true,
		"dig": true, "xxd": true, "tee": true,
		"kill": true, "head": true, "tail": true, "more": true, "less": true, "sort": true,
	}

	for _, w := range exactWords {
		if !isShellCommandWord(w, false) {
			t.Errorf("fold=false 应命中精确词 %q", w)
		}
		if isShellCommandWord(strings.ToUpper(w), false) {
			t.Errorf("fold=false 不应命中大写变体 %q", strings.ToUpper(w))
		}
		if isShellCommandWord("x"+w, false) || isShellCommandWord(w+"x", false) {
			t.Errorf("fold=false 不应命中带前缀/后缀的 %q", w)
		}
	}

	// fold=true：fold 词表（shellCommandWordsFold）的小写与混合大小写都要命中。
	for _, w := range shellCommandWordsFold {
		if !isShellCommandWord(w, true) {
			t.Errorf("fold=true 应命中 fold 词 %q", w)
		}
		mixed := strings.ToUpper(w[:1]) + w[1:]
		if mixed == w {
			mixed = w
		}
		if !isShellCommandWord(mixed, true) {
			t.Errorf("fold=true 应命中混合大小写 %q", mixed)
		}
		upper := strings.ToUpper(w)
		if !isShellCommandWord(upper, true) {
			t.Errorf("fold=true 应命中全大写 %q", upper)
		}
	}
	// fold=true 不得命中精确词中 fold 词集之外的词（既有行为差异也要锁死保留）。
	for _, w := range exactWords {
		if !exactOnly[w] {
			continue
		}
		if isShellCommandWord(w, true) {
			t.Errorf("fold=true 不应命中 fold 词集之外的词 %q", w)
		}
	}
	// 明显非命令词。
	for _, bad := range []string{"", "a", "zebra", "notacmd", "shell"} {
		if isShellCommandWord(bad, false) || isShellCommandWord(bad, true) {
			t.Errorf("非命令词 %q 不应命中任一路", bad)
		}
	}
}

// TestHasXSSIndicatorLiteralBackdoor 对 xssIndicatorLiteralBytes 逐项断言：
// 每个表项自身作为输入必须命中 hasXSSIndicator（拼写漂移即刻暴露），
// 并在正/负批量上整体断言（覆盖 '<' 首判、大小写折叠与括号边界）。
func TestHasXSSIndicatorLiteralBackdoor(t *testing.T) {
	for _, item := range xssIndicatorLiteralBytes {
		if !hasXSSIndicator(item) {
			t.Errorf("表项 %q 作为输入必须命中 hasXSSIndicator", item)
		}
	}
	if !hasXSSIndicator("<") {
		t.Error("'<' 单字符必须命中 hasXSSIndicator")
	}

	positives := []string{
		`name=" onmouseover="alert(1)`,
		"<script>alert(1)</script>",
		"javascript:alert(1)",
		"onclick=alert(1)",
		`"><img src=x onerror=alert(1)>`,
		"data:text/html,<script>",
		"{{7*7}}",
		"alert(document.cookie)",
		"document.cookie",
		"constructor.constructor('alert(1)')()",
		"srcdoc='<p>x</p>'",
		"+[]",
		"onafterscriptexecute=alert(1)",
	}
	for _, pos := range positives {
		if !hasXSSIndicator(pos) {
			t.Errorf("正例 %q 必须命中 hasXSSIndicator", pos)
		}
	}

	negatives := []string{
		"page=1&sort=name",
		"username=admin&password=test123",
		"connection timeout",
		"function greet() { return 1; }",
		"Content-Type: application/json",
		"host=example.com",
		"select * from users where id=1",
		`{"user":"alice"}`,
		"on",
		"location.href='/home'",
		"frame.setAttribute('src', url)",
		"expression without paren",
		"sourcedoc",
		"ALERT",               // 缺括号的纯词不命中
		"JAVASCRIPT:ALERT(1)", // 旧实现为大小写敏感 Contains：全大写形态不命中
	}
	for _, neg := range negatives {
		if hasXSSIndicator(neg) {
			t.Errorf("负例 %q 不应命中 hasXSSIndicator", neg)
		}
	}
}
