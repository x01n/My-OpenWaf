package owasp

import (
	"math/rand"
	"strings"
	"testing"
)

func refSQLiIndicatorMaskEquiv(s string) bool {
	return strings.ContainsAny(s, "'\"") ||
		strings.Contains(s, "--") ||
		strings.Contains(s, "/*") ||
		strings.Contains(s, "0x") ||
		strings.Contains(s, "@@") ||
		strings.Contains(s, " or ") ||
		strings.Contains(s, " and ") ||
		strings.Contains(s, "select") ||
		strings.Contains(s, "union") ||
		strings.Contains(s, "insert") ||
		strings.Contains(s, "update") ||
		strings.Contains(s, "delete") ||
		strings.Contains(s, "drop") ||
		strings.Contains(s, "alter") ||
		strings.Contains(s, "truncate") ||
		strings.Contains(s, "sleep(") ||
		strings.Contains(s, "benchmark(") ||
		strings.Contains(s, "waitfor") ||
		strings.Contains(s, "information_schema") ||
		strings.Contains(s, "outfile") ||
		strings.Contains(s, "dumpfile") ||
		strings.Contains(s, "extractvalue") ||
		strings.Contains(s, "updatexml") ||
		strings.Contains(s, "group_concat") ||
		strings.Contains(s, "group by") ||
		strings.Contains(s, "order by") ||
		strings.Contains(s, "substr(") ||
		strings.Contains(s, "substring(") ||
		strings.Contains(s, "ascii(") ||
		strings.Contains(s, "ord(") ||
		strings.Contains(s, "length(") ||
		strings.Contains(s, "count(") ||
		strings.Contains(s, "version(") ||
		strings.Contains(s, "if(") ||
		strings.Contains(s, "if (") ||
		strings.Contains(s, "concat(") ||
		strings.Contains(s, "char(") ||
		strings.Contains(s, "chr(") ||
		strings.Contains(s, "case when") ||
		strings.Contains(s, "load_file") ||
		strings.Contains(s, "xp_") ||
		strings.Contains(s, "procedure") ||
		strings.Contains(s, "having ") ||
		strings.Contains(s, "utl_http") ||
		strings.Contains(s, "utl_inaddr") ||
		strings.Contains(s, "utl_file") ||
		strings.Contains(s, "dbms_") ||
		strings.Contains(s, " like ") ||
		strings.Contains(s, "to program") ||
		strings.Contains(s, "select case") ||
		strings.Contains(s, " cast(") ||
		strings.Contains(s, " convert(")
}

func refCmdIndicatorMaskEquiv(s string) bool {
	if strings.Contains(s, "$(") ||
		strings.Contains(s, "${") ||
		strings.Contains(s, "&&") ||
		strings.Contains(s, ">>") ||
		strings.Contains(s, "%00") ||
		strings.Contains(s, "\x00") ||
		strings.Contains(s, "\n") ||
		strings.Contains(s, "\r") ||
		strings.Contains(s, "wget ") ||
		strings.Contains(s, "curl ") ||
		strings.Contains(s, "<!--#") ||
		strings.Contains(s, "$@") ||
		strings.Contains(s, "export -f") ||
		strings.Contains(s, "env -i") ||
		strings.Contains(s, "cmd.exe") ||
		strings.Contains(s, "powershell") ||
		strings.Contains(s, "pwsh") {
		return true
	}
	if strings.Contains(s, "`") {
		return true
	}
	if strings.Contains(s, "$'") {
		return true
	}
	if strings.ContainsAny(s, "|;`") && hasCmdCommandWord(s) {
		return true
	}
	if strings.ContainsAny(s, "'\"\\") && hasSplitCommandWord(s) {
		return true
	}
	for _, w := range []string{"xargs", "nohup", "timeout ", "setsid", "stdbuf", "export", "localhost", "127.0.0.1"} {
		if strings.Contains(s, w) && hasCmdCommandWord(s) {
			return true
		}
	}
	return false
}

func refSuspiciousKeywordsMaskEquiv(s string) bool {
	return strings.Contains(s, "select ") ||
		strings.Contains(s, "union ") ||
		strings.Contains(s, "insert ") ||
		strings.Contains(s, "update ") ||
		strings.Contains(s, "delete ") ||
		strings.Contains(s, "drop ") ||
		strings.Contains(s, " or ") ||
		strings.Contains(s, " and ") ||
		strings.Contains(s, "exec ") ||
		strings.Contains(s, "truncate") ||
		strings.Contains(s, "waitfor") ||
		strings.Contains(s, " having ") ||
		strings.Contains(s, "alter ") ||
		strings.Contains(s, " table ") ||
		strings.Contains(s, " from ") ||
		strings.Contains(s, " where ") ||
		strings.Contains(s, " like ") ||
		strings.Contains(s, "schema") ||
		strings.Contains(s, "database") ||
		strings.Contains(s, "sleep ") ||
		strings.Contains(s, "benchmark")
}

var suspKeywordMaskEquivLiterals = []string{
	"select ", "union ", "insert ", "update ", "delete ", "drop ", " or ", " and ",
	"exec ", "truncate", "waitfor", " having ", "alter ", " table ", " from ",
	" where ", " like ", "schema", "database", "sleep ", "benchmark",
}

var sqliMaskEquivLiterals = []string{
	"select", "union", "insert", "update", "delete", "drop", "alter", "truncate",
	"waitfor", "information_schema", "outfile", "dumpfile", "extractvalue", "updatexml",
	"group_concat", "group by", "order by", "sleep(", "benchmark(", "substr(", "substring(",
	"ascii(", "ord(", "length(", "count(", "version(", "if(", "if (", "concat(", "char(",
	"chr(", "case when", "load_file", "xp_", "procedure", "having ", "utl_http", "utl_inaddr",
	"utl_file", "dbms_", " like ", "to program", "select case", " cast(", " convert(",
	"--", "/*", "0x", "@@", " or ", " and ",
}

var cmdMaskEquivLiterals = []string{
	"$(", "${", "$@", "$'", "&&", ">>", "%00", "\x00", "\n", "\r",
	"wget ", "curl ", "<!--#", "export -f", "env -i", "cmd.exe", "powershell", "pwsh",
	"`", "| bash", "|sh", ";ls", "; id", "'a'b'c'", "\"x\"yw\"z\"", "\\p\\q\\r",
	"xargs", "nohup", "timeout ", "setsid", "stdbuf", "export", "localhost", "127.0.0.1",
	"cat /etc/passwd", "ifconfig", "python -c", "bash -i", "rm -rf /",
}

const maskEquivShellChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`()_<>@ .#\\:/%|-$'\"*&+=;\n\t~!?[]{}^,"

func TestSQLiIndicatorMaskEquivalence(t *testing.T) {
	// 逐字面量（含单字节截断变体）新旧实现逐输入比对：截断可能命中表内
	// 更短子串（如 updatexml->update），不能假设"必不命中"。
	for _, lit := range sqliMaskEquivLiterals {
		ref := refSQLiIndicatorMaskEquiv(lit)
		if got := hasSQLiIndicator(lit); got != ref {
			t.Errorf("sqli 字面量等价破坏: %q ref=%v got=%v", lit, ref, got)
		}
		for k := 0; k < len(lit); k++ {
			trunc := lit[:k] + lit[k+1:]
			if refSQLiIndicatorMaskEquiv(trunc) != hasSQLiIndicator(trunc) {
				t.Errorf("sqli 删字节等价破坏: %q -> %q", lit, trunc)
			}
		}
	}
	if !hasSQLiIndicator("'") || !hasSQLiIndicator(`"`) {
		t.Error("引号单字符必须命中 hasSQLiIndicator")
	}
	rng := rand.New(rand.NewSource(2026))
	for i := 0; i < 150000; i++ {
		n := rng.Intn(90)
		b := make([]byte, n)
		for j := range b {
			b[j] = maskEquivShellChars[rng.Intn(len(maskEquivShellChars))]
		}
		s := string(b)
		if refSQLiIndicatorMaskEquiv(s) != hasSQLiIndicator(s) {
			t.Fatalf("sqli 掩码 vs 逐条等价破坏: s=%q", s)
		}
	}
}

func TestSuspiciousKeywordsMaskEquivalence(t *testing.T) {
	// 逐字面量与删字节变体逐输入比对（截断可能命中表内更短子串）。
	for _, lit := range suspKeywordMaskEquivLiterals {
		if refSuspiciousKeywordsMaskEquiv(lit) != hasSuspiciousKeywords(lit) {
			t.Errorf("susp kw 字面量等价破坏: %q", lit)
		}
		for k := 0; k < len(lit); k++ {
			trunc := lit[:k] + lit[k+1:]
			if refSuspiciousKeywordsMaskEquiv(trunc) != hasSuspiciousKeywords(trunc) {
				t.Errorf("susp kw 删字节等价破坏: %q -> %q", lit, trunc)
			}
		}
	}
	rng := rand.New(rand.NewSource(2028))
	for i := 0; i < 120000; i++ {
		n := rng.Intn(90)
		b := make([]byte, n)
		for j := range b {
			b[j] = maskEquivShellChars[rng.Intn(len(maskEquivShellChars))]
		}
		s := string(b)
		if refSuspiciousKeywordsMaskEquiv(s) != hasSuspiciousKeywords(s) {
			t.Fatalf("susp kw 掩码 vs 逐条等价破坏: s=%q", s)
		}
	}
}

func TestCmdIndicatorMaskEquivalence(t *testing.T) {
	// 段 4/6 是"前提字面量与命令词的合取"：单独词（xargs 等不在 46 词表）
	// 旧实现即为 false，新旧逐输入比对即可，不做"必命中"假设。
	for _, lit := range cmdMaskEquivLiterals {
		if refCmdIndicatorMaskEquiv(lit) != hasCmdIndicator(lit) {
			t.Errorf("cmd 字面量等价破坏: %q ref=%v got=%v", lit, refCmdIndicatorMaskEquiv(lit), hasCmdIndicator(lit))
		}
	}
	// 段 4 组合命中：分离符 + 命令词。
	if !hasCmdIndicator("x=1; cat /etc/passwd") {
		t.Error("';cat' 组合必须命中")
	}
	if !hasCmdIndicator("echo x | bash -i") {
		t.Error("';bash' 组合必须命中")
	}
	rng := rand.New(rand.NewSource(2027))
	for i := 0; i < 150000; i++ {
		n := rng.Intn(90)
		b := make([]byte, n)
		for j := range b {
			b[j] = maskEquivShellChars[rng.Intn(len(maskEquivShellChars))]
		}
		s := string(b)
		if refCmdIndicatorMaskEquiv(s) != hasCmdIndicator(s) {
			t.Fatalf("cmd 掩码 vs 逐条等价破坏: s=%q", s)
		}
	}
}
