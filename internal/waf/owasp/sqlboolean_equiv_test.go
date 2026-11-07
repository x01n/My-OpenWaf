package owasp

import (
	"math/rand"
	"strings"
	"testing"
)

// TestSQLBooleanComparisonKindsEquiv 直接对拍合并扫描与三个独立判定函数：
// sqli:010/011/036 共用一次扫描后，每类结果必须与剪枝前完全一致。
func TestSQLBooleanComparisonKindsEquiv(t *testing.T) {
	check := func(s string) {
		t.Helper()
		numeric, quoted, emptyQuoted := sqlBooleanComparisonKinds(s)
		if want := hasSQLBooleanNumericComparison(s); numeric != want {
			t.Fatalf("numeric 偏差 %q：合并=%v 参照=%v", s, numeric, want)
		}
		if want := hasSQLBooleanQuotedComparison(s); quoted != want {
			t.Fatalf("quoted 偏差 %q：合并=%v 参照=%v", s, quoted, want)
		}
		if want := hasSQLBooleanEmptyQuotedComparison(s); emptyQuoted != want {
			t.Fatalf("emptyQuoted 偏差 %q：合并=%v 参照=%v", s, emptyQuoted, want)
		}
	}

	fixed := []string{
		"", "or", "and", "or 1=1", "and 1=1", "or1=1", "and1=1",
		"or 1 = 1", "or 1= 1", "or 1 =1", "and 12=34",
		"or 'a'='a'", `or "a"="b"`, "or'a'='a'", `or"a"="b"`,
		"or ''=''", `or ""=""`, "or '' = ''", "or''=''",
		"or ''=1", "or 1=''", "or 'a'=1", "or 1='a'",
		"x or 1=1 and 2=2", "xor 1=1", "&&or 1=1",
		"and 'a' = 'a' or 1=1", "OR 1=1", "AND 1=1",
		"or\t1=1", "\nand 1=1", "or\n'x'='y'",
		"or ''''=''''", "or \"\"\"\"=\"\"\"\"",
		"order by 1", "android 1=1", "storm 1=1",
		"or 1.5=1.5", "or -1=1", "or +1=1",
		"or 'a b'='a b'", "or 'a' = \"a\"", "or '='=",
		"or=='==", "and(1=1)", "or 1=1)", "or 1=1--",
	}
	for _, s := range fixed {
		check(s)
	}

	r := rand.New(rand.NewSource(20261106))
	alpha := []string{
		"or", "and", "OR", "AND", "or1", "and1", " ", "  ", "\t", "=", "''", `""`,
		"'", `"`, "'a'", `"b"`, "1", "12", "0", "a", "b", "x", "-", ".", "(", ")",
		"--", "/*", "#", "&", ";", "/", "%", "\n", "0x10",
	}
	for i := 0; i < 120000; i++ {
		var b strings.Builder
		for j := 0; j < 1+r.Intn(14); j++ {
			b.WriteString(alpha[r.Intn(len(alpha))])
		}
		check(b.String())
	}

	// 逐字节增删：覆盖运算符边界与引号边界附近的短串。
	for _, base := range []string{"or 1=1", "and 'a'='a'", "or ''=''", "or'a'='a'"} {
		for i := 0; i < len(base); i++ {
			check(base[:i])
			check(base[i:])
			check(base[:i] + base[i+1:])
		}
	}
}
