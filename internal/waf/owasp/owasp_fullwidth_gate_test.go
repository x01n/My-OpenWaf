package owasp

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// sqliPatternByID 从电池表取指定规则，测试样本选择失败时立即暴露。
func sqliPatternByID(t *testing.T, id string) *owaspPattern {
	t.Helper()
	for i := range sqliPatterns {
		if sqliPatterns[i].id == id {
			return &sqliPatterns[i]
		}
	}
	t.Fatalf("规则 %s 不在 sqliPatterns 中", id)
	return nil
}

// gatedFullwidthMatch 复刻生产门语义：无 ≥0xE0 字节直接判不命中，
// 否则退回原正则判定。作为对拍中被测对象。
func gatedFullwidthMatch(re *regexp.Regexp, s string) bool {
	if !hasHighByte(s) {
		return false
	}
	return re.MatchString(s)
}

// TestFullwidthGateMatchEquiv 对拍「门 + 原语义」与纯原语义：两条全角规则的
// MatchString 判定在 10 万混合串与定向全角样例上必须逐串一致。
func TestFullwidthGateMatchEquiv(t *testing.T) {
	pat049 := sqliPatternByID(t, "owasp:sqli:049")
	pat053 := sqliPatternByID(t, "owasp:sqli:053")

	// 混合生成器：ASCII 为主，掺入全角区码点、非全角高位字节、无效 UTF-8 尾字节。
	r := rand.New(rand.NewSource(20260928))
	gen := func(n int) string {
		var b strings.Builder
		for b.Len() < n {
			switch r.Intn(12) {
			case 0:
				b.WriteRune(rune(0xFF10 + r.Intn(0x4B))) // FF10-FF5A 全角区
			case 1:
				b.WriteRune(rune(0x4E00 + r.Intn(100))) // 汉字（高位字节非 EF 起点族之外）
			case 2:
				b.WriteByte(0xE9) // é 首字节（0xE9 < 0xEF，非全角区）
			case 3:
				b.WriteByte(0xF4) // 四字节首字节
			case 4:
				b.WriteByte(0x80 + byte(r.Intn(0x40))) // 孤立尾字节（无效 UTF-8）
			default:
				b.WriteByte("select unioninsertupdatedelete abcxyz019'\"-=+()%-_/"[r.Intn(49)])
			}
		}
		return b.String()
	}

	for i := 0; i < 100000; i++ {
		s := gen(1 + r.Intn(40))
		for _, pat := range []*regexp.Regexp{pat049.re, pat053.re} {
			want := pat.MatchString(s)
			got := gatedFullwidthMatch(pat, s)
			if got != want {
				t.Fatalf("第 %d 串 %q: 门判定=%v 原判定=%v", i, s, got, want)
			}
		}
	}

	// 定向全角样例：门放行路径必须保持命中语义，ASCII 必须保持不命中语义。
	fullwidthCases := []struct {
		in      string
		want049 bool
		want053 bool
	}{
		{"ＳＥＬＥＣＴ", false, true},                                      // 全角大写六连 → 053
		{"ｓｅｌｅｃｔ", false, true},                                      // 全角小写六连 → 053
		{"１２３ select", true, false},                                  // FF10 区间三连 + ASCII select → 049
		{"ｚｚｚ select", true, false},                                  // ｚ=U+FF5A 区末码点三连 → 049
		{"\xef\xbd\x9a\xef\xbd\x99\xef\xbd\x98 select", true, false}, // ｚｙｘ 的 UTF-8 字节形式 → 049
		{"\xef\xbc\x90\xef\xbc\x91\xef\xbc\x92 union", true, false},  // ０１２ 的 UTF-8 字节形式 → 049
		{"ａｂｃ union select", true, false},                            // 全角三连 + union → 049
		{"SELECT", false, false},                                     // ASCII 必然不命中两条
		{"select * from t", false, false},                            // 普通 ASCII SQL 不受 049/053 管辖
	}
	for _, tc := range fullwidthCases {
		got049 := gatedFullwidthMatch(pat049.re, tc.in)
		got053 := gatedFullwidthMatch(pat053.re, tc.in)
		if got049 != tc.want049 {
			t.Errorf("%q 049: got=%v want=%v", tc.in, got049, tc.want049)
		}
		if got053 != tc.want053 {
			t.Errorf("%q 053: got=%v want=%v", tc.in, got053, tc.want053)
		}
	}
}

// TestFullwidthShouldScanGateEquiv 对拍生产入口 shouldScanSQLiPatternWithSignals
// 与改动前语义（containsFullwidthS 直返）：两条规则的扫描门判定必须恒等。
func TestFullwidthShouldScanGateEquiv(t *testing.T) {
	pat049 := sqliPatternByID(t, "owasp:sqli:049")
	pat053 := sqliPatternByID(t, "owasp:sqli:053")
	fullwidthS := func(s string) bool {
		return strings.Contains(s, "\xef\xbd\x93") || strings.Contains(s, "\xef\xbc\xb3")
	}
	refShouldScan := func(s string, p *owaspPattern) bool {
		return fullwidthS(s)
	}
	r := rand.New(rand.NewSource(20260928))
	for i := 0; i < 100000; i++ {
		var b strings.Builder
		for b.Len() < 1+r.Intn(40) {
			switch r.Intn(5) {
			case 0:
				b.WriteString("Ｓ")
			case 1:
				b.WriteString("ｓ")
			case 2:
				b.WriteByte(0xE9)
			case 3:
				b.WriteString("select!")
			default:
				b.WriteByte("abc XYZ019+=/%"[r.Intn(14)])
			}
		}
		s := b.String()
		signals := sqliPatternSignals{containsFullwidthS: fullwidthS(s)}
		for _, p := range []*owaspPattern{pat049, pat053} {
			got := shouldScanSQLiPatternWithSignals(s, *p, signals)
			want := refShouldScan(s, p)
			if got != want {
				t.Fatalf("第 %d 串 %q 规则 %s: 门扫描判定=%v 原判定=%v", i, s, p.id, got, want)
			}
		}
	}
}

// TestFullwidthGateBytes 字节门方向：无任何 ≥0xE0 字节的 ASCII 串门必关闭，
// 有 0xEF 前导的串门必开启，覆盖阈值 0xE0 两侧字节。
func TestFullwidthGateBytes(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"SELECT", false},
		{strings.Repeat("z", 100), false},
		{"\xdf\xbf", false}, // ß=UTF-8 0xDF 0xBF（< 0xE0，未过门）
		{"\xe0\xa0\x80", true},
		{"\xe9", true},
		{"\xef", true},
		{"\xf4", true},
		{"\xff", true},
	}
	for _, tc := range cases {
		if got := hasHighByte(tc.in); got != tc.want {
			t.Errorf("hasHighByte(%q)=%v want=%v", tc.in, got, tc.want)
		}
	}
}
