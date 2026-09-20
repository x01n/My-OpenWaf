package owasp

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// decodeJSEscapesReference 是池化改造前的 strings.Builder 版实现，
// 仅供测试用于证明 decodeJSEscapesPooled 与其逐字节等价。
// 请勿在生产代码中调用。
func decodeJSEscapesReference(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		switch s[i+1] {
		case 'x', 'X':
			if i+3 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 4
					continue
				}
			}
		case 'u', 'U':
			if i+2 < len(s) && s[i+2] == '{' {
				end := strings.IndexByte(s[i+3:], '}')
				if end > 0 && end <= 6 {
					hex := s[i+3 : i+3+end]
					if v, err := strconv.ParseUint(hex, 16, 32); err == nil {
						var buf [4]byte
						n := utf8.EncodeRune(buf[:], rune(v))
						b.Write(buf[:n])
						i = i + 3 + end + 1
						continue
					}
				}
			} else if i+5 < len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
					var buf [4]byte
					n := utf8.EncodeRune(buf[:], rune(v))
					b.Write(buf[:n])
					i += 6
					continue
				}
			}
		default:
			if s[i+1] >= '0' && s[i+1] <= '7' {
				end := i + 2
				for end < len(s) && end < i+4 && s[end] >= '0' && s[end] <= '7' {
					end++
				}
				if v, err := strconv.ParseUint(s[i+1:end], 8, 8); err == nil {
					b.WriteByte(byte(v))
					i = end
					continue
				}
			}
		}
		// Not a recognized escape — keep the backslash.
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

var jsEscapeEquivFixtures = []string{
	"",
	"\\",
	"\\\\",
	"plain text with no escapes",
	"\\x41\\x42\\x43",
	"\\X4a\\X4B",
	"\\xZZ",
	"\\x4",
	"\\u0061\\u0062",
	"\\U0041",
	"\\u{61}\\u{1F600}",
	"\\u{}",
	"\\u{1234567}",
	"\\u{zz}",
	"\\101\\102\\103",
	"\\0",
	"\\8",
	"\\400",
	"\\377",
	"window[\\x27alert\\x27](1)",
	"a\\x41b\\u0042c\\103d\\u{44}e",
	"trailing backslash at end\\",
	"\\x00\\x01\\x7f\\xff",
	// surrogate / 超出 MaxRune / 边界码点：验证 utf8.AppendRune 与 utf8.EncodeRune 的
	// RuneError 回退行为一致。
	"\\ud800",
	"\\udfff",
	"\\uffff",
	"\\u0000",
	"\\u{0}",
	"\\u{d800}",
	"\\u{dfff}",
	"\\u{10ffff}",
	"\\u{110000}",
	"\\u{ffffff}",
}

// TestDecodeJSEscapesPooledMatchesReference 以固定样本加随机样本证明池化实现与原实现输出一致。
func TestDecodeJSEscapesPooledMatchesReference(t *testing.T) {
	for _, in := range jsEscapeEquivFixtures {
		if got, want := decodeJSEscapesPooled(in), decodeJSEscapesReference(in); got != want {
			t.Fatalf("decodeJSEscapesPooled(%q) = %q, reference = %q", in, got, want)
		}
	}

	alphabet := []byte("\\\\xXuU{}0123456789abcdefABCDEF <>'\"();,.=&%+/-_z")
	rng := rand.New(rand.NewSource(20260726))
	for iter := 0; iter < 200000; iter++ {
		n := rng.Intn(48)
		var sb strings.Builder
		for j := 0; j < n; j++ {
			sb.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		in := sb.String()
		if got, want := decodeJSEscapesPooled(in), decodeJSEscapesReference(in); got != want {
			t.Fatalf("iter %d: decodeJSEscapesPooled(%q) = %q, reference = %q", iter, in, got, want)
		}
	}
}

// TestDecodeJSEscapesPooledResultNotAliasedToPool 验证返回值不指向池化缓冲：
// 先收集返回值，再用大量不同长度的调用反复复用并覆写池中缓冲，最后校验早先的返回值未被破坏。
func TestDecodeJSEscapesPooledResultNotAliasedToPool(t *testing.T) {
	got := make([]string, 0, len(jsEscapeEquivFixtures))
	want := make([]string, 0, len(jsEscapeEquivFixtures))
	for _, in := range jsEscapeEquivFixtures {
		got = append(got, decodeJSEscapesPooled(in))
		want = append(want, strings.Clone(decodeJSEscapesReference(in)))
	}
	for i := 1; i <= 256; i++ {
		_ = decodeJSEscapesPooled(strings.Repeat("\\x5a", i))
	}
	for i, in := range jsEscapeEquivFixtures {
		if got[i] != want[i] {
			t.Fatalf("input %q: retained result %q was overwritten, want %q", in, got[i], want[i])
		}
	}
}

// TestNormalizeWithDecodeTargetResultNotAliasedToPool 对 normalizeWithDecodeTarget 的
// acc 累积缓冲做同样的别名检查，覆盖 found=true（有 base64 解码结果）的分支。
func TestNormalizeWithDecodeTargetResultNotAliasedToPool(t *testing.T) {
	got := make([]string, 0, len(normalizeBenchCases))
	want := make([]string, 0, len(normalizeBenchCases))
	for _, tc := range normalizeBenchCases {
		got = append(got, normalizeWithDecodeTarget(tc.raw, tc.queryPlusAsSpace))
	}
	for _, tc := range normalizeBenchCases {
		want = append(want, strings.Clone(normalizeWithDecodeTarget(tc.raw, tc.queryPlusAsSpace)))
	}
	// 用递增长度的 payload 反复占用并覆写池中缓冲。
	for i := 1; i <= 200; i++ {
		_ = normalizeWithDecodeTarget("q="+strings.Repeat("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg", i%5+1)+strings.Repeat("a", i), true)
	}
	for i, tc := range normalizeBenchCases {
		if got[i] != want[i] {
			t.Fatalf("case %s: retained result was overwritten\n got=%q\nwant=%q", tc.name, got[i], want[i])
		}
	}
}
