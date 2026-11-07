package ac

import (
	"math/rand"
	"strings"
	"testing"
)

/**
 * TestMatcherFlatTableEquivalence 用朴素子串搜索参考实现对拍加速结构。
 *
 * MatchAny / MatchMask / MatchMaskSlice 的语义定义就是「对每个 pattern 做一次
 * 大小写敏感的 strings.Contains」，AC 自动机只是它的加速结构。本测试在随机串、
 * 边界串与 needle 自身上逐位比对，保证扁平转移表与终态位内联不改变语义。
 */
func TestMatcherFlatTableEquivalence(t *testing.T) {
	needles := []string{
		"://", "169.254.169.254", "localhost", "%0d%0a", "set-cookie:",
		"..", "etc/", "jndi:", "${", "{{", "<%", "$where", ")(|",
		"o:", "s:", "!", "%", ":", "\r\n", "\n", "capability",
		"a", "ab", "abc", "abcd", "abcde", "bcd", "cd", "d",
	}
	b := NewBuilder()
	for _, n := range needles {
		b.AddPattern(n)
	}
	m := b.Build()
	if m.Empty() {
		t.Fatal("非空自动机不应报告 Empty")
	}
	if m.NumPatterns() != int32(len(needles)) {
		t.Fatalf("NumPatterns = %d, want %d", m.NumPatterns(), len(needles))
	}

	refMask := func(s string) Mask {
		var want Mask
		for i, n := range needles {
			if strings.Contains(s, n) {
				want.Set(int32(i))
			}
		}
		return want
	}

	inputs := []string{
		"", "a", ":", "%", "!", "${", "o:s:", "\r\n", "\n\n",
		"set-cookie: x", "//example.com", "capability", "fetch(",
		strings.Repeat("a", 5000), strings.Repeat("%", 1000),
		strings.Repeat("ab", 3000), "x" + strings.Repeat("d", 4096),
	}
	for _, n := range needles {
		inputs = append(inputs, n, "pre"+n+"post", strings.ToUpper(n))
	}
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=:;/.,?&% +\"'[]{}<>$\\|`~!@#^*()\r\n\t"
	rng := rand.New(rand.NewSource(20261009))
	for i := 0; i < 20000; i++ {
		buf := make([]byte, rng.Intn(220))
		for j := range buf {
			buf[j] = chars[rng.Intn(len(chars))]
		}
		inputs = append(inputs, string(buf))
	}

	for i, s := range inputs {
		want := refMask(s)
		wantAny := want != Mask{}
		if got := m.MatchAny(s); got != wantAny {
			t.Fatalf("MatchAny(%q) = %v, want %v (输入 #%d)", s, got, wantAny, i)
		}
		if got := m.MatchMask(s); got != want {
			t.Fatalf("MatchMask(%q) 与参考实现不一致 (输入 #%d)", s, i)
		}
	}
	for i := 0; i < len(inputs); i += 16 {
		end := min(i+16, len(inputs))
		part := inputs[i:end]
		var want Mask
		for _, s := range part {
			want.MergeFrom(refMask(s))
		}
		if got := m.MatchMaskSlice(part); got != want {
			t.Fatalf("MatchMaskSlice(@%d) 与参考实现不一致", i)
		}
	}
}

/**
 * TestMatcherLongestPatternAtTail 覆盖终态位内联最易出错的边界：
 * 命中发生在输入末尾、以及命中发生在状态刚发生 fail 转移之后。
 */
func TestMatcherLongestPatternAtTail(t *testing.T) {
	b := NewBuilder()
	b.AddPattern("abcdefgh")
	b.AddPattern("xyz")
	m := b.Build()

	cases := []struct {
		in   string
		want bool
	}{
		{"abcdefgh", true},        // 恰好结束于末尾
		{"prefix-abcdefgh", true}, // 末尾命中
		{"abcdefgh-suffix", true}, // 中部命中
		{"abcdefg", false},        // 差一个字节
		{"abcabcdefgh", true},     // fail 转移后重新命中
		{"abxabcdefgh", true},     // fail 转移跨过前缀
		{"xy", false},             // 前缀未完成
		{"zxyz", true},            // fail 后尾随命中
		{"", false},
	}
	for _, c := range cases {
		if got := m.MatchAny(c.in); got != c.want {
			t.Errorf("MatchAny(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

/**
 * TestMatcherFailPropagationPreserved 验证扁平化后 fail 链的输出继承仍然生效：
 * 后缀同时是另一 pattern 时，两者都必须在同一状态上被报告。
 */
func TestMatcherFailPropagationPreserved(t *testing.T) {
	b := NewBuilder()
	idxShort := b.AddPattern("he")
	idxLong := b.AddPattern("she")
	m := b.Build()

	// "ushers" 同时含 "she"（位置 1..3）与 "he"（位置 2..3），
	// 后者只能经 fail 链从 "she" 的输出继承而来。
	got := m.MatchMask("ushers")
	var want Mask
	want.Set(idxShort)
	want.Set(idxLong)
	if got != want {
		t.Fatalf("MatchMask(\"ushers\") 未继承 fail 链输出：got=%v want=%v", got, want)
	}
}
