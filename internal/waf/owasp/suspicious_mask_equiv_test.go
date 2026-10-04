package owasp

import (
	"math/rand"
	"testing"
)

// refSuspiciousContentEquiv 重建「关键词分桶之前」的 hasSuspiciousContent：
// 字节表扫描加字面关键词链（refSuspiciousKeywordsMaskEquiv 位于
// mask_equiv_test.go，是遮蔽前的参照实现）。
//
// 字符表未被关键词分桶改动，两侧共用，因此对比范围仅限于
// hasSuspiciousKeywords 与其字面参照，并组合进同一个入口函数。
func refSuspiciousContentEquiv(s string) bool {
	for i := 0; i < len(s); i++ {
		if suspiciousCharSet[s[i]] {
			return true
		}
	}
	return refSuspiciousKeywordsMaskEquiv(s)
}

// TestHasSuspiciousContentKeywordsGlue 校验 hasSuspiciousContent == 字符表 ∨ 关键词
// 在固定形态上的等价性，覆盖 suspKeywordMaskEquivLiterals 的每个字面及其单字节
// 截断，使「截断后恰好落进更短的表词」的情况在逐输入比对中被捕获。
func TestHasSuspiciousContentKeywordsGlue(t *testing.T) {
	cases := []string{
		";", "'", "\"", "<", "(", "/", "-", ".", "%", "=",
		"select ", "union ", "database", "waitfor",
		"hello", "hello world", "", "select*", "schema",
		"1 UNION SELECT NULL FROM users",
	}
	for _, s := range cases {
		if refSuspiciousContentEquiv(s) != hasSuspiciousContent(s) {
			t.Fatalf("hasSuspiciousContent 归队等价破坏: %q", s)
		}
	}
	for _, lit := range suspKeywordMaskEquivLiterals {
		if refSuspiciousContentEquiv(lit) != hasSuspiciousContent(lit) {
			t.Fatalf("keyword 字面量归队等价破坏: %q", lit)
		}
		for k := 0; k < len(lit); k++ {
			trunc := lit[:k] + lit[k+1:]
			if refSuspiciousContentEquiv(trunc) != hasSuspiciousContent(trunc) {
				t.Fatalf("keyword 删字节归队等价破坏: %q -> %q", lit, trunc)
			}
		}
	}
}

// TestHasSuspiciousContentRandomGlue 用 shell 风格随机串模糊测试该组合入口；
// 每个输入都必须在字面链参照与遮蔽构建之间取得一致。
func TestHasSuspiciousContentRandomGlue(t *testing.T) {
	rng := rand.New(rand.NewSource(20260930))
	for i := 0; i < 120000; i++ {
		n := rng.Intn(90)
		b := make([]byte, n)
		for j := range b {
			b[j] = maskEquivShellChars[rng.Intn(len(maskEquivShellChars))]
		}
		s := string(b)
		if refSuspiciousContentEquiv(s) != hasSuspiciousContent(s) {
			t.Fatalf("hasSuspiciousContent 随机归队等价破坏: %q", s)
		}
	}
}
