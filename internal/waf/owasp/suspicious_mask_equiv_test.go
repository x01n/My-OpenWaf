package owasp

import (
	"math/rand"
	"testing"
)

// refSuspiciousContentEquiv reconstructs hasSuspiciousContent "before keyword bucketization":
// byte-table scan plus a literal keyword chain (refSuspiciousKeywordsMaskEquiv lives in
// mask_equiv_test.go and is the pre-mask reference). The char table is untouched by the
// keyword bucketization, so both sides share it — the contrast is limited to
// hasSuspiciousKeywords vs its literal reference, composed into the same entry function.
func refSuspiciousContentEquiv(s string) bool {
	for i := 0; i < len(s); i++ {
		if suspiciousCharSet[s[i]] {
			return true
		}
	}
	return refSuspiciousKeywordsMaskEquiv(s)
}

// TestHasSuspiciousContentKeywordsGlue verifies hasSuspiciousContent == char-table ∨ keywords
// over fixed shapes and every suspKeywordMaskEquivLiterals literal plus its single-byte
// truncations, so a truncation that shifts into a shorter table word is caught per input.
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

// TestHasSuspiciousContentRandomGlue fuzzes the composed entry over shell-flavored random
// strings; each input must agree between the literal-chain reference and the mask build.
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
