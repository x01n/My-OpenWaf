package owasp

import (
	"math/rand"
	"strings"
	"testing"
)

// containsWideLineTerminatorRef 是 range 逐 rune 的剪枝前实现，作为黄金参照。
func containsWideLineTerminatorRef(s string) bool {
	for _, r := range s {
		if r == 0x560D || r == 0x560A {
			return true
		}
	}
	return false
}

// TestContainsWideLineTerminatorEquiv 对拍字节序列查找与 rune 遍历：
// 固定码点、混入任意字节（含非法 UTF-8）都必须给出相同判定。
func TestContainsWideLineTerminatorEquiv(t *testing.T) {
	fixed := []string{
		"",
		"plain ascii",
		"\u560d",
		"\u560a",
		"a\u560db",
		"a\u560ab",
		"\xe5\x98\x8d",
		"\xe5\x98\x8a",
		"\xe5\x98",
		"\x98\x8d",
		"\xe5\x98\x8b",
		"\u560b\u560c",
		"\xe5\xe5\x98\x8d",
		"\xf0\xe5\x98\x8d",
		"\xff\xfe\xe5\x98\x8a",
		"\xe5\x98\x8d\xe5\x98\x8a",
	}
	for _, s := range fixed {
		if got, want := containsWideLineTerminator(s), containsWideLineTerminatorRef(s); got != want {
			t.Fatalf("%q：字节=%v rune=%v", s, got, want)
		}
	}

	r := rand.New(rand.NewSource(20261106))
	alpha := []byte{0xE5, 0x98, 0x8D, 0x8A, 0x00, 0x41, 0x80, 0xBF, 0xC0, 0xF0, 0xFF, ' ', '\n'}
	for i := 0; i < 200000; i++ {
		var b strings.Builder
		for j := 0; j < 1+r.Intn(24); j++ {
			b.WriteByte(alpha[r.Intn(len(alpha))])
		}
		s := b.String()
		if got, want := containsWideLineTerminator(s), containsWideLineTerminatorRef(s); got != want {
			t.Fatalf("%q：字节=%v rune=%v", s, got, want)
		}
	}
}
