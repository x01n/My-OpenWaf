package owasp

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// base64TokenSeenRef 是 base64TokenSeen 的 map 参照语义（剪枝前实现）。
func base64TokenSeenRef(seen map[string]bool, tok string) bool {
	if seen[tok] {
		return true
	}
	seen[tok] = true
	return false
}

// TestBase64TokenSeenMatchesMap 对随机 token 序列逐项对拍「是否已出现」。
func TestBase64TokenSeenMatchesMap(t *testing.T) {
	r := rand.New(rand.NewSource(20261106))
	var got base64TokenSeen
	ref := make(map[string]bool, 8)
	for i := 0; i < 200000; i++ {
		var tok string
		if r.Intn(3) == 0 {
			tok = "tok" + strconv.Itoa(r.Intn(40))
		} else {
			var b strings.Builder
			for j := 0; j < 1+r.Intn(24); j++ {
				b.WriteByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[r.Intn(64)])
			}
			tok = b.String()
		}
		if g, w := got.mark(tok), base64TokenSeenRef(ref, tok); g != w {
			t.Fatalf("第 %d 项 %q：线性表=%v 参照=%v", i, tok, g, w)
		}
	}
}

// TestBase64TokenSeenDegrades 覆盖超过线性阈值后的 map 退化路径：
// 前 16 项仍在切片，第 17 项起改走 map，历史项与新增项都必须正确去重。
func TestBase64TokenSeenDegrades(t *testing.T) {
	var seen base64TokenSeen
	for i := 0; i < base64TokenSeenLinearLimit+8; i++ {
		tok := "token" + strconv.Itoa(i)
		if seen.mark(tok) {
			t.Fatalf("首次记录 %q 被判为重复", tok)
		}
	}
	if seen.set == nil {
		t.Fatal("超过线性阈值后未退化到 map")
	}
	for i := 0; i < base64TokenSeenLinearLimit+8; i++ {
		tok := "token" + strconv.Itoa(i)
		if !seen.mark(tok) {
			t.Fatalf("历史 token %q 未被判为重复", tok)
		}
	}
	if seen.mark("brand-new") {
		t.Fatal("新 token 被误判为重复")
	}
}
