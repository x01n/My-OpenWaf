package gm

import (
	"crypto/aes"
	"encoding/hex"
	"testing"
)

// TestNISTTestVector1 是 GCM 权威判据（NIST 800-38D 测试向量 1a）：
// key=0^128、IV=0^96、P=空、A=空 → tag=58e2fccefa7e3061367f1d57a4e7455a。
func TestNISTTestVector1(t *testing.T) {
	key := make([]byte, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := newGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	sealed := g.Seal(nonce, nil, nil)
	got := hex.EncodeToString(sealed[12:])
	want := "58e2fccefa7e3061367f1d57a4e7455a"
	if got != want {
		t.Fatalf("NIST 1a: got %s want %s", got, want)
	}
}
