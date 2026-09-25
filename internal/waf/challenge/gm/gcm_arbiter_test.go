package gm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"strings"
	"testing"
)

// TestGCMMatchesStdlib 是 GCM 实现的权威判据：sm4GCM 复用 crypto/cipher.NewGCM
// 的通用路径（gcmFallback，NIST 800-38D），同一 AES key 下输出必须与标准库
// 逐字节一致（覆盖空/短/长明文、空/短/长 AAD、篡改拒绝）。
func TestGCMMatchesStdlib(t *testing.T) {
	key := []byte("0123456789abcdef")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	myGCM, err := newGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	stdGCM, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	nonce := []byte("aNonce12bytes")[:12]
	cases := []struct {
		plain string
		aad   string
	}{
		{"", ""},
		{"", "authenticated"},
		{"hello world", ""},
		{"hello world", "authenticated"},
		{strings.Repeat("x", 40), "aad-bytes"},
	}
	for i, tc := range cases {
		got := myGCM.Seal(nonce, []byte(tc.plain), []byte(tc.aad))
		want := stdGCM.Seal(nil, nonce, []byte(tc.plain), []byte(tc.aad))
		if !equalHex(got[gcmStandardNonceSize:], want) {
			t.Fatalf("case %d (pt=%q aad=%q):\ngot  %x\nwant %x",
				i, tc.plain, tc.aad, got[gcmStandardNonceSize:], want)
		}
		if _, err := myGCM.Open(nonce, got[gcmStandardNonceSize:], []byte(tc.aad)); err != nil {
			t.Fatalf("case %d open: %v", i, err)
		}
		// 篡改 tag 必拒。
		tampered := append([]byte(nil), got...)
		tampered[len(tampered)-1] ^= 0x01
		if _, err := myGCM.Open(nonce, tampered[gcmStandardNonceSize:], []byte(tc.aad)); err == nil {
			t.Fatalf("case %d tamper must be rejected", i)
		}
	}
}

func equalHex(a, b []byte) bool {
	return hex.EncodeToString(a) == hex.EncodeToString(b)
}
