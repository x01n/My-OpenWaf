package gm

import (
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/sm4"
)

// TestGCMStandardVector 是 SM4-GCM 互操作判据（永久回归）：
// sm4.NewCipher(key16) + cipher.NewGCM（Go 官方 NIST 800-38D 通用实现）
// 产出的 ct+tag 必须与本包 sm4GCM 管套逐字节一致。固定输入（key/nonce/
// aad/plain），任何实现回归都会被该判据捕获。
func TestGCMStandardVector(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	aad := []byte{'O', 'W', 'V', 'E', 0x02, 0x01, 0x00, 64}
	plain, _ := hex.DecodeString(`{"webdriver":false,"chrome_present":true,"plugins_count":5,"languages":"zh-CN","screen_width":1920,"screen_height":1080,"hardware_concurrency":8,"color_depth":24,"platform":"Linux","web_assembly":true}`)

	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	refAEAD, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	want := refAEAD.Seal(nil, nonce, plain, aad)

	got := testSeal(t, key, nonce, plain, aad)
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("sm4-gcm mismatch:\ngot  %x\nwant %x", got, want)
	}
	if _, err := testOpen(t, key, nonce, want, aad); err != nil {
		t.Fatalf("open ref ct: %v", err)
	}
}

func testSeal(t *testing.T, key, nonce, plain, aad []byte) []byte {
	t.Helper()
	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := newGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return g.Seal(nonce, plain, aad)[gcmStandardNonceSize:]
}

func testOpen(t *testing.T, key, nonce, sealed, aad []byte) ([]byte, error) {
	t.Helper()
	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	g, err := newGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return g.Open(nonce, sealed, aad)
}
