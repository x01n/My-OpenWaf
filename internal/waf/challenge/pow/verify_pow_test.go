package pow

import (
	"fmt"
	"strings"
	"testing"
)

func challengeFindShieldPoWSolution(t *testing.T, nonce string, difficulty int) (int64, string) {
	t.Helper()
	prefix := strings.Repeat("0", difficulty)
	for counter := int64(0); counter < 1_000_000; counter++ {
		hash := SHA256Hex(fmt.Sprintf("%s%d", nonce, counter))
		if strings.HasPrefix(hash, prefix) {
			return counter, hash
		}
	}
	t.Fatalf("no PoW solution found for nonce %q difficulty %d", nonce, difficulty)
	return 0, ""
}

/**
 * TestVerifyPoWRejectsMalformedInput 验证 PoW 校验对畸形输入与非法难度的处理。
 */
func TestVerifyPoWRejectsMalformedInput(t *testing.T) {
	nonce := "abc123"
	counter, hash := challengeFindShieldPoWSolution(t, nonce, 2)

	if !VerifyPoW(nonce, counter, hash, 2) {
		t.Fatal("valid PoW solution must verify")
	}
	if VerifyPoW(nonce, counter, strings.ToUpper(hash), 2) {
		t.Fatal("uppercase hash must not be accepted as a different encoding bypass")
	}
	if VerifyPoW(nonce, counter, hash, 0) {
		t.Fatal("difficulty 0 must be rejected instead of accepting zero-work solutions")
	}
	if VerifyPoW(nonce, counter, hash, -1) {
		t.Fatal("negative difficulty must be rejected")
	}
	if VerifyPoW(nonce, counter+1, hash, 2) {
		t.Fatal("hash/counter mismatch must be rejected")
	}
	if VerifyPoW(nonce, counter, "00", 2) {
		t.Fatal("truncated hash must be rejected")
	}
	if VerifyPoW(nonce, counter, "00"+strings.Repeat("z", 62), 2) {
		t.Fatal("non-hex hash must be rejected")
	}
	if VerifyPoW(nonce, counter, hash, MaxPoWDifficulty+1) {
		t.Fatal("difficulty above the supported maximum must be rejected")
	}
}
