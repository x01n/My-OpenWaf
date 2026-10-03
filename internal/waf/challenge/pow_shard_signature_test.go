package challenge

import (
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/challenge/gm"
)

// TestShardEnvelopeSignatureRoundTrip 锁定「服务端签发的 0x06 信封带有效签名」：
// VerifyShardEnvelopeSignature 必须能解出与签发时一致的内层 JSON；
// 篡改任意字节或换密钥必须返回空串。
func TestShardEnvelopeSignatureRoundTrip(t *testing.T) {
	defer setC2TestSecret(t)()

	pub := gm.PubKeyHex()
	if pub == "" {
		t.Fatal("no signing identity loaded")
	}

	key := make([]byte, envSessionKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	envelope, _, err := GeneratePoWShardedEnvelope(ChallengeProofDifficulty, "sig-nonce", key)
	if err != nil || envelope == "" {
		t.Fatalf("GeneratePoWShardedEnvelope: %v", err)
	}

	plain := VerifyShardEnvelopeSignature(envelope, EnvSessionKeyHex(key), pub)
	if plain == "" {
		t.Fatal("signed envelope failed server-side verification")
	}
	if !strings.Contains(plain, "shards") {
		t.Fatalf("plaintext is not the shard JSON: %q", plain[:minInt(80, len(plain))])
	}

	// 空公钥必须拒绝（身份存在性守卫）。
	if got := VerifyShardEnvelopeSignature(envelope, EnvSessionKeyHex(key), ""); got != "" {
		t.Fatal("empty public key must be rejected")
	}

	// 换密钥必须拒绝。
	wrongKey := make([]byte, envSessionKeySize)
	wrongKey[0] = 0xAA
	if got := VerifyShardEnvelopeSignature(envelope, EnvSessionKeyHex(wrongKey), pub); got != "" {
		t.Fatal("wrong session key must be rejected")
	}

	// 篡改信封必须拒绝。
	tampered := []byte(envelope)
	tampered[len(tampered)/2] ^= 0x01
	if got := VerifyShardEnvelopeSignature(string(tampered), EnvSessionKeyHex(key), pub); got != "" {
		t.Fatal("tampered envelope must be rejected")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
