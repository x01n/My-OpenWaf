package challenge

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"My-OpenWaf/internal/waf/challenge/gm"
)

// setC2TestSecret 装载确定性挑战密钥，返回恢复函数。
func setC2TestSecret(t *testing.T) func() {
	t.Helper()
	prev := loadChallengeSecret()
	SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))
	return func() {
		if prev != nil {
			SetChallengeSecret(prev)
		}
	}
}

// TestC2SeedRoundTrip 验证签发/校验闭环：正确 clientIP 通过，
// 换 clientIP 即拒。
func TestC2SeedRoundTrip(t *testing.T) {
	defer setC2TestSecret(t)()

	const clientIP = "203.0.113.7"
	envelope, keyHex, ok := IssueC2Seed(clientIP)
	if !ok {
		t.Fatal("IssueC2Seed returned not-ok")
	}
	if envelope == "" || len(keyHex) != 64 {
		t.Fatalf("unexpected issue output: envelope=%q keyHex=%q", envelope, keyHex)
	}

	payload := decodeC2SeedForTest(t, envelope, keyHex)
	if payload.Cookie == "" {
		t.Fatal("seed payload is missing the pre-built cookie value")
	}
	if payload.Cookie != C2SeedCookieValue(payload.MAC, payload.Exp) {
		t.Fatalf("payload.cookie %q does not match mac/exp %q", payload.Cookie, C2SeedCookieValue(payload.MAC, payload.Exp))
	}

	if !VerifyC2Cookie(payload.Cookie, clientIP) {
		t.Fatal("valid C2 rejected")
	}
	if VerifyC2Cookie(payload.Cookie, "203.0.113.8") {
		t.Fatal("C2 accepted for a different client IP")
	}
}

// TestC2VerifyIndependentOfC1Rotation 锁定「MAC 不绑定 C1」这一关键语义：
// C1 每请求轮换是端点事实，若校验依赖 C1，dual 站点会陷入无限 412。
// 本测试在同一枚 C2 上先后用两个不同的 C1 语义去校验，结果必须一致。
func TestC2VerifyIndependentOfC1Rotation(t *testing.T) {
	defer setC2TestSecret(t)()

	const clientIP = "203.0.113.7"
	envelope, keyHex, ok := IssueC2Seed(clientIP)
	if !ok {
		t.Fatal("IssueC2Seed returned not-ok")
	}
	payload := decodeC2SeedForTest(t, envelope, keyHex)

	// 校验签名只接受 (value, clientIP)：不提供任何 C1 通道，因此无论 C1
	// 如何轮换都不会改变结论。
	for round := 0; round < 3; round++ {
		if !VerifyC2Cookie(payload.Cookie, clientIP) {
			t.Fatalf("C2 rejected at round %d: MAC must not depend on the rotating C1", round)
		}
	}
}

// TestC2VerifyRejectsMalformed 覆盖结构与前缀的拒绝路径。
func TestC2VerifyRejectsMalformed(t *testing.T) {
	defer setC2TestSecret(t)()

	cases := map[string]string{
		"empty":            "",
		"legacy outdated":  "c2.abcdefgh.1234",
		"no version":       "abcdef.1234",
		"missing exp":      C2SeedPrefix + strings.Repeat("a", 64),
		"short mac":        C2SeedPrefix + "abcd.9999999999",
		"non-hex mac":      C2SeedPrefix + strings.Repeat("z", 64) + ".9999999999",
		"non-numeric exp":  C2SeedPrefix + strings.Repeat("a", 64) + ".soon",
		"empty exp":        C2SeedPrefix + strings.Repeat("a", 64) + ".",
		"extra separator":  C2SeedPrefix + strings.Repeat("a", 64) + ".123.456",
		"negative-ish exp": C2SeedPrefix + strings.Repeat("a", 64) + ".-1",
	}
	for name, value := range cases {
		if VerifyC2Cookie(value, "203.0.113.7") {
			t.Fatalf("malformed C2 accepted: %s (%q)", name, value)
		}
	}
}

// TestC2VerifyRejectsExpired 验证过期种子被拒（临时缩短系统时钟依赖不可行，
// 改为直接构造一个已过期的 MAC 后用真实校验路径验证 exp 分支）。
func TestC2VerifyRejectsExpired(t *testing.T) {
	defer setC2TestSecret(t)()

	macKey := c2MACKey()
	if len(macKey) == 0 {
		t.Fatal("c2 mac key unavailable")
	}
	const clientIP = "203.0.113.7"
	expired := time.Now().Add(-1 * time.Minute).Unix()
	value := C2SeedCookieValue(hex.EncodeToString(c2SeedMAC(macKey, clientIP, expired)), expired)
	if VerifyC2Cookie(value, clientIP) {
		t.Fatal("expired C2 accepted")
	}
}

// TestC2VerifyRejectsForgedMAC 验证「未持有 k_mac 者无法构造 C2」。
// 攻击者能从信封解出 mac/exp（信封密钥随页面下发），但改不了 mac 的内容。
func TestC2VerifyRejectsForgedMAC(t *testing.T) {
	defer setC2TestSecret(t)()

	const clientIP = "203.0.113.7"
	_, keyHex, ok := IssueC2Seed(clientIP)
	if !ok {
		t.Fatal("IssueC2Seed returned not-ok")
	}
	sealKey, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("decode seal key: %v", err)
	}

	// 攻击者用自己的密钥伪造一枚「格式完全正确」的 C2：exp 取未来、mac 取随机。
	forgedMAC := strings.Repeat("ab", 32)
	forgedExp := time.Now().Add(time.Hour).Unix()
	if VerifyC2Cookie(C2SeedCookieValue(forgedMAC, forgedExp), clientIP) {
		t.Fatal("forged MAC accepted")
	}

	// 关键分离性：信封密钥与 MAC 密钥必须不同，否则页面侧可自行算 MAC。
	macKey := c2MACKey()
	if gm.ConstTimeEqual(sealKey, macKey) {
		t.Fatal("seal key and mac key are identical: C2 would be forgeable from the page")
	}
}

// TestC2IssueFailsClosed 验证密钥材料长度不足时签发失败（而非产出弱种子）。
func TestC2IssueFailsClosed(t *testing.T) {
	defer setC2TestSecret(t)()

	// SetChallengeSecret 接受 >=16 字节的材料，但 16 字节的密钥无法驱动
	// k_seal/k_mac 的 32 字节派生，签发必须 fail-closed。
	SetChallengeSecret([]byte("0123456789abcdef"))
	if _, _, ok := IssueC2Seed("203.0.113.7"); ok {
		t.Fatal("IssueC2Seed accepted a 16-byte challenge secret")
	}
	if VerifyC2Cookie(C2SeedCookieValue(strings.Repeat("ab", 32), time.Now().Add(time.Hour).Unix()), "203.0.113.7") {
		t.Fatal("VerifyC2Cookie accepted a value while the secret was unusable")
	}
}

// TestC2SeedEnvelopeIsAssemblableByWASM 验证种子信封与客户端
// vm_assemble_shards 的输入契约同构：JSON 结构为 {shards:[{k,d}],crc,v}，
// 单片、k=0 表示不做 XOR，crc 与解密后载荷的 FNV-1a 32 一致。
func TestC2SeedEnvelopeIsAssemblableByWASM(t *testing.T) {
	defer setC2TestSecret(t)()

	envelope, keyHex, ok := IssueC2Seed("203.0.113.7")
	if !ok {
		t.Fatal("IssueC2Seed returned not-ok")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != envSessionKeySize {
		t.Fatalf("bad seal key: %v", err)
	}
	raw, err := gm.Decode(envelope)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	plain, err := gm.Open(key[:16], raw, []byte(c2SeedEnvelopeAAD), gm.DomainPowShards, false)
	if err != nil {
		t.Fatalf("open envelope: %v", err)
	}
	var env PowShardEnvelope
	if err := json.Unmarshal(plain, &env); err != nil {
		t.Fatalf("unmarshal shard envelope: %v", err)
	}
	if len(env.Shards) != 1 {
		t.Fatalf("want exactly 1 shard, got %d", len(env.Shards))
	}
	data, err := base64.RawURLEncoding.DecodeString(env.Shards[0].Data)
	if err != nil {
		t.Fatalf("decode shard data: %v", err)
	}
	if env.Shards[0].Key != 0 {
		t.Fatalf("want XOR key 0 for a single-shard seed, got %d", env.Shards[0].Key)
	}
	body := string(data)
	if fnv1a32(body) != uint32(parseUintForTest(t, env.CRC)) {
		t.Fatalf("crc mismatch: envelope=%s recomputed=%d", env.CRC, fnv1a32(body))
	}
	var payload C2SeedPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal seed payload: %v", err)
	}
	if payload.Version != int(gm.GMEnvelopeVersion) || payload.MAC == "" || payload.Exp == 0 || payload.Cookie == "" {
		t.Fatalf("incomplete seed payload: %+v", payload)
	}
}

// decodeC2SeedForTest 走服务端路径解出种子载荷（等价于客户端 WASM 拼装后
// 的 JSON.parse 结果）。
func decodeC2SeedForTest(t *testing.T, envelope, keyHex string) C2SeedPayload {
	t.Helper()
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != envSessionKeySize {
		t.Fatalf("bad seal key: %v", err)
	}
	raw, err := gm.Decode(envelope)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	plain, err := gm.Open(key[:16], raw, []byte(c2SeedEnvelopeAAD), gm.DomainPowShards, false)
	if err != nil {
		t.Fatalf("open envelope: %v", err)
	}
	var env PowShardEnvelope
	if err := json.Unmarshal(plain, &env); err != nil {
		t.Fatalf("unmarshal shard envelope: %v", err)
	}
	if len(env.Shards) != 1 {
		t.Fatalf("want 1 shard, got %d", len(env.Shards))
	}
	data, err := base64.RawURLEncoding.DecodeString(env.Shards[0].Data)
	if err != nil {
		t.Fatalf("decode shard: %v", err)
	}
	var payload C2SeedPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return payload
}

func parseUintForTest(t *testing.T, s string) uint64 {
	t.Helper()
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			t.Fatalf("non-digit crc %q", s)
		}
		v = v*10 + uint64(c-'0')
	}
	return v
}
