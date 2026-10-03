package challenge

import (
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/challenge/gm"
)

// interopSM3Oracle 调用 /tmp 下的独立 Rust 断言工具，用于跨语言锁定 C2 的
// MAC 与分片信封两个契约。工具缺失时跳过——它是开发期对拍夹具，不是 CI 依赖。
//
// ⚠️ 验证边界（必须理解，勿高估）：该工具是 gm.rs 的**独立复刻**，逐字镜像了
// gm.rs 的 fnv1a32 / base64url_decode_buf / vm_assemble_shards 拼装内核，并复用
// 同一份 sm3.rs 源码。因此本文件验证的是「Go 侧与这份复刻逻辑一致」，
// **不验证 gm.rs 本身**——复刻与仓库源码可能漂移，且这里不经过真实 WASM。
// gm.rs 的端到端验证靠 pow_shard_quickjs_test.go 那条走真实引擎的链，
// 以及浏览器实测；本文件只是廉价的前置闸门。
func interopSM3Oracle(t *testing.T, mode string, args ...string) string {
	t.Helper()
	bin := "/tmp/c2rust/target/release/c2-interop"
	cmd := exec.Command(bin, append([]string{mode}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("interop oracle unavailable (%v): skipped", err)
	}
	return strings.TrimSpace(string(out))
}

// TestC2MACMatchesWASMInterop 锁定 MAC 契约：服务端 sm3HMAC(k_mac, msg) 必须
// 与 WASM 侧 gm_sm3_hmac 逐字节一致（两者都是 SM3(key‖msg) 单遍变体）。
func TestC2MACMatchesWASMInterop(t *testing.T) {
	defer setC2TestSecret(t)()

	macKey := c2MACKey()
	if len(macKey) == 0 {
		t.Fatal("c2 mac key unavailable")
	}
	const clientIP = "203.0.113.7"
	msg := clientIP + c2FieldSeparator + "1767225600"

	goMAC := sm3HMAC(macKey, msg)
	// Rust 侧从**主密钥**重算 k_mac（不是把已派生的 k_mac 再派生一次）。
	secretHex := hexOf(loadChallengeSecret())
	rustKeyHex := interopSM3Oracle(t, "kdf", secretHex, c2MACCategory)
	if rustKeyHex == "" {
		t.Fatal("oracle returned empty kdf output")
	}
	if rustKeyHex != hexOf(macKey) {
		t.Fatalf("k_mac interop mismatch:\n  go(server) = %s\n  rust(wasm) = %s", hexOf(macKey), rustKeyHex)
	}
	// 用 Rust 侧重算的同一把 k_mac 再算 MAC，两端必须相等。
	rustMAC := interopSM3Oracle(t, "hmac", rustKeyHex, msg)

	if got := hexOf(goMAC); got != rustMAC {
		t.Fatalf("MAC interop mismatch:\n  go(server) = %s\n  rust(wasm) = %s", got, rustMAC)
	}
}

// TestC2SeedEnvelopeMatchesWASMAssembler 锁定信封契约：服务端封装的种子
// 信封，喂给与 WASM vm_assemble_shards 同逻辑的 Rust 拼装器，必须解出与
// 服务端一致的载荷 JSON。
func TestC2SeedEnvelopeMatchesWASMAssembler(t *testing.T) {
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
	// 把内层分片 JSON 交给 Rust 拼装器（等价于客户端 vm_assemble_shards 的
	// 解码 + XOR + CRC 三段）。Rust 侧不解外层信封——那部分由 GM 契约锁定。
	assembled := interopSM3Oracle(t, "assemble", string(plain))
	if assembled == "" {
		t.Fatal("rust assembler rejected the seed shard envelope")
	}
	var payload C2SeedPayload
	if err := json.Unmarshal([]byte(assembled), &payload); err != nil {
		t.Fatalf("assembled payload is not valid JSON: %v (%q)", err, assembled)
	}
	if payload.MAC == "" || payload.Exp == 0 || payload.Cookie == "" {
		t.Fatalf("assembled payload incomplete: %+v", payload)
	}
	// 拼装结果必须能被服务端校验路径接受（客户端原样落位的正是 cookie 字段）。
	if !VerifyC2Cookie(payload.Cookie, "203.0.113.7") {
		t.Fatal("assembled seed failed server-side verification")
	}
}

func hexOf(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hexDigits[x>>4], hexDigits[x&0x0f])
	}
	return string(out)
}
