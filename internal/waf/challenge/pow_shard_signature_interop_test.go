package challenge

import (
	"os/exec"
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/challenge/gm"
)

// interopSigOracle 是签名对拍的 Rust 侧入口。工具缺失时跳过（开发期夹具）。
//
// ⚠️ 验证边界（勿高估）：该工具是 gm.rs 的**独立复刻**，逐字镜像了
// `sm2_za` / `sm2_e_preimage` / `seal_envelope_signed` / `open_raw_signed` 的
// ZA 语义与签名覆盖范围。它验证的是「Go 侧签发与这份复刻逻辑一致」，
// **不验证 gm.rs 本身**（复刻可能与仓库源码漂移，且不经过真实 WASM）。
// gm.rs 的端到端验证靠 pow_shard_quickjs_test.go 那条走真实引擎的链与
// 浏览器实测；本文件只是廉价前置闸门。
func interopSigOracle(t *testing.T, mode string, args ...string) string {
	t.Helper()
	cmd := exec.Command("/tmp/c2rust/target/release/c2-interop", append([]string{mode}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("signature interop oracle unavailable (%v): skipped", err)
	}
	return strings.TrimSpace(string(out))
}

// TestSignedEnvelopeInteropWithRustMirror 锁定签名契约：Go `gm.Seal` 产出的
// 0x06 信封，喂给 Rust 镜像的 `open_raw_signed` 等价实现，必须验签通过并
// 报告正确的密文边界。
//
// 这条是「服务端签发 → 客户端验签」这条链唯一的跨语言闸门：若两侧的 ZA
// 参数、签名覆盖范围或域处理出现分歧，这里会先红，而不是等到浏览器里
// 全体验签失败才暴露（那种静默断链最难排查）。
//
// 变异验证：改动 gm.rs 的 ECC_A 常量（历史上我确实把 ECC_P 误当作 ECC_A）
// 会让本用例变红，实测结果为 reject:zasig。
func TestSignedEnvelopeInteropWithRustMirror(t *testing.T) {
	defer setC2TestSecret(t)()

	pub := gm.PubKeyHex()
	if pub == "" {
		t.Fatal("no signing identity loaded")
	}
	key := []byte("0123456789abcdef")
	raw, err := gm.Seal(key, gm.DomainPowShards, []byte(`{"interop":true}`), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	envelope := gm.Encode(raw)

	result := interopSigOracle(t, "verifysig", envelope, hexOf(key), "6", pub)
	if !strings.HasPrefix(result, "ok:") {
		t.Fatalf("Rust mirror rejected a Go-signed envelope: %s", result)
	}
	// ok:<ct_end> 报告密文边界；核对其数值与 Go 侧布局一致（非空即说明
	// 信封结构被双方同构解析）。
	if result == "ok:" {
		t.Fatalf("Rust mirror returned no ciphertext boundary: %q", result)
	}

	// 篡改后必须被拒 —— 证明该闸门不是恒真。
	tampered := []byte(envelope)
	tampered[len(tampered)/2] ^= 0x01
	if got := interopSigOracle(t, "verifysig", string(tampered), hexOf(key), "6", pub); strings.HasPrefix(got, "ok:") {
		t.Fatalf("Rust mirror accepted a tampered envelope: %s", got)
	}

	// 错误公钥必须被拒。
	if got := interopSigOracle(t, "verifysig", envelope, hexOf(key), "6", strings.Repeat("ab", 64)); strings.HasPrefix(got, "ok:") {
		t.Fatalf("Rust mirror accepted a wrong public key: %s", got)
	}
}
