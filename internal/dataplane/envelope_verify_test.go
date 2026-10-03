package dataplane

import (
	"testing"

	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/challenge/gm"
)

/*
本文件的两个用例**锁的不是同一个机制**，改动验签路径时两个都要看：

  TestEnvelopeVerifierVerifiesIssuedEnvelopes —— 其中的「篡改必须拒绝」分支锁的是
      **完整性**（GM 信封的 SM3 整体校验）。实测：把 VerifyShardEnvelopeSignature 的
      verifySig 参数从 true 改成 false，**本用例仍然通过** —— 单字节篡改被 SM3 拦下，
      与 SM2 签名无关。
  TestEnvelopeVerifierRejectsForeignDomain —— 锁的是**签名**。域字段参与 SM2 签名
      覆盖范围（gm.Seal 的 toSign 含整个头部），而 SM3 整体校验不涉及域语义，因此
      只有这一条在 verifySig=false 时会变红（实测确认）。

结论：**关闭 verifySig 只有后者会报警**。若只跑第一个用例看到通过，会误判为
「没破坏任何东西」—— 这正是「测试看起来在保护某个机制、实际保护的是另一个机制」
的典型形态。新增验签相关用例时，请指明它属于哪一类。
*/

// TestEnvelopeVerifierVerifiesIssuedEnvelopes 锁定 B3 密码学层的对外契约：
// 服务端签发的 0x06 信封必须验签通过，篡改/换密钥/空公钥必须拒绝。
//
// 注意：本用例的篡改分支锁的是**完整性**（SM3），不是签名 —— 见文件头说明。
func TestEnvelopeVerifierVerifiesIssuedEnvelopes(t *testing.T) {
	challenge.SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))
	v := NewEnvelopeVerifier(nil)

	envelope, keyHex, ok := challenge.IssueC2Seed("203.0.113.7")
	if !ok {
		t.Fatal("IssueC2Seed returned not-ok")
	}

	plain, verified := v.Verify(envelope, keyHex)
	if !verified || plain == "" {
		t.Fatalf("issued envelope failed verification: ok=%v plain=%q", verified, plain)
	}

	// 篡改必须拒绝。
	tampered := []byte(envelope)
	tampered[len(tampered)-4] ^= 0x01
	if _, verified := v.Verify(string(tampered), keyHex); verified {
		t.Fatal("tampered envelope must be rejected")
	}

	// 换密钥必须拒绝。
	wrong := []byte(keyHex)
	wrong[0] = 'f'
	if wrong[0] == keyHex[0] {
		wrong[0] = 'a'
	}
	if _, verified := v.Verify(envelope, string(wrong)); verified {
		t.Fatal("wrong key must be rejected")
	}

	// 空输入必须拒绝。
	if _, verified := v.Verify("", keyHex); verified {
		t.Fatal("empty envelope must be rejected")
	}
	if _, verified := v.Verify(envelope, ""); verified {
		t.Fatal("empty key must be rejected")
	}
}

// TestEnvelopeVerifierRejectsForeignDomain 锁定「域必须为 0x06」：用别的域
// 签出的信封不得通过。
//
// **本用例同时是本文件里唯一真正锁「签名」的那条**：域参与 SM2 签名覆盖
// 范围，而 SM3 整体校验不涉及域语义，因此把 verifySig 关掉时只有这条会红
// （实测确认）。详见文件头说明。
//
// 这条防的是「跨用途信封互换」，而 0x06 域内多用途的隔离只靠密钥不同
// （AAD 不参与认证 —— 见 pow_shard.go 的 powShardsAAD 注释）。
func TestEnvelopeVerifierRejectsForeignDomain(t *testing.T) {
	challenge.SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))
	v := NewEnvelopeVerifier(nil)

	// 用 0x01（env）域签一个信封，keyHex 与 C2 种子同格式。
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	raw, err := gm.Seal(key[:16], gm.DomainEnv, []byte(`{"x":1}`), nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, verified := v.Verify(gm.Encode(raw), hexOfTest(key)); verified {
		t.Fatal("envelope from a foreign domain must be rejected")
	}
}

func hexOfTest(b []byte) string {
	const hd = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, hd[x>>4], hd[x&0x0f])
	}
	return string(out)
}
