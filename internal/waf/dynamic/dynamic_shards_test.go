package dynamic

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"My-OpenWaf/internal/waf/challenge/gm"
)

// TestMain 为本包独立测试进程装载 GM 信封签名身份。
// 生产运行时身份由 challenge 包的 init() 统一装载（dataplane 全链路
// import challenge）；dynamic 包单独跑测试没有那个 init，而 R2.2 的新
// 链路会让 ProcessJS 走 gm.Seal，缺身份会直接失败，所以在测试进程内
// 用固定 32 字节种子装载一次（只影响本包测试，不触碰生产身份链）。
func TestMain(m *testing.M) {
	gm.LoadIdentity([]byte("owaf-dynamic-test-sign-identit32")) // 恰好 32 字节
	os.Exit(m.Run())
}

// TestGenerateEncryptedShardedCodeServerOpenRoundTrip 是 R2.2 锁测试：
// GenerateEncryptedShardedCode 产出的信封用 Go 侧 gm.Open 以 CEK 前 16
// 字节、DomainPowShards 域、dynamicShardsAAD 解回内层 JSON，逐片反解
// 拼接后与原始 code 逐字节相等。
func TestGenerateEncryptedShardedCodeServerOpenRoundTrip(t *testing.T) {
	cases := []string{
		"window.__appReady=true;",
		"function tick(){return 1+2}",
		"var s=\"onclick='\\\"'\";alert(s);",
		strings.Repeat("console.log(1);", 300),
	}
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		t.Fatalf("crypto/rand failed: %v", err)
	}
	for i, code := range cases {
		envelopeText, shell, err := GenerateEncryptedShardedCode(code, cek, []byte(dynamicShardsAAD))
		if err != nil {
			t.Fatalf("case %d: GenerateEncryptedShardedCode: %v", i, err)
		}
		if envelopeText == "" || shell == "" {
			t.Fatalf("case %d: empty envelope/shell", i)
		}

		raw, err := gm.Decode(envelopeText)
		if err != nil {
			t.Fatalf("case %d: gm.Decode: %v", i, err)
		}
		plain, err := gm.Open(cek[:16], raw, []byte(dynamicShardsAAD), gm.DomainPowShards, false)
		if err != nil {
			t.Fatalf("case %d: gm.Open (domain 0x06): %v", i, err)
		}
		var env dynamicShardEnvelope
		if err := json.Unmarshal(plain, &env); err != nil {
			t.Fatalf("case %d: unmarshal inner JSON: %v", i, err)
		}
		if env.V != int(gm.GMEnvelopeVersion) {
			t.Fatalf("case %d: envelope v = %d, want %d", i, env.V, gm.GMEnvelopeVersion)
		}
		if len(env.Shards) < dynamicShardMinParts || len(env.Shards) > dynamicShardMaxParts+len(code) {
			t.Fatalf("case %d: shard count %d out of contract range", i, len(env.Shards))
		}
		var body bytes.Buffer
		for _, item := range env.Shards {
			data, err := base64.RawURLEncoding.DecodeString(item.Data)
			if err != nil {
				t.Fatalf("case %d: shard base64url decode: %v", i, err)
			}
			for x := range data {
				data[x] ^= item.Key
			}
			body.Write(data)
		}
		if body.String() != code {
			t.Fatalf("case %d: assembled body != original code", i)
		}
		if got := dynamicFnv1a32(body.String()); got != checksumFromString(env.CRC) {
			t.Fatalf("case %d: crc mismatch got=%d want=%d", i, got, checksumFromString(env.CRC))
		}
		// shell 不含任何片明文：信封与 CEK hex 都不得出现可解析的 code 片段。
		if strings.Contains(shell, "window.__appReady") || strings.Contains(shell, "console.log") {
			t.Fatalf("case %d: shell leaked plaintext code", i)
		}
		if !strings.Contains(shell, "vm_assemble_shards") || !strings.Contains(shell, "(0,eval)") {
			t.Fatalf("case %d: shell does not wire vm_assemble_shards/eval", i)
		}
	}
}

// TestGenerateEncryptedShardedCodeRejectsBadCEK 锁定 CEK 长度校验：
// 非 32 字节必须报错（与 decrypt_dynamic_with_cek 的 CEK 语义一致）。
func TestGenerateEncryptedShardedCodeRejectsBadCEK(t *testing.T) {
	for _, bad := range [][]byte{
		nil,
		make([]byte, 16),
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 64),
	} {
		if _, _, err := GenerateEncryptedShardedCode("var x=1;", bad, []byte(dynamicShardsAAD)); err == nil {
			t.Fatalf("CEK len %d: expected error, got nil", len(bad))
		}
	}
}

// TestGenerateEncryptedShardedCodeRejectsEmptyCode 锁定空 code 报错。
func TestGenerateEncryptedShardedCodeRejectsEmptyCode(t *testing.T) {
	cek := make([]byte, 32)
	if _, _, err := GenerateEncryptedShardedCode("", cek, []byte(dynamicShardsAAD)); err == nil {
		t.Fatal("empty code must be rejected")
	}
}

// TestCekJSDynamicShardChainDecoratesAssembly 锁定装配合成：assembly 含
// 信封变量与 vm 拼装调用，shell 与 assembly 中引用的信封文本一致。
func TestCekJSDynamicShardChainDecoratesAssembly(t *testing.T) {
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}
	shell, assembly, err := cekJSDynamicShardChain(cek)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(cek)
	for _, marker := range []string{
		"__owaf_code_env=",
		"__owaf_code_key=",
		"vm_assemble_shards(e,k)",
		"(0,eval).call(window,c)",
		keyHex,
	} {
		if !strings.Contains(assembly, marker) {
			t.Fatalf("assembly missing marker %q: %s", marker, assembly)
		}
	}
	// 取 assembly 里注入的信封文本（JSON 转义过），还原后必须能 gm.Decode。
	parts := strings.SplitN(assembly, ";", 3)
	if len(parts) < 2 {
		t.Fatalf("assembly shape unexpected: %s", assembly)
	}
	decl := parts[0] + ";" + parts[1]
	if !strings.HasPrefix(decl, "var __owaf_code_env=") {
		t.Fatalf("assembly declaration prefix unexpected: %s", decl)
	}
	// 用 json.Unmarshal 还原信封文本需要构造合法 JSON 片段：取第一个 quote 段。
	rest := strings.TrimPrefix(parts[0], "var __owaf_code_env=")
	var envText string
	dec := json.NewDecoder(strings.NewReader(rest))
	if err := dec.Decode(&envText); err != nil {
		t.Fatalf("envelope text is not valid JSON literal in assembly: %v", err)
	}
	if _, err := gm.Decode(envText); err != nil {
		t.Fatalf("assembly envelope does not decode: %v", err)
	}
	if shell == "" {
		t.Fatal("shell must not be empty")
	}
}

// TestRenderJSSelfDecryptStillMarksLegacyPath 锁定渲染器缺装配合成时的
// 旧语义回退：无上层注入时占位符替换为 (0,eval)(code)（与旧模板一致）。
func TestRenderJSSelfDecryptStillMarksLegacyPath(t *testing.T) {
	env := envelope{data: "x", iv: "y", wrap: "z", kek: "", ticket: "", key: "k", ttl: 300}
	out := string(renderJSSelfDecrypt(env))
	if !strings.Contains(out, "(0,eval)(code);owafMarkRecentSuccess") {
		t.Fatalf("legacy synthetic assembly missing: %s", out[:400])
	}
}
