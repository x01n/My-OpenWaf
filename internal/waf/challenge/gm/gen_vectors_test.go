package gm

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

var interopKey32 = mustDecodeHex("0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210")

type fixedNonceReader struct{}

func (fixedNonceReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i)
	}
	return len(p), nil
}

// 并对可确定断言的部分（KDF/HMAC/LABEL/SM4-GCM 密文）做内存回归。
func TestGenInteropVectors(t *testing.T) {
	key32 := interopKey32
	LoadIdentity(key32)

	// 断言 ③：KDF / HMAC / LABEL（与 b2 rev9 向量全等）。
	if got := hex.EncodeToString(SM3KDF(key32, "server-sign")); got != "78acbc59bf91d8617cb4859ee28f4e96df626be4eb887864b73108560387a659" {
		t.Fatalf("kdf server-sign = %s", got)
	}
	if got := hex.EncodeToString(SM3KDF(key32, "browsersign")); got != "e719a3d1bc69f4188895e4de4297565577f78f6c7358a7a1bf64bbee5a38ce25" {
		t.Fatalf("kdf browsersign = %s", got)
	}
	if got := sm3HMACHex(key32, "get|/api/v1/x"); got != "434304f51af73ab63c2283219c9cd87f05b34e1aa6ac0fe1de7224d15c2dd1dd" {
		t.Fatalf("sm3_hmac = %s", got)
	}
	if got := EnvelopeLabel("env", 2); got != "owaf-env:v2" {
		t.Fatalf("envelope_label = %q", got)
	}
	if got := EnvelopeAAD(EnvelopeLabel("env", 2), PurposeShield); got != "owaf-env:v2|shield" {
		t.Fatalf("aad = %q", got)
	}

	oldReader := NonceReader
	NonceReader = &fixedNonceReader{}
	defer func() { NonceReader = oldReader }()

	// 断言 ②：对 "mid msg" 的标准 ZA e 摘要（确定性，无随机）。
	e := interopE(t, PubKeyHex(), []byte("mid msg"))
	if got := hex.EncodeToString(e); got != "7af37cb7099fdc39946685da99e6ab0f03a2be1b138218fc2635f5c0b85f1dda" {
		t.Fatalf("e(mid msg) = %s", got)
	}

	var b strings.Builder
	headAAD := func(domain byte) []byte { return []byte{'O', 'W', 'V', 'E', 0x02, domain, 0x00, 64} }
	type gcmCase struct {
		domain byte
		plain  string
	}
	gcmCases := []gcmCase{
		{0x01, `{"webdriver":false,"chrome_present":true,"plugins_count":5,"languages":"zh-CN","screen_width":1920,"screen_height":1080,"hardware_concurrency":8,"color_depth":24,"platform":"Linux","web_assembly":true}`},
		{0x02, `{"type":"math","prompt":"1+1=?","master_img":"data:image/png;base64,AQ==","width":200,"height":80}`},
		{0x03, "42"},
	}
	for i, tc := range gcmCases {
		sealed, err := Seal(key32[:16], tc.domain, []byte(tc.plain), headAAD(tc.domain))
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		if _, err := Open(key32[:16], sealed, headAAD(tc.domain), tc.domain, false); err != nil {
			t.Fatalf("open %d (unsigned path): %v", i, err)
		}
		sealed2, err := Seal(key32[:16], tc.domain, []byte(tc.plain), headAAD(tc.domain))
		if err != nil {
			t.Fatalf("seal %d (2nd): %v", i, err)
		}
		stable := sealed[:headerLen+NonceSize+len(tc.plain)+TagSize]
		stable2 := sealed2[:headerLen+NonceSize+len(tc.plain)+TagSize]
		if hex.EncodeToString(stable) != hex.EncodeToString(stable2) {
			t.Fatalf("sm4-gcm stable[%d] not deterministic", i)
		}
		got := hex.EncodeToString(sealed)
		fmt.Fprintf(&b, "SM4GCM[%d] key=%s\n", i, hex.EncodeToString(key32[:16]))
		fmt.Fprintf(&b, "SM4GCM[%d] domain=%d aad=%s\n", i, tc.domain, hex.EncodeToString(headAAD(tc.domain)))
		fmt.Fprintf(&b, "SM4GCM[%d] plain=%s\n", i, hex.EncodeToString([]byte(tc.plain)))
		fmt.Fprintf(&b, "SM4GCM[%d] sealed_hex=%s\n", i, got)
		fmt.Fprintf(&b, "SM4GCM[%d] sealed_b64url=%s\n\n", i, Encode(sealed))
	}

	// ② SM2 三组：priv 由主裁 KDF 派生；e 确定性可断言；sig 随机化（仅自验）。
	priv := SM3KDF(key32, CategoryServerSign)
	pub := PubKeyHex()
	for i, msg := range []string{"mid msg", "owaf env probe", "GET|/api/x|q=1"} {
		e := interopE(t, pub, []byte(msg))
		sig, err := SignMessage([]byte(msg))
		if err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		if !VerifySignature([]byte(msg), sig) {
			t.Fatalf("signature %d must verify", i)
		}
		fmt.Fprintf(&b, "SM2[%d] ida=%s\n", i, DefaultSM2UserID)
		fmt.Fprintf(&b, "SM2[%d] priv=%s\n", i, hex.EncodeToString(priv))
		fmt.Fprintf(&b, "SM2[%d] pub=%s\n", i, pub)
		fmt.Fprintf(&b, "SM2[%d] msg=%q\n", i, msg)
		fmt.Fprintf(&b, "SM2[%d] e=%s\n", i, hex.EncodeToString(e))
		fmt.Fprintf(&b, "SM2[%d] sig=%s\n\n", i, hex.EncodeToString(sig))
	}

	fmt.Fprintf(&b, "LABEL envelope_label(env,2)=%s\n", EnvelopeLabel("env", 2))
	fmt.Fprintf(&b, "LABEL aad(owaf-env:v2,shield)=%s\n", EnvelopeAAD(EnvelopeLabel("env", 2), PurposeShield))
	fmt.Fprintf(&b, "KDF server-sign=%s\n", hex.EncodeToString(SM3KDF(key32, "server-sign")))
	fmt.Fprintf(&b, "KDF browsersign=%s\n", hex.EncodeToString(SM3KDF(key32, "browsersign")))
	fmt.Fprintf(&b, "HMAC get|/api/v1/x=%s\n", sm3HMACHex(key32, "get|/api/v1/x"))

	if err := os.MkdirAll("/tmp/owaf-perf-r3/gm-interop", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile("/tmp/owaf-perf-r3/gm-interop/vectors-b1.txt", []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write vectors: %v", err)
	}
	t.Logf("vectors written (%d bytes)", b.Len())
}

// sm3HMACHex 是 gm_sm3_hmac 的 Go 侧等价（key32‖msg 单遍 SM3，hex64）。
func sm3HMACHex(key []byte, msg string) string {
	in := append(append([]byte(nil), key...), msg...)
	return hex.EncodeToString(sm3Sum(in))
}

// interopE 计算标准 ZA 语义的 e（生产路径与 SM2 签名共用）。
func interopE(t *testing.T, pubHex string, msg []byte) []byte {
	t.Helper()
	pub, err := pubFromBytes(decodeHexNoLookup(pubHex))
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	e := sm2EPreimage(pub, msg)
	return e[:]
}
