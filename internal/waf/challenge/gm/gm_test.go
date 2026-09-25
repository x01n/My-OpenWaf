package gm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func testKey32(t *testing.T) []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

var testKeyHex32 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
var b2VectorKey = mustDecodeHex("0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210")

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
func TestLabelVectors(t *testing.T) {
	kdf := func(category string) string {
		in := append(append([]byte(nil), b2VectorKey...), EnvelopeLabel(category, GMEnvelopeVersion)...)
		h := sm3.Sum(in)
		return hex.EncodeToString(h[:])
	}
	hmacFn := func(msg string) string {
		in := append(append([]byte(nil), b2VectorKey...), msg...)
		h := sm3.Sum(in)
		return hex.EncodeToString(h[:])
	}

	cases := []struct {
		got  string
		want string
	}{
		{kdf("server-sign"), "78acbc59bf91d8617cb4859ee28f4e96df626be4eb887864b73108560387a659"},
		{kdf("browsersign"), "e719a3d1bc69f4188895e4de4297565577f78f6c7358a7a1bf64bbee5a38ce25"},
		{hmacFn("get|/api/v1/x"), "434304f51af73ab63c2283219c9cd87f05b34e1aa6ac0fe1de7224d15c2dd1dd"},
	}
	for i, c := range cases {
		if c.got != c.want {
			t.Fatalf("vector %d = %s, want %s", i, c.got, c.want)
		}
	}
}

// TestLabelGenerators 校验标签生成函数的统一拼接模型。
func TestLabelGenerators(t *testing.T) {
	if got := EnvelopeLabel("env", 2); got != "owaf-env:v2" {
		t.Fatalf("EnvelopeLabel(env,2) = %q", got)
	}
	if got := EnvelopePrefix(2, "owaf-env:v2"); got != "v2.owaf-env:v2" {
		t.Fatalf("EnvelopePrefix = %q", got)
	}
	if got := EnvelopeAAD(EnvelopeLabel("env", 2), PurposeShield); got != "owaf-env:v2|shield" {
		t.Fatalf("EnvelopeAAD = %q", got)
	}
	if got := SM3KDF(b2VectorKey, "server-sign"); hex.EncodeToString(got) != "78acbc59bf91d8617cb4859ee28f4e96df626be4eb887864b73108560387a659" {
		t.Fatalf("SM3KDF = %x", got)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	LoadIdentity(testKey32(t))
	key := testKey32(t)[:16] // gmsm SM4 仅支持 16 字节密钥
	for _, tc := range []struct {
		domain byte
		aad    string
		msg    string
	}{
		{0x01, "owaf-env:v2|challenge", `{"a":1}`},
		{0x02, "owaf-captcha:v2|challenge-data", ""},
		{0x02, "owaf-captcha:v2|challenge-data", string(bytes.Repeat([]byte("x"), 4096))},
	} {
		sealed, err := Seal(key, tc.domain, []byte(tc.msg), []byte(tc.aad))
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		plain, err := Open(key, sealed, []byte(tc.aad), tc.domain, true)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if string(plain) != tc.msg {
			t.Fatalf("roundtrip = %q, want %q", plain, tc.msg)
		}
	}
}

func TestOpenRejectsSignatureBeforeDomainOrKey(t *testing.T) {
	LoadIdentity(testKey32(t))
	key := testKey32(t)[:16]
	sealed, err := Seal(key, 0x01, []byte("msg"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	// 服务端自签信封：verifySig=false 打开仍成功（客户端上行信封 sig 零填充语义）；
	// 但服务端单向信封（token）在 challenge 包内以 verifySig=true 调用。
	if _, err := Open(key, sealed, []byte("aad"), 0x01, false); err != nil {
		t.Fatalf("unsigned open must succeed for client-facing envelopes: %v", err)
	}
	// 篡改 sig 字节：verifySig=true 必须拒绝。
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-Sm3TagSize-SigSize] ^= 0x01
	if _, err := Open(key, tampered, []byte("aad"), 0x01, true); err == nil {
		t.Fatal("tampered signature must fail verified open")
	}
}

func TestSealDomainMismatchRejected(t *testing.T) {
	LoadIdentity(testKey32(t))
	key := testKey32(t)[:16]
	sealed, err := Seal(key, 0x01, []byte("msg"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(key, sealed, []byte("aad-other"), 0x02, true); err == nil {
		t.Fatal("cross-domain open must be rejected")
	}
}

func TestOpenRejectsTamperedBytes(t *testing.T) {
	LoadIdentity(testKey32(t))
	key := testKey32(t)[:16]
	sealed, err := Seal(key, 0x01, []byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(sealed); i++ {
		corrupt := append([]byte(nil), sealed...)
		corrupt[i] ^= 0x01
		if _, err := Open(key, corrupt, []byte("aad"), 0x01, true); err == nil {
			t.Fatalf("tampered byte %d must be rejected", i)
		}
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	LoadIdentity(testKey32(t))
	key := testKey32(t)[:16]
	sealed, err := Seal(key, 0x01, []byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	other := []byte("zzzzzzzzzzzzzzzz")
	if _, err := Open(other, sealed, []byte("aad"), 0x01, true); err == nil {
		t.Fatal("wrong key must be rejected")
	}
}

func TestOpenRejectsShortAndLegacyFormats(t *testing.T) {
	LoadIdentity(testKey32(t))
	key := testKey32(t)[:16]
	legacyV2g := "v2g." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cases := [][]byte{
		nil,
		{},
		[]byte(Magic[:3]),
		{0x4F, 0x57, 0x56, 0x45, 0x02, 0x01},
		[]byte("v1." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))),
		[]byte(legacyV2g),
		make([]byte, MinEnvelopeLen-1),
	}
	for _, c := range cases {
		if _, err := Open(key, c, nil, 0x01, true); err == nil {
			t.Fatalf("case %x must be rejected", c)
		}
	}
}

func TestSignVerifyIdentity(t *testing.T) {
	pub := LoadIdentity(testKey32(t))
	if len(pub) != 128 {
		t.Fatalf("pub hex length = %d, want 128", len(pub))
	}
	if LoadIdentity(testKey32(t)) != pub {
		t.Fatal("identity must be deterministic for the same secret")
	}
	msg := []byte("owaf identity probe")
	sig, err := SignMessage(msg)
	if err != nil || len(sig) != SigSize {
		t.Fatalf("sign: %v len=%d", err, len(sig))
	}
	if !VerifySignature(msg, sig) {
		t.Fatal("own signature must verify")
	}
	if VerifySignature([]byte("other"), sig) {
		t.Fatal("signature must not verify a different message")
	}
	if !VerifyExternalSignature(pub, msg, sig) {
		t.Fatal("external verification must accept own signature")
	}
	if VerifyExternalSignature(pub, msg, sig[:len(sig)-1]) {
		t.Fatal("truncated signature must not verify")
	}
	corrupt := append([]byte(nil), sig...)
	corrupt[0] ^= 0x01
	if VerifyExternalSignature(pub, msg, corrupt) {
		t.Fatal("corrupt signature must not verify")
	}
}

func TestConstTimeEqual(t *testing.T) {
	a := []byte("abcdefgh")
	if !ConstTimeEqual(a, append([]byte(nil), a...)) {
		t.Fatal("equal slices must compare equal")
	}
	if ConstTimeEqual(a, []byte("abcdefgi")) {
		t.Fatal("differing last byte must compare unequal")
	}
	if ConstTimeEqual(a, a[:4]) {
		t.Fatal("different lengths must compare unequal")
	}
	if !ConstTimeEqualHex("0a0b", "0A0B") {
		t.Fatal("hex case-insensitive compare failed")
	}
	if ConstTimeEqualHex("0a", "0a0b") || ConstTimeEqualHex("zz", "00") {
		t.Fatal("invalid hex must compare unequal")
	}
}

func TestDeriveFunctions(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	d1 := DeriveSessionKey(secret, []byte(EnvelopeLabel(CategoryBrowserSign, GMEnvelopeVersion)))
	d2 := DeriveSessionKey(secret, []byte(EnvelopeLabel(CategoryBrowserSign, GMEnvelopeVersion)))
	d3 := DeriveSessionKey(secret, []byte(EnvelopeLabel(CategoryServerSign, GMEnvelopeVersion)))
	if !bytes.Equal(d1, d2) {
		t.Fatal("session key derivation must be deterministic")
	}
	if bytes.Equal(d1, d3) {
		t.Fatal("different categories must derive different keys")
	}
	k1 := DeriveRequestKey(secret, []byte(PurposeBrowserSign+"|reqkey"), []byte("nonce1"))
	k2 := DeriveRequestKey(secret, []byte(PurposeBrowserSign+"|reqkey"), []byte("nonce1"))
	k3 := DeriveRequestKey(secret, []byte(PurposeBrowserSign+"|reqkey"), []byte("nonce2"))
	if !bytes.Equal(k1, k2) || bytes.Equal(k1, k3) {
		t.Fatal("request key must be deterministic and nonce-bound")
	}
}
