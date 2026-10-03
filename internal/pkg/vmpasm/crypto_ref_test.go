package vmpasm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// 本文件的目的是给 `crypto_ref.go` 的**参照实现**建立外部权威：
// 参照实现的正确性不能由它自己证明。做法是把一条消息手工填充成一个 64 字节块，
// 用参照压缩函数处理，结果必须逐位等于 Go 标准库（`crypto/sha256`）与
// `gmsm/sm3` 的整段摘要 —— 它们是外部权威。

// sha256Pad 把消息填充成恰好一个 64 字节块（消息长度必须 < 56 字节）。
func sha256Pad(msg []byte) []byte {
	if len(msg) >= 56 {
		panic("sha256Pad: message must be shorter than 56 bytes")
	}
	block := make([]byte, 64)
	copy(block, msg)
	block[len(msg)] = 0x80
	binary.BigEndian.PutUint64(block[56:], uint64(len(msg))*8)
	return block
}

// sm3Pad 同 sha256Pad，SM3 的填充规则与 SHA-256 相同（大端比特长度）。
func sm3Pad(msg []byte) []byte { return sha256Pad(msg) }

var sm3IV = [8]uint32{
	0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
	0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
}

// TestRefSHA256CompressMatchesStandardLibrary 正向 + 反向。
func TestRefSHA256CompressMatchesStandardLibrary(t *testing.T) {
	for _, msg := range []string{"", "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"[:55]} {
		h := sha256IV
		sha256CompressBlock(&h, sha256Pad([]byte(msg)))
		got := make([]byte, 32)
		for i := range h {
			binary.BigEndian.PutUint32(got[4*i:], h[i])
		}
		want := StdSHA256([]byte(msg))
		if !bytes.Equal(got, want[:]) {
			t.Fatalf("SHA-256 compression of %q:\ngot  %x\nwant %x", msg, got, want)
		}
	}

	// 反向：改一个消息字节，压缩结果必须改变（防止"恒返回某个常量"的实现逃过检查）
	msg := []byte("abc")
	h1 := sha256IV
	sha256CompressBlock(&h1, sha256Pad(msg))
	bad := []byte("abd")
	h2 := sha256IV
	sha256CompressBlock(&h2, sha256Pad(bad))
	if h1 == h2 {
		t.Fatal("differing messages produced equal states")
	}
}

// TestRefSM3CompressMatchesStandardLibrary 正向 + 反向。
//
// 消息必须短于 56 字节：本用例只覆盖**单块**压缩路径（多块要循环，
// 那是字节码程序的责任，由 PoW 端到端用例覆盖）。
func TestRefSM3CompressMatchesStandardLibrary(t *testing.T) {
	for _, msg := range []string{"abc", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"[:55]} {
		v := sm3IV
		sm3CompressBlock(&v, sm3Pad([]byte(msg)))
		got := make([]byte, 32)
		for i := range v {
			binary.BigEndian.PutUint32(got[4*i:], v[i])
		}
		want := StdSM3([]byte(msg))
		if !bytes.Equal(got, want[:]) {
			t.Fatalf("SM3 compression of %q:\ngot  %x\nwant %x", msg, got, want)
		}
	}

	v1 := sm3IV
	sm3CompressBlock(&v1, sm3Pad([]byte("abc")))
	v2 := sm3IV
	sm3CompressBlock(&v2, sm3Pad([]byte("abd")))
	if v1 == v2 {
		t.Fatal("differing messages produced equal SM3 states")
	}
}

// TestRefSm4BlockMatchesStandardLibrary 正向 + 反向。
func TestRefSm4BlockMatchesStandardLibrary(t *testing.T) {
	key := make([]byte, 16)
	plain := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
		plain[i] = byte(0xF0 + i)
	}
	mem := make([]byte, 256)
	copy(mem[0:16], key)
	copy(mem[64:80], plain)

	if err := refSm4Block(mem, 0, 64, true); err != nil {
		t.Fatalf("refSm4Block(enc): %v", err)
	}
	ct := append([]byte(nil), mem[64:80]...)
	if bytes.Equal(ct, plain) {
		t.Fatal("SM4 encryption left the block unchanged")
	}

	if err := refSm4Block(mem, 0, 64, false); err != nil {
		t.Fatalf("refSm4Block(dec): %v", err)
	}
	if !bytes.Equal(mem[64:80], plain) {
		t.Fatalf("SM4 decrypt did not invert encrypt:\ngot  %x\nwant %x", mem[64:80], plain)
	}

	// 反向：换密钥后密文必须不同
	mem[0] ^= 0xFF
	copy(mem[64:80], plain)
	if err := refSm4Block(mem, 0, 64, true); err != nil {
		t.Fatalf("refSm4Block(enc, other key): %v", err)
	}
	if bytes.Equal(mem[64:80], ct) {
		t.Fatal("different keys produced equal ciphertext")
	}
}

// TestRefPrimitivesRejectOutOfBounds 反向：越界必须被拒绝，绝不 panic。
func TestRefPrimitivesRejectOutOfBounds(t *testing.T) {
	mem := make([]byte, 256)
	cases := []struct {
		name string
		fn   func() error
	}{
		{"sha state oob", func() error { return refSha256Compress(mem, 240, 0) }},
		{"sha block oob", func() error { return refSha256Compress(mem, 0, 240) }},
		{"sha state far oob", func() error { return refSha256Compress(mem, 1<<40, 0) }},
		{"sm3 state oob", func() error { return refSm3Compress(mem, 240, 0) }},
		{"sm4 key oob", func() error { return refSm4Block(mem, 250, 0, true) }},
		{"sm4 block oob", func() error { return refSm4Block(mem, 0, 250, true) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatal("out-of-bounds operand was accepted")
			}
			if code := CodeOf(err); code != ProgramErrorCodeOutOfBounds {
				t.Fatalf("error code = %q, want %q", code, ProgramErrorCodeOutOfBounds)
			}
		})
	}
}

// TestRefSHA256KnownVector 锁定一个已知向量（FIPS 180-4 附录 B.1 的 "abc"）。
func TestRefSHA256KnownVector(t *testing.T) {
	h := sha256IV
	sha256CompressBlock(&h, sha256Pad([]byte("abc")))
	var got []byte
	for i := range h {
		var w [4]byte
		binary.BigEndian.PutUint32(w[:], h[i])
		got = append(got, w[:]...)
	}
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if hex.EncodeToString(got) != want {
		t.Fatalf("SHA-256(abc) = %s, want %s", hex.EncodeToString(got), want)
	}
}

// TestRefSM3KnownVector 锁定一个已知向量（GB/T 32907-2016 附录 A）。
func TestRefSM3KnownVector(t *testing.T) {
	v := sm3IV
	sm3CompressBlock(&v, sm3Pad([]byte("abc")))
	var got []byte
	for i := range v {
		var w [4]byte
		binary.BigEndian.PutUint32(w[:], v[i])
		got = append(got, w[:]...)
	}
	const want = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	if hex.EncodeToString(got) != want {
		t.Fatalf("SM3(abc) = %s, want %s", hex.EncodeToString(got), want)
	}
}
