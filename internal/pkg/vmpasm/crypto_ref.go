package vmpasm

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

// 本文件是参考解释器用的密码原语。
//
// ⚠️ **这是验证用参照，不进生产调用链。** 生产路径用 Rust 侧的
// `sha2::block_api::compress256` 与 `crate::sm3::sm3_compress` —— 那是**被验证对象**；
// 本文件是**参照实现**，只被 `go test` 使用。
// **正确性锚定在外部权威**：`crypto_ref_test.go` 把它逐位对照
// Go 标准库 `crypto/sha256` 与 `github.com/emmansun/gmsm/sm3` 的整段摘要。
// **改动本文件前请先跑那组对照测试** —— 否则参照实现会退化为自证。
//
// # 为什么 SHA-256 / SM3 的压缩函数在这里被实现了一遍
//
// 这不是「重复实现」而是**独立参照**，与 `isa.rs` 的三条原语来源并不冲突：
//
//   - 生产路径（Rust `isa.rs`）用 `sha2::block_api::compress256` 与
//     `crate::sm3::sm3_compress` —— 那是**被验证对象**。
//   - 本文件是**参照实现**，只被 `go test` 使用，不进任何生产调用链。
//     它与被验证对象用不同语言、不同代码写成，因此能发现「两侧同错」。
//
// 其正确性由 `crypto_ref_test.go` 的对照测试保证：把一条单块消息手工填充成
// 一个 64 字节块，用这里的压缩函数走一遍，结果必须**逐位等于** Go 标准库
// `crypto/sha256` 与 `gmsm/sm3` 的整段摘要。标准库是外部权威，不是自证。
//
// SM4 不需要自实现：`gmsm/sm4` 本就提供单块接口。

/**
 * refSha256Compress 对 `mem[state..state+32)`（8×u32 大端）与
 * `mem[block..block+64)` 做一次 SHA-256 压缩，就地更新状态。
 */
func refSha256Compress(mem []byte, state, block uint64) error {
	s, err := checkedRange(state, 32, uint64(len(mem)))
	if err != nil {
		return RefErr(ProgramErrorCodeOutOfBounds)
	}
	b, err := checkedRange(block, 64, uint64(len(mem)))
	if err != nil {
		return RefErr(ProgramErrorCodeOutOfBounds)
	}

	var h [8]uint32
	for i := range h {
		h[i] = binary.BigEndian.Uint32(mem[s+4*i : s+4*i+4])
	}
	sha256CompressBlock(&h, mem[b:b+64])
	for i := range h {
		binary.BigEndian.PutUint32(mem[s+4*i:s+4*i+4], h[i])
	}
	return nil
}

/**
 * refSm3Compress 对 `mem[state..state+32)`（8×u32 大端）与
 * `mem[block..block+64)` 做一次 SM3 压缩，就地更新状态。
 */
func refSm3Compress(mem []byte, state, block uint64) error {
	s, err := checkedRange(state, 32, uint64(len(mem)))
	if err != nil {
		return RefErr(ProgramErrorCodeOutOfBounds)
	}
	b, err := checkedRange(block, 64, uint64(len(mem)))
	if err != nil {
		return RefErr(ProgramErrorCodeOutOfBounds)
	}

	var h [8]uint32
	for i := range h {
		h[i] = binary.BigEndian.Uint32(mem[s+4*i : s+4*i+4])
	}
	sm3CompressBlock(&h, mem[b:b+64])
	for i := range h {
		binary.BigEndian.PutUint32(mem[s+4*i:s+4*i+4], h[i])
	}
	return nil
}

/**
 * refSm4Block 对 `mem[block..block+16)` 做一次单块变换（就地）。
 * `encrypt` 为 false 时解密。密钥取 `mem[key..key+16)`。
 */
func refSm4Block(mem []byte, key, block uint64, encrypt bool) error {
	k, err := checkedRange(key, 16, uint64(len(mem)))
	if err != nil {
		return RefErr(ProgramErrorCodeOutOfBounds)
	}
	b, err := checkedRange(block, 16, uint64(len(mem)))
	if err != nil {
		return RefErr(ProgramErrorCodeOutOfBounds)
	}
	c, err := sm4.NewCipher(mem[k : k+16])
	if err != nil {
		return RefErr(ProgramErrorCodeOutOfBounds)
	}
	var dst [16]byte
	if encrypt {
		c.Encrypt(dst[:], mem[b:b+16])
	} else {
		c.Decrypt(dst[:], mem[b:b+16])
	}
	copy(mem[b:b+16], dst[:])
	return nil
}

/**
 * SHA-256 压缩函数（FIPS 180-4 §6.2.2）—— 参照实现
 *
 * 此处的实现与 Rust 侧 `isa.rs` 的 `sha256_compress_at` 是两条独立写法，
 * 用于捕捉「两侧同错」，因此不得把两者合并成一份共享代码。
 */
var sha256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func sha256CompressBlock(h *[8]uint32, block []byte) {
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[4*i : 4*i+4])
	}
	for i := 16; i < 64; i++ {
		s0 := rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3)
		s1 := rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}

	a, b, c, d, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
	for i := 0; i < 64; i++ {
		S1 := rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
		ch := (e & f) ^ (^e & g)
		temp1 := hh + S1 + ch + sha256K[i] + w[i]
		S0 := rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		temp2 := S0 + maj
		hh = g
		g = f
		f = e
		e = d + temp1
		d = c
		c = b
		b = a
		a = temp1 + temp2
	}
	h[0] += a
	h[1] += b
	h[2] += c
	h[3] += d
	h[4] += e
	h[5] += f
	h[6] += g
	h[7] += hh
}

func rotr32(x uint32, n uint) uint32 { return x>>n | x<<(32-n) }

/**
 * SM3 压缩函数（GB/T 32907-2016）—— 参照实现
 *
 * 与 `isa.rs` 的 `sm3_compress_at` 同为独立实现，用于对照验证。
 */

func sm3CompressBlock(v *[8]uint32, block []byte) {
	var w [68]uint32
	var w1 [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(block[4*i : 4*i+4])
	}
	for j := 16; j < 68; j++ {
		w[j] = sm3P1(w[j-16]^w[j-9]^rotl32(w[j-3], 15)) ^ rotl32(w[j-13], 7) ^ w[j-6]
	}
	for j := 0; j < 64; j++ {
		w1[j] = w[j] ^ w[j+4]
	}
	a, b, c, d, e, f, g, h := v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]
	for j := 0; j < 64; j++ {
		ss1 := rotl32(rotl32(a, 12)+e+rotl32(sm3T(j), uint(j)), 7)
		ss2 := ss1 ^ rotl32(a, 12)
		tt1 := sm3FF(a, b, c, j) + d + ss2 + w1[j]
		tt2 := sm3GG(e, f, g, j) + h + ss1 + w[j]
		d = c
		c = rotl32(b, 9)
		b = a
		a = tt1
		h = g
		g = rotl32(f, 19)
		f = e
		e = sm3P0(tt2)
	}
	v[0] ^= a
	v[1] ^= b
	v[2] ^= c
	v[3] ^= d
	v[4] ^= e
	v[5] ^= f
	v[6] ^= g
	v[7] ^= h
}

func rotl32(x uint32, n uint) uint32 {
	n &= 31
	return x<<n | x>>(32-n)
}

func sm3P0(x uint32) uint32 { return x ^ rotl32(x, 9) ^ rotl32(x, 17) }
func sm3P1(x uint32) uint32 { return x ^ rotl32(x, 15) ^ rotl32(x, 23) }

func sm3T(j int) uint32 {
	if j < 16 {
		return 0x79cc4519
	}
	return 0x7a879d8a
}

func sm3FF(x, y, z uint32, j int) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (x & z) | (y & z)
}

func sm3GG(x, y, z uint32, j int) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (^x & z)
}

/**
 * 供测试使用的整段摘要。
 *
 * 这里用的是 Go 标准库与第三方库，不是本文件的参照实现 —— 作为**外部权威**，
 * 用于让参照实现可被对照，而不是自证。
 */
// StdSHA256 返回标准库计算的 SHA-256 摘要。
func StdSHA256(data []byte) [32]byte { return sha256.Sum256(data) }

// StdSM3 返回 gmsm 计算的 SM3 摘要。
func StdSM3(data []byte) [32]byte { return sm3.Sum(data) }
