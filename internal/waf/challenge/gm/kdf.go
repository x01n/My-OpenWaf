package gm

import (
	"crypto/rand"

	"github.com/emmansun/gmsm/sm3"
)

/**
 * KDF 派生函数：SM3(secret||info)。
 * secret 是固定的 32 字节会话密钥材料，info 是可变的协议标签（EnvelopeLabel/EnvelopeAAD）。
 * 输出 32 字节 SM3 摘要。
 * info 必须是已生成的协议标签（EnvelopeLabel/EnvelopeAAD 产物），
 * 不允许散落字面量；长度上限 512 字节，超出视为调用方错误返回零值。
 */
func KDF(secret, info []byte) []byte {
	if len(info) > 512 {
		return make([]byte, 32)
	}
	in := make([]byte, 0, len(secret)+len(info))
	in = append(in, secret...)
	in = append(in, info...)
	sum := sm3.Sum(in)
	return append([]byte(nil), sum[:]...)
}

/**
 * DeriveRequestKey 派生 16 字节请求签名密钥：
 * k = KDF(secret, info)[0:16] xor SM3(nonce)，混合随机 nonce 阻断
 * 同一 ticket 被跨时间窗口重放。
 */
func DeriveRequestKey(secret, info, nonce []byte) []byte {
	k := KDF(secret, info)
	n := sm3.Sum(nonce)
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		out[i] = k[i] ^ n[i]
	}
	return out
}

/**
 * DeriveSessionKey 返回 32 字节会话密钥材料。
 */
func DeriveSessionKey(secret, info []byte) []byte {
	return KDF(secret, info)
}

/**
 * RandomBytes 返回 n 字节加密随机数据。
 */
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
