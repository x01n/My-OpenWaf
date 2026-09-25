package gm

import (
	"crypto/cipher"
	"errors"
)

type sm4GCM struct {
	aead cipher.AEAD
}

const gcmBlockSize = 16
const gcmTagSize = 16
const gcmStandardNonceSize = 12

// newGCM 构造 SM4-GCM 实例，语义等价于 cipher.NewGCM(sm4.NewCipher(key))。
func newGCM(block cipher.Block) (*sm4GCM, error) {
	if block == nil || block.BlockSize() != gcmBlockSize {
		return nil, errors.New("owaf: invalid SM4 block for GCM")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sm4GCM{aead: aead}, nil
}

// NonceSize 返回 GCM 标准 nonce 长度（12 字节）。
func (g *sm4GCM) NonceSize() int { return gcmStandardNonceSize }

// Overhead 返回认证标签长度（16 字节）。
func (g *sm4GCM) Overhead() int { return gcmTagSize }

// Seal 加密 plaintext 并返回 nonce||ct||tag（AAD 参与认证）。
func (g *sm4GCM) Seal(nonce, plaintext, aad []byte) []byte {
	if len(nonce) != gcmStandardNonceSize {
		panic("owaf: incorrect nonce length given to sm4-gcm")
	}
	ct := g.aead.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out
}

// Open 解密并验证 nonce||ct||tag 形态的密文（AAD 参与认证）。
func (g *sm4GCM) Open(nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != gcmStandardNonceSize {
		return nil, errors.New("owaf: incorrect nonce length given to sm4-gcm")
	}
	if len(ciphertext) > MaxEnvelopeTextLen {
		return nil, errors.New("owaf: sm4-gcm ciphertext too large")
	}
	return g.aead.Open(nil, nonce, ciphertext, aad)
}
