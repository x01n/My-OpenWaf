package dynamic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// aesKWDefaultIV 是 RFC 3394 AES Key Wrap 的默认初始值（0xA6 重复 8 次）。
// Web Crypto API 的 "AES-KW" unwrapKey 使用同一默认 IV，二者可互操作。
var aesKWDefaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// randomBytes 返回 n 个密码学安全的随机字节。
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败属于不可恢复的系统级错误，直接 panic 避免使用弱随机。
		panic("dynamic: 无法读取安全随机数: " + err.Error())
	}
	return b
}

// randomNonceB64 生成一个用于 CSP script 标签的唯一 nonce（16 字节，base64 编码）。
func randomNonceB64() string {
	return base64.StdEncoding.EncodeToString(randomBytes(16))
}

/**
 * deriveKey 使用 HKDF-SHA256 从基础密钥派生固定长度的子密钥。
 *
 * @param base   基础密钥材料（EncryptionKeyBase）。
 * @param info   上下文绑定信息，包含站点 ID，保证不同站点派生出不同密钥。
 * @param length 期望的派生密钥字节数。
 * @return       派生出的密钥字节切片。
 */
func deriveKey(base []byte, info string, length int) []byte {
	reader := hkdf.New(sha256.New, base, nil, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(reader, out); err != nil {
		panic("dynamic: HKDF 派生失败: " + err.Error())
	}
	return out
}

/**
 * aesGCMEncrypt 使用 AES-256-GCM 对明文进行 AEAD 加密。
 *
 * @param key       32 字节的内容加密密钥（CEK）。
 * @param plaintext 待加密的明文。
 * @return iv        本次加密使用的唯一 12 字节 nonce。
 * @return ciphertext 密文（尾部附带 16 字节 GCM 认证标签），与 Web Crypto AES-GCM 兼容。
 */
func aesGCMEncrypt(key, plaintext []byte) (iv, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	iv = randomBytes(gcm.NonceSize())
	ciphertext = gcm.Seal(nil, iv, plaintext, nil)
	return iv, ciphertext, nil
}

/**
 * aesKeyWrap 实现 RFC 3394 AES Key Wrap，用包装密钥（KEK）封装内容加密密钥（CEK）。
 * 输出可被 Web Crypto API 的 unwrapKey("AES-KW") 解包。
 *
 * @param kek       包装密钥（16/24/32 字节）。
 * @param plaintext 待封装的密钥材料，长度必须是 8 的倍数且不小于 16 字节。
 * @return          封装后的密钥（比输入多 8 字节）。
 */
func aesKeyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, errors.New("dynamic: AES-KW 明文长度必须是 8 的倍数且不小于 16 字节")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(plaintext) / 8
	a := make([]byte, 8)
	copy(a, aesKWDefaultIV)
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:(i+1)*8])
	}

	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[i])
			block.Encrypt(buf, buf)
			copy(a, buf[:8])
			t := uint64(n*j + i + 1)
			var tb [8]byte
			binary.BigEndian.PutUint64(tb[:], t)
			for k := 0; k < 8; k++ {
				a[k] ^= tb[k]
			}
			copy(r[i], buf[8:])
		}
	}

	out := make([]byte, 8*(n+1))
	copy(out[:8], a)
	for i := 0; i < n; i++ {
		copy(out[8+i*8:], r[i])
	}
	return out, nil
}
