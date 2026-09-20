package accessgate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// oauthSecretKeyInfo 是 HKDF 派生 OAuth client_secret 加密密钥的上下文绑定信息。
// 该常量必须与 Admin 加密侧（internal/admin/access/crypto.go）保持完全一致，
// 否则数据面无法还原 client_secret 明文。
const oauthSecretKeyInfo = "access-oauth-client-secret"

// errAccessCiphertextTooShort 密文长度不足以包含 nonce 时返回。
var errAccessCiphertextTooShort = errors.New("accessgate: ciphertext too short")

/**
 * deriveOAuthSecretKey 使用 HKDF-SHA256 从 JWT 主密钥派生 32 字节的 AES-256 密钥。
 * 与 Admin 加密侧约定：secret=JWT_SECRET, salt=nil, info=oauthSecretKeyInfo。
 *
 * @param jwtSecret JWT 签名主密钥（MY_OPENWAF_JWT_SECRET）。
 * @return 派生出的 32 字节内容加密密钥。
 */
func deriveOAuthSecretKey(jwtSecret []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, jwtSecret, nil, []byte(oauthSecretKeyInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

/**
 * DecryptClientSecret 解密 Admin 侧 encryptClientSecret 产生的 base64 密文，
 * 还原 OAuth client_secret 明文供数据面发起令牌交换使用。
 * 封装格式约定：base64.StdEncoding(nonce(gcm.NonceSize) || ciphertext||tag)。
 * 空输入直接返回空串，避免对未配置密钥的提供方报错。
 *
 * @param jwtSecret JWT 主密钥，用于派生内容加密密钥。
 * @param encoded   base64(nonce || ciphertext||tag)。
 * @return 解密出的 client_secret 明文；输入为空时返回空字符串。
 */
func DecryptClientSecret(jwtSecret []byte, encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	key, err := deriveOAuthSecretKey(jwtSecret)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errAccessCiphertextTooShort
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
