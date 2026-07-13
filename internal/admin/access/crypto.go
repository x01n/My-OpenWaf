package access

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// oauthSecretKeyInfo 是 HKDF 派生 OAuth client_secret 加密密钥的上下文绑定信息。
// 数据面解密侧必须使用完全相同的 info 才能派生出同一把密钥。
const oauthSecretKeyInfo = "access-oauth-client-secret"

// errCiphertextTooShort 密文长度不足以包含 nonce 时返回。
var errCiphertextTooShort = errors.New("access: ciphertext too short")

/**
 * deriveOAuthSecretKey 使用 HKDF-SHA256 从 JWT 主密钥派生 32 字节的 AES-256 密钥。
 *
 * @param jwtSecret JWT 签名主密钥（MY_OPENWAF_JWT_SECRET）。
 * @return 派生出的 32 字节内容加密密钥。
 */
func deriveOAuthSecretKey(jwtSecret []byte) []byte {
	reader := hkdf.New(sha256.New, jwtSecret, nil, []byte(oauthSecretKeyInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		panic("access: HKDF 派生 OAuth 密钥失败: " + err.Error())
	}
	return key
}

/**
 * encryptClientSecret 使用 AES-256-GCM 加密 OAuth client_secret。
 * 输出为 base64(nonce(12) || ciphertext||tag)，与数据面解密侧约定一致。
 * 空明文直接返回空字符串，避免存储无意义的密文。
 *
 * @param jwtSecret JWT 主密钥，用于派生内容加密密钥。
 * @param plaintext client_secret 明文。
 * @return base64 编码的密文；明文为空时返回空字符串。
 */
func encryptClientSecret(jwtSecret []byte, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(deriveOAuthSecretKey(jwtSecret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

/**
 * decryptClientSecret 解密 encryptClientSecret 产生的 base64 密文。
 *
 * @param jwtSecret JWT 主密钥，用于派生内容加密密钥。
 * @param encoded   base64(nonce || ciphertext||tag)。
 * @return 解密出的 client_secret 明文；输入为空时返回空字符串。
 */
func decryptClientSecret(jwtSecret []byte, encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(deriveOAuthSecretKey(jwtSecret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errCiphertextTooShort
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

/**
 * maskClientSecret 将 client_secret 明文遮蔽为「前 4 位 + ***」用于响应展示。
 * 长度不足 4 位时全部以 * 遮蔽，避免泄露短密钥。
 *
 * @param secret client_secret 明文。
 * @return 遮蔽后的字符串；明文为空时返回空字符串。
 */
func maskClientSecret(secret string) string {
	if secret == "" {
		return ""
	}
	if len(secret) <= 4 {
		return "***"
	}
	return secret[:4] + "***"
}
