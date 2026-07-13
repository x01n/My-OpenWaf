package accessgate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// encryptClientSecretForTest 复刻 Admin 侧 encryptClientSecret 的封装格式，
// 用于验证数据面 DecryptClientSecret 与加密契约完全对齐。
func encryptClientSecretForTest(t *testing.T, jwtSecret []byte, plaintext string) string {
	t.Helper()
	reader := hkdf.New(sha256.New, jwtSecret, nil, []byte(oauthSecretKeyInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func TestDecryptClientSecretRoundTrip(t *testing.T) {
	jwtSecret := []byte("test-jwt-secret-material-0123456789")
	plaintext := "super-secret-oauth-value"

	encoded := encryptClientSecretForTest(t, jwtSecret, plaintext)
	got, err := DecryptClientSecret(jwtSecret, encoded)
	if err != nil {
		t.Fatalf("DecryptClientSecret 返回错误: %v", err)
	}
	if got != plaintext {
		t.Fatalf("解密结果不匹配: got %q want %q", got, plaintext)
	}
}

func TestDecryptClientSecretEmpty(t *testing.T) {
	got, err := DecryptClientSecret([]byte("secret"), "")
	if err != nil {
		t.Fatalf("空输入不应报错: %v", err)
	}
	if got != "" {
		t.Fatalf("空输入应返回空串, got %q", got)
	}
}

func TestDecryptClientSecretWrongKeyFails(t *testing.T) {
	encoded := encryptClientSecretForTest(t, []byte("key-a-material-xxxxxxxxxxxxxxx"), "value")
	if _, err := DecryptClientSecret([]byte("key-b-material-yyyyyyyyyyyyyyy"), encoded); err == nil {
		t.Fatal("使用错误密钥解密应失败")
	}
}

func TestDecryptClientSecretTooShort(t *testing.T) {
	// 合法 base64 但长度不足以容纳 nonce。
	short := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})
	if _, err := DecryptClientSecret([]byte("secret"), short); err == nil {
		t.Fatal("过短密文应返回错误")
	}
}
