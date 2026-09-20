package access

import "testing"

// TestEncryptDecryptClientSecretRoundTrip 验证 client_secret 加解密可逆且密文随机化。
func TestEncryptDecryptClientSecretRoundTrip(t *testing.T) {
	secret := []byte("test-jwt-secret-material-0123456789")
	plaintext := "super-secret-oauth-value"

	enc, err := encryptClientSecret(secret, plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if enc == "" || enc == plaintext {
		t.Fatalf("密文异常: %q", enc)
	}

	dec, err := decryptClientSecret(secret, enc)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}
	if dec != plaintext {
		t.Fatalf("解密结果不匹配: got %q want %q", dec, plaintext)
	}

	// 相同明文两次加密应产生不同密文（nonce 随机）。
	enc2, err := encryptClientSecret(secret, plaintext)
	if err != nil {
		t.Fatalf("二次加密失败: %v", err)
	}
	if enc == enc2 {
		t.Fatalf("两次加密密文相同，nonce 未随机化")
	}
}

// TestEncryptClientSecretEmpty 验证空明文返回空密文，避免存储无意义数据。
func TestEncryptClientSecretEmpty(t *testing.T) {
	enc, err := encryptClientSecret([]byte("k"), "")
	if err != nil {
		t.Fatalf("加密空串失败: %v", err)
	}
	if enc != "" {
		t.Fatalf("空明文应返回空密文, got %q", enc)
	}
}

// TestDecryptClientSecretWrongKey 验证错误密钥无法解密。
func TestDecryptClientSecretWrongKey(t *testing.T) {
	enc, err := encryptClientSecret([]byte("key-a"), "value")
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}
	if _, err := decryptClientSecret([]byte("key-b"), enc); err == nil {
		t.Fatalf("错误密钥应解密失败")
	}
}

// TestMaskClientSecret 验证密钥遮蔽规则。
func TestMaskClientSecret(t *testing.T) {
	cases := map[string]string{
		"":           "",
		"ab":         "***",
		"abcd":       "***",
		"abcdefgh":   "abcd***",
		"1234567890": "1234***",
	}
	for in, want := range cases {
		if got := maskClientSecret(in); got != want {
			t.Errorf("maskClientSecret(%q) = %q, want %q", in, got, want)
		}
	}
}
