package auth

import (
	"testing"
	"time"
)

func TestSignAndVerifyAccessToken(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long-xxxxx!")
	tokenStr, exp, err := SignAccessToken("admin", secret)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Before(time.Now()) {
		t.Fatal("token already expired")
	}

	claims, err := VerifyAccessToken(tokenStr, secret)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Username != "admin" {
		t.Fatalf("expected admin, got %s", claims.Username)
	}
}

func TestVerifyAccessTokenBadSecret(t *testing.T) {
	tokenStr, _, _ := SignAccessToken("admin", []byte("secret-a"))
	_, err := VerifyAccessToken(tokenStr, []byte("secret-b"))
	if err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	jti, raw, hash, err := GenerateRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if jti == "" || raw == "" || hash == "" {
		t.Fatal("empty token parts")
	}
	if HashToken(raw) != hash {
		t.Fatal("hash mismatch")
	}
}
