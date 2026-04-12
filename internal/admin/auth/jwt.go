package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are carried inside the short-lived access JWT.
type Claims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
}

const (
	AccessTTL  = 15 * time.Minute
	RefreshTTL = 7 * 24 * time.Hour
)

// SignAccessToken produces a signed JWT for the given username.
func SignAccessToken(username string, secret []byte) (string, time.Time, error) {
	exp := time.Now().Add(AccessTTL)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Username: username,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	str, err := token.SignedString(secret)
	return str, exp, err
}

// VerifyAccessToken validates the JWT and returns claims if valid.
func VerifyAccessToken(tokenStr string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrSignatureInvalid
}

// GenerateRefreshToken returns a new JTI, the raw token string, and its SHA-256 hash.
func GenerateRefreshToken() (jti, raw, hash string, err error) {
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", "", "", err
	}
	jti = hex.EncodeToString(jtiBytes)

	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", "", "", err
	}
	raw = hex.EncodeToString(rawBytes)
	hash = HashToken(raw)
	return jti, raw, hash, nil
}

// HashToken produces a hex-encoded SHA-256 of the raw token.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
