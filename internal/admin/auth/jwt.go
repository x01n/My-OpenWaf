package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

// RBAC role constants (mirrored from store for convenience).
const (
	RoleAdmin    = store.RoleAdmin
	RoleOperator = store.RoleOperator
	RoleReadonly = store.RoleReadonly
)

// Claims carried inside the short-lived access JWT.
type Claims struct {
	jwt.RegisteredClaims
	Username   string `json:"username"`
	Role       string `json:"role"`
	IPHash     string `json:"ip_hash,omitempty"`
	DeviceHash string `json:"device_hash,omitempty"`
}

const (
	AccessTTL  = 15 * time.Minute
	RefreshTTL = 7 * 24 * time.Hour

	Issuer   = "my-openwaf"
	Audience = "my-openwaf-admin"
)

// TokenManager handles JWT signing, verification, key rotation, and token blacklisting.
type TokenManager struct {
	mu        sync.RWMutex
	primary   []byte   // current signing key
	secondary []byte   // previous key (for rotation transition)
	db        *gorm.DB // for persistent blacklist

	// In-memory blacklist (jti -> expiry)
	blacklist sync.Map
}

// NewTokenManager creates a TokenManager with the given primary secret.
func NewTokenManager(primarySecret []byte, db *gorm.DB) *TokenManager {
	tm := &TokenManager{
		primary: primarySecret,
		db:      db,
	}
	// Load persisted blacklist into memory.
	tm.loadBlacklistFromDB()
	// Start cleanup goroutine.
	go tm.cleanupLoop()
	return tm
}

// RotateKey sets a new primary key; the old primary becomes secondary.
func (tm *TokenManager) RotateKey(newSecret []byte) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.secondary = tm.primary
	tm.primary = newSecret
}

// PrimarySecret returns the current signing key (used by refresh handler).
func (tm *TokenManager) PrimarySecret() []byte {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.primary
}

// SignAccessToken produces a signed JWT for the given user.
func (tm *TokenManager) SignAccessToken(username, role, clientIP, userAgent string) (tokenStr string, jti string, exp time.Time, err error) {
	jti = generateJTI()
	exp = time.Now().Add(AccessTTL)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    Issuer,
			Audience:  jwt.ClaimStrings{Audience},
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Username:   username,
		Role:       role,
		IPHash:     hashShort(clientIP),
		DeviceHash: hashShort(userAgent),
	}
	tm.mu.RLock()
	secret := tm.primary
	tm.mu.RUnlock()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err = token.SignedString(secret)
	return
}

// VerifyAccessToken validates the JWT and returns claims if valid.
// It tries the primary key first, then falls back to the secondary key (rotation support).
func (tm *TokenManager) VerifyAccessToken(tokenStr string) (*Claims, error) {
	tm.mu.RLock()
	primary := tm.primary
	secondary := tm.secondary
	tm.mu.RUnlock()

	// Try primary key.
	claims, err := verifyWithKey(tokenStr, primary)
	if err != nil && secondary != nil {
		// Fallback to secondary (rotation transition).
		claims, err = verifyWithKey(tokenStr, secondary)
	}
	if err != nil {
		return nil, err
	}

	// Check blacklist.
	if claims.ID != "" && tm.IsBlacklisted(claims.ID) {
		return nil, fmt.Errorf("token has been revoked")
	}

	return claims, nil
}

func verifyWithKey(tokenStr string, secret []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	},
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(Audience),
	)
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrSignatureInvalid
}

// SignAccessToken is the backward-compatible package-level function.
func SignAccessToken(username string, secret []byte) (string, time.Time, error) {
	jti := generateJTI()
	exp := time.Now().Add(AccessTTL)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    Issuer,
			Audience:  jwt.ClaimStrings{Audience},
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Username: username,
		Role:     RoleAdmin,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	str, err := token.SignedString(secret)
	return str, exp, err
}

// VerifyAccessToken is the backward-compatible package-level function.
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

// BlacklistToken adds a JTI to the blacklist with the given expiry and reason.
func (tm *TokenManager) BlacklistToken(jti string, expiresAt time.Time, reason string) {
	tm.blacklist.Store(jti, expiresAt)
	// Persist to database.
	if tm.db != nil {
		tm.db.Create(&store.TokenBlacklist{
			JTI:       jti,
			ExpiresAt: expiresAt,
			Reason:    reason,
			CreatedAt: time.Now(),
		})
	}
}

// IsBlacklisted checks if a JTI is in the blacklist.
func (tm *TokenManager) IsBlacklisted(jti string) bool {
	val, ok := tm.blacklist.Load(jti)
	if !ok {
		return false
	}
	exp := val.(time.Time)
	if time.Now().After(exp) {
		tm.blacklist.Delete(jti)
		return false
	}
	return true
}

func (tm *TokenManager) loadBlacklistFromDB() {
	if tm.db == nil {
		return
	}
	var items []store.TokenBlacklist
	tm.db.Where("expires_at > ?", time.Now()).Find(&items)
	for _, item := range items {
		tm.blacklist.Store(item.JTI, item.ExpiresAt)
	}
}

func (tm *TokenManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		tm.blacklist.Range(func(key, value any) bool {
			if exp, ok := value.(time.Time); ok && now.After(exp) {
				tm.blacklist.Delete(key)
			}
			return true
		})
		// Cleanup expired entries from DB.
		if tm.db != nil {
			tm.db.Where("expires_at < ?", now).Delete(&store.TokenBlacklist{})
		}
	}
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

func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashShort(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}
