package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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

	stopCh           chan struct{} // signals cleanupLoop to exit
	closeOnce        sync.Once
	blacklistReady   atomic.Bool
	blacklistLoadMu  sync.Mutex
	blacklistRetryAt atomic.Int64
}

// ErrTokenBlacklistUnavailable indicates that the persistent blacklist could
// not be loaded. Authentication must fail closed until the store is healthy.
var ErrTokenBlacklistUnavailable = errors.New("token blacklist unavailable")

// Ready reports whether the persistent blacklist has been loaded successfully.
// A nil database is used by lightweight callers that do not persist revocations.
func (tm *TokenManager) Ready() bool {
	return tm != nil && (tm.db == nil || tm.blacklistReady.Load())
}

// NewTokenManager creates a TokenManager with the given primary secret.
func NewTokenManager(primarySecret []byte, db *gorm.DB) *TokenManager {
	tm := &TokenManager{
		primary: primarySecret,
		db:      db,
		stopCh:  make(chan struct{}),
	}
	// Load persisted blacklist into memory.
	if err := tm.loadBlacklistFromDB(); err == nil {
		tm.blacklistReady.Store(true)
	}
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
	if err := tm.ensureBlacklistReady(); err != nil {
		return nil, err
	}

	// Check blacklist.
	if claims.ID != "" && tm.IsBlacklisted(claims.ID) {
		return nil, fmt.Errorf("token has been revoked")
	}

	return claims, nil
}

// ensureBlacklistReady retries a failed startup load with a short backoff.
// This keeps startup fail-closed without permanently locking out authentication
// after a transient database outage.
func (tm *TokenManager) ensureBlacklistReady() error {
	if tm == nil || tm.db == nil || tm.blacklistReady.Load() {
		return nil
	}
	now := time.Now().UnixNano()
	next := tm.blacklistRetryAt.Load()
	if next > now || !tm.blacklistRetryAt.CompareAndSwap(next, now+time.Second.Nanoseconds()) {
		return ErrTokenBlacklistUnavailable
	}
	tm.blacklistLoadMu.Lock()
	defer tm.blacklistLoadMu.Unlock()
	if tm.blacklistReady.Load() {
		tm.blacklistRetryAt.Store(0)
		return nil
	}
	if err := tm.loadBlacklistFromDB(); err != nil {
		return fmt.Errorf("%w: %v", ErrTokenBlacklistUnavailable, err)
	}
	tm.blacklistReady.Store(true)
	tm.blacklistRetryAt.Store(0)
	return nil
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
	return SignAccessTokenWithRole(username, RoleAdmin, secret)
}

// SignAccessTokenWithRole signs a compatibility access token with the supplied current role.
func SignAccessTokenWithRole(username, role string, secret []byte) (string, time.Time, error) {
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
		Role:     role,
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
	_ = tm.BlacklistTokenChecked(jti, expiresAt, reason)
}

// BlacklistTokenChecked blacklists a token and reports persistent-storage failures.
func (tm *TokenManager) BlacklistTokenChecked(jti string, expiresAt time.Time, reason string) error {
	if jti == "" {
		return nil
	}
	tm.blacklist.Store(jti, expiresAt)
	// Persist to database. Repeated revocation is intentionally idempotent: a
	// unique JTI row is updated with the newest expiry/reason so a later restart
	// cannot resurrect a token using an older, already-expired blacklist row.
	if tm.db != nil {
		return tm.db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "jti"}},
			DoUpdates: clause.AssignmentColumns([]string{"expires_at", "reason"}),
		}).Create(&store.TokenBlacklist{
			JTI:       jti,
			ExpiresAt: expiresAt,
			Reason:    reason,
			CreatedAt: time.Now(),
		}).Error
	}
	return nil
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

func (tm *TokenManager) loadBlacklistFromDB() error {
	if tm.db == nil {
		return nil
	}
	var items []store.TokenBlacklist
	if err := tm.db.Where("expires_at > ?", time.Now()).Find(&items).Error; err != nil {
		return err
	}
	for _, item := range items {
		tm.blacklist.Store(item.JTI, item.ExpiresAt)
	}
	return nil
}

func (tm *TokenManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
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
		case <-tm.stopCh:
			return
		}
	}
}

// Close stops the background cleanup goroutine.
func (tm *TokenManager) Close() {
	if tm == nil {
		return
	}
	tm.closeOnce.Do(func() {
		if tm.stopCh != nil {
			close(tm.stopCh)
		}
	})
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
