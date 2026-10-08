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

	"My-OpenWaf/internal/store/auth"
)

// RBAC 角色常量（从 store 镜像一份，方便本包直接引用）。
const (
	RoleAdmin    = auth.RoleAdmin
	RoleOperator = auth.RoleOperator
	RoleReadonly = auth.RoleReadonly
)

// Claims 是短时效 access JWT 中携带的声明集合。
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

// TokenManager 负责 JWT 的签发、校验、密钥轮换以及令牌吊销。
type TokenManager struct {
	mu        sync.RWMutex
	primary   []byte   // 当前签名密钥
	secondary []byte   // 上一个密钥（用于轮换过渡期）
	db        *gorm.DB // 持久化黑名单所用数据库

	// 内存黑名单（jti -> 过期时间）
	blacklist sync.Map

	stopCh           chan struct{} // 通知 cleanupLoop 退出
	closeOnce        sync.Once
	blacklistReady   atomic.Bool
	blacklistLoadMu  sync.Mutex
	blacklistRetryAt atomic.Int64
}

// ErrTokenBlacklistUnavailable 表示持久化黑名单未能加载。
// 在存储恢复健康之前，认证必须保持 fail closed。
var ErrTokenBlacklistUnavailable = errors.New("token blacklist unavailable")

// Ready 报告持久化黑名单是否已成功加载。
// 轻量调用方不持久化吊销记录，此时 db 为 nil，同样视为就绪。
func (tm *TokenManager) Ready() bool {
	return tm != nil && (tm.db == nil || tm.blacklistReady.Load())
}

// NewTokenManager 用给定的主密钥构造 TokenManager。
func NewTokenManager(primarySecret []byte, db *gorm.DB) *TokenManager {
	tm := &TokenManager{
		primary: primarySecret,
		db:      db,
		stopCh:  make(chan struct{}),
	}
	// 把已持久化的黑名单载入内存。
	if err := tm.loadBlacklistFromDB(); err == nil {
		tm.blacklistReady.Store(true)
	}
	// 启动清理协程。
	go tm.cleanupLoop()
	return tm
}

// RotateKey 设置新的主密钥，原主密钥降级为备用密钥。
func (tm *TokenManager) RotateKey(newSecret []byte) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.secondary = tm.primary
	tm.primary = newSecret
}

// PrimarySecret 返回当前签名密钥（refresh handler 会用到）。
func (tm *TokenManager) PrimarySecret() []byte {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.primary
}

// SignAccessToken 为指定用户签发一个 JWT。
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

// VerifyAccessToken 校验 JWT，合法则返回其中的声明。
// 先用主密钥验证，失败再回退到备用密钥（支持密钥轮换过渡期）。
func (tm *TokenManager) VerifyAccessToken(tokenStr string) (*Claims, error) {
	tm.mu.RLock()
	primary := tm.primary
	secondary := tm.secondary
	tm.mu.RUnlock()

	// 先试主密钥。
	claims, err := verifyWithKey(tokenStr, primary)
	if err != nil && secondary != nil {
		// 回退到备用密钥（密钥轮换过渡期）。
		claims, err = verifyWithKey(tokenStr, secondary)
	}
	if err != nil {
		return nil, err
	}
	if err := tm.ensureBlacklistReady(); err != nil {
		return nil, err
	}

	// 检查黑名单。
	if claims.ID != "" && tm.IsBlacklisted(claims.ID) {
		return nil, fmt.Errorf("token has been revoked")
	}

	return claims, nil
}

// ensureBlacklistReady 以短暂退避重试启动时失败的加载。
// 这样既能让服务在启动阶段保持 fail closed，又不会因为一次短暂的
// 数据库故障而永久拒绝所有认证。
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

// SignAccessToken 是保持向后兼容的包级函数。
func SignAccessToken(username string, secret []byte) (string, time.Time, error) {
	return SignAccessTokenWithRole(username, RoleAdmin, secret)
}

// SignAccessTokenWithRole 用给定的当前角色签发一个兼容格式的 access token。
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

// VerifyAccessToken 是保持向后兼容的包级函数。
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

// BlacklistToken 把一个 JTI 连同过期时间和原因加入黑名单。
func (tm *TokenManager) BlacklistToken(jti string, expiresAt time.Time, reason string) {
	_ = tm.BlacklistTokenChecked(jti, expiresAt, reason)
}

// BlacklistTokenChecked 吊销一个令牌，并把持久化失败上报给调用方。
func (tm *TokenManager) BlacklistTokenChecked(jti string, expiresAt time.Time, reason string) error {
	if jti == "" {
		return nil
	}
	tm.blacklist.Store(jti, expiresAt)
	// 落库。重复吊销是有意设计成幂等的：同一 JTI 只有一行，
	// 且总是更新为最新的过期时间与原因，这样重启之后旧的黑名单行
	// 不会把已经过期的令牌重新“复活”。
	if tm.db != nil {
		return tm.db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "jti"}},
			DoUpdates: clause.AssignmentColumns([]string{"expires_at", "reason"}),
		}).Create(&auth.TokenBlacklist{
			JTI:       jti,
			ExpiresAt: expiresAt,
			Reason:    reason,
			CreatedAt: time.Now(),
		}).Error
	}
	return nil
}

// IsBlacklisted 检查某个 JTI 是否已被拉黑。
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
	var items []auth.TokenBlacklist
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
			// 清理数据库中已过期的条目。
			if tm.db != nil {
				tm.db.Where("expires_at < ?", now).Delete(&auth.TokenBlacklist{})
			}
		case <-tm.stopCh:
			return
		}
	}
}

// Close 停止后台清理协程。
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

// GenerateRefreshToken 返回新的 JTI、原始令牌字符串及其 SHA-256 摘要。
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

// HashToken 计算原始令牌的 SHA-256，并以十六进制字符串返回。
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
