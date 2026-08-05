package challenge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// NonceKey is the cookie name used for anti-replay nonces.
const NonceKey = "__waf_nonce"

// ChallengePassCookieName is the cookie name for challenge pass cookies.
const ChallengePassCookieName = "__waf_passed"

// DynamicProtectionSessionCookieName is the cookie name for dynamic protection bypass sessions.
const DynamicProtectionSessionCookieName = "__owaf_dp_session"

// challengeSecret is used to sign JS challenge tokens and pass cookies.
// Generated at startup so it cannot be extracted from the binary.
// This means cookies are invalidated on restart, which is acceptable for security.
// 使用 atomic.Pointer 保存：SetChallengeSecret 可能在启动接线之外被调用，
// 而签名/校验发生在请求处理协程中，普通全局变量会构成数据竞争。
var challengeSecret atomic.Pointer[[]byte]

var challengeNonceReader io.Reader = rand.Reader

func init() {
	challengeSecret.Store(generateChallengeSecret())
}

func generateChallengeSecret() *[]byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return &b
}

// loadChallengeSecret 返回当前挑战签名密钥。
func loadChallengeSecret() []byte {
	if p := challengeSecret.Load(); p != nil {
		return *p
	}
	return nil
}

// SetChallengeSecret allows overriding the secret (e.g. from JWT secret for consistency across restarts).
func SetChallengeSecret(secret []byte) {
	if len(secret) >= 16 {
		clone := append([]byte(nil), secret...)
		challengeSecret.Store(&clone)
	}
}

// ChallengeTokenClaims 是 JS 挑战 token 绑定的客户端身份。
// 绑定这些字段后，从挑战页抓取到的 rid/ts/token 三元组无法被其他客户端复用。
type ChallengeTokenClaims struct {
	ClientIP  string
	UserAgent string
	Host      string
	SiteID    uint
}

// ChallengeSessionBinding identifies the matched site that issued a server-side
// challenge session. The fields are persisted with every captcha, shield, and
// chain session and are checked before the session is consumed or advanced.
type ChallengeSessionBinding struct {
	SiteID uint   `json:"site_id"`
	Host   string `json:"host"`
	Bind   string `json:"bind"`
}

func (b ChallengeSessionBinding) normalized() ChallengeSessionBinding {
	b.Host = strings.ToLower(strings.TrimSpace(b.Host))
	return b
}

func (b ChallengeSessionBinding) matches(other ChallengeSessionBinding) bool {
	b = b.normalized()
	other = other.normalized()
	return b.SiteID == other.SiteID && b.Host == other.Host && b.Bind == other.Bind
}

// signChallengeToken 用挑战密钥对 (reqID, ts, 客户端身份) 做 HMAC 签名。
func signChallengeToken(reqID, ts string, claims ChallengeTokenClaims) string {
	mac := hmac.New(sha256.New, loadChallengeSecret())
	fmt.Fprintf(mac, "v2|%s|%s|%s|%s|%s|%d",
		reqID,
		ts,
		claims.ClientIP,
		challengeUserAgentHash(claims.UserAgent),
		strings.ToLower(claims.Host),
		claims.SiteID,
	)
	return hex.EncodeToString(mac.Sum(nil))
}

// GenerateChallengeTokenPairWithClaims creates a timestamp and HMAC token bound to the
// requesting client for JS challenge pages.
// This is used by the pages subpackage to render challenge HTML without direct access to challengeSecret.
func GenerateChallengeTokenPairWithClaims(reqID string, claims ChallengeTokenClaims) (ts, token string) {
	ts = strconv.FormatInt(time.Now().Unix(), 10)
	return ts, signChallengeToken(reqID, ts, claims)
}

// GenerateChallengeTokenPair 生成不绑定客户端身份的挑战 token。
//
// Deprecated: 数据面必须使用 GenerateChallengeTokenPairWithClaims。
// 未绑定的 token 可被任意客户端复用，仅保留给不掌握客户端身份的调用方。
func GenerateChallengeTokenPair(reqID string) (ts, token string) {
	return GenerateChallengeTokenPairWithClaims(reqID, ChallengeTokenClaims{})
}

// VerifyChallengeToken checks if a JS challenge response token is valid.
//
// Deprecated: 数据面必须使用 VerifyChallengeTokenWithClaims，
// 否则 token 不与提交它的客户端绑定。
func VerifyChallengeToken(reqID, ts, token string, maxAge time.Duration) bool {
	return VerifyChallengeTokenWithClaims(reqID, ts, token, ChallengeTokenClaims{}, maxAge)
}

// VerifyChallengeTokenWithClaims 校验 JS 挑战应答 token。
//
// 校验包含四项约束：
//  1. HMAC 必须匹配，且签名覆盖客户端 IP/UA/Host/SiteID——其他客户端无法复用；
//  2. 时间戳必须在 maxAge 内，且不能来自未来（防止预签发的长期 token）；
//  3. token 必须此前未被兑换过——同一份挑战页只能换取一次通行凭证。
//
// 一次性约束由进程内的重放守卫实现：仅在 HMAC 与时效校验通过后才登记，
// 因此攻击者无法用伪造 token 撑爆守卫的内存。
func VerifyChallengeTokenWithClaims(reqID, ts, token string, claims ChallengeTokenClaims, maxAge time.Duration) bool {
	expected := signChallengeToken(reqID, ts, claims)
	if !hmac.Equal([]byte(token), []byte(expected)) {
		return false
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	issued := time.Unix(tsInt, 0)
	age := time.Since(issued)
	if age >= maxAge {
		return false
	}
	// 允许少量时钟漂移，但拒绝明显来自未来的时间戳。
	if age < -challengeTokenClockSkew {
		return false
	}
	return challengeTokenReplayGuard.consume(token, issued.Add(maxAge))
}

// challengeTokenClockSkew 是挑战 token 时间戳允许的向前漂移量。
const challengeTokenClockSkew = 30 * time.Second

// challengeTokenGuardMaxEntries 是重放守卫的容量上限，超过时强制清扫。
const challengeTokenGuardMaxEntries = 65536

var challengeTokenReplayGuard = newReplayGuard()
var dynamicProtectionKeyReplayGuard = newReplayGuard()

// replayGuard 记录已被兑换的挑战 token，保证一次性使用。
// 条目在过期后由惰性清扫回收——挑战 token 的生命周期只有几分钟，
// 无需为此常驻一个清理协程。
type replayGuard struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	lastSweep time.Time
}

func newReplayGuard() *replayGuard {
	return &replayGuard{seen: make(map[string]time.Time), lastSweep: time.Now()}
}

// consume 登记一个 token，首次登记返回 true，重复登记返回 false。
func (g *replayGuard) consume(token string, expiresAt time.Time) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()

	if exp, ok := g.seen[token]; ok && now.Before(exp) {
		return false
	}
	if len(g.seen) >= challengeTokenGuardMaxEntries || now.Sub(g.lastSweep) > time.Minute {
		g.sweepLocked(now)
	}
	g.seen[token] = expiresAt
	return true
}

// sweepLocked 清除已过期条目，调用方必须持有锁。
// 若清扫后仍超过容量上限，说明短时间内涌入大量合法 token，直接重置以保证内存有界。
func (g *replayGuard) sweepLocked(now time.Time) {
	for token, exp := range g.seen {
		if !now.Before(exp) {
			delete(g.seen, token)
		}
	}
	if len(g.seen) >= challengeTokenGuardMaxEntries {
		g.seen = make(map[string]time.Time)
	}
	g.lastSweep = now
}

type ChallengePassClaims struct {
	Host      string
	ClientIP  net.IP
	UserAgent string
	SiteID    uint
	Bind      string
}

type DynamicProtectionClaims struct {
	Host      string
	ClientIP  net.IP
	UserAgent string
	SiteID    uint
	Bind      string
}

type DynamicProtectionKeyClaims struct {
	DynamicProtectionClaims
	Key string
}

func BuildChallengePassCookie(host string, clientIP net.IP, tlsEnabled bool, now time.Time, ttl time.Duration) string {
	return BuildChallengePassCookieWithClaims(ChallengePassClaims{Host: host, ClientIP: clientIP}, tlsEnabled, now, ttl)
}

func BuildChallengePassCookieWithClaims(claims ChallengePassClaims, tlsEnabled bool, now time.Time, ttl time.Duration) string {
	value := SignChallengePassValueWithClaims(claims, now, ttl)
	cookie := &http.Cookie{
		Name:     ChallengePassCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(normalizeChallengePassTTL(ttl).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   tlsEnabled,
	}
	return cookie.String()
}

func SignChallengePassValue(host string, clientIP net.IP, now time.Time, ttl time.Duration) string {
	return SignChallengePassValueWithClaims(ChallengePassClaims{Host: host, ClientIP: clientIP}, now, ttl)
}

func SignChallengePassValueWithClaims(claims ChallengePassClaims, now time.Time, ttl time.Duration) string {
	ttl = normalizeChallengePassTTL(ttl)
	expires := now.Add(ttl).Unix()
	sessionNonce := make([]byte, 8)
	if _, err := rand.Read(sessionNonce); err != nil {
		return ""
	}
	payload := fmt.Sprintf("v3|%s|%s|%d|%x|shield|%s|%d|%s",
		strings.ToLower(claims.Host),
		challengeIPString(claims.ClientIP),
		expires,
		sessionNonce,
		challengeUserAgentHash(claims.UserAgent),
		claims.SiteID,
		claims.Bind,
	)
	encrypted, err := challengeEncrypt([]byte(payload))
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encrypted)
}

func normalizeChallengePassTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return time.Hour
	}
	return ttl
}

func VerifyChallengePassCookie(cookieHeader, host string, clientIP net.IP, now time.Time) bool {
	return VerifyChallengePassCookieWithClaims(cookieHeader, ChallengePassClaims{Host: host, ClientIP: clientIP}, now)
}

func VerifyChallengePassCookieWithClaims(cookieHeader string, claims ChallengePassClaims, now time.Time) bool {
	if cookieHeader == "" {
		return false
	}
	for _, raw := range strings.Split(cookieHeader, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		name, value, ok := strings.Cut(raw, "=")
		if !ok || name != ChallengePassCookieName {
			continue
		}
		return VerifyChallengePassValueWithClaims(value, claims, now)
	}
	return false
}

func VerifyChallengePassValue(value, host string, clientIP net.IP, now time.Time) bool {
	return VerifyChallengePassValueWithClaims(value, ChallengePassClaims{Host: host, ClientIP: clientIP}, now)
}

func VerifyChallengePassValueWithClaims(value string, claims ChallengePassClaims, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 {
		return false
	}
	plaintext, err := challengeDecrypt(raw)
	if err != nil {
		return false
	}
	parts := strings.Split(string(plaintext), "|")
	if len(parts) >= 9 && parts[0] == "v3" {
		expires, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil || now.Unix() > expires {
			return false
		}
		siteID, err := strconv.ParseUint(parts[7], 10, 64)
		if err != nil {
			return false
		}
		return parts[1] == strings.ToLower(claims.Host) &&
			parts[2] == challengeIPString(claims.ClientIP) &&
			parts[6] == challengeUserAgentHash(claims.UserAgent) &&
			uint(siteID) == claims.SiteID &&
			parts[8] == claims.Bind
	}
	return false
}

func SignDynamicProtectionKeyTicket(claims DynamicProtectionKeyClaims, now time.Time, ttl time.Duration, kekB64 string) string {
	ttl = normalizeChallengePassTTL(ttl)
	expires := now.Add(ttl).Unix()
	sessionNonce := make([]byte, 8)
	_, _ = rand.Read(sessionNonce)
	payload := fmt.Sprintf("dpkey|%s|%s|%d|%x|%s|%d|%s|%s|%s",
		strings.ToLower(claims.Host),
		challengeIPString(claims.ClientIP),
		expires,
		sessionNonce,
		challengeUserAgentHash(claims.UserAgent),
		claims.SiteID,
		claims.Bind,
		claims.Key,
		kekB64,
	)
	encrypted, err := challengeEncrypt([]byte(payload))
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encrypted)
}

func VerifyDynamicProtectionKeyTicket(value string, claims DynamicProtectionKeyClaims, now time.Time) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 {
		return "", false
	}
	plaintext, err := challengeDecrypt(raw)
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(plaintext), "|")
	if len(parts) != 10 || parts[0] != "dpkey" {
		return "", false
	}
	expires, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || now.Unix() >= expires {
		return "", false
	}
	siteID, err := strconv.ParseUint(parts[6], 10, 64)
	if err != nil {
		return "", false
	}
	if parts[1] != strings.ToLower(claims.Host) ||
		parts[2] != challengeIPString(claims.ClientIP) ||
		parts[5] != challengeUserAgentHash(claims.UserAgent) ||
		uint(siteID) != claims.SiteID ||
		parts[7] != claims.Bind ||
		parts[8] != claims.Key {
		return "", false
	}
	if !dynamicProtectionKeyReplayGuard.consume(value, time.Unix(expires, 0)) {
		return "", false
	}
	return parts[9], true
}

func BuildDynamicProtectionSessionCookieWithClaims(claims DynamicProtectionClaims, tlsEnabled bool, now time.Time, ttl time.Duration) string {
	value := SignDynamicProtectionSessionValueWithClaims(claims, now, ttl)
	cookie := &http.Cookie{
		Name:     DynamicProtectionSessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(normalizeChallengePassTTL(ttl).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   tlsEnabled,
	}
	return cookie.String()
}

func SignDynamicProtectionSessionValueWithClaims(claims DynamicProtectionClaims, now time.Time, ttl time.Duration) string {
	ttl = normalizeChallengePassTTL(ttl)
	expires := now.Add(ttl).Unix()
	sessionNonce := make([]byte, 8)
	_, _ = rand.Read(sessionNonce)
	payload := fmt.Sprintf("dpsess|%s|%s|%d|%x|%s|%d|%s",
		strings.ToLower(claims.Host),
		challengeIPString(claims.ClientIP),
		expires,
		sessionNonce,
		challengeUserAgentHash(claims.UserAgent),
		claims.SiteID,
		claims.Bind,
	)
	encrypted, err := challengeEncrypt([]byte(payload))
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encrypted)
}

func VerifyDynamicProtectionSessionCookieWithClaims(cookieHeader string, claims DynamicProtectionClaims, now time.Time) bool {
	if cookieHeader == "" {
		return false
	}
	for _, raw := range strings.Split(cookieHeader, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		name, value, ok := strings.Cut(raw, "=")
		if !ok || name != DynamicProtectionSessionCookieName {
			continue
		}
		return VerifyDynamicProtectionSessionValueWithClaims(value, claims, now)
	}
	return false
}

func VerifyDynamicProtectionSessionValueWithClaims(value string, claims DynamicProtectionClaims, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 {
		return false
	}
	plaintext, err := challengeDecrypt(raw)
	if err != nil {
		return false
	}
	parts := strings.Split(string(plaintext), "|")
	if len(parts) != 8 || parts[0] != "dpsess" {
		return false
	}
	expires, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || now.Unix() > expires {
		return false
	}
	siteID, err := strconv.ParseUint(parts[6], 10, 64)
	if err != nil {
		return false
	}
	return parts[1] == strings.ToLower(claims.Host) &&
		parts[2] == challengeIPString(claims.ClientIP) &&
		parts[5] == challengeUserAgentHash(claims.UserAgent) &&
		uint(siteID) == claims.SiteID &&
		parts[7] == claims.Bind
}

func challengeUserAgentHash(userAgent string) string {
	sum := sha256.Sum256([]byte(userAgent))
	return hex.EncodeToString(sum[:16])
}

func challengeEncrypt(plaintext []byte) ([]byte, error) {
	key := challengeDeriveAESKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(challengeNonceReader, nonce); err != nil {
		return nil, fmt.Errorf("generate challenge nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func challengeDecrypt(ciphertext []byte) ([]byte, error) {
	key := challengeDeriveAESKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize+1 {
		return nil, fmt.Errorf("too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

func challengeDeriveAESKey() []byte {
	h := sha256.Sum256(append([]byte("owaf-challenge-aes256:"), loadChallengeSecret()...))
	return h[:]
}

func challengeIPString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
