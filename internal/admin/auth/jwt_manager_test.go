package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

/**
 * newAuthTestDB 建立仅含认证相关表的内存库。
 * @param t 测试上下文
 * @returns 已完成 AutoMigrate 的 *gorm.DB
 */
func newAuthTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.TokenBlacklist{}, &store.ActiveSession{}); err != nil {
		t.Fatalf("migrate auth tables: %v", err)
	}
	return db
}

/**
 * signClaimsWith 用指定密钥与签名算法直接签发 token，用于构造过期/异常 token。
 * @param t 测试上下文
 * @param method 签名算法
 * @param key 签名密钥
 * @param claims 待签发的 Claims
 * @returns 序列化后的 token 字符串
 */
func signClaimsWith(t *testing.T, method jwt.SigningMethod, key any, claims Claims) string {
	t.Helper()
	tokenStr, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tokenStr
}

/**
 * baseClaims 构造带合法 Issuer/Audience 的 Claims，过期时间由调用方决定。
 * @param username 用户名
 * @param role 角色
 * @param exp 过期时间
 * @returns 填充完成的 Claims
 */
func baseClaims(username, role string, exp time.Time) Claims {
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        generateJTI(),
			Issuer:    Issuer,
			Audience:  jwt.ClaimStrings{Audience},
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Username: username,
		Role:     role,
	}
}

// ---------- 签发与校验成功路径 ----------

func TestTokenManagerSignAndVerify(t *testing.T) {
	tm := NewTokenManager([]byte("primary-secret-key"), nil)
	defer tm.Close()

	tokenStr, jti, exp, err := tm.SignAccessToken("alice", RoleOperator, "10.0.0.1", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if jti == "" {
		t.Error("SignAccessToken 应返回非空 jti")
	}
	if !exp.After(time.Now()) {
		t.Error("SignAccessToken 返回的过期时间应在未来")
	}

	claims, err := tm.VerifyAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Username != "alice" {
		t.Errorf("Username = %q, want alice", claims.Username)
	}
	if claims.Role != RoleOperator {
		t.Errorf("Role = %q, want %q", claims.Role, RoleOperator)
	}
	if claims.ID != jti {
		t.Errorf("claims.ID = %q, want %q", claims.ID, jti)
	}
	if claims.Issuer != Issuer {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, Issuer)
	}
	if claims.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", claims.Subject)
	}
}

// TestSignAccessTokenHashesIPAndDevice 验证 IP 与 UA 只以哈希形式进入 token，不泄漏原文。
func TestSignAccessTokenHashesIPAndDevice(t *testing.T) {
	tm := NewTokenManager([]byte("primary-secret-key"), nil)
	defer tm.Close()

	const clientIP = "203.0.113.9"
	const userAgent = "SecretAgent/1.0"

	tokenStr, _, _, err := tm.SignAccessToken("bob", RoleReadonly, clientIP, userAgent)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	claims, err := tm.VerifyAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	if claims.IPHash == "" || claims.IPHash == clientIP {
		t.Errorf("IPHash = %q, 应为哈希且不等于原始 IP", claims.IPHash)
	}
	if claims.DeviceHash == "" || claims.DeviceHash == userAgent {
		t.Errorf("DeviceHash = %q, 应为哈希且不等于原始 UA", claims.DeviceHash)
	}
	if strings.Contains(tokenStr, clientIP) || strings.Contains(tokenStr, userAgent) {
		t.Error("token 中不应出现明文 IP 或 User-Agent")
	}
}

// ---------- 校验拒绝路径（安全边界） ----------

func TestVerifyAccessTokenRejectsWrongSecret(t *testing.T) {
	signer := NewTokenManager([]byte("secret-alpha"), nil)
	defer signer.Close()
	verifier := NewTokenManager([]byte("secret-beta"), nil)
	defer verifier.Close()

	tokenStr, _, _, err := signer.SignAccessToken("mallory", RoleAdmin, "", "")
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if _, err := verifier.VerifyAccessToken(tokenStr); err == nil {
		t.Fatal("使用其他密钥签发的 token 必须被拒绝")
	}
}

func TestVerifyAccessTokenRejectsExpiredToken(t *testing.T) {
	secret := []byte("primary-secret-key")
	tm := NewTokenManager(secret, nil)
	defer tm.Close()

	expired := baseClaims("alice", RoleAdmin, time.Now().Add(-time.Minute))
	tokenStr := signClaimsWith(t, jwt.SigningMethodHS256, secret, expired)

	if _, err := tm.VerifyAccessToken(tokenStr); err == nil {
		t.Fatal("过期 token 必须被拒绝")
	}
}

// TestVerifyAccessTokenRejectsTamperedPayload 篡改 payload 中的 role 后签名失配，必须拒绝。
func TestVerifyAccessTokenRejectsTamperedPayload(t *testing.T) {
	secret := []byte("primary-secret-key")
	tm := NewTokenManager(secret, nil)
	defer tm.Close()

	tokenStr, _, _, err := tm.SignAccessToken("lowpriv", RoleReadonly, "", "")
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("token 段数 = %d, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	tampered := strings.Replace(string(payload), `"role":"`+RoleReadonly+`"`, `"role":"`+RoleAdmin+`"`, 1)
	if tampered == string(payload) {
		t.Fatalf("未能在 payload 中定位 role 字段: %s", payload)
	}
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(tampered)) + "." + parts[2]

	if _, err := tm.VerifyAccessToken(forged); err == nil {
		t.Fatal("篡改 role 的 token 必须被拒绝（提权绕过）")
	}
}

// TestVerifyAccessTokenRejectsNoneAlgorithm 验证 alg=none 混淆攻击被 keyfunc 拒绝。
func TestVerifyAccessTokenRejectsNoneAlgorithm(t *testing.T) {
	tm := NewTokenManager([]byte("primary-secret-key"), nil)
	defer tm.Close()

	claims := baseClaims("attacker", RoleAdmin, time.Now().Add(time.Hour))
	tokenStr := signClaimsWith(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, claims)

	if _, err := tm.VerifyAccessToken(tokenStr); err == nil {
		t.Fatal("alg=none 的 token 必须被拒绝")
	}
}

func TestVerifyAccessTokenRejectsWrongIssuer(t *testing.T) {
	secret := []byte("primary-secret-key")
	tm := NewTokenManager(secret, nil)
	defer tm.Close()

	claims := baseClaims("alice", RoleAdmin, time.Now().Add(time.Hour))
	claims.Issuer = "evil-issuer"
	tokenStr := signClaimsWith(t, jwt.SigningMethodHS256, secret, claims)

	if _, err := tm.VerifyAccessToken(tokenStr); err == nil {
		t.Fatal("Issuer 不匹配的 token 必须被拒绝")
	}
}

func TestVerifyAccessTokenRejectsWrongAudience(t *testing.T) {
	secret := []byte("primary-secret-key")
	tm := NewTokenManager(secret, nil)
	defer tm.Close()

	claims := baseClaims("alice", RoleAdmin, time.Now().Add(time.Hour))
	claims.Audience = jwt.ClaimStrings{"some-other-service"}
	tokenStr := signClaimsWith(t, jwt.SigningMethodHS256, secret, claims)

	if _, err := tm.VerifyAccessToken(tokenStr); err == nil {
		t.Fatal("Audience 不匹配的 token 必须被拒绝")
	}
}

func TestVerifyAccessTokenRejectsGarbage(t *testing.T) {
	tm := NewTokenManager([]byte("primary-secret-key"), nil)
	defer tm.Close()

	for _, bad := range []string{"", "not-a-token", "a.b.c", "...."} {
		if _, err := tm.VerifyAccessToken(bad); err == nil {
			t.Errorf("非法 token %q 必须被拒绝", bad)
		}
	}
}

// ---------- 密钥轮换 ----------

func TestRotateKeyAcceptsTokensSignedWithPreviousKey(t *testing.T) {
	oldSecret := []byte("secret-generation-1")
	tm := NewTokenManager(oldSecret, nil)
	defer tm.Close()

	oldToken, _, _, err := tm.SignAccessToken("alice", RoleAdmin, "", "")
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	tm.RotateKey([]byte("secret-generation-2"))

	if got := string(tm.PrimarySecret()); got != "secret-generation-2" {
		t.Errorf("PrimarySecret = %q, want secret-generation-2", got)
	}
	// 轮换过渡期内，旧密钥签发的 token 仍应通过。
	if _, err := tm.VerifyAccessToken(oldToken); err != nil {
		t.Errorf("轮换后旧 token 应仍可校验: %v", err)
	}
	// 新密钥签发的 token 也应通过。
	newToken, _, _, err := tm.SignAccessToken("alice", RoleAdmin, "", "")
	if err != nil {
		t.Fatalf("SignAccessToken(new): %v", err)
	}
	if _, err := tm.VerifyAccessToken(newToken); err != nil {
		t.Errorf("新 token 应可校验: %v", err)
	}
}

// TestRotateKeyTwiceDropsOldestKey 连续两次轮换后，第一代密钥签发的 token 应失效。
func TestRotateKeyTwiceDropsOldestKey(t *testing.T) {
	tm := NewTokenManager([]byte("secret-generation-1"), nil)
	defer tm.Close()

	genOneToken, _, _, err := tm.SignAccessToken("alice", RoleAdmin, "", "")
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	tm.RotateKey([]byte("secret-generation-2"))
	tm.RotateKey([]byte("secret-generation-3"))

	if _, err := tm.VerifyAccessToken(genOneToken); err == nil {
		t.Fatal("连续两次轮换后，第一代密钥签发的 token 必须失效")
	}
}

func TestRotateKeyRejectsUnrelatedKey(t *testing.T) {
	tm := NewTokenManager([]byte("secret-generation-1"), nil)
	defer tm.Close()

	foreign := NewTokenManager([]byte("attacker-key"), nil)
	defer foreign.Close()
	foreignToken, _, _, err := foreign.SignAccessToken("attacker", RoleAdmin, "", "")
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	tm.RotateKey([]byte("secret-generation-2"))

	if _, err := tm.VerifyAccessToken(foreignToken); err == nil {
		t.Fatal("无关密钥签发的 token 在轮换后仍必须被拒绝")
	}
}

// ---------- 黑名单 / 吊销 ----------

func TestVerifyAccessTokenRejectsBlacklistedToken(t *testing.T) {
	tm := NewTokenManager([]byte("primary-secret-key"), nil)
	defer tm.Close()

	tokenStr, jti, exp, err := tm.SignAccessToken("alice", RoleAdmin, "", "")
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if _, err := tm.VerifyAccessToken(tokenStr); err != nil {
		t.Fatalf("吊销前 token 应有效: %v", err)
	}

	tm.BlacklistToken(jti, exp, "logout")

	if !tm.IsBlacklisted(jti) {
		t.Error("IsBlacklisted 应对已吊销 jti 返回 true")
	}
	if _, err := tm.VerifyAccessToken(tokenStr); err == nil {
		t.Fatal("已吊销的 token 必须被拒绝")
	}
}

// TestBlacklistSurvivesKeyRotation 吊销的 token 在密钥轮换后（经 secondary 校验）仍必须被拒绝。
func TestBlacklistSurvivesKeyRotation(t *testing.T) {
	tm := NewTokenManager([]byte("secret-generation-1"), nil)
	defer tm.Close()

	tokenStr, jti, exp, err := tm.SignAccessToken("alice", RoleAdmin, "", "")
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	tm.BlacklistToken(jti, exp, "force-logout")
	tm.RotateKey([]byte("secret-generation-2"))

	if _, err := tm.VerifyAccessToken(tokenStr); err == nil {
		t.Fatal("轮换后已吊销的 token 仍必须被拒绝")
	}
}

func TestIsBlacklistedUnknownJTI(t *testing.T) {
	tm := NewTokenManager([]byte("primary-secret-key"), nil)
	defer tm.Close()

	if tm.IsBlacklisted("never-seen-jti") {
		t.Error("未记录的 jti 不应被判定为已吊销")
	}
}

// TestIsBlacklistedEvictsExpiredEntry 黑名单条目过期后应被判为未吊销并从内存移除。
func TestIsBlacklistedEvictsExpiredEntry(t *testing.T) {
	tm := NewTokenManager([]byte("primary-secret-key"), nil)
	defer tm.Close()

	tm.BlacklistToken("stale-jti", time.Now().Add(-time.Minute), "expired")

	if tm.IsBlacklisted("stale-jti") {
		t.Error("已过期的黑名单条目应返回 false")
	}
	if _, ok := tm.blacklist.Load("stale-jti"); ok {
		t.Error("已过期的黑名单条目应被移除")
	}
}

func TestBlacklistTokenPersistsToDB(t *testing.T) {
	db := newAuthTestDB(t)
	tm := NewTokenManager([]byte("primary-secret-key"), db)
	defer tm.Close()

	exp := time.Now().Add(time.Hour)
	tm.BlacklistToken("persisted-jti", exp, "manual-revoke")

	var row store.TokenBlacklist
	if err := db.Where("jti = ?", "persisted-jti").First(&row).Error; err != nil {
		t.Fatalf("黑名单应持久化到数据库: %v", err)
	}
	if row.Reason != "manual-revoke" {
		t.Errorf("Reason = %q, want manual-revoke", row.Reason)
	}
}

// TestNewTokenManagerLoadsBlacklistFromDB 重启场景：未过期条目应恢复，过期条目不应恢复。
func TestNewTokenManagerLoadsBlacklistFromDB(t *testing.T) {
	db := newAuthTestDB(t)
	if err := db.Create(&store.TokenBlacklist{
		JTI:       "live-jti",
		ExpiresAt: time.Now().Add(time.Hour),
		Reason:    "revoked",
		CreatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed live blacklist row: %v", err)
	}
	if err := db.Create(&store.TokenBlacklist{
		JTI:       "dead-jti",
		ExpiresAt: time.Now().Add(-time.Hour),
		Reason:    "revoked",
		CreatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed expired blacklist row: %v", err)
	}

	tm := NewTokenManager([]byte("primary-secret-key"), db)
	defer tm.Close()

	if !tm.IsBlacklisted("live-jti") {
		t.Error("未过期的黑名单条目应在启动时恢复")
	}
	if tm.IsBlacklisted("dead-jti") {
		t.Error("已过期的黑名单条目不应在启动时恢复")
	}
}

// ---------- 包级兼容函数 ----------

func TestPackageVerifyAccessTokenRejectsExpired(t *testing.T) {
	secret := []byte("legacy-secret")
	expired := baseClaims("alice", RoleAdmin, time.Now().Add(-time.Second))
	tokenStr := signClaimsWith(t, jwt.SigningMethodHS256, secret, expired)

	if _, err := VerifyAccessToken(tokenStr, secret); err == nil {
		t.Fatal("包级 VerifyAccessToken 必须拒绝过期 token")
	}
}

func TestPackageVerifyAccessTokenRejectsNoneAlgorithm(t *testing.T) {
	claims := baseClaims("attacker", RoleAdmin, time.Now().Add(time.Hour))
	tokenStr := signClaimsWith(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, claims)

	if _, err := VerifyAccessToken(tokenStr, []byte("legacy-secret")); err == nil {
		t.Fatal("包级 VerifyAccessToken 必须拒绝 alg=none 的 token")
	}
}

// TestPackageSignAccessTokenUsesAdminRole 记录包级兼容函数固定签发 admin 角色的行为。
func TestPackageSignAccessTokenUsesAdminRole(t *testing.T) {
	secret := []byte("legacy-secret")
	tokenStr, _, err := SignAccessToken("someone", secret)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	claims, err := VerifyAccessToken(tokenStr, secret)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Role != RoleAdmin {
		t.Errorf("Role = %q, want %q", claims.Role, RoleAdmin)
	}
}

// ---------- 哈希与刷新令牌 ----------

func TestHashShort(t *testing.T) {
	if got := hashShort(""); got != "" {
		t.Errorf("hashShort(\"\") = %q, want 空字符串", got)
	}
	got := hashShort("192.0.2.1")
	if len(got) != 16 {
		t.Errorf("hashShort 长度 = %d, want 16", len(got))
	}
	if got != hashShort("192.0.2.1") {
		t.Error("hashShort 应为确定性哈希")
	}
	if got == hashShort("192.0.2.2") {
		t.Error("不同输入的 hashShort 不应相同")
	}
}

// TestGenerateRefreshTokenDoesNotLeakRaw 刷新令牌的哈希不得可反推出原文，且每次生成互不相同。
func TestGenerateRefreshTokenDoesNotLeakRaw(t *testing.T) {
	jti1, raw1, hash1, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}
	jti2, raw2, hash2, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}

	if jti1 == jti2 || raw1 == raw2 || hash1 == hash2 {
		t.Error("连续两次生成的刷新令牌不应重复")
	}
	if strings.Contains(hash1, raw1) || raw1 == hash1 {
		t.Error("哈希不得包含或等于原始令牌")
	}
	if len(jti1) != 32 {
		t.Errorf("jti 长度 = %d, want 32 (16 字节 hex)", len(jti1))
	}
	if len(raw1) != 64 {
		t.Errorf("raw 长度 = %d, want 64 (32 字节 hex)", len(raw1))
	}
	if len(hash1) != 64 {
		t.Errorf("hash 长度 = %d, want 64 (SHA-256 hex)", len(hash1))
	}
}

func TestPrimarySecretReflectsConstructor(t *testing.T) {
	tm := NewTokenManager([]byte("configured-secret"), nil)
	defer tm.Close()

	if got := string(tm.PrimarySecret()); got != "configured-secret" {
		t.Errorf("PrimarySecret = %q, want configured-secret", got)
	}
}
