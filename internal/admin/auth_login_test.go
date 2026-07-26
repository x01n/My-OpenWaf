package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// newAuthDepsForTest 构造一套基于内存库的完整认证依赖，并预置一个账号。
func newAuthDepsForTest(t *testing.T, username, password, role string) *AuthDeps {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&store.AdminAccount{},
		&store.RefreshToken{},
		&store.LoginAttempt{},
		&store.ActiveSession{},
	); err != nil {
		t.Fatalf("migrate auth tables: %v", err)
	}
	accountRepo := repository.NewAdminAccountRepo(db)
	if _, err := accountRepo.Create(username, password, role); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return &AuthDeps{
		AccountRepo: accountRepo,
		RTRepo:      repository.NewRefreshTokenRepo(db),
		JWTSecret:   []byte("test-jwt-secret-for-admin-login-tests"),
		BruteForce:  auth.NewBruteForceDetector(5, time.Minute),
		DB:          db,
	}
}

// invokeAuthHandler 构造带请求体与可选 cookie 的请求并调用 handler。
func invokeAuthHandler(handler app.HandlerFunc, uri string, body []byte, cookie string) *app.RequestContext {
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI(uri)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(body)
	}
	if cookie != "" {
		req.Header.Set("Cookie", "my_openwaf_rt="+cookie)
	}
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	handler(context.Background(), ctx)
	return ctx
}

// ---- LoginHandler ----

func TestLoginRejectsMalformedBody(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	ctx := invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login", []byte(`not json`), "")
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("malformed body: want 400, got %d", ctx.Response.StatusCode())
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	ctx := invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login",
		[]byte(`{"username":"alice","password":"wrongpass"}`), "")
	if ctx.Response.StatusCode() != 401 {
		t.Fatalf("wrong password: want 401, got %d", ctx.Response.StatusCode())
	}
}

func TestLoginRejectsUnknownUser(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	ctx := invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login",
		[]byte(`{"username":"nosuchuser","password":"password123"}`), "")
	if ctx.Response.StatusCode() != 401 {
		t.Fatalf("unknown user: want 401, got %d", ctx.Response.StatusCode())
	}
}

// TestLoginSuccessIssuesTokenAndCookie 验证成功登录返回访问令牌并下发 refresh cookie。
func TestLoginSuccessIssuesTokenAndCookie(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	ctx := invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login",
		[]byte(`{"username":"alice","password":"password123"}`), "")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   int64  `json:"expires_at"`
		Username    string `json:"username"`
		Role        string `json:"role"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("access_token must be present")
	}
	if resp.Username != "alice" || resp.Role != auth.RoleAdmin {
		t.Errorf("identity mismatch: username=%q role=%q", resp.Username, resp.Role)
	}
	if resp.ExpiresAt <= time.Now().Unix() {
		t.Error("expires_at must be in the future")
	}

	setCookie := string(ctx.Response.Header.Peek("Set-Cookie"))
	if setCookie == "" {
		t.Fatal("refresh cookie must be set on successful login")
	}
	if !bytes.Contains([]byte(setCookie), []byte("my_openwaf_rt=")) {
		t.Errorf("unexpected Set-Cookie: %q", setCookie)
	}
	if !bytes.Contains([]byte(setCookie), []byte("HttpOnly")) {
		t.Errorf("refresh cookie must be HttpOnly: %q", setCookie)
	}
}

// TestLoginResponseOmitsPasswordAndHash 验证登录响应不泄漏凭据。
func TestLoginResponseOmitsPasswordAndHash(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	ctx := invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login",
		[]byte(`{"username":"alice","password":"password123"}`), "")
	body := ctx.Response.Body()
	for _, leak := range []string{"password123", "$2a$", "password_hash"} {
		if bytes.Contains(body, []byte(leak)) {
			t.Errorf("login response leaked %q: %s", leak, body)
		}
	}
}

// TestLoginRecordsAttempts 验证成功与失败的登录都会写入审计记录。
func TestLoginRecordsAttempts(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)

	invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login",
		[]byte(`{"username":"alice","password":"wrongpass"}`), "")
	invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login",
		[]byte(`{"username":"alice","password":"password123"}`), "")

	var attempts []store.LoginAttempt
	if err := d.DB.Order("id ASC").Find(&attempts).Error; err != nil {
		t.Fatalf("query login attempts: %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("want 2 recorded attempts, got %d", len(attempts))
	}
	if attempts[0].Success {
		t.Error("first attempt (wrong password) must be recorded as failure")
	}
	if !attempts[1].Success {
		t.Error("second attempt (correct password) must be recorded as success")
	}
}

// TestLoginLocksOutAfterRepeatedFailures 验证连续失败触发暴力破解锁定并返回 429。
func TestLoginLocksOutAfterRepeatedFailures(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	badBody := []byte(`{"username":"alice","password":"wrongpass"}`)

	for i := 0; i < 5; i++ {
		ctx := invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login", badBody, "")
		if ctx.Response.StatusCode() != 401 {
			t.Fatalf("attempt %d: want 401, got %d", i+1, ctx.Response.StatusCode())
		}
	}

	locked := invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login", badBody, "")
	if locked.Response.StatusCode() != 429 {
		t.Fatalf("after 5 failures: want 429, got %d: %s",
			locked.Response.StatusCode(), bytes.TrimSpace(locked.Response.Body()))
	}
	var resp struct {
		RetryAfterSecs int `json:"retry_after_secs"`
	}
	if err := json.Unmarshal(locked.Response.Body(), &resp); err != nil {
		t.Fatalf("decode lockout response: %v", err)
	}
	if resp.RetryAfterSecs <= 0 {
		t.Errorf("retry_after_secs = %d, want positive", resp.RetryAfterSecs)
	}

	// 锁定期内即便密码正确也必须被拒绝。
	good := invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login",
		[]byte(`{"username":"alice","password":"password123"}`), "")
	if good.Response.StatusCode() != 429 {
		t.Fatalf("correct password during lockout: want 429, got %d", good.Response.StatusCode())
	}
}

// TestLoginSuccessUnlocksAccountButKeepsIPCounter 固化暴力破解检测的分层语义：
// RecordFailure 同时累加 IP+用户名 与纯 IP 两个计数器，而 RecordSuccess 只清除
// IP+用户名。成功登录因此不会重置针对该 IP 的全局计数，避免攻击者用自有账号
// 登录来抹掉同一 IP 上的失败记录。
func TestLoginSuccessUnlocksAccountButKeepsIPCounter(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	badBody := []byte(`{"username":"alice","password":"wrongpass"}`)

	for i := 0; i < 3; i++ {
		invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login", badBody, "")
	}
	ok := invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login",
		[]byte(`{"username":"alice","password":"password123"}`), "")
	if ok.Response.StatusCode() != 200 {
		t.Fatalf("login after 3 failures should succeed, got %d", ok.Response.StatusCode())
	}

	// 账号级计数已清零，但 IP 级计数仍保留 3 次，再失败 2 次即达到阈值 5。
	for i := 0; i < 2; i++ {
		ctx := invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login", badBody, "")
		if ctx.Response.StatusCode() != 401 {
			t.Fatalf("failure %d after success: want 401, got %d", i+1, ctx.Response.StatusCode())
		}
	}
	locked := invokeAuthHandler(LoginHandler(d), "/api/v1/auth/login", badBody, "")
	if locked.Response.StatusCode() != 429 {
		t.Fatalf("IP-level counter must survive a successful login: want 429, got %d",
			locked.Response.StatusCode())
	}
}

// ---- RefreshHandler ----

func TestRefreshRejectsMissingCookie(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	ctx := invokeAuthHandler(RefreshHandler(d), "/api/v1/auth/refresh", nil, "")
	if ctx.Response.StatusCode() != 401 {
		t.Fatalf("missing cookie: want 401, got %d", ctx.Response.StatusCode())
	}
}

func TestRefreshRejectsMalformedCookie(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	ctx := invokeAuthHandler(RefreshHandler(d), "/api/v1/auth/refresh", nil, "nocolonhere")
	if ctx.Response.StatusCode() != 401 {
		t.Fatalf("malformed cookie: want 401, got %d", ctx.Response.StatusCode())
	}
}

func TestRefreshRejectsUnknownJTI(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	ctx := invokeAuthHandler(RefreshHandler(d), "/api/v1/auth/refresh", nil, "no-such-jti:sometoken")
	if ctx.Response.StatusCode() != 401 {
		t.Fatalf("unknown jti: want 401, got %d", ctx.Response.StatusCode())
	}
}

// TestRefreshRejectsTamperedToken 验证 JTI 正确但令牌本体被篡改时拒绝刷新。
func TestRefreshRejectsTamperedToken(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	jti, _, hash, err := auth.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}
	if _, err := d.RTRepo.Create(jti, hash, "alice", auth.RoleAdmin,
		time.Now().Add(auth.RefreshTTL)); err != nil {
		t.Fatalf("store refresh token: %v", err)
	}

	ctx := invokeAuthHandler(RefreshHandler(d), "/api/v1/auth/refresh", nil, jti+":tampered-raw-token")
	if ctx.Response.StatusCode() != 401 {
		t.Fatalf("tampered token: want 401, got %d: %s",
			ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestRefreshSucceedsWithValidCookie 验证有效 refresh cookie 可换取新的访问令牌。
func TestRefreshSucceedsWithValidCookie(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	jti, raw, hash, err := auth.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}
	if _, err := d.RTRepo.Create(jti, hash, "alice", auth.RoleAdmin,
		time.Now().Add(auth.RefreshTTL)); err != nil {
		t.Fatalf("store refresh token: %v", err)
	}

	ctx := invokeAuthHandler(RefreshHandler(d), "/api/v1/auth/refresh", nil, jti+":"+raw)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		Username    string `json:"username"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("refresh must return a new access_token")
	}
	if resp.Username != "alice" {
		t.Errorf("username = %q, want alice", resp.Username)
	}
}

// TestRefreshRotatesToken 验证刷新后旧的 refresh token 立即失效（一次性使用）。
func TestRefreshRotatesToken(t *testing.T) {
	d := newAuthDepsForTest(t, "alice", "password123", auth.RoleAdmin)
	jti, raw, hash, err := auth.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}
	if _, err := d.RTRepo.Create(jti, hash, "alice", auth.RoleAdmin,
		time.Now().Add(auth.RefreshTTL)); err != nil {
		t.Fatalf("store refresh token: %v", err)
	}

	first := invokeAuthHandler(RefreshHandler(d), "/api/v1/auth/refresh", nil, jti+":"+raw)
	if first.Response.StatusCode() != 200 {
		t.Fatalf("first refresh: want 200, got %d", first.Response.StatusCode())
	}

	replay := invokeAuthHandler(RefreshHandler(d), "/api/v1/auth/refresh", nil, jti+":"+raw)
	if replay.Response.StatusCode() == 200 {
		t.Fatal("replaying a consumed refresh token must not succeed")
	}
}
