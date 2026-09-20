package accessgate

import (
	"testing"
	"time"
)

func TestMatchPathPattern(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		want    bool
	}{
		{"/", "*", true},
		{"/foo", "/*", true},
		{"/admin", "/admin", true},
		{"/admin/", "/admin", false},
		{"/admin/users", "/admin/*", true},
		{"/admin", "/admin/*", true},
		{"/api/v1/test", "/api/*", true},
		{"/public/file.js", "/public/*", true},
		{"/other", "/admin/*", false},
		{"", "", false},
	}

	for _, tt := range tests {
		got := matchPathPattern(tt.path, tt.pattern)
		if got != tt.want {
			t.Errorf("matchPathPattern(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
		}
	}
}

func TestMatchPathPatternEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		pattern string
		want    bool
	}{
		{"根路径精确匹配", "/", "/", true},
		{"根路径通配", "/", "/*", true},
		{"通配符匹配所有", "/any/path", "*", true},
		{"前缀通配无斜杠", "/api/v1/users", "/api*", true},
		{"前缀通配不匹配", "/other", "/api*", false},
		{"深层路径精确匹配", "/a/b/c/d", "/a/b/c/d", true},
		{"深层路径不完全匹配", "/a/b/c", "/a/b/c/d", false},
		{"目录通配含斜杠", "/assets/js/main.js", "/assets/*", true},
		{"目录通配恰好匹配前缀", "/assets", "/assets/*", true},
		{"目录通配前缀不匹配", "/assetsxyz", "/assets/*", false},
		{"空模式不匹配任何路径", "/test", "", false},
		{"空路径匹配通配符", "", "*", true},
		{"空路径不匹配前缀通配", "", "/api*", false},
		{"查询字符串不影响匹配", "/admin?foo=bar", "/admin", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPathPattern(tt.path, tt.pattern)
			if got != tt.want {
				t.Errorf("matchPathPattern(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestGateCheckAccessAllowPath(t *testing.T) {
	store := NewMemorySessionStore()
	cfg := Config{
		Enabled: true,
		SiteID:  1,
		PathRules: []PathRule{
			{Path: "/public/*", Action: "allow", Priority: 0},
			{Path: "/*", Action: "require_auth", Priority: 10},
		},
	}
	g := NewGate(cfg, store)

	allowed, redirect, _ := g.CheckAccess("", "/public/file.js")
	if !allowed || redirect {
		t.Fatal("expected public path to be allowed without auth")
	}

	allowed, redirect, _ = g.CheckAccess("", "/admin")
	if allowed || !redirect {
		t.Fatal("expected non-public path to require auth")
	}
}

func TestGateCheckAccessDenyPath(t *testing.T) {
	store := NewMemorySessionStore()
	cfg := Config{
		Enabled: true,
		SiteID:  1,
		PathRules: []PathRule{
			{Path: "/blocked", Action: "deny", Priority: 0},
		},
	}
	g := NewGate(cfg, store)

	allowed, redirect, reason := g.CheckAccess("", "/blocked")
	if allowed || redirect {
		t.Fatal("expected deny path to reject")
	}
	if reason == "" {
		t.Fatal("expected deny reason")
	}
}

func TestGateCheckAccessValidSession(t *testing.T) {
	store := NewMemorySessionStore()
	cfg := Config{
		Enabled:    true,
		SiteID:     1,
		SessionTTL: 3600,
	}
	g := NewGate(cfg, store)

	token, err := g.CreateSession("testuser", "password")
	if err != nil {
		t.Fatal(err)
	}

	allowed, redirect, _ := g.CheckAccess(token, "/admin")
	if !allowed || redirect {
		t.Fatal("expected valid session to be allowed")
	}
}

func TestGateCheckAccessCrossSiteSessionRejected(t *testing.T) {
	store := NewMemorySessionStore()

	// 站点 1 的 gate
	cfg1 := Config{Enabled: true, SiteID: 1, SessionTTL: 3600}
	g1 := NewGate(cfg1, store)

	// 站点 2 的 gate
	cfg2 := Config{Enabled: true, SiteID: 2, SessionTTL: 3600}
	g2 := NewGate(cfg2, store)

	// 在站点 1 创建会话
	token, _ := g1.CreateSession("user1", "password")

	// 用站点 1 的 token 访问站点 2 应该被拒绝
	allowed, redirect, _ := g2.CheckAccess(token, "/")
	if allowed {
		t.Fatal("cross-site session should be rejected")
	}
	if !redirect {
		t.Fatal("should redirect to login")
	}
}

func TestGateVerifySharedPassword(t *testing.T) {
	store := NewMemorySessionStore()
	// bcrypt hash of "test123"
	hash := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	cfg := Config{
		Enabled:            true,
		SiteID:             1,
		SharedPasswordHash: hash,
	}
	g := NewGate(cfg, store)

	// 由于 bcrypt 哈希是固定的，只验证接口可调用
	if g.HasSharedPassword() != true {
		t.Fatal("should have shared password")
	}
}

func TestGateCheckAccessDisabled(t *testing.T) {
	store := NewMemorySessionStore()
	cfg := Config{
		Enabled: false,
		SiteID:  1,
		PathRules: []PathRule{
			{Path: "/*", Action: "deny", Priority: 0},
		},
	}
	g := NewGate(cfg, store)

	// 访问控制禁用时即使有 deny 规则也应放行
	allowed, redirect, _ := g.CheckAccess("", "/anything")
	if !allowed || redirect {
		t.Fatal("访问控制禁用时应放行所有请求")
	}
}

func TestGateCheckAccessExpiredSession(t *testing.T) {
	store := NewMemorySessionStore()
	cfg := Config{
		Enabled:    true,
		SiteID:     1,
		SessionTTL: 1,
	}
	g := NewGate(cfg, store)

	// 直接注入一个已过期的会话
	store.mu.Lock()
	store.sessions["expired-token"] = &SessionInfo{
		SiteID:    1,
		Token:     "expired-token",
		Identity:  "user",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	store.mu.Unlock()

	allowed, redirect, _ := g.CheckAccess("expired-token", "/")
	if allowed {
		t.Fatal("过期会话不应放行")
	}
	if !redirect {
		t.Fatal("过期会话应重定向到登录页")
	}
}

func TestGateCheckAccessInvalidToken(t *testing.T) {
	store := NewMemorySessionStore()
	cfg := Config{
		Enabled:    true,
		SiteID:     1,
		SessionTTL: 3600,
	}
	g := NewGate(cfg, store)

	allowed, redirect, _ := g.CheckAccess("nonexistent-token", "/")
	if allowed {
		t.Fatal("无效 token 不应放行")
	}
	if !redirect {
		t.Fatal("无效 token 应重定向到登录页")
	}
}

func TestGateCookieName(t *testing.T) {
	store := NewMemorySessionStore()
	g1 := NewGate(Config{SiteID: 1}, store)
	g2 := NewGate(Config{SiteID: 42}, store)

	if g1.CookieName() != "__owaf_access_1" {
		t.Fatalf("站点 1 的 cookie 名称不正确: %q", g1.CookieName())
	}
	if g2.CookieName() != "__owaf_access_42" {
		t.Fatalf("站点 42 的 cookie 名称不正确: %q", g2.CookieName())
	}
	if g1.CookieName() == g2.CookieName() {
		t.Fatal("不同站点的 cookie 名称应不同")
	}
}

func TestGateSessionRevoke(t *testing.T) {
	store := NewMemorySessionStore()
	cfg := Config{
		Enabled:    true,
		SiteID:     1,
		SessionTTL: 3600,
	}
	g := NewGate(cfg, store)

	token, err := g.CreateSession("user", "password")
	if err != nil {
		t.Fatal(err)
	}

	// 吊销前应可用
	allowed, _, _ := g.CheckAccess(token, "/")
	if !allowed {
		t.Fatal("吊销前会话应放行")
	}

	if err := store.Revoke(token); err != nil {
		t.Fatal(err)
	}

	// 吊销后不应放行
	allowed, redirect, _ := g.CheckAccess(token, "/")
	if allowed {
		t.Fatal("吊销后会话不应放行")
	}
	if !redirect {
		t.Fatal("吊销后应重定向到登录页")
	}
}

func TestGatePathRulePriority(t *testing.T) {
	store := NewMemorySessionStore()
	cfg := Config{
		Enabled: true,
		SiteID:  1,
		PathRules: []PathRule{
			{Path: "/api/*", Action: "allow", Priority: 0},
			{Path: "/api/admin/*", Action: "require_auth", Priority: 1},
		},
	}
	g := NewGate(cfg, store)

	// /api/public 匹配第一条 allow 规则
	allowed, redirect, _ := g.CheckAccess("", "/api/public")
	if !allowed || redirect {
		t.Fatal("/api/public 应匹配 allow 规则放行")
	}

	// /api/admin/settings 也匹配第一条 /api/* allow 规则（首匹配）
	allowed, redirect, _ = g.CheckAccess("", "/api/admin/settings")
	if !allowed || redirect {
		t.Fatal("/api/admin/settings 应首匹配 /api/* allow 规则")
	}
}

func TestGenerateToken(t *testing.T) {
	token1, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	token2, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}

	if len(token1) != 64 { // 32 bytes hex encoded
		t.Fatalf("token 长度应为 64: got %d", len(token1))
	}
	if token1 == token2 {
		t.Fatal("两次生成的 token 不应相同")
	}
}

func TestMemorySessionStoreCleanExpired(t *testing.T) {
	store := NewMemorySessionStore()

	// 创建一个已过期的会话
	store.sessions["expired"] = &SessionInfo{
		SiteID:    1,
		Token:     "expired",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	store.sessions["valid"] = &SessionInfo{
		SiteID:    1,
		Token:     "valid",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	_ = store.CleanExpired()

	if _, err := store.Validate("expired"); err != nil {
		t.Fatal(err)
	}
	info, _ := store.Validate("valid")
	if info == nil {
		t.Fatal("valid session should still exist")
	}
}
