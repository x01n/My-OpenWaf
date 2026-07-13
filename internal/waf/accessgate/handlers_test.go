package accessgate

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func newTestGate(t *testing.T) *Gate {
	t.Helper()
	// bcrypt hash of "pass123"
	hash := mustHashForTest(t, "pass123")
	cfg := Config{
		Enabled:            true,
		SiteID:             7,
		SharedPasswordHash: hash,
		SessionTTL:         3600,
		Providers: []ProviderConfig{
			{ID: 1, Type: "password", Name: "本地", Priority: 0},
			{ID: 2, Type: "oauth2", Name: "GitHub", Priority: 1, OAuth: OAuthConfig{
				ClientID: "cid", ClientSecret: "csecret",
				AuthURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token",
				UserInfoURL: "https://idp.example/userinfo",
			}},
		},
	}
	return NewGate(cfg, NewMemorySessionStore())
}

func mustHashForTest(t *testing.T, pw string) string {
	t.Helper()
	// 直接用 bcrypt 生成，避免硬编码哈希与成本参数漂移。
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestSanitizeReturnURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{"/dashboard", "/dashboard"},
		{"/a/b?x=1", "/a/b?x=1"},
		{"//evil.com", "/"},
		{"https://evil.com", "/"},
		{"/\\evil.com", "/"},
		{"javascript:alert(1)", "/"},
	}
	for _, tt := range tests {
		if got := sanitizeReturnURL(tt.in); got != tt.want {
			t.Errorf("sanitizeReturnURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHandleVerifySharedPasswordSuccess(t *testing.T) {
	g := newTestGate(t)
	d := g.HandleVerify(AuthTypeSharedPassword, "", "pass123", 0, "/dashboard", nil)
	if !d.Authenticated {
		t.Fatalf("共享密码正确应通过, got %+v", d)
	}
	if d.Token == "" {
		t.Fatal("通过后应生成会话 token")
	}
	if d.RedirectURL != "/dashboard" {
		t.Fatalf("应跳转回 return 地址, got %q", d.RedirectURL)
	}
	// 会话应可用于后续访问校验。
	allowed, redirect, _ := g.CheckAccess(d.Token, "/dashboard")
	if !allowed || redirect {
		t.Fatal("新建会话应放行")
	}
}

func TestHandleVerifySharedPasswordWrong(t *testing.T) {
	g := newTestGate(t)
	d := g.HandleVerify(AuthTypeSharedPassword, "", "wrong", 0, "//evil.com", nil)
	if d.Authenticated {
		t.Fatal("错误密码不应通过")
	}
	if !strings.HasPrefix(d.RedirectURL, PathLogin) {
		t.Fatalf("失败应跳回登录页, got %q", d.RedirectURL)
	}
	// 开放重定向的 return 应被剔除（归一化为 "/"，不出现在 URL 中）。
	if strings.Contains(d.RedirectURL, "evil.com") {
		t.Fatalf("非法 return 不应回显, got %q", d.RedirectURL)
	}
}

func TestHandleVerifyUserPassword(t *testing.T) {
	g := newTestGate(t)
	userHash := mustHashForTest(t, "u-secret")
	lookup := func(siteID uint, username string) (string, bool) {
		if siteID == 7 && username == "alice" {
			return userHash, true
		}
		return "", false
	}

	ok := g.HandleVerify(AuthTypeUserPassword, "alice", "u-secret", 1, "/", lookup)
	if !ok.Authenticated || ok.Identity != "alice" {
		t.Fatalf("正确用户名密码应通过并记录身份, got %+v", ok)
	}

	bad := g.HandleVerify(AuthTypeUserPassword, "alice", "bad", 1, "/", lookup)
	if bad.Authenticated {
		t.Fatal("错误密码不应通过")
	}

	missing := g.HandleVerify(AuthTypeUserPassword, "bob", "x", 1, "/", lookup)
	if missing.Authenticated {
		t.Fatal("不存在用户不应通过")
	}

	nilLookup := g.HandleVerify(AuthTypeUserPassword, "alice", "u-secret", 1, "/", nil)
	if nilLookup.Authenticated {
		t.Fatal("无查询函数时 user_password 应一律失败")
	}
}

func TestHandleVerifyUnknownType(t *testing.T) {
	g := newTestGate(t)
	d := g.HandleVerify("bogus", "", "", 0, "/", nil)
	if d.Authenticated {
		t.Fatal("未知类型不应通过")
	}
}

func TestNewOAuthFlowOIDCForcesPKCE(t *testing.T) {
	p := ProviderConfig{ID: 3, Type: "oidc", OAuth: OAuthConfig{ClientID: "c", UsePKCE: false}}
	flow := NewOAuthFlow(p, "https://site/__owaf/access/oauth/callback")
	if !flow.UsePKCE {
		t.Fatal("OIDC 提供方应强制启用 PKCE")
	}
	if flow.RedirectURI != "https://site/__owaf/access/oauth/callback" {
		t.Fatalf("redirectURI 未正确传入, got %q", flow.RedirectURI)
	}
}

func TestHandleOAuthStart(t *testing.T) {
	g := newTestGate(t)
	stateStore := NewMemoryOAuthStateStore()

	authURL, err := g.HandleOAuthStart(2, "https://site/__owaf/access/oauth/callback", "/app", stateStore)
	if err != nil {
		t.Fatalf("HandleOAuthStart 报错: %v", err)
	}
	if !strings.HasPrefix(authURL, "https://idp.example/authorize?") {
		t.Fatalf("授权地址应指向 IdP authorize 端点, got %q", authURL)
	}
	if !strings.Contains(authURL, "client_id=cid") {
		t.Fatalf("授权地址应带 client_id, got %q", authURL)
	}

	// 非 OAuth 提供方（本地密码）应报错。
	if _, err := g.HandleOAuthStart(1, "https://site/cb", "/", stateStore); err == nil {
		t.Fatal("对 password 提供方发起 OAuth 应失败")
	}

	// 未知提供方应报错。
	if _, err := g.HandleOAuthStart(99, "https://site/cb", "/", stateStore); err == nil {
		t.Fatal("未知提供方应失败")
	}
}

func TestHandleOAuthCallbackInvalidState(t *testing.T) {
	g := newTestGate(t)
	stateStore := NewMemoryOAuthStateStore()

	d := g.HandleOAuthCallback("nonexistent", "code123", "https://site/cb", stateStore)
	if d.Authenticated {
		t.Fatal("无效 state 不应通过")
	}
	if !strings.HasPrefix(d.RedirectURL, PathLogin) {
		t.Fatalf("失败应跳回登录页, got %q", d.RedirectURL)
	}

	empty := g.HandleOAuthCallback("", "", "https://site/cb", stateStore)
	if empty.Authenticated {
		t.Fatal("空参数不应通过")
	}
}

func TestHandleOAuthCallbackStateConsumed(t *testing.T) {
	g := newTestGate(t)
	stateStore := NewMemoryOAuthStateStore()

	// 通过 start 生成合法 state。
	if _, err := g.HandleOAuthStart(2, "https://site/cb", "/", stateStore); err != nil {
		t.Fatal(err)
	}
	// 取出 state 参数。
	var stateParam string
	stateStore.mu.RLock()
	for k := range stateStore.states {
		stateParam = k
	}
	stateStore.mu.RUnlock()
	if stateParam == "" {
		t.Fatal("start 后应存在 state")
	}

	// 回调会尝试真实换取令牌（IdP 不可达），必然失败，但 state 应被消费。
	_ = g.HandleOAuthCallback(stateParam, "code", "https://site/cb", stateStore)
	if st, _ := stateStore.Get(stateParam); st != nil {
		t.Fatal("回调后 state 应被一次性消费删除")
	}
}
