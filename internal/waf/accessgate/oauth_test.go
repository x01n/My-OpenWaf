package accessgate

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuthFlowStartAuthURL(t *testing.T) {
	stateStore := NewMemoryOAuthStateStore()

	flow := &OAuthFlow{
		ProviderID:  10,
		ClientID:    "my-client-id",
		AuthURL:     "https://idp.example.com/authorize",
		RedirectURI: "https://app.example.com/__owaf/access/oauth/callback",
		Scopes:      []string{"openid", "email"},
		UsePKCE:     false,
	}

	authURL, err := flow.StartAuthFlow(stateStore, 1, "/dashboard")
	if err != nil {
		t.Fatalf("StartAuthFlow 返回错误: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("生成的授权 URL 不合法: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host != "idp.example.com" || parsed.Path != "/authorize" {
		t.Fatalf("授权 URL 基础部分不正确: %s", authURL)
	}

	q := parsed.Query()
	if q.Get("client_id") != "my-client-id" {
		t.Fatalf("client_id 不匹配: got %q", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://app.example.com/__owaf/access/oauth/callback" {
		t.Fatalf("redirect_uri 不匹配: got %q", q.Get("redirect_uri"))
	}
	if q.Get("response_type") != "code" {
		t.Fatalf("response_type 应为 code: got %q", q.Get("response_type"))
	}
	if q.Get("scope") != "openid email" {
		t.Fatalf("scope 不匹配: got %q", q.Get("scope"))
	}
	if q.Get("state") == "" {
		t.Fatal("state 参数不应为空")
	}
	if q.Get("code_challenge") != "" {
		t.Fatal("未启用 PKCE 时不应携带 code_challenge")
	}
}

func TestOAuthFlowStartAuthURLWithPKCE(t *testing.T) {
	stateStore := NewMemoryOAuthStateStore()

	flow := &OAuthFlow{
		ProviderID:  20,
		ClientID:    "pkce-client",
		AuthURL:     "https://idp.example.com/authorize",
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"profile"},
		UsePKCE:     true,
	}

	authURL, err := flow.StartAuthFlow(stateStore, 2, "/app")
	if err != nil {
		t.Fatalf("StartAuthFlow 返回错误: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("生成的授权 URL 不合法: %v", err)
	}

	q := parsed.Query()
	if q.Get("code_challenge") == "" {
		t.Fatal("启用 PKCE 时应携带 code_challenge")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method 应为 S256: got %q", q.Get("code_challenge_method"))
	}

	// 验证 state store 中保存了 code_verifier
	stateParam := q.Get("state")
	st, err := stateStore.Get(stateParam)
	if err != nil || st == nil {
		t.Fatal("state store 中应保存了对应的 state 条目")
	}
	if st.CodeVerifier == "" {
		t.Fatal("PKCE 启用时 state 应包含 code_verifier")
	}
	if st.SiteID != 2 {
		t.Fatalf("state 的 SiteID 不匹配: got %d, want 2", st.SiteID)
	}
	if st.ProviderID != 20 {
		t.Fatalf("state 的 ProviderID 不匹配: got %d, want 20", st.ProviderID)
	}
}

func TestOAuthFlowStartAuthURLDefaultScope(t *testing.T) {
	stateStore := NewMemoryOAuthStateStore()

	flow := &OAuthFlow{
		ProviderID:  30,
		ClientID:    "default-scope-client",
		AuthURL:     "https://idp.example.com/authorize",
		RedirectURI: "https://app.example.com/callback",
		Scopes:      nil, // 未指定 scope
	}

	authURL, err := flow.StartAuthFlow(stateStore, 1, "/")
	if err != nil {
		t.Fatalf("StartAuthFlow 返回错误: %v", err)
	}

	parsed, _ := url.Parse(authURL)
	if parsed.Query().Get("scope") != "openid email profile" {
		t.Fatalf("未指定 scope 时应使用默认值, got %q", parsed.Query().Get("scope"))
	}
}

func TestOAuthFlowStartAuthURLNoAuthURLFails(t *testing.T) {
	stateStore := NewMemoryOAuthStateStore()

	flow := &OAuthFlow{
		ProviderID:  40,
		ClientID:    "no-auth-url",
		AuthURL:     "",
		RedirectURI: "https://app.example.com/callback",
	}

	_, err := flow.StartAuthFlow(stateStore, 1, "/")
	if err == nil {
		t.Fatal("AuthURL 为空且无 Issuer 时应返回错误")
	}
}

func TestOAuthFlowStartAuthURLWithExistingQueryParams(t *testing.T) {
	stateStore := NewMemoryOAuthStateStore()

	flow := &OAuthFlow{
		ProviderID:  50,
		ClientID:    "existing-params",
		AuthURL:     "https://idp.example.com/authorize?tenant=abc",
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"openid"},
	}

	authURL, err := flow.StartAuthFlow(stateStore, 1, "/")
	if err != nil {
		t.Fatalf("StartAuthFlow 返回错误: %v", err)
	}
	// AuthURL 已有 "?" 时应使用 "&" 连接
	if !strings.Contains(authURL, "tenant=abc&") && !strings.Contains(authURL, "&tenant=abc") {
		t.Fatalf("已有查询参数应保留: %s", authURL)
	}
	if strings.Contains(authURL, "?tenant=abc?") {
		t.Fatalf("不应出现双 '?': %s", authURL)
	}
}

func TestOAuthStateStoreExpiry(t *testing.T) {
	store := NewMemoryOAuthStateStore()

	// 保存一个已过期的 state
	expired := &OAuthState{
		State:     "expired-state-001",
		SiteID:    1,
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	if err := store.Save(expired); err != nil {
		t.Fatal(err)
	}

	// 保存一个有效的 state
	valid := &OAuthState{
		State:     "valid-state-001",
		SiteID:    1,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := store.Save(valid); err != nil {
		t.Fatal(err)
	}

	// 已过期的 state 应返回 nil
	got, err := store.Get("expired-state-001")
	if err != nil {
		t.Fatalf("Get 不应返回错误: %v", err)
	}
	if got != nil {
		t.Fatal("过期的 state 应返回 nil")
	}

	// 有效的 state 应正常返回
	got, err = store.Get("valid-state-001")
	if err != nil {
		t.Fatalf("Get 不应返回错误: %v", err)
	}
	if got == nil {
		t.Fatal("有效的 state 不应返回 nil")
	}
	if got.State != "valid-state-001" {
		t.Fatalf("state 值不匹配: got %q", got.State)
	}
}

func TestOAuthStateStoreCleanExpired(t *testing.T) {
	store := NewMemoryOAuthStateStore()

	_ = store.Save(&OAuthState{State: "old", SiteID: 1, ExpiresAt: time.Now().Add(-1 * time.Hour)})
	_ = store.Save(&OAuthState{State: "fresh", SiteID: 1, ExpiresAt: time.Now().Add(1 * time.Hour)})

	if err := store.CleanExpired(); err != nil {
		t.Fatalf("CleanExpired 不应报错: %v", err)
	}

	store.mu.RLock()
	_, oldExists := store.states["old"]
	_, freshExists := store.states["fresh"]
	store.mu.RUnlock()

	if oldExists {
		t.Fatal("过期 state 应被清理")
	}
	if !freshExists {
		t.Fatal("有效 state 不应被清理")
	}
}

func TestOAuthStateStoreDelete(t *testing.T) {
	store := NewMemoryOAuthStateStore()

	_ = store.Save(&OAuthState{State: "to-delete", SiteID: 1, ExpiresAt: time.Now().Add(1 * time.Hour)})

	if err := store.Delete("to-delete"); err != nil {
		t.Fatalf("Delete 不应报错: %v", err)
	}

	got, _ := store.Get("to-delete")
	if got != nil {
		t.Fatal("已删除的 state 应返回 nil")
	}

	// 删除不存在的 key 不应报错
	if err := store.Delete("nonexistent"); err != nil {
		t.Fatalf("删除不存在的 key 不应报错: %v", err)
	}
}

func TestOAuthStateStoreGetNonexistent(t *testing.T) {
	store := NewMemoryOAuthStateStore()

	got, err := store.Get("does-not-exist")
	if err != nil {
		t.Fatalf("Get 不存在的 key 不应报错: %v", err)
	}
	if got != nil {
		t.Fatal("不存在的 key 应返回 nil")
	}
}
