package access

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"

	"My-OpenWaf/internal/store"
)

// testJWTSecret 用于 provider 测试的 JWT 主密钥。
var testJWTSecret = []byte("test-jwt-secret-for-provider-tests")

// invokeProviderHandler 构造带站点 ID（及可选 provider ID）的请求并调用 handler。
func invokeProviderHandler(
	t *testing.T,
	handler app.HandlerFunc,
	method, siteID, providerID string,
	body []byte,
) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI("/api/v1/sites/" + siteID + "/access/providers")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(body)
	}
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ps := param.Params{{Key: "id", Value: siteID}}
	if providerID != "" {
		ps = append(ps, param.Param{Key: "pid", Value: providerID})
	}
	ctx.Params = ps
	handler(context.Background(), ctx)
	return ctx
}

// ---- ListProviders ----

func TestListProvidersEmptyReturns200(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	ctx := invokeProviderHandler(t, ListProviders(repo, testJWTSecret), "GET", "1", "", nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		SiteID    uint           `json:"site_id"`
		Providers []providerResp `json:"providers"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.SiteID != 1 || len(resp.Providers) != 0 {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestListProvidersInvalidSiteIDReturns400(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	ctx := invokeProviderHandler(t, ListProviders(repo, testJWTSecret), "GET", "abc", "", nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid site id: want 400, got %d", ctx.Response.StatusCode())
	}
}

// ---- CreateProvider ----

func TestCreateProviderPasswordType(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	body, _ := json.Marshal(map[string]any{
		"type": store.AccessProviderPassword,
		"name": "local password",
	})
	ctx := invokeProviderHandler(t, CreateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", "", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp providerResp
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Type != store.AccessProviderPassword || !resp.Enabled {
		t.Fatalf("unexpected provider: %+v", resp)
	}
	if resp.Config != nil {
		t.Fatalf("password provider must not carry oauth config: %+v", resp.Config)
	}
}

func TestCreateProviderRejectsInvalidType(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	body, _ := json.Marshal(map[string]any{"type": "saml", "name": "x"})
	ctx := invokeProviderHandler(t, CreateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", "", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid type: want 400, got %d", ctx.Response.StatusCode())
	}
}

func TestCreateProviderRejectsEmptyName(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	body, _ := json.Marshal(map[string]any{"type": store.AccessProviderPassword, "name": "   "})
	ctx := invokeProviderHandler(t, CreateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", "", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("empty name: want 400, got %d", ctx.Response.StatusCode())
	}
}

func TestCreateProviderOAuth2RequiresConfig(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	body, _ := json.Marshal(map[string]any{"type": store.AccessProviderOAuth2, "name": "github"})
	ctx := invokeProviderHandler(t, CreateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", "", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("missing config: want 400, got %d", ctx.Response.StatusCode())
	}
}

func TestCreateProviderOAuth2RequiresClientID(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	body, _ := json.Marshal(map[string]any{
		"type":   store.AccessProviderOAuth2,
		"name":   "github",
		"config": map[string]any{"client_secret": "s3cr3t"},
	})
	ctx := invokeProviderHandler(t, CreateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", "", body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("missing client_id: want 400, got %d", ctx.Response.StatusCode())
	}
}

func TestCreateProviderOAuth2EncryptsAndMasksSecret(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	body, _ := json.Marshal(map[string]any{
		"type": store.AccessProviderOAuth2,
		"name": "github",
		"config": map[string]any{
			"client_id":     "gh-client-id",
			"client_secret": "supersecretvalue",
			"auth_url":      "https://example.com/authorize",
			"token_url":     "https://example.com/token",
			"scopes":        []string{"read:user"},
		},
	})
	ctx := invokeProviderHandler(t, CreateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", "", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	// 明文 client_secret 绝不能出现在响应中。
	if bytes.Contains(ctx.Response.Body(), []byte("supersecretvalue")) {
		t.Fatal("plaintext client_secret leaked into response")
	}
	var resp providerResp
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Config == nil {
		t.Fatal("oauth provider must expose masked config")
	}
	if resp.Config.ClientID != "gh-client-id" {
		t.Fatalf("client_id = %q, want gh-client-id", resp.Config.ClientID)
	}
	if !resp.Config.ClientSecretSet {
		t.Fatal("client_secret_set should be true")
	}
	if resp.Config.ClientSecretMask != "supe***" {
		t.Fatalf("mask = %q, want supe***", resp.Config.ClientSecretMask)
	}

	// 落库的密文必须能解密回原明文。
	providers, err := repo.ListAccessProviders(1)
	if err != nil || len(providers) != 1 {
		t.Fatalf("list providers: err=%v len=%d", err, len(providers))
	}
	var stored store.OAuthProviderConfig
	if err := json.Unmarshal([]byte(providers[0].Config), &stored); err != nil {
		t.Fatalf("decode stored config: %v", err)
	}
	if stored.ClientSecret == "supersecretvalue" {
		t.Fatal("client_secret must be encrypted at rest")
	}
	plain, err := decryptClientSecret(testJWTSecret, stored.ClientSecret)
	if err != nil {
		t.Fatalf("decrypt stored secret: %v", err)
	}
	if plain != "supersecretvalue" {
		t.Fatalf("decrypted secret = %q, want supersecretvalue", plain)
	}
}

// TestCreateProviderHonorsExplicitDisabled 回归测试：Enabled 带 gorm default:true，
// 若 repo 不在插入后回写该列，显式禁用会被静默改写为启用。
func TestCreateProviderHonorsExplicitDisabled(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	body, _ := json.Marshal(map[string]any{
		"type":    store.AccessProviderPassword,
		"name":    "disabled provider",
		"enabled": false,
	})
	ctx := invokeProviderHandler(t, CreateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", "", body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp providerResp
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Enabled {
		t.Fatal("explicit enabled=false must be honored in response")
	}
	providers, err := repo.ListAccessProviders(1)
	if err != nil || len(providers) != 1 {
		t.Fatalf("list providers: err=%v len=%d", err, len(providers))
	}
	if providers[0].Enabled {
		t.Fatal("explicit enabled=false must be persisted, not overwritten by gorm default:true")
	}
}

// ---- UpdateProvider ----

// seedOAuthProvider 创建一条 oauth2 提供方并返回其 ID 字符串。
func seedOAuthProvider(t *testing.T, repo interface {
	CreateAccessProvider(*store.AccessProvider) error
}, siteID uint, secret string) string {
	t.Helper()
	enc, err := encryptClientSecret(testJWTSecret, secret)
	if err != nil {
		t.Fatalf("encrypt seed secret: %v", err)
	}
	cfg, _ := json.Marshal(store.OAuthProviderConfig{
		ClientID:     "seed-client-id",
		ClientSecret: enc,
		AuthURL:      "https://example.com/authorize",
	})
	p := &store.AccessProvider{
		SiteID:   siteID,
		Type:     store.AccessProviderOAuth2,
		Name:     "seeded",
		Priority: 1,
		Enabled:  true,
		Config:   string(cfg),
	}
	if err := repo.CreateAccessProvider(p); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	return strconv.FormatUint(uint64(p.ID), 10)
}

func TestUpdateProviderNotFoundReturns404(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	body, _ := json.Marshal(map[string]any{"priority": 5})
	ctx := invokeProviderHandler(t, UpdateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", "9999", body)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing provider: want 404, got %d", ctx.Response.StatusCode())
	}
}

func TestUpdateProviderRejectsEmptyName(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	pid := seedOAuthProvider(t, repo, 1, "orig-secret")
	name := "   "
	body, _ := json.Marshal(map[string]any{"name": &name})
	ctx := invokeProviderHandler(t, UpdateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", pid, body)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("empty name: want 400, got %d", ctx.Response.StatusCode())
	}
}

func TestUpdateProviderPatchesNamePriorityEnabled(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	pid := seedOAuthProvider(t, repo, 1, "orig-secret")
	name := "renamed"
	priority := 9
	enabled := false
	body, _ := json.Marshal(map[string]any{
		"name":     &name,
		"priority": &priority,
		"enabled":  &enabled,
	})
	ctx := invokeProviderHandler(t, UpdateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", pid, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp providerResp
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "renamed" || resp.Priority != 9 || resp.Enabled {
		t.Fatalf("fields not patched: %+v", resp)
	}
}

// TestUpdateProviderEmptyClientSecretPreservesStoredSecret 验证更新其它字段时不会误清空密钥。
func TestUpdateProviderEmptyClientSecretPreservesStoredSecret(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	pid := seedOAuthProvider(t, repo, 1, "keep-this-secret")

	body, _ := json.Marshal(map[string]any{
		"config": map[string]any{
			"client_id":     "updated-client-id",
			"client_secret": "",
			"auth_url":      "https://example.com/new-authorize",
		},
	})
	ctx := invokeProviderHandler(t, UpdateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", pid, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	providers, err := repo.ListAccessProviders(1)
	if err != nil || len(providers) != 1 {
		t.Fatalf("list providers: err=%v len=%d", err, len(providers))
	}
	var stored store.OAuthProviderConfig
	if err := json.Unmarshal([]byte(providers[0].Config), &stored); err != nil {
		t.Fatalf("decode stored config: %v", err)
	}
	if stored.ClientID != "updated-client-id" {
		t.Fatalf("client_id = %q, want updated-client-id", stored.ClientID)
	}
	plain, err := decryptClientSecret(testJWTSecret, stored.ClientSecret)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain != "keep-this-secret" {
		t.Fatalf("secret = %q, want preserved keep-this-secret", plain)
	}
}

func TestUpdateProviderNewClientSecretReplacesStored(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	pid := seedOAuthProvider(t, repo, 1, "old-secret")

	body, _ := json.Marshal(map[string]any{
		"config": map[string]any{
			"client_id":     "seed-client-id",
			"client_secret": "brand-new-secret",
		},
	})
	ctx := invokeProviderHandler(t, UpdateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "1", pid, body)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	providers, _ := repo.ListAccessProviders(1)
	var stored store.OAuthProviderConfig
	if err := json.Unmarshal([]byte(providers[0].Config), &stored); err != nil {
		t.Fatalf("decode stored config: %v", err)
	}
	plain, err := decryptClientSecret(testJWTSecret, stored.ClientSecret)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain != "brand-new-secret" {
		t.Fatalf("secret = %q, want brand-new-secret", plain)
	}
}

func TestUpdateProviderCrossSiteReturns404(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	pid := seedOAuthProvider(t, repo, 1, "s")
	body, _ := json.Marshal(map[string]any{"priority": 3})
	ctx := invokeProviderHandler(t, UpdateProvider(repo, func() error { return nil }, testJWTSecret),
		"POST", "2", pid, body)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("cross-site update: want 404, got %d", ctx.Response.StatusCode())
	}
}

// ---- DeleteProvider ----

func TestDeleteProviderSucceeds(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	pid := seedOAuthProvider(t, repo, 1, "s")
	ctx := invokeProviderHandler(t, DeleteProvider(repo, func() error { return nil }),
		"POST", "1", pid, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	providers, _ := repo.ListAccessProviders(1)
	if len(providers) != 0 {
		t.Fatalf("provider should be deleted, got %d remaining", len(providers))
	}
}

func TestDeleteProviderNotFoundReturns404(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	ctx := invokeProviderHandler(t, DeleteProvider(repo, func() error { return nil }),
		"POST", "1", "9999", nil)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing provider: want 404, got %d", ctx.Response.StatusCode())
	}
}

func TestDeleteProviderCrossSiteReturns404(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	pid := seedOAuthProvider(t, repo, 1, "s")
	ctx := invokeProviderHandler(t, DeleteProvider(repo, func() error { return nil }),
		"POST", "2", pid, nil)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("cross-site delete: want 404, got %d", ctx.Response.StatusCode())
	}
}

func TestDeleteProviderInvalidProviderIDReturns400(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	ctx := invokeProviderHandler(t, DeleteProvider(repo, func() error { return nil }),
		"POST", "1", "notanumber", nil)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid provider id: want 400, got %d", ctx.Response.StatusCode())
	}
}

// ---- previousClientSecret ----

func TestPreviousClientSecret(t *testing.T) {
	if got := previousClientSecret(""); got != "" {
		t.Errorf("empty json: got %q, want empty", got)
	}
	if got := previousClientSecret("not-json"); got != "" {
		t.Errorf("malformed json: got %q, want empty", got)
	}
	cfg, _ := json.Marshal(store.OAuthProviderConfig{ClientID: "id", ClientSecret: "cipher-text"})
	if got := previousClientSecret(string(cfg)); got != "cipher-text" {
		t.Errorf("valid json: got %q, want cipher-text", got)
	}
}
