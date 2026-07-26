package system

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

/**
 * newAdminAPIKeyRepoForTest 建立仅含 AdminAPIKey 表的内存库。
 */
func newAdminAPIKeyRepoForTest(t *testing.T) *repository.AdminAPIKeyRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.AdminAPIKey{}); err != nil {
		t.Fatalf("migrate admin api keys: %v", err)
	}
	return repository.NewAdminAPIKeyRepo(db)
}

/**
 * invokeAPIKeyHandler 直接驱动 Hertz handler 并返回响应上下文。
 */
func invokeAPIKeyHandler(t *testing.T, handler app.HandlerFunc, method, uri string, params param.Params, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}

	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = params
	handler(context.Background(), ctx)
	return ctx
}

func TestCreateAPIKeyReturnsPlaintextTokenOnceAndStoresOnlyHash(t *testing.T) {
	repo := newAdminAPIKeyRepoForTest(t)

	ctx := invokeAPIKeyHandler(t, CreateAPIKey(repo), "POST", "/api/v1/api-keys", nil, []byte(`{"name":"ci-runner"}`))
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("create status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}

	var created struct {
		Token string `json:"token"`
		ID    uint   `json:"id"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &created); err != nil {
		t.Fatalf("decode created key: %v", err)
	}
	if created.Name != "ci-runner" || created.ID == 0 {
		t.Fatalf("created key = %#v, want named key with an id", created)
	}
	if len(created.Token) != 64 {
		t.Fatalf("token length = %d, want 64 hex chars", len(created.Token))
	}

	// 落库的必须是 bcrypt 哈希，明文 token 不得出现在任何持久化字段中。
	stored, err := repo.Get(created.ID)
	if err != nil {
		t.Fatalf("load stored key: %v", err)
	}
	if stored.TokenHash == "" || stored.TokenHash == created.Token {
		t.Fatalf("stored token hash must not equal the plaintext token")
	}
	if _, ok := repo.Verify(created.Token); !ok {
		t.Fatalf("returned plaintext token must verify against the stored hash")
	}
}

func TestCreateAPIKeyDefaultsUnnamedAndRejectsMalformedBody(t *testing.T) {
	repo := newAdminAPIKeyRepoForTest(t)

	ctx := invokeAPIKeyHandler(t, CreateAPIKey(repo), "POST", "/api/v1/api-keys", nil, []byte(`{}`))
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("create status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !bytes.Contains(ctx.Response.Body(), []byte(`"name":"unnamed"`)) {
		t.Fatalf("missing name should default to unnamed, got %s", bytes.TrimSpace(ctx.Response.Body()))
	}

	bad := invokeAPIKeyHandler(t, CreateAPIKey(repo), "POST", "/api/v1/api-keys", nil, []byte(`{"name":`))
	if bad.Response.StatusCode() != 400 {
		t.Fatalf("malformed body status = %d, want 400", bad.Response.StatusCode())
	}
}

func TestListAPIKeysNeverExposesTokenHashOrPrefix(t *testing.T) {
	repo := newAdminAPIKeyRepoForTest(t)
	token, key, err := repo.Create("deploy-bot")
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	ctx := invokeAPIKeyHandler(t, ListAPIKeys(repo), "GET", "/api/v1/api-keys", nil, nil)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("list status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	body := ctx.Response.Body()

	if bytes.Contains(body, []byte(token)) {
		t.Fatalf("api key list leaked the plaintext token")
	}
	if bytes.Contains(body, []byte(key.TokenHash)) {
		t.Fatalf("api key list leaked the stored token hash")
	}
	if bytes.Contains(body, []byte(key.Prefix)) {
		t.Fatalf("api key list leaked the token prefix")
	}
	for _, forbidden := range []string{"token_hash", "TokenHash", "prefix", "Prefix", "token"} {
		if bytes.Contains(body, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("api key list response must not carry a %q field: %s", forbidden, bytes.TrimSpace(body))
		}
	}

	var resp struct {
		Items []store.AdminAPIKey `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode api key list: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].Name != "deploy-bot" {
		t.Fatalf("api key list = %#v, want the seeded key", resp.Items)
	}
}

func TestDeleteAPIKeyRemovesKeyAndValidatesID(t *testing.T) {
	repo := newAdminAPIKeyRepoForTest(t)
	_, key, err := repo.Create("temp-key")
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	idStr := strconv.FormatUint(uint64(key.ID), 10)

	ctx := invokeAPIKeyHandler(t, DeleteAPIKey(repo), "POST", "/api/v1/api-keys/"+idStr+"/delete", param.Params{{Key: "id", Value: idStr}}, nil)
	if ctx.Response.StatusCode() != 204 {
		t.Fatalf("delete status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	items, err := repo.List()
	if err != nil {
		t.Fatalf("list api keys: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("api key count after delete = %d, want 0", len(items))
	}

	bad := invokeAPIKeyHandler(t, DeleteAPIKey(repo), "POST", "/api/v1/api-keys/abc/delete", param.Params{{Key: "id", Value: "abc"}}, nil)
	if bad.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", bad.Response.StatusCode())
	}
}
