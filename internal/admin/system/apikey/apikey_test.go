package apikey

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store/auth"
	"My-OpenWaf/internal/store/repository"
)

/**
 * newAdminAPIKeyRepoForTest 建立含 AdminAPIKey 与 AdminAccount 表的内存库，
 * 并预置一个名为 owner 的 admin 账号 —— 令牌必须挂在账号下，没有账号就创建不了。
 *
 * @return 令牌仓储、账号仓储、预置账号的用户名。
 */
func newAdminAPIKeyRepoForTest(t *testing.T) (*repository.AdminAPIKeyRepo, *repository.AdminAccountRepo, string) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.AdminAPIKey{}, &auth.AdminAccount{}); err != nil {
		t.Fatalf("migrate admin auth tables: %v", err)
	}
	accountRepo := repository.NewAdminAccountRepo(db)
	if _, err := accountRepo.Create("owner", "owner-password", auth.RoleAdmin); err != nil {
		t.Fatalf("seed owner account: %v", err)
	}
	return repository.NewAdminAPIKeyRepo(db), accountRepo, "owner"
}

/**
 * invokeAPIKeyHandler 直接驱动 Hertz handler 并返回响应上下文。
 */
func invokeAPIKeyHandler(t *testing.T, handler app.HandlerFunc, username, method, uri string, params param.Params, payload []byte) *app.RequestContext {
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
	if username != "" {
		ctx.Set("auth_username", username)
	}
	handler(context.Background(), ctx)
	return ctx
}

func TestCreateAPIKeyReturnsPlaintextTokenOnceAndStoresOnlyHash(t *testing.T) {
	repo, accountRepo, ownerName := newAdminAPIKeyRepoForTest(t)
	_ = ownerName

	ctx := invokeAPIKeyHandler(t, CreateAPIKey(repo, accountRepo), "owner", "POST", "/api/v1/api-keys", nil, []byte(`{"name":"ci-runner"}`))
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
	repo, accountRepo, ownerName := newAdminAPIKeyRepoForTest(t)
	_ = ownerName

	ctx := invokeAPIKeyHandler(t, CreateAPIKey(repo, accountRepo), "owner", "POST", "/api/v1/api-keys", nil, []byte(`{}`))
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("create status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if !bytes.Contains(ctx.Response.Body(), []byte(`"name":"unnamed"`)) {
		t.Fatalf("missing name should default to unnamed, got %s", bytes.TrimSpace(ctx.Response.Body()))
	}

	bad := invokeAPIKeyHandler(t, CreateAPIKey(repo, accountRepo), "owner", "POST", "/api/v1/api-keys", nil, []byte(`{"name":`))
	if bad.Response.StatusCode() != 400 {
		t.Fatalf("malformed body status = %d, want 400", bad.Response.StatusCode())
	}
}

func TestCreateAPIKeyRejectsNamesOverStorageLimit(t *testing.T) {
	repo, accountRepo, ownerName := newAdminAPIKeyRepoForTest(t)
	_ = ownerName
	tooLong := strings.Repeat("名", 65)
	ctx := invokeAPIKeyHandler(t, CreateAPIKey(repo, accountRepo), "owner", "POST", "/api/v1/api-keys", nil, []byte(`{"name":"`+tooLong+`"}`))
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("oversized name status = %d, want 400: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestListAPIKeysNeverExposesTokenHashOrPrefix(t *testing.T) {
	repo, accountRepo, ownerName := newAdminAPIKeyRepoForTest(t)
	_ = ownerName
	token, key, err := repo.Create(ownerID(t, accountRepo), "deploy-bot")
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	ctx := invokeAPIKeyHandler(t, ListAPIKeys(repo, accountRepo), "owner", "GET", "/api/v1/api-keys", nil, nil)
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
		Items []auth.AdminAPIKey `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode api key list: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].Name != "deploy-bot" {
		t.Fatalf("api key list = %#v, want the seeded key", resp.Items)
	}
}

func TestDeleteAPIKeyRemovesKeyAndValidatesID(t *testing.T) {
	repo, accountRepo, ownerName := newAdminAPIKeyRepoForTest(t)
	_ = ownerName
	_, key, err := repo.Create(ownerID(t, accountRepo), "temp-key")
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	idStr := strconv.FormatUint(uint64(key.ID), 10)

	ctx := invokeAPIKeyHandler(t, DeleteAPIKey(repo), "owner", "POST", "/api/v1/api-keys/"+idStr+"/delete", param.Params{{Key: "id", Value: idStr}}, nil)
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

	bad := invokeAPIKeyHandler(t, DeleteAPIKey(repo), "owner", "POST", "/api/v1/api-keys/abc/delete", param.Params{{Key: "id", Value: "abc"}}, nil)
	if bad.Response.StatusCode() != 400 {
		t.Fatalf("invalid id status = %d, want 400", bad.Response.StatusCode())
	}
}

func TestDeleteAPIKeyReturnsNotFoundForMissingKey(t *testing.T) {
	repo, _, ownerName := newAdminAPIKeyRepoForTest(t)
	_ = ownerName
	ctx := invokeAPIKeyHandler(t, DeleteAPIKey(repo), "owner", "POST", "/api/v1/api-keys/999/delete", param.Params{{Key: "id", Value: "999"}}, nil)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing key status = %d, want 404", ctx.Response.StatusCode())
	}
}

/**
 * ownerID 解析预置账号的主键，供直接调用仓储层的用例使用。
 */
func ownerID(t *testing.T, accountRepo *repository.AdminAccountRepo) uint {
	t.Helper()
	acct, err := accountRepo.GetByUsername("owner")
	if err != nil {
		t.Fatalf("load owner account: %v", err)
	}
	return acct.ID
}
