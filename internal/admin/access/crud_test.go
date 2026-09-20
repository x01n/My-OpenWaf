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
	"golang.org/x/crypto/bcrypt"

	"My-OpenWaf/internal/store"
)

// invokeWithSiteAndSubID 构造带 siteID + 子资源 ID 双参数的请求。
func invokeWithSiteAndSubID(
	t *testing.T,
	handler app.HandlerFunc,
	siteIDKey, siteIDVal, subIDKey, subIDVal string,
	body []byte,
) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/test")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(body)
	}
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{
		{Key: siteIDKey, Value: siteIDVal},
		{Key: subIDKey, Value: subIDVal},
	}
	handler(context.Background(), ctx)
	return ctx
}

// ---- PathRule CRUD ----

func createPathRule(t *testing.T, siteID string, path, action string) *app.RequestContext {
	t.Helper()
	repo := newAccessControlRepoForTest(t)
	body, _ := json.Marshal(map[string]any{"path": path, "action": action})
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/" + siteID + "/access/path-rules")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: siteID}}
	CreatePathRule(repo, func() error { return nil })(context.Background(), ctx)
	return ctx
}

func TestListPathRulesReturnsSeededRules(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	// 创建两条规则
	for _, p := range []string{"/admin", "/api"} {
		body, _ := json.Marshal(map[string]any{"path": p, "action": "require_auth"})
		var req protocol.Request
		req.SetMethod("POST")
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(body)
		ctx := app.NewContext(0)
		req.CopyTo(&ctx.Request)
		ctx.Params = param.Params{{Key: "id", Value: "1"}}
		CreatePathRule(repo, func() error { return nil })(context.Background(), ctx)
	}
	// List
	var req protocol.Request
	req.SetMethod("GET")
	req.SetRequestURI("/api/v1/sites/1/access/path-rules")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}}
	ListPathRules(repo)(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Rules []store.AccessPathRule `json:"rules"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(resp.Rules))
	}
}

func TestCreatePathRuleEmptyPathReturns400(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	body := []byte(`{"path":"   ","action":"require_auth"}`)
	var req protocol.Request
	req.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}}
	CreatePathRule(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("empty path: want 400, got %d", ctx.Response.StatusCode())
	}
}

func TestUpdatePathRuleReturnsNotFound(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	body, _ := json.Marshal(map[string]any{"action": "allow"})
	var req protocol.Request
	req.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}, {Key: "rid", Value: "9999"}}
	UpdatePathRule(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing rule: want 404, got %d", ctx.Response.StatusCode())
	}
}

func TestUpdatePathRulePatchesFields(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	// 先创建
	createBody, _ := json.Marshal(map[string]any{"path": "/old", "action": "require_auth"})
	var creq protocol.Request
	creq.SetMethod("POST")
	creq.Header.Set("Content-Type", "application/json")
	creq.SetBody(createBody)
	cctx := app.NewContext(0)
	creq.CopyTo(&cctx.Request)
	cctx.Params = param.Params{{Key: "id", Value: "1"}}
	CreatePathRule(repo, func() error { return nil })(context.Background(), cctx)
	var rule store.AccessPathRule
	json.Unmarshal(cctx.Response.Body(), &rule)

	ridStr := strconv.FormatUint(uint64(rule.ID), 10)
	newPath := "/new"
	enabled := false
	patchBody, _ := json.Marshal(map[string]any{"path": &newPath, "enabled": &enabled})
	var ureq protocol.Request
	ureq.SetMethod("POST")
	ureq.Header.Set("Content-Type", "application/json")
	ureq.SetBody(patchBody)
	uctx := app.NewContext(0)
	ureq.CopyTo(&uctx.Request)
	uctx.Params = param.Params{{Key: "id", Value: "1"}, {Key: "rid", Value: ridStr}}
	UpdatePathRule(repo, func() error { return nil })(context.Background(), uctx)
	if uctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", uctx.Response.StatusCode(), bytes.TrimSpace(uctx.Response.Body()))
	}
	var updated store.AccessPathRule
	json.Unmarshal(uctx.Response.Body(), &updated)
	if updated.Path != "/new" {
		t.Fatalf("path not updated: got %q", updated.Path)
	}
	if updated.Enabled {
		t.Fatal("enabled should be false after patch")
	}
}

func TestUpdatePathRuleRejectsInvalidAction(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	// 先创建
	createBody, _ := json.Marshal(map[string]any{"path": "/p", "action": "require_auth"})
	var creq protocol.Request
	creq.SetMethod("POST")
	creq.Header.Set("Content-Type", "application/json")
	creq.SetBody(createBody)
	cctx := app.NewContext(0)
	creq.CopyTo(&cctx.Request)
	cctx.Params = param.Params{{Key: "id", Value: "1"}}
	CreatePathRule(repo, func() error { return nil })(context.Background(), cctx)
	var rule store.AccessPathRule
	json.Unmarshal(cctx.Response.Body(), &rule)

	ridStr := strconv.FormatUint(uint64(rule.ID), 10)
	badAction := "block"
	patchBody, _ := json.Marshal(map[string]any{"action": &badAction})
	var ureq protocol.Request
	ureq.SetMethod("POST")
	ureq.Header.Set("Content-Type", "application/json")
	ureq.SetBody(patchBody)
	uctx := app.NewContext(0)
	ureq.CopyTo(&uctx.Request)
	uctx.Params = param.Params{{Key: "id", Value: "1"}, {Key: "rid", Value: ridStr}}
	UpdatePathRule(repo, func() error { return nil })(context.Background(), uctx)
	if uctx.Response.StatusCode() != 400 {
		t.Fatalf("invalid action: want 400, got %d", uctx.Response.StatusCode())
	}
}

func TestDeletePathRuleSucceeds(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	// 先创建
	createBody, _ := json.Marshal(map[string]any{"path": "/del", "action": "deny"})
	var creq protocol.Request
	creq.SetMethod("POST")
	creq.Header.Set("Content-Type", "application/json")
	creq.SetBody(createBody)
	cctx := app.NewContext(0)
	creq.CopyTo(&cctx.Request)
	cctx.Params = param.Params{{Key: "id", Value: "1"}}
	CreatePathRule(repo, func() error { return nil })(context.Background(), cctx)
	var rule store.AccessPathRule
	json.Unmarshal(cctx.Response.Body(), &rule)
	ridStr := strconv.FormatUint(uint64(rule.ID), 10)

	// 删除
	var dreq protocol.Request
	dreq.SetMethod("POST")
	dctx := app.NewContext(0)
	dreq.CopyTo(&dctx.Request)
	dctx.Params = param.Params{{Key: "id", Value: "1"}, {Key: "rid", Value: ridStr}}
	DeletePathRule(repo, func() error { return nil })(context.Background(), dctx)
	if dctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", dctx.Response.StatusCode(), bytes.TrimSpace(dctx.Response.Body()))
	}
}

func TestDeletePathRuleCrossSiteReturns404(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	// 在站点 1 创建规则
	createBody, _ := json.Marshal(map[string]any{"path": "/secure", "action": "require_auth"})
	var creq protocol.Request
	creq.SetMethod("POST")
	creq.Header.Set("Content-Type", "application/json")
	creq.SetBody(createBody)
	cctx := app.NewContext(0)
	creq.CopyTo(&cctx.Request)
	cctx.Params = param.Params{{Key: "id", Value: "1"}}
	CreatePathRule(repo, func() error { return nil })(context.Background(), cctx)
	var rule store.AccessPathRule
	json.Unmarshal(cctx.Response.Body(), &rule)
	ridStr := strconv.FormatUint(uint64(rule.ID), 10)

	// 用站点 2 删除站点 1 的规则（跨站越权）
	var dreq protocol.Request
	dreq.SetMethod("POST")
	dctx := app.NewContext(0)
	dreq.CopyTo(&dctx.Request)
	dctx.Params = param.Params{{Key: "id", Value: "2"}, {Key: "rid", Value: ridStr}}
	DeletePathRule(repo, func() error { return nil })(context.Background(), dctx)
	if dctx.Response.StatusCode() != 404 {
		t.Fatalf("cross-site delete: want 404, got %d", dctx.Response.StatusCode())
	}
}

// ---- User CRUD ----

func seedUser(t *testing.T, repo interface {
	CreateAccessUser(*store.AccessUser) error
}, siteID uint, username string) *store.AccessUser {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcryptCost)
	u := &store.AccessUser{SiteID: siteID, Username: username, PasswordHash: string(hash), Enabled: true}
	if err := repo.CreateAccessUser(u); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

func TestCreateUserPersistsAndHashesPassword(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	body, _ := json.Marshal(map[string]any{"username": "alice", "password": "secret"})
	var req protocol.Request
	req.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}}
	CreateUser(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	// 响应中 password_hash 字段应为 "-" tag（json隐藏），但 username 应可见
	body2 := ctx.Response.Body()
	if bytes.Contains(body2, []byte(`"password_hash"`)) {
		t.Fatal("password_hash must not appear in response")
	}
}

func TestUpdateUserChangesEnabledState(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	u := seedUser(t, repo, 1, "bob")
	uidStr := strconv.FormatUint(uint64(u.ID), 10)

	enabled := false
	patchBody, _ := json.Marshal(map[string]any{"enabled": &enabled})
	var req protocol.Request
	req.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(patchBody)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}, {Key: "uid", Value: uidStr}}
	UpdateUser(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var updated store.AccessUser
	json.Unmarshal(ctx.Response.Body(), &updated)
	if updated.Enabled {
		t.Fatal("enabled should be false after update")
	}
}

func TestUpdateUserReturnsNotFound(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	patchBody, _ := json.Marshal(map[string]any{"password": "new"})
	var req protocol.Request
	req.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(patchBody)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}, {Key: "uid", Value: "9999"}}
	UpdateUser(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("missing user: want 404, got %d", ctx.Response.StatusCode())
	}
}

func TestDeleteUserSucceeds(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	u := seedUser(t, repo, 1, "carol")
	uidStr := strconv.FormatUint(uint64(u.ID), 10)

	var req protocol.Request
	req.SetMethod("POST")
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}, {Key: "uid", Value: uidStr}}
	DeleteUser(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

func TestUpdateUserPasswordChangesHash(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	u := seedUser(t, repo, 1, "dave")
	uidStr := strconv.FormatUint(uint64(u.ID), 10)
	oldHash := u.PasswordHash

	patchBody, _ := json.Marshal(map[string]any{"password": "newpass"})
	var req protocol.Request
	req.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(patchBody)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}, {Key: "uid", Value: uidStr}}
	UpdateUser(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	// 直接从 DB 验证密码哈希已更新
	users, _ := repo.ListAccessUsers(1)
	for _, usr := range users {
		if usr.ID == u.ID {
			if usr.PasswordHash == oldHash {
				t.Fatal("password hash must change after update")
			}
			if err := bcrypt.CompareHashAndPassword([]byte(usr.PasswordHash), []byte("newpass")); err != nil {
				t.Fatalf("new password hash does not verify: %v", err)
			}
			return
		}
	}
	t.Fatal("user not found in DB after update")
}

// TestCreatePathRuleHonorsExplicitDisabled 回归测试：AccessPathRule.Enabled 带 gorm default:true，
// 若 repo 不在插入后回写该列，显式禁用会被静默改写为启用。
func TestCreatePathRuleHonorsExplicitDisabled(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	enabled := false
	body, _ := json.Marshal(map[string]any{
		"path":    "/disabled-rule",
		"action":  "deny",
		"enabled": &enabled,
	})
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/1/access/path-rules")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}}
	CreatePathRule(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp store.AccessPathRule
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Enabled {
		t.Fatal("explicit enabled=false must be honored in response")
	}
	rules, err := repo.ListAccessPathRules(1)
	if err != nil || len(rules) != 1 {
		t.Fatalf("list path rules: err=%v len=%d", err, len(rules))
	}
	if rules[0].Enabled {
		t.Fatal("explicit enabled=false must be persisted, not overwritten by gorm default:true")
	}
}

// TestCreateUserHonorsExplicitDisabled 回归测试：AccessUser.Enabled 带 gorm default:true，
// 若 repo 不在插入后回写该列，显式禁用会被静默改写为启用。
func TestCreateUserHonorsExplicitDisabled(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	enabled := false
	body, _ := json.Marshal(map[string]any{
		"username": "disabled-user",
		"password": "secret",
		"enabled":  &enabled,
	})
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/1/access/users")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(body)
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}}
	CreateUser(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp store.AccessUser
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Enabled {
		t.Fatal("explicit enabled=false must be honored in response")
	}
	users, err := repo.ListAccessUsers(1)
	if err != nil || len(users) != 1 {
		t.Fatalf("list users: err=%v len=%d", err, len(users))
	}
	if users[0].Enabled {
		t.Fatal("explicit enabled=false must be persisted, not overwritten by gorm default:true")
	}
}
