package access

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/route/param"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newAccessControlRepoForTest(t *testing.T) *repository.AccessControlRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&store.SiteAccessConfig{},
		&store.AccessUser{},
		&store.AccessPathRule{},
		&store.AccessProvider{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return repository.NewAccessControlRepo(db)
}

func invokeAccessHandler(t *testing.T, handler app.HandlerFunc, siteID string, payload []byte) *app.RequestContext {
	t.Helper()
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/" + siteID + "/access-config")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(payload)
	}
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: siteID}}
	handler(context.Background(), ctx)
	return ctx
}

// TestSaveAccessConfigDefaultSessionTTLWhenZero 验证 session_ttl=0 时 fallback 到 86400。
func TestSaveAccessConfigDefaultSessionTTLWhenZero(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	ctx := invokeAccessHandler(t, SaveAccessConfig(repo, func() error { return nil }), "1",
		[]byte(`{"enabled":true,"session_ttl":0}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp accessConfigResp
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.SessionTTL != defaultSessionTTL {
		t.Fatalf("expected session_ttl to default to %d, got %d", defaultSessionTTL, resp.SessionTTL)
	}
}

// TestSaveAccessConfigClearSharedPassword 验证 clear_shared_password=true 时清空哈希。
func TestSaveAccessConfigClearSharedPassword(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	// 先设置密码
	invokeAccessHandler(t, SaveAccessConfig(repo, func() error { return nil }), "1",
		[]byte(`{"enabled":true,"shared_password":"secret123","session_ttl":3600}`))

	// 验证密码已存储（通过 shared_password_set 判断）
	getCtx := invokeAccessHandler(t, GetAccessConfig(repo), "1", nil)
	var resp accessConfigResp
	if err := json.Unmarshal(getCtx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if !resp.SharedPasswordSet {
		t.Fatalf("expected shared_password_set=true after setting password")
	}

	// 清空密码
	ctx := invokeAccessHandler(t, SaveAccessConfig(repo, func() error { return nil }), "1",
		[]byte(`{"enabled":true,"clear_shared_password":true,"session_ttl":3600}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var clearResp accessConfigResp
	if err := json.Unmarshal(ctx.Response.Body(), &clearResp); err != nil {
		t.Fatalf("decode clear response: %v", err)
	}
	if clearResp.SharedPasswordSet {
		t.Fatalf("expected shared_password_set=false after clearing password")
	}
}

// TestSaveAccessConfigPreservesExistingPassword 验证省略 shared_password 时不覆盖已存密码。
func TestSaveAccessConfigPreservesExistingPassword(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	invokeAccessHandler(t, SaveAccessConfig(repo, func() error { return nil }), "1",
		[]byte(`{"enabled":true,"shared_password":"mysecret","session_ttl":3600}`))

	// 只更新 enabled，不带密码字段
	ctx := invokeAccessHandler(t, SaveAccessConfig(repo, func() error { return nil }), "1",
		[]byte(`{"enabled":false,"session_ttl":7200}`))
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp accessConfigResp
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.SharedPasswordSet {
		t.Fatalf("expected password to be preserved when not specified in update")
	}
	if resp.Enabled {
		t.Fatalf("expected enabled to be updated to false")
	}
}

// TestCreatePathRuleRejectsInvalidAction 验证无效 action 返回 400。
func TestCreatePathRuleRejectsInvalidAction(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/1/access/path-rules")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody([]byte(`{"path":"/admin","action":"block"}`))
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}}
	CreatePathRule(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("expected 400 for invalid action, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
}

// TestCreatePathRuleDefaultsActionToRequireAuth 验证省略 action 时默认为 require_auth。
func TestCreatePathRuleDefaultsActionToRequireAuth(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/1/access/path-rules")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody([]byte(`{"path":"/protected"}`))
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}}
	CreatePathRule(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("unexpected status %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var rule store.AccessPathRule
	if err := json.Unmarshal(ctx.Response.Body(), &rule); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rule.Action != store.AccessActionRequireAuth {
		t.Fatalf("expected default action=%q, got %q", store.AccessActionRequireAuth, rule.Action)
	}
}

// TestCreateUserRejectsEmptyUsernameOrPassword 验证空 username/password 返回 400。
func TestCreateUserRejectsEmptyUsernameOrPassword(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	handler := CreateUser(repo, func() error { return nil })

	for _, body := range [][]byte{
		[]byte(`{"username":"","password":"secret"}`),
		[]byte(`{"username":"alice","password":""}`),
		[]byte(`{}`),
	} {
		var req protocol.Request
		req.SetMethod("POST")
		req.SetRequestURI("/api/v1/sites/1/access/users")
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(body)
		ctx := app.NewContext(0)
		req.CopyTo(&ctx.Request)
		ctx.Params = param.Params{{Key: "id", Value: "1"}}
		handler(context.Background(), ctx)
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("body %s should return 400, got %d", body, ctx.Response.StatusCode())
		}
	}
}

// TestFindSiteUserPreventsCrossSiteAccess 验证 findSiteUser 不允许跨站点访问。
func TestFindSiteUserPreventsCrossSiteAccess(t *testing.T) {
	repo := newAccessControlRepoForTest(t)
	// 在站点 1 创建用户
	var req protocol.Request
	req.SetMethod("POST")
	req.SetRequestURI("/api/v1/sites/1/access/users")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody([]byte(`{"username":"bob","password":"pass"}`))
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	ctx.Params = param.Params{{Key: "id", Value: "1"}}
	CreateUser(repo, func() error { return nil })(context.Background(), ctx)
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("create user failed: %d", ctx.Response.StatusCode())
	}
	var created store.AccessUser
	if err := json.Unmarshal(ctx.Response.Body(), &created); err != nil {
		t.Fatalf("decode created user: %v", err)
	}

	// 用站点 2 尝试删除站点 1 的用户（跨站越权）
	uidStr := formatUID(created.ID)
	var delReq protocol.Request
	delReq.SetMethod("POST")
	delReq.SetRequestURI("/api/v1/sites/2/access/users/" + uidStr + "/delete")
	ctx2 := app.NewContext(0)
	delReq.CopyTo(&ctx2.Request)
	ctx2.Params = param.Params{{Key: "id", Value: "2"}, {Key: "uid", Value: uidStr}}
	DeleteUser(repo, func() error { return nil })(context.Background(), ctx2)
	if ctx2.Response.StatusCode() != 404 {
		t.Fatalf("cross-site delete should return 404, got %d", ctx2.Response.StatusCode())
	}
}

func formatUID(n uint) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
