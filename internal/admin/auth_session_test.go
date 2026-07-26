package admin

import (
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
)

// newSessionMgrForTest 基于内存库构造会话管理器。
func newSessionMgrForTest(t *testing.T) *auth.SessionManager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.ActiveSession{}); err != nil {
		t.Fatalf("migrate active sessions: %v", err)
	}
	return auth.NewSessionManager(db)
}

// invokeSessionHandler 构造带角色/用户上下文的请求并调用 handler。
func invokeSessionHandler(
	handler app.HandlerFunc,
	method, uri string,
	body []byte,
	role, username string,
) *app.RequestContext {
	var req protocol.Request
	req.SetMethod(method)
	req.SetRequestURI(uri)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.SetBody(body)
	}
	ctx := app.NewContext(0)
	req.CopyTo(&ctx.Request)
	if role != "" {
		ctx.Set("auth_role", role)
	}
	if username != "" {
		ctx.Set("auth_user", username)
	}
	handler(context.Background(), ctx)
	return ctx
}

// ---- ListSessionsHandler ----

// TestListSessionsNilManagerReturnsEmpty 验证未启用会话管理时返回空列表而非报错。
func TestListSessionsNilManagerReturnsEmpty(t *testing.T) {
	ctx := invokeSessionHandler(ListSessionsHandler(&AuthDeps{}),
		"GET", "/api/v1/auth/sessions", nil, auth.RoleAdmin, "alice")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d", ctx.Response.StatusCode())
	}
	var resp struct {
		Sessions []auth.SessionInfo `json:"sessions"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Sessions) != 0 {
		t.Fatalf("want empty sessions, got %d", len(resp.Sessions))
	}
}

// TestListSessionsScopedToCurrentUser 验证默认只返回当前用户的会话。
func TestListSessionsScopedToCurrentUser(t *testing.T) {
	sm := newSessionMgrForTest(t)
	exp := time.Now().Add(time.Hour)
	sm.CreateSession("alice", "jti-alice-1", "1.1.1.1", "curl", "cli", exp)
	sm.CreateSession("bob", "jti-bob-1", "2.2.2.2", "curl", "cli", exp)

	ctx := invokeSessionHandler(ListSessionsHandler(&AuthDeps{SessionMgr: sm}),
		"GET", "/api/v1/auth/sessions", nil, auth.RoleOperator, "alice")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d", ctx.Response.StatusCode())
	}
	var resp struct {
		Sessions []auth.SessionInfo `json:"sessions"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Sessions) != 1 || resp.Sessions[0].Username != "alice" {
		t.Fatalf("expected only alice's session, got %#v", resp.Sessions)
	}
}

// TestListSessionsAllRequiresAdminRole 验证 all=true 仅对 admin 生效，
// 非 admin 传该参数仍只能看到自己的会话。
func TestListSessionsAllRequiresAdminRole(t *testing.T) {
	sm := newSessionMgrForTest(t)
	exp := time.Now().Add(time.Hour)
	sm.CreateSession("alice", "jti-alice-1", "1.1.1.1", "curl", "cli", exp)
	sm.CreateSession("bob", "jti-bob-1", "2.2.2.2", "curl", "cli", exp)

	adminCtx := invokeSessionHandler(ListSessionsHandler(&AuthDeps{SessionMgr: sm}),
		"GET", "/api/v1/auth/sessions?all=true", nil, auth.RoleAdmin, "alice")
	var adminResp struct {
		Sessions []auth.SessionInfo `json:"sessions"`
	}
	if err := json.Unmarshal(adminCtx.Response.Body(), &adminResp); err != nil {
		t.Fatalf("decode admin: %v", err)
	}
	if len(adminResp.Sessions) != 2 {
		t.Fatalf("admin with all=true should see 2 sessions, got %d", len(adminResp.Sessions))
	}

	opCtx := invokeSessionHandler(ListSessionsHandler(&AuthDeps{SessionMgr: sm}),
		"GET", "/api/v1/auth/sessions?all=true", nil, auth.RoleOperator, "alice")
	var opResp struct {
		Sessions []auth.SessionInfo `json:"sessions"`
	}
	if err := json.Unmarshal(opCtx.Response.Body(), &opResp); err != nil {
		t.Fatalf("decode operator: %v", err)
	}
	if len(opResp.Sessions) != 1 || opResp.Sessions[0].Username != "alice" {
		t.Fatalf("operator with all=true must stay scoped to own sessions, got %#v", opResp.Sessions)
	}
}

// ---- ForceLogoutSessionHandler ----

func TestForceLogoutRejectsMissingJTI(t *testing.T) {
	sm := newSessionMgrForTest(t)
	for _, body := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"jti":""}`),
		[]byte(`not json`),
	} {
		ctx := invokeSessionHandler(ForceLogoutSessionHandler(&AuthDeps{SessionMgr: sm}),
			"POST", "/api/v1/auth/sessions/force-logout", body, auth.RoleAdmin, "alice")
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("body %s: want 400, got %d", body, ctx.Response.StatusCode())
		}
	}
}

func TestForceLogoutNilManagerReturns404(t *testing.T) {
	ctx := invokeSessionHandler(ForceLogoutSessionHandler(&AuthDeps{}),
		"POST", "/api/v1/auth/sessions/force-logout", []byte(`{"jti":"some-jti"}`),
		auth.RoleAdmin, "alice")
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("nil session manager: want 404, got %d", ctx.Response.StatusCode())
	}
}

func TestForceLogoutUnknownJTIReturns404(t *testing.T) {
	sm := newSessionMgrForTest(t)
	ctx := invokeSessionHandler(ForceLogoutSessionHandler(&AuthDeps{SessionMgr: sm}),
		"POST", "/api/v1/auth/sessions/force-logout", []byte(`{"jti":"no-such-jti"}`),
		auth.RoleAdmin, "alice")
	if ctx.Response.StatusCode() != 404 {
		t.Fatalf("unknown jti: want 404, got %d", ctx.Response.StatusCode())
	}
}

// TestForceLogoutRemovesExistingSession 验证强制下线后会话从列表中消失。
func TestForceLogoutRemovesExistingSession(t *testing.T) {
	sm := newSessionMgrForTest(t)
	sm.CreateSession("alice", "jti-to-kill", "1.1.1.1", "curl", "cli", time.Now().Add(time.Hour))

	ctx := invokeSessionHandler(ForceLogoutSessionHandler(&AuthDeps{SessionMgr: sm}),
		"POST", "/api/v1/auth/sessions/force-logout", []byte(`{"jti":"jti-to-kill"}`),
		auth.RoleAdmin, "alice")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if sm.GetSession("jti-to-kill") != nil {
		t.Fatal("session must be removed after force logout")
	}
	if len(sm.ListUserSessions("alice")) != 0 {
		t.Fatal("alice should have no remaining sessions")
	}
}
