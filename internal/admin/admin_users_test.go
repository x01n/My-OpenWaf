package admin

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

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// newAdminAccountRepoForTest 基于内存库构造管理员账号仓库。
func newAdminAccountRepoForTest(t *testing.T) *repository.AdminAccountRepo {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.AdminAccount{}); err != nil {
		t.Fatalf("migrate admin accounts: %v", err)
	}
	return repository.NewAdminAccountRepo(db)
}

// invokeAdminUserHandler 构造带路由参数与认证上下文的请求并调用 handler。
func invokeAdminUserHandler(
	handler app.HandlerFunc,
	method, uri string,
	body []byte,
	idParam string,
	role, currentUser string,
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
	if idParam != "" {
		ctx.Params = param.Params{{Key: "id", Value: idParam}}
	}
	if role != "" {
		ctx.Set("auth_role", role)
	}
	if currentUser != "" {
		ctx.Set("auth_user", currentUser)
	}
	handler(context.Background(), ctx)
	return ctx
}

// seedAdminAccount 创建一个账号并返回其 ID 字符串。
func seedAdminAccount(t *testing.T, repo *repository.AdminAccountRepo, username, role string) string {
	t.Helper()
	acct, err := repo.Create(username, "password123", role)
	if err != nil {
		t.Fatalf("seed account %q: %v", username, err)
	}
	return strconv.FormatUint(uint64(acct.ID), 10)
}

// ---- ListAdminUsers ----

// TestListAdminUsersHidesPasswordHash 验证列表响应不泄漏密码哈希。
func TestListAdminUsersHidesPasswordHash(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	seedAdminAccount(t, repo, "alice", auth.RoleAdmin)

	ctx := invokeAdminUserHandler(ListAdminUsers(repo), "GET", "/api/v1/admin-users",
		nil, "", auth.RoleAdmin, "alice")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if bytes.Contains(ctx.Response.Body(), []byte("password_hash")) ||
		bytes.Contains(ctx.Response.Body(), []byte("PasswordHash")) ||
		bytes.Contains(ctx.Response.Body(), []byte("$2a$")) {
		t.Fatalf("password hash leaked into response: %s", ctx.Response.Body())
	}
	var resp struct {
		Items []store.AdminAccount `json:"items"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].Username != "alice" {
		t.Fatalf("unexpected items: %#v", resp.Items)
	}
}

// ---- CreateAdminUser ----

func TestCreateAdminUserValidationErrors(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	handler := CreateAdminUser(repo)

	tests := []struct {
		name string
		body string
	}{
		{"empty username", `{"username":"","password":"password123"}`},
		{"blank username", `{"username":"   ","password":"password123"}`},
		{"empty password", `{"username":"bob","password":""}`},
		{"short password", `{"username":"bob","password":"short"}`},
		{"invalid role", `{"username":"bob","password":"password123","role":"superuser"}`},
		{"malformed json", `not json`},
	}
	for _, tt := range tests {
		ctx := invokeAdminUserHandler(handler, "POST", "/api/v1/admin-users",
			[]byte(tt.body), "", auth.RoleAdmin, "alice")
		if ctx.Response.StatusCode() != 400 {
			t.Errorf("%s: want 400, got %d: %s", tt.name, ctx.Response.StatusCode(),
				bytes.TrimSpace(ctx.Response.Body()))
		}
	}
}

// TestCreateAdminUserRejectsOverlongUsername 验证用户名超过 64 字符被拒绝。
func TestCreateAdminUserRejectsOverlongUsername(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	long := make([]byte, 65)
	for i := range long {
		long[i] = 'a'
	}
	body, _ := json.Marshal(map[string]any{
		"username": string(long),
		"password": "password123",
	})
	ctx := invokeAdminUserHandler(CreateAdminUser(repo), "POST", "/api/v1/admin-users",
		body, "", auth.RoleAdmin, "alice")
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("overlong username: want 400, got %d", ctx.Response.StatusCode())
	}
}

// TestCreateAdminUserDefaultsToReadonly 验证省略 role 时默认为最低权限。
func TestCreateAdminUserDefaultsToReadonly(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	ctx := invokeAdminUserHandler(CreateAdminUser(repo), "POST", "/api/v1/admin-users",
		[]byte(`{"username":"newbie","password":"password123"}`), "", auth.RoleAdmin, "alice")
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("want 201, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	var resp struct {
		Role string `json:"role"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Role != auth.RoleReadonly {
		t.Fatalf("default role = %q, want %q", resp.Role, auth.RoleReadonly)
	}
}

// TestCreateAdminUserRejectsDuplicateUsername 验证重复用户名返回 409。
func TestCreateAdminUserRejectsDuplicateUsername(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	seedAdminAccount(t, repo, "alice", auth.RoleAdmin)

	ctx := invokeAdminUserHandler(CreateAdminUser(repo), "POST", "/api/v1/admin-users",
		[]byte(`{"username":"alice","password":"password123","role":"operator"}`),
		"", auth.RoleAdmin, "alice")
	if ctx.Response.StatusCode() != 409 {
		t.Fatalf("duplicate username: want 409, got %d", ctx.Response.StatusCode())
	}
}

// TestCreateAdminUserResponseOmitsPassword 验证创建响应不回显密码或哈希。
func TestCreateAdminUserResponseOmitsPassword(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	ctx := invokeAdminUserHandler(CreateAdminUser(repo), "POST", "/api/v1/admin-users",
		[]byte(`{"username":"carol","password":"password123","role":"operator"}`),
		"", auth.RoleAdmin, "alice")
	if ctx.Response.StatusCode() != 201 {
		t.Fatalf("want 201, got %d", ctx.Response.StatusCode())
	}
	if bytes.Contains(ctx.Response.Body(), []byte("password123")) ||
		bytes.Contains(ctx.Response.Body(), []byte("$2a$")) {
		t.Fatalf("credential leaked into create response: %s", ctx.Response.Body())
	}
}

// ---- UpdateAdminRole ----

func TestUpdateAdminRoleValidationErrors(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	id := seedAdminAccount(t, repo, "bob", auth.RoleOperator)
	handler := UpdateAdminRole(repo)

	if ctx := invokeAdminUserHandler(handler, "POST", "/api/v1/admin-users/abc/role",
		[]byte(`{"role":"admin"}`), "abc", auth.RoleAdmin, "alice"); ctx.Response.StatusCode() != 400 {
		t.Errorf("invalid id: want 400, got %d", ctx.Response.StatusCode())
	}
	if ctx := invokeAdminUserHandler(handler, "POST", "/api/v1/admin-users/"+id+"/role",
		[]byte(`{"role":"superuser"}`), id, auth.RoleAdmin, "alice"); ctx.Response.StatusCode() != 400 {
		t.Errorf("invalid role: want 400, got %d", ctx.Response.StatusCode())
	}
	if ctx := invokeAdminUserHandler(handler, "POST", "/api/v1/admin-users/9999/role",
		[]byte(`{"role":"admin"}`), "9999", auth.RoleAdmin, "alice"); ctx.Response.StatusCode() != 404 {
		t.Errorf("missing account: want 404, got %d", ctx.Response.StatusCode())
	}
}

// TestUpdateAdminRoleCannotDemoteLastAdmin 验证系统始终保留至少一个 admin。
func TestUpdateAdminRoleCannotDemoteLastAdmin(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	id := seedAdminAccount(t, repo, "onlyadmin", auth.RoleAdmin)

	ctx := invokeAdminUserHandler(UpdateAdminRole(repo), "POST", "/api/v1/admin-users/"+id+"/role",
		[]byte(`{"role":"readonly"}`), id, auth.RoleAdmin, "onlyadmin")
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("demoting last admin: want 400, got %d: %s",
			ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	acct, err := repo.GetByID(1)
	if err != nil {
		t.Fatalf("reload account: %v", err)
	}
	if acct.Role != auth.RoleAdmin {
		t.Fatalf("last admin role must stay admin, got %q", acct.Role)
	}
}

// TestUpdateAdminRoleAllowsDemotionWhenAnotherAdminExists 验证存在多个 admin 时可降级。
func TestUpdateAdminRoleAllowsDemotionWhenAnotherAdminExists(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	id1 := seedAdminAccount(t, repo, "admin1", auth.RoleAdmin)
	seedAdminAccount(t, repo, "admin2", auth.RoleAdmin)

	ctx := invokeAdminUserHandler(UpdateAdminRole(repo), "POST", "/api/v1/admin-users/"+id1+"/role",
		[]byte(`{"role":"operator"}`), id1, auth.RoleAdmin, "admin2")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	acct, err := repo.GetByUsername("admin1")
	if err != nil {
		t.Fatalf("reload account: %v", err)
	}
	if acct.Role != auth.RoleOperator {
		t.Fatalf("role = %q, want operator", acct.Role)
	}
}

// ---- UpdateAdminPassword ----

func TestUpdateAdminPasswordValidationErrors(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	id := seedAdminAccount(t, repo, "bob", auth.RoleOperator)
	handler := UpdateAdminPassword(repo)

	tests := []struct {
		name string
		id   string
		body string
		want int
	}{
		{"invalid id", "abc", `{"password":"password123"}`, 400},
		{"empty password", id, `{"password":""}`, 400},
		{"short password", id, `{"password":"short"}`, 400},
		{"missing account", "9999", `{"password":"password123"}`, 404},
	}
	for _, tt := range tests {
		ctx := invokeAdminUserHandler(handler, "POST", "/api/v1/admin-users/"+tt.id+"/password",
			[]byte(tt.body), tt.id, auth.RoleAdmin, "alice")
		if ctx.Response.StatusCode() != tt.want {
			t.Errorf("%s: want %d, got %d: %s", tt.name, tt.want,
				ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
		}
	}
}

// TestUpdateAdminPasswordNonAdminCannotChangeOthers 验证非 admin 无法改他人密码。
func TestUpdateAdminPasswordNonAdminCannotChangeOthers(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	targetID := seedAdminAccount(t, repo, "victim", auth.RoleOperator)
	seedAdminAccount(t, repo, "attacker", auth.RoleOperator)

	ctx := invokeAdminUserHandler(UpdateAdminPassword(repo), "POST",
		"/api/v1/admin-users/"+targetID+"/password",
		[]byte(`{"password":"hijacked123"}`), targetID, auth.RoleOperator, "attacker")
	if ctx.Response.StatusCode() != 403 {
		t.Fatalf("cross-user password change: want 403, got %d: %s",
			ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, ok := repo.VerifyPassword("victim", "hijacked123"); ok {
		t.Fatal("victim password must not be changed by another operator")
	}
}

// TestUpdateAdminPasswordNonAdminCanChangeOwn 验证非 admin 可以改自己的密码。
func TestUpdateAdminPasswordNonAdminCanChangeOwn(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	id := seedAdminAccount(t, repo, "selfuser", auth.RoleOperator)

	ctx := invokeAdminUserHandler(UpdateAdminPassword(repo), "POST",
		"/api/v1/admin-users/"+id+"/password",
		[]byte(`{"password":"mynewpass123"}`), id, auth.RoleOperator, "selfuser")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, ok := repo.VerifyPassword("selfuser", "mynewpass123"); !ok {
		t.Fatal("own password change must take effect")
	}
}

// TestUpdateAdminPasswordAdminCanChangeOthers 验证 admin 可以改他人密码。
func TestUpdateAdminPasswordAdminCanChangeOthers(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	targetID := seedAdminAccount(t, repo, "target", auth.RoleReadonly)
	seedAdminAccount(t, repo, "root", auth.RoleAdmin)

	ctx := invokeAdminUserHandler(UpdateAdminPassword(repo), "POST",
		"/api/v1/admin-users/"+targetID+"/password",
		[]byte(`{"password":"resetbyadmin1"}`), targetID, auth.RoleAdmin, "root")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, ok := repo.VerifyPassword("target", "resetbyadmin1"); !ok {
		t.Fatal("admin-initiated password reset must take effect")
	}
}

// ---- DeleteAdminUser ----

func TestDeleteAdminUserValidationErrors(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	handler := DeleteAdminUser(repo)

	if ctx := invokeAdminUserHandler(handler, "POST", "/api/v1/admin-users/abc/delete",
		nil, "abc", auth.RoleAdmin, "alice"); ctx.Response.StatusCode() != 400 {
		t.Errorf("invalid id: want 400, got %d", ctx.Response.StatusCode())
	}
	if ctx := invokeAdminUserHandler(handler, "POST", "/api/v1/admin-users/9999/delete",
		nil, "9999", auth.RoleAdmin, "alice"); ctx.Response.StatusCode() != 404 {
		t.Errorf("missing account: want 404, got %d", ctx.Response.StatusCode())
	}
}

// TestDeleteAdminUserCannotDeleteSelf 验证不能删除自己的账号。
func TestDeleteAdminUserCannotDeleteSelf(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	id := seedAdminAccount(t, repo, "alice", auth.RoleAdmin)
	seedAdminAccount(t, repo, "bob", auth.RoleAdmin)

	ctx := invokeAdminUserHandler(DeleteAdminUser(repo), "POST", "/api/v1/admin-users/"+id+"/delete",
		nil, id, auth.RoleAdmin, "alice")
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("self delete: want 400, got %d: %s",
			ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, err := repo.GetByUsername("alice"); err != nil {
		t.Fatal("own account must not be deleted")
	}
}

// TestDeleteAdminUserCannotDeleteLastAdmin 验证系统始终保留至少一个 admin。
func TestDeleteAdminUserCannotDeleteLastAdmin(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	adminID := seedAdminAccount(t, repo, "onlyadmin", auth.RoleAdmin)
	seedAdminAccount(t, repo, "operator", auth.RoleOperator)

	ctx := invokeAdminUserHandler(DeleteAdminUser(repo), "POST",
		"/api/v1/admin-users/"+adminID+"/delete", nil, adminID, auth.RoleAdmin, "operator")
	if ctx.Response.StatusCode() != 400 {
		t.Fatalf("deleting last admin: want 400, got %d: %s",
			ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	if _, err := repo.GetByUsername("onlyadmin"); err != nil {
		t.Fatal("last admin must not be deleted")
	}
}

// TestDeleteAdminUserSucceedsForNonLastAdmin 验证存在多个 admin 时可删除其一。
func TestDeleteAdminUserSucceedsForNonLastAdmin(t *testing.T) {
	repo := newAdminAccountRepoForTest(t)
	id1 := seedAdminAccount(t, repo, "admin1", auth.RoleAdmin)
	seedAdminAccount(t, repo, "admin2", auth.RoleAdmin)

	ctx := invokeAdminUserHandler(DeleteAdminUser(repo), "POST",
		"/api/v1/admin-users/"+id1+"/delete", nil, id1, auth.RoleAdmin, "admin2")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	accounts, err := repo.List()
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	if len(accounts) != 1 || accounts[0].Username != "admin2" {
		t.Fatalf("unexpected remaining accounts: %#v", accounts)
	}
}
