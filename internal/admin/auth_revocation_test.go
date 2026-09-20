package admin

import (
	"bytes"
	"strconv"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

type revocationTestState struct {
	deps         *AuthDeps
	accountRepo  *repository.AdminAccountRepo
	db           *gorm.DB
	accessToken  string
	accessJTI    string
	refreshJTI   string
	targetUserID string
}

func newRevocationTestState(t *testing.T, targetRole string) *revocationTestState {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&store.AdminAccount{},
		&store.RefreshToken{},
		&store.TokenBlacklist{},
		&store.ActiveSession{},
	); err != nil {
		t.Fatalf("migrate auth tables: %v", err)
	}
	accountRepo := repository.NewAdminAccountRepo(db)
	target, err := accountRepo.Create("target", "password123", targetRole)
	if err != nil {
		t.Fatalf("create target account: %v", err)
	}
	if _, err := accountRepo.Create("root", "password123", auth.RoleAdmin); err != nil {
		t.Fatalf("create root account: %v", err)
	}

	tokenMgr := auth.NewTokenManager([]byte("revocation-test-jwt-secret"), db)
	t.Cleanup(tokenMgr.Close)
	sessionMgr := auth.NewSessionManager(db)
	accessToken, accessJTI, accessExp, err := tokenMgr.SignAccessToken("target", targetRole, "192.0.2.10", "test-agent")
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}
	sessionMgr.CreateSession("target", accessJTI, "192.0.2.10", "test-agent", "", accessExp)
	refreshJTI := "refresh-target"
	rtRepo := repository.NewRefreshTokenRepo(db)
	if _, err := rtRepo.Create(refreshJTI, "refresh-hash", "target", targetRole, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	return &revocationTestState{
		deps: &AuthDeps{
			AccountRepo: accountRepo,
			RTRepo:      rtRepo,
			TokenMgr:    tokenMgr,
			SessionMgr:  sessionMgr,
			DB:          db,
		},
		accountRepo:  accountRepo,
		db:           db,
		accessToken:  accessToken,
		accessJTI:    accessJTI,
		refreshJTI:   refreshJTI,
		targetUserID: strconv.FormatUint(uint64(target.ID), 10),
	}
}

func (s *revocationTestState) revoker(username, reason string) error {
	return revokeUserCredentials(s.deps, username, reason)
}

func (s *revocationTestState) assertCredentialsRevoked(t *testing.T) {
	t.Helper()
	if _, err := s.deps.RTRepo.FindByJTI(s.refreshJTI); err == nil {
		t.Fatal("refresh token remains active")
	}
	if _, err := s.deps.TokenMgr.VerifyAccessToken(s.accessToken); err == nil {
		t.Fatal("access token remains valid")
	}
	if sessions := s.deps.SessionMgr.ListUserSessions("target"); len(sessions) != 0 {
		t.Fatalf("active sessions remain: %#v", sessions)
	}
	var activeRows int64
	if err := s.db.Model(&store.ActiveSession{}).Where("username = ?", "target").Count(&activeRows).Error; err != nil {
		t.Fatalf("count active sessions: %v", err)
	}
	if activeRows != 0 {
		t.Fatalf("persisted active sessions = %d, want 0", activeRows)
	}
}

// TestAdminRoleChangeRevokesUserCredentials 验证降权后旧访问与刷新凭据全部失效。
func TestAdminRoleChangeRevokesUserCredentials(t *testing.T) {
	s := newRevocationTestState(t, auth.RoleAdmin)
	ctx := invokeAdminUserHandler(UpdateAdminRole(s.accountRepo, s.revoker), "POST",
		"/api/v1/admin-users/"+s.targetUserID+"/update-role",
		[]byte(`{"role":"readonly"}`), s.targetUserID, auth.RoleAdmin, "root")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update role: want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	s.assertCredentialsRevoked(t)
}

// TestAdminPasswordChangeRevokesUserCredentials 验证管理员重置密码后旧凭据全部失效。
func TestAdminPasswordChangeRevokesUserCredentials(t *testing.T) {
	s := newRevocationTestState(t, auth.RoleOperator)
	ctx := invokeAdminUserHandler(UpdateAdminPassword(s.accountRepo, s.revoker), "POST",
		"/api/v1/admin-users/"+s.targetUserID+"/update-password",
		[]byte(`{"password":"newpassword123"}`), s.targetUserID, auth.RoleAdmin, "root")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("update password: want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	s.assertCredentialsRevoked(t)
}

// TestAdminUserDeleteRevokesUserCredentials 验证删除账号后旧凭据全部失效。
func TestAdminUserDeleteRevokesUserCredentials(t *testing.T) {
	s := newRevocationTestState(t, auth.RoleOperator)
	ctx := invokeAdminUserHandler(DeleteAdminUser(s.accountRepo, s.revoker), "POST",
		"/api/v1/admin-users/"+s.targetUserID+"/delete", nil,
		s.targetUserID, auth.RoleAdmin, "root")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("delete user: want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	s.assertCredentialsRevoked(t)
}

// TestChangeOwnPasswordRevokesUserCredentials 验证自改密码同样撤销当前账号全部凭据。
func TestChangeOwnPasswordRevokesUserCredentials(t *testing.T) {
	s := newRevocationTestState(t, auth.RoleOperator)
	ctx := invokeAdminUserHandler(ChangeOwnPasswordHandler(s.deps), "POST",
		"/api/v1/auth/change-password",
		[]byte(`{"old_password":"password123","new_password":"selfpassword123"}`),
		"", auth.RoleOperator, "target")
	if ctx.Response.StatusCode() != 200 {
		t.Fatalf("change own password: want 200, got %d: %s", ctx.Response.StatusCode(), bytes.TrimSpace(ctx.Response.Body()))
	}
	s.assertCredentialsRevoked(t)
}
