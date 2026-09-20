package repository

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

func newRefreshTokenRepoForTest(t *testing.T) (*RefreshTokenRepo, *gorm.DB) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "refresh-token.db") + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.RefreshToken{}); err != nil {
		t.Fatalf("migrate refresh tokens: %v", err)
	}
	return NewRefreshTokenRepo(db), db
}

// TestRefreshTokenRotateAllowsExactlyOneConcurrentSuccess 验证同一旧令牌并发轮换时只有一个事务成功。
func TestRefreshTokenRotateAllowsExactlyOneConcurrentSuccess(t *testing.T) {
	repo, db := newRefreshTokenRepoForTest(t)
	if _, err := repo.Create("old-jti", "old-hash", "alice", store.RoleAdmin, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create old token: %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, newJTI := range []string{"new-jti-a", "new-jti-b"} {
		newJTI := newJTI
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := repo.Rotate("old-jti", newJTI, "new-hash", "alice", store.RoleReadonly, time.Now().Add(time.Hour))
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	successes := 0
	unavailable := 0
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrRefreshTokenUnavailable):
			unavailable++
		default:
			t.Fatalf("unexpected rotate error: %v", err)
		}
	}
	if successes != 1 || unavailable != 1 {
		t.Fatalf("rotate results = success:%d unavailable:%d, want 1 and 1", successes, unavailable)
	}

	var old store.RefreshToken
	if err := db.Where("jti = ?", "old-jti").First(&old).Error; err != nil {
		t.Fatalf("load old token: %v", err)
	}
	if !old.Revoked || old.ReplacedBy == "" {
		t.Fatalf("old token state = revoked:%t replaced_by:%q", old.Revoked, old.ReplacedBy)
	}
	var replacements []store.RefreshToken
	if err := db.Where("jti IN ?", []string{"new-jti-a", "new-jti-b"}).Find(&replacements).Error; err != nil {
		t.Fatalf("load replacements: %v", err)
	}
	if len(replacements) != 1 || replacements[0].JTI != old.ReplacedBy {
		t.Fatalf("replacement rows = %#v, old replaced_by=%q", replacements, old.ReplacedBy)
	}
}

// TestRefreshTokenRevokeFamilyRevokesReplacementChain 验证注销从旧 JTI 开始会撤销全部轮换后继令牌。
func TestRefreshTokenRevokeFamilyRevokesReplacementChain(t *testing.T) {
	repo, _ := newRefreshTokenRepoForTest(t)
	expiresAt := time.Now().Add(time.Hour)
	if _, err := repo.Create("family-old", "old-hash", "alice", store.RoleAdmin, expiresAt); err != nil {
		t.Fatalf("create old token: %v", err)
	}
	if _, err := repo.Create("unrelated", "other-hash", "alice", store.RoleAdmin, expiresAt); err != nil {
		t.Fatalf("create unrelated token: %v", err)
	}
	if _, err := repo.Rotate("family-old", "family-new", "new-hash", "alice", store.RoleAdmin, expiresAt); err != nil {
		t.Fatalf("rotate token: %v", err)
	}

	if err := repo.RevokeFamily("family-old"); err != nil {
		t.Fatalf("revoke token family: %v", err)
	}
	for _, jti := range []string{"family-old", "family-new"} {
		if _, err := repo.FindByJTI(jti); err == nil {
			t.Fatalf("family token %q remains active", jti)
		}
	}
	if _, err := repo.FindByJTI("unrelated"); err != nil {
		t.Fatalf("unrelated token was revoked: %v", err)
	}
}

// TestRefreshTokenRotateRollsBackRevocationWhenInsertFails 验证新令牌插入失败时旧令牌仍可用。
func TestRefreshTokenRotateRollsBackRevocationWhenInsertFails(t *testing.T) {
	repo, db := newRefreshTokenRepoForTest(t)
	expiresAt := time.Now().Add(time.Hour)
	if _, err := repo.Create("old-jti", "old-hash", "alice", store.RoleAdmin, expiresAt); err != nil {
		t.Fatalf("create old token: %v", err)
	}
	if _, err := repo.Create("duplicate-jti", "existing-hash", "alice", store.RoleAdmin, expiresAt); err != nil {
		t.Fatalf("create duplicate token: %v", err)
	}

	if _, err := repo.Rotate("old-jti", "duplicate-jti", "new-hash", "alice", store.RoleAdmin, expiresAt); err == nil {
		t.Fatal("duplicate replacement jti must fail")
	}
	var old store.RefreshToken
	if err := db.Where("jti = ?", "old-jti").First(&old).Error; err != nil {
		t.Fatalf("load old token: %v", err)
	}
	if old.Revoked || old.ReplacedBy != "" {
		t.Fatalf("failed rotation must rollback old token, got revoked:%t replaced_by:%q", old.Revoked, old.ReplacedBy)
	}
}

// TestRefreshTokenCleanExpiredIsBounded 验证每次认证后的清理不会无界删除历史数据。
func TestRefreshTokenCleanExpiredIsBounded(t *testing.T) {
	repo, db := newRefreshTokenRepoForTest(t)
	for i := 0; i < 5; i++ {
		jti := []string{"expired-1", "expired-2", "expired-3", "expired-4", "expired-5"}[i]
		if _, err := repo.Create(jti, "hash", "alice", store.RoleAdmin, time.Now().Add(-time.Hour)); err != nil {
			t.Fatalf("create expired token %d: %v", i, err)
		}
	}
	if _, err := repo.Create("active", "hash", "alice", store.RoleAdmin, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create active token: %v", err)
	}

	if err := repo.CleanExpired(2); err != nil {
		t.Fatalf("clean expired: %v", err)
	}
	var expiredCount int64
	if err := db.Model(&store.RefreshToken{}).Where("expires_at <= ?", time.Now()).Count(&expiredCount).Error; err != nil {
		t.Fatalf("count expired tokens: %v", err)
	}
	if expiredCount != 3 {
		t.Fatalf("expired token count = %d, want 3", expiredCount)
	}
	if _, err := repo.FindByJTI("active"); err != nil {
		t.Fatalf("active token removed by cleanup: %v", err)
	}
}

// TestRefreshTokenRevokeAdminIncludesLegacyRows 验证旧版空用户名令牌随 admin 一并撤销。
func TestRefreshTokenRevokeAdminIncludesLegacyRows(t *testing.T) {
	repo, _ := newRefreshTokenRepoForTest(t)
	expiresAt := time.Now().Add(time.Hour)
	for _, row := range []struct {
		jti      string
		username string
	}{
		{jti: "legacy-admin", username: ""},
		{jti: "current-admin", username: "admin"},
		{jti: "other-user", username: "alice"},
	} {
		if _, err := repo.Create(row.jti, "hash", row.username, store.RoleAdmin, expiresAt); err != nil {
			t.Fatalf("create %s: %v", row.jti, err)
		}
	}
	if err := repo.RevokeByUsername("admin"); err != nil {
		t.Fatalf("revoke admin tokens: %v", err)
	}
	for _, jti := range []string{"legacy-admin", "current-admin"} {
		if _, err := repo.FindByJTI(jti); err == nil {
			t.Fatalf("admin token %q remains active", jti)
		}
	}
	if _, err := repo.FindByJTI("other-user"); err != nil {
		t.Fatalf("other user's token was revoked: %v", err)
	}
}
