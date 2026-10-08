package store

import (
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"My-OpenWaf/internal/store/auth"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

/**
 * TestSeedDefaultsNeverCreatesAPIKey 锁定「初始化不预置 API 令牌」这条契约。
 *
 * 令牌一律由已登录的管理员在自己的账号下主动创建，因此无论首次运行、
 * 重启还是并发首次运行，SeedDefaults 都不得写入 admin_api_keys。
 */
func TestSeedDefaultsNeverCreatesAPIKey(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.AdminAPIKey{}, &auth.AdminAccount{}, &SystemSettings{}); err != nil {
		t.Fatalf("migrate auth tables: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	password, err := auth.SeedDefaults(db, ":9443", log)
	if err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if password == "" {
		t.Fatal("first seed must still generate the admin password")
	}

	var count int64
	if err := db.Unscoped().Model(&auth.AdminAPIKey{}).Count(&count).Error; err != nil {
		t.Fatalf("count api keys: %v", err)
	}
	if count != 0 {
		t.Fatalf("first seed must not create api keys, got %d row(s)", count)
	}

	restartedPassword, err := auth.SeedDefaults(db, ":9443", log)
	if err != nil {
		t.Fatalf("restart seed: %v", err)
	}
	if restartedPassword != "" {
		t.Fatalf("restart must not regenerate the admin password, got %q", restartedPassword)
	}
	if err := db.Unscoped().Model(&auth.AdminAPIKey{}).Count(&count).Error; err != nil {
		t.Fatalf("count api keys after restart: %v", err)
	}
	if count != 0 {
		t.Fatalf("restart must not create api keys, got %d row(s)", count)
	}
}

/**
 * TestSeedDefaultsConcurrentFirstRunStaysAPIKeyFree 验证并发首次运行下
 * 也不会出现「两个进程各自补一枚初始令牌」的竞态 —— 因为根本不再创建令牌。
 */
func TestSeedDefaultsConcurrentFirstRunStaysAPIKeyFree(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "seed.db") + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&auth.AdminAPIKey{}, &auth.AdminAccount{}, &SystemSettings{}); err != nil {
		t.Fatalf("migrate auth tables: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	var wg sync.WaitGroup
	passwords := make(chan string, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pw, seedErr := auth.SeedDefaults(db, ":9443", log)
			passwords <- pw
			errs <- seedErr
		}()
	}
	wg.Wait()
	close(passwords)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent seed: %v", err)
		}
	}
	generated := 0
	for pw := range passwords {
		if pw != "" {
			generated++
		}
	}
	if generated > 1 {
		t.Fatalf("admin password generated %d times, want at most 1", generated)
	}

	var keyCount int64
	if err := db.Unscoped().Model(&auth.AdminAPIKey{}).Count(&keyCount).Error; err != nil {
		t.Fatalf("count api keys: %v", err)
	}
	if keyCount != 0 {
		t.Fatalf("api key rows = %d, want 0", keyCount)
	}
}
