package store

import (
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// TestSeedDefaultsDoesNotRecreateDeletedAPIKey 验证 API Key 仅在首次空库生成一次。
func TestSeedDefaultsDoesNotRecreateDeletedAPIKey(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&AdminAPIKey{}, &AdminAccount{}, &SystemSettings{}); err != nil {
		t.Fatalf("migrate auth tables: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	token, password, err := SeedDefaults(db, ":9443", log)
	if err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if token == "" || password == "" {
		t.Fatalf("first seed credentials must be generated, token=%t password=%t", token != "", password != "")
	}

	var key AdminAPIKey
	if err := db.First(&key).Error; err != nil {
		t.Fatalf("load seeded api key: %v", err)
	}
	if err := db.Delete(&key).Error; err != nil {
		t.Fatalf("delete seeded api key: %v", err)
	}

	restartedToken, restartedPassword, err := SeedDefaults(db, ":9443", log)
	if err != nil {
		t.Fatalf("restart seed: %v", err)
	}
	if restartedToken != "" || restartedPassword != "" {
		t.Fatalf("restart must not regenerate credentials, token=%t password=%t", restartedToken != "", restartedPassword != "")
	}

	var activeCount int64
	if err := db.Model(&AdminAPIKey{}).Count(&activeCount).Error; err != nil {
		t.Fatalf("count active api keys: %v", err)
	}
	var allCount int64
	if err := db.Unscoped().Model(&AdminAPIKey{}).Count(&allCount).Error; err != nil {
		t.Fatalf("count all api keys: %v", err)
	}
	if activeCount != 0 || allCount != 1 {
		t.Fatalf("api key counts after restart = active:%d all:%d, want active:0 all:1", activeCount, allCount)
	}
}

func TestSeedDefaultsConcurrentFirstRunCreatesOneAPIKey(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "seed.db") + "?_pragma=busy_timeout(10000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&AdminAPIKey{}, &AdminAccount{}, &SystemSettings{}); err != nil {
		t.Fatalf("migrate auth tables: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	var wg sync.WaitGroup
	results := make(chan string, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, _, seedErr := SeedDefaults(db, ":9443", log)
			results <- token
			errs <- seedErr
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent seed: %v", err)
		}
	}
	tokens := 0
	for token := range results {
		if token != "" {
			tokens++
		}
	}
	if tokens != 1 {
		t.Fatalf("first-run token count = %d, want exactly 1", tokens)
	}
	var keyCount int64
	if err := db.Unscoped().Model(&AdminAPIKey{}).Count(&keyCount).Error; err != nil {
		t.Fatalf("count api keys: %v", err)
	}
	if keyCount != 1 {
		t.Fatalf("api key rows = %d, want 1", keyCount)
	}
}

func TestSeedDefaultsConcurrentIndependentConnectionsCreateOneAPIKey(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "seed-independent.db") + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	bootstrap, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open bootstrap sqlite: %v", err)
	}
	if err := bootstrap.AutoMigrate(&AdminAPIKey{}, &AdminAccount{}, &SystemSettings{}); err != nil {
		t.Fatalf("migrate auth tables: %v", err)
	}
	bootstrapSQL, err := bootstrap.DB()
	if err != nil {
		t.Fatalf("get bootstrap sql db: %v", err)
	}
	if err := bootstrapSQL.Close(); err != nil {
		t.Fatalf("close bootstrap sql db: %v", err)
	}

	first, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open first sqlite: %v", err)
	}
	second, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open second sqlite: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var wg sync.WaitGroup
	results := make(chan string, 2)
	errs := make(chan error, 2)
	for _, db := range []*gorm.DB{first, second} {
		wg.Add(1)
		go func(db *gorm.DB) {
			defer wg.Done()
			token, _, seedErr := SeedDefaults(db, ":9443", log)
			results <- token
			errs <- seedErr
		}(db)
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("independent concurrent seed: %v", err)
		}
	}
	tokens := 0
	for token := range results {
		if token != "" {
			tokens++
		}
	}
	if tokens != 1 {
		t.Fatalf("independent first-run token count = %d, want exactly 1", tokens)
	}
	var keyCount int64
	if err := first.Unscoped().Model(&AdminAPIKey{}).Count(&keyCount).Error; err != nil {
		t.Fatalf("count independent api keys: %v", err)
	}
	if keyCount != 1 {
		t.Fatalf("independent api key rows = %d, want 1", keyCount)
	}
}
