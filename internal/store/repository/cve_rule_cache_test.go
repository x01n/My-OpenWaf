package repository

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/cve"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newCVERuleCacheTestRepo(t *testing.T) (*CVERuleRepo, *atomic.Int64) {
	t.Helper()
	dsn := fmt.Sprintf("file:cve-cache-%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&cve.CVERuleModel{}, &store.CVERuleScopeOverride{}); err != nil {
		t.Fatalf("migrate CVE cache tables: %v", err)
	}
	rule := cve.CVERuleModel{
		CVEID:       "CVE-2026-70001",
		Category:    "general",
		Pattern:     "cache-test-rule",
		Target:      "all",
		Severity:    "high",
		Action:      "intercept",
		Enabled:     true,
		Description: "cache test",
		Source:      "custom",
		Approved:    true,
	}
	if err := db.Create(&rule).Error; err != nil {
		t.Fatalf("create CVE rule: %v", err)
	}
	action := "observe"
	override := store.CVERuleScopeOverride{
		RuleID:    rule.ID,
		ScopeType: store.CVEScopeGlobal,
		ScopeID:   0,
		Action:    &action,
	}
	if err := db.Create(&override).Error; err != nil {
		t.Fatalf("create CVE override: %v", err)
	}
	queries := &atomic.Int64{}
	if err := db.Callback().Query().Before("gorm:query").Register("test:cve-cache-query", func(*gorm.DB) {
		queries.Add(1)
	}); err != nil {
		t.Fatalf("register query callback: %v", err)
	}
	return NewCVERuleRepo(db), queries
}

func TestCVERuleCanonicalSnapshotColdSingleflightAndWarmZeroSQL(t *testing.T) {
	repo, queries := newCVERuleCacheTestRepo(t)
	if cveCanonicalSnapshotTTL != 10*time.Second {
		t.Fatalf("snapshot TTL=%s want=10s", cveCanonicalSnapshotTTL)
	}

	const workers = 32
	start := make(chan struct{})
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			snapshot, err := repo.CanonicalSnapshot()
			if err != nil {
				errCh <- err
				return
			}
			if len(snapshot.Rules) != 1 || len(snapshot.OverridesByRule[snapshot.Rules[0].ID]) != 1 {
				errCh <- fmt.Errorf("unexpected snapshot shape: %#v", snapshot)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	if got := queries.Load(); got != 2 {
		t.Fatalf("cold concurrent query callbacks=%d want=2", got)
	}

	queries.Store(0)
	if _, err := repo.CanonicalSnapshot(); err != nil {
		t.Fatalf("warm snapshot: %v", err)
	}
	if got := queries.Load(); got != 0 {
		t.Fatalf("warm snapshot query callbacks=%d want=0", got)
	}
}

func TestCVERuleCanonicalSnapshotReturnsDeepCopies(t *testing.T) {
	repo, _ := newCVERuleCacheTestRepo(t)
	first, err := repo.CanonicalSnapshot()
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	ruleID := first.Rules[0].ID
	first.Rules[0].Description = "mutated by caller"
	first.OverridesByRule[ruleID][0].Action = nil
	first.OverridesByRule[ruleID] = append(first.OverridesByRule[ruleID], store.CVERuleScopeOverride{RuleID: ruleID})
	delete(first.OverridesByRule, ruleID)

	second, err := repo.CanonicalSnapshot()
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if second.Rules[0].Description != "cache test" {
		t.Fatalf("cached rule mutated: %q", second.Rules[0].Description)
	}
	overrides := second.OverridesByRule[ruleID]
	if len(overrides) != 1 || overrides[0].Action == nil || *overrides[0].Action != "observe" {
		t.Fatalf("cached overrides mutated: %#v", overrides)
	}
}

func TestCVERuleRepositoryMutationInvalidatesCanonicalSnapshot(t *testing.T) {
	repo, queries := newCVERuleCacheTestRepo(t)
	snapshot, err := repo.CanonicalSnapshot()
	if err != nil {
		t.Fatalf("warm snapshot: %v", err)
	}
	rule := snapshot.Rules[0]
	rule.Description = "updated description"
	if err := repo.Update(&rule); err != nil {
		t.Fatalf("update rule: %v", err)
	}

	queries.Store(0)
	refreshed, err := repo.CanonicalSnapshot()
	if err != nil {
		t.Fatalf("reload snapshot: %v", err)
	}
	if got := queries.Load(); got != 2 {
		t.Fatalf("post-update query callbacks=%d want=2", got)
	}
	if refreshed.Rules[0].Description != "updated description" {
		t.Fatalf("stale description=%q", refreshed.Rules[0].Description)
	}
}

func TestCVERuleRepositoryCreateToggleDeleteInvalidateCanonicalSnapshot(t *testing.T) {
	repo, _ := newCVERuleCacheTestRepo(t)
	if _, err := repo.CanonicalSnapshot(); err != nil {
		t.Fatalf("warm initial snapshot: %v", err)
	}
	second := cve.CVERuleModel{
		CVEID:       "CVE-2026-70006",
		Category:    "general",
		Pattern:     "cache-mutation-rule",
		Target:      "all",
		Severity:    "medium",
		Action:      "intercept",
		Enabled:     true,
		Description: "mutation rule",
		Source:      "custom",
		Approved:    true,
	}
	if err := repo.Create(&second); err != nil {
		t.Fatalf("create second rule: %v", err)
	}
	created, err := repo.CanonicalSnapshot()
	if err != nil {
		t.Fatalf("snapshot after create: %v", err)
	}
	if len(created.Rules) != 2 {
		t.Fatalf("rules after create=%d want=2", len(created.Rules))
	}

	if err := repo.Toggle(second.ID, false); err != nil {
		t.Fatalf("toggle second rule: %v", err)
	}
	toggled, err := repo.CanonicalSnapshot()
	if err != nil {
		t.Fatalf("snapshot after toggle: %v", err)
	}
	if toggled.Rules[0].ID != second.ID || toggled.Rules[0].Enabled {
		t.Fatalf("toggled rule=%#v want newest disabled rule", toggled.Rules[0])
	}

	if err := repo.Delete(second.ID); err != nil {
		t.Fatalf("delete second rule: %v", err)
	}
	deleted, err := repo.CanonicalSnapshot()
	if err != nil {
		t.Fatalf("snapshot after delete: %v", err)
	}
	if len(deleted.Rules) != 1 || deleted.Rules[0].ID == second.ID {
		t.Fatalf("rules after delete=%#v", deleted.Rules)
	}
}

func TestCVERuleRepositoryDeleteRemovesScopeOverrides(t *testing.T) {
	repo, _ := newCVERuleCacheTestRepo(t)
	rule := cve.CVERuleModel{
		CVEID:       "CVE-2026-70007",
		Category:    "general",
		Pattern:     "delete-override-rule",
		Target:      "all",
		Severity:    "high",
		Action:      "intercept",
		Enabled:     true,
		Description: "delete override test",
		Source:      "custom",
		Approved:    true,
	}
	if err := repo.Create(&rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	enabled := false
	override := store.CVERuleScopeOverride{
		RuleID:    rule.ID,
		ScopeType: store.CVEScopeGlobal,
		ScopeID:   0,
		Enabled:   &enabled,
	}
	if err := repo.db.Create(&override).Error; err != nil {
		t.Fatalf("create scope override: %v", err)
	}
	if err := repo.Delete(rule.ID); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	var count int64
	if err := repo.db.Model(&store.CVERuleScopeOverride{}).
		Where("rule_id = ?", rule.ID).Count(&count).Error; err != nil {
		t.Fatalf("count scope overrides: %v", err)
	}
	if count != 0 {
		t.Fatalf("scope overrides after rule deletion = %d, want 0", count)
	}
}

func TestCVERuleEnsureBuiltinCatalogRetriesTransientFailureAndCachesSuccess(t *testing.T) {
	repo, queries := newCVERuleCacheTestRepo(t)
	var failFirst atomic.Bool
	failFirst.Store(true)
	if err := repo.db.Callback().Query().Before("gorm:query").Register("test:cve-reconcile-transient", func(tx *gorm.DB) {
		if failFirst.CompareAndSwap(true, false) {
			tx.AddError(fmt.Errorf("transient catalog read failure"))
		}
	}); err != nil {
		t.Fatalf("register transient failure: %v", err)
	}
	if err := repo.EnsureBuiltinCatalog(); err == nil {
		t.Fatal("first reconcile unexpectedly succeeded")
	}
	if err := repo.EnsureBuiltinCatalog(); err != nil {
		t.Fatalf("retry reconcile: %v", err)
	}

	queries.Store(0)
	if err := repo.EnsureBuiltinCatalog(); err != nil {
		t.Fatalf("ready reconcile: %v", err)
	}
	if got := queries.Load(); got != 0 {
		t.Fatalf("ready reconcile query callbacks=%d want=0", got)
	}
}

func TestCVERuleMarkBuiltinCatalogReadySkipsFallbackQuery(t *testing.T) {
	repo, queries := newCVERuleCacheTestRepo(t)
	queries.Store(0)
	repo.MarkBuiltinCatalogReady()
	if err := repo.EnsureBuiltinCatalog(); err != nil {
		t.Fatalf("ensure marked catalog: %v", err)
	}
	if got := queries.Load(); got != 0 {
		t.Fatalf("marked catalog query callbacks=%d want=0", got)
	}
}
