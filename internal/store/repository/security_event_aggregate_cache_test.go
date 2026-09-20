package repository

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func newSecurityEventAggregateRepoForTest(t *testing.T) (*SecurityEventRepo, *countingSQLLogger) {
	t.Helper()
	log := newCountingSQLLogger()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: log})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sqlite handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&store.SecurityEvent{}); err != nil {
		t.Fatalf("migrate security event: %v", err)
	}
	return NewSecurityEventRepo(db), log
}

func seedAggregateSecurityEvents(t *testing.T, repo *SecurityEventRepo) {
	t.Helper()
	now := time.Now()
	items := []store.SecurityEvent{
		{
			CreatedAt:  now.Add(-time.Hour),
			SiteID:     1,
			RequestID:  "site-1-recent",
			ClientIP:   "192.0.2.1",
			Path:       "/recent",
			RuleIDStr:  "rule-recent",
			Category:   "cve",
			GeoCountry: "CN",
			Action:     "intercept",
		},
		{
			CreatedAt:  now.Add(-2 * time.Hour),
			SiteID:     2,
			RequestID:  "site-2-recent",
			ClientIP:   "192.0.2.2",
			Path:       "/observe",
			RuleIDStr:  "rule-observe",
			Category:   "custom",
			GeoCountry: "US",
			Action:     "observe",
		},
		{
			CreatedAt:  now.Add(-30 * time.Hour),
			SiteID:     1,
			RequestID:  "site-1-old",
			ClientIP:   "192.0.2.3",
			Path:       "/old",
			RuleIDStr:  "rule-old",
			Category:   "owasp",
			GeoCountry: "JP",
			Action:     "drop",
		},
	}
	if err := repo.db.Create(&items).Error; err != nil {
		t.Fatalf("seed security events: %v", err)
	}
}

func TestSecurityEventAggregateSnapshotsCacheSQLAndIsolateKeys(t *testing.T) {
	repo, log := newSecurityEventAggregateRepoForTest(t)
	seedAggregateSecurityEvents(t, repo)

	log.reset()
	global24, err := repo.StatsSnapshot(24)
	if err != nil {
		t.Fatalf("global 24h stats: %v", err)
	}
	if got := log.count(); got != 6 {
		t.Fatalf("global stats cold SQL count=%d want=6", got)
	}
	if global24.Total != 2 || global24.Hours != 24 {
		t.Fatalf("global 24h stats=%+v", global24)
	}
	if len(global24.Categories) == 0 {
		t.Fatal("global stats categories are empty")
	}
	global24.Categories[0].Category = "caller-owned"

	log.reset()
	cached, err := repo.StatsSnapshot(24)
	if err != nil {
		t.Fatalf("cached global stats: %v", err)
	}
	if cached.Total != global24.Total || log.count() != 0 {
		t.Fatalf("global stats cache miss: total=%d SQL=%d", cached.Total, log.count())
	}
	if cached.Categories[0].Category == "caller-owned" {
		t.Fatal("cached stats exposed a shared category slice")
	}

	log.reset()
	site1, err := repo.StatsSnapshotBySite(1, 24)
	if err != nil {
		t.Fatalf("site 1 stats: %v", err)
	}
	if site1.Total != 1 || log.count() != 6 {
		t.Fatalf("site 1 stats total=%d SQL=%d", site1.Total, log.count())
	}

	log.reset()
	site2, err := repo.StatsSnapshotBySite(2, 24)
	if err != nil {
		t.Fatalf("site 2 stats: %v", err)
	}
	if site2.Total != 1 || log.count() != 6 {
		t.Fatalf("site 2 stats total=%d SQL=%d", site2.Total, log.count())
	}

	log.reset()
	global48, err := repo.StatsSnapshot(48)
	if err != nil {
		t.Fatalf("global 48h stats: %v", err)
	}
	if global48.Total != 3 || log.count() != 6 {
		t.Fatalf("global 48h stats total=%d SQL=%d", global48.Total, log.count())
	}

	log.reset()
	for _, request := range []struct {
		siteID uint
		hours  int
		total  int64
	}{
		{siteID: 1, hours: 24, total: 1},
		{siteID: 2, hours: 24, total: 1},
	} {
		got, err := repo.StatsSnapshotBySite(request.siteID, request.hours)
		if err != nil || got.Total != request.total {
			t.Fatalf("cached site stats site=%d hours=%d total=%d err=%v", request.siteID, request.hours, got.Total, err)
		}
	}
	got48, err := repo.StatsSnapshot(48)
	if err != nil || got48.Total != 3 || log.count() != 0 {
		t.Fatalf("stats keys were not isolated or cached: total=%d err=%v SQL=%d", got48.Total, err, log.count())
	}

	log.reset()
	timeline24, err := repo.TimelineSnapshot(24)
	if err != nil {
		t.Fatalf("global timeline: %v", err)
	}
	if len(timeline24) != 1 || timeline24[0].Count != 1 || log.count() != 1 {
		t.Fatalf("global timeline=%+v SQL=%d", timeline24, log.count())
	}

	log.reset()
	timeline48, err := repo.TimelineSnapshotBySite(1, 48)
	if err != nil {
		t.Fatalf("site timeline: %v", err)
	}
	if len(timeline48) != 2 || log.count() != 1 {
		t.Fatalf("site 48h timeline=%+v SQL=%d", timeline48, log.count())
	}

	log.reset()
	if _, err := repo.TimelineSnapshot(24); err != nil || log.count() != 0 {
		t.Fatalf("global timeline cache err=%v SQL=%d", err, log.count())
	}
	if _, err := repo.TimelineSnapshotBySite(1, 48); err != nil || log.count() != 0 {
		t.Fatalf("site timeline cache err=%v SQL=%d", err, log.count())
	}
}

func TestSecurityEventAggregateSnapshotsInvalidateAfterWrite(t *testing.T) {
	repo, log := newSecurityEventAggregateRepoForTest(t)
	seedAggregateSecurityEvents(t, repo)

	initial, err := repo.StatsSnapshot(24)
	if err != nil {
		t.Fatalf("initial stats: %v", err)
	}
	if initial.Total != 2 {
		t.Fatalf("initial total=%d want=2", initial.Total)
	}

	createdAt := time.Now().Add(-10 * time.Minute)
	if err := repo.Create(&store.SecurityEvent{
		CreatedAt: createdAt,
		SiteID:    1,
		RequestID: "site-1-new",
		ClientIP:  "192.0.2.10",
		Path:      "/new",
		Category:  "cve",
		Action:    "intercept",
	}); err != nil {
		t.Fatalf("create security event: %v", err)
	}

	log.reset()
	refreshed, err := repo.StatsSnapshot(24)
	if err != nil {
		t.Fatalf("refreshed stats: %v", err)
	}
	if refreshed.Total != 3 {
		t.Fatalf("refreshed total=%d want=3", refreshed.Total)
	}
	if log.count() == 0 {
		t.Fatal("refreshed stats unexpectedly came entirely from the stale aggregate cache")
	}

	deleted, err := repo.DeleteOlderThan(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("delete recent event: %v", err)
	}
	if deleted != 4 {
		t.Fatalf("deleted=%d want=4", deleted)
	}
	refreshed, err = repo.StatsSnapshot(24)
	if err != nil {
		t.Fatalf("stats after delete: %v", err)
	}
	if refreshed.Total != 0 {
		t.Fatalf("stats after delete total=%d want=0", refreshed.Total)
	}
}

func TestSecurityEventAggregateCacheDoesNotRepublishInvalidatedLoad(t *testing.T) {
	cache := newSecurityEventAggregateCache()
	key := securityEventAggregateKey{kind: securityEventAggregateStats, hours: 24}
	started := make(chan struct{})
	release := make(chan struct{})
	var loads atomic.Int32

	var got any
	var gotErr error
	done := make(chan struct{})
	go func() {
		got, gotErr = cache.getOrLoad(key, func() (any, error) {
			if loads.Add(1) == 1 {
				close(started)
				<-release
				return "old", nil
			}
			return "fresh", nil
		})
		close(done)
	}()
	<-started
	cache.invalidate()
	close(release)
	<-done

	if gotErr != nil {
		t.Fatalf("generation retry failed: %v", gotErr)
	}
	if got != "fresh" {
		t.Fatalf("result after invalidation=%v want fresh", got)
	}
	if loads.Load() != 2 {
		t.Fatalf("loader calls=%d want 2", loads.Load())
	}
}

func TestSecurityEventAggregateSnapshotsCollapseConcurrentColdLoads(t *testing.T) {
	repo, log := newSecurityEventAggregateRepoForTest(t)
	seedAggregateSecurityEvents(t, repo)

	const workers = 32
	start := make(chan struct{})
	type statsResult struct {
		total int64
		err   error
	}
	results := make(chan statsResult, workers)
	var wg sync.WaitGroup
	log.reset()
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			snapshot, err := repo.StatsSnapshot(24)
			if len(snapshot.Categories) > 0 {
				snapshot.Categories[0].Category = "caller-owned"
			}
			results <- statsResult{total: snapshot.Total, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for result := range results {
		if result.err != nil || result.total != 2 {
			t.Fatalf("concurrent stats total=%d err=%v", result.total, result.err)
		}
	}
	if got := log.count(); got != 6 {
		t.Fatalf("concurrent stats SQL count=%d want=6", got)
	}

	start = make(chan struct{})
	errs := make(chan error, workers)
	log.reset()
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			buckets, err := repo.TimelineSnapshot(24)
			if len(buckets) > 0 {
				buckets[0].Bucket = "caller-owned"
			}
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent timeline: %v", err)
		}
	}
	if got := log.count(); got != 1 {
		t.Fatalf("concurrent timeline SQL count=%d want=1", got)
	}
}

func TestSecurityEventAggregateSnapshotExpiresWithoutSleeping(t *testing.T) {
	if securityEventAggregateCacheTTL != 45*time.Second {
		t.Fatalf("aggregate cache TTL=%s want=45s", securityEventAggregateCacheTTL)
	}
	repo, log := newSecurityEventAggregateRepoForTest(t)
	seedAggregateSecurityEvents(t, repo)
	if _, err := repo.StatsSnapshot(24); err != nil {
		t.Fatalf("prime stats cache: %v", err)
	}

	key := securityEventAggregateKey{kind: securityEventAggregateStats, hours: 24}
	repo.aggregateCache.mu.Lock()
	entry, ok := repo.aggregateCache.entries[key]
	if ok {
		entry.expiresAt = time.Now().Add(-time.Second)
		repo.aggregateCache.entries[key] = entry
	}
	repo.aggregateCache.mu.Unlock()
	if !ok {
		t.Fatal("primed stats cache entry is missing")
	}

	log.reset()
	refreshed, err := repo.StatsSnapshot(24)
	if err != nil {
		t.Fatalf("refresh expired stats: %v", err)
	}
	if refreshed.Total != 2 || log.count() != 6 {
		t.Fatalf("expired stats total=%d SQL=%d", refreshed.Total, log.count())
	}
}

func TestSecurityEventAggregateSnapshotDoesNotCacheFailure(t *testing.T) {
	repo, log := newSecurityEventAggregateRepoForTest(t)
	if err := repo.db.Migrator().DropTable(&store.SecurityEvent{}); err != nil {
		t.Fatalf("drop security event table: %v", err)
	}

	log.reset()
	if _, err := repo.StatsSnapshot(24); err == nil {
		t.Fatal("stats on missing table unexpectedly succeeded")
	}
	failedQueries := log.count()
	if failedQueries == 0 {
		t.Fatal("failed stats did not reach the database")
	}

	if err := repo.db.AutoMigrate(&store.SecurityEvent{}); err != nil {
		t.Fatalf("recreate security event table: %v", err)
	}
	seedAggregateSecurityEvents(t, repo)
	log.reset()
	retried, err := repo.StatsSnapshot(24)
	if err != nil {
		t.Fatalf("retry stats after database recovery: %v", err)
	}
	if retried.Total != 2 || log.count() != 6 {
		t.Fatalf("retried stats total=%d SQL=%d", retried.Total, log.count())
	}
	log.reset()
	if _, err := repo.StatsSnapshot(24); err != nil || log.count() != 0 {
		t.Fatalf("successful retry was not cached: err=%v SQL=%d", err, log.count())
	}
}

func TestSecurityEventAggregateCacheIsBounded(t *testing.T) {
	cache := newSecurityEventAggregateCache()
	for hours := 1; hours <= securityEventAggregateCacheMaxEntries+32; hours++ {
		key := securityEventAggregateKey{
			kind:  securityEventAggregateStats,
			hours: hours,
		}
		if _, err := cache.getOrLoad(key, func() (any, error) { return hours, nil }); err != nil {
			t.Fatalf("load cache key hours=%d: %v", hours, err)
		}
	}
	cache.mu.Lock()
	entries := len(cache.entries)
	cache.mu.Unlock()
	if entries != securityEventAggregateCacheMaxEntries {
		t.Fatalf("cache entries=%d want=%d", entries, securityEventAggregateCacheMaxEntries)
	}
}
