package repository

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"My-OpenWaf/internal/store"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestAccessLogRepoListFingerprintsUsesBoundedProcessCache(t *testing.T) {
	log := newCountingSQLLogger()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: log})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&store.AccessLog{}, &store.BotScoreLog{}); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	if err := db.Create(&store.AccessLog{
		RequestID:  "cache-fingerprint-1",
		TLSJA3Hash: "cache-ja3-1",
		TLSJA4:     "cache-ja4-1",
		TLSVersion: "TLS13",
		TLSALPN:    "h2",
		CreatedAt:  nowForFingerprintCacheTest(),
		UserAgent:  "cache-agent",
		ClientIP:   "192.0.2.10",
	}).Error; err != nil {
		t.Fatalf("create access log: %v", err)
	}
	repo := NewAccessLogRepo(db)

	first, total, err := repo.ListFingerprints(0, 20, FingerprintFilter{})
	if err != nil {
		t.Fatalf("cold fingerprint list: %v", err)
	}
	if total != 1 || len(first) != 1 {
		t.Fatalf("cold result total=%d len=%d, want one", total, len(first))
	}
	log.reset()
	first[0].TLSJA3Hash = "caller-mutated"
	second, total, err := repo.ListFingerprints(0, 20, FingerprintFilter{})
	if err != nil {
		t.Fatalf("warm fingerprint list: %v", err)
	}
	if got := log.count(); got != 0 {
		t.Fatalf("warm fingerprint list executed %d SQL statements, want 0", got)
	}
	if total != 1 || len(second) != 1 || second[0].TLSJA3Hash != "cache-ja3-1" {
		t.Fatalf("warm result was not an isolated cached copy: total=%d items=%#v", total, second)
	}

	if err := repo.Create(&store.AccessLog{
		RequestID:  "cache-fingerprint-2",
		TLSJA3Hash: "cache-ja3-2",
		TLSJA4:     "cache-ja4-2",
		TLSVersion: "TLS13",
		TLSALPN:    "h2",
		CreatedAt:  nowForFingerprintCacheTest(),
	}); err != nil {
		t.Fatalf("create second access log: %v", err)
	}
	log.reset()
	third, total, err := repo.ListFingerprints(0, 20, FingerprintFilter{})
	if err != nil {
		t.Fatalf("post-write fingerprint list: %v", err)
	}
	if log.count() == 0 {
		t.Fatal("repository write did not invalidate the process fingerprint cache")
	}
	if total != 2 || len(third) != 2 {
		t.Fatalf("post-write result total=%d len=%d, want two", total, len(third))
	}
}

func TestFingerprintResultCacheIsBoundedAndGenerationAware(t *testing.T) {
	c := newFingerprintResultCache()
	for i := 0; i < fingerprintResultCacheMaxEntries+8; i++ {
		key := fingerprintResultCacheKey{Offset: i, Limit: 1, Filter: FingerprintFilter{TLSJA3Hash: string(rune('a' + i%26))}}
		c.setIfGeneration(key, fingerprintResult{Items: []FingerprintSummary{{TLSJA3Hash: "ja3"}}, Total: 1}, c.generationValue())
	}
	c.mu.Lock()
	entries := len(c.entries)
	c.mu.Unlock()
	if entries > fingerprintResultCacheMaxEntries {
		t.Fatalf("cache entries=%d exceed hard cap %d", entries, fingerprintResultCacheMaxEntries)
	}
	oldGeneration := c.generationValue()
	c.invalidate()
	if c.generationValue() != oldGeneration+1 {
		t.Fatalf("generation=%d want %d after invalidation", c.generationValue(), oldGeneration+1)
	}
	if _, ok := c.get(fingerprintResultCacheKey{Offset: 0, Limit: 1}); ok {
		t.Fatal("invalidated cache returned an old entry")
	}
}

func TestFingerprintHotCacheKeyIsBoundedAndFilterSpecific(t *testing.T) {
	first := fingerprintHotCacheKey("database-a", 0, fingerprintResultCacheKey{Offset: 0, Limit: 20, Filter: FingerprintFilter{TLSJA3Hash: "ja3-a"}})
	second := fingerprintHotCacheKey("database-a", 0, fingerprintResultCacheKey{Offset: 0, Limit: 20, Filter: FingerprintFilter{TLSJA3Hash: "ja3-b"}})
	if first == second {
		t.Fatal("different fingerprint filters shared a hot-cache key")
	}
	otherDatabase := fingerprintHotCacheKey("database-b", 0, fingerprintResultCacheKey{Offset: 0, Limit: 20, Filter: FingerprintFilter{TLSJA3Hash: "ja3-a"}})
	if first == otherDatabase {
		t.Fatal("different database namespaces shared a hot-cache key")
	}
	if len(first) > 128 || len(second) > 128 || len(otherDatabase) > 128 {
		t.Fatalf("hot-cache key length exceeds bound: %d/%d", len(first), len(second))
	}
}

func TestAccessLogRepoFingerprintNamespaceSeparatesRepositories(t *testing.T) {
	first := NewAccessLogRepo(nil)
	second := NewAccessLogRepo(nil)
	if first.fingerprintNamespace == "" || second.fingerprintNamespace == "" {
		t.Fatal("fingerprint cache namespace must be initialized")
	}
	if first.fingerprintNamespace == second.fingerprintNamespace {
		t.Fatal("separate repositories must not share a remote fingerprint cache namespace")
	}
	key := fingerprintResultCacheKey{Offset: 0, Limit: 20}
	if fingerprintHotCacheKey(first.fingerprintNamespace, 0, key) == fingerprintHotCacheKey(second.fingerprintNamespace, 0, key) {
		t.Fatal("separate repository namespaces produced the same remote fingerprint key")
	}
}

func TestFingerprintResultCacheSingleflight(t *testing.T) {
	c := newFingerprintResultCache()
	key := fingerprintResultCacheKey{Offset: 0, Limit: 20}
	var loads atomic.Int32
	start := make(chan struct{})
	results := make(chan fingerprintResult, 2)
	errors := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			result, err := c.getOrLoad(key, func() (fingerprintResult, error) {
				loads.Add(1)
				<-start
				return fingerprintResult{Items: []FingerprintSummary{{TLSJA3Hash: "ja3"}}, Total: 1}, nil
			})
			results <- result
			errors <- err
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-errors; err != nil {
			t.Fatalf("singleflight load: %v", err)
		}
		if got := <-results; got.Total != 1 || len(got.Items) != 1 {
			t.Fatalf("singleflight result=%#v", got)
		}
	}
	if loads.Load() != 1 {
		t.Fatalf("singleflight loader calls=%d, want 1", loads.Load())
	}
}

func TestFingerprintResultCacheGenerationSeparatesInFlightLoads(t *testing.T) {
	c := newFingerprintResultCache()
	key := fingerprintResultCacheKey{Offset: 0, Limit: 20}
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondStarted := make(chan struct{})
	var loads atomic.Int32
	firstResult := make(chan fingerprintResult, 1)
	firstError := make(chan error, 1)
	go func() {
		result, err := c.getOrLoad(key, func() (fingerprintResult, error) {
			loads.Add(1)
			close(firstStarted)
			<-releaseFirst
			return fingerprintResult{Items: []FingerprintSummary{{TLSJA3Hash: "before-write"}}, Total: 1}, nil
		})
		firstResult <- result
		firstError <- err
	}()
	<-firstStarted
	c.invalidate()
	secondResult := make(chan fingerprintResult, 1)
	secondError := make(chan error, 1)
	go func() {
		result, err := c.getOrLoad(key, func() (fingerprintResult, error) {
			loads.Add(1)
			close(secondStarted)
			return fingerprintResult{Items: []FingerprintSummary{{TLSJA3Hash: "after-write"}}, Total: 2}, nil
		})
		secondResult <- result
		secondError <- err
	}()
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("post-invalidation request joined the old in-flight load")
	}
	if err := <-secondError; err != nil {
		t.Fatalf("post-invalidation load: %v", err)
	}
	if result := <-secondResult; result.Total != 2 || result.Items[0].TLSJA3Hash != "after-write" {
		t.Fatalf("post-invalidation result=%#v", result)
	}
	close(releaseFirst)
	if err := <-firstError; err != nil {
		t.Fatalf("pre-invalidation load: %v", err)
	}
	if result := <-firstResult; result.Total != 2 || result.Items[0].TLSJA3Hash != "after-write" {
		t.Fatalf("pre-invalidation caller should retry against the new generation, result=%#v", result)
	}
	if loads.Load() != 2 {
		t.Fatalf("loader calls=%d, want independent pre/post-invalidation loads", loads.Load())
	}
}

func TestFingerprintResultCacheGenerationRetryIsBounded(t *testing.T) {
	c := newFingerprintResultCache()
	key := fingerprintResultCacheKey{Offset: 0, Limit: 20}
	var loads atomic.Int32
	done := make(chan fingerprintResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := c.getOrLoad(key, func() (fingerprintResult, error) {
			loads.Add(1)
			c.invalidate()
			return fingerprintResult{Items: []FingerprintSummary{{TLSJA3Hash: "unstable"}}, Total: 1}, nil
		})
		done <- result
		errCh <- err
	}()
	select {
	case <-time.After(time.Second):
		t.Fatal("generation retries did not terminate")
	case err := <-errCh:
		if err != nil {
			t.Fatalf("bounded retry returned error: %v", err)
		}
	}
	result := <-done
	if result.Total != 1 || len(result.Items) != 1 {
		t.Fatalf("bounded retry result=%#v", result)
	}
	wantLoads := int32(fingerprintResultCacheMaxGenerationRetries + 2)
	if got := loads.Load(); got != wantLoads {
		t.Fatalf("loader calls=%d, want bounded %d", got, wantLoads)
	}
}

func BenchmarkAccessLogRepoListFingerprintsCold(b *testing.B) {
	db := openFingerprintBenchmarkDB(b)
	repo := NewAccessLogRepo(db)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		repo.invalidateFingerprintCache()
		if _, _, err := repo.ListFingerprints(0, 20, FingerprintFilter{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAccessLogRepoListFingerprintsWarm(b *testing.B) {
	db := openFingerprintBenchmarkDB(b)
	repo := NewAccessLogRepo(db)
	if _, _, err := repo.ListFingerprints(0, 20, FingerprintFilter{}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := repo.ListFingerprints(0, 20, FingerprintFilter{}); err != nil {
			b.Fatal(err)
		}
	}
}

/**
 * BenchmarkFingerprintLatestRowProjection 对比指纹最新行查询的窄/宽扫描模型。
 *
 * 该基准只在显式提供 MY_OPENWAF_FINGERPRINT_BENCH_DB 时运行，避免默认测试读取
 * 生产数据。两组使用完全相同的 SELECT 与 WHERE，只改变 GORM 目标结构体，便于
 * 观察审计大字段未被选取时的 ORM 分配成本。
 */
func BenchmarkFingerprintLatestRowProjection(b *testing.B) {
	db := openFingerprintBenchmarkDB(b)
	selectColumns := "id, created_at, user_agent, client_ip, header_order, tls_ja3_hash, tls_ja4, tls_version, tls_alpn, tls_sni, tls_cipher_suites, tls_extensions, tls_curves, tls_point_formats"
	query := func() *gorm.DB {
		return db.Table("access_logs AS al").
			Select(selectColumns).
			Where("al.tls_ja3_hash <> ?", "").
			Order("al.created_at DESC, al.id DESC").
			Limit(20)
	}

	b.Run("narrow", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var rows []fingerprintLatestRow
			if err := query().Find(&rows).Error; err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("wide", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var rows []store.AccessLog
			if err := query().Find(&rows).Error; err != nil {
				b.Fatal(err)
			}
		}
	})
}

func openFingerprintBenchmarkDB(b *testing.B) *gorm.DB {
	b.Helper()
	path := os.Getenv("MY_OPENWAF_FINGERPRINT_BENCH_DB")
	if path == "" {
		b.Skip("MY_OPENWAF_FINGERPRINT_BENCH_DB 未设置")
	}
	db, err := gorm.Open(sqlite.Open("file:"+path+"?mode=ro"), &gorm.Config{})
	if err != nil {
		b.Fatalf("open read-only benchmark database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		b.Fatalf("get benchmark sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	b.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

func nowForFingerprintCacheTest() time.Time {
	return time.Now().UTC()
}
