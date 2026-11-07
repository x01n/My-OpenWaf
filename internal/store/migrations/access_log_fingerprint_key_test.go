package migrations

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

const v12TestAccessLogsDDL = `CREATE TABLE access_logs (
	id INTEGER PRIMARY KEY,
	tls_ja3_hash TEXT,
	tls_ja4 TEXT,
	tls_version TEXT,
	tls_alpn TEXT,
	tls_sni TEXT,
	tls_cipher_suites TEXT,
	tls_extensions TEXT,
	tls_curves TEXT,
	tls_point_formats TEXT
)`

// TestV12EnsureAccessLogFingerprintKeyIsIdempotent 验证列/索引/标记表的补齐
// 可重复执行，且不触碰历史行。
func TestV12EnsureAccessLogFingerprintKeyIsIdempotent(t *testing.T) {
	db := openMemDB(t)
	if err := db.Exec(v12TestAccessLogsDDL).Error; err != nil {
		t.Fatalf("create access_logs: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := V12EnsureAccessLogFingerprintKey(db); err != nil {
			t.Fatalf("ensure attempt %d: %v", i+1, err)
		}
	}
	table := &v12AccessLogFingerprintTable{}
	if !db.Migrator().HasColumn(table, "fingerprint_key") {
		t.Fatal("access_logs.fingerprint_key must exist after ensure")
	}
	if !db.Migrator().HasIndex(table, "idx_al_fingerprint_key") {
		t.Fatal("idx_al_fingerprint_key must exist after ensure")
	}
	if !db.Migrator().HasTable("log_schema_migrations") {
		t.Fatal("log_schema_migrations must exist after ensure")
	}
}

// TestV12BackfillAccessLogFingerprintKeyWritesKeyAndMarker 验证回填只处理
// 含 JA3/JA4 的行、写入摘要与完成标记，且标记存在后不再重复扫描。
func TestV12BackfillAccessLogFingerprintKeyWritesKeyAndMarker(t *testing.T) {
	db := openMemDB(t)
	if err := db.Exec(v12TestAccessLogsDDL).Error; err != nil {
		t.Fatalf("create access_logs: %v", err)
	}
	if err := V12EnsureAccessLogFingerprintKey(db); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := db.Exec(`INSERT INTO access_logs (id, tls_ja3_hash, tls_ja4, tls_version) VALUES
		(1, 'ja3-abc', '', 'TLS13'),
		(2, NULL, NULL, 'TLS13'),
		(3, '', NULL, 'TLS12')`).Error; err != nil {
		t.Fatalf("seed access_logs: %v", err)
	}

	if err := V12BackfillAccessLogFingerprintKey(db); err != nil {
		t.Fatalf("first backfill: %v", err)
	}

	var keys []struct {
		ID             uint
		FingerprintKey *string `gorm:"column:fingerprint_key"`
	}
	if err := db.Raw("SELECT id, fingerprint_key FROM access_logs ORDER BY id").Scan(&keys).Error; err != nil {
		t.Fatalf("read fingerprint keys: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(keys))
	}
	if keys[0].FingerprintKey == nil || len(*keys[0].FingerprintKey) != 64 {
		t.Fatalf("row 1 must carry a 64-char fingerprint key, got %+v", keys[0].FingerprintKey)
	}
	if keys[1].FingerprintKey != nil || keys[2].FingerprintKey != nil {
		t.Fatalf("rows without JA3/JA4 must keep NULL key, got %+v and %+v", keys[1].FingerprintKey, keys[2].FingerprintKey)
	}
	done, err := v12AccessLogFingerprintBackfillDone(db)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if !done {
		t.Fatal("migration marker must be written after a successful backfill")
	}

	// 标记存在后新增的含 JA3 行不应再被扫描：回填已完成。
	if err := db.Exec("INSERT INTO access_logs (id, tls_ja3_hash, tls_ja4, tls_version) VALUES (4, 'ja3-new', '', 'TLS13')").Error; err != nil {
		t.Fatalf("insert post-marker row: %v", err)
	}
	if err := V12BackfillAccessLogFingerprintKey(db); err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	var post struct {
		FingerprintKey *string `gorm:"column:fingerprint_key"`
	}
	if err := db.Raw("SELECT fingerprint_key FROM access_logs WHERE id = 4").Scan(&post).Error; err != nil {
		t.Fatalf("read post-marker row: %v", err)
	}
	if post.FingerprintKey != nil {
		t.Fatalf("marker must short-circuit further scans, got %q", *post.FingerprintKey)
	}
}

// TestV12StartAccessLogFingerprintBackfillRunsAsync 验证异步入口最终完成
// 回填并落下标记，且不阻塞调用方。
func TestV12StartAccessLogFingerprintBackfillRunsAsync(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "waf_logs.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open file sqlite: %v", err)
	}
	if err := db.Exec(v12TestAccessLogsDDL).Error; err != nil {
		t.Fatalf("create access_logs: %v", err)
	}
	if err := db.Exec("INSERT INTO access_logs (id, tls_ja3_hash, tls_ja4, tls_version) VALUES (1, 'ja3-async', '', 'TLS13')").Error; err != nil {
		t.Fatalf("seed access_logs: %v", err)
	}
	if err := V12EnsureAccessLogFingerprintKey(db); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	var asyncErr error
	V12StartAccessLogFingerprintBackfill(db, func(err error) { asyncErr = err })

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var filled int64
		if err := db.Table("access_logs").Where("fingerprint_key IS NOT NULL AND fingerprint_key <> ''").Count(&filled).Error; err != nil {
			t.Fatalf("count filled rows: %v", err)
		}
		done, err := v12AccessLogFingerprintBackfillDone(db)
		if err != nil {
			t.Fatalf("read marker: %v", err)
		}
		if filled == 1 && done {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if asyncErr != nil {
		t.Fatalf("async backfill failed: %v", asyncErr)
	}
	t.Fatal("async backfill did not finish within 10s")
}
