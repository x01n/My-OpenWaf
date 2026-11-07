package observability

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"My-OpenWaf/internal/store"
)

// 异步写入器的成本诊断基准。
//
// 为什么需要它：UnifiedWriter 是异步写库的，请求处理路径根本不写库，所以
// 「每请求 WAF 成本」之类的指标对写入成本完全不敏感。判断写径能否跟上生产
// 速率，必须在写入路径本身测量。
//
// 三个已确认的机制（读源码得到，不是推断）：
//
//  1. github.com/glebarez/go-sqlite@v1.23.0 sqlite.go:500-510 —— driver 的
//     stmt.exec 每次调用都重新 sqlite3_prepare_v2 同一段 SQL 文本；语句复用只
//     发生在 database/sql 层，没有发生在 SQLite 解析器层。因此批内 Exec 次数
//     = 批内完整 SQL 解析次数，解析成本 ∝ 批内总行数 × 列数，与组大小无关。
//  2. 同文件 sqlite.go:1052-1108 —— conn.bind 对每个参数 i 都在 args 里线性扫描
//     找 Ordinal==i，即 O(参数数²)；参数数 = 组大小 × 列数。组大小放大因此让
//     bind 变贵，与解析收益方向相反，拐点在组大小 3-8。
//  3. 空表基准测不出 Btree 深度与页缓存缺失：清空后数据页进 freelist 复用、内部
//     页留在缓存里。真实库远超 cache_size(-65536)，每行要更新的多棵索引 Btree
//     大量缺页——这一项只能在真实规模库上测（见 zz_real_scale_probe_test.go）。

// benchCols 是 access_logs 的绑定列数，用于报告占位符总数。
const benchCols = 41

// buildBFWithGroupSize 构造 flusher 并把 access_logs 的组大小覆写为 n，
// 绕过 multiGroupSizeFor 的 999/列数 截断，用于扫描生产之外的组大小。
func buildBFWithGroupSize(tb testing.TB, db *gorm.DB, n int) *sqliteBulkFlusher {
	tb.Helper()
	bf := newSQLiteBulkFlusher(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if bf == nil {
		tb.Fatal("flusher nil")
	}
	if err := bf.attachSQLDB(db); err != nil {
		tb.Fatalf("attach: %v", err)
	}
	spec := bf.specs["access_logs"]
	spec.groupSize = n
	bf.specs["access_logs"] = spec
	return bf
}

// flushWithBF 用自建 writer 把 rows 写进 access_logs（生产同款事务 + SAVEPOINT
// 语义），返回墙钟。
func flushWithBF(tb testing.TB, db *gorm.DB, bf *sqliteBulkFlusher, rows []store.AccessLog) time.Duration {
	tb.Helper()
	w := &UnifiedWriter{
		db:         db,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		batchSize:  len(rows),
		drainLimit: 4 * len(rows),
	}
	w.sqliteFlusher = bf
	t0 := time.Now()
	w.flushBuffered(nil, rows, nil, nil)
	d := time.Since(t0)
	st := w.Stats()
	if st.LastFlushRecords != int64(len(rows)) || st.LastFlushFailedRecords != 0 {
		tb.Fatalf("group=%d flush = %d/%d, want %d/0", bf.specs["access_logs"].groupSize,
			st.LastFlushRecords, st.LastFlushFailedRecords, len(rows))
	}
	return d
}

// benchRows 生成 base 起的 n 行访问日志。fingerprint_key 与 tls_ja3_hash 用真实
// 长度的哈希，避免高重复值让索引维护成本失真。
func benchRows(base, n int) []store.AccessLog {
	out := make([]store.AccessLog, n)
	for i := range out {
		id := base + i
		out[i] = store.AccessLog{
			RequestID:      "bench-" + strconv.Itoa(id),
			SiteID:         1,
			ClientIP:       "203.0.113." + strconv.Itoa(id%250+1),
			Host:           "bench.example.test",
			Path:           "/bench/" + strconv.Itoa(id),
			Method:         "POST",
			StatusCode:     200,
			WAFAction:      "none",
			HTTPProtocol:   "HTTP/1.1",
			UserAgent:      "bench-agent/1.0",
			ResponseSize:   1024,
			RequestSize:    128,
			TLSJA3Hash:     fmt.Sprintf("%032x", id),
			FingerprintKey: fmt.Sprintf("%064x", id),
		}
	}
	return out
}

// newBenchLogDB 建一个已迁移日志表的库。测试以 TMPDIR 指向 ext4（生产盘同类），
// 不是 /tmp 的 tmpfs。
func newBenchLogDB(tb testing.TB, name string) *gorm.DB {
	tb.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(tb.TempDir(), name)), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		tb.Fatalf("open: %v", err)
	}
	raw, err := db.DB()
	if err != nil {
		tb.Fatalf("db: %v", err)
	}
	tb.Cleanup(func() { _ = raw.Close() })
	if err := store.AutoMigrateLogs(db); err != nil {
		tb.Fatalf("migrate logs: %v", err)
	}
	return db
}

// dropIndexesExcept 删除目标表上除 keep 之外的全部普通索引（sql IS NOT NULL
// 排除自动索引），保持表结构与列不变。
func dropIndexesExcept(tb testing.TB, db *gorm.DB, table string, keep map[string]bool) {
	tb.Helper()
	var names []string
	if err := db.Raw("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL", table).
		Scan(&names).Error; err != nil {
		tb.Fatalf("list indexes: %v", err)
	}
	for _, name := range names {
		if keep[name] {
			continue
		}
		if err := db.Exec(`DROP INDEX "` + name + `"`).Error; err != nil {
			tb.Fatalf("drop index %s: %v", name, err)
		}
	}
}

// listIndexes 列出目标表上的普通索引名（升序）。
func listIndexes(tb testing.TB, db *gorm.DB, table string) []string {
	tb.Helper()
	var names []string
	if err := db.Raw("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL ORDER BY name", table).
		Scan(&names).Error; err != nil {
		tb.Fatalf("list indexes: %v", err)
	}
	return names
}

// TestProbeAccessLogGroupCeiling 报告 41 列形态下 prepare 可接受的最大组大小。
// 生产把 driverMaxVariableNumber 固定为 999，于是组大小被截断到 24；本用例给出
// 驱动实际能接受的边界，作为「该常量是否还有意义」的依据。
func TestProbeAccessLogGroupCeiling(t *testing.T) {
	db := newBenchLogDB(t, "ceiling.db")
	for _, n := range []int{24, 64, 256, 800} {
		bf := buildBFWithGroupSize(t, db, n)
		_, got, err := bf.ensureMultiStmtFor("access_logs")
		if err != nil {
			t.Logf("组大小 %4d（%6d 占位符）: 不可用 -> %v", n, n*benchCols, err)
			continue
		}
		t.Logf("组大小 %4d（%6d 占位符）: prepare 成功, groupSize=%d", n, n*benchCols, got)
	}
}

// BenchmarkWritePathGroupSweep 扫组大小（含 1，走单行长期语句路径）。
// 双指标：flush-ms/op（一批 256 行墙钟）与 rows-per-sec（该档的吞吐上限）。
func BenchmarkWritePathGroupSweep(b *testing.B) {
	for _, g := range []int{1, 2, 3, 4, 6, 8, 12, 16, 24} {
		b.Run(fmt.Sprintf("group=%d", g), func(b *testing.B) {
			db := newBenchLogDB(b, fmt.Sprintf("gsweep%d.db", g))
			bf := buildBFWithGroupSize(b, db, g)
			if _, _, err := bf.ensureMultiStmtFor("access_logs"); err != nil && g > 1 {
				b.Skipf("group=%d 多值语句不可用：%v", g, err)
			}
			rows := benchRows(0, 256)
			flushWithBF(b, db, bf, rows)
			var total time.Duration
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := db.Exec("DELETE FROM access_logs").Error; err != nil {
					b.Fatalf("truncate: %v", err)
				}
				total += flushWithBF(b, db, bf, rows)
			}
			b.StopTimer()
			ms := float64(total.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(ms, "flush-ms/op")
			b.ReportMetric(256/ms*1000, "rows-per-sec")
		})
	}
}

// BenchmarkWritePathBatchSweep 扫批大小（组大小固定为生产值 8）：回答「放大单批
// 能否摊薄每行成本」。空表下 1024 与 4096 已接近饱和；真实规模库上结论不同，
// 见 TestWriteRateBatchSweepRealDB。
func BenchmarkWritePathBatchSweep(b *testing.B) {
	for _, n := range []int{64, 256, 1024, 4096} {
		b.Run(fmt.Sprintf("batch=%d", n), func(b *testing.B) {
			db := newBenchLogDB(b, fmt.Sprintf("bsweep%d.db", n))
			bf := buildBFWithGroupSize(b, db, 8)
			rows := benchRows(0, n)
			flushWithBF(b, db, bf, rows)
			var total time.Duration
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := db.Exec("DELETE FROM access_logs").Error; err != nil {
					b.Fatalf("truncate: %v", err)
				}
				total += flushWithBF(b, db, bf, rows)
			}
			b.StopTimer()
			ms := float64(total.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(float64(n)/ms*1000, "rows-per-sec")
		})
	}
}

var (
	_ = os.Stat
	_ = time.Second
)
