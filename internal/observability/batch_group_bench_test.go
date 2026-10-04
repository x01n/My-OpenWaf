package observability

import (
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"My-OpenWaf/internal/store"
)

// 多值组大小微基准
//
// 复刻 UnifiedWriter.sqliteBulkFlusher 的生产写入路径：真实 LogDB（temp 目录
// SQLite 文件）、真实 GORM 事务与连接池、长期语句 + 多值组语句。可控变量只有
// 组大小（8 vs 16），其余（单批 256 条、41 绑定列的 access_logs）为生产值。
//
// 时间结论（经 3 次独立取样中位对比，单次 ns/op 是单样本不可判）：
//
//	go test -bench 'BenchmarkUnifiedWriterBatchGroup' -benchmem -count=1
//
// 17 对 8/16 独立取样的判决：16 组把每批语句执行次数减半（参数 656 条 ≤ 999）、
// allocs/op 2707→2418 的机制收益，在 wall 时长上被整页 fsync 完全掩盖——17 对
// 中 14 对 8 组更快，中位差（8 组 10.80ms vs 16 组 11.92ms）落在页缓存/调度
// 噪声量级、方向一致偏向 8。按仓库「无墙钟/吞吐证据的优化不落地」纪律已回退：
// defaultMultiGroupSize 保持 8（见 sqlite_bulk_flusher.go 常量注释）。
// 本基准是可复测基建：未来写径（事务/journal 设置）改动后可重排本判决。

// benchAccessLogs 构建 n 条字段非零的 access_logs 行。
func benchAccessLogs(n int) []store.AccessLog {
	out := make([]store.AccessLog, n)
	for i := range out {
		out[i] = store.AccessLog{
			RequestID:  "bench-" + strconv.Itoa(i),
			SiteID:     1,
			ClientIP:   "203.0.113.9",
			Host:       "bench.example.test",
			Path:       "/bench/" + strconv.Itoa(i),
			Method:     "POST",
			StatusCode: 200,
		}
	}
	return out
}

// newBenchDB 打开一个已迁移日志表的临时文件库。每个组大小子基准独立建库，
// 第二个子基准从空表开始，不承受前一个子基准累积的行数与页缓存偏置。
func newBenchDB(tb testing.TB) *gorm.DB {
	tb.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(tb.TempDir(), "bench.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		tb.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		tb.Fatalf("get sqlite db: %v", err)
	}
	tb.Cleanup(func() { _ = sqlDB.Close() })
	if err := store.AutoMigrateLogs(db); err != nil {
		tb.Fatalf("migrate logs: %v", err)
	}
	return db
}

// newBenchWriter 构建可直接 flushBuffered 的 UnifiedWriter，并注入本次运行的
// 目标组大小（经测试后门 testHookMultiGroupSize；生产路径永不读取该后门）。
// 断言注入生效：组大小不匹配说明后门失效，基准结对不再可比。
func newBenchWriter(tb testing.TB, gdb *gorm.DB, groupSize int) *UnifiedWriter {
	tb.Helper()
	testHookMultiGroupSize = func() int { return groupSize }
	w := &UnifiedWriter{
		db:         gdb,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		batchSize:  256,
		drainLimit: 1024,
	}
	bf := w.sqliteFlusherFor()
	if bf == nil {
		tb.Fatal("sqlite bulk flusher must be available on sqlite dialect")
	}
	if got := bf.specs["access_logs"].groupSize; got != groupSize {
		tb.Fatalf("access_logs groupSize = %d, want %d", got, groupSize)
	}
	return w
}

// execBenchFlush 在单个事务内写入一批访问日志，并断言本批 256 条全部落库。
func execBenchFlush(tb testing.TB, w *UnifiedWriter, accs []store.AccessLog) {
	tb.Helper()
	w.flushBuffered(nil, accs, nil, nil)
	st := w.Stats()
	if st.LastFlushRecords != int64(len(accs)) || st.LastFlushFailedRecords != 0 {
		tb.Fatalf("flush records = %d (failed %d), want %d/0",
			st.LastFlushRecords, st.LastFlushFailedRecords, len(accs))
	}
}

// BenchmarkUnifiedWriterBatchGroup 是 8 vs 16 组大小下「256 行一批」的写入
// 耗时对比子基准。两个子基准共用同一份 256 行输入；每个子基准独占一个空库，
// 每轮迭代先清空表再写入，清空成本两个分支完全一致，分支差即组大小差。
func BenchmarkUnifiedWriterBatchGroup(b *testing.B) {
	rows := benchAccessLogs(256)
	for _, group := range []int{8, 16} {
		b.Run("group="+strconv.Itoa(group), func(b *testing.B) {
			gdb := newBenchDB(b)
			w := newBenchWriter(b, gdb, group)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := gdb.Exec("DELETE FROM access_logs").Error; err != nil {
					b.Fatalf("truncate: %v", err)
				}
				execBenchFlush(b, w, rows)
			}
		})
	}
}
