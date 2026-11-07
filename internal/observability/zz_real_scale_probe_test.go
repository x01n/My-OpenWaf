package observability

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"My-OpenWaf/internal/store"
)

// 真实规模写径基准（诊断用）。
//
// 为什么必须用真实规模库：空表基准测不出 Btree 深度与页缓存缺失。清空后页会进
// freelist 复用，所有内部页留在页缓存里，于是测出来的是「热页」成本。生产库是
// 119 万行 / 608MB（数据 233MB + 索引 300MB+），而 LogDB 的 cache_size 只有 64MB，
// 每插入一行要更新的 12 棵索引 Btree 里大部分页面都不在缓存中。
//
// 环境变量：
//
//	MY_OPENWAF_LOGLOSS_SRC  真实 LogDB 路径（默认 obsrun 场的 waf_logs.db）
//	MY_OPENWAF_LOGLOSS_ROWS 每档写入行数（默认 40000）
//	MY_OPENWAF_LOGLOSS_OUT  输出目录（默认 test.TempDir）

const prodLogDSNSuffix = "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=cache_size(-65536)&_pragma=foreign_keys(OFF)&_pragma=wal_autocheckpoint(2000)"

func copyDB(tb testing.TB, src, dst string) string {
	tb.Helper()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Stat(src + suffix); err != nil {
			continue
		}
		buf, err := os.ReadFile(src + suffix)
		if err != nil {
			tb.Fatalf("read %s: %v", src+suffix, err)
		}
		if err := os.WriteFile(dst+suffix, buf, 0o644); err != nil {
			tb.Fatalf("write %s: %v", dst+suffix, err)
		}
	}
	return dst
}

func openRealLogDB(tb testing.TB, path string) *gorm.DB {
	tb.Helper()
	db, err := gorm.Open(sqlite.Open(path+prodLogDSNSuffix), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		tb.Fatalf("open real log db: %v", err)
	}
	// 样本库可能是旧版本落下的，缺少后加的列。而 sqliteBulkFlusher 在
	// values/columns 不一致时会直接 disable，导致整档 flush 全是 0 行，
	// 看起来像「写入挂了」。这里先把样本对齐到当前模型再加列不改行数据。
	if err := db.AutoMigrate(&store.SecurityEvent{}, &store.AccessLog{}, &store.DropEvent{}, &store.BotScoreLog{}); err != nil {
		tb.Fatalf("migrate sample log db: %v", err)
	}
	raw, err := db.DB()
	if err != nil {
		tb.Fatalf("db: %v", err)
	}
	tb.Cleanup(func() { _ = raw.Close() })
	return db
}

func countRows(tb testing.TB, db *gorm.DB, table string) int {
	tb.Helper()
	var n int
	if err := db.Raw("SELECT count(*) FROM " + table).Scan(&n).Error; err != nil {
		tb.Fatalf("count %s: %v", table, err)
	}
	return n
}

func writeBatches(tb testing.TB, db *gorm.DB, bf *sqliteBulkFlusher, n, batch, base int) time.Duration {
	tb.Helper()
	w := &UnifiedWriter{
		db:         db,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		batchSize:  batch,
		drainLimit: 4 * batch,
	}
	w.sqliteFlusher = bf
	written := 0
	t0 := time.Now()
	for written < n {
		sz := batch
		if n-written < sz {
			sz = n - written
		}
		rows := benchRows(base+written, sz)
		w.flushBuffered(nil, rows, nil, nil)
		st := w.Stats()
		if st.LastFlushRecords != int64(sz) || st.LastFlushFailedRecords != 0 {
			tb.Fatalf("flush = %d/%d, want %d/0", st.LastFlushRecords, st.LastFlushFailedRecords, sz)
		}
		written += sz
	}
	return time.Since(t0)
}

func loglossEnv(t *testing.T) (src string, rows int, outDir string) {
	t.Helper()
	// 该探针会按档位复制整份真实规模 LogDB（GB 级）并重建索引，
	// 放进默认测试会让所有开发机都要付出几十秒与数 GB 磁盘。
	// 只在需要重新评估索引集/批大小收益时显式开启。
	if os.Getenv("MY_OPENWAF_WRITE_RATE_PROBE") != "1" {
		t.Skip("写速率诊断探针默认跳过：设置 MY_OPENWAF_WRITE_RATE_PROBE=1 开启（需要真实规模 LogDB 作为样本）")
	}
	src = os.Getenv("MY_OPENWAF_LOGLOSS_SRC")
	if src == "" {
		src = "/home/clfchen/.cache/owaf-tmp/logloss/data/waf_logs.db"
	}
	if _, err := os.Stat(src); err != nil {
		t.Skipf("真实 LogDB 不在位：%v", err)
	}
	rows = 40000
	if v := os.Getenv("MY_OPENWAF_LOGLOSS_ROWS"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &rows); err != nil {
			t.Fatalf("ROWS: %v", err)
		}
	}
	outDir = os.Getenv("MY_OPENWAF_LOGLOSS_OUT")
	if outDir == "" {
		outDir = t.TempDir()
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return src, rows, outDir
}

// TestWriteRateOnRealLogDB 在真实规模库上测持续写入速率，对比三档索引集。
func TestWriteRateOnRealLogDB(t *testing.T) {
	src, rows, outDir := loglossEnv(t)
	cases := []struct {
		name string
		keep map[string]bool
	}{
		{"asis-12-indexes", nil},
		{"keep-3-indexes", map[string]bool{
			"idx_al_created":         true,
			"idx_al_site_created_id": true,
			"idx_al_host":            true,
		}},
		{"keep-1-created", map[string]bool{"idx_al_created": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openRealLogDB(t, copyDB(t, src, filepath.Join(outDir, tc.name+".db")))
			if tc.keep != nil {
				dropIndexesExcept(t, db, "access_logs", tc.keep)
			}
			var idx []string
			if err := db.Raw("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='access_logs' AND sql IS NOT NULL ORDER BY name").Scan(&idx).Error; err != nil {
				t.Fatalf("list idx: %v", err)
			}
			before := countRows(t, db, "access_logs")
			bf := buildBFWithGroupSize(t, db, 8)
			d := writeBatches(t, db, bf, rows, 256, before)
			after := countRows(t, db, "access_logs")
			if after-before != rows {
				t.Fatalf("rows written = %d, want %d", after-before, rows)
			}
			t.Logf("RESULT 库=%-16s 起始行=%d 索引=%2d 行数=%d 耗时=%-9s 速率=%.0f 行/s",
				tc.name, before, len(idx), rows, d.Round(time.Millisecond), float64(rows)/d.Seconds())
		})
	}
}

// TestWriteRateGroupSweepRealDB 在真实规模库上扫组大小（索引集固定为生产 12 个）。
func TestWriteRateGroupSweepRealDB(t *testing.T) {
	src, rows, outDir := loglossEnv(t)
	for _, g := range []int{4, 8, 16, 24} {
		t.Run(fmt.Sprintf("group=%d", g), func(t *testing.T) {
			db := openRealLogDB(t, copyDB(t, src, filepath.Join(outDir, fmt.Sprintf("gsweep_real_%d.db", g))))
			bf := buildBFWithGroupSize(t, db, g)
			before := countRows(t, db, "access_logs")
			d := writeBatches(t, db, bf, rows, 256, before)
			t.Logf("RESULT group=%-3d 行数=%d 耗时=%-9s 速率=%.0f 行/s",
				g, rows, d.Round(time.Millisecond), float64(rows)/d.Seconds())
		})
	}
}

// TestWriteRateCombinedRealDB 组合档：无查询消费点的索引裁掉 + 放大批大小。
//
// 这是「不靠阻塞入队也能零丢弃」的候选路径：把入库能力抬到生产速率之上，
// 队列就不会长期饱和，慢速宽限也就不必介入。
//
// 裁掉的三个索引有明确的「无消费点」证据（全仓 rg 核对）：
//   - idx_al_host：只有 host LIKE '%...%'（前导通配，索引无法作前导列），
//     无 host = ? 的生产查询；
//   - idx_al_visitor_fusion_window：字段只出现在 SELECT 的 SUM(CASE ...) 表达式里，
//     不是 WHERE/ORDER BY 谓词；
//   - idx_al_site_created (created_at, site_id)：被 idx_al_created 与
//     idx_al_site_created_id 完全覆盖，无查询以该组合为依赖。
func TestWriteRateCombinedRealDB(t *testing.T) {
	src, rows, outDir := loglossEnv(t)
	trimmed := map[string]bool{
		"idx_al_created":         true,
		"idx_al_site_created_id": true,
		"idx_al_request_id":      true,
		"idx_al_client_ip":       true,
		"idx_al_status":          true,
		"idx_al_waf_action":      true,
		"idx_al_tls_ja3_hash":    true,
		"idx_al_tls_ja4":         true,
		"idx_al_fingerprint_key": true,
	}
	cases := []struct {
		name   string
		keep   map[string]bool
		batch  int
		groups int
	}{
		{"prod-12idx-batch256-g8", nil, 256, 8},
		{"trim9-batch256-g8", trimmed, 256, 8},
		{"trim9-batch4096-g8", trimmed, 4096, 8},
		{"prod-12idx-batch4096-g8", nil, 4096, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openRealLogDB(t, copyDB(t, src, filepath.Join(outDir, tc.name+".db")))
			if tc.keep != nil {
				dropIndexesExcept(t, db, "access_logs", tc.keep)
			}
			idx := listIndexes(t, db, "access_logs")
			bf := buildBFWithGroupSize(t, db, tc.groups)
			before := countRows(t, db, "access_logs")
			d := writeBatches(t, db, bf, rows, tc.batch, before)
			t.Logf("RESULT %-26s 索引=%2d 批=%-5d 行数=%d 耗时=%-9s 速率=%.0f 行/s",
				tc.name, len(idx), tc.batch, rows, d.Round(time.Millisecond), float64(rows)/d.Seconds())
		})
	}
}
func TestWriteRateBatchSweepRealDB(t *testing.T) {
	src, rows, outDir := loglossEnv(t)
	for _, b := range []int{256, 1024, 4096} {
		t.Run(fmt.Sprintf("batch=%d", b), func(t *testing.T) {
			db := openRealLogDB(t, copyDB(t, src, filepath.Join(outDir, fmt.Sprintf("bsweep_real_%d.db", b))))
			bf := buildBFWithGroupSize(t, db, 8)
			before := countRows(t, db, "access_logs")
			d := writeBatches(t, db, bf, rows, b, before)
			t.Logf("RESULT batch=%-5d 行数=%d 耗时=%-9s 速率=%.0f 行/s",
				b, rows, d.Round(time.Millisecond), float64(rows)/d.Seconds())
		})
	}
}
