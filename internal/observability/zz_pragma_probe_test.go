package observability

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"My-OpenWaf/internal/store"
)

// 日志库 pragma 档位基准（诊断用，默认跳过）。
//
// 背景：生产 LogDB 走 wal_autocheckpoint=2000（≈8MB）。1.5GB 主库上每次
// checkpoint 都要把 WAL 中被修改的页随机写回主库并 fsync，写放大与随机 IO
// 随库规模线性增长。本探针在同一份真实库副本上扫 cache_size / autocheckpoint
// 两维档位，量化 checkpoint 窗口与页缓存的实际收益。
//
// 环境变量：
//
//	MY_OPENWAF_PRAGMA_PROBE=1 开启（默认跳过，需要真实规模 LogDB 样本）
//	MY_OPENWAF_LOGLOSS_SRC    真实 LogDB 路径
//	MY_OPENWAF_LOGLOSS_ROWS   每档写入行数（默认 30000）
//	MY_OPENWAF_LOGLOSS_OUT    输出目录（默认 test.TempDir）
func TestWriteRatePragmaSweepRealDB(t *testing.T) {
	if os.Getenv("MY_OPENWAF_PRAGMA_PROBE") != "1" {
		t.Skip("pragma 诊断探针默认跳过：设置 MY_OPENWAF_PRAGMA_PROBE=1 开启（需要真实规模 LogDB 作为样本）")
	}
	src, rows, outDir := loglossEnv(t)
	cases := []struct {
		name        string
		cacheKB     int
		autocheckpt int
	}{
		{"ckpt2000", 65536, 2000},
		{"ckpt4000", 65536, 4000},
		{"ckpt8000", 65536, 8000},
		{"ckpt16000", 65536, 16000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := filepath.Join(outDir, tc.name+".db")
			db := openPragmaLogDB(t, streamCopyLogDB(t, src, dst), tc.cacheKB, tc.autocheckpt)
			var idx []string
			if err := db.Raw("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='access_logs' AND sql IS NOT NULL ORDER BY name").Scan(&idx).Error; err != nil {
				t.Fatalf("list idx: %v", err)
			}
			before := countRows(t, db, "access_logs")
			bf := buildBFWithGroupSize(t, db, 8)
			d := writeBatches(t, db, bf, rows, 4096, before)
			after := countRows(t, db, "access_logs")
			if after-before != rows {
				t.Fatalf("rows written = %d, want %d", after-before, rows)
			}
			t.Logf("RESULT 档位=%-24s 索引=%2d 行数=%d 耗时=%-9s 速率=%.0f 行/s",
				tc.name, len(idx), rows, d.Round(time.Millisecond), float64(rows)/d.Seconds())
			_ = os.Remove(dst)
			_ = os.Remove(dst + "-wal")
			_ = os.Remove(dst + "-shm")
		})
	}
}

// openPragmaLogDB 以指定 pragma 档位打开日志库副本，并把样本库结构对齐到当前模型。
//
// 逻辑与 openRealLogDB 一致，唯一差别是 cache_size 与 wal_autocheckpoint 可配。
func openPragmaLogDB(tb testing.TB, path string, cacheKB, autocheckpt int) *gorm.DB {
	tb.Helper()
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=cache_size(-%d)&_pragma=foreign_keys(OFF)&_pragma=wal_autocheckpoint(%d)",
		path, cacheKB, autocheckpt)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		tb.Fatalf("open pragma log db: %v", err)
	}
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

// streamCopyLogDB 流式复制 LogDB（含 -wal/-shm），避免 copyDB 的整份 ReadFile
// 把 GB 级库一次性读进堆内存——本探针要连续复制多档，堆压力会直接扭曲写入速率。
func streamCopyLogDB(tb testing.TB, src, dst string) string {
	tb.Helper()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		in, err := os.Open(src + suffix)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			tb.Fatalf("open %s: %v", src+suffix, err)
		}
		out, err := os.Create(dst + suffix)
		if err != nil {
			in.Close()
			tb.Fatalf("create %s: %v", dst+suffix, err)
		}
		if _, err := io.Copy(out, in); err != nil {
			in.Close()
			out.Close()
			tb.Fatalf("copy %s: %v", src+suffix, err)
		}
		in.Close()
		if err := out.Close(); err != nil {
			tb.Fatalf("close %s: %v", dst+suffix, err)
		}
	}
	return dst
}
