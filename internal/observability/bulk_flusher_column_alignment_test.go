package observability

import (
	"io"
	"log/slog"
	"testing"

	"My-OpenWaf/internal/store"
)

// 守护：四张日志表的绑定列清单与行取值函数必须等长，否则长期语句只会在
// 运行期报 "N values for M columns"（sqlite_bulk_flusher 的列清单由
// GORM schema 生成，行取值函数是手写清单，二者必须同步）。
func TestZSpecColumnAlignment(t *testing.T) {
	bf := newSQLiteBulkFlusher(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if bf == nil {
		t.Fatal("flusher is nil")
	}
	rows := map[string]any{
		"access_logs":     &store.AccessLog{},
		"security_events": &store.SecurityEvent{},
		"drop_events":     &store.DropEvent{},
		"bot_score_logs":  &store.BotScoreLog{},
	}
	for table, spec := range bf.specs {
		row, ok := rows[table]
		if !ok {
			t.Fatalf("unexpected table %q", table)
		}
		vals := spec.values(row, fixedTime())
		if len(vals) != len(spec.cols) {
			t.Errorf("%s: values=%d cols=%d", table, len(vals), len(spec.cols))
		}
		t.Logf("%s cols=%d values=%d", table, len(spec.cols), len(vals))
	}
}
