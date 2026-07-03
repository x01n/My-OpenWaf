package observability

import (
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestDrainChanEmpty(t *testing.T) {
	ch := make(chan int)

	drained := drainChan(ch)

	if drained != nil {
		t.Fatalf("drainChan() = %v, want nil", drained)
	}
}

func TestDrainChanDrainsBelowLimit(t *testing.T) {
	ch := make(chan int, 3)
	for i := 0; i < cap(ch); i++ {
		ch <- i
	}

	drained := drainChan(ch)

	if got := len(drained); got != 3 {
		t.Fatalf("len(drainChan()) = %d, want 3", got)
	}
	if got := len(ch); got != 0 {
		t.Fatalf("len(ch) after drainChan() = %d, want 0", got)
	}
	for i, v := range drained {
		if v != i {
			t.Fatalf("drained[%d] = %d, want %d", i, v, i)
		}
	}
}

func TestDrainChanRespectsDrainLimit(t *testing.T) {
	extra := 10
	ch := make(chan int, unifiedWriterDrainLimit+extra)
	for i := 0; i < cap(ch); i++ {
		ch <- i
	}

	drained := drainChan(ch)

	if got := len(drained); got != unifiedWriterDrainLimit {
		t.Fatalf("len(drainChan()) = %d, want %d", got, unifiedWriterDrainLimit)
	}
	if got := len(ch); got != extra {
		t.Fatalf("len(ch) after drainChan() = %d, want %d", got, extra)
	}
	for i, v := range drained {
		if v != i {
			t.Fatalf("drained[%d] = %d, want %d", i, v, i)
		}
	}
}

func TestUnifiedWriterStatsTracksQueueLengthsAndDrops(t *testing.T) {
	writer := &UnifiedWriter{
		eventCh:    make(chan store.SecurityEvent, 1),
		accessCh:   make(chan store.AccessLog, 1),
		dropCh:     make(chan store.DropEvent, 1),
		botScoreCh: make(chan store.BotScoreLog, 1),
	}

	writer.RecordEvent(store.SecurityEvent{})
	writer.RecordEvent(store.SecurityEvent{})
	writer.RecordAccessLog(store.AccessLog{})
	writer.RecordAccessLog(store.AccessLog{})
	writer.RecordDropEvent(store.DropEvent{})
	writer.RecordDropEvent(store.DropEvent{})
	writer.RecordBotScore(store.BotScoreLog{})
	writer.RecordBotScore(store.BotScoreLog{})

	stats := writer.Stats()
	if stats.SecurityEventQueueLen != 1 {
		t.Fatalf("SecurityEventQueueLen = %d, want 1", stats.SecurityEventQueueLen)
	}
	if stats.AccessLogQueueLen != 1 {
		t.Fatalf("AccessLogQueueLen = %d, want 1", stats.AccessLogQueueLen)
	}
	if stats.DropEventQueueLen != 1 {
		t.Fatalf("DropEventQueueLen = %d, want 1", stats.DropEventQueueLen)
	}
	if stats.BotScoreQueueLen != 1 {
		t.Fatalf("BotScoreQueueLen = %d, want 1", stats.BotScoreQueueLen)
	}
	if stats.SecurityEventDropped != 1 {
		t.Fatalf("SecurityEventDropped = %d, want 1", stats.SecurityEventDropped)
	}
	if stats.AccessLogDropped != 1 {
		t.Fatalf("AccessLogDropped = %d, want 1", stats.AccessLogDropped)
	}
	if stats.DropEventDropped != 1 {
		t.Fatalf("DropEventDropped = %d, want 1", stats.DropEventDropped)
	}
	if stats.BotScoreDropped != 1 {
		t.Fatalf("BotScoreDropped = %d, want 1", stats.BotScoreDropped)
	}
}

func TestUnifiedWriterFlushesAccessLogsWhenBatchIsFull(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "logs.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sqlite db: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate logs: %v", err)
	}

	writer := NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	writer.flushInterval = time.Hour
	t.Cleanup(func() {
		writer.Close()
		_ = sqlDB.Close()
	})

	for i := 0; i < unifiedWriterBatchSize; i++ {
		writer.RecordAccessLog(store.AccessLog{
			RequestID: "batch-full-" + strconv.Itoa(i),
			Host:      "batch.example.test",
			Path:      "/batch",
			Method:    "GET",
		})
	}

	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var count int64
		if err := db.Model(&store.AccessLog{}).Where("host = ?", "batch.example.test").Count(&count).Error; err != nil {
			t.Fatalf("count access logs: %v", err)
		}
		stats := writer.Stats()
		if count == unifiedWriterBatchSize &&
			stats.FlushesTotal > 0 &&
			stats.LastFlushRecords == unifiedWriterBatchSize &&
			stats.TotalFlushedRecords >= unifiedWriterBatchSize &&
			stats.LastFlushUnixNano > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("access logs flushed after batch full = %d, want %d", count, unifiedWriterBatchSize)
		case <-ticker.C:
		}
	}
}
