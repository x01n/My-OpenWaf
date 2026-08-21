package observability

import (
	"bytes"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"My-OpenWaf/internal/store"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestDrainChanEmpty(t *testing.T) {
	ch := make(chan int)

	drained := drainChan(ch, 16)

	if drained != nil {
		t.Fatalf("drainChan() = %v, want nil", drained)
	}
}

func TestDrainChanDrainsBelowLimit(t *testing.T) {
	ch := make(chan int, 3)
	for i := 0; i < cap(ch); i++ {
		ch <- i
	}

	drained := drainChan(ch, 16)

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
	limit := 32
	ch := make(chan int, limit+extra)
	for i := 0; i < cap(ch); i++ {
		ch <- i
	}

	drained := drainChan(ch, limit)

	if got := len(drained); got != limit {
		t.Fatalf("len(drainChan()) = %d, want %d", got, limit)
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

func TestUnifiedWriterDropWarningIsRateLimited(t *testing.T) {
	var buf bytes.Buffer
	writer := &UnifiedWriter{
		log:        slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
		eventCh:    make(chan store.SecurityEvent, 1),
		accessCh:   make(chan store.AccessLog, 1),
		dropCh:     make(chan store.DropEvent, 1),
		botScoreCh: make(chan store.BotScoreLog, 1),
	}

	// 第一条填满缓冲区，之后每条都会走 default 分支被丢弃。
	const attempts = 20
	for i := 0; i < attempts; i++ {
		writer.RecordAccessLog(store.AccessLog{})
		writer.RecordEvent(store.SecurityEvent{})
	}

	// 计数必须逐条累加，限流只影响日志，不影响 metrics。
	stats := writer.Stats()
	if want := int64(attempts - 1); stats.AccessLogDropped != want {
		t.Fatalf("AccessLogDropped = %d, want %d", stats.AccessLogDropped, want)
	}
	if want := int64(attempts - 1); stats.SecurityEventDropped != want {
		t.Fatalf("SecurityEventDropped = %d, want %d", stats.SecurityEventDropped, want)
	}

	// 全部丢弃发生在同一个限流窗口内，只应留下一条 WARN。
	if got := strings.Count(buf.String(), "observability queue full"); got != 1 {
		t.Fatalf("drop warnings = %d, want 1\nlog:\n%s", got, buf.String())
	}

	// 窗口过期后应重新允许告警，避免持续背压期间彻底静默。
	buf.Reset()
	writer.lastDropWarnUnixNano.Store(time.Now().Add(-2 * unifiedWriterDropWarnInterval).UnixNano())
	writer.RecordAccessLog(store.AccessLog{})
	if got := strings.Count(buf.String(), "observability queue full"); got != 1 {
		t.Fatalf("drop warnings after window expiry = %d, want 1\nlog:\n%s", got, buf.String())
	}
}

func TestUnifiedWriterDropWarningToleratesNilLogger(t *testing.T) {
	writer := &UnifiedWriter{
		eventCh:    make(chan store.SecurityEvent, 1),
		accessCh:   make(chan store.AccessLog, 1),
		dropCh:     make(chan store.DropEvent, 1),
		botScoreCh: make(chan store.BotScoreLog, 1),
	}

	// 无 logger 的构造路径（测试与嵌入场景）不能因告警而 panic。
	writer.RecordAccessLog(store.AccessLog{})
	writer.RecordAccessLog(store.AccessLog{})

	if got := writer.Stats().AccessLogDropped; got != 1 {
		t.Fatalf("AccessLogDropped = %d, want 1", got)
	}
}

// newLogTestDB 打开一个迁移完毕的临时日志库，供关停与刷新用例复用。
func newLogTestDB(t *testing.T) *gorm.DB {
	t.Helper()

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
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate logs: %v", err)
	}
	return db
}

// TestDrainAllAndFlushPersistsBeyondDrainLimit 守护关停排空不再受单批上限截断。
// 关停不沿用 ticker 路径的稳态上限，且每轮排空上限会按 batchSize 等比放大。
// 这里入队 limit+500 条并断言全部落库。
func TestDrainAllAndFlushPersistsBeyondDrainLimit(t *testing.T) {
	db := newLogTestDB(t)

	const extra = 500
	limit := 256
	total := limit + extra

	writer := &UnifiedWriter{
		db:         db,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		accessCh:   make(chan store.AccessLog, total),
		batchSize:  64,
		drainLimit: limit,
	}
	for i := 0; i < total; i++ {
		writer.accessCh <- store.AccessLog{
			RequestID: "close-drain-" + strconv.Itoa(i),
			Host:      "close.example.test",
			Path:      "/close",
			Method:    "GET",
		}
	}

	writer.drainAllAndFlush(nil, nil, nil, nil)

	var count int64
	if err := db.Model(&store.AccessLog{}).Where("host = ?", "close.example.test").Count(&count).Error; err != nil {
		t.Fatalf("count access logs: %v", err)
	}
	if count != int64(total) {
		t.Fatalf("access logs persisted on close = %d, want %d", count, total)
	}
	if got := len(writer.accessCh); got != 0 {
		t.Fatalf("len(accessCh) after close drain = %d, want 0", got)
	}
	if got := writer.Stats().AccessLogDropped; got != 0 {
		t.Fatalf("AccessLogDropped after successful close drain = %d, want 0", got)
	}
}

// TestRecordAfterCloseCountsAsDropped 守护关停闸门：排空开始后入队的记录不再有
// 消费者，必须计入丢弃计数器而不是留在缓冲区里静默消失。
func TestRecordAfterCloseCountsAsDropped(t *testing.T) {
	writer := &UnifiedWriter{
		eventCh:    make(chan store.SecurityEvent, 8),
		accessCh:   make(chan store.AccessLog, 8),
		dropCh:     make(chan store.DropEvent, 8),
		botScoreCh: make(chan store.BotScoreLog, 8),
	}
	writer.closed.Store(true)

	writer.RecordEvent(store.SecurityEvent{})
	writer.RecordAccessLog(store.AccessLog{})
	writer.RecordDropEvent(store.DropEvent{})
	writer.RecordBotScore(store.BotScoreLog{})

	stats := writer.Stats()
	if stats.SecurityEventDropped != 1 || stats.AccessLogDropped != 1 ||
		stats.DropEventDropped != 1 || stats.BotScoreDropped != 1 {
		t.Fatalf("dropped counters = %+v, want 1 for each type", stats)
	}
	if stats.SecurityEventQueueLen != 0 || stats.AccessLogQueueLen != 0 ||
		stats.DropEventQueueLen != 0 || stats.BotScoreQueueLen != 0 {
		t.Fatalf("queue lengths after close = %+v, want 0 for each type", stats)
	}
}

// TestAbandonRemainingCountsEveryType 守护预算耗尽路径：放弃的记录必须出现在
// 丢弃计数器上，否则运维在 /metrics 上看不到关停期的损失量。
func TestAbandonRemainingCountsEveryType(t *testing.T) {
	writer := &UnifiedWriter{
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		eventCh:    make(chan store.SecurityEvent, 4),
		accessCh:   make(chan store.AccessLog, 4),
		dropCh:     make(chan store.DropEvent, 4),
		botScoreCh: make(chan store.BotScoreLog, 4),
	}
	for i := 0; i < 3; i++ {
		writer.eventCh <- store.SecurityEvent{}
		writer.accessCh <- store.AccessLog{}
		writer.dropCh <- store.DropEvent{}
		writer.botScoreCh <- store.BotScoreLog{}
	}

	writer.abandonRemaining()

	stats := writer.Stats()
	if stats.SecurityEventDropped != 3 || stats.AccessLogDropped != 3 ||
		stats.DropEventDropped != 3 || stats.BotScoreDropped != 3 {
		t.Fatalf("dropped counters = %+v, want 3 for each type", stats)
	}
	if stats.SecurityEventQueueLen != 0 || stats.AccessLogQueueLen != 0 ||
		stats.DropEventQueueLen != 0 || stats.BotScoreQueueLen != 0 {
		t.Fatalf("queue lengths after abandon = %+v, want 0 for each type", stats)
	}
}

// TestUnifiedWriterCloseIsIdempotent 守护重复关停不会 close 已关闭的 channel。
// server.go 用 defer 关停，测试脚手架也常在 Cleanup 里再关一次。
func TestUnifiedWriterCloseIsIdempotent(t *testing.T) {
	db := newLogTestDB(t)

	writer := NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	writer.flushInterval = time.Hour
	writer.RecordAccessLog(store.AccessLog{
		RequestID: "idempotent-close",
		Host:      "idempotent.example.test",
		Path:      "/x",
		Method:    "GET",
	})

	writer.Close()
	writer.Close()

	var count int64
	if err := db.Model(&store.AccessLog{}).Where("request_id = ?", "idempotent-close").Count(&count).Error; err != nil {
		t.Fatalf("count access logs: %v", err)
	}
	if count != 1 {
		t.Fatalf("access logs persisted on close = %d, want 1", count)
	}
}

func TestUnifiedWriterFlushIsolatesFailingRecordType(t *testing.T) {
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
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate logs: %v", err)
	}

	// 让 drop_events 一类必然写失败：表不存在。这模拟任意一类记录因约束冲突或
	// 结构漂移而失败的情形，断言其余三类仍然落库（SAVEPOINT 隔离的核心保证）。
	if err := db.Migrator().DropTable(&store.DropEvent{}); err != nil {
		t.Fatalf("drop drop_events table: %v", err)
	}

	writer := &UnifiedWriter{
		db:         db,
		log:        slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
		batchSize:  512,
		drainLimit: 2048,
	}

	writer.flushBuffered(
		[]store.SecurityEvent{{RequestID: "iso-evt", Host: "iso.example.test"}},
		[]store.AccessLog{{RequestID: "iso-log", Host: "iso.example.test", Path: "/iso", Method: "GET"}},
		[]store.DropEvent{{ClientIP: "203.0.113.7"}},
		[]store.BotScoreLog{{RequestID: "iso-bot", ClientIP: "203.0.113.8"}},
	)

	var events, logs, bots int64
	if err := db.Model(&store.SecurityEvent{}).Where("request_id = ?", "iso-evt").Count(&events).Error; err != nil {
		t.Fatalf("count security events: %v", err)
	}
	if err := db.Model(&store.AccessLog{}).Where("request_id = ?", "iso-log").Count(&logs).Error; err != nil {
		t.Fatalf("count access logs: %v", err)
	}
	if err := db.Model(&store.BotScoreLog{}).Where("request_id = ?", "iso-bot").Count(&bots).Error; err != nil {
		t.Fatalf("count bot scores: %v", err)
	}

	if events != 1 {
		t.Fatalf("security events persisted = %d, want 1 (failing drop_events must not roll back other types)", events)
	}
	if logs != 1 {
		t.Fatalf("access logs persisted = %d, want 1", logs)
	}
	if bots != 1 {
		t.Fatalf("bot scores persisted = %d, want 1 (types after the failing one must still be written)", bots)
	}

	// 失败必须计入 flush_errors_total，不能被 SAVEPOINT 静默吞掉。
	if got := writer.Stats().FlushErrorsTotal; got != 1 {
		t.Fatalf("FlushErrorsTotal = %d, want 1", got)
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

	batchSize := writer.batchSize
	for i := 0; i < batchSize; i++ {
		writer.RecordAccessLog(store.AccessLog{
			RequestID: "batch-full-" + strconv.Itoa(i),
			Host:      "batch.example.test",
			Path:      "/batch",
			Method:    "GET",
		})
	}

	// 截止时间需留足余量：单独运行约 1s（512 条 SQLite 批量写），整包并发跑时
	// 其他用例竞争 CPU 与 SQLite 写锁会成倍拉长，2s 只有 1 倍余量必然偶发失败。
	// 本用例断言的是「批满即刷」这一行为，不是刷新耗时。
	deadline := time.After(20 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var count int64
		if err := db.Model(&store.AccessLog{}).Where("host = ?", "batch.example.test").Count(&count).Error; err != nil {
			t.Fatalf("count access logs: %v", err)
		}
		stats := writer.Stats()
		if count == int64(batchSize) &&
			stats.FlushesTotal > 0 &&
			stats.LastFlushRecords == int64(batchSize) &&
			stats.TotalFlushedRecords >= int64(batchSize) &&
			stats.LastFlushUnixNano > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("access logs flushed after batch full = %d, want %d", count, batchSize)
		case <-ticker.C:
		}
	}
}
