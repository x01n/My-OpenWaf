package observability

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

// UnifiedWriter accepts all types of observability records on dedicated
// channels and flushes them in a single DB transaction on a fixed interval.
// The request hot-path only performs a non-blocking channel send, keeping
// CPU overhead to a minimum. A single goroutine drains all channels and
// writes everything in one transaction — eliminating SQLite lock contention.
type UnifiedWriter struct {
	db    *gorm.DB
	redis atomic.Pointer[goredis.Client]
	log   *slog.Logger

	eventCh    chan store.SecurityEvent
	accessCh   chan store.AccessLog
	dropCh     chan store.DropEvent
	botScoreCh chan store.BotScoreLog

	stopCh chan struct{}
	wg     sync.WaitGroup

	flushInterval time.Duration

	securityEventDropped atomic.Int64
	accessLogDropped     atomic.Int64
	dropEventDropped     atomic.Int64
	botScoreDropped      atomic.Int64

	flushesTotal        atomic.Int64
	flushErrorsTotal    atomic.Int64
	lastFlushUnixNano   atomic.Int64
	lastFlushDurationNs atomic.Int64
	lastFlushRecords    atomic.Int64
	totalFlushedRecords atomic.Int64
}

const (
	unifiedWriterBatchSize  = 512
	unifiedWriterDrainLimit = 2048
)

// UnifiedWriterStats is a point-in-time snapshot of the async observability writer.
type UnifiedWriterStats struct {
	SecurityEventQueueLen int `json:"security_event_queue_len"`
	AccessLogQueueLen     int `json:"access_log_queue_len"`
	DropEventQueueLen     int `json:"drop_event_queue_len"`
	BotScoreQueueLen      int `json:"bot_score_queue_len"`

	SecurityEventDropped int64 `json:"security_event_dropped"`
	AccessLogDropped     int64 `json:"access_log_dropped"`
	DropEventDropped     int64 `json:"drop_event_dropped"`
	BotScoreDropped      int64 `json:"bot_score_dropped"`

	FlushesTotal        int64 `json:"flushes_total"`
	FlushErrorsTotal    int64 `json:"flush_errors_total"`
	LastFlushRecords    int64 `json:"last_flush_records"`
	LastFlushDurationMs int64 `json:"last_flush_duration_ms"`
	LastFlushUnixNano   int64 `json:"last_flush_unix_nano"`
	TotalFlushedRecords int64 `json:"total_flushed_records"`
}

// NewUnifiedWriter creates a unified writer with large channel buffers.
func NewUnifiedWriter(db *gorm.DB, log *slog.Logger) *UnifiedWriter {
	w := &UnifiedWriter{
		db:            db,
		log:           log,
		eventCh:       make(chan store.SecurityEvent, 16384),
		accessCh:      make(chan store.AccessLog, 16384),
		dropCh:        make(chan store.DropEvent, 8192),
		botScoreCh:    make(chan store.BotScoreLog, 8192),
		stopCh:        make(chan struct{}),
		flushInterval: 3 * time.Second,
	}
	w.wg.Add(1)
	go w.loop()
	return w
}

// SetRedis enables Redis dual-write for real-time consumption.
func (w *UnifiedWriter) SetRedis(client *goredis.Client) {
	w.redis.Store(client)
}

// Stats returns queue, drop and flush counters for runtime diagnostics.
func (w *UnifiedWriter) Stats() UnifiedWriterStats {
	return UnifiedWriterStats{
		SecurityEventQueueLen: len(w.eventCh),
		AccessLogQueueLen:     len(w.accessCh),
		DropEventQueueLen:     len(w.dropCh),
		BotScoreQueueLen:      len(w.botScoreCh),

		SecurityEventDropped: w.securityEventDropped.Load(),
		AccessLogDropped:     w.accessLogDropped.Load(),
		DropEventDropped:     w.dropEventDropped.Load(),
		BotScoreDropped:      w.botScoreDropped.Load(),

		FlushesTotal:        w.flushesTotal.Load(),
		FlushErrorsTotal:    w.flushErrorsTotal.Load(),
		LastFlushRecords:    w.lastFlushRecords.Load(),
		LastFlushDurationMs: w.lastFlushDurationNs.Load() / int64(time.Millisecond),
		LastFlushUnixNano:   w.lastFlushUnixNano.Load(),
		TotalFlushedRecords: w.totalFlushedRecords.Load(),
	}
}

// RecordEvent enqueues a security event. Non-blocking.
func (w *UnifiedWriter) RecordEvent(ev store.SecurityEvent) {
	select {
	case w.eventCh <- ev:
	default:
		w.securityEventDropped.Add(1)
	}
}

// RecordAccessLog enqueues an access log. Non-blocking.
func (w *UnifiedWriter) RecordAccessLog(al store.AccessLog) {
	select {
	case w.accessCh <- al:
	default:
		w.accessLogDropped.Add(1)
	}
}

// RecordDropEvent enqueues a drop event. Non-blocking.
func (w *UnifiedWriter) RecordDropEvent(ev store.DropEvent) {
	select {
	case w.dropCh <- ev:
	default:
		w.dropEventDropped.Add(1)
	}
}

// RecordBotScore enqueues a bot score log. Non-blocking.
func (w *UnifiedWriter) RecordBotScore(bs store.BotScoreLog) {
	select {
	case w.botScoreCh <- bs:
	default:
		w.botScoreDropped.Add(1)
	}
}

// Close drains remaining records and stops the writer.
func (w *UnifiedWriter) Close() {
	close(w.stopCh)
	w.wg.Wait()
}

func (w *UnifiedWriter) loop() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	events := make([]store.SecurityEvent, 0, unifiedWriterBatchSize)
	accessLogs := make([]store.AccessLog, 0, unifiedWriterBatchSize)
	dropEvents := make([]store.DropEvent, 0, unifiedWriterBatchSize)
	botScores := make([]store.BotScoreLog, 0, unifiedWriterBatchSize)

	flush := func() {
		w.flushBuffered(events, accessLogs, dropEvents, botScores)
		events = events[:0]
		accessLogs = accessLogs[:0]
		dropEvents = dropEvents[:0]
		botScores = botScores[:0]
	}

	for {
		select {
		case ev := <-w.eventCh:
			events = append(events, ev)
			if unifiedWriterShouldFlush(len(events), len(accessLogs), len(dropEvents), len(botScores)) {
				flush()
			}
		case al := <-w.accessCh:
			accessLogs = append(accessLogs, al)
			if unifiedWriterShouldFlush(len(events), len(accessLogs), len(dropEvents), len(botScores)) {
				flush()
			}
		case ev := <-w.dropCh:
			dropEvents = append(dropEvents, ev)
			if unifiedWriterShouldFlush(len(events), len(accessLogs), len(dropEvents), len(botScores)) {
				flush()
			}
		case bs := <-w.botScoreCh:
			botScores = append(botScores, bs)
			if unifiedWriterShouldFlush(len(events), len(accessLogs), len(dropEvents), len(botScores)) {
				flush()
			}
		case <-ticker.C:
			events = drainChanInto(w.eventCh, events)
			accessLogs = drainChanInto(w.accessCh, accessLogs)
			dropEvents = drainChanInto(w.dropCh, dropEvents)
			botScores = drainChanInto(w.botScoreCh, botScores)
			flush()
		case <-w.stopCh:
			events = drainChanInto(w.eventCh, events)
			accessLogs = drainChanInto(w.accessCh, accessLogs)
			dropEvents = drainChanInto(w.dropCh, dropEvents)
			botScores = drainChanInto(w.botScoreCh, botScores)
			flush()
			return
		}
	}
}

func unifiedWriterShouldFlush(events, accessLogs, dropEvents, botScores int) bool {
	total := events + accessLogs + dropEvents + botScores
	return total >= unifiedWriterBatchSize ||
		events >= unifiedWriterBatchSize ||
		accessLogs >= unifiedWriterBatchSize ||
		dropEvents >= unifiedWriterBatchSize ||
		botScores >= unifiedWriterBatchSize
}

func (w *UnifiedWriter) flushBuffered(
	events []store.SecurityEvent,
	accessLogs []store.AccessLog,
	dropEvents []store.DropEvent,
	botScores []store.BotScoreLog,
) {
	records := len(events) + len(accessLogs) + len(dropEvents) + len(botScores)
	if records == 0 {
		return
	}

	start := time.Now()
	failed := false
	defer func() {
		w.recordFlushStats(records, time.Since(start), failed)
	}()

	// Push to Redis first (low-latency path for real-time consumers).
	if rc := w.redis.Load(); rc != nil {
		if err := w.pushToRedis(rc, events, accessLogs, dropEvents, botScores); err != nil {
			failed = true
		}
	}

	// Single DB transaction for all types.
	err := w.db.Transaction(func(tx *gorm.DB) error {
		if len(events) > 0 {
			if e := tx.CreateInBatches(events, unifiedWriterBatchSize).Error; e != nil {
				failed = true
				w.log.Error("flush security events failed", slog.Any("err", e), slog.Int("n", len(events)))
			}
		}
		if len(accessLogs) > 0 {
			if e := tx.CreateInBatches(accessLogs, unifiedWriterBatchSize).Error; e != nil {
				failed = true
				w.log.Error("flush access logs failed", slog.Any("err", e), slog.Int("n", len(accessLogs)))
			}
		}
		if len(dropEvents) > 0 {
			if e := tx.CreateInBatches(dropEvents, unifiedWriterBatchSize).Error; e != nil {
				failed = true
				w.log.Error("flush drop events failed", slog.Any("err", e), slog.Int("n", len(dropEvents)))
			}
		}
		if len(botScores) > 0 {
			if e := tx.CreateInBatches(botScores, unifiedWriterBatchSize).Error; e != nil {
				failed = true
				w.log.Error("flush bot scores failed", slog.Any("err", e), slog.Int("n", len(botScores)))
			}
		}
		return nil
	})
	if err != nil {
		failed = true
		w.log.Error("unified flush transaction failed", slog.Any("err", err))
	}
}

func (w *UnifiedWriter) recordFlushStats(records int, duration time.Duration, failed bool) {
	w.flushesTotal.Add(1)
	w.totalFlushedRecords.Add(int64(records))
	w.lastFlushRecords.Store(int64(records))
	w.lastFlushDurationNs.Store(duration.Nanoseconds())
	w.lastFlushUnixNano.Store(time.Now().UnixNano())
	if failed {
		w.flushErrorsTotal.Add(1)
	}
}

func (w *UnifiedWriter) pushToRedis(
	rc *goredis.Client,
	events []store.SecurityEvent,
	accessLogs []store.AccessLog,
	dropEvents []store.DropEvent,
	botScores []store.BotScoreLog,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pipe := rc.Pipeline()
	ttl := 7 * 24 * time.Hour

	pushJSON := func(key string, items []any, trim int64) {
		for _, item := range items {
			data, err := json.Marshal(item)
			if err != nil {
				continue
			}
			pipe.LPush(ctx, key, data)
		}
		pipe.LTrim(ctx, key, 0, trim)
		pipe.Expire(ctx, key, ttl)
	}

	if len(events) > 0 {
		items := make([]any, len(events))
		for i := range events {
			items[i] = events[i]
		}
		pushJSON("openwaf:security_events", items, 99999)
	}
	if len(accessLogs) > 0 {
		items := make([]any, len(accessLogs))
		for i := range accessLogs {
			items[i] = accessLogs[i]
		}
		pushJSON("openwaf:access_logs", items, 99999)
	}
	if len(dropEvents) > 0 {
		items := make([]any, len(dropEvents))
		for i := range dropEvents {
			items[i] = dropEvents[i]
		}
		pushJSON("openwaf:drop_events", items, 49999)
	}
	if len(botScores) > 0 {
		items := make([]any, len(botScores))
		for i := range botScores {
			items[i] = botScores[i]
		}
		pushJSON("openwaf:bot_scores", items, 49999)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		w.log.Warn("redis push failed", slog.Any("err", err))
		return err
	}
	return nil
}

// drainChan drains a channel into a slice without blocking.
func drainChan[T any](ch chan T) []T {
	n := len(ch)
	if n == 0 {
		return nil
	}
	if n > unifiedWriterDrainLimit {
		n = unifiedWriterDrainLimit
	}
	buf := make([]T, 0, n)
	for i := 0; i < n; i++ {
		select {
		case v := <-ch:
			buf = append(buf, v)
		default:
			return buf
		}
	}
	return buf
}

func drainChanInto[T any](ch chan T, buf []T) []T {
	for len(buf) < unifiedWriterDrainLimit {
		select {
		case v := <-ch:
			buf = append(buf, v)
		default:
			return buf
		}
	}
	return buf
}
