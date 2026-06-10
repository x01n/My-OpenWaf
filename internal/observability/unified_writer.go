package observability

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
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
	redis *goredis.Client
	log   *slog.Logger

	eventCh    chan store.SecurityEvent
	accessCh   chan store.AccessLog
	dropCh     chan store.DropEvent
	botScoreCh chan store.BotScoreLog

	stopCh chan struct{}
	wg     sync.WaitGroup

	flushInterval time.Duration
}

const (
	unifiedWriterBatchSize  = 512
	unifiedWriterDrainLimit = 2048
)

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
	w.redis = client
}

// RecordEvent enqueues a security event. Non-blocking.
func (w *UnifiedWriter) RecordEvent(ev store.SecurityEvent) {
	select {
	case w.eventCh <- ev:
	default:
	}
}

// RecordAccessLog enqueues an access log. Non-blocking.
func (w *UnifiedWriter) RecordAccessLog(al store.AccessLog) {
	select {
	case w.accessCh <- al:
	default:
	}
}

// RecordDropEvent enqueues a drop event. Non-blocking.
func (w *UnifiedWriter) RecordDropEvent(ev store.DropEvent) {
	select {
	case w.dropCh <- ev:
	default:
	}
}

// RecordBotScore enqueues a bot score log. Non-blocking.
func (w *UnifiedWriter) RecordBotScore(bs store.BotScoreLog) {
	select {
	case w.botScoreCh <- bs:
	default:
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

	for {
		select {
		case <-ticker.C:
			w.drainAndFlush()
		case <-w.stopCh:
			w.drainAndFlush()
			return
		}
	}
}

func (w *UnifiedWriter) drainAndFlush() {
	events := drainChan(w.eventCh)
	accessLogs := drainChan(w.accessCh)
	dropEvents := drainChan(w.dropCh)
	botScores := drainChan(w.botScoreCh)

	if len(events) == 0 && len(accessLogs) == 0 && len(dropEvents) == 0 && len(botScores) == 0 {
		return
	}

	// Push to Redis first (low-latency path for real-time consumers).
	if w.redis != nil {
		w.pushAllToRedis(events, accessLogs, dropEvents, botScores)
	}

	// Single DB transaction for all types.
	err := w.db.Transaction(func(tx *gorm.DB) error {
		if len(events) > 0 {
			if e := tx.CreateInBatches(events, unifiedWriterBatchSize).Error; e != nil {
				w.log.Error("flush security events failed", slog.Any("err", e), slog.Int("n", len(events)))
			}
		}
		if len(accessLogs) > 0 {
			if e := tx.CreateInBatches(accessLogs, unifiedWriterBatchSize).Error; e != nil {
				w.log.Error("flush access logs failed", slog.Any("err", e), slog.Int("n", len(accessLogs)))
			}
		}
		if len(dropEvents) > 0 {
			if e := tx.CreateInBatches(dropEvents, unifiedWriterBatchSize).Error; e != nil {
				w.log.Error("flush drop events failed", slog.Any("err", e), slog.Int("n", len(dropEvents)))
			}
		}
		if len(botScores) > 0 {
			if e := tx.CreateInBatches(botScores, unifiedWriterBatchSize).Error; e != nil {
				w.log.Error("flush bot scores failed", slog.Any("err", e), slog.Int("n", len(botScores)))
			}
		}
		return nil
	})
	if err != nil {
		w.log.Error("unified flush transaction failed", slog.Any("err", err))
	}
}

func (w *UnifiedWriter) pushAllToRedis(
	events []store.SecurityEvent,
	accessLogs []store.AccessLog,
	dropEvents []store.DropEvent,
	botScores []store.BotScoreLog,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pipe := w.redis.Pipeline()
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
	}
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
