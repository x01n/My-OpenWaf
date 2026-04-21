package observability

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

const redisEventListKey = "openwaf:security_events"

// EventWriter accepts security events on a buffered channel and batch-writes
// them to the database. When Redis is configured, events are also pushed to a
// Redis list for real-time consumption by external consumers (SIEM, dashboards).
// This ensures the data-plane hot path is never blocked by a DB write.
type EventWriter struct {
	repo    *repository.SecurityEventRepo
	redis   *goredis.Client
	ch      chan store.SecurityEvent
	log     *slog.Logger
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Tuning knobs.
	batchSize     int
	flushInterval time.Duration
	redisTTL      time.Duration // TTL for the Redis event list key
}

func NewEventWriter(repo *repository.SecurityEventRepo, log *slog.Logger) *EventWriter {
	w := &EventWriter{
		repo:          repo,
		ch:            make(chan store.SecurityEvent, 4096),
		log:           log,
		stopCh:        make(chan struct{}),
		batchSize:     64,
		flushInterval: 2 * time.Second,
		redisTTL:      7 * 24 * time.Hour, // keep Redis events for 7 days
	}
	w.wg.Add(1)
	go w.loop()
	return w
}

// SetRedis enables Redis dual-write. Events are pushed to a Redis list
// in addition to the database. Safe to call before or after construction.
func (w *EventWriter) SetRedis(client *goredis.Client) {
	w.redis = client
}

// Record enqueues an event. Non-blocking: drops if buffer full.
func (w *EventWriter) Record(ev store.SecurityEvent) {
	select {
	case w.ch <- ev:
	default:
		w.log.Warn("security event buffer full, dropping event",
			slog.String("request_id", ev.RequestID))
	}
}

// Close flushes remaining events and stops the writer.
func (w *EventWriter) Close() {
	close(w.stopCh)
	w.wg.Wait()
}

func (w *EventWriter) loop() {
	defer w.wg.Done()
	buf := make([]store.SecurityEvent, 0, w.batchSize)
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-w.ch:
			if !ok {
				w.flush(buf)
				return
			}
			buf = append(buf, ev)
			if len(buf) >= w.batchSize {
				w.flush(buf)
				buf = buf[:0]
			}
		case <-ticker.C:
			if len(buf) > 0 {
				w.flush(buf)
				buf = buf[:0]
			}
		case <-w.stopCh:
			// Drain remaining channel items.
			for {
				select {
				case ev := <-w.ch:
					buf = append(buf, ev)
				default:
					w.flush(buf)
					return
				}
			}
		}
	}
}

func (w *EventWriter) flush(buf []store.SecurityEvent) {
	if len(buf) == 0 {
		return
	}
	batch := make([]store.SecurityEvent, len(buf))
	copy(batch, buf)

	// Write to Redis first (low-latency path for real-time consumers).
	if w.redis != nil {
		w.pushToRedis(batch)
	}

	// Write to database (durable storage).
	if err := w.repo.BatchCreate(batch); err != nil {
		w.log.Error("failed to write security events", slog.Any("err", err), slog.Int("count", len(batch)))
	}
}

// pushToRedis pushes a batch of events to a Redis list using a pipeline.
// Events are serialized as JSON. The list key gets a TTL to prevent unbounded growth.
func (w *EventWriter) pushToRedis(batch []store.SecurityEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pipe := w.redis.Pipeline()
	for _, ev := range batch {
		data, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		pipe.LPush(ctx, redisEventListKey, data)
	}
	// Cap the list to prevent unbounded memory usage (keep last 100k events).
	pipe.LTrim(ctx, redisEventListKey, 0, 99999)
	// Refresh TTL so the key doesn't linger after WAF shutdown.
	pipe.Expire(ctx, redisEventListKey, w.redisTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		w.log.Warn("failed to push events to Redis", slog.Any("err", err), slog.Int("count", len(batch)))
	}
}
