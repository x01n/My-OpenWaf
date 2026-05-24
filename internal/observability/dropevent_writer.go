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
	"My-OpenWaf/internal/store/repository"
)

const redisDropEventListKey = "openwaf:drop_events"

// DropEventWriter accepts drop events on a buffered channel and batch-writes
// them to the database. When Redis is configured, events are also pushed to a
// Redis list for real-time consumption by external consumers.
type DropEventWriter struct {
	repo   *repository.DropEventRepo
	redis  *goredis.Client
	coord  *WriteCoordinator
	ch     chan store.DropEvent
	log    *slog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup

	batchSize     int
	flushInterval time.Duration
	redisTTL      time.Duration
}

// NewDropEventWriter creates a new buffered writer for drop events.
func NewDropEventWriter(repo *repository.DropEventRepo, log *slog.Logger) *DropEventWriter {
	w := &DropEventWriter{
		repo:          repo,
		ch:            make(chan store.DropEvent, 8192),
		log:           log,
		stopCh:        make(chan struct{}),
		batchSize:     256,
		flushInterval: 5 * time.Second,
		redisTTL:      7 * 24 * time.Hour,
	}
	w.wg.Add(1)
	go w.loop()
	return w
}

// SetRedis enables Redis dual-write for drop events.
func (w *DropEventWriter) SetRedis(client *goredis.Client) {
	w.redis = client
}

// SetCoordinator enables serialized DB writes through a shared coordinator.
func (w *DropEventWriter) SetCoordinator(wc *WriteCoordinator) {
	w.coord = wc
}

// Record enqueues a drop event. Non-blocking: drops if buffer full.
func (w *DropEventWriter) Record(ev store.DropEvent) {
	select {
	case w.ch <- ev:
	default:
		w.log.Warn("drop event buffer full, dropping event",
			slog.String("client_ip", ev.ClientIP))
	}
}

// Close flushes remaining events and stops the writer.
func (w *DropEventWriter) Close() {
	close(w.stopCh)
	w.wg.Wait()
}

func (w *DropEventWriter) loop() {
	defer w.wg.Done()
	buf := make([]store.DropEvent, 0, w.batchSize)
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

func (w *DropEventWriter) flush(buf []store.DropEvent) {
	if len(buf) == 0 {
		return
	}
	batch := make([]store.DropEvent, len(buf))
	copy(batch, buf)

	if w.redis != nil {
		w.pushToRedis(batch)
	}

	if w.coord != nil {
		items := batch
		w.coord.Submit(func(tx *gorm.DB) error {
			return tx.CreateInBatches(items, 100).Error
		})
	} else if err := w.repo.BatchCreate(batch); err != nil {
		w.log.Error("failed to write drop events", slog.Any("err", err), slog.Int("count", len(batch)))
	}
}

func (w *DropEventWriter) pushToRedis(batch []store.DropEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pipe := w.redis.Pipeline()
	for _, ev := range batch {
		data, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		pipe.LPush(ctx, redisDropEventListKey, data)
	}
	pipe.LTrim(ctx, redisDropEventListKey, 0, 49999)
	pipe.Expire(ctx, redisDropEventListKey, w.redisTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		w.log.Warn("failed to push drop events to Redis", slog.Any("err", err), slog.Int("count", len(batch)))
	}
}
