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

const redisBotScoreListKey = "openwaf:bot_scores"

// BotScoreWriter accepts bot score logs on a buffered channel and batch-writes
// them to the database. When Redis is configured, scores are also pushed to a
// Redis list for real-time consumption by external consumers.
type BotScoreWriter struct {
	repo   *repository.BotScoreRepo
	redis  *goredis.Client
	coord  *WriteCoordinator
	ch     chan store.BotScoreLog
	log    *slog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup

	batchSize     int
	flushInterval time.Duration
	redisTTL      time.Duration
}

// NewBotScoreWriter creates a new buffered writer for bot score logs.
func NewBotScoreWriter(repo *repository.BotScoreRepo, log *slog.Logger) *BotScoreWriter {
	w := &BotScoreWriter{
		repo:          repo,
		ch:            make(chan store.BotScoreLog, 8192),
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

// SetRedis enables Redis dual-write for bot score logs.
func (w *BotScoreWriter) SetRedis(client *goredis.Client) {
	w.redis = client
}

// SetCoordinator enables serialized DB writes through a shared coordinator.
func (w *BotScoreWriter) SetCoordinator(wc *WriteCoordinator) {
	w.coord = wc
}

// Record enqueues a bot score log. Non-blocking: drops if buffer full.
func (w *BotScoreWriter) Record(ev store.BotScoreLog) {
	select {
	case w.ch <- ev:
	default:
		w.log.Warn("bot score buffer full, dropping record",
			slog.String("client_ip", ev.ClientIP))
	}
}

// Close flushes remaining records and stops the writer.
func (w *BotScoreWriter) Close() {
	close(w.stopCh)
	w.wg.Wait()
}

func (w *BotScoreWriter) loop() {
	defer w.wg.Done()
	buf := make([]store.BotScoreLog, 0, w.batchSize)
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

func (w *BotScoreWriter) flush(buf []store.BotScoreLog) {
	if len(buf) == 0 {
		return
	}
	batch := make([]store.BotScoreLog, len(buf))
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
		w.log.Error("failed to write bot scores", slog.Any("err", err), slog.Int("count", len(batch)))
	}
}

func (w *BotScoreWriter) pushToRedis(batch []store.BotScoreLog) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pipe := w.redis.Pipeline()
	for _, ev := range batch {
		data, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		pipe.LPush(ctx, redisBotScoreListKey, data)
	}
	pipe.LTrim(ctx, redisBotScoreListKey, 0, 49999)
	pipe.Expire(ctx, redisBotScoreListKey, w.redisTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		w.log.Warn("failed to push bot scores to Redis", slog.Any("err", err), slog.Int("count", len(batch)))
	}
}
