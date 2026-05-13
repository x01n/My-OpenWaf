package observability

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	goredis "github.com/redis/go-redis/v9"
)

const redisAccessLogListKey = "openwaf:access_logs"

type AccessLogWriter struct {
	repo          *repository.AccessLogRepo
	redis         *goredis.Client
	ch            chan store.AccessLog
	log           *slog.Logger
	stopCh        chan struct{}
	wg            sync.WaitGroup
	batchSize     int
	flushInterval time.Duration
}

func NewAccessLogWriter(repo *repository.AccessLogRepo, log *slog.Logger) *AccessLogWriter {
	w := &AccessLogWriter{
		repo:          repo,
		ch:            make(chan store.AccessLog, 4096),
		log:           log,
		stopCh:        make(chan struct{}),
		batchSize:     64,
		flushInterval: 2 * time.Second,
	}
	w.wg.Add(1)
	go w.loop()
	return w
}

func (w *AccessLogWriter) SetRedis(client *goredis.Client) {
	w.redis = client
}

func (w *AccessLogWriter) Record(item store.AccessLog) {
	select {
	case w.ch <- item:
	default:
		w.log.Warn("access log buffer full, dropping record", slog.String("request_id", item.RequestID))
	}
}

func (w *AccessLogWriter) Close() {
	close(w.stopCh)
	w.wg.Wait()
}

func (w *AccessLogWriter) loop() {
	defer w.wg.Done()
	buf := make([]store.AccessLog, 0, w.batchSize)
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case item := <-w.ch:
			buf = append(buf, item)
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
				case item := <-w.ch:
					buf = append(buf, item)
				default:
					w.flush(buf)
					return
				}
			}
		}
	}
}

func (w *AccessLogWriter) flush(buf []store.AccessLog) {
	if len(buf) == 0 {
		return
	}
	batch := make([]store.AccessLog, len(buf))
	copy(batch, buf)
	if w.redis != nil {
		w.pushToRedis(batch)
	}
	if err := w.repo.BatchCreate(batch); err != nil {
		w.log.Error("failed to write access logs", slog.Any("err", err), slog.Int("count", len(batch)))
	}
}

func (w *AccessLogWriter) pushToRedis(batch []store.AccessLog) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pipe := w.redis.Pipeline()
	for _, item := range batch {
		data, err := json.Marshal(item)
		if err != nil {
			continue
		}
		pipe.LPush(ctx, redisAccessLogListKey, data)
	}
	pipe.LTrim(ctx, redisAccessLogListKey, 0, 99999)
	pipe.Expire(ctx, redisAccessLogListKey, 7*24*time.Hour)

	if _, err := pipe.Exec(ctx); err != nil {
		w.log.Warn("failed to push access logs to Redis", slog.Any("err", err), slog.Int("count", len(batch)))
	}
}
