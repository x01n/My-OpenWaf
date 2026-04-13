package observability

import (
	"log/slog"
	"sync"
	"time"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// EventWriter accepts security events on a buffered channel and batch-writes
// them to the database. This ensures the data-plane hot path is never blocked
// by a DB write.
type EventWriter struct {
	repo    *repository.SecurityEventRepo
	ch      chan store.SecurityEvent
	log     *slog.Logger
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Tuning knobs.
	batchSize    int
	flushInterval time.Duration
}

func NewEventWriter(repo *repository.SecurityEventRepo, log *slog.Logger) *EventWriter {
	w := &EventWriter{
		repo:          repo,
		ch:            make(chan store.SecurityEvent, 4096),
		log:           log,
		stopCh:        make(chan struct{}),
		batchSize:     64,
		flushInterval: 2 * time.Second,
	}
	w.wg.Add(1)
	go w.loop()
	return w
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
	if err := w.repo.BatchCreate(batch); err != nil {
		w.log.Error("failed to write security events", slog.Any("err", err), slog.Int("count", len(batch)))
	}
}
