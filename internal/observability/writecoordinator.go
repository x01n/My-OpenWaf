package observability

import (
	"log/slog"
	"sync"
	"time"

	"gorm.io/gorm"
)

// WriteCoordinator serializes all DB writes through a single goroutine to
// avoid SQLite lock contention when multiple writers flush concurrently.
// Each writer submits a flush function; the coordinator executes them
// sequentially, optionally batching multiple pending flushes into one
// DB transaction.
type WriteCoordinator struct {
	db     *gorm.DB
	ch     chan writeJob
	log    *slog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup
}

type writeJob struct {
	fn func(tx *gorm.DB) error
}

// NewWriteCoordinator creates a coordinator that serializes DB writes.
func NewWriteCoordinator(db *gorm.DB, log *slog.Logger) *WriteCoordinator {
	wc := &WriteCoordinator{
		db:     db,
		ch:     make(chan writeJob, 64),
		log:    log,
		stopCh: make(chan struct{}),
	}
	wc.wg.Add(1)
	go wc.loop()
	return wc
}

// Submit enqueues a write function. The function receives a *gorm.DB (possibly
// inside a transaction) and should perform its batch insert. Non-blocking:
// drops if the coordinator queue is full.
func (wc *WriteCoordinator) Submit(fn func(tx *gorm.DB) error) {
	select {
	case wc.ch <- writeJob{fn: fn}:
	default:
		wc.log.Warn("write coordinator queue full, dropping flush")
	}
}

// Close stops the coordinator after draining pending writes.
func (wc *WriteCoordinator) Close() {
	close(wc.stopCh)
	wc.wg.Wait()
}

func (wc *WriteCoordinator) loop() {
	defer wc.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	pending := make([]writeJob, 0, 16)

	for {
		select {
		case job := <-wc.ch:
			pending = append(pending, job)
			// Drain any additional pending jobs without blocking.
			for len(pending) < cap(pending) {
				select {
				case j := <-wc.ch:
					pending = append(pending, j)
				default:
					goto flush
				}
			}
		flush:
			wc.execBatch(pending)
			pending = pending[:0]

		case <-ticker.C:
			// Drain any pending jobs that accumulated.
			for {
				select {
				case j := <-wc.ch:
					pending = append(pending, j)
				default:
					goto flushTick
				}
			}
		flushTick:
			if len(pending) > 0 {
				wc.execBatch(pending)
				pending = pending[:0]
			}

		case <-wc.stopCh:
			for {
				select {
				case j := <-wc.ch:
					pending = append(pending, j)
				default:
					wc.execBatch(pending)
					return
				}
			}
		}
	}
}

// execBatch runs all pending write jobs inside a single DB transaction.
func (wc *WriteCoordinator) execBatch(jobs []writeJob) {
	if len(jobs) == 0 {
		return
	}
	err := wc.db.Transaction(func(tx *gorm.DB) error {
		for _, j := range jobs {
			if err := j.fn(tx); err != nil {
				wc.log.Error("write job failed inside transaction", slog.Any("err", err))
				// Continue with remaining jobs; don't abort entire batch.
			}
		}
		return nil
	})
	if err != nil {
		wc.log.Error("write coordinator transaction failed", slog.Any("err", err), slog.Int("jobs", len(jobs)))
	}
}
