package observability

import (
	"log/slog"
	"sync"
	"time"

	"gorm.io/gorm"
)

// WriteQueue is a generic async write queue for all database write operations.
// It accepts write functions, merges high-frequency operations when possible,
// and executes them in batch through a single goroutine to minimize DB lock contention.
//
// Key features:
//   - Non-blocking submission: callers never block on DB writes.
//   - Coalescing: multiple pending writes execute in a single transaction.
//   - Priority support: urgent writes (e.g., auth changes) bypass the batch timer.
//   - Graceful shutdown: all pending writes are flushed before Close returns.
type WriteQueue struct {
	db     *gorm.DB
	ch     chan writeQueueJob
	log    *slog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup

	// Tuning.
	batchInterval time.Duration
	maxBatchSize  int
}

type writeQueueJob struct {
	fn       func(tx *gorm.DB) error
	priority bool
	doneCh   chan error // optional: set when caller needs to wait for completion
}

// NewWriteQueue creates an async write queue that batches DB operations.
// All submitted write functions are executed sequentially through a single goroutine,
// eliminating lock contention on SQLite and reducing transaction overhead on all engines.
func NewWriteQueue(db *gorm.DB, log *slog.Logger) *WriteQueue {
	wq := &WriteQueue{
		db:            db,
		ch:            make(chan writeQueueJob, 256),
		log:           log,
		stopCh:        make(chan struct{}),
		batchInterval: 50 * time.Millisecond, // flush every 50ms or when batch is full
		maxBatchSize:  64,
	}
	wq.wg.Add(1)
	go wq.loop()
	return wq
}

// Submit enqueues an async write operation. Non-blocking: drops if queue is full.
// The write function will be called with a *gorm.DB (possibly in a transaction).
func (wq *WriteQueue) Submit(fn func(tx *gorm.DB) error) {
	select {
	case wq.ch <- writeQueueJob{fn: fn}:
	default:
		wq.log.Warn("write queue full, dropping write operation")
	}
}

// SubmitWait enqueues a write and blocks until it completes. Returns the error from fn.
// Use for operations where the caller needs confirmation (e.g., admin API mutations).
func (wq *WriteQueue) SubmitWait(fn func(tx *gorm.DB) error) error {
	doneCh := make(chan error, 1)
	select {
	case wq.ch <- writeQueueJob{fn: fn, doneCh: doneCh}:
		return <-doneCh
	default:
		// Queue full — execute synchronously as fallback.
		return wq.db.Transaction(func(tx *gorm.DB) error {
			return fn(tx)
		})
	}
}

// SubmitPriority enqueues a high-priority write that triggers immediate flush.
func (wq *WriteQueue) SubmitPriority(fn func(tx *gorm.DB) error) error {
	doneCh := make(chan error, 1)
	select {
	case wq.ch <- writeQueueJob{fn: fn, priority: true, doneCh: doneCh}:
		return <-doneCh
	default:
		return wq.db.Transaction(func(tx *gorm.DB) error {
			return fn(tx)
		})
	}
}

// Close stops the queue after flushing all pending writes.
func (wq *WriteQueue) Close() {
	close(wq.stopCh)
	wq.wg.Wait()
}

func (wq *WriteQueue) loop() {
	defer wq.wg.Done()
	pending := make([]writeQueueJob, 0, wq.maxBatchSize)
	ticker := time.NewTicker(wq.batchInterval)
	defer ticker.Stop()

	for {
		select {
		case job := <-wq.ch:
			pending = append(pending, job)
			// If priority or batch full, flush immediately.
			if job.priority || len(pending) >= wq.maxBatchSize {
				wq.flushBatch(pending)
				pending = pending[:0]
			}

		case <-ticker.C:
			// Drain additional pending jobs.
			draining := true
			for draining && len(pending) < wq.maxBatchSize {
				select {
				case j := <-wq.ch:
					pending = append(pending, j)
				default:
					draining = false
				}
			}
			if len(pending) > 0 {
				wq.flushBatch(pending)
				pending = pending[:0]
			}

		case <-wq.stopCh:
			// Drain all remaining jobs.
			for {
				select {
				case j := <-wq.ch:
					pending = append(pending, j)
				default:
					wq.flushBatch(pending)
					return
				}
			}
		}
	}
}

// flushBatch executes all pending write jobs in a single DB transaction.
// For high-frequency identical operations, this effectively merges them.
func (wq *WriteQueue) flushBatch(jobs []writeQueueJob) {
	if len(jobs) == 0 {
		return
	}

	// Execute all jobs in a single transaction.
	err := wq.db.Transaction(func(tx *gorm.DB) error {
		for i := range jobs {
			if jobErr := jobs[i].fn(tx); jobErr != nil {
				wq.log.Error("write queue job failed", slog.Any("err", jobErr))
				// Notify caller of individual job failure.
				if jobs[i].doneCh != nil {
					jobs[i].doneCh <- jobErr
					jobs[i].doneCh = nil // prevent double-send
				}
			}
		}
		return nil
	})

	// Notify remaining callers of completion.
	for i := range jobs {
		if jobs[i].doneCh != nil {
			jobs[i].doneCh <- err
		}
	}

	if err != nil {
		wq.log.Error("write queue transaction failed", slog.Any("err", err), slog.Int("jobs", len(jobs)))
	}
}
