package observability

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
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

	// submitMu 封闭 closed 检查与通道发送之间的竞态窗口。Close 在发布
	// stopCh 前取得写锁：已持读锁的提交先完成发送，后续提交只会观察到 closed，
	// 不会在消费循环退出后留下悬空任务。
	submitMu  sync.RWMutex
	closed    atomic.Bool
	closeOnce sync.Once

	// Tuning.
	batchInterval time.Duration
	maxBatchSize  int

	// Runtime counters. Submit intentionally remains non-blocking for the
	// request hot path, so every loss and fallback must be observable without
	// changing the repository interface.
	submittedTotal         atomic.Int64
	enqueuedTotal          atomic.Int64
	droppedFullTotal       atomic.Int64
	droppedClosedTotal     atomic.Int64
	syncFallbackTotal      atomic.Int64
	executedTotal          atomic.Int64
	succeededTotal         atomic.Int64
	failedJobsTotal        atomic.Int64
	transactionErrorsTotal atomic.Int64
	batchesTotal           atomic.Int64
	lastBatchJobs          atomic.Int64
	lastBatchSucceeded     atomic.Int64
	lastBatchFailed        atomic.Int64
	lastBatchDurationNs    atomic.Int64
	lastBatchUnixNano      atomic.Int64
	lastDropWarnUnixNano   atomic.Int64
}

// ErrWriteQueueClosed 表示同步写请求发生在队列关停开始之后。
var ErrWriteQueueClosed = errors.New("write queue is closed")

const writeQueueDropWarnInterval = 10 * time.Second

// WriteQueueStats is a point-in-time diagnostic snapshot of the generic
// asynchronous write queue. Counters distinguish queue pressure from shutdown
// drops and database failures so operators can tell whether data was rejected
// before execution or failed during persistence.
type WriteQueueStats struct {
	QueueLen               int   `json:"queue_len"`
	QueueCapacity          int   `json:"queue_capacity"`
	Closed                 bool  `json:"closed"`
	SubmittedTotal         int64 `json:"submitted_total"`
	EnqueuedTotal          int64 `json:"enqueued_total"`
	DroppedFullTotal       int64 `json:"dropped_full_total"`
	DroppedClosedTotal     int64 `json:"dropped_closed_total"`
	SyncFallbackTotal      int64 `json:"sync_fallback_total"`
	ExecutedTotal          int64 `json:"executed_total"`
	SucceededTotal         int64 `json:"succeeded_total"`
	FailedJobsTotal        int64 `json:"failed_jobs_total"`
	TransactionErrorsTotal int64 `json:"transaction_errors_total"`
	BatchesTotal           int64 `json:"batches_total"`
	LastBatchJobs          int64 `json:"last_batch_jobs"`
	LastBatchSucceeded     int64 `json:"last_batch_succeeded"`
	LastBatchFailed        int64 `json:"last_batch_failed"`
	LastBatchDurationMs    int64 `json:"last_batch_duration_ms"`
	LastBatchUnixNano      int64 `json:"last_batch_unix_nano"`
}

type writeQueueJob struct {
	fn       func(tx *gorm.DB) error
	priority bool
	doneCh   chan error // optional: set when caller needs to wait for completion
}

// 队列容量 / 批大小的硬上限，与 internal/core/config.go QueueConfig 注释保持一致。
// 超出后会被钳制，避免误调把内存吃光或单事务拉满驱动上限。
const (
	writeQueueMaxChannelCapacity = 1 << 20 // 1M
	writeQueueMaxBatchSize       = 10000
)

// 各项默认值。DefaultWriteQueueOptions 直接返回这一组；
// 切换到 DefaultQueueConfig 的语义不会改变运行时行为。
const (
	defaultWriteQueueCapacity      = 256
	defaultWriteQueueBatchSize     = 64
	defaultWriteQueueBatchInterval = 50 * time.Millisecond
)

// WriteQueueOptions 同 WriteQueue 所有可配置旋钮。
// 默认值由 DefaultWriteQueueOptions 提供，与原硬编码常量一一对应。
type WriteQueueOptions struct {
	// Capacity 是任务通道的容量。默认 256；上限 1M。
	Capacity int
	// BatchSize 是单次事务内允许累积的最大任务数。默认 64；上限 10000。
	BatchSize int
	// BatchInterval 是 ticker 周期：每隔该时长强制 flush 一次，即便未达 BatchSize。
	// 默认 50ms。
	BatchInterval time.Duration
}

// DefaultWriteQueueOptions 返回与原硬编码常量一一对应的默认值。
// 切换后不改变任何运行时行为。
func DefaultWriteQueueOptions() WriteQueueOptions {
	return WriteQueueOptions{
		Capacity:      defaultWriteQueueCapacity,
		BatchSize:     defaultWriteQueueBatchSize,
		BatchInterval: defaultWriteQueueBatchInterval,
	}
}

// clampWriteQueueOptions 把 opt 钳制到安全范围内：
//   - 容量限制到 1M；
//   - 批大小限制到 10K；
//   - 任何字段为 0 或负数时回退为默认值。
//
// 钳制不可静默：调用方拿到的不再是原值，因此统一在构造函数入口执行一次并返回
// 告警，由构造函数打成 WARN。BatchInterval 不设上界——它只影响 flush 的最迟触发
// 时间，调大不会放大单事务体积或内存占用。
func clampWriteQueueOptions(opts WriteQueueOptions) (WriteQueueOptions, []string) {
	def := DefaultWriteQueueOptions()
	var warns []string

	opts.Capacity, warns = clampObservabilityInt(
		"WriteQueueOptions.Capacity",
		opts.Capacity, def.Capacity, writeQueueMaxChannelCapacity, warns)
	opts.BatchSize, warns = clampObservabilityInt(
		"WriteQueueOptions.BatchSize",
		opts.BatchSize, def.BatchSize, writeQueueMaxBatchSize, warns)
	opts.BatchInterval, warns = clampObservabilityDuration(
		"WriteQueueOptions.BatchInterval",
		opts.BatchInterval, def.BatchInterval, 0, warns)

	return opts, warns
}

// NewWriteQueue creates an async write queue that batches DB operations.
// All submitted write functions are executed sequentially through a single goroutine,
// eliminating lock contention on SQLite and reducing transaction overhead on all engines.
// 向后兼容包装：内部使用 DefaultWriteQueueOptions；新增可配置参数请改用
// NewWriteQueueWithOptions。
func NewWriteQueue(db *gorm.DB, log *slog.Logger) *WriteQueue {
	return NewWriteQueueWithOptions(db, log, DefaultWriteQueueOptions())
}

// NewWriteQueueWithOptions 创建 WriteQueue 并按 opt 应用全部旋钮。
// 若 opt 字段为 0 或负数，会回退为 DefaultWriteQueueOptions 中的对应默认；
// 任何超出安全上限的字段会被钳制到上限（容量 ≤ 1M、批 ≤ 10K）。
// 入口钳制的好处是后续代码不需要再重复条件判断，所有内部调用均按 opt 行事。
func NewWriteQueueWithOptions(db *gorm.DB, log *slog.Logger, opt WriteQueueOptions) *WriteQueue {
	if log == nil {
		log = slog.Default()
	}
	opt, clampWarns := clampWriteQueueOptions(opt)
	logClampWarnings(log, clampWarns)
	wq := &WriteQueue{
		db:            db,
		ch:            make(chan writeQueueJob, opt.Capacity),
		log:           log,
		stopCh:        make(chan struct{}),
		batchInterval: opt.BatchInterval, // 每个 BatchInterval 或 BatchSize 满时 flush
		maxBatchSize:  opt.BatchSize,
	}
	wq.wg.Add(1)
	go wq.loop()
	return wq
}

// Stats returns queue depth and cumulative write outcomes. Reading a snapshot
// never touches the database and is safe while the queue goroutine is active.
func (wq *WriteQueue) Stats() WriteQueueStats {
	if wq == nil {
		return WriteQueueStats{}
	}
	return WriteQueueStats{
		QueueLen:               len(wq.ch),
		QueueCapacity:          cap(wq.ch),
		Closed:                 wq.closed.Load(),
		SubmittedTotal:         wq.submittedTotal.Load(),
		EnqueuedTotal:          wq.enqueuedTotal.Load(),
		DroppedFullTotal:       wq.droppedFullTotal.Load(),
		DroppedClosedTotal:     wq.droppedClosedTotal.Load(),
		SyncFallbackTotal:      wq.syncFallbackTotal.Load(),
		ExecutedTotal:          wq.executedTotal.Load(),
		SucceededTotal:         wq.succeededTotal.Load(),
		FailedJobsTotal:        wq.failedJobsTotal.Load(),
		TransactionErrorsTotal: wq.transactionErrorsTotal.Load(),
		BatchesTotal:           wq.batchesTotal.Load(),
		LastBatchJobs:          wq.lastBatchJobs.Load(),
		LastBatchSucceeded:     wq.lastBatchSucceeded.Load(),
		LastBatchFailed:        wq.lastBatchFailed.Load(),
		LastBatchDurationMs:    wq.lastBatchDurationNs.Load() / int64(time.Millisecond),
		LastBatchUnixNano:      wq.lastBatchUnixNano.Load(),
	}
}

// warnDrop emits at most one queue-pressure warning per interval. The counter
// is still incremented for every dropped submission; rate limiting only
// protects the logger from becoming a second source of overload.
func (wq *WriteQueue) warnDrop(reason string, total int64) {
	if wq == nil || wq.log == nil {
		return
	}
	now := time.Now().UnixNano()
	last := wq.lastDropWarnUnixNano.Load()
	if now-last < int64(writeQueueDropWarnInterval) {
		return
	}
	if !wq.lastDropWarnUnixNano.CompareAndSwap(last, now) {
		return
	}
	message := "write queue full, dropping write operation"
	if reason == "closed" {
		message = "write queue closed, dropping write operation"
	}
	wq.log.Warn(message,
		slog.String("reason", reason),
		slog.Int64("dropped_total", total),
	)
}

// invokeWriteJob converts a callback panic into an ordinary job error. A
// malformed observability callback must not bring down the queue goroutine or
// prevent later records from being persisted.
func invokeWriteJob(fn func(tx *gorm.DB) error, tx *gorm.DB) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("write queue job panic: %v", recovered)
		}
	}()
	return fn(tx)
}

// runWriteTransaction converts a database-driver panic into an error. The
// queue is an observability path and must not take down the process when a
// broken connection or test double panics during Begin/Commit.
func runWriteTransaction(db *gorm.DB, callback func(tx *gorm.DB) error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("write queue transaction panic: %v", recovered)
		}
	}()
	return db.Transaction(callback)
}

func (wq *WriteQueue) batchLimit() int {
	if wq == nil || wq.maxBatchSize <= 0 {
		return 1
	}
	return wq.maxBatchSize
}

// Submit enqueues an async write operation. Non-blocking: drops if queue is full.
// The write function will be called with a *gorm.DB (possibly in a transaction).
func (wq *WriteQueue) Submit(fn func(tx *gorm.DB) error) {
	if wq == nil || fn == nil {
		return
	}
	wq.submittedTotal.Add(1)
	wq.submitMu.RLock()
	if wq.closed.Load() {
		total := wq.droppedClosedTotal.Add(1)
		wq.submitMu.RUnlock()
		wq.warnDrop("closed", total)
		return
	}
	var droppedTotal int64
	dropReason := ""
	select {
	case wq.ch <- writeQueueJob{fn: fn}:
		wq.enqueuedTotal.Add(1)
	default:
		droppedTotal = wq.droppedFullTotal.Add(1)
		dropReason = "full"
	}
	wq.submitMu.RUnlock()
	if dropReason != "" {
		wq.warnDrop(dropReason, droppedTotal)
	}
}

// SubmitWait enqueues a write and blocks until it completes. Returns the error from fn.
// Use for operations where the caller needs confirmation (e.g., admin API mutations).
func (wq *WriteQueue) SubmitWait(fn func(tx *gorm.DB) error) error {
	if wq == nil || fn == nil {
		return ErrWriteQueueClosed
	}
	wq.submittedTotal.Add(1)
	doneCh := make(chan error, 1)
	wq.submitMu.RLock()
	if wq.closed.Load() {
		total := wq.droppedClosedTotal.Add(1)
		wq.submitMu.RUnlock()
		wq.warnDrop("closed", total)
		return ErrWriteQueueClosed
	}
	select {
	case wq.ch <- writeQueueJob{fn: fn, doneCh: doneCh}:
		wq.enqueuedTotal.Add(1)
		wq.submitMu.RUnlock()
		return <-doneCh
	default:
		// Queue full — execute synchronously as fallback.
		wq.syncFallbackTotal.Add(1)
		if wq.db == nil {
			wq.failedJobsTotal.Add(1)
			wq.submitMu.RUnlock()
			return errors.New("write queue database is nil")
		}
		err := wq.runSynchronously(fn)
		wq.submitMu.RUnlock()
		return err
	}
}

// SubmitPriority enqueues a high-priority write that triggers immediate flush.
func (wq *WriteQueue) SubmitPriority(fn func(tx *gorm.DB) error) error {
	if wq == nil || fn == nil {
		return ErrWriteQueueClosed
	}
	wq.submittedTotal.Add(1)
	doneCh := make(chan error, 1)
	wq.submitMu.RLock()
	if wq.closed.Load() {
		total := wq.droppedClosedTotal.Add(1)
		wq.submitMu.RUnlock()
		wq.warnDrop("closed", total)
		return ErrWriteQueueClosed
	}
	select {
	case wq.ch <- writeQueueJob{fn: fn, priority: true, doneCh: doneCh}:
		wq.enqueuedTotal.Add(1)
		wq.submitMu.RUnlock()
		return <-doneCh
	default:
		wq.syncFallbackTotal.Add(1)
		if wq.db == nil {
			wq.failedJobsTotal.Add(1)
			wq.submitMu.RUnlock()
			return errors.New("write queue database is nil")
		}
		err := wq.runSynchronously(fn)
		wq.submitMu.RUnlock()
		return err
	}
}

// runSynchronously is used only by the wait/priority fallback when the queue
// channel is full. It keeps the same outcome counters as the asynchronous path
// while preserving the caller's requirement that the write result is known.
func (wq *WriteQueue) runSynchronously(fn func(tx *gorm.DB) error) error {
	if wq == nil || wq.db == nil {
		if wq != nil {
			wq.failedJobsTotal.Add(1)
		}
		return errors.New("write queue database is nil")
	}
	wq.executedTotal.Add(1)
	err := runWriteTransaction(wq.db, func(tx *gorm.DB) error {
		return invokeWriteJob(fn, tx)
	})
	if err != nil {
		wq.failedJobsTotal.Add(1)
		wq.transactionErrorsTotal.Add(1)
		if wq.log != nil {
			wq.log.Error("synchronous write queue fallback failed", slog.Any("err", err))
		}
		return err
	}
	wq.succeededTotal.Add(1)
	return nil
}

// Close stops the queue after flushing all pending writes.
func (wq *WriteQueue) Close() {
	if wq == nil {
		return
	}
	wq.submitMu.Lock()
	wq.closeOnce.Do(func() {
		wq.closed.Store(true)
		if wq.stopCh != nil {
			close(wq.stopCh)
		}
	})
	wq.submitMu.Unlock()
	wq.wg.Wait()
}

func (wq *WriteQueue) loop() {
	defer wq.wg.Done()
	batchLimit := wq.batchLimit()
	pending := make([]writeQueueJob, 0, batchLimit)
	interval := wq.batchInterval
	if interval <= 0 {
		interval = defaultWriteQueueBatchInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case job := <-wq.ch:
			pending = append(pending, job)
			// If priority or batch full, flush immediately.
			if job.priority || len(pending) >= batchLimit {
				wq.flushBatch(pending)
				pending = pending[:0]
			}

		case <-ticker.C:
			// Drain additional pending jobs.
			draining := true
			for draining && len(pending) < batchLimit {
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
			// Drain all remaining jobs in bounded batches. A configured channel can
			// hold up to one million jobs; one giant transaction would create a
			// long SQLite lock and an avoidable memory spike during shutdown.
			for {
				for len(pending) < batchLimit {
					select {
					case j := <-wq.ch:
						pending = append(pending, j)
					default:
						if len(pending) > 0 {
							wq.flushBatch(pending)
							pending = pending[:0]
						}
						return
					}
				}
				wq.flushBatch(pending)
				pending = pending[:0]
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
	start := time.Now()
	wq.batchesTotal.Add(1)
	wq.lastBatchJobs.Store(int64(len(jobs)))
	defer func() {
		wq.lastBatchDurationNs.Store(time.Since(start).Nanoseconds())
		wq.lastBatchUnixNano.Store(time.Now().UnixNano())
	}()

	if wq.db == nil {
		wq.failedJobsTotal.Add(int64(len(jobs)))
		wq.lastBatchSucceeded.Store(0)
		wq.lastBatchFailed.Store(int64(len(jobs)))
		batchErr := errors.New("write queue database is nil")
		for i := range jobs {
			if jobs[i].doneCh != nil {
				jobs[i].doneCh <- batchErr
			}
		}
		if wq.log != nil {
			wq.log.Error("write queue batch skipped: database is nil", slog.Int("jobs", len(jobs)))
		}
		return
	}

	jobErrs := make([]error, len(jobs))
	executed := 0
	// Execute all jobs in a single transaction. Each callback gets a SAVEPOINT
	// so one malformed log cannot poison the transaction for later records. We
	// deliberately do not retry callbacks: the generic function has no
	// idempotency contract, and retrying could duplicate writes after an
	// ambiguous commit.
	err := runWriteTransaction(wq.db, func(tx *gorm.DB) error {
		for i := range jobs {
			name := fmt.Sprintf("wq_job_%d", i)
			savepointed := tx.SavePoint(name).Error == nil
			executed++
			jobErr := invokeWriteJob(jobs[i].fn, tx)
			if jobErr == nil {
				continue
			}
			jobErrs[i] = jobErr
			if savepointed {
				if rollbackErr := tx.RollbackTo(name).Error; rollbackErr != nil && wq.log != nil {
					wq.log.Error("write queue rollback to savepoint failed",
						slog.Int("job", i), slog.Any("err", rollbackErr))
				}
			}
			if wq.log != nil {
				wq.log.Error("write queue job failed",
					slog.Int("job", i), slog.Any("err", jobErr))
			}
		}
		return nil
	})
	wq.executedTotal.Add(int64(executed))

	if err != nil {
		wq.transactionErrorsTotal.Add(1)
		wq.failedJobsTotal.Add(int64(len(jobs)))
		wq.lastBatchSucceeded.Store(0)
		wq.lastBatchFailed.Store(int64(len(jobs)))
		if wq.log != nil {
			wq.log.Error("write queue transaction failed", slog.Any("err", err), slog.Int("jobs", len(jobs)))
		}
		// A transaction-level error means none of the jobs can be considered
		// durable, including callbacks that returned nil before commit.
		for i := range jobs {
			if jobs[i].doneCh != nil {
				jobs[i].doneCh <- fmt.Errorf("write queue transaction failed: %w", err)
			}
		}
		return
	}

	succeeded := 0
	failed := 0
	for i := range jobs {
		if jobs[i].doneCh != nil {
			if jobErr := jobErrs[i]; jobErr != nil {
				jobs[i].doneCh <- jobErr
			} else {
				jobs[i].doneCh <- nil
			}
		}
		if jobErrs[i] == nil {
			succeeded++
		} else {
			failed++
		}
	}
	wq.succeededTotal.Add(int64(succeeded))
	wq.failedJobsTotal.Add(int64(failed))
	wq.lastBatchSucceeded.Store(int64(succeeded))
	wq.lastBatchFailed.Store(int64(failed))
}
