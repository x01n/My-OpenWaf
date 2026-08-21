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
