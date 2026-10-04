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

/**
 * WriteQueue 是面向所有数据库写操作的通用异步写队列。
 *
 * 它接收写函数，在可能时合并高频操作，并通过单个 goroutine 批量执行，
 * 把数据库锁竞争降到最低。
 *
 * 关键特性：
 *   - 非阻塞提交：调用方从不在数据库写入上阻塞。
 *   - 合并执行：多个待写任务在同一个事务里执行。
 *   - 优先级支持：紧急写入（例如鉴权变更）绕过批次定时器。
 *   - 优雅关闭：Close 返回前所有待写任务都已 flush。
 */
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

	// 调优参数。
	batchInterval time.Duration
	maxBatchSize  int

	// 运行期计数器。Submit 为请求热路径刻意保持非阻塞，因此每一次丢失
	// 与降级都必须可观测，且不能为此改动仓储接口。
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

/**
 * WriteQueueStats 是通用异步写队列的时点诊断快照。
 *
 * 各类计数器把「队列压力」「关闭期丢弃」「数据库故障」区分开，
 * 让运维能判断数据是在执行前被拒，还是在持久化过程中失败。
 */
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
	doneCh   chan error // 可选：调用方需要等待完成时设置
}

// 队列容量 / 批大小的硬上限，与 internal/core/config.go QueueConfig 注释保持一致。
// 超出后会被钳制，避免误调把内存吃光或单事务拉满驱动上限。
const (
	writeQueueMaxChannelCapacity = 1 << 20 // 1M 条
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

/**
 * NewWriteQueue 创建按批执行数据库操作的异步写队列。
 *
 * 所有提交的写函数都由单个 goroutine 串行执行，消除 SQLite 上的锁竞争，
 * 并降低所有引擎的事务开销。
 *
 * 这是向后兼容的包装：内部使用 DefaultWriteQueueOptions；需要新增可配置
 * 参数请改用 NewWriteQueueWithOptions。
 */
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

/**
 * Stats 返回队列深度与累计写入结果。
 *
 * 读取快照不触碰数据库，在队列 goroutine 运行期间也可安全调用。
 */
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

/**
 * warnDrop 每个间隔最多打出一条队列压力告警。
 *
 * 计数器仍会对每次被丢弃的提交递增；限频只为防止日志本身变成第二个过载源。
 */
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

/**
 * invokeWriteJob 把回调 panic 转换为普通的任务错误。
 *
 * 一个写坏的可观测性回调绝不能让队列 goroutine 崩溃，也不能阻断后续
 * 记录的持久化。
 */
func invokeWriteJob(fn func(tx *gorm.DB) error, tx *gorm.DB) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("write queue job panic: %v", recovered)
		}
	}()
	return fn(tx)
}

/**
 * runWriteTransaction 把数据库驱动的 panic 转换为 error。
 *
 * 队列属于可观测性路径，当连接异常或测试替身在 Begin/Commit 期间 panic 时，
 * 绝不能让整个进程倒下。
 */
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

/**
 * Submit 把一个异步写操作入队。非阻塞：队列满时直接丢弃。
 *
 * 写函数会以 *gorm.DB（可能处于事务中）为参数被调用。
 */
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

/**
 * SubmitWait 入队一个写操作并阻塞等待其完成，返回 fn 的错误。
 *
 * 用于调用方必须拿到确认的操作（例如 Admin API 的配置变更）。
 */
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
		// 队列已满 —— 降级为同步执行。
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

// SubmitPriority 入队一个高优先级写操作，触发立即 flush。
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

/**
 * runSynchronously 仅供队列通道已满时 wait/priority 的降级路径使用。
 *
 * 它与异步路径保持相同的结局计数器，同时满足调用方「必须知道写入结果」
 * 的要求。
 */
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

// Close 先 flush 所有待写任务，再停止队列。
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
			// 优先级任务或批次已满时，立即 flush。
			if job.priority || len(pending) >= batchLimit {
				wq.flushBatch(pending)
				pending = pending[:0]
			}

		case <-ticker.C:
			// 继续排空额外待处理任务。
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
			// 以有界批次排空所有剩余任务。配置的通道最多可容纳一百万条任务，
			// 单个巨型事务会在关闭期间造成 SQLite 长时间持锁与可避免的内存尖峰。
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

/**
 * flushBatch 在单个数据库事务里执行所有待写任务。
 *
 * 对高频的同构操作，这实际上起到了合并写入的效果。
 */
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
	// 在单个事务里执行全部任务。每个回调都拿到一个 SAVEPOINT，
	// 这样一条写坏的日志不会污染整个事务、连累后续记录。这里刻意不重试
	// 回调：通用函数没有幂等契约，提交结果不明时重试可能造成重复写入。
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
		// 事务级错误意味着所有任务都不能算作已持久化，包括
		// 在提交前返回 nil 的回调。
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
