package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

// UnifiedWriter accepts all types of observability records on dedicated
// channels and flushes them in a single DB transaction on a fixed interval.
// The request hot-path only performs a non-blocking channel send, keeping
// CPU overhead to a minimum. A single goroutine drains all channels and
// writes everything in one transaction — eliminating SQLite lock contention.
type UnifiedWriter struct {
	db    *gorm.DB
	redis atomic.Pointer[goredis.Client]
	log   *slog.Logger

	eventCh    chan store.SecurityEvent
	accessCh   chan store.AccessLog
	dropCh     chan store.DropEvent
	botScoreCh chan store.BotScoreLog

	stopCh chan struct{}
	wg     sync.WaitGroup

	flushInterval time.Duration

	// batchSize 是触发 flush 的累计阈值；drainLimit 是单次从通道取数的上限。
	// 两者均由 NewUnifiedWriterWithOptions 注入；测试可绕过构造函数直接赋值。
	batchSize  int
	drainLimit int

	securityEventDropped atomic.Int64
	accessLogDropped     atomic.Int64
	dropEventDropped     atomic.Int64
	botScoreDropped      atomic.Int64

	flushesTotal        atomic.Int64
	flushErrorsTotal    atomic.Int64
	lastFlushUnixNano   atomic.Int64
	lastFlushDurationNs atomic.Int64
	lastFlushRecords    atomic.Int64
	totalFlushedRecords atomic.Int64

	// lastDropWarnUnixNano 记录上一次丢弃告警的时间，用于限流。
	// 队列满通常是持续性背压，逐条告警会让日志本身成为故障放大器。
	lastDropWarnUnixNano atomic.Int64

	// closed 在 Close 入口置位，让 Record* 在排空开始前就停止入队。
	// 没有这道闸门时关停期新到的记录会进入无人消费的缓冲区并随进程静默消失；
	// 置位后它们改走 dropped 计数路径，丢失量对 /metrics 可见。
	closed    atomic.Bool
	closeOnce sync.Once
}

// 队列容量上限（与 internal/core/config.go QueueConfig 注释保持一致）。
// 防止误调把内存吃光或单事务拉满驱动上限；超出后保留用户原值会被截断。
const (
	unifiedWriterMaxChannelCapacity = 1 << 20 // 1M
	unifiedWriterMaxBatchSize       = 10000
	unifiedWriterMaxFlushInterval   = 60 * time.Second
)

// 管道项的默认容量。DefaultUnifiedWriterOptions 返回这些值；
// 切换到 DefaultQueueConfig 的语义不会改变运行时行为。
const (
	defaultUnifiedWriterEventBufferSize = 16384
	defaultUnifiedWriterDropBufferSize  = 8192
	defaultUnifiedWriterBatchSize       = 512
	defaultUnifiedWriterFlushInterval   = 3 * time.Second
	// 4×BatchSize 与原 unifiedWriterDrainLimit = 2048 (4×512) 对齐。
	// 保留这一显式常量方便运行时按 opt 调整。
	defaultUnifiedWriterDrainLimit = 2048
)

// UnifiedWriterOptions 同 UnifiedWriter 所有可配置旋钮。
// 默认值由 DefaultUnifiedWriterOptions 提供，与原硬编码常量一一对应。
type UnifiedWriterOptions struct {
	// EventBufferSize 是 SecurityEvent / AccessLog 通道容量。
	// 默认 16384；上限 1M。
	EventBufferSize int
	// DropBufferSize 是 DropEvent / BotScoreLog 通道容量。
	// 默认 8192；上限 1M。
	DropBufferSize int
	// BatchSize 是四类记录累计触发 flush 的阈值。
	// 默认 512；上限 10000。
	BatchSize int
	// FlushInterval 是定时 flush 周期。
	// 默认 3s；上限 60s。
	FlushInterval time.Duration
}

// DefaultUnifiedWriterOptions 返回与原硬编码常量一一对应的默认值。
// 切换后不改变任何运行时行为。
func DefaultUnifiedWriterOptions() UnifiedWriterOptions {
	return UnifiedWriterOptions{
		EventBufferSize: defaultUnifiedWriterEventBufferSize,
		DropBufferSize:  defaultUnifiedWriterDropBufferSize,
		BatchSize:       defaultUnifiedWriterBatchSize,
		FlushInterval:   defaultUnifiedWriterFlushInterval,
	}
}

/**
 * clampObservabilityInt 校验单个整型旋钮，越界时回退默认值或截断到上界。
 *
 * 下界必须拦截 0 与负数：容量 0 会让所有非阻塞入队直接走 default 分支，等于整类
 * 记录被丢弃；负数直接在 make(chan) panic。
 *
 * @param name  字段名，用于告警定位。
 * @param v     待校验值。
 * @param def   下界越界时回退的默认值。
 * @param max   允许的上界。
 * @param warns 告警累加目标。
 * @return 合规值，以及追加了本次告警的切片。
 */
func clampObservabilityInt(name string, v, def, max int, warns []string) (int, []string) {
	if v <= 0 {
		return def, append(warns, fmt.Sprintf("%s=%d is out of range, falling back to default %d", name, v, def))
	}
	if v > max {
		return max, append(warns, fmt.Sprintf("%s=%d exceeds the hard limit, clamped to %d", name, v, max))
	}
	return v, warns
}

/**
 * clampObservabilityDuration 校验单个时长旋钮，语义与 clampObservabilityInt 一致。
 *
 * @param name  字段名，用于告警定位。
 * @param v     待校验值。
 * @param def   下界越界时回退的默认值。
 * @param max   允许的上界；传 0 表示不设上界。
 * @param warns 告警累加目标。
 * @return 合规值，以及追加了本次告警的切片。
 */
func clampObservabilityDuration(name string, v, def, max time.Duration, warns []string) (time.Duration, []string) {
	if v <= 0 {
		return def, append(warns, fmt.Sprintf("%s=%s is out of range, falling back to default %s", name, v, def))
	}
	if max > 0 && v > max {
		return max, append(warns, fmt.Sprintf("%s=%s exceeds the hard limit, clamped to %s", name, v, max))
	}
	return v, warns
}

/**
 * logClampWarnings 把钳制告警打成 WARN。
 *
 * log 为 nil 时静默跳过：测试与嵌入场景会用不带 logger 的构造路径，
 * 告警不能反过来成为 panic 源。
 *
 * @param log   目标 logger，可为 nil。
 * @param warns 待输出的告警文本。
 */
func logClampWarnings(log *slog.Logger, warns []string) {
	if log == nil {
		return
	}
	for _, w := range warns {
		log.Warn(w)
	}
}

// clampUnifiedWriterOptions 把 opts 钳制到安全范围内：
//   - 通道容量限制到 1M；
//   - 批大小限制到 10K；
//   - flush 间隔限制到 60s；
//   - 任何字段为 0 或负数时回退为默认值。
//
// 钳制不可静默：调用方拿到的不再是原值，因此统一在构造函数入口执行一次并返回
// 告警，由构造函数打成 WARN。环境变量一侧已在 internal/core 钳过一遍，走到这里
// 的越界值意味着调用方在代码里直接构造了不合规的 options。
func clampUnifiedWriterOptions(opts UnifiedWriterOptions) (UnifiedWriterOptions, []string) {
	def := DefaultUnifiedWriterOptions()
	var warns []string

	opts.EventBufferSize, warns = clampObservabilityInt(
		"UnifiedWriterOptions.EventBufferSize",
		opts.EventBufferSize, def.EventBufferSize, unifiedWriterMaxChannelCapacity, warns)
	opts.DropBufferSize, warns = clampObservabilityInt(
		"UnifiedWriterOptions.DropBufferSize",
		opts.DropBufferSize, def.DropBufferSize, unifiedWriterMaxChannelCapacity, warns)
	opts.BatchSize, warns = clampObservabilityInt(
		"UnifiedWriterOptions.BatchSize",
		opts.BatchSize, def.BatchSize, unifiedWriterMaxBatchSize, warns)
	opts.FlushInterval, warns = clampObservabilityDuration(
		"UnifiedWriterOptions.FlushInterval",
		opts.FlushInterval, def.FlushInterval, unifiedWriterMaxFlushInterval, warns)

	return opts, warns
}

const (
	unifiedWriterDropWarnInterval = 10 * time.Second

	// unifiedWriterCloseTimeout 是关停排空的时间预算。
	// 关停必须尽力落库而非只取一批，但 DB 已经不可用时无限重试会让进程无法退出，
	// 因此超出预算后放弃剩余记录并计入丢弃。取值留在 lifecycle 的 10s 关停窗口内。
	unifiedWriterCloseTimeout = 8 * time.Second

	// unifiedWriterCloseGrace 是 Close 等待 loop 退出的额外宽限。
	// 排空循环自身受 unifiedWriterCloseTimeout 约束，但 deadline 检查无法打断
	// 已经进入驱动的那一次写入，所以再留一段余量后强制返回，避免关停挂死。
	unifiedWriterCloseGrace = 5 * time.Second
)

// UnifiedWriterStats is a point-in-time snapshot of the async observability writer.
type UnifiedWriterStats struct {
	SecurityEventQueueLen int `json:"security_event_queue_len"`
	AccessLogQueueLen     int `json:"access_log_queue_len"`
	DropEventQueueLen     int `json:"drop_event_queue_len"`
	BotScoreQueueLen      int `json:"bot_score_queue_len"`

	SecurityEventDropped int64 `json:"security_event_dropped"`
	AccessLogDropped     int64 `json:"access_log_dropped"`
	DropEventDropped     int64 `json:"drop_event_dropped"`
	BotScoreDropped      int64 `json:"bot_score_dropped"`

	FlushesTotal        int64 `json:"flushes_total"`
	FlushErrorsTotal    int64 `json:"flush_errors_total"`
	LastFlushRecords    int64 `json:"last_flush_records"`
	LastFlushDurationMs int64 `json:"last_flush_duration_ms"`
	LastFlushUnixNano   int64 `json:"last_flush_unix_nano"`
	TotalFlushedRecords int64 `json:"total_flushed_records"`
}

// NewUnifiedWriter creates a unified writer with large channel buffers.
// 向后兼容包装：内部使用 DefaultUnifiedWriterOptions；新增可配置参数请改用
// NewUnifiedWriterWithOptions。
func NewUnifiedWriter(db *gorm.DB, log *slog.Logger) *UnifiedWriter {
	return NewUnifiedWriterWithOptions(db, log, DefaultUnifiedWriterOptions())
}

// NewUnifiedWriterWithOptions 创建 UnifiedWriter 并按 opt 应用全部旋钮。
// 若 opt 字段为 0 或负数，会回退为 DefaultUnifiedWriterOptions 中的对应默认；
// 任何超出安全上限的字段会被钳制到上限（通道 ≤ 1M、批 ≤ 10K、flush ≤ 60s）。
// 入口钳制的好处是后续代码不需要再重复条件判断，所有内部调用均按 opt 行事。
func NewUnifiedWriterWithOptions(db *gorm.DB, log *slog.Logger, opt UnifiedWriterOptions) *UnifiedWriter {
	opt, clampWarns := clampUnifiedWriterOptions(opt)
	logClampWarnings(log, clampWarns)
	w := &UnifiedWriter{
		db:            db,
		log:           log,
		eventCh:       make(chan store.SecurityEvent, opt.EventBufferSize),
		accessCh:      make(chan store.AccessLog, opt.EventBufferSize),
		dropCh:        make(chan store.DropEvent, opt.DropBufferSize),
		botScoreCh:    make(chan store.BotScoreLog, opt.DropBufferSize),
		stopCh:        make(chan struct{}),
		flushInterval: opt.FlushInterval,
		batchSize:     opt.BatchSize,
		// 4×BatchSize 与原 unifiedWriterDrainLimit = 2048 (4×512) 对齐；
		// BatchSize 收紧时 drainLimit 跟着收，避免单批事务超出整体阈值。
		drainLimit: 4 * opt.BatchSize,
	}
	w.wg.Add(1)
	go w.loop()
	return w
}

// SetRedis enables Redis dual-write for real-time consumption.
func (w *UnifiedWriter) SetRedis(client *goredis.Client) {
	w.redis.Store(client)
}

// Stats returns queue, drop and flush counters for runtime diagnostics.
func (w *UnifiedWriter) Stats() UnifiedWriterStats {
	return UnifiedWriterStats{
		SecurityEventQueueLen: len(w.eventCh),
		AccessLogQueueLen:     len(w.accessCh),
		DropEventQueueLen:     len(w.dropCh),
		BotScoreQueueLen:      len(w.botScoreCh),

		SecurityEventDropped: w.securityEventDropped.Load(),
		AccessLogDropped:     w.accessLogDropped.Load(),
		DropEventDropped:     w.dropEventDropped.Load(),
		BotScoreDropped:      w.botScoreDropped.Load(),

		FlushesTotal:        w.flushesTotal.Load(),
		FlushErrorsTotal:    w.flushErrorsTotal.Load(),
		LastFlushRecords:    w.lastFlushRecords.Load(),
		LastFlushDurationMs: w.lastFlushDurationNs.Load() / int64(time.Millisecond),
		LastFlushUnixNano:   w.lastFlushUnixNano.Load(),
		TotalFlushedRecords: w.totalFlushedRecords.Load(),
	}
}

/**
 * warnDropped 在队列满导致记录丢弃时输出限流告警。
 *
 * 丢弃是不可逆的：缓冲区已满意味着这条记录既不会入库也不会进 Redis。计数器
 * （openwaf_writer_dropped_total）始终逐条累加，但未接监控的部署只能靠日志发现，
 * 因此这里补一条 WARN。间隔限流是必需的——队列满通常是持续背压，逐条打日志会在
 * 磁盘 I/O 上二次放大故障。
 *
 * @param kind    被丢弃的记录类型，用于定位队列。
 * @param dropped 该类型累计丢弃数，让运维直接看到量级而无需查询 metrics。
 */
func (w *UnifiedWriter) warnDropped(kind string, dropped int64) {
	if w.log == nil {
		return
	}
	now := time.Now().UnixNano()
	last := w.lastDropWarnUnixNano.Load()
	if now-last < int64(unifiedWriterDropWarnInterval) {
		return
	}
	if !w.lastDropWarnUnixNano.CompareAndSwap(last, now) {
		return
	}
	w.log.Warn("observability queue full, record dropped",
		slog.String("type", kind),
		slog.Int64("dropped_total", dropped),
	)
}

/**
 * dropAfterClose 在关停闸门已落下时把记录计入丢弃并返回 true。
 *
 * 关停开始后排空循环随时可能退出，此时入队的记录不再有消费者。把它们留在缓冲区
 * 等于静默丢失——既不落库也不计数，运维在 /metrics 上看不到任何异常。这里改为
 * 直接走 dropped 计数路径，让关停期的损失与队列满的损失使用同一套可观测口径。
 *
 * @param kind    被丢弃的记录类型。
 * @param counter 该类型的丢弃计数器。
 * @return 已计入丢弃时返回 true，调用方应立即返回。
 */
func (w *UnifiedWriter) dropAfterClose(kind string, counter *atomic.Int64) bool {
	if !w.closed.Load() {
		return false
	}
	w.warnDropped(kind, counter.Add(1))
	return true
}

// RecordEvent enqueues a security event. Non-blocking.
func (w *UnifiedWriter) RecordEvent(ev store.SecurityEvent) {
	if w.dropAfterClose("security_event", &w.securityEventDropped) {
		return
	}
	select {
	case w.eventCh <- ev:
	default:
		w.warnDropped("security_event", w.securityEventDropped.Add(1))
	}
}

// RecordAccessLog enqueues an access log. Non-blocking.
func (w *UnifiedWriter) RecordAccessLog(al store.AccessLog) {
	if w.dropAfterClose("access_log", &w.accessLogDropped) {
		return
	}
	select {
	case w.accessCh <- al:
	default:
		w.warnDropped("access_log", w.accessLogDropped.Add(1))
	}
}

// RecordDropEvent enqueues a drop event. Non-blocking.
func (w *UnifiedWriter) RecordDropEvent(ev store.DropEvent) {
	if w.dropAfterClose("drop_event", &w.dropEventDropped) {
		return
	}
	select {
	case w.dropCh <- ev:
	default:
		w.warnDropped("drop_event", w.dropEventDropped.Add(1))
	}
}

// RecordBotScore enqueues a bot score log. Non-blocking.
func (w *UnifiedWriter) RecordBotScore(bs store.BotScoreLog) {
	if w.dropAfterClose("bot_score", &w.botScoreDropped) {
		return
	}
	select {
	case w.botScoreCh <- bs:
	default:
		w.warnDropped("bot_score", w.botScoreDropped.Add(1))
	}
}

/**
 * Close 关闭入队闸门、排空剩余记录并停止写入协程。
 *
 * 排空由 loop 的 stopCh 分支在 unifiedWriterCloseTimeout 预算内完成。这里额外用
 * unifiedWriterCloseGrace 兜底等待：deadline 检查发生在每批之间，无法打断已经进入
 * 驱动的那一次写入，若 DB 挂住则 wg.Wait() 会永久阻塞，把整个进程的关停一起拖死。
 * 超出宽限后放弃等待并告警——协程会随进程退出，代价是那一批记录的落库结果未知，
 * 这比进程无法退出可接受。closeOnce 保证重复调用不会 panic on closed channel。
 */
func (w *UnifiedWriter) Close() {
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		close(w.stopCh)
	})

	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(unifiedWriterCloseTimeout + unifiedWriterCloseGrace):
		if w.log != nil {
			w.log.Error("unified writer close timed out, abandoning drain",
				slog.Int("security_event_queue_len", len(w.eventCh)),
				slog.Int("access_log_queue_len", len(w.accessCh)),
				slog.Int("drop_event_queue_len", len(w.dropCh)),
				slog.Int("bot_score_queue_len", len(w.botScoreCh)),
			)
		}
	}
}

func (w *UnifiedWriter) loop() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	events := make([]store.SecurityEvent, 0, w.batchSize)
	accessLogs := make([]store.AccessLog, 0, w.batchSize)
	dropEvents := make([]store.DropEvent, 0, w.batchSize)
	botScores := make([]store.BotScoreLog, 0, w.batchSize)

	flush := func() {
		w.flushBuffered(events, accessLogs, dropEvents, botScores)
		events = events[:0]
		accessLogs = accessLogs[:0]
		dropEvents = dropEvents[:0]
		botScores = botScores[:0]
	}

	for {
		select {
		case ev := <-w.eventCh:
			events = append(events, ev)
			if w.writerShouldFlush(len(events), len(accessLogs), len(dropEvents), len(botScores)) {
				flush()
			}
		case al := <-w.accessCh:
			accessLogs = append(accessLogs, al)
			if w.writerShouldFlush(len(events), len(accessLogs), len(dropEvents), len(botScores)) {
				flush()
			}
		case ev := <-w.dropCh:
			dropEvents = append(dropEvents, ev)
			if w.writerShouldFlush(len(events), len(accessLogs), len(dropEvents), len(botScores)) {
				flush()
			}
		case bs := <-w.botScoreCh:
			botScores = append(botScores, bs)
			if w.writerShouldFlush(len(events), len(accessLogs), len(dropEvents), len(botScores)) {
				flush()
			}
		case <-ticker.C:
			events = drainChanInto(w.eventCh, events, w.drainLimit)
			accessLogs = drainChanInto(w.accessCh, accessLogs, w.drainLimit)
			dropEvents = drainChanInto(w.dropCh, dropEvents, w.drainLimit)
			botScores = drainChanInto(w.botScoreCh, botScores, w.drainLimit)
			flush()
		case <-w.stopCh:
			w.drainAllAndFlush(events, accessLogs, dropEvents, botScores)
			return
		}
	}
}

/**
 * drainAllAndFlush 在关停时把四个缓冲区全部排空落库。
 *
 * 稳态路径复用 drainChanInto 的 2048 上限是为了限制单次事务体积，但关停只有一次
 * 机会：沿用该上限会让缓冲区里超出 2048 的部分随进程静默消失，且不计入任何丢弃
 * 计数器（事件与访问日志缓冲区容量各 16384，最坏一类丢 14336 条）。这里改为循环
 * 排空到通道空，每轮仍按 2048 分批以保持事务体积可控。
 *
 * 时间预算是必需的：DB 已经不可用时每批 flush 都会失败重试，无限循环会让进程无法
 * 退出。超出 unifiedWriterCloseTimeout 后放弃剩余记录，并把它们计入对应类型的丢弃
 * 计数器，使关停期的损失与队列满的损失口径一致，而不是变成不可见的黑洞。
 *
 * @param events     入口处已缓冲的安全事件。
 * @param accessLogs 入口处已缓冲的访问日志。
 * @param dropEvents 入口处已缓冲的丢弃事件。
 * @param botScores  入口处已缓冲的 Bot 评分日志。
 */
func (w *UnifiedWriter) drainAllAndFlush(
	events []store.SecurityEvent,
	accessLogs []store.AccessLog,
	dropEvents []store.DropEvent,
	botScores []store.BotScoreLog,
) {
	deadline := time.Now().Add(unifiedWriterCloseTimeout)

	for {
		events = drainChanInto(w.eventCh, events, w.drainLimit)
		accessLogs = drainChanInto(w.accessCh, accessLogs, w.drainLimit)
		dropEvents = drainChanInto(w.dropCh, dropEvents, w.drainLimit)
		botScores = drainChanInto(w.botScoreCh, botScores, w.drainLimit)

		if len(events)+len(accessLogs)+len(dropEvents)+len(botScores) == 0 {
			return
		}

		w.flushBuffered(events, accessLogs, dropEvents, botScores)
		events = events[:0]
		accessLogs = accessLogs[:0]
		dropEvents = dropEvents[:0]
		botScores = botScores[:0]

		if time.Now().After(deadline) {
			w.abandonRemaining()
			return
		}
	}
}

/**
 * abandonRemaining 把关停预算耗尽后仍在通道里的记录计入丢弃并告警。
 *
 * 只统计不落库：走到这里说明 flush 已经在持续失败或耗时超出预算，继续重试无益。
 * 关键在于让丢失量出现在 openwaf_writer_dropped_total 上，运维据此能判断关停期
 * 到底损失了多少，而不是面对一段无法解释的日志空洞。
 */
func (w *UnifiedWriter) abandonRemaining() {
	abandoned := 0
	abandoned += drainAndCount(w.eventCh, &w.securityEventDropped)
	abandoned += drainAndCount(w.accessCh, &w.accessLogDropped)
	abandoned += drainAndCount(w.dropCh, &w.dropEventDropped)
	abandoned += drainAndCount(w.botScoreCh, &w.botScoreDropped)

	if abandoned > 0 && w.log != nil {
		w.log.Error("unified writer drain budget exhausted, records abandoned",
			slog.Int("abandoned", abandoned),
			slog.Duration("budget", unifiedWriterCloseTimeout),
		)
	}
}

/**
 * drainAndCount 排空一个通道并把取出的条数累加到丢弃计数器。
 *
 * @param ch      待排空的通道。
 * @param counter 对应类型的丢弃计数器。
 * @return 本次放弃的记录条数。
 */
func drainAndCount[T any](ch chan T, counter *atomic.Int64) int {
	n := 0
	for {
		select {
		case <-ch:
			n++
		default:
			if n > 0 {
				counter.Add(int64(n))
			}
			return n
		}
	}
}

func (w *UnifiedWriter) writerShouldFlush(events, accessLogs, dropEvents, botScores int) bool {
	return events+accessLogs+dropEvents+botScores >= w.batchSize
}

func (w *UnifiedWriter) flushBuffered(
	events []store.SecurityEvent,
	accessLogs []store.AccessLog,
	dropEvents []store.DropEvent,
	botScores []store.BotScoreLog,
) {
	records := len(events) + len(accessLogs) + len(dropEvents) + len(botScores)
	if records == 0 {
		return
	}

	start := time.Now()
	failed := false
	defer func() {
		w.recordFlushStats(records, time.Since(start), failed)
	}()

	// Push to Redis first (low-latency path for real-time consumers).
	if rc := w.redis.Load(); rc != nil {
		if err := w.pushToRedis(rc, events, accessLogs, dropEvents, botScores); err != nil {
			failed = true
		}
	}

	// Single DB transaction for all types, with one SAVEPOINT per record type so a
	// failing type cannot take the others down with it.
	err := w.db.Transaction(func(tx *gorm.DB) error {
		w.flushType(tx, "security_events", len(events), func() error {
			return tx.CreateInBatches(events, w.batchSize).Error
		}, &failed)
		w.flushType(tx, "access_logs", len(accessLogs), func() error {
			return tx.CreateInBatches(accessLogs, w.batchSize).Error
		}, &failed)
		w.flushType(tx, "drop_events", len(dropEvents), func() error {
			return tx.CreateInBatches(dropEvents, w.batchSize).Error
		}, &failed)
		w.flushType(tx, "bot_scores", len(botScores), func() error {
			return tx.CreateInBatches(botScores, w.batchSize).Error
		}, &failed)
		return nil
	})
	if err != nil {
		failed = true
		w.log.Error("unified flush transaction failed", slog.Any("err", err))
	}
}

/**
 * flushType 在独立 SAVEPOINT 内写入一类可观测记录。
 *
 * 四类记录共用一个事务是为了消除 SQLite 的写锁竞争，但共用事务会让一类的失败污染
 * 其余三类：PostgreSQL 在首个语句报错后把事务置为 aborted（SQLSTATE 25P02），后续
 * 所有 INSERT 被拒绝，commit 被降级为 rollback，四类记录全部丢失，且真正的根因被
 * 后三条派生错误掩盖。SAVEPOINT 把失败面重新收敛到单一类型：回滚到保存点即清除
 * aborted 状态，后续类型照常写入。SQLite 与 MySQL 驱动同样实现了 SavePoint /
 * RollbackTo，因此这里不需要按驱动分叉。
 *
 * 保存点本身不可用时（驱动不支持或事务状态异常）退化为直接写入，与加入保存点之前
 * 的行为一致——宁可丢失隔离性，不能因为可观测性写入而中断整个 flush 循环。
 *
 * @param tx     当前事务句柄。
 * @param name   保存点名与日志标识，取值为固定字面量，不含外部输入。
 * @param n      待写入记录数，为 0 时直接跳过。
 * @param write  实际的批量写入动作。
 * @param failed 指向本次 flush 的失败标记，用于累加 flush_errors_total。
 */
func (w *UnifiedWriter) flushType(tx *gorm.DB, name string, n int, write func() error, failed *bool) {
	if n == 0 {
		return
	}

	savepointed := tx.SavePoint(name).Error == nil

	if err := write(); err != nil {
		*failed = true
		w.log.Error("flush observability records failed",
			slog.String("type", name),
			slog.Any("err", err),
			slog.Int("n", n),
		)
		if savepointed {
			if rbErr := tx.RollbackTo(name).Error; rbErr != nil {
				w.log.Error("rollback to savepoint failed",
					slog.String("type", name),
					slog.Any("err", rbErr),
				)
			}
		}
	}
}

func (w *UnifiedWriter) recordFlushStats(records int, duration time.Duration, failed bool) {
	w.flushesTotal.Add(1)
	w.totalFlushedRecords.Add(int64(records))
	w.lastFlushRecords.Store(int64(records))
	w.lastFlushDurationNs.Store(duration.Nanoseconds())
	w.lastFlushUnixNano.Store(time.Now().UnixNano())
	if failed {
		w.flushErrorsTotal.Add(1)
	}
}

func (w *UnifiedWriter) pushToRedis(
	rc *goredis.Client,
	events []store.SecurityEvent,
	accessLogs []store.AccessLog,
	dropEvents []store.DropEvent,
	botScores []store.BotScoreLog,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pipe := rc.Pipeline()
	ttl := 7 * 24 * time.Hour

	pushJSON := func(key string, items []any, trim int64) {
		for _, item := range items {
			data, err := json.Marshal(item)
			if err != nil {
				continue
			}
			pipe.LPush(ctx, key, data)
		}
		pipe.LTrim(ctx, key, 0, trim)
		pipe.Expire(ctx, key, ttl)
	}

	if len(events) > 0 {
		items := make([]any, len(events))
		for i := range events {
			items[i] = events[i]
		}
		pushJSON("openwaf:security_events", items, 99999)
	}
	if len(accessLogs) > 0 {
		items := make([]any, len(accessLogs))
		for i := range accessLogs {
			items[i] = accessLogs[i]
		}
		pushJSON("openwaf:access_logs", items, 99999)
	}
	if len(dropEvents) > 0 {
		items := make([]any, len(dropEvents))
		for i := range dropEvents {
			items[i] = dropEvents[i]
		}
		pushJSON("openwaf:drop_events", items, 49999)
	}
	if len(botScores) > 0 {
		items := make([]any, len(botScores))
		for i := range botScores {
			items[i] = botScores[i]
		}
		pushJSON("openwaf:bot_scores", items, 49999)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		w.log.Warn("redis push failed", slog.Any("err", err))
		return err
	}
	return nil
}

// drainChan 把通道里的可用数据一次性取到切片，上限 limit；不阻塞。
// limit 取自 UnifiedWriter.drainLimit；保留为包级函数便于测试直接调用。
func drainChan[T any](ch chan T, limit int) []T {
	n := len(ch)
	if n == 0 {
		return nil
	}
	if n > limit {
		n = limit
	}
	buf := make([]T, 0, n)
	for i := 0; i < n; i++ {
		select {
		case v := <-ch:
			buf = append(buf, v)
		default:
			return buf
		}
	}
	return buf
}

// drainChanInto 把通道里可用的数据批量追加到 buf，上限 limit；不阻塞。
// 保留为包级泛型函数：Go 方法不能有独立类型形参。测试与运行时均通过 w 传入 limit。
func drainChanInto[T any](ch chan T, buf []T, limit int) []T {
	for len(buf) < limit {
		select {
		case v := <-ch:
			buf = append(buf, v)
		default:
			return buf
		}
	}
	return buf
}
