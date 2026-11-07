package observability

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	rueidis "github.com/redis/rueidis"
	"gorm.io/gorm"

	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/bot/tlsfp"
)

/**
 * UnifiedWriter 在专用通道上接收各类可观测性记录，并按固定周期在单个数据库
 * 事务里 flush。
 *
 * 请求热路径只做一次非阻塞的通道发送，把 CPU 开销压到最低。单个 goroutine
 * 排空所有通道、在同一个事务里写入全部记录——从根本上消除 SQLite 锁竞争。
 */
type UnifiedWriter struct {
	db    *gorm.DB
	redis atomic.Pointer[redisClientHolder]
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

	flushesTotal           atomic.Int64
	flushErrorsTotal       atomic.Int64
	lastFlushUnixNano      atomic.Int64
	lastFlushDurationNs    atomic.Int64
	lastFlushRecords       atomic.Int64
	lastFlushFailedRecords atomic.Int64
	totalFlushedRecords    atomic.Int64
	failedRecordsTotal     atomic.Int64

	lastDropWarnUnixNano atomic.Int64

	// redisDownUntil 是 Redis 推送失败后的熔断截止时间（UnixNano）。
	// 写入发生在唯一 flush goroutine 上，Redis 半死时每次 5s 超时会直接
	// 拖垮日志排空速率，进而撑满队列。熔断期内跳过推送、由 DB 单写兜底。
	redisDownUntil atomic.Int64

	// closed 在 Close 入口置位，让 Record* 在排空开始前就停止入队。
	// 没有这道闸门时关停期新到的记录会进入无人消费的缓冲区并随进程静默消失；
	// 置位后它们改走 dropped 计数路径，丢失量对 /metrics 可见。
	closed    atomic.Bool
	closeOnce sync.Once
	// abortOnce 与 closeOnce 必须分开：abortWaitCh 在取写锁之前关闭，stopCh 在
	// 取得写锁之后关闭，两者是先后两次独立的「只做一次」。共用同一个 Once 会让
	// 第二次 Do 变成空操作——stopCh 永不关闭，排空分支永不执行，Close 只能靠
	// unifiedWriterCloseTimeout 超时返回，记录全部丢失。
	abortOnce sync.Once

	// slowLogGrace 为 0 时入队保持原有的非阻塞语义：队列满即丢弃并计数。
	// 大于 0 时改走「队列满则等待」路径：只要队列持续为满的时长不超过该值，
	// 入队就阻塞等待消费者而不是丢弃。上限 unifiedWriterMaxSlowLogGrace。
	slowLogGrace time.Duration

	// abortWaitCh 在 Close 入口关闭，让所有处于慢速等待中的入队立刻退回丢弃
	// 路径。没有它时 Close 最坏要等满一个 slowLogGrace（上限 5 分钟）才能拿到
	// submitMu，而 lifecycle 的关停窗口只有 10s。
	//
	// 必需而非可选：测试直接构造 UnifiedWriter 字面量（不经过构造函数）时它是
	// nil，此时入队路径会因「nil channel 永不就绪」而阻塞在 select 上，绕过
	// submitMu 的闸门语义。因此入队路径在取锁前先判空，nil 一律走 dropOnFull。
	abortWaitCh chan struct{}

	// abortWaitChClosed 与 abortWaitCh 是同一个闸门的两种表示：前者面向直接
	// 构造字面量的调用方（nil channel 无法被关闭，也无从表达「已中止」）。
	abortWaitChClosed atomic.Bool

	// blockedSince 记录各类队列「持续为满」的起点（UnixNano，0 = 当前未处于
	// 持续满状态），由慢速等待路径维护。非零值只在 slowLogGrace > 0 时出现。
	blockedSinceEvent    atomic.Int64
	blockedSinceAccess   atomic.Int64
	blockedSinceDrop     atomic.Int64
	blockedSinceBotScore atomic.Int64

	// submitMu 把 closed 检查与发送操作组成一个不可分割的临界区。
	// Close 先取得写锁再关闭 stopCh，保证已取得读锁的记录完成发送后才开始排空，
	// 不会出现“检查时未关闭、发送时 loop 已退出”的悬空记录。
	submitMu sync.RWMutex

	// countCacheInvalidator 在日志事务提交后失效控制面的 COUNT 缓存。
	// 使用窄接口避免 observability 依赖 store/repository，且允许测试注入轻量替身。
	countCacheMu          sync.RWMutex
	countCacheInvalidator interface{ InvalidateAll() }
	// fingerprintCacheInvalidator 在访问日志事务提交后失效指纹聚合结果缓存。
	// 数据面直写日志库，不经过 AccessLogRepo 的写入方法，若不在这里通知，
	// 管理端进程内的指纹聚合会继续返回写入前的旧结果直到 TTL 到期。
	fingerprintCacheMu          sync.RWMutex
	fingerprintCacheInvalidator interface{ InvalidateFingerprintCache() }
	sqliteFlusher               *sqliteBulkFlusher
	sqliteFlusherInitOnce       sync.Once
}

// 队列容量上限（与 internal/core/config.go QueueConfig 注释保持一致）。
// 防止误调把内存吃光或单事务拉满驱动上限；超出后保留用户原值会被截断。
const (
	unifiedWriterMaxChannelCapacity = 1 << 20 // 1M 条
	unifiedWriterMaxBatchSize       = 10000
	unifiedWriterMaxFlushInterval   = 60 * time.Second
	// unifiedWriterMaxSlowLogGrace 是慢速日志宽限的上界。该值决定 DB 持续跟不上
	// 时请求最多被拖慢多久，无上界等于允许把数据面拖成不可用。
	unifiedWriterMaxSlowLogGrace = 5 * time.Minute
)

const (
	defaultUnifiedWriterEventBufferSize = 16384
	defaultUnifiedWriterDropBufferSize  = 8192
	defaultUnifiedWriterBatchSize       = 4096
	defaultUnifiedWriterFlushInterval   = 3 * time.Second
)

type UnifiedWriterOptions struct {
	// EventBufferSize 是 SecurityEvent / AccessLog 通道容量。
	// 默认 16384；上限 1M。
	EventBufferSize int
	// DropBufferSize 是 DropEvent / BotScoreLog 通道容量。
	// 默认 8192；上限 1M。
	DropBufferSize int
	BatchSize      int
	// FlushInterval 是定时 flush 周期。
	// 默认 3s；上限 60s。
	FlushInterval time.Duration
	// SlowLogGrace 控制队列满时的入队时长（生效值必须为正，由钳制保证；0 视为
	// 未配置并回退 defaultSlowLogGrace）。要回到「队列满即丢弃」的历史语义，
	// 用 SlowLogGraceDisabled。
	// 上限 5m。
	SlowLogGrace time.Duration
	// SlowLogGraceDisabled 显式关闭慢速日志宽限：入队保持非阻塞，队列满即丢弃
	// 并计入 dropped 计数，与参数化之前逐字节一致。
	//
	// 为什么需要独立布尔而不是让 SlowLogGrace=0 表示关闭：本结构体其余字段都按
	// 「0 即未配置」回退默认值，0 无法同时表达「未配置」与「显式关闭」。
	SlowLogGraceDisabled bool
}

/**
 * defaultSlowLogGrace 是慢速日志宽限的生产默认值：0，即关闭。
 *
 * 历史默认是 30s（队列持续为满时让调用方等待消费者腾位）。该设计把可观测性
 * 背压直接施加在请求 goroutine 上：实测同一台 8 核机器、1GB 日志库、c=320 时，
 * 登录速率约 13k 行/s，而服务端纯处理上限约 27.5k QPS，队列长期饱和后
 * `deliver` 会把请求线程挂住，端到端 QPS 被钉死在写入速率上（p50 23ms、
 * p99 61ms），而 CPU 只用到 5.1/8 核——瓶颈是阻塞等待而不是算力。
 *
 * 请求日志是可观测性附属品，不能反过来决定请求延迟。因此默认改为
 * 「队列满即丢弃并计入 openwaf_writer_dropped_total」：请求路径永远只做一次
 * 非阻塞 select。需要「宁可拖慢请求也不丢日志」的部署，用
 * MY_OPENWAF_QUEUE_SLOW_LOG_GRACE 显式恢复等待语义。
 */
const defaultSlowLogGrace = 0 * time.Second

// DefaultUnifiedWriterOptions 返回生产默认值，与参数化前的硬编码常量逐项一致
// （BatchSize 经 SQLite 写径审计由 64 → 256 → 4096）。
//
// SlowLogGrace 在此处保持 0，理由不是「默认关闭」：0 是**未配置**的表示，运行时
// 由 effectiveSlowLogGrace 解释为 defaultSlowLogGrace（30s）。把 30s 直接写进这个
// 结构体反而会让「未配置」无法与「显式配置成 30s」区分，也会打破「零值回退默认」
// 在本结构体上的既有口径。要真正关闭慢速宽限，用 SlowLogGraceDisabled。
func DefaultUnifiedWriterOptions() UnifiedWriterOptions {
	return UnifiedWriterOptions{
		EventBufferSize: defaultUnifiedWriterEventBufferSize,
		DropBufferSize:  defaultUnifiedWriterDropBufferSize,
		BatchSize:       defaultUnifiedWriterBatchSize,
		FlushInterval:   defaultUnifiedWriterFlushInterval,
	}
}

/**
 * effectiveSlowLogGrace 把 options 上的宽限取值折算成运行时生效值。
 *
 * 0 与负数都表示「未配置」，回落到 defaultSlowLogGrace（当前为 0，即非阻塞）。
 * 需要等待语义（队列满时阻塞调用方）的部署必须显式配置正数宽限，或走
 * SlowLogGraceDisabled 反向关闭。
 *
 * 这个折算刻意不放进 clampUnifiedWriterOptions：钳制函数的契约是「零值回退到
 * DefaultUnifiedWriterOptions 的对应项」，而该项本身是 0，把默认值塞进钳制会让
 * 「钳制后的零值 option 等于默认 option」这条既有断言失效。折算放在构造器上，
 * 只影响运行时字段，不影响 options 的往返一致性。
 *
 * @param grace    options 上的宽限取值。
 * @param disabled 是否显式关闭。
 * @return 运行时生效的宽限时长；0 表示关闭（非阻塞入队）。
 */
func effectiveSlowLogGrace(grace time.Duration, disabled bool) time.Duration {
	if disabled {
		return 0
	}
	if grace <= 0 {
		return defaultSlowLogGrace
	}
	return grace
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
//   - 慢速日志宽限限制到 5m；
//   - 除 SlowLogGrace 外，任何字段为 0 或负数时回退为默认值。
//
// 钳制不可静默：调用方拿到的不再是原值，因此统一在构造函数入口执行一次并返回
// 告警，由构造函数打成 WARN。环境变量一侧已在 internal/core 钳过一遍，走到这里
// 的越界值意味着调用方在代码里直接构造了不合规的 options。
//
// SlowLogGrace 的 0 是合法值（关闭慢速宽限），不能按「0 即未配置」回退默认值，
// 否则无法在代码里显式关掉它；负数按 0 处理。
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
	// SlowLogGrace 的 0 与其余字段的 0 语义不同：它一律表示「未配置」并回退默认
	// 值，且刻意不产告警——零值结构体已经会为另外四个字段各产出一条「漏了
	// DefaultUnifiedWriterOptions()」的告警，再补一条同类噪声没有额外信息量。
	// 显式关闭走 SlowLogGraceDisabled，不走 0。运行时折算见 effectiveSlowLogGrace。
	if opts.SlowLogGraceDisabled {
		opts.SlowLogGrace = 0
		return opts, warns
	}
	if opts.SlowLogGrace < 0 {
		warns = append(warns, fmt.Sprintf(
			"UnifiedWriterOptions.SlowLogGrace=%s is negative, treated as 0 (unset)", opts.SlowLogGrace))
		opts.SlowLogGrace = 0
		return opts, warns
	}
	if opts.SlowLogGrace > unifiedWriterMaxSlowLogGrace {
		warns = append(warns, fmt.Sprintf(
			"UnifiedWriterOptions.SlowLogGrace=%s exceeds the hard limit, clamped to %s",
			opts.SlowLogGrace, unifiedWriterMaxSlowLogGrace))
		opts.SlowLogGrace = unifiedWriterMaxSlowLogGrace
	}

	return opts, warns
}

const (
	unifiedWriterDropWarnInterval = 10 * time.Second

	// unifiedWriterQueueFullMessage 是缓冲区满导致丢弃时的告警文案。
	// 这类丢弃的成因是背压，运维动作是扩容或降载。
	unifiedWriterQueueFullMessage = "observability queue full, record dropped"

	// unifiedWriterClosedDropMessage 是关停闸门已落下导致丢弃时的告警文案。
	// 这类丢弃只在关停窗口内出现，成因是排空循环已停，运维动作是事后核对损失，
	// 而不是去查队列容量——与上一条共用文案会把两种故障混为一谈。
	unifiedWriterClosedDropMessage = "observability writer closed, record dropped"

	// unifiedWriterCloseTimeout 是关停排空的时间预算。
	// 关停必须尽力落库而非只取一批，但 DB 已经不可用时无限重试会让进程无法退出，
	// 因此超出预算后放弃剩余记录并计入丢弃。取值留在 lifecycle 的 10s 关停窗口内。
	unifiedWriterCloseTimeout = 8 * time.Second

	// unifiedWriterCloseGrace 是 Close 等待 loop 退出的额外宽限。
	// 排空循环自身受 unifiedWriterCloseTimeout 约束，但 deadline 检查无法打断
	// 已经进入驱动的那一次写入，所以再留一段余量后强制返回，避免关停挂死。
	unifiedWriterCloseGrace = 5 * time.Second

	// redisPushFailureBackoff 是 Redis 推送失败后的熔断窗口。
	// 与 HotCache 的 5s 故障退避保持同一量级：既避免每批都等满 5s 超时，
	// 又能在 Redis 恢复后及时回到双写。
	redisPushFailureBackoff = 5 * time.Second
)

// UnifiedWriterStats 是异步可观测性写入器的时点快照。
type UnifiedWriterStats struct {
	SecurityEventQueueLen int `json:"security_event_queue_len"`
	AccessLogQueueLen     int `json:"access_log_queue_len"`
	DropEventQueueLen     int `json:"drop_event_queue_len"`
	BotScoreQueueLen      int `json:"bot_score_queue_len"`

	SecurityEventDropped int64 `json:"security_event_dropped"`
	AccessLogDropped     int64 `json:"access_log_dropped"`
	DropEventDropped     int64 `json:"drop_event_dropped"`
	BotScoreDropped      int64 `json:"bot_score_dropped"`

	FlushesTotal           int64 `json:"flushes_total"`
	FlushErrorsTotal       int64 `json:"flush_errors_total"`
	LastFlushRecords       int64 `json:"last_flush_records"`
	LastFlushFailedRecords int64 `json:"last_flush_failed_records"`
	LastFlushDurationMs    int64 `json:"last_flush_duration_ms"`
	LastFlushUnixNano      int64 `json:"last_flush_unix_nano"`
	TotalFlushedRecords    int64 `json:"total_flushed_records"`
	FailedRecordsTotal     int64 `json:"failed_records_total"`
}

/**
 * NewUnifiedWriter 创建带大容量通道缓冲的统一写入器。
 *
 * 这是向后兼容的包装：内部使用 DefaultUnifiedWriterOptions；需要新增可配置
 * 参数请改用 NewUnifiedWriterWithOptions。
 */
func NewUnifiedWriter(db *gorm.DB, log *slog.Logger) *UnifiedWriter {
	return NewUnifiedWriterWithOptions(db, log, DefaultUnifiedWriterOptions())
}

// NewUnifiedWriterWithOptions 创建 UnifiedWriter 并按 opt 应用全部旋钮。
// 若 opt 字段为 0 或负数，会回退为 DefaultUnifiedWriterOptions 中的对应默认
// （SlowLogGrace 例外：0 是合法值，表示关闭慢速宽限）；
// 任何超出安全上限的字段会被钳制到上限（通道 ≤ 1M、批 ≤ 10K、flush ≤ 60s、
// 慢速宽限 ≤ 5m）。入口钳制的好处是后续代码不需要再重复条件判断，
// 所有内部调用均按 opt 行事。
func NewUnifiedWriterWithOptions(db *gorm.DB, log *slog.Logger, opt UnifiedWriterOptions) *UnifiedWriter {
	if log == nil {
		log = slog.Default()
	}
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
		slowLogGrace:  effectiveSlowLogGrace(opt.SlowLogGrace, opt.SlowLogGraceDisabled),
		// drainLimit 取 4×BatchSize，避免单批事务超出批阈值的整体规模；
		// BatchSize 收紧时 drainLimit 跟着收，放宽时跟着放。
		drainLimit: 4 * opt.BatchSize,
	}
	// abortWaitCh 只在启用慢速宽限时分配：关闭时入队路径完全不触碰它，
	// 测试直接构造 UnifiedWriter 字面量也不会因 nil channel 而阻塞
	// （select 里的 nil channel 永不就绪，正是不启用时的期望行为）。
	if w.slowLogGrace > 0 {
		w.abortWaitCh = make(chan struct{})
	}
	w.wg.Add(1)
	go w.loop()
	return w
}

// redisClientHolder 包装 rueidis.Client 接口，供 atomic.Pointer 原子换装。
// atomic.Pointer 的类型参数必须是具体指针类型，接口值不能直接放入。
type redisClientHolder struct {
	c rueidis.Client
}

/** SetRedis 开启 Redis 双写，供实时消费使用。 */
func (w *UnifiedWriter) SetRedis(client rueidis.Client) {
	if client == nil {
		w.redis.Store(nil)
		return
	}
	w.redis.Store(&redisClientHolder{c: client})
}

/**
 * SetCountCacheInvalidator 挂接一个可选的 COUNT 缓存失效器。
 *
 * 只有当某个事务确实提交了至少一条可观测性记录之后才会触发失效，
 * 因此失败或丢弃的批次不会扰动缓存状态。
 */
func (w *UnifiedWriter) SetCountCacheInvalidator(invalidator interface{ InvalidateAll() }) {
	if w == nil {
		return
	}
	w.countCacheMu.Lock()
	w.countCacheInvalidator = invalidator
	w.countCacheMu.Unlock()
}

func (w *UnifiedWriter) invalidateCountCache(prefixes ...string) {
	if w == nil {
		return
	}
	w.countCacheMu.RLock()
	invalidator := w.countCacheInvalidator
	w.countCacheMu.RUnlock()
	if invalidator == nil {
		return
	}
	if prefixInvalidator, ok := invalidator.(interface{ InvalidatePrefix(string) }); ok {
		for _, prefix := range prefixes {
			if prefix != "" {
				prefixInvalidator.InvalidatePrefix(prefix)
			}
		}
		return
	}
	invalidator.InvalidateAll()
}

/**
 * SetFingerprintCacheInvalidator 挂接一个可选的指纹聚合缓存失效器。
 *
 * 数据面写入不经过 AccessLogRepo，因此必须在日志事务提交后主动通知控制面，
 * 否则“先查聚合、再产生日志、再查聚合”会在缓存 TTL 内持续返回旧结果。
 * 只有事务确实提交了记录才触发失效；失败批次不扰动缓存。
 *
 * @param invalidator 实现 InvalidateFingerprintCache 的失效器，可为 nil。
 */
func (w *UnifiedWriter) SetFingerprintCacheInvalidator(invalidator interface{ InvalidateFingerprintCache() }) {
	if w == nil {
		return
	}
	w.fingerprintCacheMu.Lock()
	w.fingerprintCacheInvalidator = invalidator
	w.fingerprintCacheMu.Unlock()
}

func (w *UnifiedWriter) invalidateFingerprintCache() {
	if w == nil {
		return
	}
	w.fingerprintCacheMu.RLock()
	invalidator := w.fingerprintCacheInvalidator
	w.fingerprintCacheMu.RUnlock()
	if invalidator != nil {
		invalidator.InvalidateFingerprintCache()
	}
}

/** Stats 返回队列、丢弃与 flush 计数器，供运行期诊断。 */
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

		FlushesTotal:           w.flushesTotal.Load(),
		FlushErrorsTotal:       w.flushErrorsTotal.Load(),
		LastFlushRecords:       w.lastFlushRecords.Load(),
		LastFlushFailedRecords: w.lastFlushFailedRecords.Load(),
		LastFlushDurationMs:    w.lastFlushDurationNs.Load() / int64(time.Millisecond),
		LastFlushUnixNano:      w.lastFlushUnixNano.Load(),
		TotalFlushedRecords:    w.totalFlushedRecords.Load(),
		FailedRecordsTotal:     w.failedRecordsTotal.Load(),
	}
}

/**
 * warnDropped 在记录被丢弃时输出限流告警。
 *
 * 丢弃是不可逆的：缓冲区已满意味着这条记录既不会入库也不会进 Redis。计数器
 * （openwaf_writer_dropped_total）始终逐条累加，但未接监控的部署只能靠日志发现，
 * 因此这里补一条 WARN。间隔限流是必需的——队列满通常是持续背压，逐条打日志会在
 * 磁盘 I/O 上二次放大故障。
 *
 * 两种丢弃原因（队列满、关停闸门）共用同一把限流闸是有意的：丢弃本身才是运维
 * 要看的信号，原因只是它的属性；拆成两个闸会在关停阶段把队列满的告警挤掉。
 *
 * @param message 告警文案，由调用方按丢弃原因选择（见 unifiedWriterQueueFullMessage /
 *                unifiedWriterClosedDropMessage）。
 * @param kind    被丢弃的记录类型，用于定位队列。
 * @param dropped 该类型累计丢弃数，让运维直接看到量级而无需查询 metrics。
 */
func (w *UnifiedWriter) warnDropped(message, kind string, dropped int64) {
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
	w.log.Warn(message,
		slog.String("type", kind),
		slog.Int64("dropped_total", dropped),
	)
}

/**
 * dropAfterClose 在关停闸门已落下时把记录计入丢弃并返回 true。
 *
 * 关停开始后排空循环随时可能退出，此时入队的记录不再有消费者。把它们留在缓冲区
 * 等于静默丢失——既不落库也不计数，运维在 /metrics 上看不到任何异常。这里改为
 * 直接走 dropped 计数路径，让关停期的损失与队列满的损失使用同一套可观测口径
 * （计数），但日志文案必须区分：关停期丢弃不是背压，看到「queue full」去找容量
 * 问题是白费功夫。
 *
 * @param kind    被丢弃的记录类型。
 * @param counter 该类型的丢弃计数器。
 * @return 已计入丢弃时返回 true，调用方应立即返回。
 */
func (w *UnifiedWriter) dropAfterClose(kind string, counter *atomic.Int64) bool {
	if !w.closed.Load() {
		return false
	}
	w.warnDropped(unifiedWriterClosedDropMessage, kind, counter.Add(1))
	return true
}

// beginRecord 取得关停闸门的读锁并判定调用方能否发送；返回 true 时调用方必须释放 submitMu。
func (w *UnifiedWriter) beginRecord(kind string, counter *atomic.Int64) bool {
	if w == nil {
		return false
	}
	w.submitMu.RLock()
	if w.dropAfterClose(kind, counter) {
		w.submitMu.RUnlock()
		return false
	}
	return true
}

/** RecordEvent 入队一条安全事件。非阻塞；启用慢速宽限后在队列满时改为受限等待。 */
func (w *UnifiedWriter) RecordEvent(ev store.SecurityEvent) {
	if !w.beginRecord("security_event", &w.securityEventDropped) {
		return
	}
	defer w.submitMu.RUnlock()
	deliver(w, w.eventCh, ev, "security_event", &w.securityEventDropped, &w.blockedSinceEvent)
}

/** RecordAccessLog 入队一条访问日志。非阻塞；启用慢速宽限后在队列满时改为受限等待。 */
func (w *UnifiedWriter) RecordAccessLog(al store.AccessLog) {
	if !w.beginRecord("access_log", &w.accessLogDropped) {
		return
	}
	defer w.submitMu.RUnlock()
	deliver(w, w.accessCh, al, "access_log", &w.accessLogDropped, &w.blockedSinceAccess)
}

/** RecordDropEvent 入队一条丢包事件。非阻塞；启用慢速宽限后在队列满时改为受限等待。 */
func (w *UnifiedWriter) RecordDropEvent(ev store.DropEvent) {
	if !w.beginRecord("drop_event", &w.dropEventDropped) {
		return
	}
	defer w.submitMu.RUnlock()
	deliver(w, w.dropCh, ev, "drop_event", &w.dropEventDropped, &w.blockedSinceDrop)
}

/** RecordBotScore 入队一条 Bot 评分日志。非阻塞；启用慢速宽限后在队列满时改为受限等待。 */
func (w *UnifiedWriter) RecordBotScore(bs store.BotScoreLog) {
	if !w.beginRecord("bot_score", &w.botScoreDropped) {
		return
	}
	defer w.submitMu.RUnlock()
	deliver(w, w.botScoreCh, bs, "bot_score", &w.botScoreDropped, &w.blockedSinceBotScore)
}

/**
 * deliver 把一条记录投递进队列，返回时结果已确定：已入队，或已计入丢弃。
 *
 * 两条路径：
 *
 *  1. 快路径（永远先试）：队列有空位就直接入队。这是 slowLogGrace 未启用时的
 *     唯一路径，也是启用后稳态下唯一会走到的路径，热路径开销与参数化之前逐字节
 *     相同（一次非阻塞 select）。
 *  2. 慢速宽限（仅 slowLogGrace > 0）：队列满时不立刻丢弃，而是等待消费者腾出
 *     空位。只要队列「持续为满」的时长不超过 slowLogGrace，本条记录一定入队。
 *
 * 为什么需要「持续为满」这个判据而不是按条计时：队列满通常是持续背压，若每条
 * 记录各自等满一个宽限窗口，DB 长期跟不上时入队延迟会无上界地叠加，把数据面拖死。
 * 以连续满状态的起点统一计时，保证最多只有一个宽限窗口内的请求被拖慢，之后立刻
 * 退回快速丢弃——丢弃量在 /metrics 上照常可见，不会变成静默黑洞。
 *
 * 共享状态的维护：blockedSince 为 0 表示当前不处于连续满状态，由第一个进入等待
 * 的调用者 CAS 打点；任何一次成功入队都把它清回 0，从而让「空过一下又满」重新
 * 获得完整宽限。快路径在 blockedSince 非 0 时也清一次，否则一次超时之后该标记
 * 会永久残留，后续每次积压都会被立刻判定为超时。
 *
 * @param w            所属写入器，读取 slowLogGrace 与 abortWaitCh。
 * @param ch           目标类型队列。
 * @param v            待入队记录。
 * @param kind         记录类型名，用于丢弃告警与定位。
 * @param counter      该类型的丢弃计数器。
 * @param blockedSince 该类型「连续满」状态的起点（UnixNano，0 = 未处于该状态）。
 */
func deliver[T any](w *UnifiedWriter, ch chan T, v T, kind string, counter, blockedSince *atomic.Int64) {
	select {
	case ch <- v:
		if blockedSince.Load() != 0 {
			blockedSince.Store(0)
		}
		return
	default:
	}

	if w.slowLogGrace <= 0 || w.abortWaitCh == nil {
		// 宽限未启用（或调用方直接构造字面量、闸门不可用）时保持非阻塞语义：
		// 队列满即丢弃。这与参数化之前的实现逐字节等价。
		w.warnDropped(unifiedWriterQueueFullMessage, kind, counter.Add(1))
		return
	}

	now := time.Now().UnixNano()
	enteredAt := blockedSince.Load()
	if enteredAt == 0 {
		// 未处于连续满状态：由本调用打点。CAS 失败说明别的调用者刚打过点，
		// 读回它的取值；若读回仍是 0，说明打点后立刻被一次成功入队清空，
		// 此时按「本调用就是一个新窗口」处理。
		//
		// 这个 0 分支是必需的：若在 Load 拿到 0 之后仍按
		// enteredAt+grace-now 计算，剩余时间会是一个约等于 -now 的巨大负数，
		// remaining <= 0 会让记录被立即丢弃。实测中它表现为「丢弃数与宽限取值
		// 无关」的稀疏丢弃（1s/30s/5m 三档在 c=256 下都是约 0.002%）。
		blockedSince.CompareAndSwap(0, now)
		enteredAt = blockedSince.Load()
		if enteredAt == 0 {
			enteredAt = now
		}
	}
	remaining := time.Duration(enteredAt + int64(w.slowLogGrace) - now)
	if remaining <= 0 || w.abortWaitChClosed.Load() {
		// 连续满状态已经持续超过宽限（或关停已开始）：立刻退回快路径语义，
		// 不再拖慢调用方。
		w.warnDropped(unifiedWriterQueueFullMessage, kind, counter.Add(1))
		return
	}

	timer := time.NewTimer(remaining)
	defer timer.Stop()
	for {
		select {
		case ch <- v:
			blockedSince.Store(0)
			return
		case <-w.abortWaitCh:
			// Close 已开始排空，等待下去没有消费者；立刻退回丢弃而不是拖住关停。
			w.warnDropped(unifiedWriterQueueFullMessage, kind, counter.Add(1))
			return
		case <-timer.C:
			w.warnDropped(unifiedWriterQueueFullMessage, kind, counter.Add(1))
			return
		}
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
 *
 * abortWaitCh 必须在取写锁之前关闭：slowLogGrace > 0 时入队可能在无限期等待队列
 * 空位，而那些入队持有 submitMu 的读锁，先关 abortWaitCh 才能让它们立刻退出等待，
 * Close 才拿得到写锁。
 */
func (w *UnifiedWriter) Close() {
	if w == nil {
		return
	}
	if w.abortWaitCh != nil {
		w.abortOnce.Do(func() {
			w.abortWaitChClosed.Store(true)
			close(w.abortWaitCh)
		})
	}
	w.submitMu.Lock()
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		if w.stopCh != nil {
			close(w.stopCh)
		}
	})
	w.submitMu.Unlock()

	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// writer goroutine 已随 wg.Wait 退出，此后不再有 ensureStmtFor 的
		// 并发写入，可安全释放长期语句（幂等；未初始化时为 nil 空操作）。
		if w.sqliteFlusher != nil {
			w.sqliteFlusher.closeAll()
		}
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
 * 稳态路径复用 drainChanInto 的 drainLimit 上限是为了限制单次事务体积，但关停只有一次
 * 机会：沿用该上限会让缓冲区里超出 drainLimit 的部分随进程静默消失，且不计入任何丢弃
 * 计数器（事件与访问日志缓冲区容量各 16384，最坏一类丢 16384-drainLimit 条）。这里改为循环
 * 排空到通道空，每轮仍按 drainLimit 分批以保持事务体积可控。
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
	persistedRecords := 0
	failedRecords := 0
	var invalidationPrefixes []string
	defer func() {
		w.recordFlushStats(persistedRecords, failedRecords, time.Since(start), failed)
	}()
	if w.db == nil {
		failed = true
		failedRecords = records
		if w.log != nil {
			w.log.Error("unified flush skipped: database is nil", slog.Int("records", records))
		}
		return
	}

	bf := w.sqliteFlusherFor()
	var err error
	if bf != nil {
		var usable bool
		usable, err = w.flushBulk(bf, events, accessLogs, dropEvents, botScores,
			&persistedRecords, &failedRecords, &invalidationPrefixes, &failed)
		if !usable {
			// 事务尚未写入任何行（连接或语句准备失败），整批安全回退 GORM。
			// 永久禁用快路径：继续重试只会让每批都先失败一次并污染日志。
			if w.log != nil {
				w.log.Warn("sqlite bulk flusher unavailable, falling back to gorm",
					slog.Any("err", err))
			}
			bf.reset()
			w.sqliteFlusher = nil
			bf = nil
			err = nil
			failed = false
		}
	}
	if bf == nil {
		err = w.db.Transaction(func(tx *gorm.DB) error {
			if w.flushType(tx, "security_events", len(events), func() error {
				return tx.CreateInBatches(events, w.batchSize).Error
			}, &failed) {
				persistedRecords += len(events)
				if len(events) > 0 {
					invalidationPrefixes = append(invalidationPrefixes, "se_count:v2")
				}
			} else {
				failedRecords += len(events)
			}
			if w.flushType(tx, "access_logs", len(accessLogs), func() error {
				return tx.CreateInBatches(accessLogs, w.batchSize).Error
			}, &failed) {
				persistedRecords += len(accessLogs)
				if len(accessLogs) > 0 {
					invalidationPrefixes = append(invalidationPrefixes, "al_count:v2", "al_list:v1")
				}
			} else {
				failedRecords += len(accessLogs)
			}
			if w.flushType(tx, "drop_events", len(dropEvents), func() error {
				return tx.CreateInBatches(dropEvents, w.batchSize).Error
			}, &failed) {
				persistedRecords += len(dropEvents)
				if len(dropEvents) > 0 {
					invalidationPrefixes = append(invalidationPrefixes, "de_count")
				}
			} else {
				failedRecords += len(dropEvents)
			}
			if w.flushType(tx, "bot_scores", len(botScores), func() error {
				return tx.CreateInBatches(botScores, w.batchSize).Error
			}, &failed) {
				persistedRecords += len(botScores)
			} else {
				failedRecords += len(botScores)
			}
			return nil
		})
	}
	if err != nil {
		failed = true
		persistedRecords = 0
		failedRecords = records
		w.log.Error("unified flush transaction failed", slog.Any("err", err))
		return
	}
	if persistedRecords > 0 {
		w.invalidateCountCache(invalidationPrefixes...)
		// 访问日志影响指纹聚合：只要本批含访问日志就失效控制面缓存。
		// 即便本批访问日志写入失败、只有其它类型成功，这里多失效一次也
		// 只增加一个原子计数，不会产生错误结果。
		if len(accessLogs) > 0 {
			w.invalidateFingerprintCache()
		}
	}
	// 事务已提交：此处推送失败只会让实时读路径退回数据库，不会造成数据丢失，
	// 也不会回滚已提交的记录。h3 的 0-RTT 详情键与列表键都在这一步写出。
	if h := w.redis.Load(); h != nil && h.c != nil {
		if err := w.pushToRedis(h.c, events, accessLogs, dropEvents, botScores); err != nil {
			failed = true
		}
	}
}

// sqliteFlusherFor 惰性判断当前 LogDB 是否为 sqlite 方言并初始化长期语句
// 快路径。非 sqlite（或初始化失败）返回 nil，调用方落回 GORM 原路径。
// 判断依据：db.Config.Dialector.Name() == "sqlite"（与 internal/core/database
// 的引擎判定同源；探针阶段另有独立 DTFORM 检测，此处以方言名收敛）。
func (w *UnifiedWriter) sqliteFlusherFor() *sqliteBulkFlusher {
	if w.sqliteFlusher != nil {
		return w.sqliteFlusher
	}
	if w.db == nil || w.db.Dialector == nil || w.db.Dialector.Name() != "sqlite" {
		return nil
	}
	w.sqliteFlusherInitOnce.Do(func() {
		bf := newSQLiteBulkFlusher(w.log)
		if bf == nil {
			return
		}
		if err := bf.attachSQLDB(w.db); err != nil {
			if w.log != nil {
				w.log.Warn("sqlite bulk flusher disabled", slog.Any("err", err))
			}
			return
		}
		w.sqliteFlusher = bf
	})
	return w.sqliteFlusher
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
 * @return 该类型的全部记录是否已成功写入当前事务。
 */
func (w *UnifiedWriter) flushType(tx *gorm.DB, name string, n int, write func() error, failed *bool) bool {
	if n == 0 {
		return true
	}

	// 非 sqlite 快路径下保存点仍由 GORM 管理。
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
		return false
	}
	return true
}

/**
 * flushBulkType 在固定连接的 sqlite 事务内写入一类记录。
 *
 * 语义与 [UnifiedWriter.flushType] 完全一致：每类一个 SAVEPOINT，失败只回滚
 * 本类，其余三类继续写入。差别仅在于事务句柄是原生 *sql.Tx，保存点与回滚
 * 都直接作用在同一条固定连接上。
 *
 * @param tx     固定连接上的 flush 事务。
 * @param bf     sqlite 批量写入器（提供长期保存点语句与回滚）。
 * @param name   日志类型名（固定表名）。
 * @param n      待写入记录数，为 0 时直接跳过。
 * @param write  实际的批量写入动作。
 * @param failed 指向本次 flush 的失败标记。
 * @return 该类型的全部记录是否已成功写入当前事务。
 */
func (w *UnifiedWriter) flushBulkType(tx *sql.Tx, bf *sqliteBulkFlusher, name string, n int, write func() error, failed *bool) bool {
	if n == 0 {
		return true
	}

	savepointed := bf.execSavePointInTx(name) == nil

	if err := write(); err != nil {
		*failed = true
		w.log.Error("flush observability records failed",
			slog.String("type", name),
			slog.Any("err", err),
			slog.Int("n", n),
		)
		if savepointed {
			if rbErr := bf.rollbackToInTx(tx, name); rbErr != nil {
				w.log.Error("rollback to savepoint failed",
					slog.String("type", name),
					slog.Any("err", rbErr),
				)
			}
		}
		return false
	}
	return true
}

/**
 * flushBulk 在固定连接上以手动事务写入四类可观测记录。
 *
 * 与 GORM 路径的唯一差别是事务载体：这里在 flusher 的固定连接上 BeginTx，
 * 长期语句也在同一连接上 prepare，因此语句句柄可跨批复用，SQL 解析成本
 * 从「每批每类一次」降为「进程生命周期一次」。
 *
 * 返回 usable=false 表示连接或语句在写入任何一行之前就已失败，此时事务
 * 已回滚，调用方可以安全地把整批记录回退给 GORM 路径重写。
 * 返回 usable=true 且 err!=nil 表示事务提交失败，落库结果不确定，按既有
 * 失败口径统计，不再回退以免重复写入。
 *
 * @param bf      sqlite 批量写入器。
 * @param events / accessLogs / dropEvents / botScores 四类待写记录。
 * @param persistedRecords / failedRecords / invalidationPrefixes / failed
 *        与 flushBuffered 共享的统计累加器。
 * @return usable 与错误。
 */
func (w *UnifiedWriter) flushBulk(
	bf *sqliteBulkFlusher,
	events []store.SecurityEvent,
	accessLogs []store.AccessLog,
	dropEvents []store.DropEvent,
	botScores []store.BotScoreLog,
	persistedRecords *int,
	failedRecords *int,
	invalidationPrefixes *[]string,
	failed *bool,
) (bool, error) {
	ctx := context.Background()
	tx, err := bf.beginTx(ctx)
	if err != nil {
		return false, err
	}

	type group struct {
		name     string
		n        int
		rows     []any
		prefixes []string
	}
	groups := []group{
		{name: "security_events", n: len(events), rows: rowsToAny(events), prefixes: []string{"se_count:v2"}},
		{name: "access_logs", n: len(accessLogs), rows: rowsToAny(accessLogs), prefixes: []string{"al_count:v2", "al_list:v1"}},
		{name: "drop_events", n: len(dropEvents), rows: rowsToAny(dropEvents), prefixes: []string{"de_count"}},
		{name: "bot_scores", n: len(botScores), rows: rowsToAny(botScores)},
	}

	// 预热本批需要的语句。任何失败都发生在写入之前，整批可安全回退。
	for i := range groups {
		g := &groups[i]
		if g.n == 0 {
			continue
		}
		if _, err := bf.ensureStmtFor(g.name); err != nil {
			_ = tx.Rollback()
			return false, err
		}
		if _, err := bf.ensureSavePointStmtFor(g.name); err != nil {
			_ = tx.Rollback()
			return false, err
		}
	}

	for i := range groups {
		g := &groups[i]
		if g.n == 0 {
			continue
		}
		ok := w.flushBulkType(tx, bf, g.name, g.n, func() error {
			_, execErr := bf.execRowsInTx(g.name, g.rows)
			return execErr
		}, failed)
		if ok {
			*persistedRecords += g.n
			if g.n > 0 && len(g.prefixes) > 0 {
				*invalidationPrefixes = append(*invalidationPrefixes, g.prefixes...)
			}
		} else {
			*failedRecords += g.n
		}
	}

	if err := tx.Commit(); err != nil {
		return true, err
	}
	return true, nil
}

func (w *UnifiedWriter) recordFlushStats(persistedRecords, failedRecords int, duration time.Duration, failed bool) {
	w.flushesTotal.Add(1)
	w.totalFlushedRecords.Add(int64(persistedRecords))
	w.failedRecordsTotal.Add(int64(failedRecords))
	w.lastFlushRecords.Store(int64(persistedRecords))
	w.lastFlushFailedRecords.Store(int64(failedRecords))
	w.lastFlushDurationNs.Store(duration.Nanoseconds())
	w.lastFlushUnixNano.Store(time.Now().UnixNano())
	if failed {
		w.flushErrorsTotal.Add(1)
	}
}

func (w *UnifiedWriter) pushToRedis(
	rc rueidis.Client,
	events []store.SecurityEvent,
	accessLogs []store.AccessLog,
	dropEvents []store.DropEvent,
	botScores []store.BotScoreLog,
) error {
	// 熔断期内直接跳过：Redis 半死时每批都等满 5s 会把日志排空速率拖到
	// 请求速率以下，进而撑满队列。此窗口内由 DB 单写兜底。
	if until := w.redisDownUntil.Load(); until != 0 && time.Now().UnixNano() < until {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ttl := 7 * 24 * time.Hour
	b := rc.B()
	cmds := make([]rueidis.Completed, 0, 24)

	pushJSON := func(key string, items []any, trim int64) {
		for _, item := range items {
			if al, ok := item.(store.AccessLog); ok {
				al.TLSSNIPresence = tlsfp.SNIPresenceFromValues(al.TLSSNI, al.TLSJA4, al.TLSVersion != "" || al.TLSJA4 != "")
				item = al
			}
			data, err := json.Marshal(item)
			if err != nil {
				continue
			}
			cmds = append(cmds, b.Lpush().Key(key).Element(string(data)).Build())
		}
		cmds = append(cmds,
			b.Ltrim().Key(key).Start(0).Stop(trim).Build(),
			b.Expire().Key(key).Seconds(int64(ttl/time.Second)).Build(),
		)
	}

	if len(events) > 0 {
		items := make([]any, len(events))
		for i := range events {
			items[i] = events[i]
		}
		pushJSON("openwaf:security_events", items, 99999)

		// 安全事件按 request_id 读缓存（repository.FindByRequestID 会读
		// se_req:<id>）。事务已提交，这里删除对应键，让下一次追踪回源读到
		// 包含本次事件的完整集合——一个 request_id 可能对应多条事件，追加
		// 写Redis 无法表达合并语义，删除是唯一不会丢事件的失效方式。
		seenRequest := make(map[string]struct{}, len(events))
		for i := range events {
			requestID := events[i].RequestID
			if requestID == "" {
				continue
			}
			if _, ok := seenRequest[requestID]; ok {
				continue
			}
			seenRequest[requestID] = struct{}{}
			cmds = append(cmds, b.Del().Key(cache.HotKey(store.SecurityEventRequestCacheKey(requestID))).Build())
		}
	}
	if len(accessLogs) > 0 {
		// 访问日志除写入列表外，还按 request_id 写详情键：追踪页与
		// request_id 精确查询可以单次 GET 命中，不必回源数据库做全表过滤。
		// 时间戳在 dataplane.buildAccessLogEntry 已固定，因此这里写入的
		// created_at 与最终落库值一致，可直接用于展示与排序。
		ttlSeconds := int64(ttl / time.Second)
		for i := range accessLogs {
			al := accessLogs[i]
			al.TLSSNIPresence = tlsfp.SNIPresenceFromValues(al.TLSSNI, al.TLSJA4, al.TLSVersion != "" || al.TLSJA4 != "")
			data, err := json.Marshal(al)
			if err != nil {
				continue
			}
			cmds = append(cmds, b.Lpush().Key("openwaf:access_logs").Element(string(data)).Build())
			if al.RequestID != "" {
				cmds = append(cmds, b.Set().
					Key(cache.HotKey(store.AccessLogRequestCacheKey(al.RequestID))).
					Value(string(data)).
					ExSeconds(ttlSeconds).
					Build())
			}
		}
		cmds = append(cmds,
			b.Ltrim().Key("openwaf:access_logs").Start(0).Stop(99999).Build(),
			b.Expire().Key("openwaf:access_logs").Seconds(ttlSeconds).Build(),
		)
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

	if len(cmds) == 0 {
		return nil
	}
	resps := rc.DoMulti(ctx, cmds...)
	for _, resp := range resps {
		if err := resp.Error(); err != nil {
			w.log.Warn("redis push failed", slog.Any("err", err))
			w.redisDownUntil.Store(time.Now().Add(redisPushFailureBackoff).UnixNano())
			return err
		}
	}
	w.redisDownUntil.Store(0)
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
