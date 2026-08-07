package luaplugin

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// scriptSet 是按 stage 分桶后的脚本集合，一经发布即不可变。
//
// 整体替换而非原地改写，读侧才能无锁取用：Reload 构造全新集合再原子换指针，
// 正在执行的调用继续持有旧集合跑完。
type scriptSet struct {
	revision uint64
	pre      []*Script
	post     []*Script
}

// kvHolder 包一层以便用 atomic.Pointer 持有 interface 值。
//
// KVBackend 是 interface，atomic.Pointer[KVBackend] 需要 **KVBackend 才能表达
// 「可为 nil 的后端」，多一层间接反而更绕；包成结构体读写都只有一次解引用。
type kvHolder struct {
	kv KVBackend
}

// Engine 持有已加载的脚本与共享状态机池，是外部唯一入口。
//
// 读路径（HasScripts/Evaluate）全程无锁：脚本集合与 KV 后端都用 atomic.Pointer
// 持有，与项目 snapshot.Holder 的做法一致。这一点对数据面是必要的——管道里的
// lua 阶段对每个请求都要问一次 HasScripts，未配置脚本时也要问，读侧若含互斥
// 原语就会在多核高 QPS 下于同一 cache line 上产生跨核争抢（实测 RWMutex 读路径
// 50.7 ns/op、并发重载时 95.2 ns/op，换成 atomic 后分别为 0.46 与 0.60 ns/op）。
type Engine struct {
	scripts atomic.Pointer[scriptSet]
	kv      atomic.Pointer[kvHolder]

	// generation 串行标记每次 Reload，随脚本集合快照一起发布。
	generation atomic.Uint64
	reloadMu   sync.Mutex

	pool *vmPool
	log  *slog.Logger
}

// NewEngine 创建插件引擎。kv 可为 nil，此时脚本侧 kv.available() 返回 false。
func NewEngine(kv KVBackend, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	e := &Engine{pool: newVMPool(), log: log}
	e.scripts.Store(&scriptSet{})
	e.kv.Store(&kvHolder{kv: kv})
	return e
}

// SetKV 热替换 KV 后端，用于 Redis 运行时重连。
func (e *Engine) SetKV(kv KVBackend) {
	if e == nil {
		return
	}
	e.kv.Store(&kvHolder{kv: kv})
}

// Reload 用新的脚本集合整体替换现有集合。
//
// 按 stage 预先分桶，避免每请求都过滤一遍。
func (e *Engine) Reload(scripts []*Script) {
	if e == nil {
		return
	}
	var pre, post []*Script
	for _, s := range scripts {
		if s == nil {
			continue
		}
		switch s.stage {
		case StagePre:
			pre = append(pre, s)
		case StagePost:
			post = append(post, s)
		}
	}
	e.reloadMu.Lock()
	revision := e.generation.Add(1)
	e.scripts.Store(&scriptSet{revision: revision, pre: pre, post: post})
	e.reloadMu.Unlock()
}

// Revision 返回当前脚本集合的代际编号。
//
// 每次 Reload 都会递增，即使脚本内容没有变化也会产生新的代际，调用方
// 可据此让依赖脚本集合的缓存立即失效。返回值与 scripts 快照来自同一次
// 原子读取，因此不会把旧脚本与新代际拼在一起。
func (e *Engine) Revision() uint64 {
	if e == nil {
		return 0
	}
	set := e.scripts.Load()
	if set == nil {
		return 0
	}
	return set.revision
}

// scriptsFor 返回指定阶段的脚本快照。
//
// 返回的 slice 属于已发布的不可变集合，调用方可安全遍历而无需持锁。
func (e *Engine) scriptsFor(stage Stage) []*Script {
	set := e.scripts.Load()
	if set == nil {
		return nil
	}
	if stage == StagePre {
		return set.pre
	}
	return set.post
}

// HasScripts 报告指定阶段是否有脚本。
//
// 数据面据此跳过整个阶段。这是每请求都会走的判断，故直接取长度而不经
// scriptsFor 返回 slice。零值 Engine（未经 NewEngine）此时 Load 得到 nil，
// 报告无脚本而非 panic。
func (e *Engine) HasScripts(stage Stage) bool {
	if e == nil {
		return false
	}
	set := e.scripts.Load()
	if set == nil {
		return false
	}
	if stage == StagePre {
		return len(set.pre) > 0
	}
	return len(set.post) > 0
}

/**
 * Evaluate 依次执行指定阶段的脚本，返回首个给出判定的结果。
 *
 * 失败即跳过：单个脚本报错、超时或 panic 都只记日志并继续下一个，
 * 绝不因自定义策略故障导致请求判定失败——这是数据面的可用性底线。
 *
 * @param ctx   请求 context，取消会中断脚本。
 * @param stage 执行阶段。
 * @param req   请求视图。
 * @return 首个非空判定；无脚本判定时返回零值。
 */
func (e *Engine) Evaluate(ctx context.Context, stage Stage, req RequestView) Decision {
	if e == nil {
		return Decision{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return Decision{}
	}
	scripts := e.scriptsFor(stage)
	if len(scripts) == 0 {
		return Decision{}
	}

	var kv KVBackend
	if h := e.kv.Load(); h != nil {
		kv = h.kv
	}
	// Lua 策略依赖受控 KV 时，后端不可用必须强制 fail-open。
	// 不能让脚本绕过 ctx.kv.available() 直接返回终止动作。
	if kv == nil || !kv.Available() {
		return Decision{}
	}

	for _, s := range scripts {
		if ctx.Err() != nil {
			return Decision{}
		}
		if s == nil || (s.siteID != nil && *s.siteID != req.SiteID) {
			continue
		}
		dec, err := s.Run(ctx, e.pool, req, kv)
		if ctx.Err() != nil {
			return Decision{}
		}
		// KV 操作可能在脚本执行期间失败；健康状态变为不可用后，
		// 丢弃本次以及后续脚本判定，强制请求继续通过。
		if !kv.Available() {
			return Decision{}
		}
		if err != nil {
			e.log.Warn("lua plugin failed, skipping",
				slog.String("script", s.name),
				slog.String("stage", string(stage)),
				slog.Any("err", err))
			continue
		}
		if dec.HasAction() {
			return dec
		}
	}
	return Decision{}
}

// Stats 汇总各脚本的运行统计，供 /metrics 与管理端展示。
type Stats struct {
	ID       uint
	Name     string
	Stage    string
	Runs     int64
	Failures int64
	Timeouts int64
	AvgTime  time.Duration
}

// Stats 返回全部脚本的统计快照。
func (e *Engine) Stats() []Stats {
	if e == nil {
		return nil
	}
	set := e.scripts.Load()
	if set == nil {
		return nil
	}
	all := make([]*Script, 0, len(set.pre)+len(set.post))
	all = append(all, set.pre...)
	all = append(all, set.post...)

	out := make([]Stats, 0, len(all))
	for _, s := range all {
		runs, failures, timeouts, avg := s.Stats()
		out = append(out, Stats{
			ID:       s.id,
			Name:     s.name,
			Stage:    string(s.stage),
			Runs:     runs,
			Failures: failures,
			Timeouts: timeouts,
			AvgTime:  avg,
		})
	}
	return out
}
