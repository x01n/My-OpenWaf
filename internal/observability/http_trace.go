package observability

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/tracer/stats"
	"github.com/cloudwego/hertz/pkg/common/tracer/traceinfo"
)

// 阶段名与 Hertz 的事件对一一对应，直接作为 /metrics 的 phase label 值。
const (
	HTTPTracePhaseTotal      = "total"
	HTTPTracePhaseReadHeader = "read_header"
	HTTPTracePhaseReadBody   = "read_body"
	// HTTPTracePhaseServerHandle 覆盖 handler 全周期，含同步上游等待；
	// 语义细节见 HTTPTracePhaseServerHandleDoc——不要把它读成「WAF 自身开销」。
	HTTPTracePhaseServerHandle = "server_handle"
	HTTPTracePhaseWrite        = "write"
)

/**
 * httpTraceUnknownProto 是协议 label 取不到值时的兜底取值。
 *
 * 它同时承担一个诊断用途，因此不要在下游把它当成"脏数据"过滤掉：
 * keep-alive 空闲回收这条路径上的请求根本没被解析，协议读不到，全部落在这里。
 * 高并发停摆时客户端会大量超时断开，走的正是这条路径，所以 unknown 计数飙升本身
 * 就是"对端正在批量放弃连接"的免费信号。
 *
 * 由此推出 samples_total 的语义边界，下游取数时必须区分：
 *   - samples_total（含 unknown）= Hertz 调用 Finish 的次数；
 *   - phase="total" 且 proto!="unknown" = 真正被解析并处理过的请求数。
 * 两者之差就是连接层面的放弃量。
 */
const httpTraceUnknownProto = "unknown"

/**
 * httpTraceBucketBoundsUs 是分阶段耗时直方图的上界，单位为微秒。
 *
 * 档位密度按实测标定（上游为瞬时 200 的 Go 服务）：read_header 约 0.008ms、
 * write 约 0.068ms、server_handle 约 0.33ms；慢客户端的 read_body 可达 500ms 以上。
 * 因此低延迟段必须比常规的毫秒档更细——只有 0.05ms 一档才能把 read_header 与
 * write 分开，而两者在毫秒档里会同落进同一格。
 *
 * 注意 server_handle 的这些取值里包含上游往返，语义见 HTTPTracePhaseServerHandleDoc。
 *
 * 超出最后一格的样本落进 +Inf 桶。选择微秒而不是毫秒作为累加单位，是为了让 sum
 * 可以用 int64 精确累加——浮点 atomic 在长时间运行后会因精度丢失而漂移。
 */
var httpTraceBucketBoundsUs = [...]int64{
	50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1000000,
}

// httpTraceBucketCount 是桶个数：14 个有限上界 + 1 个 +Inf 桶。
const httpTraceBucketCount = len(httpTraceBucketBoundsUs) + 1

/**
 * httpTraceEventPair 把一个阶段名绑定到它的起止事件。
 *
 * 两个事件都必须存在才会计入样本。缺失时该阶段的 _count 不增长，而不是按 0 补齐：
 * 把「未采集」记成「耗时为零」会同时污染均值和直方图，也让采集缺口无法从指标上看出来。
 */
type httpTraceEventPair struct {
	name   string
	start  stats.Event
	finish stats.Event
}

/**
 * httpTraceDetailedEvents 是需要 LevelDetailed 才能采集到的阶段。
 *
 * 单独成表是为了按级别裁剪采集范围：LevelBase 下 events 里只有 httpTraceTotalEvent，
 * Finish 就不会为四个采不到的阶段白跑一遍事件查询。
 */
var httpTraceDetailedEvents = []httpTraceEventPair{
	{HTTPTracePhaseReadHeader, stats.ReadHeaderStart, stats.ReadHeaderFinish},
	{HTTPTracePhaseReadBody, stats.ReadBodyStart, stats.ReadBodyFinish},
	{HTTPTracePhaseServerHandle, stats.ServerHandleStart, stats.ServerHandleFinish},
	{HTTPTracePhaseWrite, stats.WriteStart, stats.WriteFinish},
}

/**
 * HTTPTracePhaseServerHandleDoc 是对 server_handle 语义的权威说明，供任何引用该阶段
 * 的地方（文档、面板、告警）引用，避免各处自行解释而写出误导性的描述。
 *
 * 括号覆盖的是**整个 handler 周期，包含同步等待上游的时间**，不是纯 WAF 计算时间：
 *   - 起点：http1 server.go:315，在 s.Core.ServeHTTP(cc, ctx)（335 行）之前记录；
 *   - 终点：同一个 eventsToTrigger 回调，在 ServeHTTP 返回之后触发。
 * 而本项目的数据面 handler 是**同步**等上游的（internal/dataplane/handler.go:1297-1319
 * 的 proxy.ForwardHTTP / ForwardWebSocket / ForwardH2ExtendedConnectWebSocket），
 * 上游返回之前 handler 不会返回。因此 server_handle ≈ WAF 各阶段耗时 + 上游往返 +
 * 响应变换，其中上游往返通常是最大的一项。
 *
 * 实测判据（同一个 WAF 实例、同一份引擎配置，只换上游）：
 *   - 上游瞬时 200 时 server_handle = 0.378ms，read_header = 0.010ms；
 *   - 上游固定延迟 300ms 时 server_handle = 301.204ms，read_header = 0.019ms。
 * server_handle 精确抬升了 300.8ms，而与之无关的 read_header 纹丝不动——这就是
 * 「它含上游等待」最直接的证据。把它当作「WAF 自身开销」会导致优化打错目标。
 *
 * 本探针**不提供**纯 WAF 计算时间。若要拆出上游那一段，可用的既有数据是：
 *   - 逐请求：访问日志的 upstream_latency_ms（internal/store/events.go:123，
 *     由 internal/dataplane/handler.go:1288 的 upstreamStart 到 1382 求得，
 *     覆盖真正发起上游请求到拿到响应）；
 *   - 健康探测延迟：/metrics 的 openwaf_upstream_*_latency_ms（internal/upstream/health.go:47-49），
 *     **那是主动探测的延迟，不是用户请求的延迟，不可用于扣减**；
 *   - 干跑基准：在内核独立的实例上禁用全部保护项（OWASP/CVE/Bot/限流），
 *     差值即保护项开销——它同样包含上游，但上游被两侧抵消。
 * 想在总耗时里分离出「WAF 计算」与「上游等待」，需要新增一个包住上游调用的打点，
 * 这是本探针刻意不做的事。
 */
const HTTPTracePhaseServerHandleDoc = "handler lifetime including the synchronous upstream round trip, not pure WAF compute time"

// httpTraceTotalEvent 是 LevelBase 即可采集的总耗时事件对。
var httpTraceTotalEvent = httpTraceEventPair{HTTPTracePhaseTotal, stats.HTTPStart, stats.HTTPFinish}

// httpTracePhase 是单个阶段的累计量；全部字段由原子操作更新。
type httpTracePhase struct {
	count   atomic.Int64
	sumUs   atomic.Int64
	invalid atomic.Int64
	buckets [httpTraceBucketCount]atomic.Int64
}

/**
 * observe 累加一次耗时观测；耗时为负的样本被拒绝并单独计数。
 *
 * 负耗时不是理论可能性：x01n/http2 fork v0.3.0 上实测复现过——同一条 h2 连接上
 * ServerHandleFinish 会读到早于本次 ServerHandleStart 的时间戳（见包内测试
 * TestHTTPTraceRejectsNegativeDurations），使 sum 单调递减、均值变成负数。
 * 直接累加会让一个阶段的数字彻底失去意义，而且是持续性的：每次采样都在反向拉低。
 *
 * 这是**上游 fork 缺陷的兜底，不是根治**：fork 的 handlerDone（server.go:986-1010）
 * 先 resetStream→closeStream→触发 DoFinish，而 runHandler 的 defer 里才
 * Record(ServerHandleFinish)，于是 Finish 读到的是上一次请求留下的陈旧事件。
 * 任何 Hertz Tracer 集成方都会踩到，与调用方怎么写无关。将来 fork 修好配对时序后，
 * 本守卫可以连同 invalid 指标一起移除——届时它应当长期恒为 0。
 *
 * 因此这里拒绝负值并计入 invalid，让它作为「框架事件配对有问题」的外部可见信号，
 * 而不是被静默吞掉——静默吞掉的话，运维只会看到均值偏小，无从察觉上游有缺陷。
 *
 * @param deltaUs 阶段耗时（微秒）。
 */
func (p *httpTracePhase) observe(deltaUs int64) {
	if deltaUs < 0 {
		p.invalid.Add(1)
		return
	}
	p.count.Add(1)
	p.sumUs.Add(deltaUs)
	p.buckets[httpTraceBucketIndex(deltaUs)].Add(1)
}

// httpTraceBucketIndex 返回耗时（微秒）落入的桶下标。
func httpTraceBucketIndex(deltaUs int64) int {
	for i, bound := range httpTraceBucketBoundsUs {
		if deltaUs <= bound {
			return i
		}
	}
	return len(httpTraceBucketBoundsUs)
}

/**
 * httpTraceProto 是按请求协议分开的一份统计。
 *
 * 分协议是必要的：x01n/http2 fork v0.3.0 只记录了 ReadHeader* 与 ServerHandleStart，
 * 缺 ReadBody*、Write* 与 ServerHandleFinish，h2 流量的分阶段覆盖天然不完整。若把两种
 * 协议混在一个计数器里，h2 的缺失会被 h1 的样本掩盖，均值看起来依然合理。
 */
type httpTraceProto struct {
	// samples 记录成功解析并完成处理的请求样本数。
	samples atomic.Int64
	// skipped 记录只收到 Finish、没有 HTTPStart 的调用次数：keep-alive 空闲连接回收与
	skipped atomic.Int64
	// errors 记录 TraceInfo 里带错误的样本数。
	errors atomic.Int64
	// reqBytes 记录 Hertz TraceInfo 里 RecvSize 的累加值；0 表示无法确定长度。
	reqBytes atomic.Int64
	// respBytes 记录 Hertz TraceInfo 里 SendSize 的累加值；0 表示无法确定长度。
	respBytes atomic.Int64
	// skippedBytes 记录在 keep-alive 空闲连接被回收时，已经读到的请求字节数。
	skippedBytes atomic.Int64
	// phases 在构造时填满，之后只读，因此无需加锁。
	phases map[string]*httpTracePhase
}

/**
 * HTTPTrace 是 Hertz 官方 Tracer 接口的实现，采集数据面请求的分阶段耗时。
 *
 * 它在请求热路径上被调用，因此 Finish 只做固定次数的原子累加，不做任何分配、
 * 不加互斥锁、不做字符串拼接；聚合与渲染发生在 /metrics 被拉取时。
 *
 * 采集级别必须是 level 字段指定的那一档：LevelBase 只出总耗时，LevelDetailed 额外
 * 出读头/读体/处理/写回四段。级别不能只靠 server 侧的 WithTraceLevel 决定——框架会
 * 按级别丢弃事件，但 Finish 仍会被调用，若此处不裁剪就只是白跑事件查询。
 */
type HTTPTrace struct {
	events []httpTraceEventPair
	level  stats.Level
	protos sync.Map // proto string -> *httpTraceProto
}

// 编译期断言：HTTPTrace 必须满足 Hertz 的 Tracer 接口与 /metrics 的 provider 接口。
var (
	_ interface {
		Start(context.Context, *app.RequestContext) context.Context
		Finish(context.Context, *app.RequestContext)
	} = (*HTTPTrace)(nil)
	_ HTTPTraceStatsProvider = (*HTTPTrace)(nil)
)

/**
 * NewHTTPTraceProtoForTest 建立一个协议维度的统计容器，供测试直接驱动 observe。
 *
 * 导出的原因：负耗时样本只能在 observe 这一层被观察到，而生产路径上产生它的
 * 时间戳组合由 fork 决定、不可控。TestHTTPTraceRejectsNegativeDurations 通过它
 * 直达该分支，锁住"负耗时必须被拒绝并计数"这条不变式。
 *
 * @param phaseNames 要预建的阶段名；生产侧由事件表派生。
 * @return 只含零值计数器的统计容器。
 */
func NewHTTPTraceProtoForTest(phaseNames ...string) *httpTraceProto {
	return &httpTraceProto{phases: newHTTPTracePhaseMap(phaseNames)}
}

// newHTTPTracePhaseMap 按阶段名建表。
func newHTTPTracePhaseMap(names []string) map[string]*httpTracePhase {
	phases := make(map[string]*httpTracePhase, len(names))
	for _, name := range names {
		phases[name] = &httpTracePhase{}
	}
	return phases
}

/**
 * NewHTTPTraceRequestContext 构造一个带 TraceInfo 的请求上下文，供测试驱动 Tracer。
 *
 * 生产路径上 RequestContext 由 Hertz 从 ctxPool 取用并注入 TraceInfo；单元测试没有
 * 这条路径，直接用 app.NewContext 得到的上下文的 TraceInfo 是 nil，Finish 会当成
 * "无 TraceInfo" 静默返回，测试就会退化成"什么都没发生也是通过"。这里显式装上
 * TraceInfo，让测试与生产的起点一致。
 *
 * @param level 要写入 TraceInfo 的事件级别。
 * @return 可用于 Tracer.Start/Finish 的请求上下文。
 */
func NewHTTPTraceRequestContext(level stats.Level) *app.RequestContext {
	c := app.NewContext(0)
	ti := traceinfo.NewTraceInfo()
	ti.Stats().SetLevel(level)
	c.SetTraceInfo(ti)
	return c
}

/**
 * RecordHTTPTraceEvent 在测试中模拟 Hertz 协议栈记录一个事件。
 *
 * 与生产一致：错误非空时事件状态为 StatusError，err 文本落进 info。
 *
 * @param c 目标请求上下文。
 * @param event 要记录的事件。
 * @param err 该事件对应的错误；nil 表示正常。
 */
func RecordHTTPTraceEvent(c *app.RequestContext, event stats.Event, err error) {
	if c == nil || c.GetTraceInfo() == nil {
		return
	}
	if err != nil {
		c.GetTraceInfo().Stats().Record(event, stats.StatusError, err.Error())
		return
	}
	c.GetTraceInfo().Stats().Record(event, stats.StatusInfo, "")
}

/**
 * NewHTTPTrace 按采集级别构造一个 Hertz Tracer。
 *
 * @param level Hertz 事件级别；LevelBase 只采总耗时，其余取值按 LevelDetailed 处理。
 *   LevelDisabled 不会走到这里——关闭时根本不注册 Tracer。
 * @return 可注册到 server.WithTracer 的 Tracer。
 */
func NewHTTPTrace(level stats.Level) *HTTPTrace {
	t := &HTTPTrace{level: level, events: []httpTraceEventPair{httpTraceTotalEvent}}
	if level >= stats.LevelDetailed {
		t.events = append(t.events, httpTraceDetailedEvents...)
	}
	return t
}

/**
 * Level 返回本 Tracer 的采集级别。
 *
 * 建 server 时必须把它交给 server.WithTraceLevel：Hertz 在未显式设置 TraceLevel 时的
 * 默认值是 LevelDetailed，比 LevelBase 更贵，与本开关"省一点是一点"的意图相反。
 *
 * @return Hertz 事件级别。
 */
func (t *HTTPTrace) Level() stats.Level {
	return t.level
}

// Start 实现 tracer.Tracer；不改变 context，也不做每请求分配。
func (t *HTTPTrace) Start(ctx context.Context, _ *app.RequestContext) context.Context {
	return ctx
}

/**
 * Finish 实现 tracer.Tracer，在请求结束时把各阶段耗时累加进原子计数。
 *
 * 有效性守卫是必需的，不是防御性代码：http1 协议栈在 keep-alive 空闲连接被回收时
 * 也会调用 DoFinish，而 DoStart 在更晚的位置才执行，因此这条路径上的上下文里只有
 * HTTPFinish、没有 HTTPStart。若直接相减，会得到 time.Time{} 的零值与真实时间之差
 * （约 1.7e18 ns），一条空闲连接就能把均值和直方图彻底污染。这类样本计入 skipped。
 *
 * @param ctx 请求 context（未使用）。
 * @param c 当前请求上下文，事件从它的 TraceInfo 读取。
 */
func (t *HTTPTrace) Finish(_ context.Context, c *app.RequestContext) {
	ti := c.GetTraceInfo()
	if ti == nil {
		return
	}
	st := ti.Stats()

	proto := httpTraceUnknownProto
	if p := c.Request.Header.GetProtocol(); p != "" {
		proto = p
	}
	// 协议种类有限（HTTP/1.0、HTTP/1.1、HTTP/2.0），sync.Map 的读路径无锁。
	v, ok := t.protos.Load(proto)
	if !ok {
		v, _ = t.protos.LoadOrStore(proto, newHTTPTraceProto(t.events))
	}
	p := v.(*httpTraceProto)

	if st.GetEvent(stats.HTTPStart) == nil {
		p.skipped.Add(1)
		p.skippedBytes.Add(int64(st.RecvSize()))
		return
	}

	p.samples.Add(1)
	p.reqBytes.Add(int64(st.RecvSize()))
	p.respBytes.Add(int64(st.SendSize()))
	if st.Error() != nil {
		p.errors.Add(1)
	}

	for _, pair := range t.events {
		start, finish := st.GetEvent(pair.start), st.GetEvent(pair.finish)
		if start == nil || finish == nil {
			continue
		}
		p.phases[pair.name].observe(finish.Time().Sub(start.Time()).Microseconds())
	}
}

// newHTTPTraceProto 建立一个协议维度的统计容器。
func newHTTPTraceProto(events []httpTraceEventPair) *httpTraceProto {
	names := make([]string, 0, len(events))
	for _, e := range events {
		names = append(names, e.name)
	}
	return &httpTraceProto{phases: newHTTPTracePhaseMap(names)}
}

// HTTPTracePhaseStats 是单个协议下单个阶段的时点视图。
type HTTPTracePhaseStats struct {
	Name string
	// Count 是成功取到起止事件且耗时为非负的样本数。
	Count int64
	// SumMs 是耗时合计（毫秒），均值即 SumMs/Count。
	SumMs float64
	// Invalid 是被拒绝的负耗时样本数。非零说明该协议的事件配对有问题
	// （x01n/http2 fork v0.3.0 的 ServerHandle 事件对即存在此问题），
	// 该阶段的 Count 与 SumMs 只覆盖有效样本。
	Invalid int64
	// Buckets 是累积直方图，下标 i 表示「耗时 ≤ httpTraceBucketBoundsUs[i]」的样本数，
	// 最后一格为 +Inf。与 httpTraceBucketBoundsMs 一一对应。
	Buckets []int64
}

// HTTPTraceProtoStats 是单个请求协议的统计视图。
type HTTPTraceProtoStats struct {
	Proto string
	// Samples 是有效样本数（存在 HTTPStart 的请求）。
	Samples int64
	// Skipped 是只收到 Finish、没有 HTTPStart 的调用次数：keep-alive 空闲连接回收与
	// 请求头读取失败会走这条路径。它恒等于「Finish 调用次数 - Samples」。
	Skipped int64
	// SkippedBytes 是 Skipped 那些连接上已读到的字节；按现状它只会是 0——这条路径上
	// 的 RecvSize 总要等首部读完才写入，而首部读不完就到不了这里。保留它是为了在
	// 路径变化时字节数不会无声消失，也让它对得上。
	SkippedBytes int64
	// Errors 是 TraceInfo 里带错误的样本数。
	Errors int64
	// RequestBytes/ResponseBytes 是 TraceInfo 记录的首部+体字节合计。Hertz 在无法确定
	// 内容长度时写入 0（http1 server 的 SetRecvSize/SetSendSize 分支），因此这两个值
	// 是「已确定长度的那部分流量」，不是全部流量。
	RequestBytes  int64
	ResponseBytes int64
	Phases        []HTTPTracePhaseStats
}

// HTTPTraceStats 是一次 /metrics 渲染所需的完整快照。
type HTTPTraceStats struct {
	Protos []HTTPTraceProtoStats
	// BucketBoundsMs 是直方图各桶的 le 值（毫秒），与每个阶段的 Buckets 一一对应。
	BucketBoundsMs []float64
}

// HTTPTraceBucketBoundsMs 返回分阶段耗时直方图的桶上界（毫秒）。
//
// 由 httpTraceBucketBoundsUs 派生，保证「桶下标 → le 标签」与采集侧用的是同一份数据，
// 避免两处各自维护一份边界而悄悄错位。
//
// @return 桶上界（毫秒），长度等于有限桶个数，不含 +Inf。
func HTTPTraceBucketBoundsMs() []float64 {
	out := make([]float64, len(httpTraceBucketBoundsUs))
	for i, us := range httpTraceBucketBoundsUs {
		out[i] = float64(us) / 1000.0
	}
	return out
}

/**
 * Stats 汇总所有协议的累计计数器，供 /metrics 渲染。
 *
 * 遍历时会对 sync.Map 取全量快照并按协议名排序，保证同一进程状态下输出稳定——
 * Prometheus 文本格式不要求顺序，但稳定的顺序让人工比对两次抓取的结果成为可能。
 *
 * @return 各协议的时点视图。
 */
func (t *HTTPTrace) Stats() HTTPTraceStats {
	out := HTTPTraceStats{BucketBoundsMs: HTTPTraceBucketBoundsMs()}

	protos := make([]string, 0, 2)
	t.protos.Range(func(k, _ any) bool {
		protos = append(protos, k.(string))
		return true
	})
	sort.Strings(protos)

	names := make([]string, 0, len(t.events))
	for _, e := range t.events {
		names = append(names, e.name)
	}

	for _, name := range protos {
		v, ok := t.protos.Load(name)
		if !ok {
			continue
		}
		p := v.(*httpTraceProto)
		entry := HTTPTraceProtoStats{
			Proto:         name,
			Samples:       p.samples.Load(),
			Skipped:       p.skipped.Load(),
			SkippedBytes:  p.skippedBytes.Load(),
			Errors:        p.errors.Load(),
			RequestBytes:  p.reqBytes.Load(),
			ResponseBytes: p.respBytes.Load(),
			Phases:        make([]HTTPTracePhaseStats, 0, len(names)),
		}
		for _, phaseName := range names {
			phase, ok := p.phases[phaseName]
			if !ok {
				continue
			}
			buckets := make([]int64, httpTraceBucketCount)
			for i := range buckets {
				buckets[i] = phase.buckets[i].Load()
			}
			entry.Phases = append(entry.Phases, HTTPTracePhaseStats{
				Name:    phaseName,
				Count:   phase.count.Load(),
				SumMs:   float64(phase.sumUs.Load()) / 1000.0,
				Invalid: phase.invalid.Load(),
				Buckets: buckets,
			})
		}
		out.Protos = append(out.Protos, entry)
	}
	return out
}
