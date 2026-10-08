package observability

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
)

// UnifiedWriterStatsProvider 向 /metrics 暴露异步写入器的诊断数据。
type UnifiedWriterStatsProvider interface {
	Stats() UnifiedWriterStats
}

/**
 * WriteQueueStatsProvider 向 /metrics 暴露通用仓储写队列的提交与持久化结果。
 *
 * 它刻意与 UnifiedWriterStatsProvider 分开：两个队列的生命周期与
 * 丢失语义不同。
 */
type WriteQueueStatsProvider interface {
	Stats() WriteQueueStats
}

// DataPlaneMetricsSnapshot 是请求路径计数器的时点视图。
type DataPlaneMetricsSnapshot struct {
	QPS1s         float64
	QPS5s         float64
	RequestsTotal int64
	Status2xx     int64
	Status4xx     int64
	Status5xx     int64
	WAFBlocks     int64
	WAFObserves   int64
	BuiltinHits   int64
	UptimeSec     int64
	UniqueIPs     int64
	AttackIPs     int64
}

// UpstreamMetricsSnapshot 是上游健康状态与延迟的时点视图。
type UpstreamMetricsSnapshot struct {
	HealthyCount     int64
	UnhealthyCount   int64
	KnownCount       int64
	CheckedCount     int64
	AverageLatencyMs float64
	MaxLastLatencyMs int64
	LatencySamples   int64
}

// CacheLayerStats 保存单个具名缓存层的累计命中/未命中计数器。
type CacheLayerStats struct {
	Name   string
	Hits   int64
	Misses int64
	// Errors 是后端故障次数（如 Redis 不可达），与「键不存在」的 Misses 区分。
	// 该值增长说明请求正在穿透到数据库，而非缓存策略失效。
	Errors int64
}

/**
 * LuaScriptStats 保存单个 Lua 策略脚本的累计执行计数器。
 *
 * 脚本失败/超时后只写一条 warn 日志就静默跳过，请求判定不受影响——这对可用性
 * 是对的，但也意味着策略长期失效不会有任何外部信号。把这些计数器暴露出来，
 * 运维才能对 Failures/Timeouts 的占比告警。
 */
type LuaScriptStats struct {
	// Name 是脚本名，来自用户输入，作为 label 输出前必须转义。
	Name  string
	Stage string
	// Runs 是总执行次数，含失败与超时的那几次。
	Runs int64
	// Failures 是不含超时的失败：handle 报错、panic、入口缺失、状态机获取失败。
	Failures int64
	// Timeouts 与 Failures 互斥——超时分支直接返回、不再累加 Failures
	// （internal/waf/luaplugin/exec.go），故成功次数是 Runs-Failures-Timeouts。
	Timeouts int64
	// AvgDurationMs 的分母是 Runs，超时的执行也会把它拉高。
	AvgDurationMs float64
}

// CacheStatsSnapshotProvider 返回各层缓存的命中/未命中计数器。
type CacheStatsSnapshotProvider func() []CacheLayerStats

// LuaScriptStatsProvider 返回各 Lua 策略插件的计数器。
type LuaScriptStatsProvider func() []LuaScriptStats

// HTTPTraceStatsProvider 返回数据面请求的分阶段耗时快照。
type HTTPTraceStatsProvider interface {
	Stats() HTTPTraceStats
}

// DataPlaneMetricsSnapshotProvider 返回当前的数据面指标快照。
type DataPlaneMetricsSnapshotProvider func() DataPlaneMetricsSnapshot

// UpstreamMetricsSnapshotProvider 返回当前的上游快照。
type UpstreamMetricsSnapshotProvider func() UpstreamMetricsSnapshot

// Metrics 收集 WAF 运行期指标，供 /metrics（Prometheus）端点使用。
type Metrics struct {
	RequestsTotal atomic.Int64
	Uptime        time.Time

	unifiedWriterStatsProvider atomic.Value
	writeQueueStatsProvider    atomic.Value
	dataPlaneMetricsProvider   atomic.Value
	upstreamMetricsProvider    atomic.Value
	cacheStatsProvider         atomic.Value
	luaScriptStatsProvider     atomic.Value
	httpTraceStatsProvider     atomic.Value
}

// NewMetrics 创建一个新的指标收集器。
func NewMetrics() *Metrics {
	return &Metrics{Uptime: time.Now()}
}

// RecordRequest 递增请求总数计数器。
func (m *Metrics) RecordRequest() { m.RequestsTotal.Add(1) }

// SetUnifiedWriterStatsProvider 把异步写入器诊断数据挂到 /metrics。
func (m *Metrics) SetUnifiedWriterStatsProvider(provider UnifiedWriterStatsProvider) {
	if provider == nil {
		return
	}
	m.unifiedWriterStatsProvider.Store(provider)
}

// SetWriteQueueStatsProvider 把通用仓储队列诊断数据挂到 /metrics。
func (m *Metrics) SetWriteQueueStatsProvider(provider WriteQueueStatsProvider) {
	if provider == nil {
		return
	}
	m.writeQueueStatsProvider.Store(provider)
}

// SetDataPlaneMetricsProvider 把请求路径计数器挂到 /metrics。
func (m *Metrics) SetDataPlaneMetricsProvider(provider DataPlaneMetricsSnapshotProvider) {
	if provider == nil {
		return
	}
	m.dataPlaneMetricsProvider.Store(provider)
}

// SetUpstreamMetricsProvider 把上游健康与延迟指标挂到 /metrics。
func (m *Metrics) SetUpstreamMetricsProvider(provider UpstreamMetricsSnapshotProvider) {
	if provider == nil {
		return
	}
	m.upstreamMetricsProvider.Store(provider)
}

// SetCacheStatsProvider 把各层缓存的命中/未命中指标挂到 /metrics。
func (m *Metrics) SetCacheStatsProvider(provider CacheStatsSnapshotProvider) {
	if provider == nil {
		return
	}
	m.cacheStatsProvider.Store(provider)
}

// SetLuaScriptStatsProvider 把各 Lua 策略插件的指标挂到 /metrics。
func (m *Metrics) SetLuaScriptStatsProvider(provider LuaScriptStatsProvider) {
	if provider == nil {
		return
	}
	m.luaScriptStatsProvider.Store(provider)
}

// SetHTTPTraceStatsProvider 把数据面分阶段耗时挂到 /metrics。
//
// 未启用遥测时不要调用：该 provider 一旦挂上就会在每次抓取时遍历一次协议与阶段表，
// 没有 Tracer 就只是白跑。
func (m *Metrics) SetHTTPTraceStatsProvider(provider HTTPTraceStatsProvider) {
	if provider == nil {
		return
	}
	m.httpTraceStatsProvider.Store(provider)
}

// PrometheusHandler 返回以 Prometheus 文本格式提供 /metrics 的 Hertz 处理函数。
func PrometheusHandler(m *Metrics) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		body := PrometheusBody(m)

		c.SetContentType("text/plain; version=0.0.4; charset=utf-8")
		c.SetStatusCode(200)
		c.SetBodyString(body)
	}
}

// PrometheusBody 以 Prometheus 文本格式渲染指标。
func PrometheusBody(m *Metrics) string {
	if m == nil {
		m = NewMetrics()
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	uptimeSec := time.Since(m.Uptime).Seconds()

	// 本结构体只保留「进程级」指标（请求总数、存活时长、goroutine、内存、GC）。
	// 拦截/观察/内置命中/缓存命中未命中/上游错误这些计数器不在本结构体，
	// 唯一真实来源是 dataplane.Metrics（prometheusDataPlaneMetrics 输出的
	// openwaf_dataplane_* 系列）与 CacheStatsSnapshotProvider
	// （owaf_cache_* 系列）；此处曾输出恒为 0 的同名指标，已移除。
	//
	// 注意：下面的 openwaf_requests_total 同样未接线——本包的 RecordRequest
	// 没有任何生产调用点，app 只把 promMetrics 用于 Set*Provider 与 /metrics
	// handler。真实请求数见 openwaf_dataplane_requests_total。
	body := fmt.Sprintf(`# HELP openwaf_requests_total Total HTTP requests processed
# TYPE openwaf_requests_total counter
openwaf_requests_total %d

# HELP openwaf_uptime_seconds Seconds since process start
# TYPE openwaf_uptime_seconds gauge
openwaf_uptime_seconds %.2f

# HELP openwaf_goroutines Current number of goroutines
# TYPE openwaf_goroutines gauge
openwaf_goroutines %d

# HELP openwaf_memory_alloc_bytes Current heap allocation in bytes
# TYPE openwaf_memory_alloc_bytes gauge
openwaf_memory_alloc_bytes %d

# HELP openwaf_memory_sys_bytes Total memory obtained from OS
# TYPE openwaf_memory_sys_bytes gauge
openwaf_memory_sys_bytes %d

# HELP openwaf_gc_pause_total_ns Total GC pause time in nanoseconds
# TYPE openwaf_gc_pause_total_ns counter
openwaf_gc_pause_total_ns %d
`,
		m.RequestsTotal.Load(),
		uptimeSec,
		runtime.NumGoroutine(),
		memStats.Alloc,
		memStats.Sys,
		memStats.PauseTotalNs,
	)

	if v := m.unifiedWriterStatsProvider.Load(); v != nil {
		if provider, ok := v.(UnifiedWriterStatsProvider); ok {
			body += prometheusUnifiedWriterStats(provider.Stats())
		}
	}
	if v := m.writeQueueStatsProvider.Load(); v != nil {
		if provider, ok := v.(WriteQueueStatsProvider); ok {
			body += prometheusWriteQueueStats(provider.Stats())
		}
	}
	if v := m.dataPlaneMetricsProvider.Load(); v != nil {
		if provider, ok := v.(DataPlaneMetricsSnapshotProvider); ok {
			body += prometheusDataPlaneMetrics(provider())
		}
	}
	if v := m.upstreamMetricsProvider.Load(); v != nil {
		if provider, ok := v.(UpstreamMetricsSnapshotProvider); ok {
			body += prometheusUpstreamMetrics(provider())
		}
	}
	if v := m.cacheStatsProvider.Load(); v != nil {
		if provider, ok := v.(CacheStatsSnapshotProvider); ok {
			body += prometheusCacheStats(provider())
		}
	}
	if v := m.luaScriptStatsProvider.Load(); v != nil {
		if provider, ok := v.(LuaScriptStatsProvider); ok {
			body += prometheusLuaScriptStats(provider())
		}
	}
	if v := m.httpTraceStatsProvider.Load(); v != nil {
		if provider, ok := v.(HTTPTraceStatsProvider); ok {
			body += prometheusHTTPTraceStats(provider.Stats())
		}
	}

	return body
}

func prometheusDataPlaneMetrics(snapshot DataPlaneMetricsSnapshot) string {
	return fmt.Sprintf(`
# HELP openwaf_dataplane_qps Current request rate by sampling window
# TYPE openwaf_dataplane_qps gauge
openwaf_dataplane_qps{window="1s"} %.6f
openwaf_dataplane_qps{window="5s"} %.6f

# HELP openwaf_dataplane_requests_total Total requests seen by data-plane listeners
# TYPE openwaf_dataplane_requests_total counter
openwaf_dataplane_requests_total %d

# HELP openwaf_dataplane_status_total Total data-plane responses by status class
# TYPE openwaf_dataplane_status_total counter
openwaf_dataplane_status_total{class="2xx"} %d
openwaf_dataplane_status_total{class="4xx"} %d
openwaf_dataplane_status_total{class="5xx"} %d

# HELP openwaf_dataplane_waf_actions_total Total WAF actions seen by data-plane listeners
# TYPE openwaf_dataplane_waf_actions_total counter
openwaf_dataplane_waf_actions_total{action="block"} %d
openwaf_dataplane_waf_actions_total{action="observe"} %d

# HELP openwaf_dataplane_builtin_hits_total Total builtin rule hits seen by data-plane listeners
# TYPE openwaf_dataplane_builtin_hits_total counter
openwaf_dataplane_builtin_hits_total %d

# HELP openwaf_dataplane_unique_ips_total Total client IP observations seen by data-plane listeners
# TYPE openwaf_dataplane_unique_ips_total counter
openwaf_dataplane_unique_ips_total %d

# HELP openwaf_dataplane_attack_ips_total Total attack IP observations seen by data-plane listeners
# TYPE openwaf_dataplane_attack_ips_total counter
openwaf_dataplane_attack_ips_total %d

# HELP openwaf_dataplane_uptime_seconds Seconds since data-plane metrics start
# TYPE openwaf_dataplane_uptime_seconds gauge
openwaf_dataplane_uptime_seconds %d
`,
		snapshot.QPS1s,
		snapshot.QPS5s,
		snapshot.RequestsTotal,
		snapshot.Status2xx,
		snapshot.Status4xx,
		snapshot.Status5xx,
		snapshot.WAFBlocks,
		snapshot.WAFObserves,
		snapshot.BuiltinHits,
		snapshot.UniqueIPs,
		snapshot.AttackIPs,
		snapshot.UptimeSec,
	)
}

func prometheusUpstreamMetrics(snapshot UpstreamMetricsSnapshot) string {
	return fmt.Sprintf(`
# HELP openwaf_upstream_healthy_total Total upstream targets currently marked healthy
# TYPE openwaf_upstream_healthy_total gauge
openwaf_upstream_healthy_total %d

# HELP openwaf_upstream_unhealthy_total Total upstream targets currently marked unhealthy
# TYPE openwaf_upstream_unhealthy_total gauge
openwaf_upstream_unhealthy_total %d

# HELP openwaf_upstream_known_total Total upstream targets with a known state snapshot
# TYPE openwaf_upstream_known_total gauge
openwaf_upstream_known_total %d

# HELP openwaf_upstream_checked_total Total upstream targets that have been probed at least once
# TYPE openwaf_upstream_checked_total gauge
openwaf_upstream_checked_total %d

# HELP openwaf_upstream_average_latency_ms Average latency across upstream targets with latency samples
# TYPE openwaf_upstream_average_latency_ms gauge
openwaf_upstream_average_latency_ms %.2f

# HELP openwaf_upstream_max_last_latency_ms Maximum latest latency across upstream targets
# TYPE openwaf_upstream_max_last_latency_ms gauge
openwaf_upstream_max_last_latency_ms %d

# HELP openwaf_upstream_latency_samples_total Total upstream latency samples across all targets
# TYPE openwaf_upstream_latency_samples_total counter
openwaf_upstream_latency_samples_total %d
`,
		snapshot.HealthyCount,
		snapshot.UnhealthyCount,
		snapshot.KnownCount,
		snapshot.CheckedCount,
		snapshot.AverageLatencyMs,
		snapshot.MaxLastLatencyMs,
		snapshot.LatencySamples,
	)
}

func prometheusCacheStats(layers []CacheLayerStats) string {
	body := `
# HELP owaf_cache_hits_total Cache hits by cache layer
# TYPE owaf_cache_hits_total counter
`
	for _, l := range layers {
		body += fmt.Sprintf(`owaf_cache_hits_total{cache="%s"} %d`+"\n", escapePrometheusLabelValue(l.Name), l.Hits)
	}
	body += `
# HELP owaf_cache_misses_total Cache misses by cache layer
# TYPE owaf_cache_misses_total counter
`
	for _, l := range layers {
		body += fmt.Sprintf(`owaf_cache_misses_total{cache="%s"} %d`+"\n", escapePrometheusLabelValue(l.Name), l.Misses)
	}
	body += `
# HELP owaf_cache_errors_total Cache backend failures by cache layer (excludes key-not-found)
# TYPE owaf_cache_errors_total counter
`
	for _, l := range layers {
		body += fmt.Sprintf(`owaf_cache_errors_total{cache="%s"} %d`+"\n", escapePrometheusLabelValue(l.Name), l.Errors)
	}
	return body
}

/**
 * escapePrometheusLabelValue 转义 label 值中的特殊字符。
 *
 * Prometheus 文本格式只定义三种转义：反斜杠、双引号、换行，分别写作 \\ 、\" 、\n。
 * 未转义的双引号会提前闭合 label，未转义的换行会被解析成新的一行样本——脚本名
 * 由用户自由填写，不转义就等于把整份 /metrics 的格式交给用户控制。
 *
 * 不用 %q：Go 的引号语法还会把制表符、控制字符写成 \t 、\x01，这些在 Prometheus
 * 里是**非法**转义序列，解析器会直接报错，比不转义更糟。
 *
 * @param v 原始 label 值。
 * @return 已转义的值，不含外层引号。
 */
func escapePrometheusLabelValue(v string) string {
	if !strings.ContainsAny(v, "\\\"\n") {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 8)
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

/**
 * prometheusLuaScriptStats 渲染每个 Lua 策略脚本的运行统计。
 *
 * 无脚本时返回空串而不是空的 HELP/TYPE 头：label 组合本就随配置变化，
 * 没有脚本就没有系列。
 *
 * @param scripts 脚本统计快照。
 * @return Prometheus 文本片段，以空行开头以便直接拼接。
 */
func prometheusLuaScriptStats(scripts []LuaScriptStats) string {
	if len(scripts) == 0 {
		return ""
	}

	// label 部分四组指标共用，先转义一次避免重复开销。
	labels := make([]string, len(scripts))
	for i, s := range scripts {
		labels[i] = fmt.Sprintf(`{script="%s",stage="%s"}`,
			escapePrometheusLabelValue(s.Name), escapePrometheusLabelValue(s.Stage))
	}

	var b strings.Builder
	b.WriteString("\n# HELP openwaf_lua_script_runs_total Lua policy script executions by script and stage\n")
	b.WriteString("# TYPE openwaf_lua_script_runs_total counter\n")
	for i, s := range scripts {
		fmt.Fprintf(&b, "openwaf_lua_script_runs_total%s %d\n", labels[i], s.Runs)
	}

	b.WriteString("\n# HELP openwaf_lua_script_failures_total Lua policy script failures excluding timeouts: handle errors, panics and missing entrypoint\n")
	b.WriteString("# TYPE openwaf_lua_script_failures_total counter\n")
	for i, s := range scripts {
		fmt.Fprintf(&b, "openwaf_lua_script_failures_total%s %d\n", labels[i], s.Failures)
	}

	b.WriteString("\n# HELP openwaf_lua_script_timeouts_total Lua policy script executions aborted by the per-script timeout\n")
	b.WriteString("# TYPE openwaf_lua_script_timeouts_total counter\n")
	for i, s := range scripts {
		fmt.Fprintf(&b, "openwaf_lua_script_timeouts_total%s %d\n", labels[i], s.Timeouts)
	}

	b.WriteString("\n# HELP openwaf_lua_script_avg_duration_ms Average Lua policy script execution time in milliseconds\n")
	b.WriteString("# TYPE openwaf_lua_script_avg_duration_ms gauge\n")
	for i, s := range scripts {
		fmt.Fprintf(&b, "openwaf_lua_script_avg_duration_ms%s %.6f\n", labels[i], s.AvgDurationMs)
	}

	return b.String()
}

/**
 * prometheusHTTPTraceStats 渲染数据面请求的分阶段耗时。
 *
 * 分协议输出是有意为之：x01n/http2 fork v0.3.0 不记录 ReadBody*、Write* 事件，
 * h2 的覆盖天然不完整。若把协议混在一起，h2 的缺口会被 h1 的样本掩盖。运维看到
 * 某个阶段在 h2 上恒为 0 时，需要能直接判断这是「未采集」而不是「耗时为零」——
 * 因此缺失阶段不补零，只有指标名下的 count=0。
 *
 * 注意 phase="server_handle" 的语义：它是 handler 全周期，**含同步等待上游的时间**，
 * 不是纯 WAF 计算时间。权威说明见 HTTPTracePhaseServerHandleDoc。
 *
 * 没有 Tracer 注册时返回空串而不是空的 HELP/TYPE 头：没有采集就没有系列。
 *
 * @param stats 分阶段耗时快照。
 * @return Prometheus 文本片段，以空行开头以便直接拼接。
 */
func prometheusHTTPTraceStats(stats HTTPTraceStats) string {
	if len(stats.Protos) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n# HELP openwaf_httptrace_samples_total Data-plane requests with a complete Hertz trace record\n")
	b.WriteString("# TYPE openwaf_httptrace_samples_total counter\n")
	for _, p := range stats.Protos {
		fmt.Fprintf(&b, "openwaf_httptrace_samples_total{proto=\"%s\"} %d\n",
			escapePrometheusLabelValue(p.Proto), p.Samples)
	}

	b.WriteString("\n# HELP openwaf_httptrace_skipped_total Hertz tracer finish calls without a matching HTTPStart, for example keep-alive idle connection reaping\n")
	b.WriteString("# TYPE openwaf_httptrace_skipped_total counter\n")
	for _, p := range stats.Protos {
		fmt.Fprintf(&b, "openwaf_httptrace_skipped_total{proto=\"%s\"} %d\n",
			escapePrometheusLabelValue(p.Proto), p.Skipped)
	}

	b.WriteString("\n# HELP openwaf_httptrace_errors_total Data-plane requests whose Hertz trace record carried an error\n")
	b.WriteString("# TYPE openwaf_httptrace_errors_total counter\n")
	for _, p := range stats.Protos {
		fmt.Fprintf(&b, "openwaf_httptrace_errors_total{proto=\"%s\"} %d\n",
			escapePrometheusLabelValue(p.Proto), p.Errors)
	}

	b.WriteString("\n# HELP openwaf_httptrace_skipped_bytes_total Request bytes observed while draining a keep-alive connection that closed without a complete request; counted separately because the exchange is not a request\n")
	b.WriteString("# TYPE openwaf_httptrace_skipped_bytes_total counter\n")
	for _, p := range stats.Protos {
		fmt.Fprintf(&b, "openwaf_httptrace_skipped_bytes_total{proto=\"%s\"} %d\n",
			escapePrometheusLabelValue(p.Proto), p.SkippedBytes)
	}

	b.WriteString("\n# HELP openwaf_httptrace_request_bytes_total Request header and body bytes recorded by the Hertz trace record; 0 when the length is indeterminate\n")
	b.WriteString("# TYPE openwaf_httptrace_request_bytes_total counter\n")
	for _, p := range stats.Protos {
		fmt.Fprintf(&b, "openwaf_httptrace_request_bytes_total{proto=\"%s\"} %d\n",
			escapePrometheusLabelValue(p.Proto), p.RequestBytes)
	}

	b.WriteString("\n# HELP openwaf_httptrace_response_bytes_total Response header and body bytes recorded by the Hertz trace record; 0 when the length is indeterminate\n")
	b.WriteString("# TYPE openwaf_httptrace_response_bytes_total counter\n")
	for _, p := range stats.Protos {
		fmt.Fprintf(&b, "openwaf_httptrace_response_bytes_total{proto=\"%s\"} %d\n",
			escapePrometheusLabelValue(p.Proto), p.ResponseBytes)
	}

	// 直方图与累计和共用一组标签；先算一次避免重复拼接。
	//
	// 只渲染有有效样本的协议。三种情况会落到 samples=0：keep-alive 空闲回收（协议读不到）、
	// 从没被完整解析的连接，以及探测型连接。它们的信息已由 skipped_total 与 errors_total
	// 表达，若照样渲染直方图，每次抓取会多出 16 桶 × 5 阶段的 80 行恒零样本，把要看的
	// 数字淹掉。注意这与"某个阶段在 h2 上恒零"不同：后者属于已解析协议的正常输出，
	// 必须保留，因为"未采集"正是运维需要看到的。
	type labeled struct {
		proto string
		phase HTTPTracePhaseStats
	}
	all := make([]labeled, 0, len(stats.Protos)*5)
	for _, p := range stats.Protos {
		if p.Samples == 0 {
			continue
		}
		for _, phase := range p.Phases {
			all = append(all, labeled{proto: p.Proto, phase: phase})
		}
	}

	b.WriteString("\n# HELP openwaf_httptrace_phase_duration_seconds Cumulative duration of a data-plane request phase by protocol; phase=\"server_handle\" is the whole handler lifetime including the synchronous upstream round trip, not pure WAF compute time\n")
	b.WriteString("# TYPE openwaf_httptrace_phase_duration_seconds histogram\n")
	for _, item := range all {
		labels := fmt.Sprintf("proto=\"%s\",phase=\"%s\"",
			escapePrometheusLabelValue(item.proto), escapePrometheusLabelValue(item.phase.Name))
		var cumulative int64
		for i, bound := range stats.BucketBoundsMs {
			if i < len(item.phase.Buckets) {
				cumulative += item.phase.Buckets[i]
			}
			fmt.Fprintf(&b, "openwaf_httptrace_phase_duration_seconds_bucket{%s,le=\"%s\"} %d\n",
				labels, formatPrometheusBucketBound(bound), cumulative)
		}
		if len(item.phase.Buckets) > 0 {
			cumulative += item.phase.Buckets[len(item.phase.Buckets)-1]
		}
		fmt.Fprintf(&b, "openwaf_httptrace_phase_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, cumulative)
		fmt.Fprintf(&b, "openwaf_httptrace_phase_duration_seconds_sum{%s} %.6f\n", labels, item.phase.SumMs/1000.0)
		fmt.Fprintf(&b, "openwaf_httptrace_phase_duration_seconds_count{%s} %d\n", labels, item.phase.Count)
	}

	// 负耗时样本单独成指标而不是并进 count：它衡量的是上游事件配对的健康度，
	// 不是请求耗时。并进 count 会让 count - 各桶之和 出现无法解释的差额。
	b.WriteString("\n# HELP openwaf_httptrace_phase_invalid_total Rejected phase samples whose end event preceded its start event, indicating broken event pairing in the protocol stack\n")
	b.WriteString("# TYPE openwaf_httptrace_phase_invalid_total counter\n")
	for _, item := range all {
		labels := fmt.Sprintf("proto=\"%s\",phase=\"%s\"",
			escapePrometheusLabelValue(item.proto), escapePrometheusLabelValue(item.phase.Name))
		fmt.Fprintf(&b, "openwaf_httptrace_phase_invalid_total{%s} %d\n", labels, item.phase.Invalid)
	}

	return b.String()
}

/**
 * formatPrometheusBucketBound 渲染直方图的 le 标签值。
 *
 * 去掉无意义的尾随零（1.000000 → 1），既贴近 Prometheus 客户端的惯例，也让
 * Grafana 的 legend 不必额外格式化。边界值全部由 httpTraceBucketBoundsUs 派生，
 * 是有限小数，不会出现需要科学计数法的取值。
 *
 * @param bound 桶上界（毫秒）。
 * @return 已格式化的 le 值。
 */
func formatPrometheusBucketBound(bound float64) string {
	return strconv.FormatFloat(bound, 'f', -1, 64)
}

func prometheusUnifiedWriterStats(stats UnifiedWriterStats) string {
	return fmt.Sprintf(`
# HELP openwaf_writer_queue_len Current queued observability records
# TYPE openwaf_writer_queue_len gauge
openwaf_writer_queue_len{type="security_event"} %d
openwaf_writer_queue_len{type="access_log"} %d
openwaf_writer_queue_len{type="drop_event"} %d
openwaf_writer_queue_len{type="bot_score"} %d

# HELP openwaf_writer_dropped_total Total observability records dropped before enqueue
# TYPE openwaf_writer_dropped_total counter
openwaf_writer_dropped_total{type="security_event"} %d
openwaf_writer_dropped_total{type="access_log"} %d
openwaf_writer_dropped_total{type="drop_event"} %d
openwaf_writer_dropped_total{type="bot_score"} %d

# HELP openwaf_writer_flushes_total Total async writer flushes
# TYPE openwaf_writer_flushes_total counter
openwaf_writer_flushes_total %d

# HELP openwaf_writer_flush_errors_total Total async writer flushes with Redis or database errors
# TYPE openwaf_writer_flush_errors_total counter
openwaf_writer_flush_errors_total %d

# HELP openwaf_writer_failed_records_total Total observability records not persisted because a database flush failed
# TYPE openwaf_writer_failed_records_total counter
openwaf_writer_failed_records_total %d

# HELP openwaf_writer_last_flush_records Records persisted by the latest async writer flush
# TYPE openwaf_writer_last_flush_records gauge
openwaf_writer_last_flush_records %d

# HELP openwaf_writer_last_flush_failed_records Records not persisted by the latest async writer flush
# TYPE openwaf_writer_last_flush_failed_records gauge
openwaf_writer_last_flush_failed_records %d

# HELP openwaf_writer_last_flush_duration_ms Duration of the latest async writer flush in milliseconds
# TYPE openwaf_writer_last_flush_duration_ms gauge
openwaf_writer_last_flush_duration_ms %d

# HELP openwaf_writer_last_flush_unix_nano Unix timestamp of the latest async writer flush in nanoseconds
# TYPE openwaf_writer_last_flush_unix_nano gauge
openwaf_writer_last_flush_unix_nano %d

# HELP openwaf_writer_total_flushed_records Total observability records persisted by async writer flushes
# TYPE openwaf_writer_total_flushed_records counter
openwaf_writer_total_flushed_records %d
`,
		stats.SecurityEventQueueLen,
		stats.AccessLogQueueLen,
		stats.DropEventQueueLen,
		stats.BotScoreQueueLen,
		stats.SecurityEventDropped,
		stats.AccessLogDropped,
		stats.DropEventDropped,
		stats.BotScoreDropped,
		stats.FlushesTotal,
		stats.FlushErrorsTotal,
		stats.FailedRecordsTotal,
		stats.LastFlushRecords,
		stats.LastFlushFailedRecords,
		stats.LastFlushDurationMs,
		stats.LastFlushUnixNano,
		stats.TotalFlushedRecords,
	)
}

func prometheusWriteQueueStats(stats WriteQueueStats) string {
	closed := 0
	if stats.Closed {
		closed = 1
	}
	return fmt.Sprintf(`
# HELP openwaf_write_queue_len Current generic repository write queue depth
# TYPE openwaf_write_queue_len gauge
openwaf_write_queue_len %d

# HELP openwaf_write_queue_capacity Configured generic repository write queue capacity
# TYPE openwaf_write_queue_capacity gauge
openwaf_write_queue_capacity %d

# HELP openwaf_write_queue_closed Whether the generic repository write queue has begun shutdown
# TYPE openwaf_write_queue_closed gauge
openwaf_write_queue_closed %d

# HELP openwaf_write_queue_submitted_total Total repository write jobs submitted
# TYPE openwaf_write_queue_submitted_total counter
openwaf_write_queue_submitted_total %d

# HELP openwaf_write_queue_enqueued_total Total repository write jobs enqueued asynchronously
# TYPE openwaf_write_queue_enqueued_total counter
openwaf_write_queue_enqueued_total %d

# HELP openwaf_write_queue_dropped_full_total Jobs rejected because the repository write queue was full
# TYPE openwaf_write_queue_dropped_full_total counter
openwaf_write_queue_dropped_full_total %d

# HELP openwaf_write_queue_dropped_closed_total Jobs rejected after repository write queue shutdown began
# TYPE openwaf_write_queue_dropped_closed_total counter
openwaf_write_queue_dropped_closed_total %d

# HELP openwaf_write_queue_sync_fallback_total Synchronous fallbacks used when waitable queue submissions found a full queue
# TYPE openwaf_write_queue_sync_fallback_total counter
openwaf_write_queue_sync_fallback_total %d

# HELP openwaf_write_queue_executed_total Jobs whose callbacks were invoked
# TYPE openwaf_write_queue_executed_total counter
openwaf_write_queue_executed_total %d

# HELP openwaf_write_queue_succeeded_total Jobs persisted successfully
# TYPE openwaf_write_queue_succeeded_total counter
openwaf_write_queue_succeeded_total %d

# HELP openwaf_write_queue_failed_total Jobs whose callbacks or transaction failed
# TYPE openwaf_write_queue_failed_total counter
openwaf_write_queue_failed_total %d

# HELP openwaf_write_queue_transaction_errors_total Transactions that failed to commit
# TYPE openwaf_write_queue_transaction_errors_total counter
openwaf_write_queue_transaction_errors_total %d

# HELP openwaf_write_queue_batches_total Completed queue flush batches
# TYPE openwaf_write_queue_batches_total counter
openwaf_write_queue_batches_total %d

# HELP openwaf_write_queue_last_batch_jobs Jobs in the latest flush batch
# TYPE openwaf_write_queue_last_batch_jobs gauge
openwaf_write_queue_last_batch_jobs %d

# HELP openwaf_write_queue_last_batch_succeeded Jobs succeeded in the latest flush batch
# TYPE openwaf_write_queue_last_batch_succeeded gauge
openwaf_write_queue_last_batch_succeeded %d

# HELP openwaf_write_queue_last_batch_failed Jobs failed in the latest flush batch
# TYPE openwaf_write_queue_last_batch_failed gauge
openwaf_write_queue_last_batch_failed %d

# HELP openwaf_write_queue_last_batch_duration_ms Duration of the latest flush batch in milliseconds
# TYPE openwaf_write_queue_last_batch_duration_ms gauge
openwaf_write_queue_last_batch_duration_ms %d

# HELP openwaf_write_queue_last_batch_unix_nano Unix timestamp of the latest flush batch
# TYPE openwaf_write_queue_last_batch_unix_nano gauge
openwaf_write_queue_last_batch_unix_nano %d
`,
		stats.QueueLen,
		stats.QueueCapacity,
		closed,
		stats.SubmittedTotal,
		stats.EnqueuedTotal,
		stats.DroppedFullTotal,
		stats.DroppedClosedTotal,
		stats.SyncFallbackTotal,
		stats.ExecutedTotal,
		stats.SucceededTotal,
		stats.FailedJobsTotal,
		stats.TransactionErrorsTotal,
		stats.BatchesTotal,
		stats.LastBatchJobs,
		stats.LastBatchSucceeded,
		stats.LastBatchFailed,
		stats.LastBatchDurationMs,
		stats.LastBatchUnixNano,
	)
}
