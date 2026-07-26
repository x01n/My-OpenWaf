package observability

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
)

// UnifiedWriterStatsProvider exposes async writer diagnostics to /metrics.
type UnifiedWriterStatsProvider interface {
	Stats() UnifiedWriterStats
}

// DataPlaneMetricsSnapshot is a point-in-time view of request-path counters.
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

// UpstreamMetricsSnapshot is a point-in-time view of upstream health and latency.
type UpstreamMetricsSnapshot struct {
	HealthyCount     int64
	UnhealthyCount   int64
	KnownCount       int64
	CheckedCount     int64
	AverageLatencyMs float64
	MaxLastLatencyMs int64
	LatencySamples   int64
}

// CacheLayerStats holds cumulative hit/miss counters for a single named cache layer.
type CacheLayerStats struct {
	Name   string
	Hits   int64
	Misses int64
	// Errors 是后端故障次数（如 Redis 不可达），与「键不存在」的 Misses 区分。
	// 该值增长说明请求正在穿透到数据库，而非缓存策略失效。
	Errors int64
}

// LuaScriptStats holds cumulative execution counters for a single Lua policy script.
//
// 脚本失败/超时后只写一条 warn 日志就静默跳过，请求判定不受影响——这对可用性
// 是对的，但也意味着策略长期失效不会有任何外部信号。把这些计数器暴露出来，
// 运维才能对 Failures/Timeouts 的占比告警。
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

// CacheStatsSnapshotProvider returns per-layer cache hit/miss counters.
type CacheStatsSnapshotProvider func() []CacheLayerStats

// LuaScriptStatsProvider returns per-script Lua policy plugin counters.
type LuaScriptStatsProvider func() []LuaScriptStats

// DataPlaneMetricsSnapshotProvider returns a current data-plane metrics snapshot.
type DataPlaneMetricsSnapshotProvider func() DataPlaneMetricsSnapshot

// UpstreamMetricsSnapshotProvider returns a current upstream snapshot.
type UpstreamMetricsSnapshotProvider func() UpstreamMetricsSnapshot

// Metrics collects WAF runtime metrics for the /metrics (Prometheus) endpoint.
type Metrics struct {
	RequestsTotal  atomic.Int64
	BlocksTotal    atomic.Int64
	ObservesTotal  atomic.Int64
	BuiltinHits    atomic.Int64
	CacheHits      atomic.Int64
	CacheMisses    atomic.Int64
	UpstreamErrors atomic.Int64
	Uptime         time.Time

	unifiedWriterStatsProvider atomic.Value
	dataPlaneMetricsProvider   atomic.Value
	upstreamMetricsProvider    atomic.Value
	cacheStatsProvider         atomic.Value
	luaScriptStatsProvider     atomic.Value
}

// NewMetrics creates a new metrics collector.
func NewMetrics() *Metrics {
	return &Metrics{Uptime: time.Now()}
}

// RecordRequest increments the total request counter.
func (m *Metrics) RecordRequest() { m.RequestsTotal.Add(1) }

// RecordBlock increments the block counter.
func (m *Metrics) RecordBlock() { m.BlocksTotal.Add(1) }

// RecordObserve increments the observe counter.
func (m *Metrics) RecordObserve() { m.ObservesTotal.Add(1) }

// RecordBuiltin increments the builtin hit counter.
func (m *Metrics) RecordBuiltin() { m.BuiltinHits.Add(1) }

// RecordCacheHit increments cache hit counter.
func (m *Metrics) RecordCacheHit() { m.CacheHits.Add(1) }

// RecordCacheMiss increments cache miss counter.
func (m *Metrics) RecordCacheMiss() { m.CacheMisses.Add(1) }

// RecordUpstreamError increments upstream error counter.
func (m *Metrics) RecordUpstreamError() { m.UpstreamErrors.Add(1) }

// SetUnifiedWriterStatsProvider attaches async writer diagnostics to /metrics.
func (m *Metrics) SetUnifiedWriterStatsProvider(provider UnifiedWriterStatsProvider) {
	if provider == nil {
		return
	}
	m.unifiedWriterStatsProvider.Store(provider)
}

// SetDataPlaneMetricsProvider attaches request-path counters to /metrics.
func (m *Metrics) SetDataPlaneMetricsProvider(provider DataPlaneMetricsSnapshotProvider) {
	if provider == nil {
		return
	}
	m.dataPlaneMetricsProvider.Store(provider)
}

// SetUpstreamMetricsProvider attaches upstream health and latency metrics to /metrics.
func (m *Metrics) SetUpstreamMetricsProvider(provider UpstreamMetricsSnapshotProvider) {
	if provider == nil {
		return
	}
	m.upstreamMetricsProvider.Store(provider)
}

// SetCacheStatsProvider attaches per-layer cache hit/miss metrics to /metrics.
func (m *Metrics) SetCacheStatsProvider(provider CacheStatsSnapshotProvider) {
	if provider == nil {
		return
	}
	m.cacheStatsProvider.Store(provider)
}

// SetLuaScriptStatsProvider attaches per-script Lua policy plugin metrics to /metrics.
func (m *Metrics) SetLuaScriptStatsProvider(provider LuaScriptStatsProvider) {
	if provider == nil {
		return
	}
	m.luaScriptStatsProvider.Store(provider)
}

// PrometheusHandler returns a Hertz handler that serves /metrics in Prometheus text format.
func PrometheusHandler(m *Metrics) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		body := PrometheusBody(m)

		c.SetContentType("text/plain; version=0.0.4; charset=utf-8")
		c.SetStatusCode(200)
		c.SetBodyString(body)
	}
}

// PrometheusBody renders metrics in Prometheus text format.
func PrometheusBody(m *Metrics) string {
	if m == nil {
		m = NewMetrics()
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	uptimeSec := time.Since(m.Uptime).Seconds()

	body := fmt.Sprintf(`# HELP openwaf_requests_total Total HTTP requests processed
# TYPE openwaf_requests_total counter
openwaf_requests_total %d

# HELP openwaf_blocks_total Total requests blocked
# TYPE openwaf_blocks_total counter
openwaf_blocks_total %d

# HELP openwaf_observes_total Total observe-only detections
# TYPE openwaf_observes_total counter
openwaf_observes_total %d

# HELP openwaf_builtin_hits_total Total builtin OWASP rule hits
# TYPE openwaf_builtin_hits_total counter
openwaf_builtin_hits_total %d

# HELP openwaf_cache_hits_total Response cache hits
# TYPE openwaf_cache_hits_total counter
openwaf_cache_hits_total %d

# HELP openwaf_cache_misses_total Response cache misses
# TYPE openwaf_cache_misses_total counter
openwaf_cache_misses_total %d

# HELP openwaf_upstream_errors_total Upstream proxy errors
# TYPE openwaf_upstream_errors_total counter
openwaf_upstream_errors_total %d

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
		m.BlocksTotal.Load(),
		m.ObservesTotal.Load(),
		m.BuiltinHits.Load(),
		m.CacheHits.Load(),
		m.CacheMisses.Load(),
		m.UpstreamErrors.Load(),
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
		body += fmt.Sprintf("owaf_cache_hits_total{cache=%q} %d\n", l.Name, l.Hits)
	}
	body += `
# HELP owaf_cache_misses_total Cache misses by cache layer
# TYPE owaf_cache_misses_total counter
`
	for _, l := range layers {
		body += fmt.Sprintf("owaf_cache_misses_total{cache=%q} %d\n", l.Name, l.Misses)
	}
	body += `
# HELP owaf_cache_errors_total Cache backend failures by cache layer (excludes key-not-found)
# TYPE owaf_cache_errors_total counter
`
	for _, l := range layers {
		body += fmt.Sprintf("owaf_cache_errors_total{cache=%q} %d\n", l.Name, l.Errors)
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

# HELP openwaf_writer_last_flush_records Records in the latest async writer flush
# TYPE openwaf_writer_last_flush_records gauge
openwaf_writer_last_flush_records %d

# HELP openwaf_writer_last_flush_duration_ms Duration of the latest async writer flush in milliseconds
# TYPE openwaf_writer_last_flush_duration_ms gauge
openwaf_writer_last_flush_duration_ms %d

# HELP openwaf_writer_last_flush_unix_nano Unix timestamp of the latest async writer flush in nanoseconds
# TYPE openwaf_writer_last_flush_unix_nano gauge
openwaf_writer_last_flush_unix_nano %d

# HELP openwaf_writer_total_flushed_records Total records handled by async writer flushes
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
		stats.LastFlushRecords,
		stats.LastFlushDurationMs,
		stats.LastFlushUnixNano,
		stats.TotalFlushedRecords,
	)
}
