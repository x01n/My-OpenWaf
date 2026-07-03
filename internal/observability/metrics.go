package observability

import (
	"context"
	"fmt"
	"runtime"
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
