package observability

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
)

// Metrics collects WAF runtime metrics for the /metrics (Prometheus) endpoint.
type Metrics struct {
	RequestsTotal   atomic.Int64
	BlocksTotal     atomic.Int64
	ObservesTotal   atomic.Int64
	BuiltinHits     atomic.Int64
	CacheHits       atomic.Int64
	CacheMisses     atomic.Int64
	UpstreamErrors  atomic.Int64
	Uptime          time.Time
}

// NewMetrics creates a new metrics collector.
func NewMetrics() *Metrics {
	return &Metrics{Uptime: time.Now()}
}

// RecordRequest increments the total request counter.
func (m *Metrics) RecordRequest()  { m.RequestsTotal.Add(1) }

// RecordBlock increments the block counter.
func (m *Metrics) RecordBlock()    { m.BlocksTotal.Add(1) }

// RecordObserve increments the observe counter.
func (m *Metrics) RecordObserve()  { m.ObservesTotal.Add(1) }

// RecordBuiltin increments the builtin hit counter.
func (m *Metrics) RecordBuiltin()  { m.BuiltinHits.Add(1) }

// RecordCacheHit increments cache hit counter.
func (m *Metrics) RecordCacheHit() { m.CacheHits.Add(1) }

// RecordCacheMiss increments cache miss counter.
func (m *Metrics) RecordCacheMiss() { m.CacheMisses.Add(1) }

// RecordUpstreamError increments upstream error counter.
func (m *Metrics) RecordUpstreamError() { m.UpstreamErrors.Add(1) }

// PrometheusHandler returns a Hertz handler that serves /metrics in Prometheus text format.
func PrometheusHandler(m *Metrics) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
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

		c.SetContentType("text/plain; version=0.0.4; charset=utf-8")
		c.SetStatusCode(200)
		c.SetBodyString(body)
	}
}
