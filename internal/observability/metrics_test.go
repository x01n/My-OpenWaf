package observability

import (
	"strings"
	"testing"
)

type fakeUnifiedWriterStatsProvider struct {
	stats UnifiedWriterStats
}

func (f fakeUnifiedWriterStatsProvider) Stats() UnifiedWriterStats {
	return f.stats
}

func TestPrometheusBodyIncludesUnifiedWriterStats(t *testing.T) {
	m := NewMetrics()
	m.SetUnifiedWriterStatsProvider(fakeUnifiedWriterStatsProvider{
		stats: UnifiedWriterStats{
			SecurityEventQueueLen: 3,
			AccessLogQueueLen:     5,
			DropEventQueueLen:     7,
			BotScoreQueueLen:      11,
			SecurityEventDropped:  13,
			AccessLogDropped:      17,
			DropEventDropped:      19,
			BotScoreDropped:       23,
			FlushesTotal:          29,
			FlushErrorsTotal:      31,
			LastFlushRecords:      37,
			LastFlushDurationMs:   41,
			LastFlushUnixNano:     43,
			TotalFlushedRecords:   47,
		},
	})

	body := PrometheusBody(m)
	for _, want := range []string{
		`openwaf_writer_queue_len{type="security_event"} 3`,
		`openwaf_writer_queue_len{type="access_log"} 5`,
		`openwaf_writer_queue_len{type="drop_event"} 7`,
		`openwaf_writer_queue_len{type="bot_score"} 11`,
		`openwaf_writer_dropped_total{type="security_event"} 13`,
		`openwaf_writer_dropped_total{type="access_log"} 17`,
		`openwaf_writer_dropped_total{type="drop_event"} 19`,
		`openwaf_writer_dropped_total{type="bot_score"} 23`,
		"openwaf_writer_flushes_total 29",
		"openwaf_writer_flush_errors_total 31",
		"openwaf_writer_last_flush_records 37",
		"openwaf_writer_last_flush_duration_ms 41",
		"openwaf_writer_last_flush_unix_nano 43",
		"openwaf_writer_total_flushed_records 47",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("PrometheusBody() missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestPrometheusBodyIncludesDataPlaneMetrics(t *testing.T) {
	m := NewMetrics()
	m.SetDataPlaneMetricsProvider(func() DataPlaneMetricsSnapshot {
		return DataPlaneMetricsSnapshot{
			QPS1s:         12.5,
			QPS5s:         8.25,
			RequestsTotal: 101,
			Status2xx:     89,
			Status4xx:     7,
			Status5xx:     5,
			WAFBlocks:     3,
			WAFObserves:   2,
			BuiltinHits:   11,
			UptimeSec:     97,
			UniqueIPs:     13,
			AttackIPs:     17,
		}
	})

	body := PrometheusBody(m)
	for _, want := range []string{
		`openwaf_dataplane_qps{window="1s"} 12.500000`,
		`openwaf_dataplane_qps{window="5s"} 8.250000`,
		"openwaf_dataplane_requests_total 101",
		`openwaf_dataplane_status_total{class="2xx"} 89`,
		`openwaf_dataplane_status_total{class="4xx"} 7`,
		`openwaf_dataplane_status_total{class="5xx"} 5`,
		`openwaf_dataplane_waf_actions_total{action="block"} 3`,
		`openwaf_dataplane_waf_actions_total{action="observe"} 2`,
		"openwaf_dataplane_builtin_hits_total 11",
		"openwaf_dataplane_unique_ips_total 13",
		"openwaf_dataplane_attack_ips_total 17",
		"openwaf_dataplane_uptime_seconds 97",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("PrometheusBody() missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestPrometheusBodyIncludesUpstreamMetrics(t *testing.T) {
	m := NewMetrics()
	m.SetUpstreamMetricsProvider(func() UpstreamMetricsSnapshot {
		return UpstreamMetricsSnapshot{
			HealthyCount:     2,
			UnhealthyCount:   1,
			KnownCount:       3,
			CheckedCount:     3,
			AverageLatencyMs: 123.45,
			MaxLastLatencyMs: 250,
			LatencySamples:   9,
		}
	})

	body := PrometheusBody(m)
	for _, want := range []string{
		"openwaf_upstream_healthy_total 2",
		"openwaf_upstream_unhealthy_total 1",
		"openwaf_upstream_known_total 3",
		"openwaf_upstream_checked_total 3",
		"openwaf_upstream_average_latency_ms 123.45",
		"openwaf_upstream_max_last_latency_ms 250",
		"openwaf_upstream_latency_samples_total 9",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("PrometheusBody() missing %q\nbody:\n%s", want, body)
		}
	}
}
