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

func TestPrometheusBodyIncludesLuaScriptStats(t *testing.T) {
	m := NewMetrics()
	m.SetLuaScriptStatsProvider(func() []LuaScriptStats {
		return []LuaScriptStats{
			{Name: "block-scanner", Stage: "pre", Runs: 4000, Failures: 3, Timeouts: 1, AvgDurationMs: 0.075},
			{Name: "audit", Stage: "post", Runs: 12, Failures: 0, Timeouts: 0, AvgDurationMs: 1.5},
		}
	})

	body := PrometheusBody(m)
	for _, want := range []string{
		"# TYPE openwaf_lua_script_runs_total counter",
		`openwaf_lua_script_runs_total{script="block-scanner",stage="pre"} 4000`,
		`openwaf_lua_script_runs_total{script="audit",stage="post"} 12`,
		`openwaf_lua_script_failures_total{script="block-scanner",stage="pre"} 3`,
		`openwaf_lua_script_timeouts_total{script="block-scanner",stage="pre"} 1`,
		"# TYPE openwaf_lua_script_avg_duration_ms gauge",
		`openwaf_lua_script_avg_duration_ms{script="block-scanner",stage="pre"} 0.075000`,
		`openwaf_lua_script_avg_duration_ms{script="audit",stage="post"} 1.500000`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("PrometheusBody() missing %q\nbody:\n%s", want, body)
		}
	}

	// HELP/TYPE 每个 metric family 只能出现一次，否则解析器拒绝整份输出。
	for _, name := range []string{
		"openwaf_lua_script_runs_total",
		"openwaf_lua_script_failures_total",
		"openwaf_lua_script_timeouts_total",
		"openwaf_lua_script_avg_duration_ms",
	} {
		if n := strings.Count(body, "# TYPE "+name+" "); n != 1 {
			t.Errorf("# TYPE %s 出现 %d 次，应恰好 1 次", name, n)
		}
	}
}

// TestPrometheusBodyOmitsLuaScriptStatsWhenEmpty 验证无脚本时不输出空的 HELP/TYPE 头。
func TestPrometheusBodyOmitsLuaScriptStatsWhenEmpty(t *testing.T) {
	m := NewMetrics()
	m.SetLuaScriptStatsProvider(func() []LuaScriptStats { return nil })

	if body := PrometheusBody(m); strings.Contains(body, "openwaf_lua_script_") {
		t.Errorf("无脚本时不应输出 lua 指标\nbody:\n%s", body)
	}
}

// TestPrometheusLuaScriptStatsEscapesLabels 是核心注入防线。
//
// 脚本名由用户自由填写。未转义的双引号会提前闭合 label，未转义的换行会被解析成
// 新的一行样本——只要用户建一个名字带引号或换行的脚本，整份 /metrics 就不可解析。
func TestPrometheusLuaScriptStatsEscapesLabels(t *testing.T) {
	out := prometheusLuaScriptStats([]LuaScriptStats{
		{Name: `evil" hack`, Stage: "pre", Runs: 1},
		{Name: `back\slash`, Stage: "pre", Runs: 2},
		{Name: "line\nbreak", Stage: "pre", Runs: 3},
	})

	for _, want := range []string{
		`openwaf_lua_script_runs_total{script="evil\" hack",stage="pre"} 1`,
		`openwaf_lua_script_runs_total{script="back\\slash",stage="pre"} 2`,
		`openwaf_lua_script_runs_total{script="line\nbreak",stage="pre"} 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("缺少已转义的行 %q\n输出:\n%s", want, out)
		}
	}

	// 原始换行不得出现在样本行内部：出现即意味着多了一行伪造样本。
	if strings.Contains(out, "line\nbreak") {
		t.Error("脚本名中的原始换行未被转义，会伪造出新的指标行")
	}
	// 每一行非空、非注释的样本行都必须以指标名开头。
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "openwaf_lua_script_") {
			t.Errorf("出现非法样本行 %q，label 转义被绕过", line)
		}
	}
}

func TestEscapePrometheusLabelValue(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"plain", "plain"},
		{`a"b`, `a\"b`},
		{`a\b`, `a\\b`},
		{"a\nb", `a\nb`},
		{"a\"\\\nb", `a\"\\\nb`},
		// 制表符不在 Prometheus 的转义集内，写成 \t 反而是非法序列，须原样保留。
		{"a\tb", "a\tb"},
	}
	for _, tt := range cases {
		if got := escapePrometheusLabelValue(tt.in); got != tt.want {
			t.Errorf("escapePrometheusLabelValue(%q) = %q, want %q", tt.in, got, tt.want)
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
