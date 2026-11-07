package observability

import (
	"sort"
	"strings"
	"testing"
)

// fakeHTTPTraceStatsProvider 提供一份固定的分阶段耗时快照。
type fakeHTTPTraceStatsProvider struct {
	stats HTTPTraceStats
}

func (f fakeHTTPTraceStatsProvider) Stats() HTTPTraceStats { return f.stats }

// fakeImageTransformStats 提供一份固定的图像转换快照。
//
// ImageTransformStatsProvider 是函数类型而非接口，直接返回闭包即可。
func fakeImageTransformStats() ImageTransformStatsSnapshot {
	return ImageTransformStatsSnapshot{
		WebPDynamicAvailable: true,
		Applied:              1,
		Skipped:              2,
		TimedOut:             3,
		GateLimit:            4,
		GateInUse:            5,
		GateSkipped:          6,
	}
}

/*
fullExpositionMetrics 构造一个所有 provider 都已接线的收集器。

/provider 全部挂上是为了让 /metrics 输出覆盖全部指标族：没挂 provider 的族
（lua、httptrace、imagery、cache）根本不会被渲染，用默认收集器断言「存在」会失败，
但那反映的是「这台机器没开这个特性」，不是指标名写错了。
*/
func fullExpositionMetrics() *Metrics {
	m := NewMetrics()
	m.SetUnifiedWriterStatsProvider(fakeUnifiedWriterStatsProvider{stats: UnifiedWriterStats{
		SecurityEventQueueLen:  1,
		AccessLogQueueLen:      2,
		DropEventQueueLen:      3,
		BotScoreQueueLen:       4,
		SecurityEventDropped:   5,
		AccessLogDropped:       6,
		DropEventDropped:       7,
		BotScoreDropped:        8,
		FlushesTotal:           9,
		FlushErrorsTotal:       10,
		FailedRecordsTotal:     11,
		LastFlushRecords:       12,
		LastFlushFailedRecords: 13,
		LastFlushDurationMs:    14,
		LastFlushUnixNano:      15,
		TotalFlushedRecords:    16,
	}})
	m.SetWriteQueueStatsProvider(fakeWriteQueueStatsProvider{stats: WriteQueueStats{
		QueueLen:               1,
		QueueCapacity:          256,
		SubmittedTotal:         2,
		EnqueuedTotal:          3,
		DroppedFullTotal:       4,
		DroppedClosedTotal:     5,
		SyncFallbackTotal:      6,
		ExecutedTotal:          7,
		SucceededTotal:         8,
		FailedJobsTotal:        9,
		TransactionErrorsTotal: 10,
		BatchesTotal:           11,
		LastBatchJobs:          12,
		LastBatchSucceeded:     13,
		LastBatchFailed:        14,
		LastBatchDurationMs:    15,
		LastBatchUnixNano:      16,
	}})
	m.SetDataPlaneMetricsProvider(func() DataPlaneMetricsSnapshot {
		return DataPlaneMetricsSnapshot{
			QPS1s:         1.5,
			QPS5s:         1.25,
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
	m.SetUpstreamMetricsProvider(func() UpstreamMetricsSnapshot {
		return UpstreamMetricsSnapshot{
			HealthyCount:     2,
			UnhealthyCount:   1,
			KnownCount:       3,
			CheckedCount:     3,
			AverageLatencyMs: 12.5,
			MaxLastLatencyMs: 25,
			LatencySamples:   9,
		}
	})
	m.SetCacheStatsProvider(func() []CacheLayerStats {
		return []CacheLayerStats{{Name: "query", Hits: 4, Misses: 2, Errors: 1}}
	})
	m.SetLuaScriptStatsProvider(func() []LuaScriptStats {
		return []LuaScriptStats{{Name: "audit", Stage: "pre", Runs: 3, Failures: 1, Timeouts: 1, AvgDurationMs: 0.5}}
	})
	m.SetHTTPTraceStatsProvider(fakeHTTPTraceStatsProvider{stats: HTTPTraceStats{
		BucketBoundsMs: HTTPTraceBucketBoundsMs(),
		Protos: []HTTPTraceProtoStats{{
			Proto:         "http1",
			Samples:       2,
			Skipped:       1,
			SkippedBytes:  0,
			Errors:        0,
			RequestBytes:  64,
			ResponseBytes: 128,
			Phases: []HTTPTracePhaseStats{{
				Name:    "total",
				Count:   2,
				SumMs:   3.5,
				Invalid: 0,
				Buckets: make([]int64, len(HTTPTraceBucketBoundsMs())+1),
			}},
		}},
	}})
	m.SetImageTransformStatsProvider(fakeImageTransformStats)
	return m
}

// declaredMetricFamilies 从 Prometheus 文本里取出 # TYPE 声明的全部指标族名。
func declaredMetricFamilies(body string) map[string]string {
	families := make(map[string]string)
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "# TYPE ") {
			continue
		}
		rest := strings.TrimPrefix(line, "# TYPE ")
		fields := strings.Fields(rest)
		if len(fields) != 2 {
			continue
		}
		families[fields[0]] = fields[1]
	}
	return families
}

/*
sampleMetricNames 从 Prometheus 文本里取出全部样本行的指标名。

只在非空、非注释的行上取第一个 `{` 或空格之前的 token；直方图的 _bucket/_sum/_count
三个后缀还原成所属的族名，这样样本行与 # TYPE 声明可以用同一套名字比对。
*/
func sampleMetricNames(body string) []string {
	var names []string
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		end := strings.IndexAny(line, "{ ")
		if end < 0 {
			end = len(line)
		}
		name := line[:end]
		for _, suffix := range []string{"_bucket", "_sum", "_count"} {
			if strings.HasSuffix(name, suffix) {
				name = strings.TrimSuffix(name, suffix)
				break
			}
		}
		names = append(names, name)
	}
	return names
}

/*
TestMetricsExpositionHasNoPhantomRequestsTotal 是本文件的核心：/metrics 不得再输出
openwaf_requests_total。

这条指标曾经恒为 0——observability.Metrics.RecordRequest 没有任何生产调用点，数据面
请求走的是 dataplane/metrics 的同名计数器。结果 /metrics 上同时存在
`openwaf_requests_total 0`（假）与 `openwaf_dataplane_requests_total <真值>`，
而按名字抓取的仪表盘多半会抓走前者。断言写成「整份输出里不出现该串」而不是
「其值不为 0」：两者都能抓住回归，但前者还能拦住有人把它改回一条名字不同、
语义仍假的计数器。
*/
func TestMetricsExpositionHasNoPhantomRequestsTotal(t *testing.T) {
	body := PrometheusBody(fullExpositionMetrics())

	if strings.Contains(body, "openwaf_requests_total") {
		t.Fatalf("PrometheusBody() 仍输出 openwaf_requests_total；该指标没有生产调用点，"+
			"请求总量唯一真实来源是 openwaf_dataplane_requests_total\nbody:\n%s", body)
	}

	// 反向兜底：真值必须在，否则「删掉假的」就变成了「两个都没了」。
	if !strings.Contains(body, "openwaf_dataplane_requests_total 101") {
		t.Fatalf("PrometheusBody() 缺少真实请求总量 openwaf_dataplane_requests_total 101\nbody:\n%s", body)
	}
}

/*
TestMetricsExpositionFamilies 逐条断言实际发出的指标族。

表驱动的原因：这些名字是 /metrics 的对外契约，任何一次改名都是破坏性变更，
而散落在各 provider 渲染函数里的字符串常量不会被编译器保护。整表比对还能发现
「注释里留了名字、样本行却没发」这种半吊子状态。
*/
func TestMetricsExpositionFamilies(t *testing.T) {
	cases := []struct {
		family string
		kind   string
	}{
		// 进程级：始终输出，不依赖任何 provider。
		{"openwaf_uptime_seconds", "gauge"},
		{"openwaf_goroutines", "gauge"},
		{"openwaf_memory_alloc_bytes", "gauge"},
		{"openwaf_memory_sys_bytes", "gauge"},
		{"openwaf_gc_pause_total_ns", "counter"},

		// 数据面：唯一真实来源 dataplane/metrics。
		{"openwaf_dataplane_qps", "gauge"},
		{"openwaf_dataplane_requests_total", "counter"},
		{"openwaf_dataplane_status_total", "counter"},
		{"openwaf_dataplane_waf_actions_total", "counter"},
		{"openwaf_dataplane_builtin_hits_total", "counter"},
		{"openwaf_dataplane_unique_ips_total", "counter"},
		{"openwaf_dataplane_attack_ips_total", "counter"},
		{"openwaf_dataplane_uptime_seconds", "gauge"},

		// 上游：主动健康探测，不是用户请求延迟。
		{"openwaf_upstream_healthy_total", "gauge"},
		{"openwaf_upstream_unhealthy_total", "gauge"},
		{"openwaf_upstream_known_total", "gauge"},
		{"openwaf_upstream_checked_total", "gauge"},
		{"openwaf_upstream_average_latency_ms", "gauge"},
		{"openwaf_upstream_max_last_latency_ms", "gauge"},
		{"openwaf_upstream_latency_samples_total", "counter"},

		// 缓存：前缀是 owaf_ 而不是 openwaf_，且带 cache label。
		{"owaf_cache_hits_total", "counter"},
		{"owaf_cache_misses_total", "counter"},
		{"owaf_cache_errors_total", "counter"},

		// Lua 策略插件。
		{"openwaf_lua_script_runs_total", "counter"},
		{"openwaf_lua_script_failures_total", "counter"},
		{"openwaf_lua_script_timeouts_total", "counter"},
		{"openwaf_lua_script_avg_duration_ms", "gauge"},

		// 数据面分阶段耗时。
		{"openwaf_httptrace_samples_total", "counter"},
		{"openwaf_httptrace_skipped_total", "counter"},
		{"openwaf_httptrace_errors_total", "counter"},
		{"openwaf_httptrace_skipped_bytes_total", "counter"},
		{"openwaf_httptrace_request_bytes_total", "counter"},
		{"openwaf_httptrace_response_bytes_total", "counter"},
		{"openwaf_httptrace_phase_duration_seconds", "histogram"},
		{"openwaf_httptrace_phase_invalid_total", "counter"},

		// 图像转换。
		{"openwaf_imagery_webp_dynamic_available", "gauge"},
		{"openwaf_imagery_applied_total", "counter"},
		{"openwaf_imagery_skipped_total", "counter"},
		{"openwaf_imagery_timed_out_total", "counter"},
		{"openwaf_imagery_gate_limit", "gauge"},
		{"openwaf_imagery_gate_in_use", "gauge"},
		{"openwaf_imagery_gate_skipped_total", "counter"},

		// 异步写入器。
		{"openwaf_writer_queue_len", "gauge"},
		{"openwaf_writer_dropped_total", "counter"},
		{"openwaf_writer_flushes_total", "counter"},
		{"openwaf_writer_flush_errors_total", "counter"},
		{"openwaf_writer_failed_records_total", "counter"},
		{"openwaf_writer_last_flush_records", "gauge"},
		{"openwaf_writer_last_flush_failed_records", "gauge"},
		{"openwaf_writer_last_flush_duration_ms", "gauge"},
		{"openwaf_writer_last_flush_unix_nano", "gauge"},
		{"openwaf_writer_total_flushed_records", "counter"},

		// 通用仓储写队列。
		{"openwaf_write_queue_len", "gauge"},
		{"openwaf_write_queue_capacity", "gauge"},
		{"openwaf_write_queue_closed", "gauge"},
		{"openwaf_write_queue_submitted_total", "counter"},
		{"openwaf_write_queue_enqueued_total", "counter"},
		{"openwaf_write_queue_dropped_full_total", "counter"},
		{"openwaf_write_queue_dropped_closed_total", "counter"},
		{"openwaf_write_queue_sync_fallback_total", "counter"},
		{"openwaf_write_queue_executed_total", "counter"},
		{"openwaf_write_queue_succeeded_total", "counter"},
		{"openwaf_write_queue_failed_total", "counter"},
		{"openwaf_write_queue_transaction_errors_total", "counter"},
		{"openwaf_write_queue_batches_total", "counter"},
		{"openwaf_write_queue_last_batch_jobs", "gauge"},
		{"openwaf_write_queue_last_batch_succeeded", "gauge"},
		{"openwaf_write_queue_last_batch_failed", "gauge"},
		{"openwaf_write_queue_last_batch_duration_ms", "gauge"},
		{"openwaf_write_queue_last_batch_unix_nano", "gauge"},
	}

	body := PrometheusBody(fullExpositionMetrics())
	declared := declaredMetricFamilies(body)

	for _, tc := range cases {
		got, ok := declared[tc.family]
		if !ok {
			t.Errorf("PrometheusBody() 未声明指标族 %s", tc.family)
			continue
		}
		if got != tc.kind {
			t.Errorf("指标族 %s 的类型是 %s，期望 %s", tc.family, got, tc.kind)
		}
	}

	// 反向：不得存在任何未在表中登记的指标族。新增指标必须同步登记，
	// 否则文档与仪表盘会再次落后于代码。
	known := make(map[string]struct{}, len(cases))
	for _, tc := range cases {
		known[tc.family] = struct{}{}
	}
	var undeclared []string
	for family := range declared {
		if _, ok := known[family]; !ok {
			undeclared = append(undeclared, family)
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		t.Errorf("PrometheusBody() 输出了未登记的指标族 %v；请同步更新本测试与 docs/ 下的指标清单", undeclared)
	}

	// 每条样本行都必须落在已声明的族上：游离的样本行通常来自错误的拼接，
	// Prometheus 解析器会整份拒绝（样本行引用了未声明的 metric family 时只警告，
	// 但重复的 HELP/TYPE 会直接报错）。
	for _, name := range sampleMetricNames(body) {
		if _, ok := known[name]; !ok {
			t.Errorf("样本行使用了未登记的指标名 %s", name)
		}
	}
}
