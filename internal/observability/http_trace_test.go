package observability

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/common/tracer/stats"
)

// sleepMillis 制造可预测的耗时。事件时间由 Hertz 在 Record 时用 time.Now 打点，
// 没有时钟注入口，只能用真实等待来构造区间断言。
func sleepMillis(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// parseHistogramBuckets 从渲染出的文本里取出某条直方图的桶计数，按 le 升序返回，末位为 +Inf。
func parseHistogramBuckets(t *testing.T, body, proto, phase string) []int64 {
	t.Helper()
	prefix := "openwaf_httptrace_phase_duration_seconds_bucket{proto=\"" + proto + "\",phase=\"" + phase + "\",le=\""
	var out []int64
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		value := line[strings.LastIndex(line, "} ")+2:]
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			t.Fatalf("bucket line %q: %v", line, err)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		t.Fatalf("no histogram lines for %s/%s in body:\n%s", proto, phase, body)
	}
	return out
}

// findProto 在快照里取出指定协议的统计，找不到时让调用方直接失败。
func findProto(t *testing.T, snapshot HTTPTraceStats, proto string) HTTPTraceProtoStats {
	t.Helper()
	for _, p := range snapshot.Protos {
		if p.Proto == proto {
			return p
		}
	}
	t.Fatalf("proto %q not found in %+v", proto, snapshot.Protos)
	return HTTPTraceProtoStats{}
}

// findPhase 在协议统计里取出指定阶段，找不到时让调用方直接失败。
func findPhase(t *testing.T, entry HTTPTraceProtoStats, name string) HTTPTracePhaseStats {
	t.Helper()
	for _, p := range entry.Phases {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("phase %q not found in %+v", name, entry.Phases)
	return HTTPTracePhaseStats{}
}

// bucketTotal 是各桶样本数之和，恒等于有效样本数（含 +Inf 桶）。
func bucketTotal(buckets []int64) int64 {
	var total int64
	for _, v := range buckets {
		total += v
	}
	return total
}

// TestHTTPTraceIgnoresFinishWithoutHTTPStart 锁住最重要的守卫：
// keep-alive 空闲连接被回收时 Hertz 会调用 DoFinish，但 DoStart 尚未执行，
// 上下文里只有 HTTPFinish、没有 HTTPStart。若把它当成正常样本，
// HTTPFinish 减去零值时间会得到约 1.7e18 ns，一条空闲连接就能污染均值。
func TestHTTPTraceIgnoresFinishWithoutHTTPStart(t *testing.T) {
	tr := NewHTTPTrace(stats.LevelDetailed)
	c := NewHTTPTraceRequestContext(stats.LevelDetailed)
	c.Request.Header.SetProtocol("HTTP/1.1")
	// 只记录 finish，不记录 start —— 这正是空闲连接回收的形态。
	RecordHTTPTraceEvent(c, stats.HTTPFinish, nil)

	tr.Finish(nil, c)

	snapshot := tr.Stats()
	entry := findProto(t, snapshot, "HTTP/1.1")
	if entry.Samples != 0 {
		t.Fatalf("Samples = %d, want 0 for a finish without a start", entry.Samples)
	}
	if entry.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", entry.Skipped)
	}
	// 被丢弃样本上已读到的字节单独成列：既不能并进 RequestBytes（那不是一次完整请求），
	// 也不能丢掉（否则"这些流量去哪了"无从回答）。
	c.GetTraceInfo().Stats().SetRecvSize(777)
	tr.Finish(nil, c)
	if got := findProto(t, tr.Stats(), "HTTP/1.1").SkippedBytes; got != 777 {
		t.Fatalf("SkippedBytes = %d, want 777", got)
	}
	total := findPhase(t, entry, HTTPTracePhaseTotal)
	if total.Count != 0 || total.SumMs != 0 {
		t.Fatalf("total phase = %+v, want zero", total)
	}
	if got := bucketTotal(total.Buckets); got != 0 {
		t.Fatalf("total histogram samples = %d, want 0", got)
	}
}

// TestHTTPTraceServerHandleDocStatesUpstreamIncluded 锁住 server_handle 的语义说明。
//
// 这条不是修辞检查：server_handle 覆盖 handler 全周期、**包含同步上游等待**，
// 而"它等于 WAF 自身开销"是个极容易被写进文档的误读，照着它做优化会打错目标。
// 说明文本一旦被改回"WAF 开销"之类，这里必须变红。
func TestHTTPTraceServerHandleDocStatesUpstreamIncluded(t *testing.T) {
	doc := HTTPTracePhaseServerHandleDoc
	for _, want := range []string{"handler lifetime", "synchronous upstream round trip", "not pure WAF compute time"} {
		if !strings.Contains(doc, want) {
			t.Fatalf("HTTPTracePhaseServerHandleDoc missing %q\ndoc: %s", want, doc)
		}
	}
	// 渲染出的 HELP 文本也必须带上这个限定，否则只看 /metrics 的人读不到。
	body := prometheusHTTPTraceStats(HTTPTraceStats{
		Protos: []HTTPTraceProtoStats{{
			Proto:   "HTTP/1.1",
			Samples: 1,
			Phases:  []HTTPTracePhaseStats{{Name: HTTPTracePhaseServerHandle}},
		}},
		BucketBoundsMs: HTTPTraceBucketBoundsMs(),
	})
	if !strings.Contains(body, "not pure WAF compute time") {
		t.Fatalf("HELP text does not qualify server_handle\nbody:\n%s", body)
	}
}

// TestHTTPTraceRecordsDetailedPhases 断言五对事件都被换算成耗时并计入对应阶段，
// 且均值落在用 sleep 构造的区间内——锁的是"Finish 读的是事件对的时间差"，
// 而不是"某个计数器被加过"。
func TestHTTPTraceRecordsDetailedPhases(t *testing.T) {
	tr := NewHTTPTrace(stats.LevelDetailed)
	c := NewHTTPTraceRequestContext(stats.LevelDetailed)
	c.Request.Header.SetProtocol("HTTP/1.1")

	// 用 sleep 制造可预测的耗时：只有 server_handle 段被拉长，其余保持瞬时。
	RecordHTTPTraceEvent(c, stats.HTTPStart, nil)
	RecordHTTPTraceEvent(c, stats.ReadHeaderStart, nil)
	RecordHTTPTraceEvent(c, stats.ReadHeaderFinish, nil)
	RecordHTTPTraceEvent(c, stats.ReadBodyStart, nil)
	RecordHTTPTraceEvent(c, stats.ReadBodyFinish, nil)
	RecordHTTPTraceEvent(c, stats.ServerHandleStart, nil)
	sleepMillis(20)
	RecordHTTPTraceEvent(c, stats.ServerHandleFinish, nil)
	RecordHTTPTraceEvent(c, stats.WriteStart, nil)
	RecordHTTPTraceEvent(c, stats.WriteFinish, nil)
	RecordHTTPTraceEvent(c, stats.HTTPFinish, nil)

	tr.Finish(nil, c)

	entry := findProto(t, tr.Stats(), "HTTP/1.1")
	if entry.Samples != 1 {
		t.Fatalf("Samples = %d, want 1", entry.Samples)
	}
	if entry.Skipped != 0 {
		t.Fatalf("Skipped = %d, want 0", entry.Skipped)
	}

	handle := findPhase(t, entry, HTTPTracePhaseServerHandle)
	if handle.Count != 1 {
		t.Fatalf("server_handle count = %d, want 1", handle.Count)
	}
	if handle.SumMs < 15 || handle.SumMs > 200 {
		t.Fatalf("server_handle SumMs = %.3f, want within [15,200] for a 20ms sleep", handle.SumMs)
	}

	// 其余三段未被拉长：它们夹在瞬时事件之间，不应接近 20ms 量级。
	for _, name := range []string{HTTPTracePhaseReadHeader, HTTPTracePhaseReadBody, HTTPTracePhaseWrite} {
		phase := findPhase(t, entry, name)
		if phase.Count != 1 {
			t.Fatalf("%s count = %d, want 1", name, phase.Count)
		}
		if phase.SumMs > 15 {
			t.Fatalf("%s SumMs = %.3f, want well below the 20ms sleep", name, phase.SumMs)
		}
	}

	// 总耗时必然不小于它内部的 server_handle 段——这是同一请求的两个窗口，
	// 不是两个可以互相独立的计数器。反过来说明总耗时确实包住了 sleep。
	total := findPhase(t, entry, HTTPTracePhaseTotal)
	if total.Count != 1 {
		t.Fatalf("total count = %d, want 1", total.Count)
	}
	const slack = 1.0 // 毫秒；两次 time.Now 的取整与调度抖动
	if total.SumMs+slack < handle.SumMs {
		t.Fatalf("total SumMs = %.3f is smaller than server_handle %.3f by more than %v ms", total.SumMs, handle.SumMs, slack)
	}
	if total.SumMs < 15 {
		t.Fatalf("total SumMs = %.3f, want at least the 20ms sleep inside it", total.SumMs)
	}
}

// TestHTTPTraceMissingEventsDoNotZeroFill 断言事件缺失时不补零。
// 把"未采集"记成"耗时为零"会同时拉低均值并让采集缺口无法从指标上发现；
// x01n/http2 fork 正是缺 ReadBody*/Write* 的环境。
func TestHTTPTraceMissingEventsDoNotZeroFill(t *testing.T) {
	tr := NewHTTPTrace(stats.LevelDetailed)
	c := NewHTTPTraceRequestContext(stats.LevelDetailed)
	c.Request.Header.SetProtocol("HTTP/2.0")

	RecordHTTPTraceEvent(c, stats.HTTPStart, nil)
	RecordHTTPTraceEvent(c, stats.ReadHeaderStart, nil)
	RecordHTTPTraceEvent(c, stats.ReadHeaderFinish, nil)
	RecordHTTPTraceEvent(c, stats.ServerHandleStart, nil)
	RecordHTTPTraceEvent(c, stats.HTTPFinish, nil)

	tr.Finish(nil, c)

	entry := findProto(t, tr.Stats(), "HTTP/2.0")
	if entry.Samples != 1 {
		t.Fatalf("Samples = %d, want 1", entry.Samples)
	}
	if got := findPhase(t, entry, HTTPTracePhaseReadHeader).Count; got != 1 {
		t.Fatalf("read_header count = %d, want 1", got)
	}
	// 三对缺失的事件不应产出样本。
	for _, name := range []string{HTTPTracePhaseReadBody, HTTPTracePhaseServerHandle, HTTPTracePhaseWrite} {
		phase := findPhase(t, entry, name)
		if phase.Count != 0 {
			t.Fatalf("%s count = %d, want 0 when its events are absent", name, phase.Count)
		}
		if phase.SumMs != 0 {
			t.Fatalf("%s SumMs = %v, want 0 when its events are absent", name, phase.SumMs)
		}
	}
}

// TestHTTPTraceBaseLevelSkipsDetailedPhases 断言 LevelBase 下只采总耗时。
// 级别裁剪必须发生在采集侧：框架会按级别丢弃事件，但 Finish 仍会被调用，
// 不裁剪只是白跑四次事件查询。
func TestHTTPTraceBaseLevelSkipsDetailedPhases(t *testing.T) {
	tr := NewHTTPTrace(stats.LevelBase)
	if tr.Level() != stats.LevelBase {
		t.Fatalf("Level() = %v, want LevelBase", tr.Level())
	}
	c := NewHTTPTraceRequestContext(stats.LevelBase)
	c.Request.Header.SetProtocol("HTTP/1.1")

	RecordHTTPTraceEvent(c, stats.HTTPStart, nil)
	RecordHTTPTraceEvent(c, stats.HTTPFinish, nil)

	tr.Finish(nil, c)

	entry := findProto(t, tr.Stats(), "HTTP/1.1")
	if got := findPhase(t, entry, HTTPTracePhaseTotal).Count; got != 1 {
		t.Fatalf("total count = %d, want 1", got)
	}
	if len(entry.Phases) != 1 {
		names := make([]string, 0, len(entry.Phases))
		for _, p := range entry.Phases {
			names = append(names, p.Name)
		}
		t.Fatalf("phases = %v, want only %q at LevelBase", names, HTTPTracePhaseTotal)
	}
}

// TestHTTPTraceSeparatesProtocols 断言分协议统计不混算。
// 两种协议的阶段覆盖不同（h2 缺读体/写回），混在一起会让 h2 的缺口被 h1 的样本掩盖。
func TestHTTPTraceSeparatesProtocols(t *testing.T) {
	tr := NewHTTPTrace(stats.LevelDetailed)

	h1 := NewHTTPTraceRequestContext(stats.LevelDetailed)
	h1.Request.Header.SetProtocol("HTTP/1.1")
	RecordHTTPTraceEvent(h1, stats.HTTPStart, nil)
	RecordHTTPTraceEvent(h1, stats.HTTPFinish, nil)
	tr.Finish(nil, h1)

	h2 := NewHTTPTraceRequestContext(stats.LevelDetailed)
	h2.Request.Header.SetProtocol("HTTP/2.0")
	RecordHTTPTraceEvent(h2, stats.HTTPStart, nil)
	RecordHTTPTraceEvent(h2, stats.HTTPFinish, nil)
	tr.Finish(nil, h2)

	snapshot := tr.Stats()
	if got := findProto(t, snapshot, "HTTP/1.1").Samples; got != 1 {
		t.Fatalf("HTTP/1.1 Samples = %d, want 1", got)
	}
	if got := findProto(t, snapshot, "HTTP/2.0").Samples; got != 1 {
		t.Fatalf("HTTP/2.0 Samples = %d, want 1", got)
	}
}

// TestHTTPTraceRecordsSizesAndErrors 断言包大小与错误样本被计入。
// 大小取自 TraceInfo 的 SetRecvSize/SetSendSize，未设置时为 0 属正常（内容长度未定）。
func TestHTTPTraceRecordsSizesAndErrors(t *testing.T) {
	tr := NewHTTPTrace(stats.LevelDetailed)
	c := NewHTTPTraceRequestContext(stats.LevelDetailed)
	c.Request.Header.SetProtocol("HTTP/1.1")

	RecordHTTPTraceEvent(c, stats.HTTPStart, nil)
	c.GetTraceInfo().Stats().SetRecvSize(4096)
	c.GetTraceInfo().Stats().SetSendSize(512)
	// 与 hertz 的 Controller.DoFinish 同序：先记 HTTPFinish，再 SetError，
	// 最后才调用 tracer.Finish。只记事件不 SetError 的话 Errors 不会增长。
	RecordHTTPTraceEvent(c, stats.HTTPFinish, errors.New("client disconnected"))
	c.GetTraceInfo().Stats().SetError(errors.New("client disconnected"))

	tr.Finish(nil, c)

	entry := findProto(t, tr.Stats(), "HTTP/1.1")
	if entry.RequestBytes != 4096 {
		t.Fatalf("RequestBytes = %d, want 4096", entry.RequestBytes)
	}
	if entry.ResponseBytes != 512 {
		t.Fatalf("ResponseBytes = %d, want 512", entry.ResponseBytes)
	}
	if entry.Errors != 1 {
		t.Fatalf("Errors = %d, want 1", entry.Errors)
	}
}

// TestHTTPTraceRejectsNegativeDurations 锁住负耗时守卫。
//
// 这条不变式来自实测而非推测：x01n/http2 fork v0.3.0 上，同一条 h2 连接上
// ServerHandleFinish 会读到早于本次 ServerHandleStart 的时间戳（实测输出
// handle_start=22:14:37.188896 handle_finish=22:14:36.985222 delta_us=-203674）。
// 若直接累加，sum 会单调递减、均值变成负数，且每次采样都在反向拉低。
func TestHTTPTraceRejectsNegativeDurations(t *testing.T) {
	p := NewHTTPTraceProtoForTest(HTTPTracePhaseServerHandle)
	phase := p.phases[HTTPTracePhaseServerHandle]

	phase.observe(1500) // 正常样本
	phase.observe(-203674)
	phase.observe(-1)

	if got := phase.count.Load(); got != 1 {
		t.Fatalf("count = %d, want 1 (only the non-negative sample)", got)
	}
	if got := phase.sumUs.Load(); got != 1500 {
		t.Fatalf("sumUs = %d, want 1500", got)
	}
	if got := phase.invalid.Load(); got != 2 {
		t.Fatalf("invalid = %d, want 2", got)
	}
	// 负样本不能进任何桶，否则 count 与各桶之和不一致。
	var buckets []int64
	for i := range phase.buckets {
		buckets = append(buckets, phase.buckets[i].Load())
	}
	if got := bucketTotal(buckets); got != 1 {
		t.Fatalf("bucket total = %d, want 1 (the 1500us sample only, in the le=2000 bucket)", got)
	}
	if got := phase.buckets[httpTraceBucketIndex(1500)].Load(); got != 1 {
		t.Fatalf("bucket for 1500us = %d, want 1", got)
	}

	// 负样本只出现在 invalid 计里，且 sum 不再下降。
	before := phase.sumUs.Load()
	phase.observe(-1)
	if after := phase.sumUs.Load(); after != before {
		t.Fatalf("sumUs changed on a rejected sample: %d -> %d", before, after)
	}
	if got := phase.invalid.Load(); got != 3 {
		t.Fatalf("invalid = %d, want 3", got)
	}
}

// TestPrometheusHTTPTraceStatsRendersInvalidSamples 断言负样本计数被渲染出来，
// 让"上游事件配对坏了"成为运维可见的信号，而不是被静默吞掉。
func TestPrometheusHTTPTraceStatsRendersInvalidSamples(t *testing.T) {
	tr := NewHTTPTrace(stats.LevelDetailed)
	c := NewHTTPTraceRequestContext(stats.LevelDetailed)
	c.Request.Header.SetProtocol("HTTP/2.0")
	RecordHTTPTraceEvent(c, stats.HTTPStart, nil)
	// 构造 finish 早于 start 的事件对（fork 上实测到的形态）。
	RecordHTTPTraceEvent(c, stats.ServerHandleFinish, nil)
	sleepMillis(2)
	RecordHTTPTraceEvent(c, stats.ServerHandleStart, nil)
	RecordHTTPTraceEvent(c, stats.HTTPFinish, nil)

	tr.Finish(nil, c)

	entry := findProto(t, tr.Stats(), "HTTP/2.0")
	handle := findPhase(t, entry, HTTPTracePhaseServerHandle)
	if handle.Invalid != 1 {
		t.Fatalf("server_handle Invalid = %d, want 1", handle.Invalid)
	}
	if handle.Count != 0 || handle.SumMs != 0 {
		t.Fatalf("server_handle = %+v, want zero count/sum for the rejected sample", handle)
	}

	body := prometheusHTTPTraceStats(tr.Stats())
	want := `openwaf_httptrace_phase_invalid_total{proto="HTTP/2.0",phase="server_handle"} 1`
	if !strings.Contains(body, want) {
		t.Fatalf("Prometheus body missing %q\nbody:\n%s", want, body)
	}
}

// TestHTTPTraceBucketBoundsPin 钉住桶边界取值。
//
// 档位是标定出来的，不是随手取的：引擎全开时 read_header 约 0.008ms、write 约
// 0.068ms，必须有 0.05ms 这一档才能把两者分开；若退回常见的毫秒档，它们会一起
// 落进第一格，低延迟段的分辨率就没了。这条用例防止后续"顺手改成整毫秒"。
func TestHTTPTraceBucketBoundsPin(t *testing.T) {
	want := []int64{50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1000000}
	if len(httpTraceBucketBoundsUs) != len(want) {
		t.Fatalf("bounds count = %d, want %d", len(httpTraceBucketBoundsUs), len(want))
	}
	for i, us := range want {
		if httpTraceBucketBoundsUs[i] != us {
			t.Fatalf("bounds[%d] = %d, want %d", i, httpTraceBucketBoundsUs[i], us)
		}
	}
	if httpTraceBucketCount != len(want)+1 {
		t.Fatalf("bucketCount = %d, want %d (finite bounds + +Inf)", httpTraceBucketCount, len(want)+1)
	}
	// 最低一档必须是 0.05ms——低于这个量级的阶段（read_header）在毫米档下无法与
	// 其它阶段区分。
	if bound := HTTPTraceBucketBoundsMs()[0]; bound != 0.05 {
		t.Fatalf("first bucket bound = %v ms, want 0.05", bound)
	}
}

// TestHTTPTraceBucketIndex 逐个核对桶边界映射。
// 边界值本身必须落在该档内（<= 语义），否则 Prometheus 的 le 标签与实际分档不一致。
func TestHTTPTraceBucketIndex(t *testing.T) {
	bounds := HTTPTraceBucketBoundsMs()
	if len(bounds) != len(httpTraceBucketBoundsUs) {
		t.Fatalf("bucket bounds = %d, want %d", len(bounds), len(httpTraceBucketBoundsUs))
	}
	for i, us := range httpTraceBucketBoundsUs {
		if got := httpTraceBucketIndex(us); got != i {
			t.Fatalf("httpTraceBucketIndex(%d) = %d, want %d", us, got, i)
		}
		// 边界之上 1 微秒必须落进下一档——相邻边界的最小间隔是 100 微秒，
		// 因此不存在 us+1 与下一档边界相等的歧义。
		if i == len(httpTraceBucketBoundsUs)-1 {
			continue
		}
		if got := httpTraceBucketIndex(us + 1); got != i+1 {
			t.Fatalf("httpTraceBucketIndex(%d) = %d, want %d", us+1, got, i+1)
		}
	}
	// 超出最后一格的样本进 +Inf 桶。
	if got := httpTraceBucketIndex(httpTraceBucketBoundsUs[len(httpTraceBucketBoundsUs)-1] + 1); got != httpTraceBucketCount-1 {
		t.Fatalf("overflow index = %d, want %d", got, httpTraceBucketCount-1)
	}
	// 负耗时（时钟回拨等异常）落在第一格，而不是越界。
	if got := httpTraceBucketIndex(-1); got != 0 {
		t.Fatalf("negative index = %d, want 0", got)
	}
}

// TestHTTPTraceProtoDefaultsToUnknown 断言取不到协议时不丢样本。
// 协议名在 Finish 时才读，某些路径上可能为空；宁可落在 unknown 下也不能丢失。
func TestHTTPTraceProtoDefaultsToUnknown(t *testing.T) {
	tr := NewHTTPTrace(stats.LevelDetailed)
	c := NewHTTPTraceRequestContext(stats.LevelDetailed)
	// 刻意不设置协议。

	RecordHTTPTraceEvent(c, stats.HTTPStart, nil)
	RecordHTTPTraceEvent(c, stats.HTTPFinish, nil)
	tr.Finish(nil, c)

	entry := findProto(t, tr.Stats(), httpTraceUnknownProto)
	if entry.Samples != 1 {
		t.Fatalf("unknown proto Samples = %d, want 1", entry.Samples)
	}
}

// TestPrometheusHTTPTraceStatsRendersHistogram 断言 /metrics 文本里的直方图自洽：
// 桶计数单调不减、+Inf 桶等于 count、sum/count 与采集侧一致。
func TestPrometheusHTTPTraceStatsRendersHistogram(t *testing.T) {
	tr := NewHTTPTrace(stats.LevelDetailed)
	for i := 0; i < 3; i++ {
		c := NewHTTPTraceRequestContext(stats.LevelDetailed)
		c.Request.Header.SetProtocol("HTTP/1.1")
		RecordHTTPTraceEvent(c, stats.HTTPStart, nil)
		RecordHTTPTraceEvent(c, stats.ServerHandleStart, nil)
		sleepMillis(5)
		RecordHTTPTraceEvent(c, stats.ServerHandleFinish, nil)
		RecordHTTPTraceEvent(c, stats.HTTPFinish, nil)
		tr.Finish(nil, c)
	}

	body := prometheusHTTPTraceStats(tr.Stats())
	for _, want := range []string{
		"openwaf_httptrace_samples_total{proto=\"HTTP/1.1\"} 3",
		"openwaf_httptrace_phase_duration_seconds_count{proto=\"HTTP/1.1\",phase=\"server_handle\"} 3",
		"openwaf_httptrace_phase_duration_seconds_bucket{proto=\"HTTP/1.1\",phase=\"server_handle\",le=\"+Inf\"} 3",
		"openwaf_httptrace_phase_duration_seconds_sum{proto=\"HTTP/1.1\",phase=\"server_handle\"}",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Prometheus body missing %q\nbody:\n%s", want, body)
		}
	}

	// le 标签必须能被解析且单调递增，否则 Prometheus 会拒绝整份文本。
	buckets := parseHistogramBuckets(t, body, "HTTP/1.1", HTTPTracePhaseServerHandle)
	if len(buckets) != httpTraceBucketCount {
		t.Fatalf("rendered buckets = %d, want %d", len(buckets), httpTraceBucketCount)
	}
	for i := 1; i < len(buckets); i++ {
		if buckets[i] < buckets[i-1] {
			t.Fatalf("bucket counts not monotonic at %d: %v", i, buckets)
		}
	}
	if buckets[len(buckets)-1] != 3 {
		t.Fatalf("+Inf bucket = %d, want 3", buckets[len(buckets)-1])
	}
}

// TestPrometheusHTTPTraceStatsEmptyWhenNoProtos 断言没有采集数据时不输出空的 HELP/TYPE 头。
func TestPrometheusHTTPTraceStatsEmptyWhenNoProtos(t *testing.T) {
	if body := prometheusHTTPTraceStats(HTTPTraceStats{}); body != "" {
		t.Fatalf("body = %q, want empty", body)
	}
}

// TestFormatPrometheusBucketBound 钉住 le 标签的格式：不带尾随零。
func TestFormatPrometheusBucketBound(t *testing.T) {
	tests := map[float64]string{
		0.1: "0.1",
		1:   "1",
		2.5: "2.5",
		500: "500",
	}
	for in, want := range tests {
		if got := formatPrometheusBucketBound(in); got != want {
			t.Fatalf("formatPrometheusBucketBound(%v) = %q, want %q", in, got, want)
		}
	}
}
