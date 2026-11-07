package imagery

import (
	"sync/atomic"

	"github.com/gen2brain/webp"
)

var webpDynamicAvailable atomic.Bool

func init() {
	webpDynamicAvailable.Store(webp.Dynamic() == nil)
}

// WebPDynamicAvailable 返回系统 libwebp 是否可用。
//
// @return 可用时为 true（native 路径），否则为 false。
func WebPDynamicAvailable() bool {
	return webpDynamicAvailable.Load()
}

// 转换统计计数器。
//
// 采用项目既有的原子计数风格（与 internal/observability 的公开路径一致），
// 不引入新的指标库依赖。这里只做累计计数与最近一次跳过原因；分位统计需求
// 出现后再接入 observability 的直方图。
var (
	statApplied  atomic.Uint64
	statSkipped  atomic.Uint64
	statTimedOut atomic.Uint64
)

// MetricsSnapshot 是 imagery 包对外的运行期指标快照。
//
// 与 SnapshotStats、SnapshotGateStats 分开：那两个是本包的内部诊断快照，
// 这里是为 /metrics 准备的、已经换算好标签与布尔量的一份视图。
type MetricsSnapshot struct {
	// WebPDynamicAvailable 见同名函数。
	WebPDynamicAvailable bool
	// Applied、Skipped、TimedOut 与 Stats 同义，直接搬运。
	Applied  uint64
	Skipped  uint64
	TimedOut uint64
	// GateLimit 是并发闸门额度（正常为 CPU 核数或站点配置值）。
	GateLimit int
	// GateInUse 是当前占用的额度，可用于判断转换是否长期打满。
	GateInUse int
	// GateSkipped 是因并发超限而原图直通的累计次数。
	GateSkipped uint64
}

// Metrics 返回 imagery 的运行期指标快照。
//
// @return 指标快照。
func Metrics() MetricsSnapshot {
	stats := SnapshotStats()
	gateStats := SnapshotGateStats()
	return MetricsSnapshot{
		WebPDynamicAvailable: WebPDynamicAvailable(),
		Applied:              stats.Applied,
		Skipped:              stats.Skipped,
		TimedOut:             stats.TimedOut,
		GateLimit:            gateStats.Limit,
		GateInUse:            gateStats.InUse,
		GateSkipped:          gateStats.Skipped,
	}
}

// Stats 是转换统计的快照。
type Stats struct {
	// Applied 是成功产出新字节的次数。
	Applied uint64
	// Skipped 是因解码/编码/参数问题而原图直通的次数。
	Skipped uint64
	// TimedOut 是因墙钟预算耗尽而放弃转换的次数。
	TimedOut uint64
}

// SnapshotStats 返回当前统计快照。
//
// @return 统计快照。
func SnapshotStats() Stats {
	return Stats{
		Applied:  statApplied.Load(),
		Skipped:  statSkipped.Load(),
		TimedOut: statTimedOut.Load(),
	}
}

// ResetStats 清零统计（仅供测试使用）。
func ResetStats() {
	statApplied.Store(0)
	statSkipped.Store(0)
	statTimedOut.Store(0)
	lastSkipReason.Store(nil)
}

// recordApplied 记录一次成功转换。
func recordApplied() {
	statApplied.Add(1)
}

// recordSkip 记录一次跳过。
//
// @param err 跳过原因；nil 时只计入计数。
func recordSkip(err error) {
	statSkipped.Add(1)
	if err != nil {
		recordSkipReason(err.Error())
	}
}

// recordTimeout 记录一次超时放弃。
//
// 超时同时计入 TimedOut 与 Skipped：对调用方而言两者都是「原图直通」，
// 但 TimedOut 单独可观测，便于区分「参数/格式问题」与「预算不足」。
func recordTimeout() {
	statTimedOut.Add(1)
	statSkipped.Add(1)
}

// maxSkipReasonBytes 是最近一次跳过原因的最大保留长度。
const maxSkipReasonBytes = 256

var lastSkipReason atomic.Pointer[string]

// recordSkipReason 记录最近一次跳过原因。
//
// @param reason 原因文本。
func recordSkipReason(reason string) {
	if len(reason) > maxSkipReasonBytes {
		reason = reason[:maxSkipReasonBytes]
	}
	lastSkipReason.Store(&reason)
}

// LastSkipReason 返回最近一次跳过原因。
//
// 仅供测试与排障读取，不投影到 /metrics：语义是「最近一次」而非累计量，
// 做成 counter 没有意义，做成 gauge 会随抓取时刻抖动。累计口径看
// Metrics().Skipped / TimedOut。
//
// @return 原因文本；尚无记录时为空串。
func LastSkipReason() string {
	if p := lastSkipReason.Load(); p != nil {
		return *p
	}
	return ""
}
