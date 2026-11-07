package imagery

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// gate 是全局并发闸门。
//
// 图像解码是 CPU 与内存的双重放大器：一张声明 16,777,216 px 的输入按 RGBA
// 计就是 64 MiB，加上中间画布与编码器缓冲，单张峰值可达 130-200 MiB。
// 响应变换链本身没有任何并发限制，因此在数据面上必须有一道闸门。
//
// 语义选择「超限即原图直通」而不是「排队等待」或「报错」：
//
//   - 排队会让突发流量把请求线程全部堵在 CPU 密集路径上，放大尾延迟；
//   - 报错会把用户的图片打成 5xx，与本包的失败语义冲突。
//
// 因此 Get 不阻塞：拿不到额度立刻放弃转换。
var gate = struct {
	mu      sync.Mutex
	limit   int
	inUse   int
	waiting uint64
	skipped uint64
}{
	limit: defaultGateLimit(),
}

// defaultGateLimit 返回闸门的默认并发额度。
//
// 取 NumCPU：解码与编码都是纯 CPU 工作，超过核数只会加剧调度抖动。
// 下限 1 保证单核环境仍然可用。
//
// @return 并发额度。
func defaultGateLimit() int {
	n := runtime.NumCPU()
	if n < 1 {
		n = 1
	}
	return n
}

// SetGateLimit 调整闸门额度（仅供测试与管理端显式调整使用）。
//
// @param n 新的并发额度；<=0 时重置为 NumCPU。
func SetGateLimit(n int) {
	if n <= 0 {
		n = defaultGateLimit()
	}
	gate.mu.Lock()
	gate.limit = n
	gate.mu.Unlock()
}

// GateStats 是闸门的当前状态。
type GateStats struct {
	// Limit 是并发额度。
	Limit int
	// InUse 是当前占用中的额度。
	InUse int
	// Waiting 是累计因超限而放弃转换的次数。
	Waiting uint64
	// Skipped 是因超限而原图直通的次数（当前实现与 Waiting 同义）。
	Skipped uint64
}

// SnapshotGateStats 返回闸门状态快照。
//
// @return 状态快照。
func SnapshotGateStats() GateStats {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return GateStats{
		Limit:   gate.limit,
		InUse:   gate.inUse,
		Waiting: gate.waiting,
		Skipped: gate.skipped,
	}
}

// acquire 尝试占用一个额度。
//
// @return 是否成功；失败时调用方必须原图直通。
func acquire() bool {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.inUse >= gate.limit {
		gate.waiting++
		gate.skipped++
		return false
	}
	gate.inUse++
	return true
}

// release 归还额度。
func release() {
	gate.mu.Lock()
	if gate.inUse > 0 {
		gate.inUse--
	}
	gate.mu.Unlock()
}

// TransformGuarded 在并发闸门与墙钟预算内执行 Transform。
//
// 与 Transform 的唯一差别是前置两道保护：
//
//  1. 尝试占用闸门额度；失败即返回「原图直通 + 跳过原因」。
//  2. 用 context.WithTimeout 施加上限（timeout <= 0 时取 DefaultOpTimeout）。
//
// @param ctx 请求上下文；为 nil 时使用 context.Background()。
// @param data 原始图片字节。
// @param contentType 上游返回的 Content-Type。
// @param opts 已解析的转换参数。
// @param watermarkText 服务端配置的水印文案。
// @param limits 解码限额；零值使用 DefaultDecodeLimits。
// @param timeout 单张图的墙钟预算；<=0 时取 DefaultOpTimeout。
// @return 转换结果；被闸门拒绝时 Changed 为 false。
func TransformGuarded(
	ctx context.Context,
	data []byte,
	contentType string,
	opts Options,
	watermarkText string,
	limits DecodeLimits,
	timeout time.Duration,
) Result {
	if len(data) == 0 || opts.IsZero() {
		return Result{Body: data, ContentType: contentType, SkipReason: "no-op"}
	}
	if !acquire() {
		return Result{Body: data, ContentType: contentType, SkipReason: "concurrency limit"}
	}
	defer release()

	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = DefaultOpTimeout
	}
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return Transform(opCtx, data, contentType, opts, watermarkText, limits)
}
