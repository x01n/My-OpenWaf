package proxy

import (
	"errors"

	"github.com/cloudwego/hertz/pkg/app"
)

// CompressionEventKind 区分解压降级的两种成因。
//
// 两者的处置相同（记录事件后按原始压缩字节继续），但审计含义不同：
// malformed 是「声明与实际不符」，limit_exceeded 是「压缩炸弹防护触发」。
// 分开记录才能让运维区分「客户端 bug」与「有人拿炸弹打进来」。
type CompressionEventKind string

const (
	// CompressionEventKindMalformed 表示压缩体畸形（声明受支持编码但字节流不是
	// 该编码，或解压中途损坏）。
	CompressionEventKindMalformed CompressionEventKind = "malformed_request_body"
	// CompressionEventKindLimitExceeded 表示解压产出超过硬上限，解压已终止。
	CompressionEventKindLimitExceeded CompressionEventKind = "decompression_limit_exceeded"
)

// CompressionEvent 是一次请求体解压降级/中断的审计载荷。
//
// 只描述「发生了什么」，站点与请求标识由数据面在挂载观察者时补齐：
// proxy 拿不到这些信息，也不应该为此反向依赖数据面。
type CompressionEvent struct {
	// Encoding 是请求声明的 Content-Encoding 原始取值。
	Encoding string
	// Kind 是降级成因。
	Kind CompressionEventKind
	// Detail 是英文短描述，落进安全事件的 MatchDesc。
	Detail string
}

// compressionEventContextKey 是数据面挂在请求上下文上的观察者键。
//
// 数据面在 handler 入口按需挂载（仅在请求带 Content-Encoding 时才挂），
// 未挂载时 proxy 侧的全部降级路径静默跳过，不产生任何额外开销。
const compressionEventContextKey = "openwaf_compression_event_observer"

// requestDecodeSkipContextKey 是「本请求体不得解压转发」的标记键。
//
// 与观察者分开成两个键而不是一个结构：标记由数据面在采样阶段决定，转发路径
// 只读它；观察者是事件出口，两条路径的生命周期与读者都不同。
const requestDecodeSkipContextKey = "openwaf_skip_request_body_decode"

/**
 * ContextWithSkippedRequestBodyDecode 标记本次请求的请求体不得解压转发。
 *
 * 数据面在采样阶段判定「这段压缩体解不动」时调用：压缩炸弹触发上限、或解压
 * 器连解码器都建不起来。标记之后转发路径按原始压缩字节转发并保留
 * Content-Encoding，由上游自行解码——这正是「降级而不是拒绝」：WAF 放弃对
 * 这部分内容的处理，但请求照常通过。
 *
 * 这个标记同时消除了重复解压：已经知道解不动（或不该解）的请求体，不该在
 * 转发路径上再被完整解压一遍，那正是压缩炸弹想要的 CPU/内存开销。
 *
 * @param c Hertz 请求上下文。
 */
func ContextWithSkippedRequestBodyDecode(c *app.RequestContext) {
	if c == nil {
		return
	}
	c.Set(requestDecodeSkipContextKey, true)
}

// SkippedRequestBodyDecode 返回该请求是否已被标记跳过请求体解压。
//
// 未标记时返回 false，即转发路径按原有语义解压并去掉 Content-Encoding。
func SkippedRequestBodyDecode(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	value, exists := c.Get(requestDecodeSkipContextKey)
	if !exists {
		return false
	}
	skip, _ := value.(bool)
	return skip
}

// bufferedCompressedBodyContextKey 是「压缩请求体已完整缓冲」的标记键。
const bufferedCompressedBodyContextKey = "openwaf_compressed_body_buffered"

/**
 * ContextWithBufferedCompressedBody 标记本次请求的压缩体已完整落在内存中。
 *
 * 数据面把请求体偷读前缀当作压缩体采样来源，当偷读到的字节数已经覆盖声明的
 * Content-Length 时，整段压缩体就在内存里（长度受偷读窗硬约束）。这个事实让
 * 转发路径可以对它做**先缓冲、再按预算解压**的处理：解压失败或触及压缩炸弹
 * 上限时按原始压缩字节转发，而不是把半截明文交给上游后由上游报错。
 *
 * 流式路径无法在读取中途回退——错误发生在 http 传输层，那时响应头很可能已经
 * 发出，只能落成 502。因此「已知完整且很小」的输入必须提前走可回退的路径。
 *
 * @param c Hertz 请求上下文。
 */
func ContextWithBufferedCompressedBody(c *app.RequestContext) {
	if c == nil {
		return
	}
	c.Set(bufferedCompressedBodyContextKey, true)
}

// BufferedCompressedBody 返回本次请求的压缩体是否已完整落在内存。
func BufferedCompressedBody(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	value, exists := c.Get(bufferedCompressedBodyContextKey)
	if !exists {
		return false
	}
	buffered, _ := value.(bool)
	return buffered
}

// CompressionEventObserver 由数据面实现：接收一次解压降级的审计载荷。
//
// 实现方需要自行补齐站点/请求标识并落库 —— proxy 不能 import
// internal/observability，事件通道的方向与 js_plugin_response.go 里的查找
// 函数相反（那边是 proxy 向数据面要运行时，这边是 proxy 向数据面交事件）。
type CompressionEventObserver func(ev CompressionEvent)

// ContextWithCompressionEventObserver 把解压降级观察者挂到请求上下文。
//
// observer 为 nil 或上下文为 nil 时不做任何事，调用方无需额外判空。
func ContextWithCompressionEventObserver(c *app.RequestContext, observer CompressionEventObserver) {
	if c == nil || observer == nil {
		return
	}
	c.Set(compressionEventContextKey, observer)
}

// compressionEventObserverFromContext 取回数据面挂载的观察者。
func compressionEventObserverFromContext(c *app.RequestContext) (CompressionEventObserver, bool) {
	if c == nil {
		return nil, false
	}
	value, exists := c.Get(compressionEventContextKey)
	if !exists {
		return nil, false
	}
	observer, ok := value.(CompressionEventObserver)
	return observer, ok
}

// observeCompressionEvent 把一次解压降级交给数据面的观察者。
//
// 没有观察者时静默丢弃：事件记录是审计增强，任何情况下都不得影响转发。
func observeCompressionEvent(c *app.RequestContext, ev CompressionEvent) {
	observer, ok := compressionEventObserverFromContext(c)
	if !ok || observer == nil {
		return
	}
	observer(ev)
}

/**
 * ObserveUpstreamRequestBodyDecodeFailure 把请求体解压失败归成两类并上报。
 *
 * 供数据面在请求侧调用：数据面在采样阶段就分得清「解压产出超限」（压缩炸弹）
 * 与「压缩体畸形」，两者在上游应答前就能定性，不必等转发阶段才发现。
 *
 * 超限（errDecompressionLimitExceeded）与畸形在转发层的处置相同——都放弃
 * 解压、按原始压缩字节转发——但事件类型分开，便于区分攻击与客户端缺陷。
 *
 * @param c Hertz 请求上下文（携带观察者时才会真正上报）。
 * @param contentEncoding 请求声明的 Content-Encoding 原始取值。
 * @param err 解压失败原因。
 */
func ObserveUpstreamRequestBodyDecodeFailure(c *app.RequestContext, contentEncoding string, err error) {
	if err == nil {
		return
	}
	ev := CompressionEvent{
		Encoding: contentEncoding,
		Kind:     CompressionEventKindMalformed,
		Detail:   "request body declared Content-Encoding " + contentEncoding + " but could not be decoded; passing through raw bytes undecoded",
	}
	if errors.Is(err, errDecompressionLimitExceeded) {
		ev.Kind = CompressionEventKindLimitExceeded
		ev.Detail = "request body decompression exceeded the hard limit; decompression aborted and raw bytes passed through undecoded"
	}
	observeCompressionEvent(c, ev)
}
