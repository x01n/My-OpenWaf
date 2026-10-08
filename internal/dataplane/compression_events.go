package dataplane

import (
	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/store"
)

// 解压降级审计使用的类别与规则标识。
//
// 与 smuggling_sniff 的 proto_violation 同一层含义：不是判定出来的攻击，
// 而是「这一层没能完成它该做的检查」的审计留痕。规则标识区分三种成因，
// 让运维在安全事件列表里能直接筛出「WAF 没能检测到的压缩请求体」。
const (
	compressionEventCategory = "decompression_degraded"

	compressionRuleUninspected = "compression:request_body_not_inspected"
	compressionRuleLimit       = "compression:decompression_limit_exceeded"
	compressionRuleMalformed   = "compression:request_body_decode_failed"
)

/**
 * ContextWithCompressionEventObserver 把解压降级的接收端挂到请求上下文。
 *
 * 方向与 js_request.go 的 ContextWithJSResponseRuntime 相反：那边是 proxy
 * 向数据面要运行时，这边是数据面把「事件该往哪写」交给 proxy。proxy 不能
 * import internal/observability，也不该认识站点与请求标识，因此事件载荷里
 * 只有「发生了什么」，归属信息在这里补齐。
 *
 * @param c Hertz 请求上下文。
 * @param opts 数据面选项（取事件写入器）。
 * @param siteID 站点 ID。
 * @param requestID 请求 ID。
 * @param clientIP 客户端 IP 文本。
 * @param host 请求 Host。
 * @param method 请求方法。
 * @param userAgent 请求 UA。
 */
func ContextWithCompressionEventObserver(c *app.RequestContext, opts Options, siteID uint, requestID, clientIP, host, method, userAgent string) {
	if c == nil || opts.Writer == nil {
		return
	}
	writer := opts.Writer
	proxy.ContextWithCompressionEventObserver(c, func(ev proxy.CompressionEvent) {
		writer.RecordEvent(store.SecurityEvent{
			SiteID:    siteID,
			RequestID: requestID,
			ClientIP:  clientIP,
			Host:      host,
			Path:      string(c.Path()),
			Method:    method,
			UserAgent: userAgent,
			RuleIDStr: compressionRuleIDForEvent(ev.Kind),
			RuleName:  "compressed request body not inspected",
			RuleDesc:  ev.Detail,
			Phase:     "request_decode",
			Action:    string(action.Observe),
			Category:  compressionEventCategory,
			MatchDesc: "content_encoding=" + ev.Encoding + " kind=" + string(ev.Kind),
		})
	})
}

// compressionRuleIDForEvent 把降级成因映射成稳定的事件规则标识。
func compressionRuleIDForEvent(kind proxy.CompressionEventKind) string {
	switch kind {
	case proxy.CompressionEventKindLimitExceeded:
		return compressionRuleLimit
	case proxy.CompressionEventKindMalformed:
		return compressionRuleMalformed
	default:
		return compressionRuleUninspected
	}
}

/**
 * recordUndetectedCompressedBodyEvent 为「采样阶段没能解出明文」的压缩请求体
 * 记一条安全事件。
 *
 * 用户的裁定是「降级而不是不处理」：请求照常按原始压缩字节转发，但必须在
 * 审计里留下「这部分内容 WAF 没有检测」。三种成因：
 *
 *   - 采样解压产出超限（压缩炸弹防护触发，解压已中断）；
 *   - 压缩体超出偷读前缀，采样解压读不到帧尾（zstd 超过 64 KiB 即如此）；
 *   - 采样器不认识声明的内容编码形态。
 *
 * 只在请求带 Content-Encoding 且采样确实没解出明文时记录，无编码的绝大多数
 * 请求不会建立快照，这里直接返回。
 *
 * @param c Hertz 请求上下文。
 * @param opts 数据面选项。
 * @param siteID 站点 ID。
 * @param requestID 请求 ID。
 * @param clientIP 客户端 IP 文本。
 * @param host 请求 Host。
 * @param method 请求方法。
 * @param userAgent 请求 UA。
 */
func recordUndetectedCompressedBodyEvent(c *app.RequestContext, opts Options, siteID uint, requestID, clientIP, host, method, userAgent string) {
	if c == nil || opts.Writer == nil || !c.Request.IsBodyStream() {
		return
	}
	snap, ok := requestBodySnapshotFromContext(c)
	if !ok {
		return
	}
	if snap.inspectionLimitExceededEncoding != "" {
		writeCompressionDegradedEvent(opts, siteID, requestID, clientIP, host, string(c.Path()), method, userAgent,
			compressionRuleLimit, proxy.CompressionEventKindLimitExceeded, snap.inspectionLimitExceededEncoding)
		return
	}
	if snap.inspectionUndetectedEncoding != "" {
		writeCompressionDegradedEvent(opts, siteID, requestID, clientIP, host, string(c.Path()), method, userAgent,
			compressionRuleUninspected, proxy.CompressionEventKindMalformed, snap.inspectionUndetectedEncoding)
	}
}

// writeCompressionDegradedEvent 落一条解压降级的观察型安全事件。
func writeCompressionDegradedEvent(opts Options, siteID uint, requestID, clientIP, host, path, method, userAgent, ruleID string, kind proxy.CompressionEventKind, encoding string) {
	if opts.Writer == nil {
		return
	}
	opts.Writer.RecordEvent(store.SecurityEvent{
		SiteID:    siteID,
		RequestID: requestID,
		ClientIP:  clientIP,
		Host:      host,
		Path:      path,
		Method:    method,
		UserAgent: userAgent,
		RuleIDStr: ruleID,
		RuleName:  "compressed request body not inspected",
		RuleDesc:  "request body kept compressed because the inspection sample could not be decoded; content was forwarded without WAF inspection",
		Phase:     "request_decode",
		Action:    string(action.Observe),
		Category:  compressionEventCategory,
		MatchDesc: "content_encoding=" + encoding + " kind=" + string(kind),
	})
}
