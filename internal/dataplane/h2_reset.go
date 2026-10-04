package dataplane

import (
	"github.com/cloudwego/hertz/pkg/app"
	forkhttp2 "github.com/x01n/http2"
)

/**
 * h2StreamResetter 用 fork 自己的 ErrCode 命名类型声明签名：接口方法签名
 * 的身份比较要求类型完全相同，两个不同包各自定义的 uint32 命名类型
 * （dataplane.http2ErrCode vs http2.ErrCode）不满足 identical 规则，
 * 用本地类型声明会让断言恒 false——这是 r7.44 的原始缺陷。
 */
type h2StreamResetter interface {
	ResetStreamHandler(code forkhttp2.ErrCode) bool
}

const h2ErrCodeCancel = forkhttp2.ErrCodeCancel

func maybeH2ResetStream(guard *InboundProtocolGuard, code forkhttp2.ErrCode) bool {
	if guard == nil || guard.conn == nil {
		return false
	}
	resetter, ok := guard.conn.(h2StreamResetter)
	if !ok || resetter == nil {
		return false
	}
	return resetter.ResetStreamHandler(code)
}

/**
 * maybeH3ResetStream 执行 internal/app 在入站请求时注册的逐请求 HTTP/3 重置闭包。
 * 该闭包在本 goroutine 上同步执行 quic.Stream.CancelWrite(H3_REQUEST_CANCELED)，
 * 因此 handler 返回时流已被取消，此后任何写入尝试（包括 quic-go 自己在 handler
 * 之后的 flush）都会失败且不发出任何帧。这里的请求是一条回环请求，其 token 已由
 * applyInternalHTTP3RequestMetadata 从内部请求头中消费。闭包是一次性的：执行时
 * 会清空上下文槽位，因此重复的、紧邻 drop 的调用不会二次触发。
 */
func maybeH3ResetStream(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	value, ok := c.Get(InternalHTTP3ResetTokenHeader)
	if !ok {
		return false
	}
	reset, ok := value.(func())
	if !ok || reset == nil {
		return false
	}
	reset()
	c.Set(InternalHTTP3ResetTokenHeader, (func())(nil))
	return true
}
