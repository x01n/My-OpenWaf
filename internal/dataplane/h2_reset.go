package dataplane

import (
	"github.com/cloudwego/hertz/pkg/app"
	forkhttp2 "github.com/x01n/http2"
)

// h2StreamResetter 用 fork 自己的 ErrCode 命名类型声明签名：接口方法签名
// 的身份比较要求类型完全相同，两个不同包各自定义的 uint32 命名类型
// （dataplane.http2ErrCode vs http2.ErrCode）不满足 identical 规则，
// 用本地类型声明会让断言恒 false——这是 r7.44 的原始缺陷。
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

// maybeH3ResetStream executes the per-request HTTP/3 reset closure that
// internal/app registered at inbound-request time. The closure performs
// quic.Stream.CancelWrite(H3_REQUEST_CANCELED) synchronously on this
// goroutine, so by the time the handler returns the stream is already
// canceled and any later write attempt (including quic-go's own
// post-handler flush) fails without emitting frames. The request here is a
// loopback request whose token was consumed from the internal header by
// applyInternalHTTP3RequestMetadata. The closure is one-shot: the context
// slot is cleared on execution so a repeated drop-adjacent call cannot
// double-fire.
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
