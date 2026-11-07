package transport

import (
	"errors"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

/**
 * upstreamHTTP3RoundTripper 在 http3.Transport 之上补「0-RTT 发送」语义。
 *
 * quic-go 的 http3 包用私有约定表达 0-RTT：把请求方法写成 `GET_0RTT` /
 * `HEAD_0RTT`，ClientConn 见到这两种方法时不再等待握手完成，而是立即在
 * early 流上发出请求，并把实际方法改回 GET / HEAD。没有这层包装时，即使
 * TLSClientConfig 已经缓存了上游 session ticket，上游请求也永远走 1-RTT。
 *
 * 为什么不直接改 req.Method 而要多一层：`http.Client` 与 httputil.ReverseProxy
 * 都会用方法做语义判断（重定向、body 可重放性），在它们之上暴露 `GET_0RTT`
 * 会污染这些判断。因此只在交给 http3.Transport 之前对副本改写。
 */
type upstreamHTTP3RoundTripper struct {
	base *http3.Transport
}

/**
 * newUpstreamHTTP3RoundTripper 包装一个 h3 transport；nil 时返回 nil。
 *
 * @param base 已配置好的上游 h3 transport。
 * @return 带 0-RTT 语义的 RoundTripper，base 为 nil 时返回 nil。
 */
func newUpstreamHTTP3RoundTripper(base *http3.Transport) http.RoundTripper {
	if base == nil {
		return nil
	}
	return &upstreamHTTP3RoundTripper{base: base}
}

/**
 * RoundTrip 对安全方法尝试 0-RTT，并在 0-RTT 被拒时用 1-RTT 重发。
 *
 * 重发是安全的：`quic.Err0RTTRejected` 意味着服务端丢弃了全部 early 数据，
 * 请求从未被处理；且本方法只对无请求体的 GET / HEAD 启用，重放没有副作用。
 * 其它错误一律原样返回，避免把一次上游故障放大成两次请求。
 *
 * @param req 待转发的上游请求。
 * @return 上游响应或错误。
 */
func (t *upstreamHTTP3RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	earlyMethod, ok := upstreamHTTP3EarlyMethod(req)
	if !ok {
		return t.base.RoundTrip(req)
	}

	earlyReq := req.Clone(req.Context())
	earlyReq.Method = earlyMethod
	rsp, err := t.base.RoundTrip(earlyReq)
	if err == nil {
		return rsp, nil
	}
	if !errors.Is(err, quic.Err0RTTRejected) {
		return nil, err
	}

	retryReq := req.Clone(req.Context())
	if req.GetBody != nil {
		body, bodyErr := req.GetBody()
		if bodyErr != nil {
			return nil, err
		}
		retryReq.Body = body
	}
	return t.base.RoundTrip(retryReq)
}

/**
 * upstreamHTTP3EarlyMethod 判断请求能否以 0-RTT 发出，并返回对应的伪方法。
 *
 * 只允许 GET / HEAD：两者都是 RFC 9110 定义的安全方法，且天然没有请求体。
 * 带 body 的请求即使方法是 GET（语义上是读，但传输上有副作用风险）也不启用，
 * 因为 early 数据被拒时无法保证 body 能完整重放。
 *
 * @param req 待判断的请求。
 * @return 0-RTT 伪方法与是否启用；不启用时返回空串与 false。
 */
func upstreamHTTP3EarlyMethod(req *http.Request) (string, bool) {
	if req == nil || req.URL == nil || req.URL.Scheme != "https" {
		return "", false
	}
	if req.Body != nil && req.Body != http.NoBody {
		return "", false
	}
	switch strings.ToUpper(strings.TrimSpace(req.Method)) {
	case http.MethodGet:
		return http3.MethodGet0RTT, true
	case http.MethodHead:
		return http3.MethodHead0RTT, true
	default:
		return "", false
	}
}
