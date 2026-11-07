package transport

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

/**
 * TestUpstreamHTTP3EarlyMethodAllowsOnlyBodylessSafeMethods 锁定上游 0-RTT 的启用条件。
 *
 * 0-RTT 的 early 数据可被中间人重放，只有「无请求体的安全方法」才允许沿用
 * 早期数据。任何带 body 的请求都必须退回 1-RTT：一旦 0-RTT 被拒，我们没有
 * 可靠手段保证 body 完整重放，重试会产生半个请求。
 */
func TestUpstreamHTTP3EarlyMethodAllowsOnlyBodylessSafeMethods(t *testing.T) {
	newReq := func(method string, body io.Reader) *http.Request {
		req := &http.Request{
			Method: method,
			URL:    &url.URL{Scheme: "https", Host: "upstream.example", Path: "/"},
			Header: make(http.Header),
		}
		if body != nil {
			req.Body = io.NopCloser(body)
		}
		return req
	}

	tests := []struct {
		name   string
		method string
		body   io.Reader
		want   string
		wantOK bool
	}{
		{name: "GET 无 body 走 0-RTT", method: http.MethodGet, want: "GET_0RTT", wantOK: true},
		{name: "HEAD 无 body 走 0-RTT", method: http.MethodHead, want: "HEAD_0RTT", wantOK: true},
		{name: "小写 get 归一化后走 0-RTT", method: "get", want: "GET_0RTT", wantOK: true},
		{name: "POST 永不走 0-RTT", method: http.MethodPost, wantOK: false},
		{name: "PUT 永不走 0-RTT", method: http.MethodPut, wantOK: false},
		{name: "DELETE 永不走 0-RTT", method: http.MethodDelete, wantOK: false},
		{name: "GET 带 body 不走 0-RTT", method: http.MethodGet, body: strings.NewReader("x"), wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := upstreamHTTP3EarlyMethod(newReq(tc.method, tc.body))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if got != tc.want {
				t.Fatalf("method = %q, want %q", got, tc.want)
			}
		})
	}
}

/**
 * TestUpstreamHTTP3EarlyMethodRejectsNonHTTPSAndNilRequest 锁定入参防御。
 *
 * http3 只承载 https URL；scheme 不是 https 时 0-RTT 伪方法会被下游 transport
 * 直接判为不支持，因此这里提前返回 false，避免把错误推迟到连接建立阶段。
 */
func TestUpstreamHTTP3EarlyMethodRejectsNonHTTPSAndNilRequest(t *testing.T) {
	if _, ok := upstreamHTTP3EarlyMethod(nil); ok {
		t.Fatal("nil request must not enable 0-RTT")
	}
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "http", Host: "upstream.example", Path: "/"},
		Header: make(http.Header),
	}
	if _, ok := upstreamHTTP3EarlyMethod(req); ok {
		t.Fatal("plaintext http request must not enable 0-RTT")
	}
	if _, ok := upstreamHTTP3EarlyMethod(&http.Request{Method: http.MethodGet}); ok {
		t.Fatal("request without URL must not enable 0-RTT")
	}
}

/**
 * TestNewUpstreamHTTP3RoundTripperNilBase 锁定 nil 防御。
 */
func TestNewUpstreamHTTP3RoundTripperNilBase(t *testing.T) {
	if rt := newUpstreamHTTP3RoundTripper(nil); rt != nil {
		t.Fatalf("wrapper for nil transport = %v, want nil", rt)
	}
}
