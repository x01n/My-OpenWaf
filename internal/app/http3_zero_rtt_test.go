package app

import (
	"net/http"
	"testing"
)

/**
 * TestHTTP3ZeroRTTMethodAllowed 锁定 0-RTT 应用层白名单。
 *
 * RFC 9114 §8.1 要求服务端自行对 0-RTT 做重放防护。WAF 无法在应用层证明
 * 任意方法幂等，因此只放行 RFC 9110 定义的安全方法；其余方法在早期数据
 * 阶段一律返回 425，由客户端在握手完成后重发。
 */
func TestHTTP3ZeroRTTMethodAllowed(t *testing.T) {
	allowed := []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace, "get", " Head "}
	for _, method := range allowed {
		if !http3ZeroRTTMethodAllowed(method) {
			t.Fatalf("method %q must be allowed over 0-RTT", method)
		}
	}
	denied := []string{
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodConnect, "", "PURGE",
	}
	for _, method := range denied {
		if http3ZeroRTTMethodAllowed(method) {
			t.Fatalf("method %q must be rejected over 0-RTT", method)
		}
	}
}

/**
 * TestHTTP3RequestUsedZeroRTTWithoutConn 锁定无连接上下文时的保守取值。
 *
 * 缺少 *quic.Conn 说明请求并非来自 h3 连接（或连接已被回收），此时必须
 * 按「不是 0-RTT」处理，不能把未知当已知、把普通请求误判成早期数据。
 */
func TestHTTP3RequestUsedZeroRTTWithoutConn(t *testing.T) {
	if http3RequestUsedZeroRTT(nil) {
		t.Fatal("nil request must not be treated as 0-RTT")
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if http3RequestUsedZeroRTT(req) {
		t.Fatal("request without a quic conn in context must not be treated as 0-RTT")
	}
}
