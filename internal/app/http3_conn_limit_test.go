package app

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// TestHTTP3LoopbackTransportsBoundPerHostConnections 固定 h3 内环回注 transport 的连接上限。
//
// 与 internal/proxy/upstream_conn_limit_test.go 同一口径：上限必须为正，且不得大于
// MaxIdleConns。缺失上限时，一次高并发洪峰会按「每个拿不到空闲连接的请求各拨一条连接」
// 增长，与入站连接争用同一个本机临时端口池（默认 28232 个）；共享上游 transport 已在
// 实测中因此出现 i/o timeout 成片、RPS 从 9940 掉到 2531（见 internal/proxy/proxy.go）。
//
// 两个 transport 的职责不同，断言一致：proxyTransport 是 h2 主回注通道，
// proxyHTTP11Transport 只用于 WebSocket 升级桥接（serveHTTP3WebSocketBridge）。
func TestHTTP3LoopbackTransportsBoundPerHostConnections(t *testing.T) {
	srv := NewHTTP3Server(HTTP3ServerConfig{
		Bind: "127.0.0.1:8443",
		RouteTable: http3RouteTable{
			exact: map[string]string{
				"loopback-conn-limit.example.test": "127.0.0.1:9443",
			},
		},
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	})
	if srv == nil {
		t.Fatal("NewHTTP3Server 返回 nil")
	}

	for name, tr := range map[string]*http.Transport{
		"h2 loopback":   srv.proxyTransport,
		"http11 bridge": srv.proxyHTTP11Transport,
	} {
		if tr == nil {
			t.Fatalf("%s transport is nil", name)
		}
		if tr.MaxConnsPerHost <= 0 {
			t.Fatalf("%s MaxConnsPerHost = %d, want > 0", name, tr.MaxConnsPerHost)
		}
		if tr.MaxConnsPerHost > tr.MaxIdleConns {
			t.Fatalf("%s MaxConnsPerHost = %d exceeds MaxIdleConns = %d", name, tr.MaxConnsPerHost, tr.MaxIdleConns)
		}
	}
}
