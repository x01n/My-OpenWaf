package upstream

import (
	"net/http"
	"testing"
	"time"
)

// TestHTTPProbeTransportBoundsPerHostConnections 固定探测 transport 的每主机连接上限。
//
// 与 internal/proxy/upstream_conn_limit_test.go 同一口径：上限必须为正，且不得大于
// MaxIdleConns —— Go 的 Transport 在连接释放时只会把连接放回空闲池，池满即关闭，
// 上限超过池容量会让连接释放后无处回收、复用率退化。
//
// 当前探测是串行路径（Pool.ProbeWithResult 逐个 upstream 调用 probe），这里固定的是
// 防御性约束：一旦探测改成并发，没有上限就会退化成「每个请求各拨一条连接」，
// 与上游 transport 踩过的临时端口耗尽是同一形态。
//
// 既有断言（health_test.go 的 TestHTTPProbeDefaultClientSupportsTLS10HTTPSUpstream 与
// TestHTTPProbeH2CClientUsesBoundedTransport 逐字钉住 MaxIdleConns=128 /
// MaxIdleConnsPerHost=32）保持不变，本用例只覆盖新增的上限字段。
func TestHTTPProbeTransportBoundsPerHostConnections(t *testing.T) {
	clients := map[string]*http.Client{
		"default": newHTTPProbeClient(time.Second),
		"h2c":     newHTTPProbeH2CClient(time.Second),
	}
	for name, client := range clients {
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("%s probe transport = %T, want *http.Transport", name, client.Transport)
		}
		if tr.MaxConnsPerHost <= 0 {
			t.Fatalf("%s probe MaxConnsPerHost = %d, want > 0", name, tr.MaxConnsPerHost)
		}
		if tr.MaxConnsPerHost > tr.MaxIdleConns {
			t.Fatalf("%s probe MaxConnsPerHost = %d exceeds MaxIdleConns = %d", name, tr.MaxConnsPerHost, tr.MaxIdleConns)
		}
	}
}
