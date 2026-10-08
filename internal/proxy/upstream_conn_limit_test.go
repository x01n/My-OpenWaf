package proxy

import (
	"testing"

	"My-OpenWaf/internal/snapshot"
)

// TestSharedTransportForUpstreamBoundsConcurrentConnections 固定上游并发连接上限。
//
// 该上限缺失时，一次高并发洪峰会让每个拿不到空闲连接的请求各拨一条上游连接：
// 这些连接与入站连接争用同一个本机临时端口池（默认 32768-60999，共 28232 个），
// 实测 c=20000 时进程持有的上游连接峰值 20395 条、临时端口占用峰值 25696/28232，
// i/o timeout 成片出现（该场景 2531 RPS / 35316 次 timeout）。
//
// 上限必须为正，且不得大于 MaxIdleConns：Go 的 Transport 在连接释放时只会把连接
// 放回空闲池，池满即关闭，因此上限超过池容量会让连接释放后无处回收、复用率退化。
func TestSharedTransportForUpstreamBoundsConcurrentConnections(t *testing.T) {
	rt := snapshot.SiteRuntime{}
	for _, base := range []string{"http://127.0.0.1:8080", "https://127.0.0.1:8443"} {
		tr := SharedTransportForUpstream(rt, base)
		if tr.MaxConnsPerHost <= 0 {
			t.Fatalf("%s: MaxConnsPerHost = %d, want > 0", base, tr.MaxConnsPerHost)
		}
		if tr.MaxConnsPerHost > tr.MaxIdleConns {
			t.Fatalf("%s: MaxConnsPerHost = %d exceeds MaxIdleConns = %d", base, tr.MaxConnsPerHost, tr.MaxIdleConns)
		}
	}
}
