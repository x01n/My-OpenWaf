package proxy

import (
	"testing"
	"time"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

// h3SiteRuntimeForTest 构造一个上游为 h3:// 前缀的站点 runtime。
func h3SiteRuntimeForTest(t *testing.T, host string) snapshot.SiteRuntime {
	t.Helper()
	return snapshot.SiteRuntime{
		Site:         store.Site{Host: "h3.test", UpstreamURLs: "h3://" + host, Enabled: true},
		UpstreamURLs: []string{"h3://" + host},
	}
}

func TestSharedPooledClientH3PoolsAndStats(t *testing.T) {
	rt := h3SiteRuntimeForTest(t, "127.0.0.1:8443")
	tr := http3TransportForUpstream(rt, "127.0.0.1:8443")
	if tr == nil {
		t.Fatal("http3TransportForUpstream returned nil")
	}
	defer func() {
		http3ClientMu.Lock()
		delete(http3Clients, tr)
		delete(http3NoTimeoutClients, tr)
		http3ClientMu.Unlock()
		http3TransportMu.Lock()
		delete(http3TransportPool, http3TransportKey{
			upstreamHost:          "127.0.0.1:8443",
			tlsServerName:         rt.Site.UpstreamTLSServerName,
			tlsSkipVerify:         rt.Site.UpstreamTLSSkipVerify,
			clientCertFingerprint: upstreamClientCertFingerprint(rt),
		})
		http3TransportMu.Unlock()
	}()

	before := UpstreamTransportPoolStatsSnapshot()
	if before.HTTP3Transports < 1 {
		t.Fatalf("HTTP3Transports = %d, want >= 1", before.HTTP3Transports)
	}

	buffered := sharedPooledClient(tr, 30*time.Second)
	mid := UpstreamTransportPoolStatsSnapshot()
	if mid.HTTP3Clients != 1 || mid.HTTP3NoTimeoutClients != 0 {
		t.Fatalf("h3 client pools = %d/%d, want 1/0 after first buffered use", mid.HTTP3Clients, mid.HTTP3NoTimeoutClients)
	}
	if again := sharedPooledClient(tr, 30*time.Second); again != buffered {
		t.Fatal("sharedPooledClient(tr, 30s) returned a different instance, pool miss")
	}
	if got := UpstreamTransportPoolStatsSnapshot().HTTP3Clients; got != 1 {
		t.Fatalf("HTTP3Clients = %d after reuse, want still 1", got)
	}

	stream := sharedPooledClient(tr, 0)
	if stream == buffered {
		t.Fatal("no-timeout client unexpectedly shared the buffered instance")
	}
	if got := UpstreamTransportPoolStatsSnapshot().HTTP3NoTimeoutClients; got != 1 {
		t.Fatalf("HTTP3NoTimeoutClients = %d, want 1", got)
	}
}

func TestPruneInactiveUpstreamTransportsRemovesH3Clients(t *testing.T) {
	rt := h3SiteRuntimeForTest(t, "prune.test:8443")
	tr := http3TransportForUpstream(rt, "prune.test:8443")
	if tr == nil {
		t.Fatal("http3TransportForUpstream returned nil")
	}
	sharedPooledClient(tr, 30*time.Second)
	sharedPooledClient(tr, 0)

	if got := UpstreamTransportPoolStatsSnapshot(); got.HTTP3Transports < 1 || got.HTTP3Clients != 1 || got.HTTP3NoTimeoutClients != 1 {
		t.Fatalf("pre-prune h3 stats = %+v, want transport >=1 and client pools 1/1", got)
	}

	// 快照只引用一个非 h3 站点：h3 transport key 不在活跃集中，应连带 client 一并修剪。
	sn := &snapshot.Snapshot{
		Sites: map[string]*snapshot.SiteRuntime{
			"keep.test": {Site: store.Site{Host: "keep.test", UpstreamURLs: "http://127.0.0.1:8080", Enabled: true}, UpstreamURLs: []string{"http://127.0.0.1:8080"}},
		},
	}
	pruned := PruneInactiveUpstreamTransports(sn)
	if pruned.HTTP3Transports != 1 || pruned.HTTP3Clients != 1 || pruned.HTTP3NoTimeoutClients != 1 {
		t.Fatalf("PruneStats = %+v, want h3 transport/client/no-timeout-client 1/1/1", pruned)
	}
	if got := UpstreamTransportPoolStatsSnapshot(); got.HTTP3Transports != 0 || got.HTTP3Clients != 0 || got.HTTP3NoTimeoutClients != 0 {
		t.Fatalf("post-prune h3 stats = %+v, want all zero", got)
	}
}
