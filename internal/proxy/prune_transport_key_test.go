package proxy

import (
	"testing"
	"time"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

// siteRuntimeForPruneTest 以显式站点字段构造站点 runtime，供活跃键相关的 prune 测试使用。
func siteRuntimeForPruneTest(host, base string, mutate func(*store.Site)) snapshot.SiteRuntime {
	site := store.Site{Host: host, UpstreamURLs: base, Enabled: true}
	if mutate != nil {
		mutate(&site)
	}
	return snapshot.SiteRuntime{Site: site, UpstreamURLs: []string{base}}
}

// snapshotForPruneTest 构造只引用给定站点 runtime 的快照。
func snapshotForPruneTest(runtimes ...snapshot.SiteRuntime) *snapshot.Snapshot {
	sites := make(map[string]*snapshot.SiteRuntime, len(runtimes))
	for i := range runtimes {
		sites[runtimes[i].Site.Host] = &runtimes[i]
	}
	return &snapshot.Snapshot{Sites: sites}
}

// TestPruneInactiveUpstreamTransportsKeepsPlainHTTPTransportOfTLSSite 覆盖活跃键漂移：
// 明文（http://）上游的 transport 不配置 TLSClientConfig，建池键的 TLS 维度恒为零值
// （见 sharedTransportForUpstreamClassified）；若活跃键把站点的 SNI/skip-verify/证书
// 指纹写进去，该键就与池内键不同构，站点自己的 transport 会被判为不活跃而删除。
// upstream-tab 的 TLS 表单对任何 scheme 都可见可保存，组合在生产可达。
func TestPruneInactiveUpstreamTransportsKeepsPlainHTTPTransportOfTLSSite(t *testing.T) {
	rt := siteRuntimeForPruneTest("prune-plain-tls.test", "http://127.0.0.1:8080", func(s *store.Site) {
		s.UpstreamTLSServerName = "prune-plain-tls-sni.example"
		s.UpstreamTLSSkipVerify = true
	})
	tr := SharedTransportForUpstream(rt, "http://127.0.0.1:8080")
	sn := snapshotForPruneTest(rt)

	pruned := PruneInactiveUpstreamTransports(sn)
	if again := SharedTransportForUpstream(rt, "http://127.0.0.1:8080"); again != tr {
		t.Fatalf("active plain HTTP transport was evicted from the pool (pruned=%+v)", pruned)
	}
}

// TestPruneInactiveUpstreamTransportsKeepsEveryUpstreamSchemeOfSite 覆盖多上游站点：
// 站点可配置多个上游，池键不含 host，活跃集必须覆盖每个上游 scheme 决定的键，
// 否则非首个上游（协议优先级通常更高的 https/h3）的 transport 会被误删。
func TestPruneInactiveUpstreamTransportsKeepsEveryUpstreamSchemeOfSite(t *testing.T) {
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			Host:                  "prune-multi.test",
			UpstreamURLs:          "http://127.0.0.1:8080, https://127.0.0.1:9443",
			UpstreamTLSServerName: "prune-multi-sni.example",
			Enabled:               true,
		},
		UpstreamURLs: []string{"http://127.0.0.1:8080", "https://127.0.0.1:9443"},
	}
	httpsTr := SharedTransportForUpstream(rt, "https://127.0.0.1:9443")
	sn := snapshotForPruneTest(rt)

	pruned := PruneInactiveUpstreamTransports(sn)
	if again := SharedTransportForUpstream(rt, "https://127.0.0.1:9443"); again != httpsTr {
		t.Fatalf("HTTPS transport of a multi-upstream site was evicted (pruned=%+v)", pruned)
	}
}

// TestPruneInactiveUpstreamTransportsH2CSiteDoesNotEvictHTTPSPool 复核 H-2 报告的结论：
// h2c 站点产出的活跃键（h2cPrior=true）确实永不匹配池内键，因为 h2c 走
// h2cTransportForUpstream 单例、从不写入 transportPool；但这只让该条目在活跃集里
// 空转，不会让任何在用 transport 被删除——同 TLS 字段的 https 站点由自身活跃键保护。
func TestPruneInactiveUpstreamTransportsH2CSiteDoesNotEvictHTTPSPool(t *testing.T) {
	const sharedSNI = "prune-h2c-shared-sni.example"
	httpsRT := siteRuntimeForPruneTest("prune-h2c-https.test", "https://127.0.0.1:9443", func(s *store.Site) {
		s.UpstreamTLSServerName = sharedSNI
		s.UpstreamTLSSkipVerify = true
	})
	h2cRT := siteRuntimeForPruneTest("prune-h2c-plain.test", "h2c://127.0.0.1:9090", func(s *store.Site) {
		s.UpstreamTLSServerName = sharedSNI
		s.UpstreamTLSSkipVerify = true
	})
	httpsTr := SharedTransportForUpstream(httpsRT, "https://127.0.0.1:9443")
	sn := snapshotForPruneTest(httpsRT, h2cRT)

	pruned := PruneInactiveUpstreamTransports(sn)
	if again := SharedTransportForUpstream(httpsRT, "https://127.0.0.1:9443"); again != httpsTr {
		t.Fatalf("HTTPS transport sharing TLS fields with an h2c site was evicted (pruned=%+v)", pruned)
	}
}

// TestPruneInactiveUpstreamTransportsKeepsLaterH3UpstreamOfSite 覆盖 h3 活跃集的同口径修正：
// activeH3 原先只看站点首条上游，站点把 h3 放在非首位时，其 h3 transport 会被判为
// 不活跃而连带 client 一起删除。
func TestPruneInactiveUpstreamTransportsKeepsLaterH3UpstreamOfSite(t *testing.T) {
	const h3Host = "prune-multi-h3.test:8443"
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			Host:         "prune-multi-h3-site.test",
			UpstreamURLs: "http://127.0.0.1:8080, h3://" + h3Host,
			Enabled:      true,
		},
		UpstreamURLs: []string{"http://127.0.0.1:8080", "h3://" + h3Host},
	}
	tr := http3TransportForUpstream(rt, h3Host)
	sharedPooledClient(tr, 30*time.Second)
	sharedPooledClient(tr, 0)
	defer func() {
		http3ClientMu.Lock()
		delete(http3Clients, tr)
		delete(http3NoTimeoutClients, tr)
		http3ClientMu.Unlock()
		http3TransportMu.Lock()
		delete(http3TransportPool, http3TransportKey{
			upstreamHost:          h3Host,
			tlsServerName:         rt.Site.UpstreamTLSServerName,
			tlsSkipVerify:         rt.Site.UpstreamTLSSkipVerify,
			clientCertFingerprint: upstreamClientCertFingerprint(rt),
		})
		http3TransportMu.Unlock()
	}()
	sn := snapshotForPruneTest(rt)

	PruneInactiveUpstreamTransports(sn)

	http3TransportMu.RLock()
	_, stillPresent := http3TransportPool[http3TransportKey{upstreamHost: h3Host}]
	http3TransportMu.RUnlock()
	if !stillPresent {
		t.Fatal("h3 transport of a non-first upstream was evicted from the pool")
	}
	http3ClientMu.RLock()
	_, hasClient := http3Clients[tr]
	_, hasNoTimeoutClient := http3NoTimeoutClients[tr]
	http3ClientMu.RUnlock()
	if !hasClient || !hasNoTimeoutClient {
		t.Fatalf("h3 clients of a non-first upstream were evicted: buffered=%v no-timeout=%v", hasClient, hasNoTimeoutClient)
	}
}

// TestPruneInactiveUpstreamTransportsStillRemovesGenuinelyInactive 是修复的回归边界：
// 收敛活跃键构造后，真正不再被任何站点引用的 transport 及其 client 仍必须被删除。
// 该用例不比对 PruneStats 计数——transportPool/clientCache 是包级共享状态，同包其他
// 用例（含 t.Fatalf 提前返回者）留下的条目会一并计入；只看目标键的去留。
func TestPruneInactiveUpstreamTransportsStillRemovesGenuinelyInactive(t *testing.T) {
	dead := siteRuntimeForPruneTest("prune-dead.test", "https://127.0.0.1:9444", func(s *store.Site) {
		s.UpstreamTLSServerName = "prune-dead-sni.example"
	})
	tr := SharedTransportForUpstream(dead, "https://127.0.0.1:9444")
	sharedClient(tr)
	sharedNoTimeoutClient(tr)

	keep := siteRuntimeForPruneTest("prune-keep.test", "https://127.0.0.1:9445", func(s *store.Site) {
		s.UpstreamTLSServerName = "prune-keep-sni.example"
	})
	sn := snapshotForPruneTest(keep)

	PruneInactiveUpstreamTransports(sn)

	transportMu.RLock()
	_, stillPresent := transportPool[transportKeyForUpstream("https://127.0.0.1:9444", dead)]
	transportMu.RUnlock()
	if stillPresent {
		t.Fatal("genuinely inactive transport survived the prune")
	}
	clientPoolMu.RLock()
	_, hasClient := clientCache[tr]
	_, hasNoTimeoutClient := noTimeoutClientPool[tr]
	clientPoolMu.RUnlock()
	if hasClient || hasNoTimeoutClient {
		t.Fatalf("inactive transport clients survived the prune: buffered=%v no-timeout=%v", hasClient, hasNoTimeoutClient)
	}
}
