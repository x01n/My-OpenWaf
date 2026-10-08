package proxy

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

// h3RaceRuntimeForTest 构造上游为 h3:// 的站点 runtime。
func h3RaceRuntimeForTest(host string) snapshot.SiteRuntime {
	return snapshot.SiteRuntime{
		Site:         store.Site{Host: "h3-race.test", UpstreamURLs: "h3://" + host, Enabled: true},
		UpstreamURLs: []string{"h3://" + host},
	}
}

// h3RaceSnapshotForTest 构造只引用给定 h3 上游的站点快照。
func h3RaceSnapshotForTest(hosts ...string) *snapshot.Snapshot {
	sites := make(map[string]*snapshot.SiteRuntime, len(hosts))
	for _, host := range hosts {
		rt := h3RaceRuntimeForTest(host)
		sites[host] = &rt
	}
	return &snapshot.Snapshot{Sites: sites}
}

// deleteH3PoolEntriesForTest 清除指定前缀的 h3 transport 池条目，隔离本测试对池的影响。
func deleteH3PoolEntriesForTest(prefix string) {
	http3TransportMu.Lock()
	for key := range http3TransportPool {
		if strings.HasPrefix(key.upstreamHost, prefix) {
			delete(http3TransportPool, key)
		}
	}
	http3TransportMu.Unlock()
}

// TestCloseIdleUpstreamTransportsH3PoolRace 是 H-1 的并发复现：
// CloseIdleUpstreamTransports 在 http3TransportMu.RLock 释放之后才 range
// http3TransportPool，而 PruneInactiveUpstreamTransports 的 delete 与
// http3TransportForUpstream 的赋值都在写锁内进行，两者与无锁遍历并发时构成
// map 迭代/写入竞态（生产表现为 fatal error: concurrent map iteration and map
// write，Go 运行时致命错误，无法 recover）。
//
// 读侧是自旋循环：先于写方启动并跑到写方结束，一旦写方落地任何池变更，读侧的
// 下一次遍历就会命中竞态，故单轮即可稳定复现，无需重试或扩大并发度。
// 修复前：-race 必须报出该竞态。修复后：-race 干净通过。
func TestCloseIdleUpstreamTransportsH3PoolRace(t *testing.T) {
	const (
		keepCount  = 256
		writerN    = 4
		burstSize  = 8
		roundCount = 400
	)
	defer deleteH3PoolEntriesForTest("race-")

	// 预置一批常驻 h3 transport，使每次遍历都跨越多条桶，放大无锁遍历窗口。
	keepHosts := make([]string, 0, keepCount)
	for i := 0; i < keepCount; i++ {
		host := fmt.Sprintf("race-keep-%03d.test", i)
		rt := h3RaceRuntimeForTest(host)
		http3TransportForUpstream(rt, host)
		keepHosts = append(keepHosts, host)
	}
	keepSnapshot := h3RaceSnapshotForTest(keepHosts...)

	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
				CloseIdleUpstreamTransports()
			}
		}
	}()

	var writerWG sync.WaitGroup
	for w := 0; w < writerN; w++ {
		writerWG.Add(1)
		go func(w int) {
			defer writerWG.Done()
			for round := 0; round < roundCount; round++ {
				for i := 0; i < burstSize; i++ {
					host := fmt.Sprintf("race-w%d-r%d-i%d.test", w, round, i)
					rt := h3RaceRuntimeForTest(host)
					http3TransportForUpstream(rt, host)
				}
				PruneInactiveUpstreamTransports(keepSnapshot)
			}
		}(w)
	}

	writerWG.Wait()
	close(stop)
	readerWG.Wait()

	// 常驻键在写方停止后仍应可复用，避免测试自身把池删空。
	for _, host := range keepHosts {
		rt := h3RaceRuntimeForTest(host)
		if tr := http3TransportForUpstream(rt, host); tr == nil {
			t.Fatalf("keep transport %s unexpectedly missing", host)
		}
	}
}
