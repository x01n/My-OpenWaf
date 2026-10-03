package cache

import (
	"testing"

	rueidis "github.com/redis/rueidis"
)

// newHotCacheFailureClient 用故障注入模式 mock 制造确定性的命令失败：
// 与指挥真实不可达端口等价，但不依赖 OS 端口状态，测试更稳且更快。
func newHotCacheFailureClient(t *testing.T) (client rueidis.Client, kv *HotCache) {
	t.Helper()
	mock := startKVMiniRedisFailAll(t)
	client = newKVTestClient(t, mock.ln.Addr().String())
	return client, newSilentHotCache(client)
}

func TestHotCacheRedisFailureCountsAsErrorNotMissOnMock(t *testing.T) {
	_, h := newHotCacheFailureClient(t)
	var dest map[string]string
	if h.Get("some-key", &dest) {
		t.Fatal("故障注入下 Get 应返回 false")
	}
	if h.ErrorCount() != 1 {
		t.Errorf("ErrorCount = %d, want 1 —— 命令失败应计为故障", h.ErrorCount())
	}
	if _, misses := h.HitStats(); misses != 0 {
		t.Errorf("misses = %d, want 0 —— 故障不应计为未命中", misses)
	}
}

func TestHotCacheGetBytesFailureCountsAsErrorOnMock(t *testing.T) {
	_, h := newHotCacheFailureClient(t)
	if h.GetBytes("k") != nil {
		t.Fatal("故障注入下 GetBytes 应返回 nil")
	}
	if h.ErrorCount() != 1 {
		t.Errorf("ErrorCount = %d, want 1", h.ErrorCount())
	}
}

func TestHotCacheErrorLogThrottledOnMock(t *testing.T) {
	_, h := newHotCacheFailureClient(t)
	var dest string
	h.Get("k", &dest)
	if !h.errLogging.Load() {
		t.Error("故障期间 errLogging 应保持置位")
	}
	if h.Available() {
		t.Fatal("首次故障后 HotCache 应进入短时熔断")
	}
	h.unavailableUntil.Store(0)
	h.Get("k", &dest)
	if h.ErrorCount() != 2 {
		t.Errorf("ErrorCount = %d, want 2 —— 熔断到期后应重新探测", h.ErrorCount())
	}
}
