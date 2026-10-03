package cache

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	rueidis "github.com/redis/rueidis"
)

func newSilentHotCache(client rueidis.Client) *HotCache {
	return NewHotCache(client, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestHotCacheNilRedisIsNoop 验证未配置 Redis 时所有调用安全降级。
func TestHotCacheNilRedisIsNoop(t *testing.T) {
	h := newSilentHotCache(nil)

	var dest map[string]string
	if h.Get("k", &dest) {
		t.Error("nil Redis 时 Get 应返回 false")
	}
	if h.GetBytes("k") != nil {
		t.Error("nil Redis 时 GetBytes 应返回 nil")
	}
	h.Set("k", map[string]string{"a": "b"}, 0)
	h.SetBytes("k", []byte("x"), 0)

	hits, misses := h.HitStats()
	if hits != 0 || misses != 0 {
		t.Errorf("nil Redis 不应产生命中统计：hits=%d misses=%d", hits, misses)
	}
	if h.ErrorCount() != 0 {
		t.Errorf("nil Redis 不应计入故障：errs=%d", h.ErrorCount())
	}
}

// TestHotCacheNilReceiverSafe 验证 nil 接收者不 panic（metrics 采集路径会碰到）。
func TestHotCacheNilReceiverSafe(t *testing.T) {
	var h *HotCache
	if hits, misses := h.HitStats(); hits != 0 || misses != 0 {
		t.Errorf("nil 接收者应返回零值")
	}
	if h.ErrorCount() != 0 {
		t.Error("nil 接收者 ErrorCount 应为 0")
	}
	var dest string
	if h.Get("k", &dest) {
		t.Error("nil 接收者 Get 应返回 false")
	}
}

func newUnreachableRedisClient(t *testing.T) rueidis.Client {
	t.Helper()
	client, err := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:  []string{"127.0.0.1:1"},
		Dialer:       net.Dialer{Timeout: 200 * time.Millisecond},
		DisableRetry: true,
		DisableCache: true,
	})
	if client == nil && err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestHotCacheRedisFailureCountsAsErrorNotMiss(t *testing.T) {
	_, h := newHotCacheFailureClient(t)

	var dest map[string]string
	if h.Get("some-key", &dest) {
		t.Fatal("Redis 不可达时 Get 应返回 false")
	}

	hits, misses := h.HitStats()
	if hits != 0 {
		t.Errorf("hits = %d, want 0", hits)
	}
	if misses != 0 {
		t.Errorf("misses = %d, want 0 —— 连接失败不应计为未命中", misses)
	}
	if h.ErrorCount() != 1 {
		t.Errorf("ErrorCount = %d, want 1 —— 连接失败应计为故障", h.ErrorCount())
	}
}

// TestHotCacheGetBytesFailureCountsAsError 验证 GetBytes 与 Get 口径一致。
func TestHotCacheGetBytesFailureCountsAsError(t *testing.T) {
	_, h := newHotCacheFailureClient(t)
	if h.GetBytes("k") != nil {
		t.Fatal("Redis 不可达时 GetBytes 应返回 nil")
	}
	if _, misses := h.HitStats(); misses != 0 {
		t.Errorf("misses = %d, want 0", misses)
	}
	if h.ErrorCount() != 1 {
		t.Errorf("ErrorCount = %d, want 1", h.ErrorCount())
	}
}

func TestHotCacheErrorLogThrottled(t *testing.T) {
	_, h := newHotCacheFailureClient(t)
	var dest string
	h.Get("k", &dest)
	if !h.errLogging.Load() {
		t.Error("故障期间 errLogging 应保持置位以抑制重复日志")
	}
	if h.Available() {
		t.Fatal("首次 Redis 故障后 HotCache 应进入短时熔断")
	}

	started := time.Now()
	h.Get("k", &dest)
	if elapsed := time.Since(started); elapsed >= 50*time.Millisecond {
		t.Fatalf("熔断期间 Get 耗时 %s，未快速回源", elapsed)
	}
	if h.ErrorCount() != 1 {
		t.Errorf("ErrorCount = %d, want 1 —— 熔断期间不应重复访问故障 Redis", h.ErrorCount())
	}

	h.unavailableUntil.Store(time.Now().Add(-time.Second).UnixNano())
	h.Get("k", &dest)
	if h.ErrorCount() != 2 {
		t.Errorf("ErrorCount = %d, want 2 —— 熔断到期后应重新探测 Redis", h.ErrorCount())
	}
}

func TestHotCacheIgnoresResultsFromReplacedClient(t *testing.T) {
	// 指针身份由 RESP3 mock 客户端承担；这两个客户端不发起任何命令，
	// 只作 recordReadErr/noteHealthy 的当前客户端比对锚点。
	newClient := func(t *testing.T) rueidis.Client {
		t.Helper()
		mock := startKVMiniRedis(t)
		return newKVTestClient(t, mock.ln.Addr().String())
	}

	t.Run("stale failure does not alter counters or breaker", func(t *testing.T) {
		oldClient := newClient(t)
		replacement := newClient(t)
		h := newSilentHotCache(oldClient)
		started := make(chan struct{})
		release := make(chan struct{})
		done := make(chan struct{})

		go func() {
			close(started)
			<-release
			h.recordReadErr(oldClient, "old-error", errors.New("stale redis failure"))
			h.recordReadErr(oldClient, "old-miss", rueidis.Nil)
			close(done)
		}()

		<-started
		h.SetRedis(replacement)
		close(release)
		<-done

		if h.ErrorCount() != 0 {
			t.Fatalf("ErrorCount = %d, want 0 for a stale client failure", h.ErrorCount())
		}
		if hits, misses := h.HitStats(); hits != 0 || misses != 0 {
			t.Fatalf("stale client changed hit stats: hits=%d misses=%d", hits, misses)
		}
		if h.unavailableUntil.Load() != 0 || h.errLogging.Load() {
			t.Fatal("stale client failure must not trip the replacement client's breaker")
		}
	})

	t.Run("stale success does not heal replacement failure or add hits", func(t *testing.T) {
		oldClient := newClient(t)
		replacement := newClient(t)
		h := newSilentHotCache(oldClient)
		started := make(chan struct{})
		release := make(chan struct{})
		accepted := make(chan bool, 1)

		go func() {
			close(started)
			<-release
			current := h.noteHealthy(oldClient)
			if current {
				h.hits.Add(1)
			}
			accepted <- current
		}()

		<-started
		h.SetRedis(replacement)
		h.recordReadErr(replacement, "new-error", errors.New("replacement redis failure"))
		breakerUntil := h.unavailableUntil.Load()
		close(release)
		if <-accepted {
			t.Fatal("a stale client's successful result must be rejected")
		}

		if h.ErrorCount() != 1 {
			t.Fatalf("ErrorCount = %d, want only the replacement client's failure", h.ErrorCount())
		}
		if hits, misses := h.HitStats(); hits != 0 || misses != 0 {
			t.Fatalf("stale success changed hit stats: hits=%d misses=%d", hits, misses)
		}
		if h.unavailableUntil.Load() != breakerUntil || !h.errLogging.Load() {
			t.Fatal("stale success must not heal the replacement client's breaker")
		}
	})
}
