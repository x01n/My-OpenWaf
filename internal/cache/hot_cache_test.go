package cache

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

func newSilentHotCache(client *goredis.Client) *HotCache {
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

// TestHotCacheRedisFailureCountsAsErrorNotMiss 是核心回归：
// Redis 故障必须计入 errs 而非 misses。若两者混淆，Redis 整体宕机时
// 命中率会显示为 0%，看起来像缓存策略失效而非依赖不可用，误导排障方向。
//
// 用一个指向无人监听端口的客户端制造确定性的连接失败。
func TestHotCacheRedisFailureCountsAsErrorNotMiss(t *testing.T) {
	// 127.0.0.1:1 通常无监听，拨号立即失败。
	client := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 200_000_000, // 200ms，避免拖慢测试
		MaxRetries:  -1,          // 关闭重试，让失败尽快返回
	})
	defer client.Close()

	h := newSilentHotCache(client)
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
	client := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 200_000_000,
		MaxRetries:  -1,
	})
	defer client.Close()

	h := newSilentHotCache(client)
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

// TestHotCacheErrorLogThrottled 验证故障期间不会每次都打日志。
// 连续多次失败后 errLogging 应保持置位，故障计数仍逐次累加。
func TestHotCacheErrorLogThrottled(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 200_000_000,
		MaxRetries:  -1,
	})
	defer client.Close()

	h := newSilentHotCache(client)
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
	newClient := func(t *testing.T, addr string) *goredis.Client {
		t.Helper()
		client := goredis.NewClient(&goredis.Options{Addr: addr})
		t.Cleanup(func() { _ = client.Close() })
		return client
	}

	t.Run("stale failure does not alter counters or breaker", func(t *testing.T) {
		oldClient := newClient(t, "127.0.0.1:1")
		replacement := newClient(t, "127.0.0.1:2")
		h := newSilentHotCache(oldClient)
		started := make(chan struct{})
		release := make(chan struct{})
		done := make(chan struct{})

		go func() {
			close(started)
			<-release
			h.recordReadErr(oldClient, "old-error", errors.New("stale redis failure"))
			h.recordReadErr(oldClient, "old-miss", goredis.Nil)
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
		oldClient := newClient(t, "127.0.0.1:3")
		replacement := newClient(t, "127.0.0.1:4")
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
