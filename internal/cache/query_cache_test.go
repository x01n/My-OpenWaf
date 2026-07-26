package cache

import (
	"testing"
	"time"
)

// ---- Get/Set 基础读写 ----

func TestQueryCacheGetSetRoundTrip(t *testing.T) {
	qc := NewQueryCache(5 * time.Second)
	defer qc.Close()

	qc.Set("k1", 42)
	v, ok := qc.Get("k1")
	if !ok || v.(int) != 42 {
		t.Fatalf("want (42, true), got (%v, %v)", v, ok)
	}
}

func TestQueryCacheGetMissReturnsFalse(t *testing.T) {
	qc := NewQueryCache(5 * time.Second)
	defer qc.Close()

	v, ok := qc.Get("nonexistent")
	if ok || v != nil {
		t.Fatalf("miss: want (nil, false), got (%v, %v)", v, ok)
	}
}

// ---- TTL 过期 ----

func TestQueryCacheGetExpiredEntryReturnsMiss(t *testing.T) {
	qc := NewQueryCache(5 * time.Second)
	defer qc.Close()

	// 用极短的 TTL 写入
	qc.SetWithTTL("exp-key", "value", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	_, ok := qc.Get("exp-key")
	if ok {
		t.Fatal("expired entry should be a miss")
	}
}

func TestQueryCacheSetWithTTLCustomDuration(t *testing.T) {
	qc := NewQueryCache(5 * time.Second)
	defer qc.Close()

	qc.SetWithTTL("ttl-key", "hello", 100*time.Millisecond)
	v, ok := qc.Get("ttl-key")
	if !ok || v.(string) != "hello" {
		t.Fatalf("before expiry: want (hello, true), got (%v, %v)", v, ok)
	}

	time.Sleep(150 * time.Millisecond)
	_, ok = qc.Get("ttl-key")
	if ok {
		t.Fatal("after TTL expiry: want miss")
	}
}

// ---- HitStats ----

func TestQueryCacheHitStats(t *testing.T) {
	qc := NewQueryCache(5 * time.Second)
	defer qc.Close()

	qc.Set("s", "v")
	qc.Get("s")       // hit
	qc.Get("s")       // hit
	qc.Get("missing") // miss

	hits, misses := qc.HitStats()
	if hits != 2 {
		t.Fatalf("want hits=2, got %d", hits)
	}
	if misses != 1 {
		t.Fatalf("want misses=1, got %d", misses)
	}
}

func TestQueryCacheHitStatsNilReceiverNoPanic(t *testing.T) {
	var qc *QueryCache
	hits, misses := qc.HitStats()
	if hits != 0 || misses != 0 {
		t.Fatalf("nil receiver: want (0,0), got (%d,%d)", hits, misses)
	}
}

// ---- Invalidate / InvalidateAll ----

func TestQueryCacheInvalidateRemovesKey(t *testing.T) {
	qc := NewQueryCache(5 * time.Second)
	defer qc.Close()

	qc.Set("del", 99)
	qc.Invalidate("del")
	_, ok := qc.Get("del")
	if ok {
		t.Fatal("invalidated key should be gone")
	}
}

func TestQueryCacheInvalidateNonexistentKeyNoPanic(t *testing.T) {
	qc := NewQueryCache(5 * time.Second)
	defer qc.Close()

	qc.Invalidate("never-set") // 不应 panic
}

func TestQueryCacheInvalidateAllClearsEverything(t *testing.T) {
	qc := NewQueryCache(5 * time.Second)
	defer qc.Close()

	qc.Set("a", 1)
	qc.Set("b", 2)
	qc.Set("c", 3)
	qc.InvalidateAll()

	for _, key := range []string{"a", "b", "c"} {
		if _, ok := qc.Get(key); ok {
			t.Fatalf("key %q should be gone after InvalidateAll", key)
		}
	}
}

// ---- 容量上限（storeLocked） ----

func TestQueryCacheCapLimitDropsNewEntryWhenFull(t *testing.T) {
	// 设置 maxEntries=2，写满后新 key 不应能插入（除非有过期项可清理）
	qc := &QueryCache{
		entries:    make(map[string]*queryCacheEntry),
		ttl:        time.Hour,
		maxEntries: 2,
		stopCh:     make(chan struct{}),
	}
	defer qc.Close()

	qc.Set("k1", 1)
	qc.Set("k2", 2)
	// 第3个 key（无过期项可回收）应被跳过
	qc.Set("k3", 3)

	qc.mu.RLock()
	n := len(qc.entries)
	qc.mu.RUnlock()
	if n > 2 {
		t.Fatalf("entries should not exceed maxEntries=2, got %d", n)
	}
}

func TestQueryCacheCapLimitEvictsExpiredBeforeDropping(t *testing.T) {
	// 设置 maxEntries=2，k1 已过期，写 k3 时应能驱逐 k1 并成功
	qc := &QueryCache{
		entries:    make(map[string]*queryCacheEntry),
		ttl:        time.Hour,
		maxEntries: 2,
		stopCh:     make(chan struct{}),
	}
	defer qc.Close()

	qc.SetWithTTL("k1", "expired", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	qc.Set("k2", 2)
	// 此时 k1 过期，k2 占1位；写 k3 应驱逐 k1 后成功
	qc.Set("k3", 3)

	if _, ok := qc.Get("k3"); !ok {
		t.Fatal("k3 should be stored after evicting expired k1")
	}
}

// ---- 覆写已存在 key ----

func TestQueryCacheSetOverwritesExistingKey(t *testing.T) {
	qc := NewQueryCache(5 * time.Second)
	defer qc.Close()

	qc.Set("ow", "first")
	qc.Set("ow", "second")
	v, ok := qc.Get("ow")
	if !ok || v.(string) != "second" {
		t.Fatalf("overwrite: want (second, true), got (%v, %v)", v, ok)
	}
}
