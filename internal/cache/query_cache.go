package cache

import (
	"sync"
	"sync/atomic"
	"time"
)

// defaultQueryCacheMaxEntries 是 QueryCache 的默认容量上限。缓存 key 由查询
// 过滤条件（Host/Path/QueryString/TLS 指纹等用户可控字段）拼成，基数可被外部
// 请求放大；若不设上限，即便 5s TTL 也可能在清理窗口内堆积到 OOM。达到上限时
// 先清过期项，仍满则跳过写入（降级为直查 DB，不影响正确性）。
const defaultQueryCacheMaxEntries = 8192

// QueryCache is a simple in-memory TTL cache for expensive DB query results
// (e.g., COUNT queries on large tables). It uses a sync.Map for concurrent
// access and a periodic cleanup goroutine.
type QueryCache struct {
	mu         sync.RWMutex
	entries    map[string]*queryCacheEntry
	ttl        time.Duration
	maxEntries int
	stopCh     chan struct{}

	// hits/misses 记录读取命中与未命中次数，供 /metrics 暴露命中率。
	hits   atomic.Int64
	misses atomic.Int64
}

type queryCacheEntry struct {
	value     any
	expiresAt time.Time
}

// NewQueryCache creates a query cache with the given default TTL.
func NewQueryCache(ttl time.Duration) *QueryCache {
	qc := &QueryCache{
		entries:    make(map[string]*queryCacheEntry),
		ttl:        ttl,
		maxEntries: defaultQueryCacheMaxEntries,
		stopCh:     make(chan struct{}),
	}
	go qc.cleanup()
	return qc
}

// storeLocked 在持有写锁的前提下写入一条缓存，并强制容量上限。
// key 已存在时直接覆盖（不增加基数）；新增时若已达上限，先内联清理过期项，
// 仍满则跳过写入（降级直查 DB），避免无界增长导致 OOM。
func (qc *QueryCache) storeLocked(key string, e *queryCacheEntry) {
	if _, exists := qc.entries[key]; !exists && len(qc.entries) >= qc.maxEntries {
		now := time.Now()
		for k, ent := range qc.entries {
			if now.After(ent.expiresAt) {
				delete(qc.entries, k)
			}
		}
		if len(qc.entries) >= qc.maxEntries {
			return
		}
	}
	qc.entries[key] = e
}

// Get retrieves a cached value. Returns nil, false on miss or expiry.
func (qc *QueryCache) Get(key string) (any, bool) {
	qc.mu.RLock()
	e, ok := qc.entries[key]
	qc.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		qc.misses.Add(1)
		return nil, false
	}
	qc.hits.Add(1)
	return e.value, true
}

// HitStats 返回累计的命中与未命中次数，供 /metrics 暴露命中率。
// nil 接收者返回 0，保证空缓存场景不 panic。
func (qc *QueryCache) HitStats() (hits, misses int64) {
	if qc == nil {
		return 0, 0
	}
	return qc.hits.Load(), qc.misses.Load()
}

// Set stores a value with the default TTL.
func (qc *QueryCache) Set(key string, value any) {
	qc.mu.Lock()
	qc.storeLocked(key, &queryCacheEntry{
		value:     value,
		expiresAt: time.Now().Add(qc.ttl),
	})
	qc.mu.Unlock()
}

// SetWithTTL stores a value with a custom TTL.
func (qc *QueryCache) SetWithTTL(key string, value any, ttl time.Duration) {
	qc.mu.Lock()
	qc.storeLocked(key, &queryCacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	})
	qc.mu.Unlock()
}

// Invalidate removes a specific key.
func (qc *QueryCache) Invalidate(key string) {
	qc.mu.Lock()
	delete(qc.entries, key)
	qc.mu.Unlock()
}

// InvalidateAll clears the entire cache.
func (qc *QueryCache) InvalidateAll() {
	qc.mu.Lock()
	qc.entries = make(map[string]*queryCacheEntry)
	qc.mu.Unlock()
}

// Close stops the cleanup goroutine.
func (qc *QueryCache) Close() {
	close(qc.stopCh)
}

func (qc *QueryCache) cleanup() {
	// 清理间隔为 TTL 的 2 倍，确保过期项在 3×TTL 内被回收，同时避免高频扫描。
	ticker := time.NewTicker(qc.ttl * 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			qc.mu.Lock()
			for k, e := range qc.entries {
				if now.After(e.expiresAt) {
					delete(qc.entries, k)
				}
			}
			if len(qc.entries) == 0 {
				qc.entries = make(map[string]*queryCacheEntry)
			}
			qc.mu.Unlock()
		case <-qc.stopCh:
			return
		}
	}
}
