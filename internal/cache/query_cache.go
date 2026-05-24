package cache

import (
	"sync"
	"time"
)

// QueryCache is a simple in-memory TTL cache for expensive DB query results
// (e.g., COUNT queries on large tables). It uses a sync.Map for concurrent
// access and a periodic cleanup goroutine.
type QueryCache struct {
	mu      sync.RWMutex
	entries map[string]*queryCacheEntry
	ttl     time.Duration
	stopCh  chan struct{}
}

type queryCacheEntry struct {
	value     any
	expiresAt time.Time
}

// NewQueryCache creates a query cache with the given default TTL.
func NewQueryCache(ttl time.Duration) *QueryCache {
	qc := &QueryCache{
		entries: make(map[string]*queryCacheEntry),
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}
	go qc.cleanup()
	return qc
}

// Get retrieves a cached value. Returns nil, false on miss or expiry.
func (qc *QueryCache) Get(key string) (any, bool) {
	qc.mu.RLock()
	e, ok := qc.entries[key]
	qc.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.value, true
}

// Set stores a value with the default TTL.
func (qc *QueryCache) Set(key string, value any) {
	qc.mu.Lock()
	qc.entries[key] = &queryCacheEntry{
		value:     value,
		expiresAt: time.Now().Add(qc.ttl),
	}
	qc.mu.Unlock()
}

// SetWithTTL stores a value with a custom TTL.
func (qc *QueryCache) SetWithTTL(key string, value any, ttl time.Duration) {
	qc.mu.Lock()
	qc.entries[key] = &queryCacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
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
	ticker := time.NewTicker(30 * time.Second)
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
			qc.mu.Unlock()
		case <-qc.stopCh:
			return
		}
	}
}
