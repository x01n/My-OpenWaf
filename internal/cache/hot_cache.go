package cache

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// HotCache provides a Redis-backed read-through cache for hot data (frequently
// accessed queries) and large result sets. When Redis is unavailable, all calls
// are no-ops and return miss — callers fall back to the database transparently.
//
// Key design principles:
//   - All keys are prefixed with "openwaf:hot:" to avoid collision with other Redis usage.
//   - TTLs are short (seconds to minutes) — the cache is meant to absorb bursts, not replace the DB.
//   - Writes invalidate the relevant cache key so stale data is never served after mutation.
//   - Thread-safe: backed by Redis atomic operations.
type HotCache struct {
	mu     sync.RWMutex
	redis  *goredis.Client
	log    *slog.Logger
	prefix string
}

const hotCachePrefix = "openwaf:hot:"

// NewHotCache creates a Redis-backed hot data cache. Returns a no-op instance if redis is nil.
func NewHotCache(redis *goredis.Client, log *slog.Logger) *HotCache {
	return &HotCache{
		redis:  redis,
		log:    log,
		prefix: hotCachePrefix,
	}
}

func (h *HotCache) redisClient() *goredis.Client {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	client := h.redis
	h.mu.RUnlock()
	return client
}

func (h *HotCache) SetRedis(redis *goredis.Client) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.redis = redis
	h.mu.Unlock()
}

// Get retrieves a cached JSON value. Returns false on miss or when Redis is unavailable.
func (h *HotCache) Get(key string, dest any) bool {
	client := h.redisClient()
	if client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	data, err := client.Get(ctx, h.prefix+key).Bytes()
	if err != nil {
		return false
	}
	if err := json.Unmarshal(data, dest); err != nil {
		h.log.Warn("hot cache unmarshal failed", slog.String("key", key), slog.Any("err", err))
		return false
	}
	return true
}

// Set stores a value as JSON with the given TTL.
func (h *HotCache) Set(key string, value any, ttl time.Duration) {
	client := h.redisClient()
	if client == nil {
		return
	}
	data, err := json.Marshal(value)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Set(ctx, h.prefix+key, data, ttl).Err(); err != nil {
		h.log.Warn("hot cache set failed", slog.String("key", key), slog.Any("err", err))
	}
}

// SetBytes stores raw bytes with the given TTL (for pre-serialized data).
func (h *HotCache) SetBytes(key string, data []byte, ttl time.Duration) {
	client := h.redisClient()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client.Set(ctx, h.prefix+key, data, ttl)
}

// GetBytes retrieves raw bytes. Returns nil on miss.
func (h *HotCache) GetBytes(key string) []byte {
	client := h.redisClient()
	if client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, err := client.Get(ctx, h.prefix+key).Bytes()
	if err != nil {
		return nil
	}
	return data
}

// Invalidate removes a specific cache key.
func (h *HotCache) Invalidate(key string) {
	client := h.redisClient()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client.Del(ctx, h.prefix+key)
}

// InvalidatePattern removes all keys matching the glob pattern.
// Use with caution — SCAN-based deletion can be expensive on large keyspaces.
func (h *HotCache) InvalidatePattern(pattern string) {
	client := h.redisClient()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var cursor uint64
	for {
		keys, next, err := client.Scan(ctx, cursor, h.prefix+pattern, 200).Result()
		if err != nil {
			break
		}
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
}

// Available returns true if Redis is connected.
func (h *HotCache) Available() bool {
	return h.redisClient() != nil
}

// GetOrLoad implements the read-through pattern: try cache first, on miss call loader,
// cache the result, and return it. If loader returns an error, the cache is not populated.
func (h *HotCache) GetOrLoad(key string, dest any, ttl time.Duration, loader func() (any, error)) error {
	if h.Get(key, dest) {
		return nil
	}
	result, err := loader()
	if err != nil {
		return err
	}
	// Populate dest from result.
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, dest); err != nil {
		return err
	}
	h.Set(key, result, ttl)
	return nil
}

// ListCache stores paginated list results in Redis with short TTL.
// Suitable for large query results like security events and access logs.
type ListCacheEntry struct {
	Items json.RawMessage `json:"items"`
	Total int64           `json:"total"`
}

// GetListRaw retrieves a cached list result as raw bytes + total count.
// This method satisfies the repository.HotCacheBackend interface without cross-package types.
func (h *HotCache) GetListRaw(key string) (items []byte, total int64, ok bool) {
	if !h.Available() {
		return nil, 0, false
	}
	var entry ListCacheEntry
	if h.Get(key, &entry) {
		return entry.Items, entry.Total, true
	}
	return nil, 0, false
}

// GetList retrieves a cached list result.
func (h *HotCache) GetList(key string) (*ListCacheEntry, bool) {
	if !h.Available() {
		return nil, false
	}
	var entry ListCacheEntry
	if h.Get(key, &entry) {
		return &entry, true
	}
	return nil, false
}

// SetList stores a list result with TTL.
func (h *HotCache) SetList(key string, items any, total int64, ttl time.Duration) {
	if !h.Available() {
		return
	}
	data, err := json.Marshal(items)
	if err != nil {
		return
	}
	entry := ListCacheEntry{Items: data, Total: total}
	h.Set(key, entry, ttl)
}
