package cache

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
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

	// sf 合并同 key 的并发回源加载，防止缓存击穿。
	sf singleflight.Group
	// hits/misses 记录读取命中与未命中次数，供 /metrics 暴露命中率。
	hits   atomic.Int64
	misses atomic.Int64
	// errs 记录 Redis 侧故障次数（连接失败、超时等），与「键不存在」区分开。
	//
	// 若把两者都计入 misses，Redis 整体故障时命中率会显示为 0%，看起来像
	// 缓存未生效而非依赖不可用，排障方向会被引偏。
	errs atomic.Int64
	// errLogging 限制故障日志频率；unavailableUntil 在 Redis 故障后短暂熔断，
	// 避免每个接口请求都先等待 Redis 超时再回源数据库。
	errLogging       atomic.Bool
	unavailableUntil atomic.Int64
}

const (
	hotCachePrefix         = "openwaf:hot:"
	hotCacheFailureBackoff = 5 * time.Second
)

// NewHotCache creates a Redis-backed hot data cache. Returns a no-op instance if redis is nil.
func NewHotCache(redis *goredis.Client, log *slog.Logger) *HotCache {
	if log == nil {
		log = slog.Default()
	}
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
	h.unavailableUntil.Store(0)
	h.errLogging.Store(false)
	h.mu.Unlock()
}

// Get retrieves a cached JSON value. Returns false on miss or when Redis is unavailable.
func (h *HotCache) Get(key string, dest any) bool {
	if !h.Available() {
		return false
	}
	client := h.redisClient()
	if client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	data, err := client.Get(ctx, h.prefix+key).Bytes()
	if err != nil {
		h.recordReadErr(client, key, err)
		return false
	}
	if !h.noteHealthy(client) {
		return false
	}
	if err := json.Unmarshal(data, dest); err != nil {
		h.misses.Add(1)
		h.log.Warn("hot cache unmarshal failed", slog.String("key", key), slog.Any("err", err))
		return false
	}
	h.hits.Add(1)
	return true
}

/**
 * recordReadErr 区分「键不存在」与「Redis 故障」并分别计数。
 *
 * goredis.Nil 是正常的未命中；其余（拨号失败、超时、连接池耗尽等）属于依赖故障，
 * 计入 errs 并打印一次告警，避免故障期间每个请求都刷日志。
 *
 * @param client 发起命令时使用的 Redis 客户端。
 * @param key 缓存键（仅用于日志，不含敏感内容）。
 * @param err client.Get 返回的错误。
 */
func (h *HotCache) recordReadErr(client *goredis.Client, key string, err error) {
	if h == nil || client == nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.redis != client {
		return
	}
	if errors.Is(err, goredis.Nil) {
		h.misses.Add(1)
		return
	}
	h.errs.Add(1)
	h.unavailableUntil.Store(time.Now().Add(hotCacheFailureBackoff).UnixNano())
	if h.errLogging.CompareAndSwap(false, true) {
		h.log.Warn("hot cache redis unavailable, falling back to database",
			slog.String("key", key), slog.Any("err", err))
	}
}

// noteHealthy 仅接受当前客户端的成功结果，并复位故障状态。
func (h *HotCache) noteHealthy(client *goredis.Client) bool {
	if h == nil || client == nil {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.redis != client {
		return false
	}
	h.unavailableUntil.Store(0)
	if h.errLogging.Load() {
		h.errLogging.Store(false)
	}
	return true
}

// HitStats 返回累计的命中与未命中次数，供 /metrics 暴露命中率。
// nil 接收者返回 0，保证 Redis 不可用场景不 panic。
func (h *HotCache) HitStats() (hits, misses int64) {
	if h == nil {
		return 0, 0
	}
	return h.hits.Load(), h.misses.Load()
}

// ErrorCount 返回累计的 Redis 故障次数（不含「键不存在」）。
// 该值持续增长说明 Redis 不可用、请求正在穿透到数据库，而非缓存策略失效。
func (h *HotCache) ErrorCount() int64 {
	if h == nil {
		return 0
	}
	return h.errs.Load()
}

// Set stores a value as JSON with the given TTL.
func (h *HotCache) Set(key string, value any, ttl time.Duration) {
	if !h.Available() {
		return
	}
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
		h.recordReadErr(client, key, err)
		return
	}
	h.noteHealthy(client)
}

// SetBytes stores raw bytes with the given TTL (for pre-serialized data).
func (h *HotCache) SetBytes(key string, data []byte, ttl time.Duration) {
	if !h.Available() {
		return
	}
	client := h.redisClient()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Set(ctx, h.prefix+key, data, ttl).Err(); err != nil {
		h.recordReadErr(client, key, err)
		return
	}
	h.noteHealthy(client)
}

// GetBytes retrieves raw bytes. Returns nil on miss.
func (h *HotCache) GetBytes(key string) []byte {
	if !h.Available() {
		return nil
	}
	client := h.redisClient()
	if client == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, err := client.Get(ctx, h.prefix+key).Bytes()
	if err != nil {
		h.recordReadErr(client, key, err)
		return nil
	}
	if !h.noteHealthy(client) {
		return nil
	}
	h.hits.Add(1)
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
	if h.redisClient() == nil {
		return false
	}
	until := h.unavailableUntil.Load()
	return until == 0 || time.Now().UnixNano() >= until
}

// GetOrLoad implements the read-through pattern: try cache first, on miss call loader,
// cache the result, and return it. If loader returns an error, the cache is not populated.
//
// 并发同 key 的回源加载通过 singleflight 合并，避免缓存击穿：只有一个 goroutine
// 真正执行 loader，其余共享其结果，再各自 json 反序列化到自己的 dest。
func (h *HotCache) GetOrLoad(key string, dest any, ttl time.Duration, loader func() (any, error)) error {
	if h.Get(key, dest) {
		return nil
	}
	// singleflight 合并同 key 的并发 loader 调用，返回共享的原始 JSON 字节。
	raw, err, _ := h.sf.Do(key, func() (any, error) {
		// 双重检查：抢到执行权后再读一次缓存，可能已被先行者回填。
		var cached json.RawMessage
		if h.Get(key, &cached) {
			return []byte(cached), nil
		}
		result, err := loader()
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		h.SetBytes(key, data, ttl)
		return data, nil
	})
	if err != nil {
		return err
	}
	return json.Unmarshal(raw.([]byte), dest)
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
