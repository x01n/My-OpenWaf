package cache

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	rueidis "github.com/redis/rueidis"
	"golang.org/x/sync/singleflight"
)

type HotCache struct {
	mu     sync.RWMutex
	redis  rueidis.Client
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

// NewHotCache 创建 Redis 支撑的热数据缓存；redis 为 nil 时返回空操作实例。
func NewHotCache(redis rueidis.Client, log *slog.Logger) *HotCache {
	if log == nil {
		log = slog.Default()
	}
	return &HotCache{
		redis:  redis,
		log:    log,
		prefix: hotCachePrefix,
	}
}

func (h *HotCache) redisClient() rueidis.Client {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	client := h.redis
	h.mu.RUnlock()
	return client
}

func (h *HotCache) SetRedis(redis rueidis.Client) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.redis = redis
	h.unavailableUntil.Store(0)
	h.errLogging.Store(false)
	h.mu.Unlock()
}

// Get 取出缓存的 JSON 值；未命中或 Redis 不可用时返回 false。
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

	data, err := client.Do(ctx, client.B().Get().Key(h.prefix+key).Build()).AsBytes()
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
 * rueidis.Nil 是正常的未命中；其余（拨号失败、超时、连接池耗尽等）属于依赖故障，
 * 计入 errs 并打印一次告警，避免故障期间每个请求都刷日志。
 *
 * @param client 发起命令时使用的 Redis 客户端。
 * @param key 缓存键（仅用于日志，不含敏感内容）。
 * @param err client.Get 返回的错误。
 */
func (h *HotCache) recordReadErr(client rueidis.Client, key string, err error) {
	if h == nil || client == nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.redis != client {
		return
	}
	if errors.Is(err, rueidis.Nil) {
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
func (h *HotCache) noteHealthy(client rueidis.Client) bool {
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

// Set 按给定 TTL 以 JSON 形式写入一个值。
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
	if err := client.Do(ctx, client.B().Set().Key(h.prefix+key).Value(string(data)).Px(ttl).Build()).Error(); err != nil {
		h.recordReadErr(client, key, err)
		return
	}
	h.noteHealthy(client)
}

// SetBytes 按给定 TTL 写入原始字节（用于已预先序列化的数据）。
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
	if err := client.Do(ctx, client.B().Set().Key(h.prefix+key).Value(string(data)).Px(ttl).Build()).Error(); err != nil {
		h.recordReadErr(client, key, err)
		return
	}
	h.noteHealthy(client)
}

// GetBytes 取出原始字节；未命中返回 nil。
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
	data, err := client.Do(ctx, client.B().Get().Key(h.prefix+key).Build()).AsBytes()
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

// Invalidate 删除指定缓存键。
func (h *HotCache) Invalidate(key string) {
	client := h.redisClient()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client.Do(ctx, client.B().Del().Key(h.prefix+key).Build())
}

/**
 * InvalidatePattern 删除所有匹配 glob 模式的键。
 *
 * 慎用：在大 keyspace 上基于 SCAN 的删除开销很高。
 */
func (h *HotCache) InvalidatePattern(pattern string) {
	client := h.redisClient()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var cursor uint64
	for {
		entry, err := client.Do(ctx, client.B().Scan().Cursor(cursor).Match(h.prefix+pattern).Count(200).Build()).AsScanEntry()
		if err != nil {
			break
		}
		if len(entry.Elements) > 0 {
			client.Do(ctx, client.B().Del().Key(entry.Elements...).Build())
		}
		cursor = entry.Cursor
		if cursor == 0 {
			break
		}
	}
}

// Available 报告 Redis 当前是否可用。
func (h *HotCache) Available() bool {
	if h.redisClient() == nil {
		return false
	}
	until := h.unavailableUntil.Load()
	return until == 0 || time.Now().UnixNano() >= until
}

/**
 * GetOrLoad 实现读穿（read-through）模式：先查缓存，未命中则调用 loader，
 * 把结果写入缓存后返回；loader 返回错误时不写缓存。
 *
 * 并发同 key 的回源加载通过 singleflight 合并，避免缓存击穿：只有一个 goroutine
 * 真正执行 loader，其余共享其结果，再各自 json 反序列化到自己的 dest。
 */
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

/**
 * ListCacheEntry 是写入 Redis 的分页列表结果，使用短 TTL。
 *
 * 适合安全事件、访问日志这类大结果集。
 */
type ListCacheEntry struct {
	Items json.RawMessage `json:"items"`
	Total int64           `json:"total"`
}

/**
 * GetListRaw 以原始字节 + 总数取出缓存的列表结果。
 *
 * 该方法满足 repository.HotCacheBackend 接口，且不引入跨包类型。
 */
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

// GetList 取出缓存的列表结果。
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

// SetList 按 TTL 写入一个列表结果。
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
