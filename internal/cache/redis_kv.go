package cache

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const redisPrefix = "openwaf:"

const incrFixedWindowScript = `
local value = redis.call("INCR", KEYS[1])
if value == 1 then
	redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return value
`

// RedisKV is a distributed key-value cache backed by Redis.
// Used for cross-node shared state: API response caching, rate limit metadata,
// IP ban synchronization, etc.
//
// This is intentionally separate from the snapshot Layer — snapshots are
// process-local objects that should never be serialized to Redis.
type RedisKV struct {
	mu     sync.RWMutex
	client *goredis.Client
	health atomic.Bool
}

// NewRedisKV creates a Redis KV cache. The wrapper stays usable even when the
// underlying client is nil so runtime hot reload can attach Redis later.
func NewRedisKV(client *goredis.Client) *RedisKV {
	r := &RedisKV{client: client}
	r.health.Store(client != nil)
	return r
}

func (r *RedisKV) clientValue() *goredis.Client {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()
	return client
}

func (r *RedisKV) SetClient(client *goredis.Client) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.client = client
	r.health.Store(client != nil)
	r.mu.Unlock()
}

// AvailableContext reports whether Redis is configured, healthy, and the caller context is active.
func (r *RedisKV) AvailableContext(ctx context.Context) bool {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return false
		}
	}
	return r.Available()
}

func (r *RedisKV) Available() bool {
	return r != nil && r.clientValue() != nil && r.health.Load()
}

// noteCommandResult updates health only when client is still the active client.
// redis.Nil is a successful Redis response (a cache miss), not a dependency
// failure, and therefore restores health just like any other successful command.
func (r *RedisKV) noteCommandResult(client *goredis.Client, err error) {
	if r == nil || client == nil {
		return
	}
	r.mu.RLock()
	if r.client == client {
		if err == nil || errors.Is(err, goredis.Nil) {
			r.health.Store(true)
		} else {
			r.health.Store(false)
		}
	}
	r.mu.RUnlock()
}

// Set stores a byte value with TTL.
func (r *RedisKV) Set(key string, value []byte, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return r.SetContext(ctx, key, value, ttl)
}

// SetContext stores a byte value with TTL using the caller's context.
func (r *RedisKV) SetContext(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	client := r.clientValue()
	if client == nil {
		return errors.New("redis kv unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err := client.Set(ctx, redisPrefix+key, value, ttl).Err()
	r.noteCommandResult(client, err)
	return err
}

// Get retrieves a byte value. Returns nil, false on miss.
func (r *RedisKV) Get(key string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return r.GetContext(ctx, key)
}

// GetContext retrieves a byte value using the caller's context. It returns nil, false on miss.
func (r *RedisKV) GetContext(ctx context.Context, key string) ([]byte, bool) {
	client := r.clientValue()
	if client == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	val, err := client.Get(ctx, redisPrefix+key).Bytes()
	r.noteCommandResult(client, err)
	if err != nil {
		return nil, false
	}
	return val, true
}

// Delete removes a key.
func (r *RedisKV) Delete(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r.DeleteContext(ctx, key)
}

// DeleteContext removes a key using the caller's context.
func (r *RedisKV) DeleteContext(ctx context.Context, key string) {
	client := r.clientValue()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	r.noteCommandResult(client, client.Del(ctx, redisPrefix+key).Err())
}

// SetJSON marshals v to JSON and stores it with TTL.
func (r *RedisKV) SetJSON(key string, v any, ttl time.Duration) error {
	if r == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return r.Set(key, data, ttl)
}

// GetJSON retrieves and unmarshals a JSON value.
func (r *RedisKV) GetJSON(key string, dest any) bool {
	data, ok := r.Get(key)
	if !ok {
		return false
	}
	return json.Unmarshal(data, dest) == nil
}

// Incr atomically increments a counter and returns the new value.
func (r *RedisKV) Incr(key string, ttl time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return r.IncrContext(ctx, key, ttl)
}

// IncrContext atomically increments a fixed-window counter.
// The first increment sets the TTL; subsequent increments leave the original
// window unchanged.
func (r *RedisKV) IncrContext(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	client := r.clientValue()
	if client == nil {
		return 0, errors.New("redis kv unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	value, err := client.Eval(ctx, incrFixedWindowScript, []string{redisPrefix + key}, ttl.Milliseconds()).Int64()
	r.noteCommandResult(client, err)
	if err != nil {
		return 0, err
	}
	return value, nil
}

// Exists checks if a key exists.
func (r *RedisKV) Exists(key string) bool {
	client := r.clientValue()
	if client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n, err := client.Exists(ctx, redisPrefix+key).Result()
	r.noteCommandResult(client, err)
	return err == nil && n > 0
}

// drainHashPairScript 原子地读取计数 hash 与元数据 hash 的全部字段并删除两者，
// 保证同一批聚合数据只被回写一次：任何后续命中都会写入被清空后的新 hash，
// 不会与已被取走的这批重复。KEYS[1]=计数 hash，KEYS[2]=元数据 hash。
const drainHashPairScript = `
local cnt = redis.call('HGETALL', KEYS[1])
local meta = redis.call('HGETALL', KEYS[2])
redis.call('DEL', KEYS[1], KEYS[2])
return {cnt, meta}
`

// HAggregateFlush 在单次 pipeline 往返内把一批资源命中送入 Redis：对计数 hash
// 的每个字段执行 HINCRBY（跨节点累加、不丢失），对元数据 hash 的对应字段执行
// HSET（最新命中覆盖旧元数据）。两个 hash 均刷新 TTL 防止节点全部下线后残留。
//
// counts 与 metas 以相同的资源唯一键为字段名。client 为 nil 时静默返回。
func (r *RedisKV) HAggregateFlush(cntKey, metaKey string, counts map[string]int64, metas map[string][]byte, ttl time.Duration) error {
	client := r.clientValue()
	if client == nil || len(counts) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fullCnt := redisPrefix + cntKey
	fullMeta := redisPrefix + metaKey
	pipe := client.Pipeline()
	for field, n := range counts {
		pipe.HIncrBy(ctx, fullCnt, field, n)
	}
	for field, val := range metas {
		pipe.HSet(ctx, fullMeta, field, val)
	}
	pipe.Expire(ctx, fullCnt, ttl)
	pipe.Expire(ctx, fullMeta, ttl)
	_, err := pipe.Exec(ctx)
	r.noteCommandResult(client, err)
	return err
}

// DrainAggregated 原子取出并清空计数/元数据两个 hash，返回 field->累计次数 与
// field->元数据字节。调用方须先持有 sink 分布式锁，确保集群内同一时刻只有一个
// 节点执行回写，避免重复 Upsert。client 为 nil 时返回空结果。
func (r *RedisKV) DrainAggregated(cntKey, metaKey string) (map[string]int64, map[string][]byte, error) {
	client := r.clientValue()
	if client == nil {
		return nil, nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res, err := client.Eval(ctx, drainHashPairScript, []string{redisPrefix + cntKey, redisPrefix + metaKey}).Result()
	r.noteCommandResult(client, err)
	if err != nil {
		return nil, nil, err
	}
	outer, ok := res.([]interface{})
	if !ok || len(outer) != 2 {
		return nil, nil, nil
	}
	counts := parseHashInt64(outer[0])
	metas := parseHashBytes(outer[1])
	return counts, metas, nil
}

// parseHashInt64 把 Lua 返回的扁平 HGETALL 数组（field,value,field,value,...）
// 解析为 field->int64。非法数值字段被跳过。
func parseHashInt64(v interface{}) map[string]int64 {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make(map[string]int64, len(arr)/2)
	for i := 0; i+1 < len(arr); i += 2 {
		field, ok := arr[i].(string)
		if !ok {
			continue
		}
		valStr, ok := arr[i+1].(string)
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(valStr, 10, 64)
		if err != nil {
			continue
		}
		out[field] = n
	}
	return out
}

// parseHashBytes 把 Lua 返回的扁平 HGETALL 数组解析为 field->[]byte。
func parseHashBytes(v interface{}) map[string][]byte {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(arr)/2)
	for i := 0; i+1 < len(arr); i += 2 {
		field, ok := arr[i].(string)
		if !ok {
			continue
		}
		valStr, ok := arr[i+1].(string)
		if !ok {
			continue
		}
		out[field] = []byte(valStr)
	}
	return out
}

// AcquireLock 尝试获取一个带 TTL 的分布式锁（SET key token NX PX ttl）。
// 成功返回 true。用于选出唯一的 sink 节点。client 为 nil 时返回 false。
func (r *RedisKV) AcquireLock(key, token string, ttl time.Duration) bool {
	client := r.clientValue()
	if client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ok, err := client.SetNX(ctx, redisPrefix+key, token, ttl).Result()
	r.noteCommandResult(client, err)
	return err == nil && ok
}

// releaseLockScript 仅在锁仍归本 token 所有时删除，避免误删他人续得的锁。
const releaseLockScript = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`

// ReleaseLock 释放由 token 持有的分布式锁。持有权不匹配时不做任何操作。
func (r *RedisKV) ReleaseLock(key, token string) {
	client := r.clientValue()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r.noteCommandResult(client, client.Eval(ctx, releaseLockScript, []string{redisPrefix + key}, token).Err())
}
