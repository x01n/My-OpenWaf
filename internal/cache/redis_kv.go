package cache

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	rueidis "github.com/redis/rueidis"
)

const (
	redisPrefix           = "openwaf:"
	redisKVFailureBackoff = 5 * time.Second
)

const incrFixedWindowScript = `
local value = redis.call("INCR", KEYS[1])
if value == 1 then
	redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return value
`

type RedisKV struct {
	mu               sync.RWMutex
	client           rueidis.Client
	health           atomic.Bool
	unavailableUntil atomic.Int64
}

func NewRedisKV(client rueidis.Client) *RedisKV {
	r := &RedisKV{client: client}
	r.health.Store(client != nil)
	return r
}

func (r *RedisKV) clientValue() rueidis.Client {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	client := r.client
	r.mu.RUnlock()
	return client
}

func (r *RedisKV) SetClient(client rueidis.Client) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.client = client
	r.health.Store(client != nil)
	r.unavailableUntil.Store(0)
	r.mu.Unlock()
}

func (r *RedisKV) AvailableContext(ctx context.Context) bool {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return false
		}
	}
	return r.Available()
}

func (r *RedisKV) Available() bool {
	if r == nil || r.clientValue() == nil {
		return false
	}
	if r.health.Load() {
		return true
	}
	until := r.unavailableUntil.Load()
	return until > 0 && time.Now().UnixNano() >= until
}

func (r *RedisKV) noteCommandResult(client rueidis.Client, err error) {
	if r == nil || client == nil {
		return
	}
	r.mu.RLock()
	if r.client == client {
		if err == nil || errors.Is(err, rueidis.Nil) {
			r.health.Store(true)
			r.unavailableUntil.Store(0)
		} else {
			r.health.Store(false)
			r.unavailableUntil.Store(time.Now().Add(redisKVFailureBackoff).UnixNano())
		}
	}
	r.mu.RUnlock()
}

// Set 按 TTL 写入一个字节值。
func (r *RedisKV) Set(key string, value []byte, ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return r.SetContext(ctx, key, value, ttl)
}

// SetContext 使用调用方的 context，按 TTL 写入一个字节值。
func (r *RedisKV) SetContext(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	client := r.clientValue()
	if client == nil {
		return errors.New("redis kv unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err := client.Do(ctx, client.B().Set().Key(redisPrefix+key).Value(rueidis.BinaryString(value)).Px(ttl).Build()).Error()
	r.noteCommandResult(client, err)
	return err
}

// Get 取出一个字节值；未命中返回 nil, false。
func (r *RedisKV) Get(key string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return r.GetContext(ctx, key)
}

// GetContext 使用调用方的 context 取出字节值；未命中返回 nil, false。
func (r *RedisKV) GetContext(ctx context.Context, key string) ([]byte, bool) {
	client := r.clientValue()
	if client == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	val, err := client.Do(ctx, client.B().Get().Key(redisPrefix+key).Build()).AsBytes()
	r.noteCommandResult(client, err)
	if err != nil {
		return nil, false
	}
	return val, true
}

// Delete 删除一个 key。
func (r *RedisKV) Delete(key string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r.DeleteContext(ctx, key)
}

// DeleteContext 使用调用方的 context 删除一个 key。
func (r *RedisKV) DeleteContext(ctx context.Context, key string) {
	client := r.clientValue()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	r.noteCommandResult(client, client.Do(ctx, client.B().Del().Key(redisPrefix+key).Build()).Error())
}

// SetJSON 把 v 序列化为 JSON 并按 TTL 写入。
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

// GetJSON 取出 JSON 值并反序列化。
func (r *RedisKV) GetJSON(key string, dest any) bool {
	data, ok := r.Get(key)
	if !ok {
		return false
	}
	return json.Unmarshal(data, dest) == nil
}

// Incr 原子递增计数器并返回新值。
func (r *RedisKV) Incr(key string, ttl time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return r.IncrContext(ctx, key, ttl)
}

var incrFixedWindowLua = rueidis.NewLuaScript(incrFixedWindowScript)

func (r *RedisKV) IncrContext(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	client := r.clientValue()
	if client == nil {
		return 0, errors.New("redis kv unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	resp := incrFixedWindowLua.Exec(ctx, client, []string{redisPrefix + key}, []string{strconv.FormatInt(ttl.Milliseconds(), 10)})
	value, err := resp.AsInt64()
	r.noteCommandResult(client, err)
	if err != nil {
		return 0, err
	}
	return value, nil
}

// Exists 判断某个 key 是否存在。
func (r *RedisKV) Exists(key string) bool {
	client := r.clientValue()
	if client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n, err := client.Do(ctx, client.B().Exists().Key(redisPrefix+key).Build()).AsInt64()
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
	b := client.B()
	cmds := make([]rueidis.Completed, 0, len(counts)+len(metas)+2)
	for field, n := range counts {
		cmds = append(cmds, b.Hincrby().Key(fullCnt).Field(field).Increment(n).Build())
	}
	for field, val := range metas {
		cmds = append(cmds, b.Hset().Key(fullMeta).FieldValue().FieldValue(field, rueidis.BinaryString(val)).Build())
	}
	cmds = append(cmds,
		b.Expire().Key(fullCnt).Seconds(int64(ttl/time.Second)).Build(),
		b.Expire().Key(fullMeta).Seconds(int64(ttl/time.Second)).Build(),
	)
	resps := client.DoMulti(ctx, cmds...)
	var err error
	for _, resp := range resps {
		if e := resp.Error(); e != nil {
			err = e
			break
		}
	}
	r.noteCommandResult(client, err)
	return err
}

var drainHashPairLua = rueidis.NewLuaScript(drainHashPairScript)

func (r *RedisKV) DrainAggregated(cntKey, metaKey string) (map[string]int64, map[string][]byte, error) {
	client := r.clientValue()
	if client == nil {
		return nil, nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp := drainHashPairLua.Exec(ctx, client, []string{redisPrefix + cntKey, redisPrefix + metaKey}, nil)
	err := resp.Error()
	r.noteCommandResult(client, err)
	if err != nil {
		return nil, nil, err
	}
	arr, err := resp.ToArray()
	if err != nil || len(arr) != 2 {
		return nil, nil, nil
	}
	counts := flatHashToInt64(arr[0])
	metas := flatHashToBytes(arr[1])
	return counts, metas, nil
}

func flatHashToInt64(m rueidis.RedisMessage) map[string]int64 {
	pairs, err := m.AsStrSlice()
	if err != nil || len(pairs) == 0 {
		return nil
	}
	out := make(map[string]int64, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		n, err := strconv.ParseInt(pairs[i+1], 10, 64)
		if err != nil {
			continue
		}
		out[pairs[i]] = n
	}
	return out
}

func flatHashToBytes(m rueidis.RedisMessage) map[string][]byte {
	pairs, err := m.AsStrSlice()
	if err != nil || len(pairs) == 0 {
		return nil
	}
	out := make(map[string][]byte, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out[pairs[i]] = []byte(pairs[i+1])
	}
	return out
}

// parseHashInt64 保留旧名与行为（兼容既有测试引用）；新实现走 flatHashToInt64。
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
	resp := client.Do(ctx, client.B().Set().Key(redisPrefix+key).Value(token).Nx().Px(ttl).Build())
	err := resp.Error()
	if rueidis.IsRedisNil(err) {
		err = nil
	}
	r.noteCommandResult(client, err)
	return err == nil
}

const releaseLockScript = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`

var releaseLockLua = rueidis.NewLuaScript(releaseLockScript)

func (r *RedisKV) ReleaseLock(key, token string) {
	client := r.clientValue()
	if client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp := releaseLockLua.Exec(ctx, client, []string{redisPrefix + key}, []string{token})
	r.noteCommandResult(client, resp.Error())
}
