package cache

import (
	"context"
	"encoding/json"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const redisPrefix = "openwaf:"

// RedisKV is a distributed key-value cache backed by Redis.
// Used for cross-node shared state: API response caching, rate limit metadata,
// IP ban synchronization, etc.
//
// This is intentionally separate from the snapshot Layer — snapshots are
// process-local objects that should never be serialized to Redis.
type RedisKV struct {
	client *goredis.Client
}

// NewRedisKV creates a Redis KV cache. Returns nil if client is nil.
func NewRedisKV(client *goredis.Client) *RedisKV {
	if client == nil {
		return nil
	}
	return &RedisKV{client: client}
}

// Set stores a byte value with TTL.
func (r *RedisKV) Set(key string, value []byte, ttl time.Duration) error {
	if r == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return r.client.Set(ctx, redisPrefix+key, value, ttl).Err()
}

// Get retrieves a byte value. Returns nil, false on miss.
func (r *RedisKV) Get(key string) ([]byte, bool) {
	if r == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	val, err := r.client.Get(ctx, redisPrefix+key).Bytes()
	if err != nil {
		return nil, false
	}
	return val, true
}

// Delete removes a key.
func (r *RedisKV) Delete(key string) {
	if r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r.client.Del(ctx, redisPrefix+key)
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
	if r == nil {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pipe := r.client.Pipeline()
	incr := pipe.Incr(ctx, redisPrefix+key)
	pipe.Expire(ctx, redisPrefix+key, ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

// Exists checks if a key exists.
func (r *RedisKV) Exists(key string) bool {
	if r == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n, err := r.client.Exists(ctx, redisPrefix+key).Result()
	return err == nil && n > 0
}
