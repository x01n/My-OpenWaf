package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// RedisRateLimiter implements sliding-window rate limiting backed by Redis.
// Suitable for distributed deployments where multiple WAF nodes share state.
type RedisRateLimiter struct {
	client   *goredis.Client
	prefix   string
	configMu sync.RWMutex
	windowS  int64
	maxReqs  int64
	enabled  atomic.Bool
}

// NewRedisRateLimiter creates a Redis-backed rate limiter.
// Returns nil if client is nil (falls back to local limiter).
func NewRedisRateLimiter(client *goredis.Client, prefix string, windowSec, maxReqs int, enabled bool) *RedisRateLimiter {
	if client == nil {
		return nil
	}
	if windowSec <= 0 || maxReqs <= 0 {
		enabled = false
	}
	rl := &RedisRateLimiter{
		client:  client,
		prefix:  prefix,
		windowS: int64(windowSec),
		maxReqs: int64(maxReqs),
	}
	rl.enabled.Store(enabled)
	return rl
}

func (rl *RedisRateLimiter) Enabled() bool {
	if rl == nil {
		return false
	}
	rl.configMu.RLock()
	enabled := rl.enabled.Load()
	rl.configMu.RUnlock()
	return enabled
}

// SetEnabled cannot re-enable an invalid window/quota pair.
func (rl *RedisRateLimiter) SetEnabled(v bool) {
	if rl == nil {
		return
	}
	rl.configMu.Lock()
	defer rl.configMu.Unlock()
	if v && (rl.windowS <= 0 || rl.maxReqs <= 0) {
		v = false
	}
	rl.enabled.Store(v)
}

// Reconfigure updates window and max parameters.
func (rl *RedisRateLimiter) Reconfigure(windowSec, maxReqs int, enabled bool) {
	if rl == nil {
		return
	}
	rl.configMu.Lock()
	defer rl.configMu.Unlock()
	if windowSec <= 0 || maxReqs <= 0 {
		enabled = false
	}
	rl.windowS = int64(windowSec)
	rl.maxReqs = int64(maxReqs)
	rl.enabled.Store(enabled)
}

// Allow checks and increments the counter using a Redis Lua script for atomicity.
// Uses sliding window with sorted sets.
var slidingWindowScript = goredis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])

local min_ts = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', min_ts)
local count = redis.call('ZCARD', key)
if count < limit then
    redis.call('ZADD', key, now, now .. ':' .. math.random(1, 1000000))
    redis.call('EXPIRE', key, window + 1)
    return 1
end
return 0
`)

var incrementWindowScript = goredis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local min_ts = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', min_ts)
redis.call('ZADD', key, now, now .. ':' .. math.random(1, 1000000))
redis.call('EXPIRE', key, window + 1)
return redis.call('ZCARD', key)
`)

var countWindowScript = goredis.NewScript(`
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local min_ts = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', min_ts)
redis.call('EXPIRE', key, window + 1)
return redis.call('ZCARD', key)
`)

// Allow returns true if the request should proceed (under limit).
func (rl *RedisRateLimiter) Allow(key string) bool {
	if rl == nil {
		return true
	}
	rl.configMu.RLock()
	enabled := rl.enabled.Load()
	windowS := rl.windowS
	maxReqs := rl.maxReqs
	rl.configMu.RUnlock()
	if !enabled || windowS <= 0 || maxReqs <= 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	redisKey := rl.prefix + ":rl:" + key
	now := time.Now().UnixMilli()
	windowMs := windowS * 1000

	result, err := slidingWindowScript.Run(ctx, rl.client, []string{redisKey}, now, windowMs, maxReqs).Int()
	if err != nil {
		return true
	}
	return result == 1
}

// Increment adds one event to the current sliding window and returns the count.
func (rl *RedisRateLimiter) Increment(key string) int64 {
	if rl == nil {
		return 0
	}
	rl.configMu.RLock()
	enabled := rl.enabled.Load()
	windowS := rl.windowS
	rl.configMu.RUnlock()
	if !enabled || windowS <= 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	redisKey := rl.prefix + ":rl:" + key
	now := time.Now().UnixMilli()
	windowMs := windowS * 1000

	result, err := incrementWindowScript.Run(ctx, rl.client, []string{redisKey}, now, windowMs).Int64()
	if err != nil {
		return 0
	}
	return result
}

// IsOverLimit checks the current sliding window without incrementing it.
func (rl *RedisRateLimiter) IsOverLimit(key string) bool {
	if rl == nil {
		return false
	}
	rl.configMu.RLock()
	enabled := rl.enabled.Load()
	windowS := rl.windowS
	maxReqs := rl.maxReqs
	rl.configMu.RUnlock()
	if !enabled || windowS <= 0 || maxReqs <= 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	redisKey := rl.prefix + ":rl:" + key
	now := time.Now().UnixMilli()
	windowMs := windowS * 1000

	count, err := countWindowScript.Run(ctx, rl.client, []string{redisKey}, now, windowMs).Int64()
	if err != nil {
		return false
	}
	return count > maxReqs
}

// Close is a no-op for the Redis limiter (connection managed externally).
func (rl *RedisRateLimiter) Close() {}
