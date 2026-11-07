package ratelimit

import "sync"

// DynamicRateLimiter 包装一个可变后端，使 Redis 与本地实现能在运行时互换，
// 无需重建引擎。
type DynamicRateLimiter struct {
	mu      sync.RWMutex
	backend RateLimiterBackend
}

func NewDynamicRateLimiter(backend RateLimiterBackend) *DynamicRateLimiter {
	return &DynamicRateLimiter{backend: backend}
}

func (d *DynamicRateLimiter) current() RateLimiterBackend {
	d.mu.RLock()
	backend := d.backend
	d.mu.RUnlock()
	return backend
}

func (d *DynamicRateLimiter) Swap(backend RateLimiterBackend) {
	d.mu.Lock()
	old := d.backend
	d.backend = backend
	d.mu.Unlock()

	if old != nil && old != backend {
		old.Close()
	}
}

func (d *DynamicRateLimiter) Enabled() bool {
	backend := d.current()
	return backend != nil && backend.Enabled()
}

func (d *DynamicRateLimiter) Reconfigure(windowSec, maxReqs int, enabled bool) {
	backend := d.current()
	if backend != nil {
		backend.Reconfigure(windowSec, maxReqs, enabled)
	}
}

func (d *DynamicRateLimiter) Allow(key string) bool {
	backend := d.current()
	if backend == nil {
		return true
	}
	return backend.Allow(key)
}

func (d *DynamicRateLimiter) Increment(key string) int64 {
	backend := d.current()
	if backend == nil {
		return 0
	}
	return backend.Increment(key)
}

func (d *DynamicRateLimiter) IsOverLimit(key string) bool {
	backend := d.current()
	if backend == nil {
		return false
	}
	return backend.IsOverLimit(key)
}

/**
 * AllowWithQuota 把站点级配额透传给当前后端。
 *
 * 后端未实现 SiteQuotaLimiter（例如测试替身）时回退到 Allow，即沿用后端的
 * 全局配额——与「站点未覆盖」的语义一致，不会因为缺少可选能力而放行全部请求。
 *
 * @param key       计数键。
 * @param windowSec 窗口长度（秒）。
 * @param maxReqs   窗口内允许的请求数。
 * @return 未超限返回 true。
 */
func (d *DynamicRateLimiter) AllowWithQuota(key string, windowSec, maxReqs int) bool {
	backend := d.current()
	if backend == nil {
		return true
	}
	if q, ok := backend.(SiteQuotaLimiter); ok {
		return q.AllowWithQuota(key, windowSec, maxReqs)
	}
	return backend.Allow(key)
}

func (d *DynamicRateLimiter) Close() {
	d.Swap(nil)
}
