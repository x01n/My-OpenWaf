package ratelimit

import "sync"

// DynamicRateLimiter wraps a mutable backend so Redis/local implementations can
// be swapped at runtime without rebuilding the engine.
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

func (d *DynamicRateLimiter) Close() {
	d.Swap(nil)
}
