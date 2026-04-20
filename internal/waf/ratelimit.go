package waf

import (
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter implements fixed-window rate limiting keyed by (clientIP + host).
type RateLimiter struct {
	mu      sync.Mutex
	windows map[string]*window
	windowS int64
	maxReqs int64
	enabled atomic.Bool
	stopCh  chan struct{}
}

type window struct {
	count  atomic.Int64
	expiry int64 // unix seconds
}

func NewRateLimiter(windowSec, maxReqs int, enabled bool) *RateLimiter {
	rl := &RateLimiter{
		windows: make(map[string]*window),
		windowS: int64(windowSec),
		maxReqs: int64(maxReqs),
		stopCh:  make(chan struct{}),
	}
	rl.enabled.Store(enabled)
	go rl.cleaner()
	return rl
}

func (rl *RateLimiter) Enabled() bool { return rl.enabled.Load() }

func (rl *RateLimiter) SetEnabled(v bool) { rl.enabled.Store(v) }

func (rl *RateLimiter) Reconfigure(windowSec, maxReqs int, enabled bool) {
	rl.mu.Lock()
	rl.windowS = int64(windowSec)
	rl.maxReqs = int64(maxReqs)
	rl.mu.Unlock()
	rl.enabled.Store(enabled)
}

func (rl *RateLimiter) Allow(key string) bool {
	if !rl.enabled.Load() {
		return true
	}
	now := time.Now().Unix()
	rl.mu.Lock()
	w, ok := rl.windows[key]
	if !ok || w.expiry <= now {
		w = &window{expiry: now + rl.windowS}
		rl.windows[key] = w
	}
	rl.mu.Unlock()
	n := w.count.Add(1)
	return n <= rl.maxReqs
}

// Increment is used for error rate counting (called after upstream response).
func (rl *RateLimiter) Increment(key string) int64 {
	if !rl.enabled.Load() {
		return 0
	}
	now := time.Now().Unix()
	rl.mu.Lock()
	w, ok := rl.windows[key]
	if !ok || w.expiry <= now {
		w = &window{expiry: now + rl.windowS}
		rl.windows[key] = w
	}
	rl.mu.Unlock()
	return w.count.Add(1)
}

// IsOverLimit checks whether the current count exceeds max.
func (rl *RateLimiter) IsOverLimit(key string) bool {
	if !rl.enabled.Load() {
		return false
	}
	rl.mu.Lock()
	w, ok := rl.windows[key]
	rl.mu.Unlock()
	if !ok {
		return false
	}
	return w.count.Load() > rl.maxReqs
}

func (rl *RateLimiter) Close() {
	close(rl.stopCh)
}

func (rl *RateLimiter) cleaner() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			now := time.Now().Unix()
			rl.mu.Lock()
			for k, w := range rl.windows {
				if w.expiry <= now {
					delete(rl.windows, k)
				}
			}
			rl.mu.Unlock()
		}
	}
}
