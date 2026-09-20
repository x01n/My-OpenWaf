package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiterBackend is shared by local and Redis-backed rate limiters.
type RateLimiterBackend interface {
	Enabled() bool
	Reconfigure(windowSec, maxReqs int, enabled bool)
	Allow(key string) bool
	Increment(key string) int64
	IsOverLimit(key string) bool
	Close()
}

// RateLimiter implements fixed-window rate limiting keyed by (clientIP + host).
type RateLimiter struct {
	mu        sync.Mutex
	configMu  sync.RWMutex
	windows   map[string]*window
	windowS   int64
	maxReqs   int64
	enabled   atomic.Bool
	stopCh    chan struct{}
	closeOnce sync.Once
}

type window struct {
	count  atomic.Int64
	expiry int64 // unix seconds
}

func NewRateLimiter(windowSec, maxReqs int, enabled bool) *RateLimiter {
	if windowSec <= 0 || maxReqs <= 0 {
		// 无效的限流参数不能把所有请求误判为超限（尤其是 max=0 会
		// 让第一请求直接得到 429）；按未启用处理，交由管理端提示修正。
		enabled = false
	}
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

func (rl *RateLimiter) Enabled() bool {
	if rl == nil {
		return false
	}
	rl.configMu.RLock()
	enabled := rl.enabled.Load()
	rl.configMu.RUnlock()
	return enabled
}

func (rl *RateLimiter) SetEnabled(v bool) {
	if rl == nil {
		return
	}
	rl.configMu.Lock()
	defer rl.configMu.Unlock()
	if v {
		rl.mu.Lock()
		valid := rl.windowS > 0 && rl.maxReqs > 0
		rl.mu.Unlock()
		if !valid {
			v = false
		}
	}
	rl.enabled.Store(v)
}

func (rl *RateLimiter) Reconfigure(windowSec, maxReqs int, enabled bool) {
	if rl == nil {
		return
	}
	rl.configMu.Lock()
	defer rl.configMu.Unlock()
	if windowSec <= 0 || maxReqs <= 0 {
		enabled = false
	}
	rl.mu.Lock()
	rl.windowS = int64(windowSec)
	rl.maxReqs = int64(maxReqs)
	rl.mu.Unlock()
	rl.enabled.Store(enabled)
}

func (rl *RateLimiter) Allow(key string) bool {
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
	now := time.Now().Unix()
	rl.mu.Lock()
	w, ok := rl.windows[key]
	if !ok || w.expiry <= now {
		w = &window{expiry: now + windowS}
		rl.windows[key] = w
	}
	rl.mu.Unlock()
	n := w.count.Add(1)
	return n <= maxReqs
}

// Increment is used for error rate counting (called after upstream response).
func (rl *RateLimiter) Increment(key string) int64 {
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
	now := time.Now().Unix()
	rl.mu.Lock()
	w, ok := rl.windows[key]
	if !ok || w.expiry <= now {
		w = &window{expiry: now + windowS}
		rl.windows[key] = w
	}
	rl.mu.Unlock()
	return w.count.Add(1)
}

// IsOverLimit checks whether the current count exceeds max.
func (rl *RateLimiter) IsOverLimit(key string) bool {
	if rl == nil {
		return false
	}
	rl.configMu.RLock()
	enabled := rl.enabled.Load()
	maxReqs := rl.maxReqs
	rl.configMu.RUnlock()
	if !enabled || maxReqs <= 0 {
		return false
	}
	rl.mu.Lock()
	w, ok := rl.windows[key]
	rl.mu.Unlock()
	if !ok {
		return false
	}
	return w.count.Load() > maxReqs
}

func (rl *RateLimiter) Close() {
	if rl == nil {
		return
	}
	rl.closeOnce.Do(func() {
		if rl.stopCh != nil {
			close(rl.stopCh)
		}
	})
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
			if len(rl.windows) == 0 {
				rl.windows = make(map[string]*window)
			}
			rl.mu.Unlock()
		}
	}
}
