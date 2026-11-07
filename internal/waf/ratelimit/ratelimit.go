package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiterBackend 由本地与 Redis 两套限流实现共享。
type RateLimiterBackend interface {
	Enabled() bool
	Reconfigure(windowSec, maxReqs int, enabled bool)
	Allow(key string) bool
	Increment(key string) int64
	IsOverLimit(key string) bool
	Close()
}

/**
 * SiteQuotaLimiter 是限流后端的可选能力：以调用方给定的窗口与配额判定。
 *
 * 后端自身持有的是「全局配额」，而站点级 rate_limit_window / rate_limit_max
 * 是每站点不同的覆盖值——把它们 Reconfigure 进进程级单例会互相踩踏。实现本
 * 接口的后端按 (key, window, max) 独立计数，使站点覆盖值能真正生效。
 *
 * 未实现本接口的后端由调用方回退到 Allow（沿用全局配额）。
 */
type SiteQuotaLimiter interface {
	AllowWithQuota(key string, windowSec, maxReqs int) bool
}

// RateLimiter 实现以 (clientIP + host) 为键的固定窗口限流。
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
	expiry int64 // unix 秒
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

// Increment 用于错误率计数（在上游响应之后调用）。
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

/**
 * AllowWithQuota 用调用方给定的窗口与配额判定，用于站点级覆盖值。
 *
 * 与 Allow 的差别只有配额来源：窗口与上限来自参数而非后端自身的全局配置，
 * 因此同一后端可同时服务多个站点而互不干扰。计数窗口与 Allow 共用同一张
 * windows 表——键里已含站点维度，不会串桶；仅当站点配额与全局配额一致时
 * 两者才指向同一个桶，此时语义也相同。
 *
 * enabled 仍取后端的全局开关：站点级字段只覆盖窗口与配额，不单独表达启停。
 *
 * @param key       计数键。
 * @param windowSec 窗口长度（秒）；<=0 时按未启用处理。
 * @param maxReqs   窗口内允许的请求数；<=0 时按未启用处理。
 * @return 未超限返回 true。
 */
func (rl *RateLimiter) AllowWithQuota(key string, windowSec, maxReqs int) bool {
	if rl == nil {
		return true
	}
	rl.configMu.RLock()
	enabled := rl.enabled.Load()
	rl.configMu.RUnlock()
	if !enabled || windowSec <= 0 || maxReqs <= 0 {
		return true
	}
	now := time.Now().Unix()
	rl.mu.Lock()
	w, ok := rl.windows[key]
	if !ok || w.expiry <= now {
		w = &window{expiry: now + int64(windowSec)}
		rl.windows[key] = w
	}
	rl.mu.Unlock()
	n := w.count.Add(1)
	return n <= int64(maxReqs)
}

// IsOverLimit 检查当前计数是否已超过 max。
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
