package auth

import (
	"fmt"
	"sync"
	"time"
)

// BruteForceDetector 按 IP 与用户名统计登录失败次数，用于抵挡暴力破解。
type BruteForceDetector struct {
	mu          sync.RWMutex
	attempts    map[string]*attemptRecord
	maxFailures int
	lockoutDur  time.Duration
	stopCh      chan struct{}
	closeOnce   sync.Once
}

type attemptRecord struct {
	failures int
	lockedAt time.Time
	lastFail time.Time
}

// NewBruteForceDetector 创建一个可配置阈值的检测器。
// 默认值：5 次失败、锁定 15 分钟。
func NewBruteForceDetector(maxFailures int, lockoutDuration time.Duration) *BruteForceDetector {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if lockoutDuration <= 0 {
		lockoutDuration = 15 * time.Minute
	}
	bf := &BruteForceDetector{
		attempts:    make(map[string]*attemptRecord),
		maxFailures: maxFailures,
		lockoutDur:  lockoutDuration,
		stopCh:      make(chan struct{}),
	}
	go bf.cleanupLoop()
	return bf
}

func (bf *BruteForceDetector) Reconfigure(maxFailures int, lockoutDuration time.Duration) {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if lockoutDuration <= 0 {
		lockoutDuration = 15 * time.Minute
	}
	bf.mu.Lock()
	bf.maxFailures = maxFailures
	bf.lockoutDur = lockoutDuration
	now := time.Now()
	for _, rec := range bf.attempts {
		if rec.failures >= maxFailures && rec.lockedAt.IsZero() {
			rec.lockedAt = now
		}
	}
	bf.mu.Unlock()
}

func bruteforceKey(ip, username string) string {
	return fmt.Sprintf("%s|%s", ip, username)
}

// IsLocked 判断给定的 IP+用户名 组合是否处于锁定状态。
func (bf *BruteForceDetector) IsLocked(ip, username string) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	// 先看 IP 级锁定。
	if bf.isLockedKey(ip) {
		return true
	}
	// 再看 IP+用户名 锁定。
	return bf.isLockedKey(bruteforceKey(ip, username))
}

// isLockedKey 报告该 key 当前是否被锁定。
// 本方法必须保持只读：调用方只持有 mu.RLock()，而 RWMutex 允许多个读者并发，
// 一旦在这里修改 bf.attempts，两个并发的 IsLocked 调用就可能同时写 map，
// 触发 "fatal error: concurrent map writes" 使进程崩溃。已过期的记录
// 故意留在原处：recordForKey 会在下次失败时重置它们，cleanupLoop 负责回收。
func (bf *BruteForceDetector) isLockedKey(key string) bool {
	rec, ok := bf.attempts[key]
	if !ok {
		return false
	}
	if rec.failures >= bf.maxFailures {
		return time.Since(rec.lockedAt) < bf.lockoutDur
	}
	return false
}

// RecordFailure 同时递增 IP 与 IP+用户名 两个维度的失败计数。
func (bf *BruteForceDetector) RecordFailure(ip, username string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	now := time.Now()
	// 记录 IP+用户名 维度。
	bf.recordForKey(bruteforceKey(ip, username), now)
	// 记录纯 IP 维度（IP 级全局限速）。
	bf.recordForKey(ip, now)
}

func (bf *BruteForceDetector) recordForKey(key string, now time.Time) {
	rec, ok := bf.attempts[key]
	if !ok {
		rec = &attemptRecord{}
		bf.attempts[key] = rec
	}
	// 锁定已过期的记录会重新开始计数，让调用方拿回完整的失败额度，
	// 而不是被单次失败立刻再次锁定。isLockedKey 有意保留这类记录。
	if rec.failures >= bf.maxFailures && now.Sub(rec.lockedAt) >= bf.lockoutDur {
		rec.failures = 0
		rec.lockedAt = time.Time{}
	}
	rec.failures++
	rec.lastFail = now
	if rec.failures >= bf.maxFailures {
		rec.lockedAt = now
	}
}

// RecordSuccess 清除给定 IP+用户名 的失败计数。
func (bf *BruteForceDetector) RecordSuccess(ip, username string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	delete(bf.attempts, bruteforceKey(ip, username))
}

// RemainingAttempts 返回距离锁定还剩多少次尝试机会。
func (bf *BruteForceDetector) RemainingAttempts(ip, username string) int {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	key := bruteforceKey(ip, username)
	rec, ok := bf.attempts[key]
	if !ok {
		return bf.maxFailures
	}
	// 已过期的锁定记录会在下次 recordForKey 时被重置，
	// 所以这里上报完整额度，而不是它仍然持有的那个陈旧零值。
	if rec.failures >= bf.maxFailures && time.Since(rec.lockedAt) >= bf.lockoutDur {
		return bf.maxFailures
	}
	remaining := bf.maxFailures - rec.failures
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

// LockoutRemaining 返回锁定状态的剩余时长，未锁定时返回 0。
func (bf *BruteForceDetector) LockoutRemaining(ip, username string) time.Duration {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	key := bruteforceKey(ip, username)
	rec, ok := bf.attempts[key]
	if !ok || rec.failures < bf.maxFailures {
		return 0
	}
	remaining := bf.lockoutDur - time.Since(rec.lockedAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Close 停止周期性清理协程，可安全地重复调用。
func (bf *BruteForceDetector) Close() {
	if bf == nil {
		return
	}
	bf.closeOnce.Do(func() {
		if bf.stopCh != nil {
			close(bf.stopCh)
		}
	})
}

func (bf *BruteForceDetector) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-bf.stopCh:
			return
		case <-ticker.C:
			bf.mu.Lock()
			now := time.Now()
			for key, rec := range bf.attempts {
				// 清理空闲时间超过两倍锁定时长的条目。
				if now.Sub(rec.lastFail) > bf.lockoutDur*2 {
					delete(bf.attempts, key)
				}
			}
			bf.mu.Unlock()
		}
	}
}
