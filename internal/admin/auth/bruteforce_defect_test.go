package auth

import (
	"sync"
	"testing"
	"time"
)

// TestIsLockedMustNotMutateMapUnderReadLock 回归测试：IsLocked 只持有 mu.RLock()，
// 因此其调用链不得写 bf.attempts。
//
// 历史缺陷：isLockedKey 曾在锁定过期分支执行 delete(bf.attempts, key)。RWMutex 允许
// 多个读者并发，两个并发的 IsLocked 会同时写 map，触发 Go 运行时不可恢复的
// "fatal error: concurrent map writes"。LoginHandler 每次登录都调用 IsLocked，
// 而 /api/v1/auth/login 是未认证端点，故该缺陷可被远程触发导致控制平面崩溃。
//
// 本用例采用确定性构造而非竞态探测：测试协程持有读锁期间，另一协程调用 IsLocked；
// 若 IsLocked 仍会在读锁下写 map，attempts 的长度会发生变化。
func TestIsLockedMustNotMutateMapUnderReadLock(t *testing.T) {
	const ip = "198.51.100.7"

	bf := &BruteForceDetector{
		attempts:    make(map[string]*attemptRecord),
		maxFailures: 2,
		lockoutDur:  time.Minute,
	}
	// 锁定时刻远早于 lockoutDur，使 isLockedKey 进入过期判断分支。
	past := time.Now().Add(-time.Hour)
	bf.attempts[ip] = &attemptRecord{failures: 5, lockedAt: past, lastFail: past}

	bf.mu.RLock()
	sizeBefore := len(bf.attempts)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// 读锁可并发获取，该调用会与外层读锁同时持有读锁。
		bf.IsLocked(ip, "admin")
	}()
	wg.Wait()

	sizeAfter := len(bf.attempts)
	bf.mu.RUnlock()

	if sizeAfter != sizeBefore {
		t.Errorf("IsLocked 在只持有读锁时修改了 attempts (len %d -> %d)；"+
			"isLockedKey 必须保持只读，过期条目交由 recordForKey 重置、cleanupLoop 回收",
			sizeBefore, sizeAfter)
	}
}

// TestConcurrentIsLockedOnExpiredRecords 以并发压力复现原缺陷的触发场景：
// 多个协程同时对已过期的锁定记录调用 IsLocked。配合 -race 运行可检出数据竞争。
func TestConcurrentIsLockedOnExpiredRecords(t *testing.T) {
	bf := &BruteForceDetector{
		attempts:    make(map[string]*attemptRecord),
		maxFailures: 2,
		lockoutDur:  time.Millisecond,
	}
	past := time.Now().Add(-time.Hour)
	const ip = "203.0.113.9"
	const user = "admin"

	for round := 0; round < 50; round++ {
		bf.mu.Lock()
		bf.attempts[ip] = &attemptRecord{failures: 9, lockedAt: past, lastFail: past}
		bf.attempts[bruteforceKey(ip, user)] = &attemptRecord{failures: 9, lockedAt: past, lastFail: past}
		bf.mu.Unlock()

		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				bf.IsLocked(ip, user)
			}()
		}
		wg.Wait()
	}
}

// TestExpiredLockoutGrantsFullBudget 验证锁定期满后重新获得完整失败额度，
// 而不是残留的高计数导致一次失败即再次锁定。
func TestExpiredLockoutGrantsFullBudget(t *testing.T) {
	const (
		ip   = "192.0.2.44"
		user = "alice"
		max  = 3
	)
	bf := &BruteForceDetector{
		attempts:    make(map[string]*attemptRecord),
		maxFailures: max,
		lockoutDur:  time.Minute,
	}
	past := time.Now().Add(-time.Hour)
	bf.attempts[ip] = &attemptRecord{failures: max, lockedAt: past, lastFail: past}
	bf.attempts[bruteforceKey(ip, user)] = &attemptRecord{failures: max, lockedAt: past, lastFail: past}

	if bf.IsLocked(ip, user) {
		t.Fatal("锁定期已过，IsLocked 应返回 false")
	}
	if got := bf.RemainingAttempts(ip, user); got != max {
		t.Fatalf("锁定期满后 RemainingAttempts = %d, want %d", got, max)
	}
	if got := bf.LockoutRemaining(ip, user); got != 0 {
		t.Fatalf("锁定期满后 LockoutRemaining = %v, want 0", got)
	}

	// 过期后的第一次失败应从 1 重新计数，而非在残留计数上累加。
	bf.RecordFailure(ip, user)
	if bf.IsLocked(ip, user) {
		t.Fatal("过期记录上的首次失败不应立即重新锁定")
	}
	if got := bf.RemainingAttempts(ip, user); got != max-1 {
		t.Fatalf("首次失败后 RemainingAttempts = %d, want %d", got, max-1)
	}

	// 用满剩余额度后才应重新锁定。
	for i := 0; i < max-1; i++ {
		bf.RecordFailure(ip, user)
	}
	if !bf.IsLocked(ip, user) {
		t.Fatal("用满完整失败额度后应重新锁定")
	}
}
