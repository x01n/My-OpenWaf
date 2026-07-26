package auth

import (
	"testing"
	"time"
)

/**
 * newTestDetector 构造不启动 cleanupLoop 协程的探测器，便于确定性断言。
 * @param maxFailures 触发锁定的失败次数
 * @param lockoutDur 锁定时长
 * @returns 初始化完成的 *BruteForceDetector
 */
func newTestDetector(maxFailures int, lockoutDur time.Duration) *BruteForceDetector {
	return &BruteForceDetector{
		attempts:    make(map[string]*attemptRecord),
		maxFailures: maxFailures,
		lockoutDur:  lockoutDur,
	}
}

// ---------- 构造与默认值 ----------

// TestNewBruteForceDetectorAppliesDefaults 非正参数应回落到 5 次 / 15 分钟。
func TestNewBruteForceDetectorAppliesDefaults(t *testing.T) {
	bf := NewBruteForceDetector(0, 0)
	if bf.maxFailures != 5 {
		t.Errorf("maxFailures = %d, want 5", bf.maxFailures)
	}
	if bf.lockoutDur != 15*time.Minute {
		t.Errorf("lockoutDur = %v, want 15m", bf.lockoutDur)
	}

	neg := NewBruteForceDetector(-3, -time.Second)
	if neg.maxFailures != 5 || neg.lockoutDur != 15*time.Minute {
		t.Errorf("负数参数未回落到默认值: maxFailures=%d lockoutDur=%v", neg.maxFailures, neg.lockoutDur)
	}
}

// TestReconfigureAppliesDefaults Reconfigure 传入非正参数同样应回落默认值。
func TestReconfigureAppliesDefaults(t *testing.T) {
	bf := newTestDetector(3, time.Minute)
	bf.Reconfigure(0, 0)

	if bf.maxFailures != 5 {
		t.Errorf("maxFailures = %d, want 5", bf.maxFailures)
	}
	if bf.lockoutDur != 15*time.Minute {
		t.Errorf("lockoutDur = %v, want 15m", bf.lockoutDur)
	}
}

// ---------- 锁定触发 ----------

// TestLockoutTriggersAtThreshold 失败次数达到阈值的那一次才应锁定，之前不锁。
func TestLockoutTriggersAtThreshold(t *testing.T) {
	bf := newTestDetector(3, time.Minute)

	for i := 1; i < 3; i++ {
		bf.RecordFailure("192.0.2.10", "admin")
		if bf.IsLocked("192.0.2.10", "admin") {
			t.Fatalf("第 %d 次失败后不应锁定（阈值 3）", i)
		}
	}

	bf.RecordFailure("192.0.2.10", "admin")
	if !bf.IsLocked("192.0.2.10", "admin") {
		t.Fatal("达到阈值后必须锁定")
	}
}

// TestIPLevelLockAffectsOtherUsernames 同一 IP 上跨用户名的失败累计应触发 IP 级锁定。
func TestIPLevelLockAffectsOtherUsernames(t *testing.T) {
	bf := newTestDetector(3, time.Minute)

	// 三个不同用户名各失败一次，IP 级计数累计到 3。
	bf.RecordFailure("192.0.2.20", "alice")
	bf.RecordFailure("192.0.2.20", "bob")
	bf.RecordFailure("192.0.2.20", "carol")

	if !bf.IsLocked("192.0.2.20", "dave") {
		t.Error("IP 级计数达到阈值后，同 IP 的全新用户名也应被锁定（防用户名枚举）")
	}
	if bf.IsLocked("192.0.2.21", "alice") {
		t.Error("其他 IP 不应受影响")
	}
}

// TestExpiredLockoutResets 锁定超时后应自动解锁。
func TestExpiredLockoutResets(t *testing.T) {
	bf := newTestDetector(2, time.Minute)
	bf.RecordFailure("192.0.2.30", "admin")
	bf.RecordFailure("192.0.2.30", "admin")
	if !bf.IsLocked("192.0.2.30", "admin") {
		t.Fatal("达到阈值后应锁定")
	}

	// 将锁定时间回拨到 lockoutDur 之前，模拟锁定到期。
	past := time.Now().Add(-2 * time.Minute)
	for _, key := range []string{"192.0.2.30", bruteforceKey("192.0.2.30", "admin")} {
		if rec, ok := bf.attempts[key]; ok {
			rec.lockedAt = past
			rec.lastFail = past
		}
	}

	if bf.IsLocked("192.0.2.30", "admin") {
		t.Error("锁定到期后应自动解锁")
	}
}

// TestFailureAfterExpiryStartsFreshCount 锁定到期后的首次失败应重置计数，而非立即重新锁定。
//
// isLockedKey 只读判断、不再删除过期条目，因此过期记录会残留在 attempts 中；
// recordForKey 必须在其上重新计数，否则用户在解锁后一次失败就会被再次锁定。
func TestFailureAfterExpiryStartsFreshCount(t *testing.T) {
	bf := newTestDetector(3, time.Minute)
	for i := 0; i < 3; i++ {
		bf.RecordFailure("192.0.2.130", "admin")
	}
	if !bf.IsLocked("192.0.2.130", "admin") {
		t.Fatal("前置条件：应已锁定")
	}

	// 回拨锁定时间，模拟锁定到期。
	past := time.Now().Add(-2 * time.Minute)
	for _, key := range []string{"192.0.2.130", bruteforceKey("192.0.2.130", "admin")} {
		rec := bf.attempts[key]
		rec.lockedAt = past
		rec.lastFail = past
	}
	if bf.IsLocked("192.0.2.130", "admin") {
		t.Fatal("前置条件：锁定应已到期")
	}

	// 到期后的第一次失败只应计 1 次，不得立即重新锁定。
	bf.RecordFailure("192.0.2.130", "admin")

	if bf.IsLocked("192.0.2.130", "admin") {
		t.Error("解锁后单次失败不应立即重新锁定")
	}
	if got := bf.RemainingAttempts("192.0.2.130", "admin"); got != 2 {
		t.Errorf("解锁后单次失败 RemainingAttempts = %d, want 2（应恢复完整预算）", got)
	}
	if rec := bf.attempts[bruteforceKey("192.0.2.130", "admin")]; rec.failures != 1 {
		t.Errorf("failures = %d, want 1（过期记录应被重置）", rec.failures)
	}
}

// TestExpiredRecordCanLockAgainAfterFullBudget 到期重置后仍需再次用满阈值才会锁定。
func TestExpiredRecordCanLockAgainAfterFullBudget(t *testing.T) {
	bf := newTestDetector(3, time.Minute)
	for i := 0; i < 3; i++ {
		bf.RecordFailure("192.0.2.140", "admin")
	}
	past := time.Now().Add(-2 * time.Minute)
	for _, key := range []string{"192.0.2.140", bruteforceKey("192.0.2.140", "admin")} {
		rec := bf.attempts[key]
		rec.lockedAt = past
		rec.lastFail = past
	}

	bf.RecordFailure("192.0.2.140", "admin")
	bf.RecordFailure("192.0.2.140", "admin")
	if bf.IsLocked("192.0.2.140", "admin") {
		t.Fatal("重置后 2 次失败（阈值 3）不应锁定")
	}

	bf.RecordFailure("192.0.2.140", "admin")
	if !bf.IsLocked("192.0.2.140", "admin") {
		t.Error("重置后再次达到阈值应重新锁定")
	}
}

// ---------- RecordSuccess ----------

// TestRecordSuccessClearsUserCounter 成功登录应清空该 IP+用户名 的失败计数。
func TestRecordSuccessClearsUserCounter(t *testing.T) {
	bf := newTestDetector(5, time.Minute)
	bf.RecordFailure("192.0.2.40", "admin")
	bf.RecordFailure("192.0.2.40", "admin")

	if got := bf.RemainingAttempts("192.0.2.40", "admin"); got != 3 {
		t.Fatalf("RemainingAttempts = %d, want 3", got)
	}

	bf.RecordSuccess("192.0.2.40", "admin")

	if got := bf.RemainingAttempts("192.0.2.40", "admin"); got != 5 {
		t.Errorf("成功登录后 RemainingAttempts = %d, want 5", got)
	}
}

// TestRecordSuccessDoesNotClearIPCounter 记录当前行为：成功登录只清 IP+用户名，不清 IP 级计数。
func TestRecordSuccessDoesNotClearIPCounter(t *testing.T) {
	bf := newTestDetector(3, time.Minute)
	bf.RecordFailure("192.0.2.50", "alice")
	bf.RecordFailure("192.0.2.50", "bob")
	bf.RecordFailure("192.0.2.50", "carol")

	bf.RecordSuccess("192.0.2.50", "alice")

	if _, ok := bf.attempts["192.0.2.50"]; !ok {
		t.Fatal("IP 级计数条目应保留")
	}
	if !bf.IsLocked("192.0.2.50", "alice") {
		t.Error("成功登录不会解除 IP 级锁定，IsLocked 仍应为 true")
	}
}

// ---------- RemainingAttempts ----------

func TestRemainingAttemptsUnknownKey(t *testing.T) {
	bf := newTestDetector(4, time.Minute)
	if got := bf.RemainingAttempts("192.0.2.60", "nobody"); got != 4 {
		t.Errorf("RemainingAttempts = %d, want 4", got)
	}
}

func TestRemainingAttemptsDecrementsAndFloorsAtZero(t *testing.T) {
	bf := newTestDetector(3, time.Minute)

	want := []int{2, 1, 0}
	for i, expect := range want {
		bf.RecordFailure("192.0.2.70", "admin")
		if got := bf.RemainingAttempts("192.0.2.70", "admin"); got != expect {
			t.Errorf("第 %d 次失败后 RemainingAttempts = %d, want %d", i+1, got, expect)
		}
	}

	// 超过阈值后不应返回负数。
	bf.RecordFailure("192.0.2.70", "admin")
	bf.RecordFailure("192.0.2.70", "admin")
	if got := bf.RemainingAttempts("192.0.2.70", "admin"); got != 0 {
		t.Errorf("超过阈值后 RemainingAttempts = %d, want 0", got)
	}
}

// ---------- LockoutRemaining ----------

func TestLockoutRemainingZeroWhenNotLocked(t *testing.T) {
	bf := newTestDetector(3, time.Minute)

	if got := bf.LockoutRemaining("192.0.2.80", "admin"); got != 0 {
		t.Errorf("无记录时 LockoutRemaining = %v, want 0", got)
	}

	bf.RecordFailure("192.0.2.80", "admin")
	if got := bf.LockoutRemaining("192.0.2.80", "admin"); got != 0 {
		t.Errorf("未达阈值时 LockoutRemaining = %v, want 0", got)
	}
}

func TestLockoutRemainingPositiveWhenLocked(t *testing.T) {
	bf := newTestDetector(2, 10*time.Minute)
	bf.RecordFailure("192.0.2.90", "admin")
	bf.RecordFailure("192.0.2.90", "admin")

	got := bf.LockoutRemaining("192.0.2.90", "admin")
	if got <= 0 {
		t.Fatalf("锁定期间 LockoutRemaining = %v, 应为正值", got)
	}
	if got > 10*time.Minute {
		t.Errorf("LockoutRemaining = %v, 不应超过 lockoutDur", got)
	}
}

// TestLockoutRemainingZeroAfterExpiry 锁定到期后剩余时间应为 0 而非负值。
func TestLockoutRemainingZeroAfterExpiry(t *testing.T) {
	bf := newTestDetector(2, time.Minute)
	bf.RecordFailure("192.0.2.91", "admin")
	bf.RecordFailure("192.0.2.91", "admin")

	rec := bf.attempts[bruteforceKey("192.0.2.91", "admin")]
	rec.lockedAt = time.Now().Add(-2 * time.Minute)

	if got := bf.LockoutRemaining("192.0.2.91", "admin"); got != 0 {
		t.Errorf("到期后 LockoutRemaining = %v, want 0", got)
	}
}

// TestIPLevelLockReportsZeroRetryAfter 记录 IsLocked 与 LockoutRemaining 的口径不一致。
//
// IsLocked 同时检查 IP 级与 IP+用户名 两个键，而 RemainingAttempts / LockoutRemaining
// 只查 IP+用户名 键。当客户端仅因 IP 级计数被锁定时，LoginHandler
// (internal/admin/auth.go:45-52) 会返回 429 且 retry_after_secs 为 0。
func TestIPLevelLockReportsZeroRetryAfter(t *testing.T) {
	bf := newTestDetector(3, 10*time.Minute)
	bf.RecordFailure("192.0.2.100", "alice")
	bf.RecordFailure("192.0.2.100", "bob")
	bf.RecordFailure("192.0.2.100", "carol")

	if !bf.IsLocked("192.0.2.100", "dave") {
		t.Fatal("IP 级锁定应对新用户名生效")
	}
	if got := bf.LockoutRemaining("192.0.2.100", "dave"); got != 0 {
		t.Errorf("当前实现下 LockoutRemaining = %v, 期望记录为 0（口径不一致）", got)
	}
	if got := bf.RemainingAttempts("192.0.2.100", "dave"); got != 3 {
		t.Errorf("当前实现下 RemainingAttempts = %d, 期望记录为 3（口径不一致）", got)
	}
}

// ---------- Reconfigure ----------

// TestReconfigureMarksAlreadyExceededRecordsLocked 调低阈值后，既有超限记录应被补盖锁定时间戳。
func TestReconfigureMarksAlreadyExceededRecordsLocked(t *testing.T) {
	bf := newTestDetector(10, time.Minute)
	for i := 0; i < 4; i++ {
		bf.RecordFailure("192.0.2.110", "admin")
	}
	if bf.IsLocked("192.0.2.110", "admin") {
		t.Fatal("阈值 10 时 4 次失败不应锁定")
	}

	bf.Reconfigure(4, time.Minute)

	rec := bf.attempts[bruteforceKey("192.0.2.110", "admin")]
	if rec.lockedAt.IsZero() {
		t.Error("Reconfigure 应为已超限记录补写 lockedAt")
	}
	if !bf.IsLocked("192.0.2.110", "admin") {
		t.Error("调低阈值后应立即锁定")
	}
	if got := bf.LockoutRemaining("192.0.2.110", "admin"); got <= 0 {
		t.Errorf("调低阈值后 LockoutRemaining = %v, 应为正值", got)
	}
}

// TestReconfigureRaisingThresholdUnlocks 调高阈值后，原本锁定的记录应解锁。
func TestReconfigureRaisingThresholdUnlocks(t *testing.T) {
	bf := newTestDetector(2, time.Minute)
	bf.RecordFailure("192.0.2.120", "admin")
	bf.RecordFailure("192.0.2.120", "admin")
	if !bf.IsLocked("192.0.2.120", "admin") {
		t.Fatal("阈值 2 时应锁定")
	}

	bf.Reconfigure(10, time.Minute)

	if bf.IsLocked("192.0.2.120", "admin") {
		t.Error("阈值调高到 10 后不应再锁定")
	}
}
