package ratelimit

import "testing"

func TestRateLimiterIncrement(t *testing.T) {
	rl := NewRateLimiter(60, 100, true)
	defer rl.Close()

	n1 := rl.Increment("err-key")
	if n1 != 1 {
		t.Fatalf("first increment: want 1, got %d", n1)
	}
	n2 := rl.Increment("err-key")
	if n2 != 2 {
		t.Fatalf("second increment: want 2, got %d", n2)
	}
}

func TestRateLimiterIncrementDisabledReturnsZero(t *testing.T) {
	rl := NewRateLimiter(60, 100, false)
	defer rl.Close()

	if n := rl.Increment("key"); n != 0 {
		t.Fatalf("disabled increment: want 0, got %d", n)
	}
}

func TestRateLimiterIsOverLimitFalseBeforeThreshold(t *testing.T) {
	rl := NewRateLimiter(60, 3, true)
	defer rl.Close()

	rl.Allow("k")
	rl.Allow("k")
	if rl.IsOverLimit("k") {
		t.Fatal("2/3 requests: should not be over limit")
	}
}

func TestRateLimiterIsOverLimitTrueAfterThreshold(t *testing.T) {
	rl := NewRateLimiter(60, 2, true)
	defer rl.Close()

	rl.Allow("k")
	rl.Allow("k")
	rl.Allow("k") // 超出
	if !rl.IsOverLimit("k") {
		t.Fatal("3/2 requests: should be over limit")
	}
}

func TestRateLimiterIsOverLimitDisabledAlwaysFalse(t *testing.T) {
	rl := NewRateLimiter(60, 1, false)
	defer rl.Close()

	rl.Increment("k")
	rl.Increment("k")
	if rl.IsOverLimit("k") {
		t.Fatal("disabled: IsOverLimit should always be false")
	}
}

func TestRateLimiterSetEnabledToggles(t *testing.T) {
	rl := NewRateLimiter(60, 1, true)
	defer rl.Close()

	if !rl.Enabled() {
		t.Fatal("expected enabled=true initially")
	}
	rl.SetEnabled(false)
	if rl.Enabled() {
		t.Fatal("expected enabled=false after SetEnabled(false)")
	}
	// 禁用后 Allow 应始终返回 true
	if !rl.Allow("any") {
		t.Fatal("disabled limiter must allow all")
	}
}

func TestRateLimiterIsOverLimitUnknownKeyFalse(t *testing.T) {
	rl := NewRateLimiter(60, 5, true)
	defer rl.Close()

	if rl.IsOverLimit("never-seen") {
		t.Fatal("unknown key: IsOverLimit should be false")
	}
}

func TestRateLimiterDifferentKeyIsolated(t *testing.T) {
	rl := NewRateLimiter(60, 2, true)
	defer rl.Close()

	rl.Allow("a")
	rl.Allow("a")
	// key "a" 已满，key "b" 应该仍然允许
	if !rl.Allow("b") {
		t.Fatal("different key should be independent")
	}
}
