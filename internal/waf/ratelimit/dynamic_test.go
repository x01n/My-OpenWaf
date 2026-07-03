package ratelimit

import "testing"

type stubRateLimiterBackend struct {
	enabled          bool
	allowValue       bool
	incrementValue   int64
	overLimit        bool
	reconfigureCalls int
	windowSec        int
	maxReqs          int
	closeCalls       int
}

func (s *stubRateLimiterBackend) Enabled() bool {
	return s.enabled
}

func (s *stubRateLimiterBackend) Reconfigure(windowSec, maxReqs int, enabled bool) {
	s.reconfigureCalls++
	s.windowSec = windowSec
	s.maxReqs = maxReqs
	s.enabled = enabled
}

func (s *stubRateLimiterBackend) Allow(key string) bool {
	return s.allowValue
}

func (s *stubRateLimiterBackend) Increment(key string) int64 {
	return s.incrementValue
}

func (s *stubRateLimiterBackend) IsOverLimit(key string) bool {
	return s.overLimit
}

func (s *stubRateLimiterBackend) Close() {
	s.closeCalls++
}

func TestDynamicRateLimiterDelegatesAndSwapsBackend(t *testing.T) {
	first := &stubRateLimiterBackend{
		enabled:        true,
		allowValue:     false,
		incrementValue: 3,
		overLimit:      true,
	}
	rl := NewDynamicRateLimiter(first)

	if !rl.Enabled() {
		t.Fatal("expected first backend enabled state to be visible")
	}
	if rl.Allow("client") {
		t.Fatal("expected first backend allow result to be used")
	}
	if got := rl.Increment("client"); got != 3 {
		t.Fatalf("increment = %d, want 3", got)
	}
	if !rl.IsOverLimit("client") {
		t.Fatal("expected over-limit result from first backend")
	}

	rl.Reconfigure(30, 9, false)
	if first.reconfigureCalls != 1 || first.windowSec != 30 || first.maxReqs != 9 || first.enabled {
		t.Fatalf("unexpected first backend reconfigure state: %#v", first)
	}

	second := &stubRateLimiterBackend{
		enabled:        true,
		allowValue:     true,
		incrementValue: 7,
	}
	rl.Swap(second)
	if first.closeCalls != 1 {
		t.Fatalf("first backend close calls = %d, want 1", first.closeCalls)
	}
	if !rl.Allow("client") {
		t.Fatal("expected swapped backend allow result to be used")
	}
	if got := rl.Increment("client"); got != 7 {
		t.Fatalf("increment after swap = %d, want 7", got)
	}

	rl.Close()
	if second.closeCalls != 1 {
		t.Fatalf("second backend close calls = %d, want 1", second.closeCalls)
	}
	if !rl.Allow("client") {
		t.Fatal("nil backend should allow by default")
	}
}
