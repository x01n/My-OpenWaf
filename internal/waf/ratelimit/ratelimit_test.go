package ratelimit

import (
	"testing"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(60, 3, true)
	defer rl.Close()

	for i := 0; i < 3; i++ {
		if !rl.Allow("key1") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if rl.Allow("key1") {
		t.Fatal("4th request should be blocked")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	rl := NewRateLimiter(60, 1, false)
	defer rl.Close()

	if !rl.Allow("key1") {
		t.Fatal("disabled limiter should always allow")
	}
	if !rl.Allow("key1") {
		t.Fatal("disabled limiter should always allow")
	}
}

func TestRateLimiterReconfigure(t *testing.T) {
	rl := NewRateLimiter(60, 100, false)
	defer rl.Close()

	rl.Reconfigure(60, 2, true)
	rl.Allow("k")
	rl.Allow("k")
	if rl.Allow("k") {
		t.Fatal("should be over limit after reconfigure")
	}
}
