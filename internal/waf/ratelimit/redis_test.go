package ratelimit

import (
	"testing"

	goredis "github.com/redis/go-redis/v9"
)

func TestNewRedisRateLimiterNilClientReturnsNil(t *testing.T) {
	rl := NewRedisRateLimiter(nil, "pfx", 60, 100, true)
	if rl != nil {
		t.Error("NewRedisRateLimiter(nil) should return nil")
	}
}

func TestNewRedisRateLimiterNonNil(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	rl := NewRedisRateLimiter(client, "pfx", 60, 100, true)
	if rl == nil {
		t.Fatal("NewRedisRateLimiter should return non-nil when client is non-nil")
	}
}

func TestRedisRateLimiterEnabledDefault(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	rl := NewRedisRateLimiter(client, "pfx", 60, 10, true)
	if rl == nil {
		t.Fatal("expected non-nil")
	}
	if !rl.Enabled() {
		t.Error("Enabled() should be true after creation with enabled=true")
	}
}

func TestRedisRateLimiterEnabledFalse(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	rl := NewRedisRateLimiter(client, "pfx", 60, 10, false)
	if rl == nil {
		t.Fatal("expected non-nil")
	}
	if rl.Enabled() {
		t.Error("Enabled() should be false after creation with enabled=false")
	}
}

func TestRedisRateLimiterReconfigure(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	rl := NewRedisRateLimiter(client, "pfx", 60, 10, false)
	if rl == nil {
		t.Fatal("expected non-nil")
	}
	rl.Reconfigure(30, 5, true)
	if !rl.Enabled() {
		t.Error("Enabled() should be true after Reconfigure(..., true)")
	}
}

func TestRedisRateLimiterAllowDisabledAlwaysTrue(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	rl := NewRedisRateLimiter(client, "pfx", 60, 1, false)
	if rl == nil {
		t.Fatal("expected non-nil")
	}
	for i := 0; i < 5; i++ {
		if !rl.Allow("key") {
			t.Fatalf("disabled Allow should always return true, failed at i=%d", i)
		}
	}
}

func TestRedisRateLimiterIncrementDisabledReturnsZero(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	rl := NewRedisRateLimiter(client, "pfx", 60, 10, false)
	if rl == nil {
		t.Fatal("expected non-nil")
	}
	if n := rl.Increment("key"); n != 0 {
		t.Errorf("disabled Increment should return 0, got %d", n)
	}
}

func TestRedisRateLimiterIsOverLimitDisabledAlwaysFalse(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	rl := NewRedisRateLimiter(client, "pfx", 60, 1, false)
	if rl == nil {
		t.Fatal("expected non-nil")
	}
	if rl.IsOverLimit("key") {
		t.Error("disabled IsOverLimit should always return false")
	}
}

func TestRedisRateLimiterAllowRedisUnavailableReturnsTrue(t *testing.T) {
	// Redis 不可用时降级为允许（fail-open），防止误拦截
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:19999"})
	defer client.Close()

	rl := NewRedisRateLimiter(client, "pfx", 60, 1, true)
	if rl == nil {
		t.Fatal("expected non-nil")
	}
	// Redis 连接失败应返回 true（fail-open）
	if !rl.Allow("key") {
		t.Error("Allow should return true when Redis is unavailable (fail-open)")
	}
}

func TestRedisRateLimiterIncrementRedisUnavailableReturnsZero(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:19999"})
	defer client.Close()

	rl := NewRedisRateLimiter(client, "pfx", 60, 10, true)
	if rl == nil {
		t.Fatal("expected non-nil")
	}
	if n := rl.Increment("key"); n != 0 {
		t.Errorf("Increment with Redis unavailable should return 0, got %d", n)
	}
}

func TestRedisRateLimiterIsOverLimitRedisUnavailableReturnsFalse(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:19999"})
	defer client.Close()

	rl := NewRedisRateLimiter(client, "pfx", 60, 1, true)
	if rl == nil {
		t.Fatal("expected non-nil")
	}
	if rl.IsOverLimit("key") {
		t.Error("IsOverLimit with Redis unavailable should return false (fail-open)")
	}
}

func TestRedisRateLimiterCloseIsNoOp(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer client.Close()

	rl := NewRedisRateLimiter(client, "pfx", 60, 10, true)
	if rl == nil {
		t.Fatal("expected non-nil")
	}
	rl.Close() // 不应 panic，是 no-op
}
