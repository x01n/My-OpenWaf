package ratelimit

import "testing"

/**
 * TestRateLimiterAllowWithQuotaUsesCallerQuota 验证 AllowWithQuota 的配额来自
 * 调用方而非后端全局配置：后端全局配额是 300/60s，站点配额是 3/60s，第 4 次
 * 请求必须被拒。
 */
func TestRateLimiterAllowWithQuotaUsesCallerQuota(t *testing.T) {
	rl := NewRateLimiter(60, 300, true)
	defer rl.Close()

	for i := 1; i <= 3; i++ {
		if !rl.AllowWithQuota("site-key", 60, 3) {
			t.Fatalf("第 %d 次请求应放行（站点配额 3/60s）", i)
		}
	}
	if rl.AllowWithQuota("site-key", 60, 3) {
		t.Fatal("第 4 次请求应被站点配额 3/60s 拒绝")
	}
}

/**
 * TestRateLimiterAllowAndAllowWithQuotaShareBucket 验证站点配额与全局配额在
 * 键相同时指向同一个计数桶：配额判定按调用方传入的上限，而不是各自独立计数。
 */
func TestRateLimiterAllowAndAllowWithQuotaShareBucket(t *testing.T) {
	rl := NewRateLimiter(60, 5, true)
	defer rl.Close()

	// 全局 Allow 记 2 次，站点配额上限 3：累计第 3 次仍放行，第 4 次被拒。
	if !rl.Allow("k") || !rl.Allow("k") {
		t.Fatal("全局配额 5/60s 下前两次请求应放行")
	}
	if !rl.AllowWithQuota("k", 60, 3) {
		t.Fatal("累计第 3 次请求应放行（站点上限 3）")
	}
	if rl.AllowWithQuota("k", 60, 3) {
		t.Fatal("累计第 4 次请求应被站点上限 3 拒绝")
	}
}

/**
 * TestRateLimiterAllowWithQuotaIsolatesKeys 验证不同站点键互不干扰：站点 A 的
 * 流量不得把站点 B 顶到配额上限。
 */
func TestRateLimiterAllowWithQuotaIsolatesKeys(t *testing.T) {
	rl := NewRateLimiter(60, 300, true)
	defer rl.Close()

	for i := 0; i < 3; i++ {
		if !rl.AllowWithQuota("site-a", 60, 3) {
			t.Fatalf("站点 A 第 %d 次请求应放行", i+1)
		}
	}
	if rl.AllowWithQuota("site-a", 60, 3) {
		t.Fatal("站点 A 第 4 次请求应被拒")
	}
	if !rl.AllowWithQuota("site-b", 60, 3) {
		t.Fatal("站点 B 首次请求应放行：其计数桶与站点 A 独立")
	}
}

/**
 * TestRateLimiterAllowWithQuotaInvalidQuotaAllows 验证 window/max <=0 时按未启用
 * 处理，返回 true，而不是把请求全部判为超限。
 */
func TestRateLimiterAllowWithQuotaInvalidQuotaAllows(t *testing.T) {
	rl := NewRateLimiter(60, 3, true)
	defer rl.Close()

	if !rl.AllowWithQuota("k", 0, 3) {
		t.Fatal("window=0 应按未启用处理并放行")
	}
	if !rl.AllowWithQuota("k", 60, 0) {
		t.Fatal("max=0 应按未启用处理并放行")
	}
	if !rl.AllowWithQuota("k", -1, -1) {
		t.Fatal("负配额应按未启用处理并放行")
	}
}

/**
 * TestRateLimiterAllowWithQuotaHonorsBackendEnabled 验证 enabled 仍取后端的全局
 * 开关：后端未启用时站点配额不再判定，所有请求放行。
 */
func TestRateLimiterAllowWithQuotaHonorsBackendEnabled(t *testing.T) {
	rl := NewRateLimiter(60, 3, false)
	defer rl.Close()

	for i := 0; i < 5; i++ {
		if !rl.AllowWithQuota("k", 60, 1) {
			t.Fatalf("后端未启用时第 %d 次请求应放行", i+1)
		}
	}
}
