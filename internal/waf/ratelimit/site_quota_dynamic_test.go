package ratelimit

import (
	"context"
	"testing"
	"time"

	rueidis "github.com/redis/rueidis"
)

type noQuotaStubBackend struct {
	allowCalls  int
	allowResult bool
	enabled     bool
}

func (s *noQuotaStubBackend) Enabled() bool                { return s.enabled }
func (s *noQuotaStubBackend) Reconfigure(_, _ int, _ bool) {}
func (s *noQuotaStubBackend) Allow(string) bool {
	s.allowCalls++
	return s.allowResult
}
func (s *noQuotaStubBackend) Increment(string) int64  { return 0 }
func (s *noQuotaStubBackend) IsOverLimit(string) bool { return false }
func (s *noQuotaStubBackend) Close()                  {}

type quotaStubBackend struct {
	noQuotaStubBackend
	quotaCalls int
	lastWindow int
	lastMax    int
	lastKey    string
}

func (s *quotaStubBackend) AllowWithQuota(key string, windowSec, maxReqs int) bool {
	s.quotaCalls++
	s.lastKey = key
	s.lastWindow = windowSec
	s.lastMax = maxReqs
	return false
}

/**
 * TestDynamicRateLimiterAllowWithQuotaForwardsToCapableBackend 验证后端实现
 * SiteQuotaLimiter 时，动态包装器把站点配额原样透传，不再走全局 Allow。
 */
func TestDynamicRateLimiterAllowWithQuotaForwardsToCapableBackend(t *testing.T) {
	backend := &quotaStubBackend{}
	backend.enabled = true
	d := NewDynamicRateLimiter(backend)

	if d.AllowWithQuota("k", 60, 3) {
		t.Fatal("后端返回 false 时应透传 false")
	}
	if backend.quotaCalls != 1 {
		t.Fatalf("AllowWithQuota 调用次数 = %d, want 1", backend.quotaCalls)
	}
	if backend.allowCalls != 0 {
		t.Fatalf("透传路径不应调用全局 Allow，实际 %d 次", backend.allowCalls)
	}
	if backend.lastKey != "k" || backend.lastWindow != 60 || backend.lastMax != 3 {
		t.Fatalf("透传参数 = (%q,%d,%d), want (\"k\",60,3)", backend.lastKey, backend.lastWindow, backend.lastMax)
	}
}

/**
 * TestDynamicRateLimiterAllowWithQuotaFallsBackToAllow 验证后端**未**实现
 * SiteQuotaLimiter 时回退到全局 Allow，而不是放行全部请求。
 */
func TestDynamicRateLimiterAllowWithQuotaFallsBackToAllow(t *testing.T) {
	backend := &noQuotaStubBackend{enabled: true, allowResult: false}
	d := NewDynamicRateLimiter(backend)

	if d.AllowWithQuota("k", 60, 3) {
		t.Fatal("后端未声明 SiteQuotaLimiter 时应回退到 Allow，此处 Allow 返回 false")
	}
	if backend.allowCalls != 1 {
		t.Fatalf("回退路径应调用 Allow 一次，实际 %d 次", backend.allowCalls)
	}

	backend.allowResult = true
	if !d.AllowWithQuota("k", 60, 3) {
		t.Fatal("回退路径应返回 Allow 的结果")
	}
	if backend.allowCalls != 2 {
		t.Fatalf("回退路径累计 Allow 调用 = %d, want 2", backend.allowCalls)
	}
}

/**
 * TestDynamicRateLimiterAllowWithQuotaNilBackendAllows 验证无后端时放行，
 * 与 DynamicRateLimiter 其余方法在 nil 后端下的约定一致。
 */
func TestDynamicRateLimiterAllowWithQuotaNilBackendAllows(t *testing.T) {
	d := NewDynamicRateLimiter(nil)
	if !d.AllowWithQuota("k", 60, 3) {
		t.Fatal("nil 后端应放行")
	}
}

/**
 * TestRedisRateLimiterImplementsSiteQuotaLimiter 锁定 Redis 侧的接口实现，
 * 使两端点在编译期保持语义对齐（本地后端由 site_quota_test.go 的行为用例覆盖）。
 */
func TestRedisRateLimiterImplementsSiteQuotaLimiter(t *testing.T) {
	var backend RateLimiterBackend = &RedisRateLimiter{}
	if _, ok := backend.(SiteQuotaLimiter); !ok {
		t.Fatal("*RedisRateLimiter 必须实现 SiteQuotaLimiter，否则 Redis 部署下站点配额会回退到全局值")
	}
}

/**
 * TestRedisRateLimiterAllowWithQuotaWithoutRedisAllows 说明无 Redis 服务时的
 * 行为：脚本执行失败即放行（fail-open，与 Allow 的既有约定一致）。
 *
 * 端口取 19999，与既有用例 TestRedisRateLimiterAllowRedisUnavailableReturnsTrue
 * 相同：rueidis 在该端口上仍会构造出客户端对象，失败发生在脚本执行阶段而不是
 * 构造阶段，因此本用例不需要跳过。
 */
func TestRedisRateLimiterAllowWithQuotaWithoutRedisAllows(t *testing.T) {
	client, err := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:       []string{"127.0.0.1:19999"},
		DisableCache:      true,
		DisableRetry:      true,
		ForceSingleClient: true,
	})
	if client == nil && err != nil {
		t.Fatalf("构造 Redis 客户端失败：%v", err)
	}
	defer client.Close()

	rl := NewRedisRateLimiter(client, "owaf-test", 60, 1, true)
	if rl == nil {
		t.Fatal("新建的 RedisRateLimiter 不应为 nil")
	}
	// 上限为 1 且无可用 Redis：脚本执行失败时放行，不得把请求误判为超限。
	for i := 1; i <= 2; i++ {
		if !rl.AllowWithQuota("k", 60, 1) {
			t.Fatalf("第 %d 次请求在 Redis 不可用时被拒，违反 fail-open 约定", i)
		}
	}
}

/**
 * TestRedisRateLimiterAllowWithQuotaAgainstLiveRedis 在存在真实 Redis 时校验
 * 站点配额判定，说明本地与 Redis 两端点语义一致（同样的 3 次上限，第 4 次被拒）。
 *
 * 未配置本机 Redis 时跳过：跳过即表示本场未覆盖 Redis 侧行为，报告中须并列说明。
 */
func TestRedisRateLimiterAllowWithQuotaAgainstLiveRedis(t *testing.T) {
	client, err := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:       []string{"127.0.0.1:6379"},
		DisableCache:      true,
		DisableRetry:      true,
		ForceSingleClient: true,
	})
	if err != nil {
		t.Skipf("本机无 Redis（127.0.0.1:6379），跳过 Redis 侧行为校验：%v", err)
	}
	defer client.Close()

	prefix := "owaf-test-sitequota"
	rl := NewRedisRateLimiter(client, prefix, 60, 300, true)
	if rl == nil {
		t.Fatal("新建的 RedisRateLimiter 不应为 nil")
	}
	key := "live-quota-key-" + time.Now().Format("150405.000000000")
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = client.Do(ctx, client.B().Del().Key(prefix+":rl:"+key).Build()).Error()
	}()

	for i := 1; i <= 3; i++ {
		if !rl.AllowWithQuota(key, 60, 3) {
			t.Fatalf("第 %d 次请求应放行（站点配额 3/60s）", i)
		}
	}
	if rl.AllowWithQuota(key, 60, 3) {
		t.Fatal("第 4 次请求应被站点配额 3/60s 拒绝（Redis 滑动窗口）")
	}
}
