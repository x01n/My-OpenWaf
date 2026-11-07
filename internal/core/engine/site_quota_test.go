package engine

import (
	"net"
	"strconv"
	"sync"
	"testing"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/core/rules"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

/**
 * siteQuotaLimiterSpy 记录每个 key 的计数，并按调用方传入的配额判定。
 *
 * 它同时实现 ratelimit.SiteQuotaLimiter，因此引擎会走 AllowWithQuota 分支；
 * 记录到的 (window, max) 就是阶段实际携带的站点级配额。
 */
type siteQuotaLimiterSpy struct {
	mu      sync.Mutex
	counts  map[string]int
	windows map[string]int
	maxes   map[string]int
	enabled bool
}

func newSiteQuotaLimiterSpy() *siteQuotaLimiterSpy {
	return &siteQuotaLimiterSpy{
		counts:  map[string]int{},
		windows: map[string]int{},
		maxes:   map[string]int{},
		enabled: true,
	}
}

func (s *siteQuotaLimiterSpy) Enabled() bool { return s.enabled }
func (s *siteQuotaLimiterSpy) Reconfigure(_, _ int, enabled bool) {
	s.enabled = enabled
}

// Allow 是全局配额路径：上限固定在 1，用于验证未携带站点配额时的调用方。
func (s *siteQuotaLimiterSpy) Allow(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[key]++
	return s.counts[key] <= 1
}

func (s *siteQuotaLimiterSpy) Increment(key string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[key]++
	return int64(s.counts[key])
}

func (s *siteQuotaLimiterSpy) IsOverLimit(string) bool { return false }
func (s *siteQuotaLimiterSpy) Close()                  {}

func (s *siteQuotaLimiterSpy) AllowWithQuota(key string, windowSec, maxReqs int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[key]++
	s.windows[key] = windowSec
	s.maxes[key] = maxReqs
	return s.counts[key] <= maxReqs
}

func (s *siteQuotaLimiterSpy) observed(key string) (window, max int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, hasW := s.windows[key]
	m, hasM := s.maxes[key]
	return w, m, hasW && hasM
}

func (s *siteQuotaLimiterSpy) calls(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[key]
}

/**
 * TestReqRateLimitPhaseCarriesSiteQuota 是站点级配额的守门测试。
 *
 * 站点级 rate_limit_window / rate_limit_max 由 mergeProtection 写进
 * rt.EffectiveProtection，但进程级限流单例的 Reconfigure 只反映全局配置。
 * 若阶段构造时不携带站点配额，站点覆盖值就没有任何运行时读取者——
 * 表现为「管理界面能存、实际按全局配额限流」。
 *
 * 断言两点：
 *  1. 站点覆盖值确实传到了限流后端（window/max 与站点配置一致）；
 *  2. 未覆盖的站点尽管不带站点值，仍必须进入限流判定（走全局配额），
 *     不能在回退路径上被整体放行。
 *
 * 请求由数据面之外的调用方发起，故用例显式填充 Bind/ClientIP/SiteID：
 * 它们与 handler.go 生产路径写入的值一致（reqCtx.SiteID = rt.Site.ID）。
 */
func TestReqRateLimitPhaseCarriesSiteQuota(t *testing.T) {
	global := store.DefaultProtectionConfig()
	global.RequestRateLimitEnabled = true
	global.RequestRateLimitWindow = 60
	global.RequestRateLimitMax = 300

	// 站点级配额远小于全局配额，确保「第 4 次被拒」只可能来自站点值。
	overridden := global
	overridden.RequestRateLimitWindow = 7
	overridden.RequestRateLimitMax = 3

	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: global,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "overridden.example.com"): {
				Site:                store.Site{ID: 1, Host: "overridden.example.com", Bind: ":80"},
				Bind:                ":80",
				PolicyID:            1,
				EffectiveProtection: &overridden,
			},
			snapshot.SiteMapKey(":80", "inherited.example.com"): {
				Site:     store.Site{ID: 2, Host: "inherited.example.com", Bind: ":80"},
				Bind:     ":80",
				PolicyID: 1,
			},
		},
	})

	limiter := newSiteQuotaLimiterSpy()
	eng := New(holder, limiter, nil, nil)

	siteKey := func(siteID uint, host string) string {
		return ":80|" + strconv.FormatUint(uint64(siteID), 10) + "|" + host + "|203.0.113.9"
	}
	run := func(host string, siteID uint) string {
		return string(eng.Process(&pipeline.RequestCtx{
			Bind:     ":80",
			SiteID:   siteID,
			Host:     host,
			Path:     "/",
			ClientIP: net.ParseIP("203.0.113.9"),
			Headers:  map[string]string{},
		}).Action.Type)
	}

	// 站点配额 3/7s：前 3 次放行，第 4 次起限流。
	for i := 1; i <= 3; i++ {
		if got := run("overridden.example.com", 1); got != "allow" {
			t.Fatalf("站点配额 3 次内第 %d 次 action = %q, want allow", i, got)
		}
	}
	key := siteKey(1, "overridden.example.com")
	window, max, ok := limiter.observed(key)
	if !ok {
		t.Fatalf("站点级配额未到达限流后端：键 %q 未记录 window/max；已观测=%v", key, limiter.maxes)
	}
	if window != 7 || max != 3 {
		t.Fatalf("站点级配额 = window:%d max:%d, want window:7 max:3（站点覆盖值未生效）", window, max)
	}
	if got := run("overridden.example.com", 1); got != "rate_limit" {
		t.Fatalf("第 4 次请求 action = %q, want rate_limit（旧代码按全局 300 会放行）", got)
	}

	// 未覆盖站点：不带站点覆盖值，但必须仍然进入限流判定（走全局配额）。
	if got := run("inherited.example.com", 2); got != "allow" {
		t.Fatalf("未覆盖站点首次请求 action = %q, want allow", got)
	}
	inheritedKey := siteKey(2, "inherited.example.com")
	if limiter.calls(inheritedKey) != 1 {
		t.Fatalf("未覆盖站点应进入限流判定，键 %q 计数 = %d, want 1", inheritedKey, limiter.calls(inheritedKey))
	}
}

/**
 * vanillaLimiterSpy 只实现 RateLimiterBackend，刻意**不**实现 SiteQuotaLimiter，
 * 用于验证回退路径：阶段携带站点配额时，未声明该能力的后端必须退回 Allow。
 */
type vanillaLimiterSpy struct {
	mu       sync.Mutex
	counts   map[string]int
	maxReqs  int
	allowHit int
	quotaHit int
}

func newVanillaLimiterSpy(maxReqs int) *vanillaLimiterSpy {
	return &vanillaLimiterSpy{counts: map[string]int{}, maxReqs: maxReqs}
}

func (v *vanillaLimiterSpy) Enabled() bool                { return true }
func (v *vanillaLimiterSpy) Reconfigure(_, _ int, _ bool) {}
func (v *vanillaLimiterSpy) Increment(string) int64       { return 0 }
func (v *vanillaLimiterSpy) IsOverLimit(string) bool      { return false }
func (v *vanillaLimiterSpy) Close()                       {}

func (v *vanillaLimiterSpy) Allow(key string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.allowHit++
	v.counts[key]++
	return v.counts[key] <= v.maxReqs
}

func (v *vanillaLimiterSpy) hits() (allow, quota int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.allowHit, v.quotaHit
}

/**
 * TestReqRateLimitPhaseVanillaLimiterFallsBackToGlobalQuota 确保不认识
 * SiteQuotaLimiter 的后端（仅实现 RateLimiterBackend）不会因缺少可选能力而放行：
 * 阶段携带站点配额时必须退回 Allow，由后端自己的全局配额判定。
 */
func TestReqRateLimitPhaseVanillaLimiterFallsBackToGlobalQuota(t *testing.T) {
	global := store.DefaultProtectionConfig()
	global.RequestRateLimitEnabled = true

	// 站点覆盖成「宽松配额」：若阶段把站点配额硬塞给后端，第二次请求仍会放行。
	overridden := global
	overridden.RequestRateLimitWindow = 3600
	overridden.RequestRateLimitMax = 9999

	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: global,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "example.com"): {
				Site:                store.Site{ID: 1, Host: "example.com", Bind: ":80"},
				Bind:                ":80",
				PolicyID:            1,
				EffectiveProtection: &overridden,
			},
		},
	})

	vanilla := newVanillaLimiterSpy(1)
	eng := New(holder, vanilla, nil, nil)
	req := func() string {
		return string(eng.Process(&pipeline.RequestCtx{
			Bind:     ":80",
			SiteID:   1,
			Host:     "example.com",
			Path:     "/",
			ClientIP: net.ParseIP("203.0.113.9"),
			Headers:  map[string]string{},
		}).Action.Type)
	}

	if first := req(); first != "allow" {
		t.Fatalf("第一次请求 action = %q, want allow", first)
	}
	if second := req(); second != "rate_limit" {
		t.Fatalf("回退路径应按后端全局配额限流：第二次 action = %q, want rate_limit", second)
	}
	allowHits, _ := vanilla.hits()
	if allowHits != 2 {
		t.Fatalf("回退路径应调用后端 Allow 两次（每次请求一次），实际 %d 次", allowHits)
	}
}

/**
 * TestReqRateLimitPhaseWithoutSiteQuotaUsesGlobalOnly 锁定 window<=0 或 max<=0 的
 * 等价性：任一非正时不得走站点配额分支，且每次请求只调用后端一次
 * （Allow 与 AllowWithQuota 都会自增计数，双重调用会把一次请求记成两次）。
 */
func TestReqRateLimitPhaseWithoutSiteQuotaUsesGlobalOnly(t *testing.T) {
	global := store.DefaultProtectionConfig()
	global.RequestRateLimitEnabled = true
	global.RequestRateLimitWindow = 60
	global.RequestRateLimitMax = 300

	zeroWindow := global
	zeroWindow.RequestRateLimitWindow = 0
	zeroWindow.RequestRateLimitMax = 3

	zeroMax := global
	zeroMax.RequestRateLimitWindow = 7
	zeroMax.RequestRateLimitMax = 0

	cases := []struct {
		name string
		prot store.ProtectionConfig
	}{
		{"window<=0", zeroWindow},
		{"max<=0", zeroMax},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			holder := &snapshot.Holder{}
			holder.Store(&snapshot.Snapshot{
				Revision:   1,
				Protection: global,
				Sites: map[string]*snapshot.SiteRuntime{
					snapshot.SiteMapKey(":80", "example.com"): {
						Site:                store.Site{ID: 1, Host: "example.com", Bind: ":80"},
						Bind:                ":80",
						PolicyID:            1,
						EffectiveProtection: &tc.prot,
					},
				},
			})

			limiter := newSiteQuotaLimiterSpy()
			eng := New(holder, limiter, nil, nil)
			eng.Process(&pipeline.RequestCtx{
				Bind:     ":80",
				SiteID:   1,
				Host:     "example.com",
				Path:     "/",
				ClientIP: net.ParseIP("203.0.113.9"),
				Headers:  map[string]string{},
			})

			key := ":80|1|example.com|203.0.113.9"
			window, _, observed := limiter.observed(key)
			if observed {
				t.Fatalf("站点配额未生效时不应调用 AllowWithQuota（观测到 window:%d）", window)
			}
			if got := limiter.calls(key); got != 1 {
				t.Fatalf("每次请求的后端计数调用次数 = %d, want 1（Allow 与 AllowWithQuota 不得双计）", got)
			}
		})
	}
}

// 显式断言两个构造器都在非覆盖场景下可用，避免 NewReqRateLimitPhase 被弃用后无人覆盖。
func TestNewReqRateLimitPhaseStillAvailable(t *testing.T) {
	if p := rules.NewReqRateLimitPhase(newVanillaLimiterSpy(1), action.RateLimit); p == nil {
		t.Fatal("NewReqRateLimitPhase 不应返回 nil")
	}
}
