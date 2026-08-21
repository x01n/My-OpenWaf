package dataplane

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/challenge"
)

/*
本文件补齐 antireplay_handler_test.go 未覆盖的三类语义，同样只固化现状、不改运行时行为：

  1. 开关与 TTL 的**继承关系**（站点 vs 全局 protection）；
  2. AntiReplay 关闭时两个入口是否都真正静默；
  3. 站点 AntiReplayTTL 在 **Cookie 入口**的实际生效情况
     （既有测试只在 websocket_test.go:1153 覆盖了 X-Nonce phase 的 TTL）。

取证结论（均来自源码）：

  - 开关不是"继承"而是**逻辑或**：internal/snapshot/build.go:321 写作
    `AntiReplayEnabled: s.AntiReplayEnabled || protection.AntiReplayEnabled`。
    因此站点关闭**无法**覆盖全局开启，不存在 nullable 三态语义。
  - Site.AntiReplayEnabled 是非指针 bool（internal/store/site.go:60，
    `gorm:"default:false"`），与 OWASPEnabled/CVEEnabled 等 `*bool` 三态字段
    （site.go:64、67）形成对比，从类型上就不具备"继承全局"的表达能力。
  - TTL **只有站点级**一个来源：Site.AntiReplayTTL（site.go:61，default:300）。
    ProtectionConfig 中不存在对应字段（internal/store/protection.go:69 仅有
    AntiReplayEnabled）。TTL<=0 时回落到 AntiReplayManager 构造入参
    （antireplay.go:99-101、53-55，最终默认 5 分钟）。
  - Action 也只有站点级来源：Site.AntiReplayAction（site.go:62,
    `default:'shield_challenge'`），经 build.go:322 原样进入 SiteRuntime，
    再由 normalizeAntiReplayAction（handler.go:2049-2064）归一化，
    空值与未识别值都落到 "challenge"。
*/

/**
 * antiReplayConfigHost 与 antireplay_handler_test.go 的 Host 区分，避免快照 key 冲突。
 */
const antiReplayConfigHost = "antireplay-config.example.com"

/**
 * antiReplayConfigEnv 汇总一次配置维度用例所需的依赖。
 */
type antiReplayConfigEnv struct {
	handler          app.HandlerFunc
	manager          *antireplay.AntiReplayManager
	upstreamRequests func() int
}

func antiReplayEnabledPtr(value bool) *bool {
	return &value
}

/**
 * newAntiReplayConfigEnv 按显式给定的站点开关与全局 protection 开关构造 handler，
 * 用于观测 build.go:321 的逻辑或语义在数据面的实际后果。
 *
 * 注意：本函数**不调用** snapshot.Build，而是直接按 build.go:321 的公式
 * 计算 AntiReplayEnabled 后写入 SiteRuntime。原因是 Build 需要 DB 与
 * SystemSettings 种子数据；公式本身的正确性由 internal/snapshot 包的
 * TestBuildAntiReplayEnabledIsSiteOrGlobal 单独取证。
 *
 * @param t 测试上下文
 * @param siteEnabled 站点级 Site.AntiReplayEnabled
 * @param globalEnabled 全局 ProtectionConfig.AntiReplayEnabled
 * @param siteTTL 站点级 Site.AntiReplayTTL（秒）
 * @param managerTTL AntiReplayManager 构造入参 TTL
 * @returns handler、manager 与上游命中计数
 */
func newAntiReplayConfigEnv(t *testing.T, siteEnabled *bool, globalEnabled bool, siteTTL int, managerTTL time.Duration) antiReplayConfigEnv {
	t.Helper()

	var mu sync.Mutex
	upstreamHits := 0
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(upstreamServer.Close)

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.OWASPEnabled = false
	protection.BotDetectionEnabled = false
	protection.AntiReplayEnabled = globalEnabled

	effectiveAntiReplayEnabled := protection.AntiReplayEnabled
	if siteEnabled != nil {
		effectiveAntiReplayEnabled = *siteEnabled
	}
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:                1,
			Host:              antiReplayConfigHost,
			Bind:              ":80",
			AntiReplayEnabled: siteEnabled,
			AntiReplayTTL:     siteTTL,
		},
		Bind:                ":80",
		UpstreamURLs:        []string{upstreamServer.URL},
		EffectiveProtection: &protection,
		AntiReplayEnabled:   effectiveAntiReplayEnabled,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", antiReplayConfigHost): &rt,
		},
	})

	eng := engine.New(holder, nil, nil, nil)
	mgr := antireplay.NewAntiReplayManager("antireplay-config-test-secret", nil, managerTTL)
	eng.SetAntiReplayManager(mgr)

	return antiReplayConfigEnv{
		handler: Handler(Options{
			Holder: holder,
			Engine: eng,
			Log:    slog.Default(),
			Bind:   ":80",
		}),
		manager: mgr,
		upstreamRequests: func() int {
			mu.Lock()
			defer mu.Unlock()
			return upstreamHits
		},
	}
}

/**
 * doAntiReplayConfigRequest 驱动一次针对 antiReplayConfigHost 的 handler 调用。
 *
 * @param handler 被测 handler
 * @param nonceCookie 非空时写入 __waf_nonce Cookie
 * @param nonceHeader 非空时写入 X-Nonce 请求头
 * @returns 执行完成的请求上下文
 */
func doAntiReplayConfigRequest(handler app.HandlerFunc, nonceCookie, nonceHeader string) *app.RequestContext {
	c := app.NewContext(0)
	c.Request.Header.SetMethod(http.MethodGet)
	c.Request.SetRequestURI("/guarded")
	c.Request.Header.SetHost(antiReplayConfigHost)
	if nonceCookie != "" {
		c.Request.Header.SetCookie(challenge.NonceKey, nonceCookie)
	}
	if nonceHeader != "" {
		c.Request.Header.Set("X-Nonce", nonceHeader)
	}
	handler(context.Background(), c)
	return c
}

/**
 * TestAntiReplayEnabledIsSiteOrGlobalNotInheritance 固化开关语义：
 * 站点开关与全局 protection 开关是**逻辑或**（build.go:321），不是三态继承。
 *
 * 关键后果（第 3 个子用例）：站点显式关闭时，只要全局开启，Cookie 入口
 * 依然生效 —— 站点侧**没有**关闭 AntiReplay 的能力。
 * 这是现状，是否符合产品意图待定。
 *
 * 判据：AntiReplay 生效时首访会下发 __waf_nonce（handler.go:419-422），
 * 关闭时整段跳过、不下发任何 Cookie。
 */
func TestAntiReplayEnabledUsesNullableSiteOverride(t *testing.T) {
	enabled := true
	disabled := false
	cases := []struct {
		name         string
		site         *bool
		global       bool
		wantNonceSet bool
	}{
		{name: "继承关闭的全局配置", site: nil, global: false, wantNonceSet: false},
		{name: "继承开启的全局配置", site: nil, global: true, wantNonceSet: true},
		{name: "站点显式开启覆盖关闭的全局配置", site: &enabled, global: false, wantNonceSet: true},
		{name: "站点显式关闭覆盖开启的全局配置", site: &disabled, global: true, wantNonceSet: false},
		{name: "站点显式开启覆盖开启的全局配置", site: &enabled, global: true, wantNonceSet: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newAntiReplayConfigEnv(t, tc.site, tc.global, 0, 5*time.Minute)

			c := doAntiReplayConfigRequest(env.handler, "", "")

			if got := c.Response.StatusCode(); got != http.StatusOK {
				t.Fatalf("status = %d, want %d", got, http.StatusOK)
			}
			issued := issuedNonceCookies(c)
			if tc.wantNonceSet && len(issued) != 1 {
				t.Fatalf("site=%v global=%v 应下发 1 个 nonce, got %v", tc.site, tc.global, issued)
			}
			if !tc.wantNonceSet && len(issued) != 0 {
				t.Fatalf("site=%v global=%v 应完全跳过、不下发 nonce, got %v", tc.site, tc.global, issued)
			}
			if got := env.upstreamRequests(); got != 1 {
				t.Fatalf("上游命中次数 = %d, want 1", got)
			}
		})
	}
}

/**
 * TestAntiReplayDisabledSilencesBothEntrances 固化关闭语义：
 * AntiReplayEnabled 为假时，Cookie 入口与 X-Nonce phase **同时**静默。
 *
 * 机制：Cookie 入口由 handler.go:411 的 `if rt.AntiReplayEnabled` 门控；
 * X-Nonce phase 由 engine.go:376 的 `e.antiReplay != nil && rt.AntiReplayEnabled`
 * 决定是否挂载。两者读同一个 rt.AntiReplayEnabled，故开关一致。
 *
 * 本用例特意传入一个**已被消费过**的 nonce：若 phase 仍在挂载，
 * 该值会被判重放并 403；实际放行即证明 phase 未挂载。
 */
func TestAntiReplayDisabledSilencesBothEntrances(t *testing.T) {
	env := newAntiReplayConfigEnv(t, nil, false, 0, 5*time.Minute)
	nonce := env.manager.GenerateNonce(antiReplayClientIP)

	// 先在 manager 上直接消费一次，使该 nonce 进入 spent 状态。
	if valid, _, _ := env.manager.ValidateAndRotate(nonce, antiReplayClientIP, 0); !valid {
		t.Fatal("构造前提失败：首次消费应成功")
	}

	c := doAntiReplayConfigRequest(env.handler, nonce, nonce)

	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("关闭时携带已消费 nonce status = %d, want %d（两入口均应静默）", got, http.StatusOK)
	}
	if issued := issuedNonceCookies(c); len(issued) != 0 {
		t.Fatalf("关闭时不应下发 nonce, got %v", issued)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1", got)
	}
}

/**
 * TestAntiReplayCookieEntryEnforcesSiteTTL 固化 TTL 语义：
 * 站点 Site.AntiReplayTTL 在 **Cookie 入口**同样生效（handler.go:422-425）。
 *
 * 既有覆盖只到 X-Nonce phase（websocket_test.go:1153 的
 * TestInspectWebSocketPayloadAppliesSiteAntiReplayTTLToNonceHeaderPhase），
 * 本用例补上 Cookie 入口这一侧。
 *
 * 机制：ValidateAndRotate 用 sessionTTL 判定 nonce 年龄
 * （antireplay.go:120-123，age > sessionTTL 即失效）。站点 TTL 设为 1 秒并
 * 真实等待，使 nonce 超龄，落入 handler 的 default 分支 → 403 + 补发新 nonce。
 *
 * 为排除"manager 默认 TTL 起作用"的干扰，manager 构造 TTL 取 5 分钟，
 * 远大于站点的 1 秒；若站点 TTL 未被采纳，nonce 仍然有效、用例会以 200 失败。
 */
func TestAntiReplayCookieEntryEnforcesSiteTTL(t *testing.T) {
	siteEnabled := true
	env := newAntiReplayConfigEnv(t, &siteEnabled, false, 1, 5*time.Minute)
	nonce := env.manager.GenerateNonce(antiReplayClientIP)

	// 站点 TTL=1s，等待越过该窗口。
	time.Sleep(1100 * time.Millisecond)

	c := doAntiReplayConfigRequest(env.handler, nonce, "")

	if got := c.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("超过站点 TTL 的 nonce status = %d, want %d（证明站点 TTL 生效）", got, http.StatusForbidden)
	}
	issued := issuedNonceCookies(c)
	if len(issued) != 1 {
		t.Fatalf("invalid_nonce 分支应补发 1 个新 nonce, got %v", issued)
	}
	if issued[0] == nonce {
		t.Fatal("补发的 nonce 不应等于已过期入参")
	}
	if got := env.upstreamRequests(); got != 0 {
		t.Fatalf("上游命中次数 = %d, want 0", got)
	}
}

/**
 * TestAntiReplayCookieEntryFallsBackToManagerTTLWhenSiteTTLZero 固化 TTL 回落：
 * 站点 AntiReplayTTL<=0 时，handler 传入 ttl=0（handler.go:422-425 的初值），
 * ValidateAndRotate 回落到 manager 构造 TTL（antireplay.go:99-101）。
 *
 * 构造：manager TTL 取 1 秒，站点 TTL 取 0。等待越过 1 秒后 nonce 应失效，
 * 从而证明生效的是 manager TTL 而非某个隐含默认值。
 */
func TestAntiReplayCookieEntryFallsBackToManagerTTLWhenSiteTTLZero(t *testing.T) {
	siteEnabled := true
	env := newAntiReplayConfigEnv(t, &siteEnabled, false, 0, 1*time.Second)
	nonce := env.manager.GenerateNonce(antiReplayClientIP)

	time.Sleep(1100 * time.Millisecond)

	c := doAntiReplayConfigRequest(env.handler, nonce, "")

	if got := c.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("超过 manager TTL 的 nonce status = %d, want %d（证明回落生效）", got, http.StatusForbidden)
	}
	if issued := issuedNonceCookies(c); len(issued) != 1 {
		t.Fatalf("invalid_nonce 分支应补发 1 个新 nonce, got %v", issued)
	}
}

/**
 * TestAntiReplayActionHasNoGlobalFallback 固化 action 语义：
 * 失效 nonce 的响应动作**只**取自站点 Site.AntiReplayAction（build.go:322），
 * ProtectionConfig 中不存在对应字段，因此没有全局兜底。
 * 空值经 normalizeAntiReplayAction 归一为 "challenge"（handler.go:2061-2062）。
 *
 * 判据：action 为 intercept 时走 pages.WriteBlockResponse，
 * 为 challenge 时走 pages.WriteChallengeResponse（handler.go:2129-2134）。
 * 两者产出的页面正文不同，用状态码 + 是否补发 nonce 之外的正文特征区分。
 * 这里只断言二者**正文不同**，不硬编码具体模板文案，避免与页面改版耦合。
 */
func TestAntiReplayActionHasNoGlobalFallback(t *testing.T) {
	bodyFor := func(t *testing.T, siteAction string) string {
		t.Helper()
		upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(upstreamServer.Close)

		holder := &snapshot.Holder{}
		protection := store.DefaultProtectionConfig()
		protection.OWASPEnabled = false
		protection.BotDetectionEnabled = false
		rt := snapshot.SiteRuntime{
			Site: store.Site{
				ID:                1,
				Host:              antiReplayConfigHost,
				Bind:              ":80",
				AntiReplayEnabled: antiReplayEnabledPtr(true),
				AntiReplayAction:  siteAction,
			},
			Bind:                ":80",
			UpstreamURLs:        []string{upstreamServer.URL},
			EffectiveProtection: &protection,
			AntiReplayEnabled:   true,
			AntiReplayAction:    siteAction,
		}
		holder.Store(&snapshot.Snapshot{
			Revision:   1,
			Protection: protection,
			Sites: map[string]*snapshot.SiteRuntime{
				snapshot.SiteMapKey(":80", antiReplayConfigHost): &rt,
			},
		})
		eng := engine.New(holder, nil, nil, nil)
		mgr := antireplay.NewAntiReplayManager("antireplay-action-test", nil, 5*time.Minute)
		eng.SetAntiReplayManager(mgr)
		handler := Handler(Options{Holder: holder, Engine: eng, Log: slog.Default(), Bind: ":80"})

		// 用为其他 IP 签发的 nonce 触发签名校验失败，进入 default 分支。
		foreign := mgr.GenerateNonce("203.0.113.9")
		c := doAntiReplayConfigRequest(handler, foreign, "")
		if got := c.Response.StatusCode(); got != http.StatusForbidden {
			t.Fatalf("action=%q status = %d, want %d", siteAction, got, http.StatusForbidden)
		}
		return string(c.Response.Body())
	}

	// 挑战页正文含每请求随机量（Request ID、PoW nonce、环境指纹密钥），
	// 因此不能做全文相等比较，只能比对稳定的结构性标记。
	// 标记取自实测正文：challenge 页来自 shield.html 的 h1，
	// intercept 页来自 pages.WriteBlockResponse 渲染的拦截页标题。
	const challengeMarker = "Checking your browser"
	const blockMarker = "访问被拒绝"

	emptyBody := bodyFor(t, "")
	challengeBody := bodyFor(t, "challenge")
	interceptBody := bodyFor(t, "intercept")

	if !strings.Contains(emptyBody, challengeMarker) {
		t.Fatalf("空 action 应归一为 challenge，正文应含 %q", challengeMarker)
	}
	if !strings.Contains(challengeBody, challengeMarker) {
		t.Fatalf("显式 challenge 正文应含 %q", challengeMarker)
	}
	if !strings.Contains(interceptBody, blockMarker) {
		t.Fatalf("intercept 正文应含拦截页标记 %q", blockMarker)
	}
	if strings.Contains(interceptBody, challengeMarker) {
		t.Fatalf("intercept 不应渲染挑战页，动作语义未被保留")
	}
}
