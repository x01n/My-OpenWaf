package dataplane

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	rueidis "github.com/redis/rueidis"

	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/challenge"
)

/*
本文件为 AntiReplay 在数据面 handler 层的**现状固化**回归测试，不修改任何运行时行为。

取证结论（均来自源码，非推断）：

  - Cookie 入口位于 internal/dataplane/handler.go:412-509，受 rt.AntiReplayEnabled 控制，
    在 WAF pipeline 之前执行。Cookie 名取自常量 challenge.NonceKey，
    其值在 internal/waf/challenge/token.go:23 定义为 "__waf_nonce"。
    写入 Cookie 由 setNonceCookie（internal/dataplane/helpers.go:52-59）以
    Response.Header.Add("Set-Cookie", ...) 完成，属性固定为
    Path=/; HttpOnly; SameSite=Strict; Max-Age=snapshot.OneDaySeconds，
    仅当 rt.Site.TLSEnabled 为真时追加 Secure。
  - 路径排除逻辑：handler.go:414-415 对 path 取 toLowerASCII 后，
    前缀 "/__owaf/" 或 isStaticAsset(lp)（helpers.go:36-50，按静态扩展名与
    /static/ /assets/ /public/ /favicon 前缀判定）时整段跳过 nonce 检查。
  - Pipeline 入口是独立的第二个入口：internal/core/rules/phases.go:1093-1124，
    读请求头 "x-nonce"（phases.go:1098，注释写作 X-Nonce），仅在
    engine.go:376-377 即 e.antiReplay != nil && rt.AntiReplayEnabled 时挂载。
  - 共享消费记录：两入口都调用同一个 AntiReplayManager.ValidateAndRotate
    （internal/waf/antireplay/antireplay.go:98-171），因此共享 spentUntil /
    idemRotated 状态。
  - Redis 分支并非直接 SET NX EX 调用，而是 redis.Eval 执行 redisNonceLua
    脚本（antireplay.go:34-45、141），脚本内部用 SET ... NX EX 抢占 spentKey；
    仅当 m.redisClient() == nil 时才走本地回退 validateAndRotateLocal
    （antireplay.go:170、173-205）。
  - 幂等窗口常量为 antiReplayIdemSeconds = 8（antireplay.go:32），本地与 Redis
    分支共用该值。
  - nonce 仅绑定 clientIP：GenerateNonce 的 HMAC payload 为
    clientIP + 8 字节时间戳 + 16 字节随机数（antireplay.go:84-90），
    不含站点、Host、UA、路径。

以下每个用例断言的都是**当前真实行为**，是否符合产品意图待定。
*/

/**
 * antiReplayTestHost 是本文件所有用例共用的站点 Host，与其他测试文件的
 * Host 保持区分，避免快照 key 冲突。
 */
const antiReplayTestHost = "antireplay-handler.example.com"

/**
 * antiReplayHandlerEnv 汇总一次 handler 驱动所需的全部依赖。
 */
type antiReplayHandlerEnv struct {
	handler          app.HandlerFunc
	manager          *antireplay.AntiReplayManager
	upstreamRequests func() int
}

/**
 * newAntiReplayHandlerEnv 复用本包既有测试脚手架模式（httptest 上游 +
 * snapshot.Holder + Handler(Options{...})）构造一个开启 AntiReplay 的站点。
 *
 * 关闭 OWASP 与 Bot 检测，使响应状态只由 AntiReplay 语义决定；不注入 Writer
 * 与 Metrics，因此 handler 中的 opts.Writer / opts.Metrics 分支为 nil-safe 路径。
 *
 * @param t 测试上下文
 * @param siteAntiReplayTTL 站点级 AntiReplayTTL（秒），0 表示沿用管理器默认 TTL
 * @returns 构造好的 handler、底层 AntiReplayManager，以及上游命中计数读取函数
 */
func newAntiReplayHandlerEnv(t *testing.T, siteAntiReplayTTL int) antiReplayHandlerEnv {
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
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:            1,
			Host:          antiReplayTestHost,
			Bind:          ":80",
			AntiReplayTTL: siteAntiReplayTTL,
		},
		Bind:                ":80",
		UpstreamURLs:        []string{upstreamServer.URL},
		EffectiveProtection: &protection,
		AntiReplayEnabled:   true,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", antiReplayTestHost): &rt,
		},
	})

	eng := engine.New(holder, nil, nil, nil)
	mgr := antireplay.NewAntiReplayManager("antireplay-handler-test-secret", nil, 5*time.Minute)
	eng.SetAntiReplayManager(mgr)

	return antiReplayHandlerEnv{
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
 * antiReplayClientIP 是 app.NewContext(0) 下 security.ResolveClientIP 的解析结果。
 * 本包既有测试（handler_test.go:536-538）已确认无远端地址时解析为 0.0.0.0，
 * nonce 的 HMAC 绑定必须使用该值，否则签名校验必然失败。
 */
const antiReplayClientIP = "0.0.0.0"

/**
 * doAntiReplayRequest 驱动一次 handler 调用。
 *
 * @param handler 被测 handler
 * @param path 请求路径
 * @param nonceCookie 非空时写入 __waf_nonce Cookie
 * @param nonceHeader 非空时写入 X-Nonce 请求头
 * @returns 执行完成的请求上下文
 */
func doAntiReplayRequest(handler app.HandlerFunc, path, nonceCookie, nonceHeader string) *app.RequestContext {
	c := app.NewContext(0)
	c.Request.Header.SetMethod(http.MethodGet)
	c.Request.SetRequestURI(path)
	c.Request.Header.SetHost(antiReplayTestHost)
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
 * issuedNonceCookies 提取响应中所有 __waf_nonce 的 Set-Cookie 取值部分。
 * setNonceCookie 用 Header.Add 而非 Set，故必须 VisitAll 遍历重复头。
 *
 * @param c 已执行的请求上下文
 * @returns 按出现顺序排列的 nonce 值列表
 */
func issuedNonceCookies(c *app.RequestContext) []string {
	var values []string
	prefix := challenge.NonceKey + "="
	c.Response.Header.VisitAll(func(key, value []byte) {
		if !strings.EqualFold(string(key), "Set-Cookie") {
			return
		}
		raw := string(value)
		if !strings.HasPrefix(raw, prefix) {
			return
		}
		values = append(values, strings.TrimPrefix(strings.SplitN(raw, ";", 2)[0], prefix))
	})
	return values
}

/**
 * TestAntiReplayHandlerFirstVisitIssuesNonceAndPasses 固化语义点 1：
 * 首次访问不带 __waf_nonce Cookie 时，handler 签发新 nonce 并**放行**到上游。
 *
 * 现状：缺失 Cookie 不是拒绝条件，而是初始化条件（handler.go:419-422），
 * 即 fail-open。这是现状，是否符合产品意图待定 —— 攻击者只要丢弃 Cookie
 * 即可无条件获得一次放行。
 */
func TestAntiReplayHandlerFirstVisitIssuesNonceAndPasses(t *testing.T) {
	env := newAntiReplayHandlerEnv(t, 0)

	c := doAntiReplayRequest(env.handler, "/guarded", "", "")

	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("首次访问 status = %d, want %d（现状为放行）", got, http.StatusOK)
	}
	issued := issuedNonceCookies(c)
	if len(issued) != 1 {
		t.Fatalf("首次访问下发 nonce cookie 数量 = %d, want 1: %v", len(issued), issued)
	}
	if issued[0] == "" {
		t.Fatal("首次访问下发了空 nonce")
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1（证明请求确实被放行）", got)
	}

	// Cookie 属性固定为 HttpOnly + SameSite=Strict + Path=/；TLSEnabled 为 false 时无 Secure。
	rawCookie := ""
	c.Response.Header.VisitAll(func(key, value []byte) {
		if strings.EqualFold(string(key), "Set-Cookie") && strings.HasPrefix(string(value), challenge.NonceKey+"=") {
			rawCookie = string(value)
		}
	})
	for _, attr := range []string{"Path=/", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(rawCookie, attr) {
			t.Fatalf("nonce cookie 缺少属性 %q: %q", attr, rawCookie)
		}
	}
	if strings.Contains(rawCookie, "Secure") {
		t.Fatalf("站点 TLSEnabled=false 时不应出现 Secure: %q", rawCookie)
	}
}

/**
 * TestAntiReplayHandlerValidCookieRotatesToNewValue 固化语义点 2：
 * 携带合法 Cookie 时请求放行，且响应中的新 nonce 与旧值不同（轮换生效）。
 */
func TestAntiReplayHandlerValidCookieRotatesToNewValue(t *testing.T) {
	env := newAntiReplayHandlerEnv(t, 0)
	original := env.manager.GenerateNonce(antiReplayClientIP)

	c := doAntiReplayRequest(env.handler, "/guarded", original, "")

	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("合法 nonce status = %d, want %d", got, http.StatusOK)
	}
	issued := issuedNonceCookies(c)
	if len(issued) != 1 {
		t.Fatalf("轮换下发 cookie 数量 = %d, want 1: %v", len(issued), issued)
	}
	if issued[0] == original {
		t.Fatal("轮换后的 nonce 与旧值相同，未发生轮换")
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1", got)
	}
}

/**
 * TestAntiReplayHandlerRepeatedCookieWithinIdemWindowReplaysSameRotation
 * 固化语义点 3 的第一半：同一 Cookie 值在 8 秒幂等窗口（antiReplayIdemSeconds）
 * 内重复提交时，**两次都放行**，且第二次返回与第一次完全相同的轮换值。
 *
 * 现状：validateAndRotateLocal（antireplay.go:192-194）先查 idemRotated，
 * 命中即返回 (true, false, 缓存值)，不判定重放。因此"同一 Cookie 提交两次
 * 只有一次成功"在窗口内**不成立**。这是现状，是否符合产品意图待定 ——
 * 该窗口为并发/重试场景而设，但也给了攻击者 8 秒的自由重放期。
 */
func TestAntiReplayHandlerRepeatedCookieWithinIdemWindowReplaysSameRotation(t *testing.T) {
	env := newAntiReplayHandlerEnv(t, 0)
	original := env.manager.GenerateNonce(antiReplayClientIP)

	first := doAntiReplayRequest(env.handler, "/guarded", original, "")
	second := doAntiReplayRequest(env.handler, "/guarded", original, "")

	if got := first.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("第一次提交 status = %d, want %d", got, http.StatusOK)
	}
	if got := second.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("窗口内第二次提交 status = %d, want %d（现状为幂等放行，非拦截）", got, http.StatusOK)
	}

	firstIssued := issuedNonceCookies(first)
	secondIssued := issuedNonceCookies(second)
	if len(firstIssued) != 1 || len(secondIssued) != 1 {
		t.Fatalf("下发 cookie 数量异常: first=%v second=%v", firstIssued, secondIssued)
	}
	if firstIssued[0] != secondIssued[0] {
		t.Fatalf("窗口内两次轮换值不一致: first=%q second=%q（现状应为同值幂等）", firstIssued[0], secondIssued[0])
	}
	if got := env.upstreamRequests(); got != 2 {
		t.Fatalf("上游命中次数 = %d, want 2（两次均放行）", got)
	}
}

/**
 * TestAntiReplayHandlerRepeatedCookieBeyondIdemWindowIsIntercepted
 * 固化语义点 3 的第二半：幂等窗口过期后，同一 Cookie 值再次提交被判定为
 * 重放并以 403 拦截，且拦截响应**不下发**新 nonce。
 *
 * 拦截分支为 handler.go:433-466（RuleIDStr "antireplay:nonce_reuse"，
 * Phase "anti_replay"），直接 WriteBlockResponse 后 return，不调用 setNonceCookie。
 *
 * 用例需真实等待超过 antiReplayIdemSeconds = 8 秒：该常量未导出且无注入点，
 * 无法在不改动非测试文件的前提下缩短。
 */
func TestAntiReplayHandlerRepeatedCookieBeyondIdemWindowIsIntercepted(t *testing.T) {
	env := newAntiReplayHandlerEnv(t, 0)
	original := env.manager.GenerateNonce(antiReplayClientIP)

	first := doAntiReplayRequest(env.handler, "/guarded", original, "")
	if got := first.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("第一次提交 status = %d, want %d", got, http.StatusOK)
	}

	// 幂等窗口固定 8 秒，留出余量以避免调度抖动导致的临界抖动。
	time.Sleep(8300 * time.Millisecond)

	second := doAntiReplayRequest(env.handler, "/guarded", original, "")
	if got := second.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("窗口外重放 status = %d, want %d", got, http.StatusForbidden)
	}
	if issued := issuedNonceCookies(second); len(issued) != 0 {
		t.Fatalf("重放拦截响应不应下发新 nonce, got %v", issued)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1（重放请求未到达上游）", got)
	}
}

/**
 * TestAntiReplayHandlerConcurrentSameNonceAllPassWithSingleRotation
 * 固化语义点 4：N 个 goroutine 并发提交同一 nonce 时，**全部放行**，
 * 且所有响应共享同一个轮换值。
 *
 * 现状：并发不会被收敛为"只放行一次"。首个抢到 localMu 的请求写入
 * idemRotated（antireplay.go:203），其余请求命中幂等缓存后同样得到
 * (true, false, 同一 newNonce)。这是现状，是否符合产品意图待定 ——
 * 若期望"仅一次成功"，当前实现不满足。
 *
 * 本用例不触碰 DB，故无需 SQLite；共享状态仅为进程内的 AntiReplayManager。
 */
func TestAntiReplayHandlerConcurrentSameNonceAllPassWithSingleRotation(t *testing.T) {
	env := newAntiReplayHandlerEnv(t, 0)
	original := env.manager.GenerateNonce(antiReplayClientIP)

	const concurrency = 16
	statuses := make([]int, concurrency)
	rotated := make([]string, concurrency)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			c := doAntiReplayRequest(env.handler, "/guarded", original, "")
			statuses[idx] = c.Response.StatusCode()
			if issued := issuedNonceCookies(c); len(issued) == 1 {
				rotated[idx] = issued[0]
			}
		}(i)
	}
	close(start)
	wg.Wait()

	passed := 0
	distinct := make(map[string]struct{})
	for i := 0; i < concurrency; i++ {
		if statuses[i] == http.StatusOK {
			passed++
		}
		if rotated[i] == "" {
			t.Fatalf("第 %d 个并发请求未获得轮换 nonce, status = %d", i, statuses[i])
		}
		distinct[rotated[i]] = struct{}{}
	}
	if passed != concurrency {
		t.Fatalf("并发放行数 = %d, want %d（现状为全部放行）", passed, concurrency)
	}
	if len(distinct) != 1 {
		t.Fatalf("并发轮换值种类 = %d, want 1（幂等窗口应收敛为同值）", len(distinct))
	}
	if got := env.upstreamRequests(); got != concurrency {
		t.Fatalf("上游命中次数 = %d, want %d", got, concurrency)
	}
}

/**
 * TestAntiReplayHandlerCookieAndHeaderShareConsumptionRecord
 * 固化语义点 5：Cookie 与 X-Nonce 携带**同一值**时请求整体放行，
 * 证明两入口共享同一份消费记录，且 Cookie 入口的消费不会让随后的
 * pipeline 入口把同值判为重放。
 *
 * 机制：Cookie 入口先执行并写入 idemRotated（antireplay.go:203），
 * pipeline 入口随后对同值再次调用 ValidateAndRotate 时命中幂等缓存
 * （antireplay.go:192-194）返回 valid=true，因此未被判重放。
 * 若两入口各自维护独立状态，第二次校验会落入 spentUntil 分支返回
 * isReplay=true，phase 将以 403 拦截（phases.go:1112-1122）。
 *
 * 现状：同值双入口"被重复消费但都放行"，实际保护依赖 8 秒幂等窗口而非
 * 入口间的显式协调。这是现状，是否符合产品意图待定。
 */
func TestAntiReplayHandlerCookieAndHeaderShareConsumptionRecord(t *testing.T) {
	env := newAntiReplayHandlerEnv(t, 0)
	shared := env.manager.GenerateNonce(antiReplayClientIP)

	c := doAntiReplayRequest(env.handler, "/guarded", shared, shared)

	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("Cookie 与 X-Nonce 同值 status = %d, want %d（共享幂等记录故放行）", got, http.StatusOK)
	}
	if issued := issuedNonceCookies(c); len(issued) != 1 {
		t.Fatalf("下发 cookie 数量 = %d, want 1: %v", len(issued), issued)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1", got)
	}
}

/**
 * TestAntiReplayHandlerHeaderRotationIsDiscarded 固化 X-Nonce 入口的交付缺口：
 * 当 Cookie 与 X-Nonce 携带**不同的**合法 nonce 时请求放行，但响应中只有
 * 一个 Set-Cookie，即 Cookie 入口轮换出的值；pipeline 入口为 X-Nonce
 * 轮换出的新值被丢弃，客户端无法获知。
 *
 * 机制：phases.go:1111 以 `valid, isReplay, _ :=` 显式丢弃第三个返回值，
 * 没有任何写回响应头或上下文的路径。
 * 后果：X-Nonce 客户端每次都必须自行签发新 nonce，服务端轮换形同虚设。
 * 这是现状，是否符合产品意图待定。
 */
func TestAntiReplayHandlerHeaderRotationIsDiscarded(t *testing.T) {
	env := newAntiReplayHandlerEnv(t, 0)
	cookieNonce := env.manager.GenerateNonce(antiReplayClientIP)
	headerNonce := env.manager.GenerateNonce(antiReplayClientIP)
	if cookieNonce == headerNonce {
		t.Fatal("构造前提失败：两个 nonce 必须不同")
	}

	c := doAntiReplayRequest(env.handler, "/guarded", cookieNonce, headerNonce)

	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("双入口不同合法 nonce status = %d, want %d", got, http.StatusOK)
	}
	issued := issuedNonceCookies(c)
	if len(issued) != 1 {
		t.Fatalf("下发 nonce 数量 = %d, want 1（X-Nonce 轮换值无交付机制）: %v", len(issued), issued)
	}
	if issued[0] == cookieNonce || issued[0] == headerNonce {
		t.Fatalf("下发值不应等于任一入参 nonce: issued=%q cookie=%q header=%q", issued[0], cookieNonce, headerNonce)
	}
}

/**
 * TestAntiReplayHandlerMissingHeaderNonceSkipsPipelinePhase 固化 X-Nonce 缺失语义：
 * 不带 X-Nonce 时 pipeline 的 anti_replay phase 直接 Pass（phases.go:1099-1102），
 * 请求放行。与 Cookie 入口缺失时"签发后放行"同为 fail-open，但两者的失败
 * 语义并不一致：Cookie 入口缺失会**初始化**状态，X-Nonce 缺失则是**完全跳过**。
 * 这是现状，是否符合产品意图待定。
 */
func TestAntiReplayHandlerMissingHeaderNonceSkipsPipelinePhase(t *testing.T) {
	env := newAntiReplayHandlerEnv(t, 0)
	cookieNonce := env.manager.GenerateNonce(antiReplayClientIP)

	c := doAntiReplayRequest(env.handler, "/guarded", cookieNonce, "")

	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("缺失 X-Nonce status = %d, want %d", got, http.StatusOK)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1", got)
	}
}

/**
 * TestAntiReplayHandlerNonceBoundOnlyToClientIP 固化语义：nonce 的 HMAC 只绑定
 * clientIP。为其他 IP 签发的 nonce 在本请求（clientIP=0.0.0.0）下签名校验失败，
 * 落入 handler.go:467-504 的 default 分支：先补发一个新 nonce，再按
 * normalizeAntiReplayAction(rt.AntiReplayAction) 渲染动作响应（默认 challenge，
 * 状态码 403）。
 *
 * 反面含义同样是现状：由于绑定项**只有** clientIP，同一 IP 在站点 A 取得的
 * nonce 可在站点 B 通过签名校验（payload 不含 SiteID/Host，antireplay.go:84-90）。
 * 这是现状，是否符合产品意图待定。
 */
func TestAntiReplayHandlerNonceBoundOnlyToClientIP(t *testing.T) {
	env := newAntiReplayHandlerEnv(t, 0)
	foreignNonce := env.manager.GenerateNonce("203.0.113.9")

	c := doAntiReplayRequest(env.handler, "/guarded", foreignNonce, "")

	if got := c.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("跨 IP nonce status = %d, want %d", got, http.StatusForbidden)
	}
	issued := issuedNonceCookies(c)
	if len(issued) != 1 {
		t.Fatalf("invalid_nonce 分支应补发 1 个新 nonce, got %v", issued)
	}
	if issued[0] == foreignNonce {
		t.Fatal("补发的 nonce 不应等于无效入参")
	}
	if got := env.upstreamRequests(); got != 0 {
		t.Fatalf("上游命中次数 = %d, want 0", got)
	}
}

/**
 * TestAntiReplayHandlerSkipsStaticAssetAndOWAFPaths 固化路径排除语义：
 * "/__owaf/" 前缀与 isStaticAsset 命中的路径整段跳过 nonce 检查，
 * 既不校验也不下发 Cookie（handler.go:414-416）。
 */
func TestAntiReplayHandlerSkipsStaticAssetAndOWAFPaths(t *testing.T) {
	env := newAntiReplayHandlerEnv(t, 0)

	// isStaticAsset 同时按扩展名与目录前缀判定，两类各取一个代表。
	for _, path := range []string{"/assets/app.css", "/main.js", "/favicon.ico"} {
		c := doAntiReplayRequest(env.handler, path, "", "")
		if got := c.Response.StatusCode(); got != http.StatusOK {
			t.Fatalf("静态路径 %s status = %d, want %d", path, got, http.StatusOK)
		}
		if issued := issuedNonceCookies(c); len(issued) != 0 {
			t.Fatalf("静态路径 %s 不应下发 nonce, got %v", path, issued)
		}
	}
}

/**
 * TestAntiReplayHandlerRedisFailureIsFailClosedWhileMissingCookieStaysFailOpen
 * 固化语义点 6：Redis 配置但不可用时，**已携带 Cookie** 的请求被 403 拦截
 * （fail-closed），而**未携带 Cookie** 的请求仍然放行（fail-open）。
 *
 * 机制：ValidateAndRotate 在 m.redisClient() != nil 时只走 Redis 分支，
 * Eval 出错即返回 (false, true, "")（antireplay.go:142-144），
 * 不回退到 validateAndRotateLocal —— 本地回退仅在 redisClient() == nil
 * 时可达（antireplay.go:170）。handler 的 isReplay 分支随即以
 * "antireplay:nonce_reuse" 403 拦截。而 Cookie 为空时 handler 在
 * handler.go:419-422 就已放行，根本不会调用 ValidateAndRotate，
 * 因此 Redis 故障对该路径无影响。
 *
 * 这意味着 Redis 故障期间：老客户端全量 403，新客户端（无 Cookie）畅通，
 * 且故障被记为 nonce_reuse 重放事件而非基础设施错误。
 * 这是现状，是否符合产品意图待定。
 *
 * 注入方式：通过已导出的 AntiReplayManager.SetRedis（antireplay.go:69）注入
 * 一个指向**已关闭端口**的客户端，无需真实 Redis 服务。
 */
func TestAntiReplayHandlerRedisFailureIsFailClosedWhileMissingCookieStaysFailOpen(t *testing.T) {
	// 先占用一个端口再立即释放，得到一个大概率无人监听的地址。
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("预留端口失败: %v", err)
	}
	unreachableAddr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("释放端口失败: %v", err)
	}

	env := newAntiReplayHandlerEnv(t, 0)
	// nonce 必须在注入故障客户端之前签发：GenerateNonce 只做本地 HMAC，
	// 不触碰 Redis，因此签发顺序不影响其有效性，但可让意图更清晰。
	validNonce := env.manager.GenerateNonce(antiReplayClientIP)

	failingRedis, ferr := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:       []string{unreachableAddr},
		Dialer:            net.Dialer{Timeout: 50 * time.Millisecond},
		DisableRetry:      true,
		DisableCache:      true,
		ForceSingleClient: true,
	})
	if failingRedis == nil && ferr != nil {
		t.Fatalf("构造故障 Redis 客户端: %v", ferr)
	}
	defer failingRedis.Close()
	env.manager.SetRedis(failingRedis)

	withCookie := doAntiReplayRequest(env.handler, "/guarded", validNonce, "")
	if got := withCookie.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("Redis 故障且携带 Cookie 时 status = %d, want %d（fail-closed）", got, http.StatusForbidden)
	}
	if issued := issuedNonceCookies(withCookie); len(issued) != 0 {
		t.Fatalf("nonce_reuse 拦截分支不应下发新 nonce, got %v", issued)
	}

	withoutCookie := doAntiReplayRequest(env.handler, "/guarded", "", "")
	if got := withoutCookie.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("Redis 故障且无 Cookie 时 status = %d, want %d（fail-open 未受影响）", got, http.StatusOK)
	}
	if issued := issuedNonceCookies(withoutCookie); len(issued) != 1 {
		t.Fatalf("无 Cookie 路径应下发 1 个 nonce, got %v", issued)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1（仅无 Cookie 的请求到达上游）", got)
	}
}

/*
无法在本层单测覆盖的项：

 1. Redis 成功路径（redisNonceLua 的 SET NX EX 抢占与 idem 返回码 1/2 分支）。
    原因：ValidateAndRotate 只接受具体客户端类型（antireplay.go:20、69），
    没有接口抽象，无法注入内存假实现；redisNonceLua 依赖服务端 Lua 求值，
    也无法用协议层打桩伪造。
    需要什么才能覆盖：把 rdb 字段抽象为最小接口（仅需 Eval），或在测试中
    接入真实 Redis 实例（miniredis 不支持 Lua 的 SET ... NX EX 返回语义，
    需先核实其 Eval 兼容性再决定）。

 2. Redis 分支的跨进程重放收敛（多实例共享 spent 记录）。
    原因：同上，且需要多进程/多实例编排，超出单包单测范围。

 3. 缩短 antiReplayIdemSeconds = 8 的幂等窗口以加速用例。
    原因：该常量未导出且无注入点（antireplay.go:32）。
    现状：TestAntiReplayHandlerRepeatedCookieBeyondIdemWindowIsIntercepted
    必须真实 sleep 约 8.3 秒。
    需要什么才能覆盖得更快：把窗口做成 AntiReplayManager 的可配置字段，
    或允许注入时钟。此改动属于非测试文件，本任务范围内不做。

 4. 站点维度隔离的实证（同一 IP 的 nonce 跨站点复用）。
    原因：需要构造两个站点并跨站驱动，且断言的是"缺少绑定"这一否定事实；
    GenerateNonce 的 payload 已直接证明 payload 不含 SiteID/Host
    （antireplay.go:84-90），代码事实比行为断言更精确。
    TestAntiReplayHandlerNonceBoundOnlyToClientIP 的注释已记录该结论。
*/

/**
 * newDualAntiReplayHandlerEnv 在 newAntiReplayHandlerEnv 的基础上构造
 * AntiReplayCookieMode="dual" 的站点，其余脚手架完全一致。
 *
 * @param t 测试上下文
 * @param siteAntiReplayTTL 站点级 AntiReplayTTL（秒），0 表示沿用管理器默认 TTL
 * @returns 构造好的 handler、AntiReplayManager 与上游命中计数读取函数
 */
func newDualAntiReplayHandlerEnv(t *testing.T, siteAntiReplayTTL int) antiReplayHandlerEnv {
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
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:            1,
			Host:          antiReplayTestHost,
			Bind:          ":80",
			AntiReplayTTL: siteAntiReplayTTL,
		},
		Bind:                 ":80",
		UpstreamURLs:         []string{upstreamServer.URL},
		EffectiveProtection:  &protection,
		AntiReplayEnabled:    true,
		AntiReplayCookieMode: "dual",
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", antiReplayTestHost): &rt,
		},
	})

	eng := engine.New(holder, nil, nil, nil)
	mgr := antireplay.NewAntiReplayManager("antireplay-handler-test-secret", nil, 5*time.Minute)
	eng.SetAntiReplayManager(mgr)

	return antiReplayHandlerEnv{
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
 * doDualAntiReplayRequest 驱动一次 dual env 的 handler 调用，支持携带 C2
 * （__waf_nonce2）。
 *
 * 不设置 Accept 头，即 Accept 为空、不显式接受 text/html：按
 * clientAcceptsHTML 的判据属于非浏览器客户端，dual 不再渲染续期页。
 * 浏览器路径请使用 doDualAntiReplayBrowserRequest。
 *
 * @param handler 被测 handler
 * @param path 请求路径
 * @param nonceCookie 非空时写入 __waf_nonce Cookie
 * @param pairCookie 非空时写入 __waf_nonce2 Cookie
 * @returns 执行完成的请求上下文
 */
func doDualAntiReplayRequest(handler app.HandlerFunc, path, nonceCookie, pairCookie string) *app.RequestContext {
	c := newDualAntiReplayContext(path, nonceCookie, pairCookie)
	handler(context.Background(), c)
	return c
}

/**
 * doDualAntiReplayBrowserRequest 与 doDualAntiReplayRequest 相同，但显式发送
 * "Accept: text/html,application/xhtml+xml,..."（浏览器导航请求的典型取值），
 * 用于覆盖 dual 续期页对真实浏览器的完整流程。
 *
 * @param handler 被测 handler
 * @param path 请求路径
 * @param nonceCookie 非空时写入 __waf_nonce Cookie
 * @param pairCookie 非空时写入 __waf_nonce2 Cookie
 * @returns 执行完成的请求上下文
 */
func doDualAntiReplayBrowserRequest(handler app.HandlerFunc, path, nonceCookie, pairCookie string) *app.RequestContext {
	c := newDualAntiReplayContext(path, nonceCookie, pairCookie)
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	handler(context.Background(), c)
	return c
}

func newDualAntiReplayContext(path, nonceCookie, pairCookie string) *app.RequestContext {
	c := app.NewContext(0)
	c.Request.Header.SetMethod(http.MethodGet)
	c.Request.SetRequestURI(path)
	c.Request.Header.SetHost(antiReplayTestHost)
	if nonceCookie != "" {
		c.Request.Header.SetCookie(challenge.NonceKey, nonceCookie)
	}
	if pairCookie != "" {
		c.Request.Header.SetCookie(challenge.NoncePairKey, pairCookie)
	}
	return c
}

/**
 * TestDualFirstVisitReturns412AndIssuesNonce 验证 dual 首访（浏览器，
 * Accept 显式包含 text/html）：拿到 412 + 续期页，且响应只下发 1 个 C1，
 * 不触上游。
 */
func TestDualFirstVisitReturns412AndIssuesNonce(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)

	c := doDualAntiReplayBrowserRequest(env.handler, "/guarded", "", "")

	if got := c.Response.StatusCode(); got != http.StatusPreconditionFailed {
		t.Fatalf("dual 首访 status = %d, want %d (412)", got, http.StatusPreconditionFailed)
	}
	issued := issuedNonceCookies(c)
	if len(issued) != 1 {
		t.Fatalf("dual 首访下发 C1 数量 = %d, want 1: %v", len(issued), issued)
	}
	if got := string(c.Response.Header.Peek("X-OWAF-Probe")); got != "renew" {
		t.Fatalf("X-OWAF-Probe = %q, want %q", got, "renew")
	}
	if got := env.upstreamRequests(); got != 0 {
		t.Fatalf("dual 首访上游命中次数 = %d, want 0", got)
	}
	body := string(c.Response.Body())
	if !strings.Contains(body, "__waf_nonce2") {
		t.Fatalf("续期页缺少 __waf_nonce2 脚本内容")
	}
}

/**
 * TestDualMissingCookie2Returns412 验证 dual 下浏览器携带合法 C1 但缺失 C2：
 * 412 + 轮换后的 C1 下发，请求不触上游。
 */
func TestDualMissingCookie2Returns412(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	original := env.manager.GenerateNonce(antiReplayClientIP)

	c := doDualAntiReplayBrowserRequest(env.handler, "/guarded", original, "")

	if got := c.Response.StatusCode(); got != http.StatusPreconditionFailed {
		t.Fatalf("dual 缺 C2 status = %d, want %d (412)", got, http.StatusPreconditionFailed)
	}
	issued := issuedNonceCookies(c)
	if len(issued) != 1 {
		t.Fatalf("缺 C2 分支应轮换下发 1 个 C1, got %v", issued)
	}
	if issued[0] == original {
		t.Fatal("缺 C2 分支未轮换 C1")
	}
	if got := env.upstreamRequests(); got != 0 {
		t.Fatalf("缺 C2 请求不应触上游, got %d", got)
	}
}

/**
 * TestDualValidPairPassesAndRotates 验证 dual 下合法 C1 + 任意非空 C2：
 * 200 放行且轮换 C1，上游命中 1 次。
 */
func TestDualValidPairPassesAndRotates(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	original := env.manager.GenerateNonce(antiReplayClientIP)

	c := doDualAntiReplayRequest(env.handler, "/guarded", original, "c2.any-value")

	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("dual 合法对 status = %d, want %d", got, http.StatusOK)
	}
	issued := issuedNonceCookies(c)
	if len(issued) != 1 {
		t.Fatalf("合法对应轮换下发 1 个 C1, got %v", issued)
	}
	if issued[0] == original {
		t.Fatal("合法对未轮换 C1")
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("合法对应触上游 1 次, got %d", got)
	}
}

/**
 * TestDualReplayStill403 验证 dual 下重放语义不变：同一 C1 越过 8 秒幂等
 * 窗口后再次提交，即使携带 C2 也仍以 403 nonce_reuse 拦截。
 */
func TestDualReplayStill403(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	original := env.manager.GenerateNonce(antiReplayClientIP)

	first := doDualAntiReplayRequest(env.handler, "/guarded", original, "c2.profile")
	if got := first.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("第一次提交 status = %d, want %d", got, http.StatusOK)
	}

	// 幂等窗口固定 8 秒，留出余量以避免调度抖动。
	time.Sleep(8300 * time.Millisecond)

	second := doDualAntiReplayRequest(env.handler, "/guarded", original, "c2.profile")
	if got := second.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("dual 重放 status = %d, want %d (403)", got, http.StatusForbidden)
	}
	if issued := issuedNonceCookies(second); len(issued) != 0 {
		t.Fatalf("重放拦截不应下发新 C1, got %v", issued)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1（重放未到达上游）", got)
	}
}

/**
 * TestDualNonBrowserFirstVisitPassesWithoutRenew 验证 dual 站点对非浏览器
 * 客户端（无 Accept / 不通配 HTML）不再渲染 412 续期页：
 * 首访按 standard 语义签发 C1 后直接放行到上游，且不带 X-OWAF-Probe。
 *
 * 这是「curl、blazehttp、gotestwaf、API 客户端全部停在 412」的回归防线。
 */
func TestDualNonBrowserFirstVisitPassesWithoutRenew(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)

	c := doDualAntiReplayRequest(env.handler, "/guarded", "", "")

	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("dual 非浏览器首访 status = %d, want %d（不得为 412）", got, http.StatusOK)
	}
	if got := string(c.Response.Header.Peek("X-OWAF-Probe")); got != "" {
		t.Fatalf("非浏览器请求不应带续期页探针头, got %q", got)
	}
	issued := issuedNonceCookies(c)
	if len(issued) != 1 {
		t.Fatalf("非浏览器首访仍应下发 1 个 C1, got %v", issued)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("非浏览器首访应放行到上游 1 次, got %d", got)
	}
}

/**
 * TestDualNonBrowserWildcardAcceptPasses 覆盖 curl 的默认头形态
 * Accept 为通配符（星号斜杠星号）：通配符只表示「任何类型都接受」，
 * 不代表客户端会执行页面内联脚本，因此同样不进入续期页。
 */
func TestDualNonBrowserWildcardAcceptPasses(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)

	c := newDualAntiReplayContext("/guarded", "", "")
	c.Request.Header.Set("Accept", "*/*")
	env.handler(context.Background(), c)

	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("Accept: */* 的 dual 首访 status = %d, want %d", got, http.StatusOK)
	}
	if got := string(c.Response.Header.Peek("X-OWAF-Probe")); got != "" {
		t.Fatalf("通配符 Accept 不应触发续期页, got X-OWAF-Probe=%q", got)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("通配符 Accept 应放行到上游 1 次, got %d", got)
	}
}

/**
 * TestDualNonBrowserInvalidNonceStillBlocked 验证非浏览器放行只作用于
 * 「无 Cookie 首访」这一 fail-open 初始化路径：携带签名无效的 C1 时仍按
 * 站点配置的反重放动作处置（默认 challenge → 403），不会因为不渲染续期页
 * 就被放过。
 */
func TestDualNonBrowserInvalidNonceStillBlocked(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)

	c := doDualAntiReplayRequest(env.handler, "/guarded", "not-a-valid-nonce", "")

	if got := c.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("非法 C1 非浏览器请求 status = %d, want %d (403)", got, http.StatusForbidden)
	}
	if got := env.upstreamRequests(); got != 0 {
		t.Fatalf("非法 C1 不应触上游, got %d", got)
	}
}

/**
 * TestStandardModeUnchangedByModeField 验证新字段为空串时回落 standard：
 * 首访签发 C1 后直接 200 放行（与固化语义点 1 完全一致）。
 */
func TestStandardModeUnchangedByModeField(t *testing.T) {
	env := newAntiReplayHandlerEnv(t, 0)

	c := doAntiReplayRequest(env.handler, "/guarded", "", "")

	if got := c.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("standard 首访 status = %d, want %d", got, http.StatusOK)
	}
	issued := issuedNonceCookies(c)
	if len(issued) != 1 {
		t.Fatalf("standard 首访下发 C1 数量 = %d, want 1: %v", len(issued), issued)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("standard 首访上游命中次数 = %d, want 1", got)
	}
	if got := string(c.Response.Header.Peek("X-OWAF-Probe")); got != "" {
		t.Fatalf("standard 模式不应带 X-OWAF-Probe, got %q", got)
	}
}

/**
 * TestDualBrowserValidC2PassesAcrossRotations 覆盖「MAC 不绑定 C1」在真实
 * handler 路径上的效果：浏览器用同一枚 C2 连续通过两次续期校验（每次 C1 都
 * 被轮换成新值），两次都必须 200 并触上游。
 *
 * 若 MAC 绑定 C1，这里第一次就会退化成 412——即 dual 站点的无限续期循环。
 * 修复前后本用例是唯一会跑到「跨轮换」路径的断言。
 */
func TestDualBrowserValidC2PassesAcrossRotations(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	challenge.SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))

	// 构造浏览器会原样落位的 C2：服务端签发 -> 解封 -> 取 cookie 字段。
	payload := mustIssueC2CookieForTest(t, antiReplayClientIP)

	for round := 1; round <= 2; round++ {
		c1 := env.manager.GenerateNonce(antiReplayClientIP)
		c := doDualAntiReplayBrowserRequest(env.handler, "/guarded", c1, payload)
		if got := c.Response.StatusCode(); got != http.StatusOK {
			t.Fatalf("round %d: 携带合法 C2 的浏览器请求 status = %d, want %d", round, got, http.StatusOK)
		}
		if got := string(c.Response.Header.Peek("X-OWAF-Probe")); got == "renew" {
			t.Fatalf("round %d: 合法 C2 不应回续期页", round)
		}
	}
	if got := env.upstreamRequests(); got != 2 {
		t.Fatalf("两轮合法请求应各触上游一次, got %d", got)
	}
}

/**
 * TestDualBrowserForgedC2ReturnsRenew 验证无效 C2 走「重签 412 续期页」的
 * 降级路径，而不是拒绝也不是死循环：响应必须仍是可自愈的续期页。
 */
func TestDualBrowserForgedC2ReturnsRenew(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	challenge.SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))

	c1 := env.manager.GenerateNonce(antiReplayClientIP)
	forged := "w2." + strings.Repeat("ab", 32) + "." + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	c := doDualAntiReplayBrowserRequest(env.handler, "/guarded", c1, forged)

	if got := c.Response.StatusCode(); got != http.StatusPreconditionFailed {
		t.Fatalf("伪造 C2 status = %d, want %d", got, http.StatusPreconditionFailed)
	}
	if got := string(c.Response.Header.Peek("X-OWAF-Probe")); got != "renew" {
		t.Fatalf("伪造 C2 应回续期页, X-OWAF-Probe = %q", got)
	}
	if got := env.upstreamRequests(); got != 0 {
		t.Fatalf("伪造 C2 不应触上游, got %d", got)
	}
}

/**
 * mustIssueC2CookieForTest 走「服务端签发 -> 解封 -> 取 cookie 字段」的
 * 完整路径，产出浏览器会原样落位的 C2 值。c2seed.go 的信封密钥只随页面
 * 下发，测试内需自行解封，故这里复用与生产一致的 gm 解封调用。
 */
func mustIssueC2CookieForTest(t *testing.T, clientIP string) string {
	t.Helper()
	envelope, keyHex, ok := challenge.IssueC2Seed(clientIP)
	if !ok {
		t.Fatal("IssueC2Seed failed")
	}
	cookie := challenge.C2SeedCookieFromEnvelopeForTest(envelope, keyHex)
	if cookie == "" {
		t.Fatal("failed to unseal the issued C2 seed")
	}
	return cookie
}

/**
 * TestDualBrowserFullFlowCrossRotationConvergesInThreeRounds 是「首次访问
 * dual 站点的完整往返计数」实测：从零 Cookie 出发，逐轮记录状态码与是否
 * 触上游，直到进入 200 稳态。
 *
 * 这是防复发测试：上一版 C2 的 MAC 绑定 C1，导致每轮都因「用下一枚 C1
 * 校验绑定上一枚 C1 的 MAC」而不匹配，第 ② 轮起永远停留在 412——即用户
 * 所见「首次访问只有验证码页、进不去」的现象。测试名带 CrossRotation，
 * 让后来者一眼看到这条路径已被覆盖。
 *
 * 断言必须真的经过 ValidateAndRotate：第 ② 轮携带的 C1_a 由第 ① 轮响应
 * 下发，进入 handler 后会被轮换成新的 C1_b，C2 校验发生在轮换之后。
 */
func TestDualBrowserFullFlowCrossRotationConvergesInThreeRounds(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	challenge.SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))

	const maxRounds = 3

	var (
		c1        string
		c2        string
		rounds    int
		statusLog []int
	)
	for round := 1; round <= maxRounds; round++ {
		rounds = round
		c := doDualAntiReplayBrowserRequest(env.handler, "/guarded", c1, c2)
		status := c.Response.StatusCode()
		statusLog = append(statusLog, status)

		if status == http.StatusOK {
			break
		}
		if status != http.StatusPreconditionFailed {
			t.Fatalf("round %d: status = %d, want 412 or 200 (states=%v)", round, status, statusLog)
		}
		// 从续期页响应的 Set-Cookie 里取出下一枚 C1。
		issued := issuedNonceCookies(c)
		if len(issued) != 1 {
			t.Fatalf("round %d: 续期页应下发 1 个 C1, got %v", round, issued)
		}
		c1 = issued[0]
		// 浏览器落位的 C2 与 C1 无关（MAC 绑 clientIP+exp），只在首轮取一次。
		if c2 == "" {
			c2 = mustIssueC2CookieForTest(t, antiReplayClientIP)
		}
	}

	if rounds > maxRounds {
		t.Fatalf("未能收敛: %d 轮后仍非 200 (states=%v)", rounds, statusLog)
	}
	if rounds == 1 {
		t.Fatalf("首轮即 200，说明请求未携带 C1（首访应回 412）: states=%v", statusLog)
	}
	// 往返次数必须**恰好**是 2：首轮 412 发 C1 + 落位 C2，次轮 200。
	if rounds != 2 {
		t.Fatalf("首次访问进入稳态的往返次数 = %d, want 2 (states=%v)", rounds, statusLog)
	}
	if statusLog[0] != http.StatusPreconditionFailed || statusLog[1] != http.StatusOK {
		t.Fatalf("往返序列 = %v, want [412 200]", statusLog)
	}
	if got := env.upstreamRequests(); got != 1 {
		t.Fatalf("稳态路径应只触上游 1 次, got %d", got)
	}
}

/**
 * TestDualIdemWindowCrossRotationHasNoEffect 实测「8 秒幂等窗口在解除 C1
 * 绑定后不再影响 C2 校验」：同一枚 C1 在幂等窗口内重复提交（handler 会
 * 返回缓存的同一枚 C1_b），携带与 C1 无关的合法 C2 两种情况下都必须放行。
 *
 * 这条用实测回答「幂等窗口与 C1 轮换是否还有交互缺陷」，而不是推断。
 */
func TestDualIdemWindowCrossRotationHasNoEffect(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	challenge.SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))

	c2 := mustIssueC2CookieForTest(t, antiReplayClientIP)
	c1 := env.manager.GenerateNonce(antiReplayClientIP)

	// 第一次：消费 C1，进入幂等记录。
	first := doDualAntiReplayBrowserRequest(env.handler, "/guarded", c1, c2)
	if got := first.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("幂等窗口内第一次请求 status = %d, want 200", got)
	}
	firstIssued := issuedNonceCookies(first)
	if len(firstIssued) != 1 {
		t.Fatalf("第一次请求应轮换下发 1 个 C1, got %v", firstIssued)
	}

	// 第二次：同一枚 C1 仍在幂等窗口内，handler 返回缓存的同一枚 C1_b。
	second := doDualAntiReplayBrowserRequest(env.handler, "/guarded", c1, c2)
	if got := second.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("幂等窗口内第二次请求 status = %d, want 200（C2 不绑 C1，幂等窗口不影响校验）", got)
	}
	secondIssued := issuedNonceCookies(second)
	if len(secondIssued) != 1 {
		t.Fatalf("第二次请求应下发 1 个 C1, got %v", secondIssued)
	}
	// 幂等性本身未被改动：两次下发的是同一枚 C1。
	if firstIssued[0] != secondIssued[0] {
		t.Fatalf("幂等窗口内两次下发的 C1 应相同: first=%q second=%q", firstIssued[0], secondIssued[0])
	}
	// 两次都放行，各触上游一次。
	if got := env.upstreamRequests(); got != 2 {
		t.Fatalf("幂等窗口内两次请求应各触上游一次, got %d", got)
	}
}

/**
 * setSecureFetchHeaders 把一组 Sec-Fetch-* 头写入请求，模拟浏览器/脚本上下文。
 * 取值为实测所得（真实 Chromium 抓头）：
 *
 *	fetch/XHR          -> Dest: empty, Mode: cors
 *	表单 POST / reload -> Dest: document, Mode: navigate
 */
func setSecureFetchHeaders(c *app.RequestContext, dest, mode string) {
	if dest != "" {
		c.Request.Header.Set("Sec-Fetch-Dest", dest)
	}
	if mode != "" {
		c.Request.Header.Set("Sec-Fetch-Mode", mode)
	}
}

/**
 * doDualBrowserRequestWithMethod 构造一次带指定方法与 Accept 的 dual 请求。
 * 用于覆盖「方法 + 上下文」两个维度的组合。
 */
func doDualBrowserRequestWithMethod(handler app.HandlerFunc, path, method, nonceCookie, pairCookie string) *app.RequestContext {
	c := newDualAntiReplayContext(path, nonceCookie, pairCookie)
	c.Request.Header.SetMethod(method)
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	handler(context.Background(), c)
	return c
}

/**
 * TestDualPostNavigationDoesNotGetRenewPage 覆盖「幂等导航 / 非幂等」维度：
 * 非幂等（POST）即使带 Accept: text/html，也不得拿到 412 续期页。
 *
 * 变异验证：把 renewRequired 的 `!isUnsafeRequestMethod(method)` 去掉，本
 * 用例立刻变红（POST 会拿到 412 + 续期页）。
 *
 * 注意断言的是「不返回续期页」而不是「返回 200」：非幂等方法仍按 Cookie
 * 状态判定，缺 Cookie 时依 standard 首访语义签发 C1 后放行。
 */
func TestDualPostNavigationDoesNotGetRenewPage(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	challenge.SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))

	c := doDualBrowserRequestWithMethod(env.handler, "/guarded", http.MethodPost, "", "")
	if got := c.Response.StatusCode(); got == http.StatusPreconditionFailed {
		t.Fatalf("非幂等请求不应拿到 412 续期页, got %d (probe=%q)", got, string(c.Response.Header.Peek("X-OWAF-Probe")))
	}
	if probe := string(c.Response.Header.Peek("X-OWAF-Probe")); probe == "renew" || probe == "renew-json" {
		t.Fatalf("非幂等请求不应触发续期路径, X-OWAF-Probe = %q", probe)
	}
	// C1 仍应照常签发（Cookie 状态判定未被跳过）。
	if len(issuedNonceCookies(c)) != 1 {
		t.Fatalf("非幂等首访仍应签发 1 个 C1, got %v", issuedNonceCookies(c))
	}
}

/**
 * TestDualGetNavigationStillGetsRenewPage 覆盖「幂等导航」维度：GET 顶层导航
 * 仍拿完整 HTML 续期页。这是上面那条的对照组——若谓词写反（把所有方法都排除），
 * 本用例会红。
 */
func TestDualGetNavigationStillGetsRenewPage(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	challenge.SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))

	c := newDualAntiReplayContext("/guarded", "", "")
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	setSecureFetchHeaders(c, "document", "navigate")
	env.handler(context.Background(), c)

	if got := c.Response.StatusCode(); got != http.StatusPreconditionFailed {
		t.Fatalf("GET 顶层导航应拿到 412 续期页, got %d", got)
	}
	if probe := string(c.Response.Header.Peek("X-OWAF-Probe")); probe != "renew" {
		t.Fatalf("GET 顶层导航应走 HTML 续期页, X-OWAF-Probe = %q", probe)
	}
	if ct := string(c.Response.Header.ContentType()); !strings.Contains(ct, "text/html") {
		t.Fatalf("GET 顶层导航应为 HTML, Content-Type = %q", ct)
	}
}

/**
 * TestDualScriptFetchGetsRenewJSON 覆盖「脚本 fetch」维度：Sec-Fetch-Dest:
 * empty / Mode: cors 的请求拿到 412 + JSON + Retry-After，而不是 HTML。
 *
 * 变异验证：去掉 requestWantsRenewJSON 判据（或让它恒 false），本用例会红
 * （Content-Type 变 text/html）。
 */
func TestDualScriptFetchGetsRenewJSON(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	challenge.SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))

	c := newDualAntiReplayContext("/api/data", "", "")
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml")
	setSecureFetchHeaders(c, "empty", "cors")
	env.handler(context.Background(), c)

	if got := c.Response.StatusCode(); got != http.StatusPreconditionFailed {
		t.Fatalf("脚本 fetch 应拿到 412, got %d", got)
	}
	if probe := string(c.Response.Header.Peek("X-OWAF-Probe")); probe != "renew-json" {
		t.Fatalf("脚本 fetch 应走 JSON 分支, X-OWAF-Probe = %q", probe)
	}
	if ct := string(c.Response.Header.ContentType()); !strings.Contains(ct, "application/json") {
		t.Fatalf("脚本 fetch 应为 JSON, Content-Type = %q", ct)
	}
	if got := string(c.Response.Header.Peek("Retry-After")); got != "1" {
		t.Fatalf("脚本 fetch 应带 Retry-After: 1, got %q", got)
	}
	var body struct {
		Renew string `json:"renew"`
		URL   string `json:"url"`
	}
	if err := json.Unmarshal(c.Response.Body(), &body); err != nil {
		t.Fatalf("响应体不是合法 JSON: %v (body=%q)", err, string(c.Response.Body()))
	}
	if body.Renew != "required" {
		t.Fatalf(`renew 字段 = %q, want "required"`, body.Renew)
	}
	if body.URL != "/api/data" {
		t.Fatalf("url 字段 = %q, want %q", body.URL, "/api/data")
	}
}

/**
 * TestDualMissingSecFetchFallsBackToHTML 覆盖「无 Sec-Fetch-* 头」维度：
 * Safari 与部分爬虫不带该头，必须回退到完整 HTML 页面，既不返 JSON 也不
 * 拒服务。
 *
 * 变异验证：把 requestWantsRenewJSON 的缺失回退改成「缺头即返 JSON」，
 * 本用例会红。
 */
func TestDualMissingSecFetchFallsBackToHTML(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	challenge.SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))

	c := newDualAntiReplayContext("/guarded", "", "")
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml")
	// 刻意不设置任何 Sec-Fetch-* 头。
	env.handler(context.Background(), c)

	if got := c.Response.StatusCode(); got != http.StatusPreconditionFailed {
		t.Fatalf("无 Sec-Fetch 头应仍回 412, got %d", got)
	}
	if probe := string(c.Response.Header.Peek("X-OWAF-Probe")); probe != "renew" {
		t.Fatalf("无 Sec-Fetch 头应回退 HTML 页面, X-OWAF-Probe = %q", probe)
	}
	if ct := string(c.Response.Header.ContentType()); !strings.Contains(ct, "text/html") {
		t.Fatalf("无 Sec-Fetch 头应为 HTML, Content-Type = %q", ct)
	}
}

/**
 * TestDualPostReloadLoopIsBroken 是用户症状的端到端复现与回归锁：
 * 模拟「POST -> 412 续期页 -> location.reload() 重提交同一 POST」这一序列。
 *
 * 缺陷形态下（renewRequired 不看方法）：每一轮 POST 都拿到 412 续期页，
 * reload 重提交 POST 又拿到 412 —— 无限循环，请求永不恢复。
 * 修复后：POST 不再进续期页，序列在第一次就脱离循环。
 *
 * 本用例断言的是「连续三次 POST 重放都不出现 412 续期页」，即循环被打断。
 */
func TestDualPostReloadLoopIsBroken(t *testing.T) {
	env := newDualAntiReplayHandlerEnv(t, 0)
	challenge.SetChallengeSecret([]byte("0123456789abcdef0123456789abcdef"))

	// 第一轮：浏览器导航式 POST（Accept: text/html）。reload 会重提交同一请求。
	var lastCookie string
	for round := 1; round <= 3; round++ {
		c := doDualBrowserRequestWithMethod(env.handler, "/submit", http.MethodPost, lastCookie, "")
		setSecureFetchHeaders(c, "document", "navigate")
		status := c.Response.StatusCode()
		if probe := string(c.Response.Header.Peek("X-OWAF-Probe")); probe == "renew" {
			t.Fatalf("round %d: POST 重放仍被 412 续期页打断（循环未打断），status=%d", round, status)
		}
		if status == http.StatusPreconditionFailed {
			t.Fatalf("round %d: POST 重放仍拿到 412（循环未打断）", round)
		}
		issued := issuedNonceCookies(c)
		if len(issued) != 1 {
			t.Fatalf("round %d: 应签发 1 个 C1, got %v", round, issued)
		}
		lastCookie = issued[0]
	}
}
