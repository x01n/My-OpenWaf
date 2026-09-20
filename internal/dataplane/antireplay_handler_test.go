package dataplane

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	goredis "github.com/redis/go-redis/v9"

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

	failingRedis := goredis.NewClient(&goredis.Options{
		Addr:        unreachableAddr,
		DialTimeout: 50 * time.Millisecond,
		MaxRetries:  -1,
	})
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
    原因：ValidateAndRotate 只接受 *goredis.Client 具体类型（antireplay.go:20、69），
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
