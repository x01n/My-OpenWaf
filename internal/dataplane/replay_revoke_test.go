package dataplane

import (
	"context"
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
	"My-OpenWaf/internal/waf/accessgate"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/challenge"
)

/*
本文件为「防重放命中双吊销（access 登录会话 + 挑战免验态）」的回归测试。

产品事实（均来自源码，非推断）：
  - 全局会话存储 dataplane.globalAccessSessionStore 由 accessgate.NewMemorySessionStore()
    创建（access_control.go:20），token 全局唯一，支持按 token Validate/Revoke；
  - accessgate.Gate.CookieName() 按站点隔离，名为 __owaf_access_<SiteID>；
  - handleAntiReplayCookie 的 isReplay 分支现依次执行：
    ①revokeAccessSessionIfPresent——请求携带该站点有效会话 token 时 Revoke
      并追加 Set-Cookie 清除头，否则维持原有拦截行为不变；
    ②clearChallengePassCookie——无条件追加 __waf_passed 挑战免验态清除头
      （该 cookie 是无状态签名、服务端无存储，吊销只能靠浏览器侧删除）。
  - 测试进程内多实例共享同一全局 store —— 本文件刻意用两个站点实例交叉验证
    「吊销即全局立即生效」与站点隔离，不模拟生产多 listener 的启动方式。
*/

// replayRevokeHostA / replayRevokeHostB 与其他测试文件的 Host 保持隔离。
const (
	replayRevokeHostA = "replay-revoke-a.example.com"
	replayRevokeHostB = "replay-revoke-b.example.com"
)

const (
	replayRevokeSiteA uint = 11
	replayRevokeSiteB uint = 12
)

// replayRevokeCookieName 构造与 accessgate.CookieName 一致的站点会话 cookie 名。
func replayRevokeCookieName(siteID uint) string {
	return accessgate.NewGate(accessgate.Config{Enabled: true, SiteID: siteID}, nil).CookieName()
}

// newReplayRevokeEnv 复用本包既有测试脚手架（httptest 上游 + snapshot.Holder）。
// 每实例独立构造 manager，跨实例共享 nonce 消费状态需用例显式传入共享 manager。
func newReplayRevokeEnv(t *testing.T, siteID uint, host string, shared *antireplay.AntiReplayManager) (app.HandlerFunc, *antireplay.AntiReplayManager, func() int) {
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
			ID:   siteID,
			Host: host,
			Bind: ":80",
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
			snapshot.SiteMapKey(":80", host): &rt,
		},
	})

	eng := engine.New(holder, nil, nil, nil)
	mgr := shared
	if mgr == nil {
		mgr = antireplay.NewAntiReplayManager("replay-revoke-test-secret", nil, 5*time.Minute)
	}
	eng.SetAntiReplayManager(mgr)

	return Handler(Options{
			Holder: holder,
			Engine: eng,
			Bind:   ":80",
		}), mgr, func() int {
			mu.Lock()
			defer mu.Unlock()
			return upstreamHits
		}
}

// doReplayRevokeRequest 驱动一次 handler 调用。sessionCookies 依次写入请求
// Cookie 头（同名 cookie 只保留最后写入的值，与浏览器发送语义一致）。
func doReplayRevokeRequest(handler app.HandlerFunc, host, nonce string, sessionCookies ...string) *app.RequestContext {
	c := app.NewContext(0)
	c.Request.Header.SetMethod(http.MethodGet)
	c.Request.SetRequestURI("/guarded")
	c.Request.Header.SetHost(host)
	if nonce != "" {
		c.Request.Header.SetCookie(challenge.NonceKey, nonce)
	}
	for _, pair := range sessionCookies {
		name, value, _ := strings.Cut(pair, "=")
		c.Request.Header.SetCookie(name, value)
	}
	handler(context.Background(), c)
	return c
}

// setCookieLinesWithPrefix 提取响应 Set-Cookie 头中满足前缀的所有行。
func setCookieLinesWithPrefix(c *app.RequestContext, prefix string) []string {
	var lines []string
	c.Response.Header.VisitAll(func(key, value []byte) {
		if !strings.EqualFold(string(key), "Set-Cookie") {
			return
		}
		if strings.HasPrefix(string(value), prefix) {
			lines = append(lines, string(value))
		}
	})
	return lines
}

// challengePassClearLines 提取响应中 __waf_passed 清除头的 Set-Cookie 行。
// 该清除头无条件追加：__waf_passed 是无状态签名，「吊销」只能靠浏览器侧删除。
func challengePassClearLines(c *app.RequestContext) []string {
	return setCookieLinesWithPrefix(c, challenge.ChallengePassCookieName+"=;")
}

// seedAccessSession 向全局会话存储写入一个测试会话并返回 token。
func seedAccessSession(t *testing.T, siteID uint) string {
	t.Helper()
	token, err := globalAccessSessionStore.Create(siteID, "replay-user", "password", 3600)
	if err != nil {
		t.Fatalf("创建测试会话失败: %v", err)
	}
	return token
}

/**
 * TestReplayRevokeValidAccessSession 验收用例 1：重放命中且请求携带该站点
 * 有效会话时，store 中该 token 被撤销，且响应出现清除该 cookie 的 Set-Cookie。
 * 拦截行为本身保持不变（403、不达上游、不下发新 nonce）。
 */
func TestReplayRevokeValidAccessSession(t *testing.T) {
	handler, mgr, hits := newReplayRevokeEnv(t, replayRevokeSiteA, replayRevokeHostA, nil)
	original := mgr.GenerateNonce(antiReplayClientIP)
	token := seedAccessSession(t, replayRevokeSiteA)

	first := doReplayRevokeRequest(handler, replayRevokeHostA, original)
	if got := first.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("首次消费 nonce status = %d, want %d", got, http.StatusOK)
	}

	// 幂等窗口固定 8 秒，留余量等待窗口过期以触发重放判定。
	time.Sleep(8300 * time.Millisecond)

	second := doReplayRevokeRequest(handler, replayRevokeHostA, original, replayRevokeCookieName(replayRevokeSiteA)+"="+token)
	if got := second.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("重放请求 status = %d, want %d（拦截必须保持）", got, http.StatusForbidden)
	}
	if got := hits(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1（重放请求不达上游）", got)
	}

	if info, _ := globalAccessSessionStore.Validate(token); info != nil {
		t.Fatal("重放命中后会话 token 未被撤销")
	}
	clears := setCookieLinesWithPrefix(second, replayRevokeCookieName(replayRevokeSiteA)+"=;")
	if len(clears) != 1 {
		t.Fatalf("响应中的会话清除 Set-Cookie 数 = %d, want 1: %v", len(clears), clears)
	}
	if !strings.Contains(clears[0], "Max-Age=0") {
		t.Fatalf("清除头缺少 Max-Age=0（无法让浏览器删除）: %q", clears[0])
	}
	if issued := issuedNonceCookies(second); len(issued) != 0 {
		t.Fatalf("重放拦截响应不应下发新 nonce, got %v", issued)
	}
	// 双吊销断言：挑战免验态清除头必须存在，且属性保持签发侧 (token.go
	// BuildChallengePassCookieWithClaims) 一致，否则浏览器视作不同 cookie 清不掉。
	passClears := challengePassClearLines(second)
	if len(passClears) != 1 {
		t.Fatalf("挑战免验态清除 Set-Cookie 数 = %d, want 1: %v", len(passClears), passClears)
	}
	if !strings.Contains(passClears[0], "Max-Age=0") {
		t.Fatalf("挑战免验态清除头缺少 Max-Age=0（无法让浏览器删除）: %q", passClears[0])
	}
	for _, attr := range []string{"Path=/", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(passClears[0], attr) {
			t.Fatalf("挑战免验态清除头缺少属性 %q: %q", attr, passClears[0])
		}
	}
	if strings.Contains(passClears[0], "Secure") {
		t.Fatalf("站点 TLSEnabled=false 时清除头不应带 Secure: %q", passClears[0])
	}
}

/**
 * TestReplayRevokeWithoutSessionKeepsLegacyBehavior 验收用例 2：重放命中且
 * 未携带有效会话时，access 会话侧行为与旧实现一致——store 无任何变化、无
 * access 清除头；挑战免验态清除头属无条件追加（无状态签名无法服务端吊销），
 * 按新语义必然存在。
 */
func TestReplayRevokeWithoutSessionKeepsLegacyBehavior(t *testing.T) {
	handler, mgr, hits := newReplayRevokeEnv(t, replayRevokeSiteA, replayRevokeHostA, nil)
	original := mgr.GenerateNonce(antiReplayClientIP)

	// 预置一个无关站点的有效会话，验证吊销逻辑不会波及它。
	unrelated := seedAccessSession(t, replayRevokeSiteB)

	first := doReplayRevokeRequest(handler, replayRevokeHostA, original)
	if got := first.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("首次消费 nonce status = %d, want %d", got, http.StatusOK)
	}
	time.Sleep(8300 * time.Millisecond)

	second := doReplayRevokeRequest(handler, replayRevokeHostA, original)
	if got := second.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("重放请求 status = %d, want %d", got, http.StatusForbidden)
	}
	if got := hits(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1", got)
	}
	if clears := setCookieLinesWithPrefix(second, replayRevokeCookieName(replayRevokeSiteA)+"=;"); len(clears) != 0 {
		t.Fatalf("无会话时不应下发会话清除头, got %v", clears)
	}
	// __waf_passed 是无状态签名，重放命中即无条件追加清除头（与 access
	// session 的条件性吊销不同）。
	if clears := challengePassClearLines(second); len(clears) != 1 {
		t.Fatalf("重放命中必须下发挑战免验态清除头, got %v", clears)
	}
	if info, _ := globalAccessSessionStore.Validate(unrelated); info == nil {
		t.Fatal("无关站点的会话被误撤销")
	}
}

/**
 * TestReplayRevokeIgnoresOtherSiteToken 站点隔离：携带的是**其他站点**的有效
 * token 时，不撤销、不下发清除头，拦截照旧。
 */
func TestReplayRevokeIgnoresOtherSiteToken(t *testing.T) {
	handler, mgr, hits := newReplayRevokeEnv(t, replayRevokeSiteA, replayRevokeHostA, nil)
	original := mgr.GenerateNonce(antiReplayClientIP)
	other := seedAccessSession(t, replayRevokeSiteB)

	first := doReplayRevokeRequest(handler, replayRevokeHostA, original)
	if got := first.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("首次消费 nonce status = %d, want %d", got, http.StatusOK)
	}
	time.Sleep(8300 * time.Millisecond)

	second := doReplayRevokeRequest(handler, replayRevokeHostA, original, replayRevokeCookieName(replayRevokeSiteB)+"="+other)
	if got := second.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("重放请求 status = %d, want %d", got, http.StatusForbidden)
	}
	if got := hits(); got != 1 {
		t.Fatalf("上游命中次数 = %d, want 1", got)
	}
	if info, _ := globalAccessSessionStore.Validate(other); info == nil {
		t.Fatal("其他站点的有效会话被误撤销")
	}
	if clears := setCookieLinesWithPrefix(second, replayRevokeCookieName(replayRevokeSiteB)+"=;"); len(clears) != 0 {
		t.Fatalf("不应为其他站点私下发清除头, got %v", clears)
	}
	// 本机属实站点的 cookie 名未被清除头覆盖（防止清掉用户合法 cookie）。
	if clears := setCookieLinesWithPrefix(second, replayRevokeCookieName(replayRevokeSiteA)+"=;"); len(clears) != 0 {
		t.Fatalf("无本机属实有效会话时不应下发清除头, got %v", clears)
	}
	if clears := challengePassClearLines(second); len(clears) != 1 {
		t.Fatalf("重放命中必须下发挑战免验态清除头, got %v", clears)
	}
}

/**
 * TestReplayRevokeCrossSiteSharedStore 验证全局共享存储下的吊销即时生效：
 * 在两个站点实例间重放同一 nonce，命中站点的有效会话在另一实例视角同样失效。
 */
func TestReplayRevokeCrossSiteSharedStore(t *testing.T) {
	// 显式共享同一 manager：模拟生产多 listener 监听不同 Bind/SNI 时仍由
	// 同一个 AntiReplayManager 消费 nonce 的真实拓扑。
	shared := antireplay.NewAntiReplayManager("replay-revoke-test-secret", nil, 5*time.Minute)
	handlerA, mgr, hitsA := newReplayRevokeEnv(t, replayRevokeSiteA, replayRevokeHostA, shared)
	handlerB, _, hitsB := newReplayRevokeEnv(t, replayRevokeSiteB, replayRevokeHostB, shared)
	original := mgr.GenerateNonce(antiReplayClientIP)
	tokenB := seedAccessSession(t, replayRevokeSiteB)

	first := doReplayRevokeRequest(handlerA, replayRevokeHostA, original)
	if got := first.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("站点 A 首次消费 nonce status = %d, want %d", got, http.StatusOK)
	}
	time.Sleep(8300 * time.Millisecond)

	second := doReplayRevokeRequest(handlerB, replayRevokeHostB, original, replayRevokeCookieName(replayRevokeSiteB)+"="+tokenB)
	if got := second.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("站点 B 重放请求 status = %d, want %d（同 secret 共享 nonce 消费状态）", got, http.StatusForbidden)
	}
	if got := hitsA(); got != 1 {
		t.Fatalf("站点 A 上游命中 = %d, want 1", got)
	}
	if got := hitsB(); got != 0 {
		t.Fatalf("站点 B 上游命中 = %d, want 0", got)
	}
	if info, _ := globalAccessSessionStore.Validate(tokenB); info != nil {
		t.Fatal("站点 B 会话未被撤销")
	}
	if clears := setCookieLinesWithPrefix(second, replayRevokeCookieName(replayRevokeSiteB)+"=;"); len(clears) != 1 {
		t.Fatalf("站点 B 清除头数量 = %d, want 1: %v", len(clears), clears)
	}
	if clears := challengePassClearLines(second); len(clears) != 1 {
		t.Fatalf("重放命中必须下发挑战免验态清除头, got %v", clears)
	}
}
