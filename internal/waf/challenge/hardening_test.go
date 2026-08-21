package challenge

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

/**
 * TestShieldSessionRedeemedOnlyOnceUnderConcurrency 验证同一个 shield 会话
 * 在并发提交同一份 PoW 解时只能被兑换一次。
 *
 * 复现（修复前）：loadShieldSession 与 deleteShieldSession 是两个独立操作，
 * N 个并发请求可以同时读到同一会话并各自校验通过，一份 PoW 解被重复兑换 N 次。
 */
func TestShieldSessionRedeemedOnlyOnceUnderConcurrency(t *testing.T) {
	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	mgr := NewShieldManager(captcha, nil, 1)
	defer mgr.Close()

	cfg := DefaultShieldConfig()
	cfg.Difficulty = 1
	cfg.EnableEnvCheck = false
	cfg.EnableDevToolsDetect = false
	mgr.SetConfig(cfg)

	session, err := mgr.GenerateChallenge("/protected", "http/1.1")
	if err != nil {
		t.Fatalf("GenerateChallenge(): %v", err)
	}
	counter, hash := findShieldPoWSolution(t, session.Nonce, session.Difficulty)

	const workers = 32
	var passed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, _ := mgr.VerifyChallenge(session.ID, "", counter, hash, "", "http/1.1"); ok {
				passed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := passed.Load(); got != 1 {
		t.Fatalf("shield PoW solution was redeemed %d times, want exactly 1", got)
	}
}

/**
 * TestShieldSessionSequentialReplayRejected 验证 shield 会话在串行重放下同样只能兑换一次。
 */
func TestShieldSessionSequentialReplayRejected(t *testing.T) {
	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	mgr := NewShieldManager(captcha, nil, 1)
	defer mgr.Close()

	cfg := DefaultShieldConfig()
	cfg.Difficulty = 1
	cfg.EnableEnvCheck = false
	mgr.SetConfig(cfg)

	session, err := mgr.GenerateChallenge("/protected", "http/1.1")
	if err != nil {
		t.Fatalf("GenerateChallenge(): %v", err)
	}
	counter, hash := findShieldPoWSolution(t, session.Nonce, session.Difficulty)

	if ok, _ := mgr.VerifyChallenge(session.ID, "", counter, hash, "", "http/1.1"); !ok {
		t.Fatal("first shield verification must pass")
	}
	if ok, _ := mgr.VerifyChallenge(session.ID, "", counter, hash, "", "http/1.1"); ok {
		t.Fatal("replayed shield PoW solution must be rejected")
	}
}

/**
 * TestShieldSessionTimeoutIsFrozen 验证会话创建后不受后续配置热重载影响，
 * 并且缺少 timeout_secs 的旧 Redis JSON 会话仍按原有五分钟期限处理。
 */
func TestShieldSessionTimeoutIsFrozen(t *testing.T) {
	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	mgr := NewShieldManager(captcha, nil, 1)
	defer mgr.Close()

	cfg := DefaultShieldConfig()
	cfg.Difficulty = 1
	cfg.TimeoutSecs = 1
	cfg.EnvStrictness = 0
	cfg.EnableEnvCheck = false
	cfg.EnableDevToolsDetect = false
	mgr.SetConfig(cfg)
	session, err := mgr.GenerateChallenge("/protected", "http/1.1")
	if err != nil {
		t.Fatalf("GenerateChallenge(): %v", err)
	}
	if got := session.sessionTTL(); got != time.Second {
		t.Fatalf("session TTL = %s, want 1s", got)
	}
	if !session.expiredAt(session.CreatedAt.Add(time.Second)) {
		t.Fatal("session must expire at its exact TTL boundary")
	}

	cfg.TimeoutSecs = 60
	cfg.EnvStrictness = 2
	cfg.EnableEnvCheck = true
	mgr.SetConfig(cfg)
	if got := mgr.shieldPageConfig(session).TimeoutSecs; got != 1 {
		t.Fatalf("shield page timeout = %d, want frozen value 1", got)
	}
	if mgr.shieldPageConfig(session).EnableEnvCheck {
		t.Fatal("shield page environment check must preserve the session value")
	}
	if got := mgr.shieldPageConfig(session).EnvStrictness; got != 0 {
		t.Fatalf("shield page environment strictness = %d, want frozen value 0", got)
	}

	session.CreatedAt = time.Now().Add(-2 * time.Second)
	counter, hash := findShieldPoWSolution(t, session.Nonce, session.Difficulty)
	if ok, redirect := mgr.VerifyChallenge(session.ID, "", counter, hash, "", "http/1.1"); ok || redirect != "/protected" {
		t.Fatalf("expired shield session = (%t, %q), want (false, %q)", ok, redirect, "/protected")
	}

	var legacy ShieldSession
	if err := json.Unmarshal([]byte(`{"id":"legacy","created_at":"2026-08-05T00:00:00Z"}`), &legacy); err != nil {
		t.Fatalf("decode legacy Redis session: %v", err)
	}
	if got := legacy.sessionTTL(); got != legacyShieldSessionTTL {
		t.Fatalf("legacy session TTL = %s, want %s", got, legacyShieldSessionTTL)
	}
	if legacy.expiredAt(time.Date(2026, time.August, 5, 0, 4, 0, 0, time.UTC)) {
		t.Fatal("legacy session expired before its five-minute fallback TTL")
	}
	if !legacy.expiredAt(time.Date(2026, time.August, 5, 0, 6, 0, 0, time.UTC)) {
		t.Fatal("legacy session must expire after its five-minute fallback TTL")
	}

	legacySession := &ShieldSession{
		ID:              "legacy-env-config",
		Nonce:           GeneratePoWNonce(),
		Difficulty:      1,
		OriginalURL:     "/legacy",
		RequestProtocol: "http/1.1",
		CreatedAt:       time.Now(),
	}
	mgr.mu.Lock()
	mgr.sessions[legacySession.ID] = legacySession
	mgr.mu.Unlock()
	counter, hash = findShieldPoWSolution(t, legacySession.Nonce, legacySession.Difficulty)
	if ok, redirect := mgr.VerifyChallenge(legacySession.ID, "", counter, hash, "", "http/1.1"); ok || redirect != "/legacy" {
		t.Fatalf("legacy session without frozen environment config = (%t, %q), want (false, %q)", ok, redirect, "/legacy")
	}
}

/**
 * TestShieldSessionProtocolIsFrozenAndBound 验证 Shield 会话锁定签发协议及协议策略，
 * 后续配置热重载不能改变已签发会话的协议校验结果。
 */
func TestShieldSessionProtocolIsFrozenAndBound(t *testing.T) {
	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	mgr := NewShieldManager(captcha, nil, 1)
	defer mgr.Close()

	cfg := DefaultShieldConfig()
	cfg.Difficulty = 1
	cfg.EnableEnvCheck = false
	cfg.RequireHTTP2 = false
	cfg.RequireHTTP3 = false
	cfg.AllowHTTP1 = true
	mgr.SetConfig(cfg)

	h2Session, err := mgr.GenerateChallenge("/protocol", "h2")
	if err != nil {
		t.Fatalf("GenerateChallenge(h2): %v", err)
	}
	h2Counter, h2Hash := findShieldPoWSolution(t, h2Session.Nonce, h2Session.Difficulty)
	if ok, redirect := mgr.VerifyChallenge(h2Session.ID, "", h2Counter, h2Hash, "", "http/1.1"); ok || redirect != "/protocol" {
		t.Fatalf("h2 session verified over HTTP/1.1 = (%t, %q), want (false, %q)", ok, redirect, "/protocol")
	}

	h1Session, err := mgr.GenerateChallenge("/protocol", "http/1.1")
	if err != nil {
		t.Fatalf("GenerateChallenge(http/1.1): %v", err)
	}
	reloaded := DefaultShieldConfig()
	reloaded.Difficulty = 1
	reloaded.EnableEnvCheck = false
	reloaded.RequireHTTP2 = true
	reloaded.AllowHTTP1 = false
	mgr.SetConfig(reloaded)

	pageCfg := mgr.shieldPageConfig(h1Session)
	if pageCfg.RequireHTTP2 || pageCfg.RequireHTTP3 || !pageCfg.AllowHTTP1 {
		t.Fatalf("shield page protocol config = %+v, want session protocol policy", pageCfg)
	}
	h1Counter, h1Hash := findShieldPoWSolution(t, h1Session.Nonce, h1Session.Difficulty)
	if ok, redirect := mgr.VerifyChallenge(h1Session.ID, "", h1Counter, h1Hash, "", "http/1.1"); !ok || redirect != "/protocol" {
		t.Fatalf("h1 session after protocol reload = (%t, %q), want (true, %q)", ok, redirect, "/protocol")
	}
}

/**
 * TestShieldVerifyChallengeAppliesEnvStrictness 验证环境检测开关及三级严格度在会话签发时冻结。
 */
func TestShieldVerifyChallengeAppliesEnvStrictness(t *testing.T) {
	normalFingerprint := shieldNormalEnvFingerprint()
	mediumScoreFingerprint := *normalFingerprint
	mediumScoreFingerprint.DevtoolsOpen = true
	mediumScoreFingerprint.DevtoolsTiming = 101
	mediumScoreFingerprint.ElectronSign = true
	if result := ValidateEnvFingerprint(&mediumScoreFingerprint); result.Score != 65 {
		t.Fatalf("medium-score fingerprint score = %d, want 65", result.Score)
	}

	mediumScoreJSON := marshalShieldEnvFingerprint(t, &mediumScoreFingerprint)
	normalJSON := marshalShieldEnvFingerprint(t, normalFingerprint)
	cases := []struct {
		name           string
		enabled        bool
		strictness     int
		envFingerprint string
		plainPayload   bool
		wantPass       bool
	}{
		{name: "disabled skips automated fingerprint", enabled: false, strictness: 2, envFingerprint: `{"webdriver":true}`, wantPass: true},
		{name: "strictness zero rejects missing", enabled: true, strictness: 0, wantPass: false},
		{name: "strictness zero rejects malformed", enabled: true, strictness: 0, envFingerprint: `{`, wantPass: false},
		{name: "strictness zero accepts score above fifty", enabled: true, strictness: 0, envFingerprint: mediumScoreJSON, plainPayload: true, wantPass: true},
		{name: "strictness zero rejects score one hundred", enabled: true, strictness: 0, envFingerprint: `{"webdriver":true}`, plainPayload: true, wantPass: false},
		{name: "strictness one rejects missing", enabled: true, strictness: 1, wantPass: false},
		{name: "strictness one rejects malformed", enabled: true, strictness: 1, envFingerprint: `{`, wantPass: false},
		{name: "strictness one rejects score above fifty", enabled: true, strictness: 1, envFingerprint: mediumScoreJSON, plainPayload: true, wantPass: false},
		{name: "strictness two rejects missing", enabled: true, strictness: 2, wantPass: false},
		{name: "strictness two rejects malformed", enabled: true, strictness: 2, envFingerprint: `{`, wantPass: false},
		{name: "strictness two rejects score above fifty", enabled: true, strictness: 2, envFingerprint: mediumScoreJSON, plainPayload: true, wantPass: false},
		{name: "strictness two accepts score at most fifty", enabled: true, strictness: 2, envFingerprint: normalJSON, plainPayload: true, wantPass: true},
	}

	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	mgr := NewShieldManager(captcha, nil, 1)
	defer mgr.Close()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultShieldConfig()
			cfg.Difficulty = 1
			cfg.EnableEnvCheck = tc.enabled
			cfg.EnvStrictness = tc.strictness
			mgr.SetConfig(cfg)

			session, err := mgr.GenerateChallenge("/protected", "http/1.1")
			if err != nil {
				t.Fatalf("GenerateChallenge(): %v", err)
			}
			envFingerprint := tc.envFingerprint
			if tc.plainPayload {
				envFingerprint = encryptShieldEnvFingerprint(
					t,
					envFingerprint,
					session.EnvKey,
					EnvFingerprintAAD("shield", session.ID, session.ChallengeSessionBinding),
				)
			}
			reloaded := DefaultShieldConfig()
			reloaded.Difficulty = 1
			reloaded.EnableEnvCheck = !tc.enabled
			reloaded.EnvStrictness = 2
			mgr.SetConfig(reloaded)
			if got := mgr.shieldPageConfig(session).EnableEnvCheck; got != tc.enabled {
				t.Fatalf("shield page environment check = %t, want frozen value %t", got, tc.enabled)
			}
			if got := mgr.shieldPageConfig(session).EnvStrictness; got != tc.strictness {
				t.Fatalf("shield page environment strictness = %d, want frozen value %d", got, tc.strictness)
			}
			counter, hash := findShieldPoWSolution(t, session.Nonce, session.Difficulty)
			got, _ := mgr.VerifyChallenge(session.ID, "", counter, hash, envFingerprint, "http/1.1")
			if got != tc.wantPass {
				t.Fatalf("VerifyChallenge() = %t, want %t", got, tc.wantPass)
			}
		})
	}
}

func shieldNormalEnvFingerprint() *EnvFingerprint {
	return &EnvFingerprint{
		ChromePresent:        true,
		PluginsCount:         2,
		Languages:            "en-US",
		CanvasHash:           "canvas",
		WebGLRenderer:        "Intel",
		ScreenWidth:          1920,
		ScreenHeight:         1080,
		HardwareConcur:       4,
		ColorDepth:           24,
		PixelRatio:           1,
		AudioHash:            "audio",
		FontCount:            1,
		SessionStorage:       true,
		IndexedDB:            true,
		PlatformStr:          "Win32",
		CookieEnabled:        true,
		WebAssembly:          true,
		ServiceWorker:        true,
		MediaDevices:         true,
		WebGL2Support:        true,
		ScreenConsistency:    true,
		TimezoneConsistency:  true,
		LanguageConsistency:  true,
		MathConsistency:      true,
		IntersectionObserver: true,
		MutationObserver:     true,
		ResizeObserver:       true,
	}
}

func marshalShieldEnvFingerprint(t *testing.T, fp *EnvFingerprint) string {
	t.Helper()
	data, err := json.Marshal(fp)
	if err != nil {
		t.Fatalf("marshal env fingerprint: %v", err)
	}
	return string(data)
}

func encryptShieldEnvFingerprint(t *testing.T, plaintext string, key []byte, aad string) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new AES cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("new GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), []byte(aad))
	return envCiphertextPrefix + base64.RawURLEncoding.EncodeToString(append(nonce, ciphertext...))
}

/**
 * TestShieldSetConfigNormalizesInvalidEnvStrictness 验证非法严格度归一为 1。
 */
func TestShieldSetConfigNormalizesInvalidEnvStrictness(t *testing.T) {
	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	mgr := NewShieldManager(captcha, nil, 1)
	defer mgr.Close()

	for _, strictness := range []int{-1, 3} {
		cfg := DefaultShieldConfig()
		cfg.EnvStrictness = strictness
		mgr.SetConfig(cfg)
		if got := mgr.Config().EnvStrictness; got != 1 {
			t.Fatalf("strictness=%d: Config().EnvStrictness = %d, want 1", strictness, got)
		}
	}
}

/**
 * TestCaptchaSessionRedeemedOnlyOnceUnderConcurrency 验证验证码会话在并发提交
 * 同一个正确答案时只能被兑换一次。
 */
func TestCaptchaSessionRedeemedOnlyOnceUnderConcurrency(t *testing.T) {
	cm := NewCaptchaManager(nil, 0)
	defer cm.Close()

	sessionID := "captcha-concurrent"
	cm.sessions[sessionID] = &CaptchaSession{
		ID:        sessionID,
		Type:      CaptchaTypeMath,
		Answer:    "42",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}

	const workers = 32
	var passed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if cm.Verify(sessionID, "42") {
				passed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := passed.Load(); got != 1 {
		t.Fatalf("captcha answer was accepted %d times, want exactly 1", got)
	}
}

/**
 * TestCaptchaAdvancedSessionRedeemedOnlyOnce 验证高级验证码（点击/滑动/旋转）
 * 会话同样受一次性约束。
 */
func TestCaptchaAdvancedSessionRedeemedOnlyOnce(t *testing.T) {
	cm := NewCaptchaManager(nil, 0)
	defer cm.Close()

	sessionID := "captcha-advanced-once"
	// stored answer 必须带 dx/dy：它们是滑块初始绘制位置，slide.Validate 的 sx/sy
	// 契约是绝对坐标，而前端提交的是相对位移量，校验时需要 dx+offset 换算。
	// 用户提交 x=90 对应绝对坐标 30+90=120，正好命中目标 x=120。
	cm.sessions[sessionID] = &CaptchaSession{
		ID:        sessionID,
		Type:      CaptchaTypeSlide,
		Answer:    `{"x":120,"y":60,"dx":30,"dy":60}`,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}

	const workers = 16
	var passed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, _ := cm.VerifyAdvancedSession(sessionID, `{"x":90}`); ok {
				passed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := passed.Load(); got != 1 {
		t.Fatalf("advanced captcha answer was accepted %d times, want exactly 1", got)
	}
}

/**
 * TestChainProcessStepConcurrentSameSession 验证并发提交同一个 chain 会话时
 * 不会出现 data race，并且状态机不会被并发重复推进。
 *
 * 复现（修复前）：loadChainState 在内存模式下直接返回 map 中的共享指针，
 * ProcessStep 在锁外修改 state.CurrentStep / state.Scores，`go test -race`
 * 报告数据竞争，并发写 map 还可能触发 fatal "concurrent map writes"。
 */
func TestChainProcessStepConcurrentSameSession(t *testing.T) {
	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	mgr := NewChainChallengeManager(captcha, nil)
	defer mgr.Close()

	mgr.Reconfigure([]ChainStepConfig{
		{Type: ChainStepEnv, Condition: "all"},
		{Type: ChainStepEnv, Condition: "all"},
		{Type: ChainStepEnv, Condition: "all"},
	}, 1)

	sessionID, _ := mgr.StartChain("/protected")
	envFP := `{"webdriver":false,"chrome_present":true,"plugins_count":3}`

	const workers = 24
	var completed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, _, _ := mgr.ProcessStep(sessionID, map[string]string{"env_fp": envFP}); ok {
				completed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	// 3 个步骤的链路最多只能被“走完”一次，不允许多个并发请求同时拿到通行结果。
	if got := completed.Load(); got > 1 {
		t.Fatalf("chain challenge completed %d times for one session, want at most 1", got)
	}
}

/**
 * TestChainStateExpires 验证过期的 chain 状态不再可用（内存模式）。
 *
 * 复现（修复前）：loadChainState 不检查 CreatedAt，且 ChainChallengeManager
 * 没有清理协程，内存模式下 chain 会话永久有效且永不释放。
 */
func TestChainStateExpires(t *testing.T) {
	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	mgr := NewChainChallengeManager(captcha, nil)
	defer mgr.Close()

	sessionID, _ := mgr.StartChain("/protected")

	mgr.mu.Lock()
	state := mgr.states[sessionID]
	if state == nil {
		mgr.mu.Unlock()
		t.Fatal("expected in-memory chain state to exist")
	}
	state.CreatedAt = time.Now().Add(-2 * chainStateTTL)
	mgr.mu.Unlock()

	if ok, _, html := mgr.ProcessStep(sessionID, map[string]string{"env_fp": "{}"}); ok || html != "" {
		t.Fatalf("expired chain state must not be processable: ok=%v html=%q", ok, html)
	}
	if got := mgr.ListSessions(); len(got) != 0 {
		t.Fatalf("expired chain state must not be listed, got %+v", got)
	}
}

/**
 * TestChainStateCleanupRemovesExpired 验证清理逻辑会释放过期的内存态 chain 会话。
 */
func TestChainStateCleanupRemovesExpired(t *testing.T) {
	captcha := NewCaptchaManager(nil, 0)
	defer captcha.Close()
	mgr := NewChainChallengeManager(captcha, nil)
	defer mgr.Close()

	sessionID, _ := mgr.StartChain("/protected")
	mgr.mu.Lock()
	mgr.states[sessionID].CreatedAt = time.Now().Add(-2 * chainStateTTL)
	mgr.mu.Unlock()

	mgr.purgeExpiredStates(time.Now())

	mgr.mu.RLock()
	remaining := len(mgr.states)
	mgr.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("purgeExpiredStates() left %d expired states", remaining)
	}
}

/**
 * TestChallengeTokenBoundToClient 验证 JS 挑战 token 绑定到客户端身份，
 * 无法被其他 IP / User-Agent / 站点复用。
 *
 * 复现（修复前）：token = HMAC(reqID + ":" + ts)，不含任何客户端信息，
 * 任意客户端拿到页面里的 rid/ts/token 三元组即可获得通行 cookie。
 */
func TestChallengeTokenBoundToClient(t *testing.T) {
	owner := ChallengeTokenClaims{ClientIP: "203.0.113.10", UserAgent: "Mozilla/5.0 owner", Host: "a.example", SiteID: 7}
	reqID := "req-bound-1"
	ts, token := GenerateChallengeTokenPairWithClaims(reqID, owner)

	if !VerifyChallengeTokenWithClaims(reqID, ts, token, owner, 5*time.Minute) {
		t.Fatal("token must verify for the client it was issued to")
	}

	others := []struct {
		name   string
		claims ChallengeTokenClaims
	}{
		{"other ip", ChallengeTokenClaims{ClientIP: "198.51.100.5", UserAgent: owner.UserAgent, Host: owner.Host, SiteID: owner.SiteID}},
		{"other ua", ChallengeTokenClaims{ClientIP: owner.ClientIP, UserAgent: "curl/8.0", Host: owner.Host, SiteID: owner.SiteID}},
		{"other host", ChallengeTokenClaims{ClientIP: owner.ClientIP, UserAgent: owner.UserAgent, Host: "b.example", SiteID: owner.SiteID}},
		{"other site", ChallengeTokenClaims{ClientIP: owner.ClientIP, UserAgent: owner.UserAgent, Host: owner.Host, SiteID: 8}},
	}
	for _, tt := range others {
		t.Run(tt.name, func(t *testing.T) {
			if VerifyChallengeTokenWithClaims(reqID, ts, token, tt.claims, 5*time.Minute) {
				t.Fatalf("token must not verify for %s", tt.name)
			}
		})
	}
}

/**
 * TestChallengeTokenSingleUse 验证 JS 挑战 token 只能兑换一次。
 *
 * 复现（修复前）：VerifyChallengeToken 是纯 HMAC 校验，在 maxAge 内可无限重放，
 * 一份被抓取的挑战页可以让整个 botnet 反复换取通行 cookie。
 */
func TestChallengeTokenSingleUse(t *testing.T) {
	claims := ChallengeTokenClaims{ClientIP: "203.0.113.11", UserAgent: "ua", Host: "a.example", SiteID: 1}
	reqID := "req-single-use"
	ts, token := GenerateChallengeTokenPairWithClaims(reqID, claims)

	if !VerifyChallengeTokenWithClaims(reqID, ts, token, claims, 5*time.Minute) {
		t.Fatal("first redemption must pass")
	}
	if VerifyChallengeTokenWithClaims(reqID, ts, token, claims, 5*time.Minute) {
		t.Fatal("replayed challenge token must be rejected")
	}
}

/**
 * TestChallengeTokenSingleUseUnderConcurrency 验证并发重放挑战 token 只有一个成功。
 */
func TestChallengeTokenSingleUseUnderConcurrency(t *testing.T) {
	claims := ChallengeTokenClaims{ClientIP: "203.0.113.12", UserAgent: "ua", Host: "a.example", SiteID: 1}
	reqID := "req-concurrent-use"
	ts, token := GenerateChallengeTokenPairWithClaims(reqID, claims)

	const workers = 32
	var passed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if VerifyChallengeTokenWithClaims(reqID, ts, token, claims, 5*time.Minute) {
				passed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := passed.Load(); got != 1 {
		t.Fatalf("challenge token accepted %d times, want exactly 1", got)
	}
}

/**
 * TestChallengeTokenExpires 验证过期的挑战 token 被拒绝，且未来时间戳同样被拒绝。
 */
func TestChallengeTokenExpires(t *testing.T) {
	claims := ChallengeTokenClaims{ClientIP: "203.0.113.13", UserAgent: "ua", Host: "a.example", SiteID: 1}
	reqID := "req-expiry"
	ts, token := GenerateChallengeTokenPairWithClaims(reqID, claims)
	if VerifyChallengeTokenWithClaims(reqID, ts, token, claims, time.Nanosecond) {
		t.Fatal("expired challenge token must be rejected")
	}

	futureTS := fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix())
	futureToken := signChallengeToken("req-future", futureTS, claims)
	if VerifyChallengeTokenWithClaims("req-future", futureTS, futureToken, claims, 5*time.Minute) {
		t.Fatal("challenge token with future timestamp must be rejected")
	}
}

/**
 * TestMathCaptchaAnswerSpaceIsWide 验证内置算式验证码的答案空间足够大、
 * 单一定值猜测的命中率足够低。
 *
 * 复现（修复前）：a∈[1,50]、b∈[1,30] 且只有加减两种运算，答案集中在
 * 极小区间内，猜测最高频答案的命中率约为百分之几，配合无限次重新取题
 * 即可暴力绕过验证码。
 */
func TestMathCaptchaAnswerSpaceIsWide(t *testing.T) {
	const samples = 20000
	freq := make(map[int]int, samples)
	for i := 0; i < samples; i++ {
		expr, answer := randomMathProblem()
		if answer < mathAnswerMin || answer > mathAnswerMax {
			t.Fatalf("answer %d outside declared range for %q", answer, expr)
		}
		freq[answer]++
	}

	maxCount := 0
	for _, n := range freq {
		if n > maxCount {
			maxCount = n
		}
	}
	best := float64(maxCount) / float64(samples)
	if best > 0.01 {
		t.Fatalf("most frequent math captcha answer hit rate = %.4f (>1%%), distinct answers = %d", best, len(freq))
	}
	if len(freq) < 200 {
		t.Fatalf("math captcha answer space too small: %d distinct answers", len(freq))
	}
}

/**
 * TestMathCaptchaExpressionMatchesAnswer 验证生成的题面与存储答案一致，
 * 且渲染后的题面不会超出验证码画布宽度。
 */
func TestMathCaptchaExpressionMatchesAnswer(t *testing.T) {
	for i := 0; i < 2000; i++ {
		expr, answer := randomMathProblem()
		var a, b, got int
		var op string
		if _, err := fmt.Sscanf(expr, "%d %s %d = ?", &a, &op, &b); err != nil {
			t.Fatalf("unparsable expression %q: %v", expr, err)
		}
		switch op {
		case "+":
			got = a + b
		case "-":
			got = a - b
		default:
			t.Fatalf("unexpected operator %q in %q", op, expr)
		}
		if got != answer {
			t.Fatalf("expression %q evaluates to %d, stored answer is %d", expr, got, answer)
		}
		if w := mathExpressionPixelWidth(expr); w > 200 {
			t.Fatalf("expression %q renders %dpx wide, exceeds the 200px captcha canvas", expr, w)
		}
	}
}

// mathExpressionPixelWidth 按 drawText 的排版规则估算题面渲染宽度（含 startX=20）。
func mathExpressionPixelWidth(expr string) int {
	x := 20
	for _, ch := range expr {
		pattern := getCharPattern(ch)
		if pattern == nil {
			x += 12
			continue
		}
		x += len(pattern[0])*2 + 4
	}
	return x
}

/**
 * TestVerifyPoWRejectsMalformedInput 验证 PoW 校验对畸形输入与非法难度的处理。
 */
func TestVerifyPoWRejectsMalformedInput(t *testing.T) {
	nonce := "abc123"
	counter, hash := findShieldPoWSolution(t, nonce, 2)

	if !VerifyPoW(nonce, counter, hash, 2) {
		t.Fatal("valid PoW solution must verify")
	}
	if VerifyPoW(nonce, counter, strings.ToUpper(hash), 2) {
		t.Fatal("uppercase hash must not be accepted as a different encoding bypass")
	}
	if VerifyPoW(nonce, counter, hash, 0) {
		t.Fatal("difficulty 0 must be rejected instead of accepting zero-work solutions")
	}
	if VerifyPoW(nonce, counter, hash, -1) {
		t.Fatal("negative difficulty must be rejected")
	}
	if VerifyPoW(nonce, counter+1, hash, 2) {
		t.Fatal("hash/counter mismatch must be rejected")
	}
	if VerifyPoW(nonce, counter, "00", 2) {
		t.Fatal("truncated hash must be rejected")
	}
	if VerifyPoW(nonce, counter, "00"+strings.Repeat("z", 62), 2) {
		t.Fatal("non-hex hash must be rejected")
	}
	if VerifyPoW(nonce, counter, hash, maxPoWDifficulty+1) {
		t.Fatal("difficulty above the supported maximum must be rejected")
	}
}

/**
 * TestSetChallengeSecretIsRaceFree 验证挑战密钥的读写是并发安全的。
 */
func TestSetChallengeSecretIsRaceFree(t *testing.T) {
	original := loadChallengeSecret()
	t.Cleanup(func() { SetChallengeSecret(original) })

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			secret := []byte(fmt.Sprintf("secret-%032d", n))
			for j := 0; j < 50; j++ {
				SetChallengeSecret(secret)
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claims := ChallengeTokenClaims{ClientIP: "203.0.113.20", UserAgent: "ua", Host: "a.example", SiteID: 1}
			for j := 0; j < 50; j++ {
				ts, token := GenerateChallengeTokenPairWithClaims(fmt.Sprintf("rid-%d", j), claims)
				_ = ts
				_ = token
				_ = SignChallengePassValue("a.example", nil, time.Now(), time.Hour)
			}
		}()
	}
	wg.Wait()
}

/**
 * TestVerifyRotateAnswerRejectsOutOfRangeAngles 验证旋转验证码拒绝超出 0 到 360 度范围的输入，并遵循 go-captcha 的补偿角契约。
 */
func TestVerifyRotateAnswerRejectsOutOfRangeAngles(t *testing.T) {
	stored := `{"angle":90}`
	for _, answer := range []string{
		`{"angle":1000000}`,
		`{"angle":-1000000}`,
		`{"angle":450}`,
	} {
		if verifyRotateAnswer(stored, answer, 10) {
			t.Fatalf("verifyRotateAnswer accepted out-of-range answer %s", answer)
		}
	}
	for _, test := range []struct {
		name   string
		answer string
		want   bool
	}{
		{name: "exact compensation", answer: `{"angle":270}`, want: true},
		{name: "within compensation tolerance", answer: `{"angle":265}`, want: true},
		{name: "same angle is not compensation", answer: `{"angle":90}`, want: false},
		{name: "missing angle", answer: `{}`, want: false},
		{name: "wrong angle type", answer: `{"angle":"270"}`, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := verifyRotateAnswer(stored, test.answer, 10); got != test.want {
				t.Fatalf("verifyRotateAnswer(%s) = %v, want %v", test.answer, got, test.want)
			}
		})
	}
}
