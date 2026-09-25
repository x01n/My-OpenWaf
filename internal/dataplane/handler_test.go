package dataplane

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/antireplay"
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/challenge/gm"
	"My-OpenWaf/internal/waf/challenge/powdata"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/luaplugin"
	"My-OpenWaf/internal/waf/pages"
	"My-OpenWaf/internal/waf/ratelimit"
)

/* 站点级质询策略（challenge_action / captcha_type）渲染链路测试。 */

// TestHandlerSiteChallengeActionOverridesGlobal 覆盖站点级质询动作优先级：
// 命中通用 challenge 动作时，站点配置 render 到 captcha 流；验证码类型
// 规则级 → 站点 → 全局 的链在站点覆盖存在时取站点值。
func TestHandlerSiteChallengeActionOverridesGlobal(t *testing.T) {
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	protection.CaptchaEnabled = true
	protection.CaptchaType = "rotate"

	challengeAction := "captcha_challenge"
	captchaType := "slide"
	rt := &snapshot.SiteRuntime{
		Site:                 store.Site{ID: 1, Host: "site-challenge-override.example.com", Bind: ":80"},
		Bind:                 ":80",
		ChallengeAction:      challengeAction,
		ChallengeCaptchaType: captchaType,
		Rules: []snapshot.CompiledRule{{
			ID:       85,
			Phase:    store.PhaseCustom,
			Kind:     "block_path_exact",
			Arg:      "/guarded",
			Action:   store.ActionChallenge, // 规则动作是通用 challenge
			Priority: 1,
		}},
		EffectiveProtection: &protection,
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", rt.Site.Host): rt,
		},
	})

	captchaManager := challenge.NewCaptchaManager(nil, 0)
	captchaManager.SetGoCaptchaProvider(challenge.NewGoCaptchaProvider(challenge.DefaultGoCaptchaConfig(), slog.Default()))
	defer captchaManager.Close()
	handler := Handler(Options{
		Holder:         holder,
		Engine:         engine.New(holder, nil, nil, nil),
		Log:            slog.Default(),
		Bind:           ":80",
		CaptchaManager: captchaManager,
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/guarded")
	ctx.Request.Header.SetHost(rt.Site.Host)

	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
	}
	body := string(ctx.Response.Body())
	if !strings.Contains(body, `action="/__owaf/captcha/verify"`) {
		t.Fatalf("site challenge_action did not select captcha render: %s", body)
	}
	// 题目类型不再以明文 DOM（slide-range 等）下发，类型选择由加密信封承载：
	// 解密信封里 type 必须等于站点 captcha_type（slide）。
	if strings.Contains(body, `id="slide-range"`) || strings.Contains(body, `id="rotate-range"`) {
		t.Fatalf("site captcha_type must not leak typed challenge DOM in plaintext: %s", body)
	}
	// 解出信封校验类型：站点 slide 必须生效。
	sessionID := extractCaptchaSessionFromPage(t, body)
	if sessionID == "" {
		t.Fatal("captcha page did not expose session id")
	}
	if got := captchaEnvelopeType(t, captchaManager, sessionID, body); got != "slide" {
		t.Fatalf("site captcha_type did not select slide captcha: got %q", got)
	}
	if strings.Contains(body, "__waf_challenge_token") {
		t.Fatal("site override fell back to generic JS challenge token")
	}
}

// extractCaptchaSessionFromPage 从渲染后的验证码页 HTML 里提取会话 ID。
// session 隐藏域或 JS 绑定都可能携带它；本辅助只做渲染断言，不改渲染链路。
func extractCaptchaSessionFromPage(t *testing.T, body string) string {
	t.Helper()
	// __waf_captcha_session 隐藏域 value 即会话 ID。
	idx := strings.Index(body, `name="__waf_captcha_session"`)
	if idx < 0 {
		return ""
	}
	rest := body[idx:]
	eq := strings.Index(rest, `value=`)
	if eq < 0 {
		return ""
	}
	rest = rest[eq+len(`value=`):]
	quote := rest[0]
	if quote != '"' && quote != '\'' {
		return ""
	}
	end := strings.Index(rest[1:], string(quote))
	if end < 0 {
		return ""
	}
	return rest[1 : 1+end]
}

// captchaEnvelopeType 从页面信封解出题目类型，与内存会话密钥对账。
// 信封断言走真实解密链路（session EnvKey + envDecrypt），确保页面下发物可还原。
func captchaEnvelopeType(t *testing.T, manager *challenge.CaptchaManager, sessionID, body string) string {
	t.Helper()
	dataIdx := strings.Index(body, `id="cap-data"`)
	if dataIdx < 0 {
		return ""
	}
	rest := body[dataIdx:]
	eq := strings.Index(rest, `value=`)
	if eq < 0 {
		return ""
	}
	rest = rest[eq+len(`value=`):]
	if len(rest) == 0 || (rest[0] != '"' && rest[0] != '\'') {
		return ""
	}
	quote := rest[0]
	end := strings.Index(rest[1:], string(quote))
	if end < 0 {
		return ""
	}
	envelope := rest[1 : 1+end]
	_, envKey, _, found := challenge.CaptchaManagerPendingForTest(manager, sessionID)
	if !found || len(envKey) != 32 {
		t.Fatalf("pending captcha session %q env key missing", sessionID)
	}
	payload := challenge.DecryptChallengeData(envelope, envKey)
	if payload == nil {
		t.Fatal("page envelope did not decrypt with session key")
	}
	return payload.Type
}

// TestHandlerGlobalChallengeActionOverrides 覆盖全局质询动作优先级：
// 站点未配置时，全局 ProtectionConfig.ChallengeAction 生效。
func TestHandlerGlobalChallengeActionOverrides(t *testing.T) {
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	protection.CaptchaEnabled = true
	protection.CaptchaType = "math"
	protection.ChallengeAction = "chain_challenge"
	protection.ChainEnabled = true

	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 2, Host: "global-challenge-override.example.com", Bind: ":80"},
		Bind: ":80",
		Rules: []snapshot.CompiledRule{{
			ID: 86, Phase: store.PhaseCustom, Kind: "block_path_exact", Arg: "/guarded",
			Action: store.ActionChallenge, Priority: 1,
		}},
		EffectiveProtection: &protection,
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision: 1, Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{snapshot.SiteMapKey(":80", rt.Site.Host): rt},
	})

	captchaManager := challenge.NewCaptchaManager(nil, 0)
	defer captchaManager.Close()
	shieldManager := challenge.NewShieldManager(captchaManager, nil, 1)
	defer shieldManager.Close()
	chainManager := challenge.NewChainChallengeManager(captchaManager, nil)
	defer chainManager.Close()
	handler := Handler(Options{
		Holder: holder, Engine: engine.New(holder, nil, nil, nil), Log: slog.Default(),
		Bind: ":80", CaptchaManager: captchaManager, ShieldManager: shieldManager, ChainManager: chainManager,
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/guarded")
	ctx.Request.Header.SetHost(rt.Site.Host)

	handler(context.Background(), ctx)
	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got)
	}
	body := string(ctx.Response.Body())
	if !strings.Contains(body, `action='/__owaf/chain/verify'`) {
		t.Fatalf("global challenge_action did not select chain render: %s", body)
	}
	if strings.Contains(body, "__waf_challenge_token") {
		t.Fatal("global override fell back to generic JS challenge token")
	}
}

// TestHandlerRuleCaptchaTypeBeatsSiteAndSiteBeatsGlobal 覆盖验证码类型优先级链
// 规则级 > 站点 > 全局：规则带 rotate、站点带 slide、全局 math 时取规则 rotate。
func TestHandlerRuleCaptchaTypeBeatsSiteAndSiteBeatsGlobal(t *testing.T) {
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	protection.CaptchaEnabled = true
	protection.CaptchaType = "math"

	rt := &snapshot.SiteRuntime{
		Site:                 store.Site{ID: 3, Host: "rule-captcha-chain.example.com", Bind: ":80"},
		Bind:                 ":80",
		ChallengeCaptchaType: "slide",
		Rules: []snapshot.CompiledRule{{
			ID: 87, Phase: store.PhaseCustom, Kind: "block_path_exact", Arg: "/guarded",
			Action: store.ActionCaptchaChallenge, CaptchaType: "rotate", Priority: 1,
		}},
		EffectiveProtection: &protection,
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision: 1, Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{snapshot.SiteMapKey(":80", rt.Site.Host): rt},
	})
	captchaManager := challenge.NewCaptchaManager(nil, 0)
	captchaManager.SetGoCaptchaProvider(challenge.NewGoCaptchaProvider(challenge.DefaultGoCaptchaConfig(), slog.Default()))
	defer captchaManager.Close()
	handler := Handler(Options{
		Holder: holder, Engine: engine.New(holder, nil, nil, nil), Log: slog.Default(),
		Bind: ":80", CaptchaManager: captchaManager,
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/guarded")
	ctx.Request.Header.SetHost(rt.Site.Host)

	handler(context.Background(), ctx)
	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got)
	}
	body := string(ctx.Response.Body())
	sessionID := extractCaptchaSessionFromPage(t, body)
	if sessionID == "" {
		t.Fatal("captcha page did not expose session id")
	}
	if got := captchaEnvelopeType(t, captchaManager, sessionID, body); got != "rotate" {
		t.Fatalf("rule captcha_type did not beat site/global: got %q, want rotate", got)
	}
	// 题目类型以加密信封承载，明文 DOM 不得出现类型化题目结构。
	if strings.Contains(body, `id="rotate-range"`) || strings.Contains(body, `id="slide-range"`) {
		t.Fatalf("rule captcha_type leaked typed challenge DOM: %s", body)
	}
}

// TestHandlerGlobalChallengeActionEmptyRendersDefaultChallenge 覆盖全局
// ProtectionConfig.ChallengeAction 为空串（旧数据兼容路径）时的回退：
// 命中通用 challenge 动作渲染默认 JS 挑战页，不崩溃、不 500。
func TestHandlerGlobalChallengeActionEmptyRendersDefaultChallenge(t *testing.T) {
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	protection.ChallengeAction = ""

	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 4, Host: "empty-global-challenge.example.com", Bind: ":80"},
		Bind: ":80",
		Rules: []snapshot.CompiledRule{{
			ID: 88, Phase: store.PhaseCustom, Kind: "block_path_exact", Arg: "/guarded",
			Action: store.ActionChallenge, Priority: 1,
		}},
		EffectiveProtection: &protection,
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision: 1, Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{snapshot.SiteMapKey(":80", rt.Site.Host): rt},
	})
	handler := Handler(Options{
		Holder: holder, Engine: engine.New(holder, nil, nil, nil), Log: slog.Default(),
		Bind: ":80",
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/guarded")
	ctx.Request.Header.SetHost(rt.Site.Host)

	handler(context.Background(), ctx)
	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got)
	}
	body := string(ctx.Response.Body())
	if !strings.Contains(body, "__waf_challenge_token") {
		t.Fatalf("empty global challenge_action should render default JS challenge: %s", body)
	}
}

/* 原有测试区（不含本节新增用例；以下为既有测试的延续）。 */

type trackingRequestBodyStream struct {
	reader io.Reader
	closed bool
}

func (s *trackingRequestBodyStream) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *trackingRequestBodyStream) Close() error {
	s.closed = true
	return nil
}

type closeSensitiveRequestBodyStream struct {
	reader io.Reader
	closed bool
}

func (s *closeSensitiveRequestBodyStream) Read(p []byte) (int, error) {
	if s.closed {
		return 0, errors.New("stream closed before replay completed")
	}
	return s.reader.Read(p)
}

func (s *closeSensitiveRequestBodyStream) Close() error {
	s.closed = true
	return nil
}

type unexpectedEOFRequestBodyStream struct {
	reader     io.Reader
	emittedEOF bool
}

type blockingRequestBodyReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type handlerLuaKV struct{}

func (handlerLuaKV) Available() bool { return true }
func (handlerLuaKV) AvailableContext(ctx context.Context) bool {
	return ctx == nil || ctx.Err() == nil
}
func (handlerLuaKV) Get(string) ([]byte, bool)                         { return nil, false }
func (handlerLuaKV) Set(string, []byte, time.Duration) error           { return nil }
func (handlerLuaKV) Delete(string)                                     {}
func (handlerLuaKV) Incr(string, time.Duration) (int64, error)         { return 1, nil }
func (handlerLuaKV) GetContext(context.Context, string) ([]byte, bool) { return nil, false }
func (handlerLuaKV) SetContext(context.Context, string, []byte, time.Duration) error {
	return nil
}
func (handlerLuaKV) DeleteContext(context.Context, string) {}
func (handlerLuaKV) IncrContext(context.Context, string, time.Duration) (int64, error) {
	return 1, nil
}

func (r *blockingRequestBodyReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return 0, io.EOF
}

func (s *unexpectedEOFRequestBodyStream) Read(p []byte) (int, error) {
	n, err := s.reader.Read(p)
	if err == io.EOF && !s.emittedEOF {
		s.emittedEOF = true
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func (s *unexpectedEOFRequestBodyStream) Close() error {
	return nil
}

func TestNormalizeAntiReplayActionKeepsChallengeActions(t *testing.T) {
	cases := map[string]string{
		"":                  "challenge",
		"shield_challenge":  "shield_challenge",
		"captcha_challenge": "captcha_challenge",
		"chain_challenge":   "chain_challenge",
		"block":             "intercept",
		"drop":              "challenge",
	}
	for input, want := range cases {
		if got := normalizeAntiReplayAction(input); got != want {
			t.Fatalf("normalizeAntiReplayAction(%q) = %q, want %q", input, got, want)
		}
	}
}

/**
 * TestDataPlanePoWAssetsServeCompressedEmbeddedBytes 验证数据面在站点解析前服务
 * PoW 运行时资源，且 gzip 解压后的内容与嵌入资源一致。
 */
func TestDataPlanePoWAssetsServeCompressedEmbeddedBytes(t *testing.T) {
	handler := Handler(Options{Log: slog.Default()})

	for _, tt := range []struct {
		path        string
		contentType string
		want        []byte
	}{
		{path: "/__owaf/pow.wasm", contentType: "application/wasm", want: powdata.WASMBinary},
		{path: "/__owaf/pow_glue.js", contentType: "application/javascript", want: powdata.PowGlueJS},
	} {
		t.Run(tt.path, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.SetMethod("GET")
			ctx.Request.SetRequestURI(tt.path)
			handler(context.Background(), ctx)

			if ctx.Response.StatusCode() != 200 {
				t.Fatalf("GET %s status = %d, want 200", tt.path, ctx.Response.StatusCode())
			}
			if got := string(ctx.Response.Header.ContentType()); got != tt.contentType {
				t.Fatalf("GET %s Content-Type = %q, want %q", tt.path, got, tt.contentType)
			}
			if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
				t.Fatalf("GET %s Content-Encoding = %q, want gzip", tt.path, got)
			}

			gz, err := gzip.NewReader(bytes.NewReader(ctx.Response.Body()))
			if err != nil {
				t.Fatalf("GET %s gzip reader: %v", tt.path, err)
			}
			got, err := io.ReadAll(gz)
			if closeErr := gz.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				t.Fatalf("GET %s decompress: %v", tt.path, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("GET %s decompressed body differs from embedded bytes", tt.path)
			}
		})
	}
}

func TestHandlerFinalizesInternalEndpointAccessLogWithFingerprint(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler := Handler(Options{Writer: writer, AccessLogSamplingRate: 0})
	ctx := app.NewContext(0)
	ctx.Request.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/__owaf/pow_glue.js")
	fp := bot.TLSClientFingerprint{TLSVersion: "TLS13", JA3Hash: "ja3-internal", JA4: "ja4-internal"}
	handler(ContextWithTLSFingerprint(context.Background(), fp), ctx)
	writer.Close()

	requestID := string(ctx.Response.Header.Peek("X-Request-ID"))
	var entry store.AccessLog
	if err := db.Where("request_id = ?", requestID).First(&entry).Error; err != nil {
		t.Fatalf("read internal endpoint access log: %v", err)
	}
	if entry.StatusCode != http.StatusOK || entry.Path != "/__owaf/pow_glue.js" {
		t.Fatalf("internal endpoint access log = %#v", entry)
	}
	if entry.TLSVersion != fp.TLSVersion || entry.TLSJA3Hash != fp.JA3Hash || entry.TLSJA4 != fp.JA4 {
		t.Fatalf("internal endpoint access log lost TLS fingerprint: %#v", entry)
	}
}

func TestHandleDynamicProtectionKeyRecordsErrorStatuses(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "dynamic-key-logs.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate logs: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer writer.Close()

	rt := snapshot.SiteRuntime{
		Site: store.Site{ID: 7, Host: "dynamic-key.example.test", Bind: ":80"},
	}
	siteHolder := &snapshot.Holder{}
	siteHolder.Store(&snapshot.Snapshot{
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "dynamic-key.example.test"): &rt,
		},
	})
	emptyHolder := &snapshot.Holder{}
	emptyHolder.Store(&snapshot.Snapshot{Sites: map[string]*snapshot.SiteRuntime{}})
	notLoadedHolder := &snapshot.Holder{}

	cases := []struct {
		name       string
		method     string
		body       []byte
		holder     *snapshot.Holder
		host       string
		wantStatus int
		wantAction string
	}{
		{name: "method", method: http.MethodGet, host: "dynamic-key.example.test", holder: notLoadedHolder, wantStatus: http.StatusMethodNotAllowed, wantAction: "dynamic_key_error"},
		{name: "body_too_large", method: http.MethodPost, host: "dynamic-key.example.test", holder: notLoadedHolder, body: bytes.Repeat([]byte("x"), dynamicProtectionKeyRequestBodyMax+1), wantStatus: http.StatusRequestEntityTooLarge, wantAction: "dynamic_key_error"},
		{name: "invalid_json", method: http.MethodPost, host: "dynamic-key.example.test", holder: notLoadedHolder, body: []byte("{"), wantStatus: http.StatusBadRequest, wantAction: "dynamic_key_error"},
		{name: "snapshot_not_loaded", method: http.MethodPost, host: "dynamic-key.example.test", holder: notLoadedHolder, body: []byte(`{"ticket":"bad","key":"k"}`), wantStatus: http.StatusServiceUnavailable, wantAction: "dynamic_key_error"},
		{name: "site_not_found", method: http.MethodPost, host: "missing-dynamic-key.example.test", holder: emptyHolder, body: []byte(`{"ticket":"bad","key":"k"}`), wantStatus: http.StatusNotFound, wantAction: "dynamic_key_error"},
		{name: "ticket_rejected", method: http.MethodPost, host: "dynamic-key.example.test", holder: siteHolder, body: []byte(`{"ticket":"bad","key":"k"}`), wantStatus: http.StatusForbidden, wantAction: "dynamic_key_error"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.SetMethod(tt.method)
			ctx.Request.SetRequestURI(dynamicProtectionKeyPath + "?token=dynamic-key-secret&mode=test")
			ctx.Request.Header.SetHost(tt.host)
			if len(tt.body) > 0 {
				ctx.Request.SetBody(tt.body)
			}
			handled := handleDynamicProtectionKey(ctx, Options{
				Holder: tt.holder,
				Writer: writer,
				Bind:   ":80",
				Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			if !handled {
				t.Fatal("dynamic key endpoint was not handled")
			}
			if got := ctx.Response.StatusCode(); got != tt.wantStatus {
				t.Fatalf("status = %d, want %d", got, tt.wantStatus)
			}
		})
	}

	writer.Close()
	var entries []store.AccessLog
	if err := db.Where("path = ?", dynamicProtectionKeyPath).Find(&entries).Error; err != nil {
		t.Fatalf("read dynamic key access logs: %v", err)
	}
	if len(entries) != len(cases) {
		t.Fatalf("dynamic key access logs = %d, want %d", len(entries), len(cases))
	}
	seen := make(map[string]int, len(entries))
	for _, entry := range entries {
		key := strconv.Itoa(entry.StatusCode) + ":" + entry.WAFAction
		seen[key]++
		if entry.RequestBodyPreview != "[redacted]" {
			t.Fatalf("dynamic key request body = %q, want [redacted]", entry.RequestBodyPreview)
		}
		if entry.QueryString != "mode=test&token=%5Bredacted%5D" {
			t.Fatalf("dynamic key query = %q, want sanitized query", entry.QueryString)
		}
	}
	for _, tt := range cases {
		key := strconv.Itoa(tt.wantStatus) + ":" + tt.wantAction
		if seen[key] != 1 {
			t.Fatalf("access log %s count = %d, want 1", key, seen[key])
		}
	}
}

func TestRequestBodySamplePreservesBodyStreamForForwarding(t *testing.T) {
	body := []byte(strings.Repeat("streamed-request-body-", 4096))

	ctx := app.NewContext(0)
	ctx.Request.Header.SetContentLength(len(body))
	stream := &trackingRequestBodyStream{reader: bytes.NewReader(body)}
	ctx.Request.SetBodyStream(stream, len(body))

	sample, truncated, size := requestBodySample(ctx)
	if len(sample) != requestInspectionBodyLimit {
		t.Fatalf("sample length = %d, want %d", len(sample), requestInspectionBodyLimit)
	}
	if !truncated {
		t.Fatal("expected truncated sample for oversized stream body")
	}
	if size != int64(len(body)) {
		t.Fatalf("sample size = %d, want %d", size, len(body))
	}
	if !bytes.Equal(sample, body[:requestInspectionBodyLimit]) {
		t.Fatal("sample prefix mismatch")
	}

	replayed, err := io.ReadAll(ctx.Request.BodyStream())
	if err != nil {
		t.Fatalf("read replayed body stream: %v", err)
	}
	if !bytes.Equal(replayed, body) {
		t.Fatalf("replayed body mismatch: got %d bytes want %d bytes", len(replayed), len(body))
	}
	if err := ctx.Request.CloseBodyStream(); err != nil {
		t.Fatalf("CloseBodyStream returned error: %v", err)
	}
	if stream.closed {
		t.Fatal("forwarding stream close must not close the original Hertz stream")
	}
	restoreOriginalRequestBodyStream(ctx)
	if err := ctx.Request.CloseBodyStream(); err != nil {
		t.Fatalf("close restored original stream: %v", err)
	}
	if !stream.closed {
		t.Fatal("expected Hertz cleanup to close the restored original stream")
	}
}

func TestRequestBodySampleDoesNotCloseOriginalStreamDuringRebind(t *testing.T) {
	body := []byte(strings.Repeat("streamed-request-body-", 4096))

	ctx := app.NewContext(0)
	ctx.Request.Header.SetContentLength(len(body))
	stream := &closeSensitiveRequestBodyStream{reader: bytes.NewReader(body)}
	ctx.Request.SetBodyStream(stream, len(body))

	sample, truncated, size := requestBodySample(ctx)
	if len(sample) != requestInspectionBodyLimit {
		t.Fatalf("sample length = %d, want %d", len(sample), requestInspectionBodyLimit)
	}
	if !truncated {
		t.Fatal("expected truncated sample for oversized stream body")
	}
	if size != int64(len(body)) {
		t.Fatalf("sample size = %d, want %d", size, len(body))
	}
	if stream.closed {
		t.Fatal("original stream must not be closed during request body rebind")
	}

	replayed, err := io.ReadAll(ctx.Request.BodyStream())
	if err != nil {
		t.Fatalf("read replayed body stream: %v", err)
	}
	if !bytes.Equal(replayed, body) {
		t.Fatalf("replayed body mismatch: got %d bytes want %d bytes", len(replayed), len(body))
	}
	if err := ctx.Request.CloseBodyStream(); err != nil {
		t.Fatalf("CloseBodyStream returned error: %v", err)
	}
	if stream.closed {
		t.Fatal("forwarding stream close must not close the original Hertz stream")
	}
	restoreOriginalRequestBodyStream(ctx)
	if err := ctx.Request.CloseBodyStream(); err != nil {
		t.Fatalf("close restored original stream: %v", err)
	}
	if !stream.closed {
		t.Fatal("expected Hertz cleanup to close the restored original stream")
	}
}

func TestPrefetchedRequestBodyStreamCloseWaitsForActiveRead(t *testing.T) {
	reader := &blockingRequestBodyReader{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	stream := &prefetchedRequestBodyStream{reader: reader}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = stream.Read(make([]byte, 1))
	}()
	<-reader.started

	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		_ = stream.Close()
	}()

	select {
	case <-closeDone:
		t.Fatal("Close returned while Read was still active")
	case <-time.After(20 * time.Millisecond):
	}
	close(reader.release)
	<-readDone
	<-closeDone

	if n, err := stream.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("Read after Close = (%d, %v), want (0, EOF)", n, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

func TestRestoreOriginalRequestBodyStreamAfterSnapshot(t *testing.T) {
	body := []byte(strings.Repeat("streamed-request-body-", 4096))
	ctx := app.NewContext(0)
	ctx.Request.Header.SetContentLength(len(body))
	stream := &closeSensitiveRequestBodyStream{reader: bytes.NewReader(body)}
	ctx.Request.SetBodyStream(stream, len(body))

	requestBodySample(ctx)
	if ctx.Request.BodyStream() == stream {
		t.Fatal("expected prefetched wrapper before restore")
	}

	restoreOriginalRequestBodyStream(ctx)
	if ctx.Request.BodyStream() != stream {
		t.Fatal("original request stream was not restored")
	}
	if stream.closed {
		t.Fatal("original stream must remain open for server cleanup")
	}
}

func TestRequestBodySampleCapturesPrefetchReadError(t *testing.T) {
	body := []byte(strings.Repeat("prefetch-read-error-", 64))

	ctx := app.NewContext(0)
	stream := &unexpectedEOFRequestBodyStream{reader: bytes.NewReader(body)}
	ctx.Request.SetBodyStream(stream, -1)

	sample, truncated, size := requestBodySample(ctx)
	if truncated {
		t.Fatal("unexpected truncated sample for short stream body")
	}
	if !bytes.Equal(sample, body) {
		t.Fatal("sample body mismatch")
	}
	if size != int64(len(body)) {
		t.Fatalf("sample size = %d, want %d", size, len(body))
	}
	if err := requestBodySnapshotError(ctx); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("requestBodySnapshotError() = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestChallengeSubmissionValuesOnlyAcceptsURLEncodedForm(t *testing.T) {
	values := url.Values{
		"__waf_challenge_ts":    {"1700000000"},
		"__waf_challenge_token": {"signed-token"},
		"__waf_challenge_rid":   {"request-id"},
	}

	sub, ok := challengeSubmissionValues([]byte(values.Encode()), "application/x-www-form-urlencoded; charset=UTF-8")
	if !ok {
		t.Fatal("expected complete URL-encoded challenge submission")
	}
	if sub.TS != "1700000000" || sub.Token != "signed-token" || sub.RequestID != "request-id" || sub.EnvFP != "" {
		t.Fatalf("challenge values = %+v", sub)
	}

	if _, ok := challengeSubmissionValues([]byte(values.Encode()), "multipart/form-data; boundary=test"); ok {
		t.Fatal("multipart body must not be parsed as a challenge submission")
	}
	values.Del("__waf_challenge_token")
	if _, ok := challengeSubmissionValues([]byte(values.Encode()), "application/x-www-form-urlencoded"); ok {
		t.Fatal("incomplete challenge submission must be rejected")
	}
}

// solveChallengePoW 以挑战页脚本相同的算法求出合法工作量证明，
// 供端到端测试构造「客户端已完成挑战」的提交。
func solveChallengePoW(t *testing.T, token string) (counter, hash string) {
	t.Helper()
	prefix := strings.Repeat("0", challenge.ChallengeProofDifficulty)
	for i := int64(0); i < 5_000_000; i++ {
		sum := sha256.Sum256([]byte(token + strconv.FormatInt(i, 10)))
		h := hex.EncodeToString(sum[:])
		if strings.HasPrefix(h, prefix) {
			return strconv.FormatInt(i, 10), h
		}
	}
	t.Fatalf("未能求出难度 %d 的解", challenge.ChallengeProofDifficulty)
	return "", ""
}

// TestChallengeSubmissionValuesParsesProofFields 验证工作量证明字段被正确解析。
func TestChallengeSubmissionValuesParsesProofFields(t *testing.T) {
	values := url.Values{
		"__waf_challenge_ts":      {"1700000000"},
		"__waf_challenge_token":   {"signed-token"},
		"__waf_challenge_rid":     {"request-id"},
		"__waf_challenge_proof":   {"0000abcdef"},
		"__waf_challenge_counter": {"12345"},
	}
	sub, ok := challengeSubmissionValues([]byte(values.Encode()), "application/x-www-form-urlencoded")
	if !ok {
		t.Fatal("expected complete submission")
	}
	if sub.Proof != "0000abcdef" || sub.Counter != "12345" {
		t.Fatalf("proof fields = %q / %q", sub.Proof, sub.Counter)
	}
}

func TestHandlerMultipartBodyLifecycle(t *testing.T) {
	tests := []struct {
		name      string
		bodySize  int
		filename  string
		content   string
		wantBlock bool
	}{
		{name: "forwards 435-byte clean body", bodySize: 435, filename: "report.txt", content: "ordinary report"},
		{name: "forwards 43336-byte clean body", bodySize: 43336, filename: "report.txt", content: "ordinary report"},
		{name: "forwards body above inspection limit", bodySize: 64 * 1024, filename: "report.txt", content: "ordinary report"},
		{name: "blocks 435-byte executable upload", bodySize: 435, filename: "avatar.php;.jpg", content: "<?php system($_GET['task']); ?>", wantBlock: true},
		{name: "blocks 43336-byte executable upload", bodySize: 43336, filename: "avatar.php;.jpg", content: "<?php system($_GET['task']); ?>", wantBlock: true},
		{name: "blocks executable upload above inspection limit", bodySize: 64 * 1024, filename: "avatar.php;.jpg", content: "<?php system($_GET['task']); ?>", wantBlock: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, contentType := fixedLengthMultipartBody(t, tt.bodySize, tt.filename, tt.content)
			var upstreamRequests atomic.Int32
			receivedBody := make(chan []byte, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamRequests.Add(1)
				got, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upstream body: %v", err)
				}
				receivedBody <- got
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			}))
			defer upstream.Close()

			holder := &snapshot.Holder{}
			protection := store.DefaultProtectionConfig()
			protection.OWASPEnabled = true
			protection.OWASPAction = "intercept"
			protection.BotDetectionEnabled = false
			rt := snapshot.SiteRuntime{
				Site:                store.Site{ID: 1, Host: "upload.example.com", Bind: ":80"},
				Bind:                ":80",
				UpstreamURLs:        []string{upstream.URL},
				EffectiveProtection: &protection,
			}
			holder.Store(&snapshot.Snapshot{
				Revision:   1,
				Protection: protection,
				Sites: map[string]*snapshot.SiteRuntime{
					snapshot.SiteMapKey(":80", "upload.example.com"): &rt,
				},
			})

			handler := Handler(Options{
				Holder: holder,
				Engine: engine.New(holder, nil, nil, nil),
				Log:    slog.Default(),
				Bind:   ":80",
			})
			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod(http.MethodPost)
			ctx.Request.SetRequestURI("/upload")
			ctx.Request.Header.SetHost("upload.example.com")
			ctx.Request.Header.Set("Content-Type", contentType)
			ctx.Request.SetBodyStream(&trackingRequestBodyStream{reader: bytes.NewReader(body)}, len(body))

			handler(context.Background(), ctx)

			if tt.wantBlock {
				if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
					t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
				}
				if got := upstreamRequests.Load(); got != 0 {
					t.Fatalf("upstream requests = %d, want 0", got)
				}
				return
			}

			if got := ctx.Response.StatusCode(); got != http.StatusOK {
				t.Fatalf("status = %d, want %d", got, http.StatusOK)
			}
			if got := upstreamRequests.Load(); got != 1 {
				t.Fatalf("upstream requests = %d, want 1", got)
			}
			got := <-receivedBody
			if !bytes.Equal(got, body) {
				t.Fatalf("upstream body mismatch: got %d bytes want %d", len(got), len(body))
			}
		})
	}
}

func TestHandlerEvaluatesWAFBeforeChallengeRedirect(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		wantStatus int
		wantCookie bool
	}{
		{name: "valid challenge redirects after clean WAF result", wantStatus: http.StatusFound, wantCookie: true},
		{name: "dangerous body is blocked before valid challenge redirect", payload: `<script>alert(1)</script>`, wantStatus: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamRequests atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamRequests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			holder := &snapshot.Holder{}
			protection := store.DefaultProtectionConfig()
			protection.OWASPEnabled = true
			protection.OWASPAction = "intercept"
			protection.BotDetectionEnabled = false
			protection.ShieldEnableEnvCheck = false
			rt := snapshot.SiteRuntime{
				Site:                store.Site{ID: 1, Host: "challenge.example.com", Bind: ":80"},
				Bind:                ":80",
				UpstreamURLs:        []string{upstream.URL},
				EffectiveProtection: &protection,
				Rules: []snapshot.CompiledRule{{
					ID:       1,
					Phase:    store.PhaseCustom,
					Action:   store.ActionChallenge,
					Priority: 1,
					Kind:     "always",
				}},
			}
			holder.Store(&snapshot.Snapshot{
				Revision:   1,
				Protection: protection,
				Sites: map[string]*snapshot.SiteRuntime{
					snapshot.SiteMapKey(":80", "challenge.example.com"): &rt,
				},
			})

			requestID := "challenge-request-id"
			// token 必须按数据面实际使用的客户端绑定信息签发，否则校验会失败。
			// app.NewContext 无远端地址时 ResolveClientIP 解析为 0.0.0.0。
			ts, token := challenge.GenerateChallengeTokenPairWithClaims(requestID, challenge.ChallengeTokenClaims{
				ClientIP: "0.0.0.0",
				Host:     "challenge.example.com",
				SiteID:   1,
			})
			proofCounter, proofHash := solveChallengePoW(t, token)
			values := url.Values{
				"__waf_challenge_ts":      {ts},
				"__waf_challenge_token":   {token},
				"__waf_challenge_rid":     {requestID},
				"__waf_challenge_counter": {proofCounter},
				"__waf_challenge_proof":   {proofHash},
			}
			if tt.payload != "" {
				values.Set("payload", tt.payload)
			}
			body := []byte(values.Encode())

			handler := Handler(Options{
				Holder: holder,
				Engine: engine.New(holder, nil, nil, nil),
				Log:    slog.Default(),
				Bind:   ":80",
			})
			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod(http.MethodPost)
			ctx.Request.SetRequestURI("/guarded")
			ctx.Request.Header.SetHost("challenge.example.com")
			ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			ctx.Request.Header.Set("Referer", "/original")
			ctx.Request.SetBodyStream(&trackingRequestBodyStream{reader: bytes.NewReader(body)}, len(body))

			handler(context.Background(), ctx)

			if got := ctx.Response.StatusCode(); got != tt.wantStatus {
				t.Fatalf("status = %d, want %d", got, tt.wantStatus)
			}
			if got := upstreamRequests.Load(); got != 0 {
				t.Fatalf("upstream requests = %d, want 0", got)
			}
			if got := len(ctx.Response.Header.Peek("Set-Cookie")) > 0; got != tt.wantCookie {
				t.Fatalf("challenge cookie present = %v, want %v", got, tt.wantCookie)
			}
		})
	}
}

// TestChallengeTokenCannotBeReplayedOrShared 端到端验证 JS 挑战 token 的两条约束：
// 同一 token 只能兑换一次通行 cookie，且不能被另一个客户端（不同 UA）复用。
//
// 修复前 token = HMAC(reqID+":"+ts)，既不绑定客户端也没有一次性约束，
// 抓取一份挑战页即可让任意数量的客户端在 5 分钟内反复换取通行 cookie。
func TestChallengeTokenCannotBeReplayedOrShared(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.OWASPEnabled = false
	protection.BotDetectionEnabled = false
	protection.ShieldEnableEnvCheck = false
	rt := snapshot.SiteRuntime{
		Site:                store.Site{ID: 1, Host: "replay.example.com", Bind: ":80"},
		Bind:                ":80",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
		Rules: []snapshot.CompiledRule{{
			ID:       1,
			Phase:    store.PhaseCustom,
			Action:   store.ActionChallenge,
			Priority: 1,
			Kind:     "always",
		}},
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "replay.example.com"): &rt,
		},
	})

	const requestID = "replay-request-id"
	const ownerUA = "Mozilla/5.0 owner"
	ts, token := challenge.GenerateChallengeTokenPairWithClaims(requestID, challenge.ChallengeTokenClaims{
		ClientIP:  "0.0.0.0",
		UserAgent: ownerUA,
		Host:      "replay.example.com",
		SiteID:    1,
	})
	replayCounter, replayHash := solveChallengePoW(t, token)
	body := []byte(url.Values{
		"__waf_challenge_ts":      {ts},
		"__waf_challenge_token":   {token},
		"__waf_challenge_rid":     {requestID},
		"__waf_challenge_counter": {replayCounter},
		"__waf_challenge_proof":   {replayHash},
	}.Encode())

	handler := Handler(Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Log:    slog.Default(),
		Bind:   ":80",
	})

	submit := func(userAgent string) *app.RequestContext {
		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod(http.MethodPost)
		ctx.Request.SetRequestURI("/guarded")
		ctx.Request.Header.SetHost("replay.example.com")
		ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx.Request.Header.Set("User-Agent", userAgent)
		ctx.Request.Header.Set("Referer", "/original")
		ctx.Request.SetBodyStream(&trackingRequestBodyStream{reader: bytes.NewReader(body)}, len(body))
		handler(context.Background(), ctx)
		return ctx
	}

	first := submit(ownerUA)
	if got := first.Response.StatusCode(); got != http.StatusFound {
		t.Fatalf("first submission status = %d, want %d", got, http.StatusFound)
	}
	if len(first.Response.Header.Peek("Set-Cookie")) == 0 {
		t.Fatal("first submission should issue a challenge pass cookie")
	}

	replay := submit(ownerUA)
	if got := replay.Response.StatusCode(); got == http.StatusFound {
		t.Fatal("replayed challenge token must not issue a second pass cookie")
	}

	shared := submit("curl/8.0")
	if got := shared.Response.StatusCode(); got == http.StatusFound {
		t.Fatal("challenge token must not be usable by a different client")
	}
}

func TestHandlerChallengeVerifyFailureRespectsSiteWhitelistAndXFF(t *testing.T) {
	const (
		bind        = ":80"
		host        = "challenge-verify.example.com"
		proxyIP     = "192.0.2.10"
		forwardedIP = "198.51.100.7"
	)

	_, whitelistCIDR, err := net.ParseCIDR(forwardedIP + "/32")
	if err != nil {
		t.Fatalf("parse whitelist CIDR: %v", err)
	}

	cases := []struct {
		name string
		path string
		form url.Values
	}{
		{
			name: "captcha",
			path: "/__owaf/captcha/verify",
			form: url.Values{
				"__waf_captcha_session": {"missing"},
				"__waf_captcha_answer":  {"wrong"},
			},
		},
		{
			name: "shield",
			path: "/__owaf/shield/verify",
			form: url.Values{
				"__waf_shield_session": {"missing"},
				"__waf_pow_counter":    {"0"},
				"__waf_pow_hash":       {"bad"},
			},
		},
		{
			name: "chain",
			path: "/__owaf/chain/verify",
			form: url.Values{
				"__waf_chain_session": {"missing"},
			},
		},
	}

	newHandler := func(t *testing.T, whitelist bool) (*iprep.IPReputation, app.HandlerFunc) {
		t.Helper()
		protection := store.DefaultProtectionConfig()
		protection.OWASPEnabled = false
		protection.BotDetectionEnabled = false
		rt := snapshot.SiteRuntime{
			Site:                store.Site{ID: 1, Host: host, Bind: bind},
			Bind:                bind,
			XFFMode:             store.XFFModeTrustOuter,
			TrustedCIDR:         "192.0.2.0/24",
			ClientIPHeaderOrder: []string{store.ClientIPHeaderXForwardedFor},
			EffectiveProtection: &protection,
		}
		if whitelist {
			rt.SiteIPWhitelist = []iprep.IPListEntry{{CIDR: whitelistCIDR}}
		}
		holder := &snapshot.Holder{}
		holder.Store(&snapshot.Snapshot{
			Revision:   1,
			Protection: protection,
			Sites: map[string]*snapshot.SiteRuntime{
				snapshot.SiteMapKey(bind, host): &rt,
			},
		})

		ipRep := iprep.NewIPReputation()
		ipRep.ConfigureAutoBan(true, 1, 60, 3600)
		captchaManager := challenge.NewCaptchaManager(nil, 0)
		shieldManager := challenge.NewShieldManager(captchaManager, nil, 1)
		chainManager := challenge.NewChainChallengeManager(captchaManager, nil)
		t.Cleanup(func() {
			chainManager.Close()
			shieldManager.Close()
			captchaManager.Close()
			ipRep.Close()
		})

		return ipRep, Handler(Options{
			Holder:         holder,
			Engine:         engine.New(holder, nil, nil, ipRep),
			Log:            slog.Default(),
			Bind:           bind,
			CaptchaManager: captchaManager,
			ShieldManager:  shieldManager,
			ChainManager:   chainManager,
		})
	}

	makeRequest := func(t *testing.T, path string, form url.Values) *app.RequestContext {
		t.Helper()
		client, server := net.Pipe()
		t.Cleanup(func() {
			client.Close()
			server.Close()
		})
		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod(http.MethodPost)
		ctx.Request.SetRequestURI(path)
		ctx.Request.Header.SetHost(host)
		ctx.Request.Header.Set("X-Forwarded-For", forwardedIP)
		ctx.Request.SetFormDataFromValues(form)
		ctx.SetConn(&loopbackHertzConn{
			Conn:       &testHertzConn{Conn: server},
			remoteAddr: &net.TCPAddr{IP: net.ParseIP(proxyIP), Port: 8443},
		})
		return ctx
	}

	for _, tc := range cases {
		t.Run(tc.name+" whitelist", func(t *testing.T) {
			ipRep, handler := newHandler(t, true)
			ctx := makeRequest(t, tc.path, tc.form)
			handler(context.Background(), ctx)
			if got := ctx.Response.StatusCode(); got != http.StatusFound {
				t.Fatalf("status = %d, want %d", got, http.StatusFound)
			}
			if got := string(ctx.Response.Header.Peek("Location")); got != "/" {
				t.Fatalf("location = %q, want %q", got, "/")
			}
			if bans := ipRep.ActiveBans(); len(bans) != 0 {
				t.Fatalf("whitelisted forwarded client unexpectedly auto-banned: %+v", bans)
			}
		})
	}

	t.Run("non-whitelist records forwarded client", func(t *testing.T) {
		ipRep, handler := newHandler(t, false)
		ctx := makeRequest(t, cases[0].path, cases[0].form)
		handler(context.Background(), ctx)
		if got := ctx.Response.StatusCode(); got != http.StatusFound {
			t.Fatalf("status = %d, want %d", got, http.StatusFound)
		}
		bans := ipRep.ActiveBans()
		if len(bans) != 1 || bans[0].IP != forwardedIP {
			t.Fatalf("auto-ban IPs = %+v, want only forwarded client %s", bans, forwardedIP)
		}
		if decision := ipRep.Check(net.ParseIP(proxyIP)); decision.Category == "auto_ban" {
			t.Fatalf("trusted proxy was auto-banned: %+v", decision)
		}
	})
}

func TestHandlerChallengeVerifyFailureWithoutSnapshotUsesDirectIP(t *testing.T) {
	const (
		directIP  = "203.0.113.10"
		spoofedIP = "198.51.100.99"
	)

	ipRep := iprep.NewIPReputation()
	ipRep.ConfigureAutoBan(true, 1, 60, 3600)
	captchaManager := challenge.NewCaptchaManager(nil, 0)
	t.Cleanup(func() {
		captchaManager.Close()
		ipRep.Close()
	})

	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.SetRequestURI("/__owaf/captcha/verify")
	ctx.Request.Header.SetHost("unmatched.example.com")
	ctx.Request.Header.Set("X-Forwarded-For", spoofedIP)
	ctx.Request.SetFormDataFromValues(url.Values{
		"__waf_captcha_session": {"missing"},
		"__waf_captcha_answer":  {"wrong"},
	})
	ctx.SetConn(&loopbackHertzConn{
		Conn:       &testHertzConn{Conn: server},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP(directIP), Port: 8443},
	})

	handler := Handler(Options{
		Engine:         engine.New(nil, nil, nil, ipRep),
		Log:            slog.Default(),
		CaptchaManager: captchaManager,
	})
	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusFound {
		t.Fatalf("status = %d, want %d", got, http.StatusFound)
	}
	bans := ipRep.ActiveBans()
	if len(bans) != 1 || bans[0].IP != directIP {
		t.Fatalf("auto-ban IPs = %+v, want only direct IP %s", bans, directIP)
	}
	if decision := ipRep.Check(net.ParseIP(spoofedIP)); decision.Category == "auto_ban" {
		t.Fatalf("spoofed XFF IP was auto-banned: %+v", decision)
	}
}

func TestHandlerChallengeVerifyWritesSpecificAccessLog(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate logs: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer writer.Close()

	protection := store.DefaultProtectionConfig()
	protection.OWASPEnabled = false
	protection.CVEEnabled = false
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site:                store.Site{ID: 17, Host: "challenge-log.example.test", Bind: ":80"},
		Bind:                ":80",
		EffectiveProtection: &protection,
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", rt.Site.Host): &rt,
		},
	})
	captchaManager := challenge.NewCaptchaManager(nil, 0)
	defer captchaManager.Close()

	handler := Handler(Options{
		Holder:                holder,
		Engine:                engine.New(holder, nil, nil, nil),
		Writer:                writer,
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Bind:                  ":80",
		CaptchaManager:        captchaManager,
		AccessLogSamplingRate: 0,
	})
	ctx := app.NewContext(0)
	ctx.Request.SetMethod(http.MethodPost)
	ctx.Request.SetRequestURI("/__owaf/captcha/verify")
	ctx.Request.SetHost(rt.Site.Host)
	ctx.Request.SetFormDataFromValues(url.Values{
		"__waf_captcha_session": {"missing"},
		"__waf_captcha_answer":  {"wrong"},
	})
	fp := bot.TLSClientFingerprint{TLSVersion: "TLS13", JA3Hash: "ja3-challenge-log", JA4: "ja4-challenge-log"}
	handler(ContextWithTLSFingerprint(context.Background(), fp), ctx)
	requestID := string(ctx.Response.Header.Peek("X-Request-ID"))
	if requestID == "" {
		t.Fatal("challenge verify response is missing X-Request-ID")
	}

	writer.Close()
	var entry store.AccessLog
	if err := db.Where("request_id = ?", requestID).First(&entry).Error; err != nil {
		t.Fatalf("read challenge verify access log: %v", err)
	}
	if entry.SiteID != rt.Site.ID || entry.StatusCode != http.StatusFound || entry.WAFAction != "challenge_verify" {
		t.Fatalf("challenge verify access log = %#v", entry)
	}
	if entry.TLSVersion != fp.TLSVersion || entry.TLSJA3Hash != fp.JA3Hash || entry.TLSJA4 != fp.JA4 {
		t.Fatalf("challenge verify access log lost TLS fingerprint: %#v", entry)
	}
	var count int64
	if err := db.Model(&store.AccessLog{}).Where("request_id = ?", requestID).Count(&count).Error; err != nil {
		t.Fatalf("count challenge verify access logs: %v", err)
	}
	if count != 1 {
		t.Fatalf("challenge verify access log count = %d, want 1", count)
	}
}

func fixedLengthMultipartBody(t *testing.T, size int, filename, content string) ([]byte, string) {
	t.Helper()
	const boundary = "owaf-lifecycle-boundary"
	prefix := []byte("--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"document\"; filename=\"" + filename + "\"\r\n" +
		"Content-Type: text/plain\r\n\r\n" + content)
	suffix := []byte("\r\n--" + boundary + "--\r\n")
	paddingSize := size - len(prefix) - len(suffix)
	if paddingSize < 0 {
		t.Fatalf("multipart target size %d is below framing size %d", size, len(prefix)+len(suffix))
	}
	body := make([]byte, 0, size)
	body = append(body, prefix...)
	body = append(body, bytes.Repeat([]byte("A"), paddingSize)...)
	body = append(body, suffix...)
	if len(body) != size {
		t.Fatalf("multipart body length = %d, want %d", len(body), size)
	}
	return body, "multipart/form-data; boundary=" + boundary
}

func TestErrorRateLimitActionDefaultsToRateLimit(t *testing.T) {
	got := errorRateLimitAction("")
	if got.Type != action.RateLimit || !got.Matched || got.Phase != "error_rate_limit" || got.StatusCode != 429 {
		t.Fatalf("errorRateLimitAction() = %#v", got)
	}
}

func TestHandlerLuaRateLimitPersistsPluginIdentity(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate logs: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))

	protection := store.DefaultProtectionConfig()
	protection.OWASPEnabled = false
	protection.CVEEnabled = false
	protection.BotDetectionEnabled = false
	holder := &snapshot.Holder{}
	runtime := snapshot.SiteRuntime{
		Site:                store.Site{ID: 1, Host: "lua-identity.example.test", Bind: ":80"},
		Bind:                ":80",
		EffectiveProtection: &protection,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", runtime.Site.Host): &runtime,
		},
	})

	script, err := luaplugin.Compile("lua-rate-limit", luaplugin.StagePre, `function handle(ctx) return "rate_limit" end`)
	if err != nil {
		t.Fatalf("compile Lua plugin: %v", err)
	}
	script.SetID(73)
	luaEngine := luaplugin.NewEngine(handlerLuaKV{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	luaEngine.Reload([]*luaplugin.Script{script})
	wafEngine := engine.New(holder, nil, nil, nil)
	wafEngine.SetLuaPlugins(luaEngine)
	handler := Handler(Options{
		Holder: holder,
		Engine: wafEngine,
		Writer: writer,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Bind:   ":80",
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/limited")
	ctx.Request.Header.SetHost(runtime.Site.Host)
	handler(context.Background(), ctx)
	writer.Close()

	if got := ctx.Response.StatusCode(); got != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", got, http.StatusTooManyRequests)
	}
	requestID := string(ctx.Response.Header.Peek("X-Request-ID"))
	var event store.SecurityEvent
	if err := db.Where("request_id = ?", requestID).First(&event).Error; err != nil {
		t.Fatalf("read Lua security event: %v", err)
	}
	if event.Phase != "lua_pre" || event.Action != "rate_limit" || event.RuleID != 73 || event.RuleIDStr != "lua-rate-limit" {
		t.Fatalf("Lua security event identity = %+v", event)
	}
}

func TestErrorRateLimitActionKeepsConfiguredIntercept(t *testing.T) {
	got := errorRateLimitAction("intercept")
	if got.Type != action.Intercept || got.StatusCode != 0 {
		t.Fatalf("errorRateLimitAction(intercept) = %#v", got)
	}
}

func TestHandlerErrorRateLimitObserveProxiesAndRecordsObserve(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate logs: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))

	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if upstreamRequests.Add(1) <= 2 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("upstream not found"))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	protection.ErrorRateLimitEnabled = true
	protection.ErrorRateLimitWindow = 60
	protection.ErrorRateLimitMax = 1
	protection.ErrorRateLimitCount4xx = true
	protection.ErrorRateLimitCount5xx = false
	protection.ErrorRateLimitCountBlock = false
	protection.ErrorRateLimitAction = "observe"
	rt := snapshot.SiteRuntime{
		Site:                store.Site{ID: 1, Host: "error-ratelimit-observe.example.test", Bind: ":80"},
		Bind:                ":80",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", rt.Site.Host): &rt,
		},
	})

	errorLimiter := ratelimit.NewRateLimiter(protection.ErrorRateLimitWindow, protection.ErrorRateLimitMax, true)
	defer errorLimiter.Close()
	metrics := NewMetrics()
	handler := Handler(Options{
		Holder:                holder,
		Engine:                engine.New(holder, nil, errorLimiter, nil),
		Metrics:               metrics,
		Writer:                writer,
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Bind:                  ":80",
		AccessLogSamplingRate: 0,
	})
	request := func() *app.RequestContext {
		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod(http.MethodGet)
		ctx.Request.SetRequestURI("/error-ratelimit-observe")
		ctx.Request.Header.SetHost(rt.Site.Host)
		handler(context.Background(), ctx)
		return ctx
	}

	for requestNumber := 1; requestNumber <= 2; requestNumber++ {
		if got := request().Response.StatusCode(); got != http.StatusNotFound {
			t.Fatalf("request %d status = %d, want %d", requestNumber, got, http.StatusNotFound)
		}
	}
	observed := request()
	writer.Close()

	if got := observed.Response.StatusCode(); got != http.StatusNoContent {
		t.Fatalf("observed request status = %d, want upstream status %d", got, http.StatusNoContent)
	}
	if got := upstreamRequests.Load(); got != 3 {
		t.Fatalf("upstream requests = %d, want 3", got)
	}
	if got := metrics.WAFObserves.Load(); got != 1 {
		t.Fatalf("WAF observe metrics = %d, want 1", got)
	}

	var securityEvent store.SecurityEvent
	if err := db.Where("site_id = ? AND action = ?", rt.Site.ID, "observe").First(&securityEvent).Error; err != nil {
		t.Fatalf("read observe security event: %v", err)
	}
	if securityEvent.Phase != "error_rate_limit" || securityEvent.RuleIDStr != "error_rate_limit" {
		t.Fatalf("observe security event = %#v", securityEvent)
	}

	var accessLog store.AccessLog
	if err := db.Where("site_id = ? AND waf_action = ?", rt.Site.ID, "observe").First(&accessLog).Error; err != nil {
		t.Fatalf("read observe access log: %v", err)
	}
	if accessLog.StatusCode != http.StatusNoContent {
		t.Fatalf("observe access log = %#v", accessLog)
	}
}

func TestHandlerAllProtectionsDisabledAttributesUpstreamStatus(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate logs: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/limited" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("upstream rate limit"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	protection := store.DefaultProtectionConfig()
	protection.RequestRateLimitEnabled = false
	protection.ErrorRateLimitEnabled = false
	protection.OWASPEnabled = false
	protection.CVEEnabled = false
	protection.BotDetectionEnabled = false
	protection.AntiReplayEnabled = false
	protection.BrowserSignEnabled = false
	protection.MaintenanceGlobalEnabled = false
	runtime := snapshot.SiteRuntime{
		Site:                store.Site{ID: 1, Host: "no-protection.example.test", Bind: ":80"},
		Bind:                ":80",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", runtime.Site.Host): &runtime,
		},
	})
	handler := Handler(Options{
		Holder:                holder,
		Engine:                engine.New(holder, nil, nil, nil),
		Writer:                writer,
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Bind:                  ":80",
		AccessLogSamplingRate: 0,
	})

	request := func(path string) *app.RequestContext {
		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod(http.MethodGet)
		ctx.Request.SetRequestURI(path)
		ctx.Request.Header.SetHost(runtime.Site.Host)
		handler(context.Background(), ctx)
		return ctx
	}
	okResponse := request("/ok")
	limitedResponse := request("/limited")
	writer.Close()

	if got := okResponse.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("clean status = %d, want %d", got, http.StatusOK)
	}
	if got := limitedResponse.Response.StatusCode(); got != http.StatusTooManyRequests {
		t.Fatalf("upstream status = %d, want %d", got, http.StatusTooManyRequests)
	}
	limitedRequestID := string(limitedResponse.Response.Header.Peek("X-Request-ID"))
	var accessLog store.AccessLog
	if err := db.Where("request_id = ?", limitedRequestID).First(&accessLog).Error; err != nil {
		t.Fatalf("read upstream 429 access log: %v", err)
	}
	if accessLog.WAFAction != "none" || accessLog.StatusCode != http.StatusTooManyRequests || accessLog.CacheState != "bypass" || accessLog.Upstream != upstream.URL {
		t.Fatalf("upstream 429 attribution = %+v", accessLog)
	}
	var securityEvents int64
	if err := db.Model(&store.SecurityEvent{}).Where("request_id = ?", limitedRequestID).Count(&securityEvents).Error; err != nil {
		t.Fatalf("count security events: %v", err)
	}
	if securityEvents != 0 {
		t.Fatalf("upstream 429 security events = %d, want 0", securityEvents)
	}
}

// TestHandlerInvalidEnabledRateLimitNeverSynthesizes429 覆盖旧配置中开关为真但
// 窗口/配额为零的情况：限流器必须安全停用，普通请求仍应到达上游。
func TestHandlerInvalidEnabledRateLimitNeverSynthesizes429(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	protection := store.DefaultProtectionConfig()
	protection.RequestRateLimitEnabled = true
	protection.RequestRateLimitWindow = 0
	protection.RequestRateLimitMax = 0
	protection.OWASPEnabled = false
	protection.CVEEnabled = false
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{ID: 1, Host: "invalid-rate.example.test", Bind: ":80"},
		Bind: ":80", UpstreamURLs: []string{upstream.URL}, EffectiveProtection: &protection,
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision: 1, Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{snapshot.SiteMapKey(":80", rt.Site.Host): &rt},
	})
	limiter := ratelimit.NewRateLimiter(0, 0, true)
	defer limiter.Close()
	handler := Handler(Options{
		Holder: holder,
		Engine: engine.New(holder, limiter, nil, nil),
		Log:    slog.Default(), Bind: ":80",
		AccessLogSamplingRate: 1,
	})
	ctx := app.NewContext(0)
	ctx.Request.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/")
	ctx.Request.SetHost(rt.Site.Host)
	handler(context.Background(), ctx)
	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want 200 (invalid limiter must fail open)", got)
	}
}

func TestHandlerDisabledErrorRateLimitDoesNotUseHistoricalCounter(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	protection := store.DefaultProtectionConfig()
	protection.ErrorRateLimitEnabled = false
	protection.OWASPEnabled = false
	protection.CVEEnabled = false
	protection.BotDetectionEnabled = false
	protection.AntiReplayEnabled = false
	rt := snapshot.SiteRuntime{
		Site:                store.Site{ID: 19, Host: "no-error-limit.example.test", Bind: ":80"},
		Bind:                ":80",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", rt.Site.Host): &rt,
		},
	})

	errLimiter := ratelimit.NewRateLimiter(60, 1, true)
	defer errLimiter.Close()
	key := "|no-error-limit.example.test"
	errLimiter.Increment(key)
	errLimiter.Increment(key)

	handler := Handler(Options{
		Holder:                holder,
		Engine:                engine.New(holder, nil, errLimiter, nil),
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Bind:                  ":80",
		AccessLogSamplingRate: 1,
	})
	ctx := app.NewContext(0)
	ctx.Request.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/no-rules")
	ctx.Request.SetHost(rt.Site.Host)
	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want 200 while error rate limit is disabled", got)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}

func TestRateLimitActionUsesDefault429Status(t *testing.T) {
	res := action.Result{Type: action.RateLimit, Matched: true}
	if got := res.ResponseStatusCode(); got != 429 {
		t.Fatalf("rate limit response status = %d, want 429", got)
	}
}

func TestAccessLogKeepsSpecificChallengeActions(t *testing.T) {
	for _, actionName := range []string{
		"challenge",
		"captcha_challenge",
		"shield_challenge",
		"chain_challenge",
	} {
		ctx := app.NewContext(0)
		entry := buildAccessLogEntry(ctx, accessLogInfo{WAFAction: actionName, StatusCode: 403})
		if entry.WAFAction != actionName {
			t.Fatalf("access log WAFAction = %q, want %q", entry.WAFAction, actionName)
		}
	}
}

func TestAntiReplayChallengeActionsRenderSpecificChallengePages(t *testing.T) {
	captchaManager := challenge.NewCaptchaManager(nil, 0)
	defer captchaManager.Close()
	shieldManager := challenge.NewShieldManager(captchaManager, nil, 1)
	defer shieldManager.Close()
	chainManager := challenge.NewChainChallengeManager(captchaManager, nil)

	baseProtection := store.DefaultProtectionConfig()
	baseProtection.CaptchaEnabled = true
	baseProtection.CaptchaType = "math"
	baseProtection.ShieldEnabled = true
	baseProtection.ChainEnabled = true

	opts := Options{
		CaptchaManager: captchaManager,
		ShieldManager:  shieldManager,
		ChainManager:   chainManager,
	}

	cases := []struct {
		name       string
		actionName action.Type
		wantParts  []string
	}{
		{
			name:       "captcha",
			actionName: action.CaptchaChallenge,
			wantParts: []string{
				`action="/__owaf/captcha/verify"`,
				`name="__waf_captcha_session"`,
				`Security Verification / 安全验证`,
			},
		},
		{
			name:       "shield",
			actionName: action.ShieldChallenge,
			wantParts: []string{
				`action='/__owaf/shield/verify'`,
				`__waf_shield_session`,
				`shield-icon`,
			},
		},
		{
			name:       "chain",
			actionName: action.ChainChallenge,
			wantParts: []string{
				`action='/__owaf/chain/verify'`,
				`__waf_chain_session`,
				`Environment Check / 环境检测`,
			},
		},
	}

	// 站点/全局 captcha_type 链在防重放 captcha 分支的覆盖用例：
	// 不污染其余动作分支（站点 ChallengeAction 不能覆盖防重放自身的动作维度）。
	for _, rt := range []*snapshot.SiteRuntime{
		{},
		{ChallengeAction: "captcha_challenge", ChallengeCaptchaType: "slide"},
	} {
		sn := &snapshot.Snapshot{Protection: baseProtection}
		if rt.ChallengeCaptchaType == "slide" {
			captchaManager.SetGoCaptchaProvider(challenge.NewGoCaptchaProvider(challenge.DefaultGoCaptchaConfig(), slog.Default()))
		}
		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod("GET")
		ctx.Request.SetRequestURI("/guarded?from=anti-replay-captcha-type")
		ctx.Request.Header.SetHost("example.com")

		writeAntiReplayActionResponse(ctx, Options{CaptchaManager: captchaManager, ShieldManager: shieldManager, ChainManager: chainManager}, sn, rt, "req-ar-type", string(action.CaptchaChallenge), action.Result{Type: action.CaptchaChallenge, Matched: true}, 403)
		if got := ctx.Response.StatusCode(); got != 403 {
			t.Fatalf("anti-replay captcha status = %d, want 403", got)
		}
		body := string(ctx.Response.Body())
		if strings.Contains(body, `id="slide-range"`) || strings.Contains(body, `id="rotate-range"`) {
			t.Fatal("anti-replay captcha leaked typed challenge DOM")
		}
		// 站点覆盖落地在加密信封的题目类型上。
		sessionID := extractCaptchaSessionFromPage(t, body)
		if sessionID == "" {
			t.Fatal("anti-replay captcha page did not expose session id")
		}
		wantType := "math"
		if rt.ChallengeCaptchaType == "slide" {
			wantType = "slide"
		}
		if got := captchaEnvelopeType(t, captchaManager, sessionID, body); got != wantType {
			t.Fatalf("anti-replay captcha_type = %q, want %q", got, wantType)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod("GET")
			ctx.Request.SetRequestURI("/guarded?from=anti-replay")
			ctx.Request.Header.SetHost("example.com")

			pageCtx := app.NewContext(0)
			pageCtx.Request.Header.SetMethod("GET")
			pageCtx.Request.SetRequestURI("/guarded?from=anti-replay")
			pageCtx.Request.Header.SetHost("example.com")

			sn := &snapshot.Snapshot{Protection: baseProtection}
			rt := &snapshot.SiteRuntime{Site: store.Site{ID: 1, Host: "example.com"}}
			result := action.Result{Type: tc.actionName, Matched: true}

			writeAntiReplayActionResponse(ctx, opts, sn, rt, "req-specific-challenge", string(tc.actionName), result, 403)
			// 用与真实请求相同参数渲染一次，供网络流量模拟断言正文，
			// 避免与既有既有 result 类型分支冲突。
			if tc.actionName == action.CaptchaChallenge {
				writeAntiReplayActionResponse(pageCtx, opts, sn, rt, "req-specific-challenge", string(tc.actionName), result, 403)
				bodyProbe := string(pageCtx.Response.Body())
				for _, deny := range []string{
					`id="slide-range"`,
					`id="rotate-range"`,
					`id="cap-img"`,
					`data:image/png;base64,`,
					`data:image/jpeg;base64,`,
				} {
					if strings.Contains(bodyProbe, deny) {
						t.Fatalf("captcha render leaked plaintext challenge DOM %q in network probe", deny)
					}
				}
				for _, want := range []string{
					`id="cap-data"`,
					`id="cap-key"`,
					`decrypt_challenge_data`,
					`__waf_captcha_answer`,
				} {
					if !strings.Contains(bodyProbe, want) {
						t.Fatalf("captcha render missing encrypted-envelope marker %q in network probe", want)
					}
				}
			}
			if got := ctx.Response.StatusCode(); got != 403 {
				t.Fatalf("status = %d, want 403", got)
			}
			body := string(ctx.Response.Body())
			for _, want := range tc.wantParts {
				if !strings.Contains(body, want) {
					t.Fatalf("response body missing %q", want)
				}
			}
			if strings.Contains(body, "__waf_challenge_token") {
				t.Fatalf("%s response used generic JS challenge token", tc.actionName)
			}
			if tc.actionName == action.CaptchaChallenge {
				for _, deny := range []string{
					`id="slide-range"`,
					`id="rotate-range"`,
					`id="cap-img"`,
					`data:image/png;base64,`,
					`data:image/jpeg;base64,`,
				} {
					if strings.Contains(body, deny) {
						t.Fatalf("captcha page leaked plaintext challenge DOM %q in response body", deny)
					}
				}
			}
		})
	}
}

func TestHandlerRuleChallengeActionsRenderSpecificChallengePages(t *testing.T) {
	captchaManager := challenge.NewCaptchaManager(nil, 0)
	captchaManager.SetGoCaptchaProvider(challenge.NewGoCaptchaProvider(challenge.DefaultGoCaptchaConfig(), slog.Default()))
	defer captchaManager.Close()
	shieldManager := challenge.NewShieldManager(captchaManager, nil, 1)
	defer shieldManager.Close()
	chainManager := challenge.NewChainChallengeManager(captchaManager, nil)

	cases := []struct {
		name            string
		actionName      store.RuleAction
		captchaType     string
		captchaWantPart string
		captchaNotPart  string
		wantParts       []string
	}{
		{
			name:            "captcha",
			actionName:      store.ActionCaptchaChallenge,
			captchaType:     "slide",
			captchaWantPart: `id="cap-data"`,
			captchaNotPart:  `id="slide-range"`,
			wantParts: []string{
				`action="/__owaf/captcha/verify"`,
				`name="__waf_captcha_session"`,
				`Security Verification / 安全验证`,
			},
		},
		{
			name:       "shield",
			actionName: store.ActionShieldChallenge,
			wantParts: []string{
				`action='/__owaf/shield/verify'`,
				`__waf_shield_session`,
				`shield-icon`,
			},
		},
		{
			name:       "chain",
			actionName: store.ActionChainChallenge,
			wantParts: []string{
				`action='/__owaf/chain/verify'`,
				`__waf_chain_session`,
				`Environment Check / 环境检测`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			holder := &snapshot.Holder{}
			protection := store.DefaultProtectionConfig()
			protection.BotDetectionEnabled = false
			protection.CaptchaEnabled = true
			protection.CaptchaType = "math"
			protection.ShieldEnabled = true
			protection.ChainEnabled = true

			rt := snapshot.SiteRuntime{
				Site: store.Site{
					ID:   1,
					Host: "challenge-rule.example.com",
					Bind: ":80",
				},
				Bind:     ":80",
				PolicyID: 1,
				Rules: []snapshot.CompiledRule{
					{
						ID:          81,
						Phase:       store.PhaseCustom,
						Kind:        "block_path_exact",
						Arg:         "/guarded",
						Action:      tc.actionName,
						Priority:    1,
						CaptchaType: tc.captchaType,
					},
				},
				EffectiveProtection: &protection,
			}
			sn := &snapshot.Snapshot{
				Revision:   1,
				Protection: protection,
				Sites: map[string]*snapshot.SiteRuntime{
					snapshot.SiteMapKey(":80", "challenge-rule.example.com"): &rt,
				},
			}
			holder.Store(sn)

			handler := Handler(Options{
				Holder:         holder,
				Engine:         engine.New(holder, nil, nil, nil),
				Log:            slog.Default(),
				Bind:           ":80",
				CaptchaManager: captchaManager,
				ShieldManager:  shieldManager,
				ChainManager:   chainManager,
			})

			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod("GET")
			ctx.Request.SetRequestURI("/guarded?from=rule")
			ctx.Request.Header.SetHost("challenge-rule.example.com")

			handler(context.Background(), ctx)

			if got := ctx.Response.StatusCode(); got != 403 {
				t.Fatalf("status = %d, want 403", got)
			}
			body := string(ctx.Response.Body())
			for _, want := range tc.wantParts {
				if !strings.Contains(body, want) {
					t.Fatalf("response body missing %q", want)
				}
			}
			if tc.captchaWantPart != "" && !strings.Contains(body, tc.captchaWantPart) {
				t.Fatalf("response body missing CAPTCHA marker %q", tc.captchaWantPart)
			}
			if tc.captchaNotPart != "" && strings.Contains(body, tc.captchaNotPart) {
				t.Fatalf("response body unexpectedly contains CAPTCHA marker %q", tc.captchaNotPart)
			}
			if tc.actionName == store.ActionCaptchaChallenge {
				sessionID := extractCaptchaSessionFromPage(t, body)
				if sessionID == "" {
					t.Fatal("captcha page did not expose session id")
				}
				if got := captchaEnvelopeType(t, captchaManager, sessionID, body); got != tc.captchaType {
					t.Fatalf("rule captcha_type = %q, want envelope type %q", got, tc.captchaType)
				}
			}
			if strings.Contains(body, "__waf_challenge_token") {
				t.Fatalf("%s response used generic JS challenge token", tc.actionName)
			}
		})
	}
}

func TestHandlerSiteCCCaptchaActionRendersCaptchaPage(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&store.Site{},
		&store.SiteListener{},
		&store.Certificate{},
		&store.Policy{},
		&store.Rule{},
		&store.ApplicationRouteRule{},
		&store.SystemSettings{},
	); err != nil {
		t.Fatalf("migrate snapshot build tables: %v", err)
	}

	defaultSlot := uint(1)
	if err := db.Create(&store.Policy{Name: "default", DefaultSlot: &defaultSlot}).Error; err != nil {
		t.Fatalf("seed default policy: %v", err)
	}
	protection := store.DefaultProtectionConfig()
	protection.CaptchaEnabled = true
	protection.CaptchaType = "math"
	protectionJSON, err := json.Marshal(protection)
	if err != nil {
		t.Fatalf("marshal protection config: %v", err)
	}
	if err := db.Create(&store.SystemSettings{Key: "protection", Value: string(protectionJSON)}).Error; err != nil {
		t.Fatalf("seed protection config: %v", err)
	}

	useCustomCC := true
	site := store.Site{
		Host:         "cc-captcha.example.com",
		UpstreamURLs: "http://127.0.0.1:8080",
		Bind:         ":80",
		Network:      "tcp",
		Enabled:      true,
		CCUseCustom:  &useCustomCC,
		CCRules: `[{
			"enabled":true,
			"action":"captcha",
			"captcha_type":"click",
			"conditions":[{"target":"url_path","operator":"equals","value":"/guarded"}]
		}]`,
	}
	if err := db.Create(&site).Error; err != nil {
		t.Fatalf("seed site: %v", err)
	}

	sn, err := snapshot.Build(db, 1, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	rt, ok := sn.MatchSite(":80", site.Host)
	if !ok {
		t.Fatal("site was not matched")
	}
	if len(rt.Rules) != 1 {
		t.Fatalf("compiled rules = %d, want 1", len(rt.Rules))
	}
	if got := rt.Rules[0].Action; got != store.ActionCaptchaChallenge {
		t.Fatalf("compiled CC action = %q, want %q", got, store.ActionCaptchaChallenge)
	}

	holder := &snapshot.Holder{}
	holder.Store(sn)
	captchaManager := challenge.NewCaptchaManager(nil, 0)
	captchaManager.SetGoCaptchaProvider(challenge.NewGoCaptchaProvider(challenge.DefaultGoCaptchaConfig(), slog.Default()))
	defer captchaManager.Close()
	handler := Handler(Options{
		Holder:         holder,
		Engine:         engine.New(holder, nil, nil, nil),
		Log:            slog.Default(),
		Bind:           ":80",
		CaptchaManager: captchaManager,
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/guarded")
	ctx.Request.Header.SetHost(site.Host)

	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
	}
	body := string(ctx.Response.Body())
	for _, want := range []string{
		`action="/__owaf/captcha/verify"`,
		`name="__waf_captcha_session"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response body missing %q", want)
		}
	}
	if strings.Contains(body, "__waf_challenge_token") {
		t.Fatal("response used generic JS challenge token")
	}
}

func TestHandlerRuleCaptchaTypeInheritsGlobal(t *testing.T) {
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	protection.CaptchaEnabled = true
	protection.CaptchaType = "rotate"

	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 1, Host: "rule-captcha-inherit.example.com", Bind: ":80"},
		Bind: ":80",
		Rules: []snapshot.CompiledRule{{
			ID:       83,
			Phase:    store.PhaseCustom,
			Kind:     "block_path_exact",
			Arg:      "/guarded",
			Action:   store.ActionCaptchaChallenge,
			Priority: 1,
		}},
		EffectiveProtection: &protection,
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", rt.Site.Host): rt,
		},
	})

	captchaManager := challenge.NewCaptchaManager(nil, 0)
	captchaManager.SetGoCaptchaProvider(challenge.NewGoCaptchaProvider(challenge.DefaultGoCaptchaConfig(), slog.Default()))
	defer captchaManager.Close()
	handler := Handler(Options{
		Holder:         holder,
		Engine:         engine.New(holder, nil, nil, nil),
		Log:            slog.Default(),
		Bind:           ":80",
		CaptchaManager: captchaManager,
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/guarded")
	ctx.Request.Header.SetHost(rt.Site.Host)

	handler(context.Background(), ctx)
	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
	}
	body := string(ctx.Response.Body())
	sessionID := extractCaptchaSessionFromPage(t, body)
	if sessionID == "" {
		t.Fatal("captcha page did not expose session id")
	}
	if got := captchaEnvelopeType(t, captchaManager, sessionID, body); got != "rotate" {
		t.Fatal("empty rule captcha_type should inherit global rotate CAPTCHA")
	}
	if strings.Contains(body, `id="slide-range"`) || strings.Contains(body, `id="rotate-range"`) {
		t.Fatal("inherited captcha_type leaked typed challenge DOM")
	}
}

// TestHandlerExplicitCaptchaActionIgnoresGlobalAutoSwitch 验证规则明确要求
// captcha_challenge 时仍按规则类型渲染；全局开关只控制自动触发，不应把显式
// CAPTCHA 动作降级成通用状态页。
func TestHandlerExplicitCaptchaActionIgnoresGlobalAutoSwitch(t *testing.T) {
	protection := store.DefaultProtectionConfig()
	protection.CaptchaEnabled = false
	protection.CaptchaType = "math"
	protection.BotDetectionEnabled = false
	rt := &snapshot.SiteRuntime{
		Site: store.Site{ID: 1, Host: "explicit-captcha.example.com", Bind: ":80"},
		Bind: ":80",
		Rules: []snapshot.CompiledRule{{
			ID: 84, Phase: store.PhaseCustom, Kind: "block_path_exact", Arg: "/guarded",
			Action: store.ActionCaptchaChallenge, CaptchaType: "rotate", Priority: 1,
		}},
		EffectiveProtection: &protection,
	}
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{
		Revision: 1, Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{snapshot.SiteMapKey(":80", rt.Site.Host): rt},
	})
	captchaManager := challenge.NewCaptchaManager(nil, 0)
	captchaManager.SetGoCaptchaProvider(challenge.NewGoCaptchaProvider(challenge.DefaultGoCaptchaConfig(), slog.Default()))
	defer captchaManager.Close()
	handler := Handler(Options{
		Holder: holder, Engine: engine.New(holder, nil, nil, nil), Log: slog.Default(),
		Bind: ":80", CaptchaManager: captchaManager,
	})
	ctx := app.NewContext(0)
	ctx.Request.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/guarded")
	ctx.Request.SetHost(rt.Site.Host)
	handler(context.Background(), ctx)
	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got)
	}
	body := string(ctx.Response.Body())
	if strings.Contains(body, "__waf_challenge_token") {
		t.Fatalf("explicit CAPTCHA action fell back to generic JS challenge token: %s", body)
	}
	sessionID := extractCaptchaSessionFromPage(t, body)
	if sessionID == "" {
		t.Fatal("captcha page did not expose session id")
	}
	if got := captchaEnvelopeType(t, captchaManager, sessionID, body); got != "rotate" {
		t.Fatalf("explicit CAPTCHA action did not render selected type: got %q", got)
	}
}

func TestBuildAccessLogEntryKeepsHTTPProtocol(t *testing.T) {
	ctx := app.NewContext(0)
	entry := buildAccessLogEntry(ctx, accessLogInfo{
		SiteID:       1,
		StatusCode:   200,
		WAFAction:    "none",
		HTTPProtocol: "h2",
	})
	if entry.HTTPProtocol != "h2" {
		t.Fatalf("HTTPProtocol = %q, want %q", entry.HTTPProtocol, "h2")
	}
}

func TestBuildAccessLogEntryPersistsTLSCipherSuites(t *testing.T) {
	ctx := app.NewContext(0)
	entry := buildAccessLogEntry(ctx, accessLogInfo{
		SiteID:     1,
		StatusCode: 403,
		WAFAction:  "intercept",
		TLSFingerprint: bot.TLSClientFingerprint{
			CipherSuites: []uint16{4865, 4866},
		},
	})
	if entry.TLSCipherSuites != "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384" {
		t.Fatalf("TLSCipherSuites = %q, want canonical TLS suite names", entry.TLSCipherSuites)
	}
}

func TestBuildAccessLogEntryPersistsTLSShapeMetadata(t *testing.T) {
	ctx := app.NewContext(0)
	entry := buildAccessLogEntry(ctx, accessLogInfo{
		SiteID:     1,
		StatusCode: 403,
		WAFAction:  "intercept",
		TLSFingerprint: bot.TLSClientFingerprint{
			Extensions:   []uint16{0, 16, 43},
			Curves:       []uint16{29, 23},
			PointFormats: []uint8{0},
		},
	})
	if entry.TLSExtensions != "0,16,43" {
		t.Fatalf("TLSExtensions = %q, want %q", entry.TLSExtensions, "0,16,43")
	}
	if entry.TLSCurves != "29,23" {
		t.Fatalf("TLSCurves = %q, want %q", entry.TLSCurves, "29,23")
	}
	if entry.TLSPointFormats != "0" {
		t.Fatalf("TLSPointFormats = %q, want %q", entry.TLSPointFormats, "0")
	}
}

func TestBuildAccessLogEntryPersistsVisitorFusionOnlyForReleasedHTTPS(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Request.Header.Set("Sec-CH-UA", `"Chromium";v="123"`)
	ctx.Request.Header.Set("Accept", "text/html")
	ctx.Request.Header.Set("Accept-Encoding", "gzip, br")
	fp := bot.TLSClientFingerprint{
		JA3:        "771,4865,0,29,0",
		JA4:        "t13d1516h2_0123456789ab_0123456789ab",
		TLSVersion: "TLS13",
		ALPN:       []string{"h2"},
	}

	entry := buildAccessLogEntry(ctx, accessLogInfo{
		SiteID:                1,
		Method:                "GET",
		UserAgent:             "Mozilla/5.0 Chrome/123.0 Safari/537.36",
		StatusCode:            200,
		WAFAction:             "observe",
		TLSFingerprint:        fp,
		VisitorFusionEligible: true,
		VisitorFusionAction:   action.Result{Matched: true, Type: action.Observe},
	})
	if entry.VisitorFusionClass != "human" || !entry.VisitorFusionEvidenceSufficient {
		t.Fatalf("released HTTPS fusion fields = %#v", entry)
	}
	if entry.VisitorFusionClientFamily != "chromium_like" || entry.VisitorFusionConsistency != "consistent" {
		t.Fatalf("unexpected fusion family/consistency: %#v", entry)
	}

	httpEntry := buildAccessLogEntry(ctx, accessLogInfo{
		SiteID:                1,
		TLSFingerprint:        fp,
		VisitorFusionEligible: false,
		VisitorFusionAction:   action.Result{Matched: true, Type: action.Observe},
	})
	if httpEntry.VisitorFusionClass != "" || httpEntry.VisitorFusionReasons != "" {
		t.Fatalf("HTTP site must not persist fusion fields: %#v", httpEntry)
	}

	terminalEntry := buildAccessLogEntry(ctx, accessLogInfo{
		SiteID:                1,
		TLSFingerprint:        fp,
		VisitorFusionEligible: true,
		VisitorFusionAction:   action.Result{Matched: true, Type: action.Drop},
	})
	if terminalEntry.VisitorFusionClass != "" || terminalEntry.VisitorFusionReasons != "" {
		t.Fatalf("terminal WAF action must not persist fusion fields: %#v", terminalEntry)
	}
}

func TestShouldEvaluateVisitorFusionRejectsTerminalActions(t *testing.T) {
	base := accessLogInfo{
		VisitorFusionEligible: true,
		TLSFingerprint:        bot.TLSClientFingerprint{TLSVersion: "TLS13"},
		VisitorFusionAction:   action.Result{Matched: true, Type: action.Observe},
	}
	if !shouldEvaluateVisitorFusion(base) {
		t.Fatal("released HTTPS request must enter visitor fusion")
	}

	terminalTypes := []action.Type{
		action.Drop,
		action.Intercept,
		action.RateLimit,
		action.Challenge,
		action.CaptchaChallenge,
		action.ShieldChallenge,
		action.ChainChallenge,
		action.Redirect,
	}
	for _, actionType := range terminalTypes {
		info := base
		info.VisitorFusionAction = action.Result{Matched: true, Type: actionType}
		if shouldEvaluateVisitorFusion(info) {
			t.Errorf("terminal action %q must not execute visitor fusion", actionType)
		}
	}
}

func TestRecordSecurityEventAddsTLSMetadata(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/tls-security-event?q=1")
	ctx.Request.Header.Set("Host", "127.0.0.1")
	ctx.Request.Header.Set("User-Agent", "tls-security-event-test")
	reqCtx := ContextWithTLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		JA3:          "771,4865-4866,0-11,29,0",
		JA3Hash:      "0123456789abcdef0123456789abcdef",
		JA4:          "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
		TLSVersion:   "TLS13",
		SNI:          "security-event.example",
		ALPN:         []string{"h2", "http/1.1"},
		CipherSuites: []uint16{4865, 4866},
		Extensions:   []uint16{0, 11, 29},
		Curves:       []uint16{29, 23},
		PointFormats: []uint8{0},
	})
	if fp, ok := tlsFingerprintFromContext(reqCtx); ok {
		ctx.Set(tlsFingerprintContextKey, fp)
	}

	recordSecurityEvent(ctx, Options{Writer: writer}, store.SecurityEvent{
		SiteID:     1,
		RequestID:  "req-tls-security",
		ClientIP:   "127.0.0.1",
		Host:       "127.0.0.1",
		Path:       "/tls-security-event",
		Method:     "GET",
		UserAgent:  "tls-security-event-test",
		RuleIDStr:  "owasp:sqli:001",
		Phase:      "owasp_default",
		Action:     "intercept",
		Category:   "sqli",
		MatchDesc:  "SQL injection signals",
		StatusCode: 403,
	})
	writer.Close()

	var got store.SecurityEvent
	if err := db.Where("request_id = ?", "req-tls-security").First(&got).Error; err != nil {
		t.Fatalf("read security event: %v", err)
	}
	if got.TLSSNI != "security-event.example" || got.TLSVersion != "TLS13" || got.TLSALPN != "h2,http/1.1" {
		t.Fatalf("security event missed TLS metadata: %#v", got)
	}
	if got.TLSJA3Hash != "0123456789abcdef0123456789abcdef" || got.TLSJA4 == "" || got.TLSJA3 == "" {
		t.Fatalf("security event missed TLS fingerprint: %#v", got)
	}
	if got.TLSCipherSuites != "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384" {
		t.Fatalf("security event missed TLS cipher suites: %#v", got)
	}
	if got.TLSExtensions != "0,11,29" || got.TLSCurves != "29,23" || got.TLSPointFormats != "0" {
		t.Fatalf("security event missed TLS shape metadata: %#v", got)
	}
	if got.HeaderOrder == "" {
		t.Fatalf("security event missed header order: %#v", got)
	}
}

func TestRecordSecurityEventAddsInternalHTTP3TLSMetadata(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/h3-security-event?q=1")
	ctx.Request.Header.Set("Host", "h3.example.com")
	ctx.Request.Header.Set("User-Agent", "h3-security-event-test")
	ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSVersionHeader, "TLS13")
	ctx.Request.Header.Set(InternalHTTP3TLSSNIHeader, "client.example")
	ctx.Request.Header.Set(InternalHTTP3TLSALPNHeader, "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSJA3Header, "771,4865-4866,0-16-43,29,0")
	ctx.Request.Header.Set(InternalHTTP3TLSJA3HashHeader, "0123456789abcdef0123456789abcdef")
	ctx.Request.Header.Set(InternalHTTP3TLSJA4Header, "q13d0511h3_fea09b2e4d67_1234567890ab")
	ctx.Request.Header.Set(InternalHTTP3TLSCipherSuitesHeader, "4865,4866")
	ctx.Request.Header.Set(InternalHTTP3TLSExtensionsHeader, "0,16,43")
	ctx.Request.Header.Set(InternalHTTP3TLSCurvesHeader, "29,23")
	ctx.Request.Header.Set(InternalHTTP3TLSPointFormatsHeader, "0")
	ctx.SetConn(&loopbackHertzConn{
		Conn:       &testHertzConn{Conn: server},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	applyInternalHTTP3RequestMetadata(ctx)

	recordSecurityEvent(ctx, Options{Writer: writer}, store.SecurityEvent{
		SiteID:     1,
		RequestID:  "req-h3-tls-security",
		ClientIP:   "127.0.0.1",
		Host:       "h3.example.com",
		Path:       "/h3-security-event",
		Method:     "GET",
		UserAgent:  "h3-security-event-test",
		RuleIDStr:  "custom:h3:001",
		Phase:      "custom",
		Action:     "intercept",
		Category:   "fingerprint",
		MatchDesc:  "HTTP/3 fingerprint match",
		StatusCode: 403,
	})
	writer.Close()

	var got store.SecurityEvent
	if err := db.Where("request_id = ?", "req-h3-tls-security").First(&got).Error; err != nil {
		t.Fatalf("read security event: %v", err)
	}
	if got.TLSVersion != "TLS13" || got.TLSSNI != "client.example" || got.TLSALPN != "h3" {
		t.Fatalf("internal HTTP/3 security event missed TLS metadata: %#v", got)
	}
	if got.TLSJA3 != "771,4865-4866,0-16-43,29,0" || got.TLSJA3Hash != "0123456789abcdef0123456789abcdef" || got.TLSJA4 != "q13d0511h3_fea09b2e4d67_1234567890ab" {
		t.Fatalf("internal HTTP/3 security event missed JA3/JA4 metadata: %#v", got)
	}
	if got.TLSCipherSuites != "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384" {
		t.Fatalf("internal HTTP/3 security event missed TLS cipher suites: %#v", got)
	}
	if got.TLSExtensions != "0,16,43" || got.TLSCurves != "29,23" || got.TLSPointFormats != "0" {
		t.Fatalf("internal HTTP/3 security event missed TLS shape metadata: %#v", got)
	}
}

func TestHandlerRecordsTLSSNIWarningForHostMismatch(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:         1,
			Host:       "app.example.com",
			Bind:       ":443",
			TLSEnabled: true,
		},
		Bind:                ":443",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":443", "app.example.com"): &rt,
		},
	}
	holder.Store(sn)

	handler := Handler(Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Writer: writer,
		Log:    slog.Default(),
		Bind:   ":443",
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/sni-warning")
	ctx.Request.Header.SetHost("app.example.com")
	ctx.Request.Header.Set("User-Agent", "tls-sni-warning-test")

	handler(ContextWithTLSHandshakeInfo(context.Background(), "TLS13", "other.example.com", "h2"), ctx)
	writer.Close()

	if got := ctx.Response.StatusCode(); got != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", got, http.StatusNoContent)
	}

	var got store.SecurityEvent
	if err := db.Where("site_id = ? AND rule_id_str = ?", 1, "tls:unknown_sni").First(&got).Error; err != nil {
		t.Fatalf("read TLS SNI warning event: %v", err)
	}
	if got.Action != "observe" || got.Phase != "tls" || got.Category != "tls_sni" {
		t.Fatalf("unexpected TLS SNI warning classification: %#v", got)
	}
	if got.Host != "app.example.com" || got.TLSSNI != "other.example.com" || got.TLSVersion != "TLS13" || got.TLSALPN != "h2" {
		t.Fatalf("unexpected TLS SNI warning metadata: %#v", got)
	}
	if got.Path != "/sni-warning" || got.Method != "GET" || got.UserAgent != "tls-sni-warning-test" {
		t.Fatalf("unexpected TLS SNI request metadata: %#v", got)
	}
	if got.MatchDesc != "tls_sni=other.example.com host=app.example.com" {
		t.Fatalf("match_desc = %q", got.MatchDesc)
	}
}

func TestHandlerSkipsTLSSNIWarningWhenHostMatches(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:         1,
			Host:       "app.example.com",
			Bind:       ":443",
			TLSEnabled: true,
		},
		Bind:                ":443",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":443", "app.example.com"): &rt,
		},
	}
	holder.Store(sn)

	handler := Handler(Options{
		Holder: holder,
		Engine: engine.New(holder, nil, nil, nil),
		Writer: writer,
		Log:    slog.Default(),
		Bind:   ":443",
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/sni-ok")
	ctx.Request.Header.SetHost("APP.EXAMPLE.COM:443")

	handler(ContextWithTLSHandshakeInfo(context.Background(), "TLS13", " app.example.com ", "h2"), ctx)
	writer.Close()

	if got := ctx.Response.StatusCode(); got != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", got, http.StatusNoContent)
	}

	var count int64
	if err := db.Model(&store.SecurityEvent{}).Where("category = ?", "tls_sni").Count(&count).Error; err != nil {
		t.Fatalf("count TLS SNI warning events: %v", err)
	}
	if count != 0 {
		t.Fatalf("TLS SNI warning event count = %d, want 0", count)
	}
}

func TestHandlerRecordedResourcesKeepMatchFieldsRawButStoreRedactedAudits(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recorded_resources.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	if err := db.AutoMigrate(&store.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resources: %v", err)
	}
	recordedRepo := repository.NewRecordedResourceRepo(db)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("upstream method = %s, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "sid=resp-secret")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"resp-secret","status":"ok"}`))
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "app.example.com",
			Bind: ":80",
		},
		Bind:                ":80",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
		AppRouteRules: []appresource.CompiledRule{
			{ID: 11, Target: store.AppRouteTargetRequestBody, Op: store.AppRouteOpContains, Pattern: `"password":"secret"`},
			{ID: 12, Target: store.AppRouteTargetResponseBody, Op: store.AppRouteOpContains, Pattern: `"token":"resp-secret"`},
			{ID: 13, Target: store.AppRouteTargetFingerprint, Op: store.AppRouteOpContains, Pattern: "ja3-match-value"},
		},
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "app.example.com"): &rt,
		},
	}
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	resourceAgg := NewRecordedResourceAggregator(recordedRepo, slog.Default())
	handler := Handler(Options{
		Holder:             holder,
		Engine:             eng,
		Log:                slog.Default(),
		Bind:               ":80",
		ResourceAggregator: resourceAgg,
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetRequestURI("/submit?page=1&token=query-secret")
	ctx.Request.Header.SetHost("app.example.com")
	ctx.Request.Header.Set("User-Agent", "handler-recorded-resource-test")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Authorization", "Bearer req-secret")
	ctx.Request.SetBody([]byte(`{"username":"alice","password":"secret"}`))

	handler(ContextWithTLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		TLSVersion: "TLS13",
		SNI:        "client.example",
		ALPN:       []string{"h3"},
		JA3Hash:    "ja3-match-value",
		JA4:        "ja4-match-value",
	}), ctx)

	// Record 为同步调用，Close 强制 flush 内存聚合条目，落库后即可确定性查询。
	resourceAgg.Close()

	if got := ctx.Response.StatusCode(); got != http.StatusCreated {
		t.Fatalf("status = %d, want %d", got, http.StatusCreated)
	}

	var rec store.RecordedResource
	deadline := time.Now().Add(2 * time.Second)
	for {
		err = db.Where("site_id = ? AND method = ? AND host = ? AND path = ?", 1, "POST", "app.example.com", "/submit").First(&rec).Error
		if err == nil {
			break
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("load recorded resource: %v", err)
		}
		if time.Now().After(deadline) {
			var rows []store.RecordedResource
			if listErr := db.Order("id ASC").Find(&rows).Error; listErr != nil {
				t.Fatalf("timed out waiting for recorded resource row; list rows failed: %v", listErr)
			}
			t.Fatalf("timed out waiting for recorded resource row, existing rows=%#v", rows)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if rec.MatchedRuleIDs != "11,12,13" || rec.PrimaryRuleID != 11 {
		t.Fatalf("unexpected matched rule metadata: %#v", rec)
	}
	if rec.TLSVersion != "TLS13" || rec.TLSSNI != "client.example" || rec.TLSALPN != "h3" {
		t.Fatalf("unexpected TLS metadata: %#v", rec)
	}
	if rec.JA3Hash != "ja3-match-value" || rec.JA4 != "ja4-match-value" {
		t.Fatalf("unexpected TLS fingerprint metadata: %#v", rec)
	}
	if rec.QueryString != "page=1&token=%5Bredacted%5D" {
		t.Fatalf("QueryString = %q, want sanitized query", rec.QueryString)
	}
	if strings.Contains(rec.RequestHeadersJSON, "req-secret") || !strings.Contains(rec.RequestHeadersJSON, `[redacted]`) {
		t.Fatalf("request_headers_json should redact secrets, got %q", rec.RequestHeadersJSON)
	}
	if strings.Contains(rec.ResponseHeadersJSON, "resp-secret") || !strings.Contains(rec.ResponseHeadersJSON, `[redacted]`) {
		t.Fatalf("response_headers_json should redact secrets, got %q", rec.ResponseHeadersJSON)
	}
	if strings.Contains(rec.RequestBodySnippet, "secret") || !strings.Contains(rec.RequestBodySnippet, `[redacted]`) {
		t.Fatalf("request_body_snippet should redact secrets, got %q", rec.RequestBodySnippet)
	}
	if strings.Contains(rec.ResponseBodySnippet, "resp-secret") || !strings.Contains(rec.ResponseBodySnippet, `[redacted]`) {
		t.Fatalf("response_body_snippet should redact secrets, got %q", rec.ResponseBodySnippet)
	}
}

func TestHandlerRecordedResourcesUseInternalHTTP3TLSMetadata(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recorded_resources_h3.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	if err := db.AutoMigrate(&store.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resources: %v", err)
	}
	recordedRepo := repository.NewRecordedResourceRepo(db)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:         1,
			Host:       "h3-resource.example.com",
			Bind:       ":443",
			TLSEnabled: true,
		},
		Bind:                ":443",
		UpstreamURLs:        []string{upstream.URL},
		EffectiveProtection: &protection,
		AppRouteRules: []appresource.CompiledRule{
			{ID: 21, Target: store.AppRouteTargetRequestMethod, Op: store.AppRouteOpEq, Pattern: "GET"},
		},
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":443", "h3-resource.example.com"): &rt,
		},
	}
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	resourceAgg := NewRecordedResourceAggregator(recordedRepo, slog.Default())
	handler := Handler(Options{
		Holder:             holder,
		Engine:             eng,
		Log:                slog.Default(),
		Bind:               ":443",
		ResourceAggregator: resourceAgg,
	})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/assets/app.js?v=1")
	ctx.Request.Header.SetHost("h3-resource.example.com")
	ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
	ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSVersionHeader, "TLS13")
	ctx.Request.Header.Set(InternalHTTP3TLSSNIHeader, "client.example")
	ctx.Request.Header.Set(InternalHTTP3TLSALPNHeader, "h3")
	ctx.Request.Header.Set(InternalHTTP3TLSJA3Header, "771,4865-4866,0-16-43,29,0")
	ctx.Request.Header.Set(InternalHTTP3TLSJA3HashHeader, "0123456789abcdef0123456789abcdef")
	ctx.Request.Header.Set(InternalHTTP3TLSJA4Header, "q13d0511h3_fea09b2e4d67_1234567890ab")
	ctx.SetConn(&loopbackHertzConn{
		Conn: &testHertzConn{Conn: bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{
			TLSVersion: "TLS13",
			SNI:        "proxy.example",
			ALPN:       []string{"h2"},
			JA3Hash:    "proxy-ja3",
			JA4:        "proxy-ja4",
		})},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
	})

	handler(context.Background(), ctx)

	// Record 为同步调用，Close 强制 flush 内存聚合条目，落库后即可确定性查询。
	resourceAgg.Close()

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}

	var rec store.RecordedResource
	deadline := time.Now().Add(2 * time.Second)
	for {
		err = db.Where("site_id = ? AND method = ? AND host = ? AND path = ?", 1, "GET", "h3-resource.example.com", "/assets/app.js").First(&rec).Error
		if err == nil {
			break
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("load recorded resource: %v", err)
		}
		if time.Now().After(deadline) {
			var rows []store.RecordedResource
			if listErr := db.Order("id ASC").Find(&rows).Error; listErr != nil {
				t.Fatalf("timed out waiting for recorded resource row; list rows failed: %v", listErr)
			}
			t.Fatalf("timed out waiting for recorded resource row, existing rows=%#v", rows)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if rec.TLSVersion != "TLS13" || rec.TLSSNI != "client.example" || rec.TLSALPN != "h3" {
		t.Fatalf("recorded resource missed internal HTTP/3 TLS metadata: %#v", rec)
	}
	if rec.JA3Hash != "0123456789abcdef0123456789abcdef" || rec.JA4 != "q13d0511h3_fea09b2e4d67_1234567890ab" {
		t.Fatalf("recorded resource missed internal HTTP/3 JA3/JA4 metadata: %#v", rec)
	}
	if rec.QueryString != "v=1" {
		t.Fatalf("QueryString = %q, want %q", rec.QueryString, "v=1")
	}
}

func TestHandlerRecordedResourcesIncludeInterceptedRequestsWithoutTreatingLocalBlockPageAsUpstreamResponse(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "recorded_resources_intercept.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	if err := db.AutoMigrate(&store.RecordedResource{}); err != nil {
		t.Fatalf("migrate recorded resources: %v", err)
	}
	recordedRepo := repository.NewRecordedResourceRepo(db)

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "blocked.example.com",
			Bind: ":80",
		},
		Bind:     ":80",
		PolicyID: 1,
		Rules: []snapshot.CompiledRule{
			{
				ID:       41,
				Phase:    store.PhaseCustom,
				Kind:     "block_path_exact",
				Arg:      "/blocked",
				Action:   store.ActionIntercept,
				Priority: 1,
			},
		},
		EffectiveProtection: &protection,
		AppRouteRules: []appresource.CompiledRule{
			{ID: 71, Target: store.AppRouteTargetRequestMethod, Op: store.AppRouteOpEq, Pattern: "POST"},
			{ID: 72, Target: store.AppRouteTargetResponseBody, Op: store.AppRouteOpContains, Pattern: "访问被拒绝"},
		},
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "blocked.example.com"): &rt,
		},
	}
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	resourceAgg := NewRecordedResourceAggregator(recordedRepo, slog.Default())
	handler := Handler(Options{
		Holder:             holder,
		Engine:             eng,
		Log:                slog.Default(),
		Bind:               ":80",
		ResourceAggregator: resourceAgg,
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetRequestURI("/blocked?redirect=%2Fconsole&token=req-secret")
	ctx.Request.Header.SetHost("blocked.example.com")
	ctx.Request.Header.Set("User-Agent", "handler-intercept-recorded-resource-test")
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.SetBody([]byte(`{"token":"body-secret","status":"attempt"}`))

	handler(ContextWithTLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		TLSVersion: "TLS13",
		SNI:        "blocked.example.com",
		ALPN:       []string{"h2"},
		JA3Hash:    "ja3-intercept-value",
		JA4:        "ja4-intercept-value",
	}), ctx)

	// Record 为同步调用，Close 强制 flush 内存聚合条目，落库后即可确定性查询。
	resourceAgg.Close()

	if got := ctx.Response.StatusCode(); got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
	}

	var rec store.RecordedResource
	deadline := time.Now().Add(2 * time.Second)
	for {
		err = db.Where("site_id = ? AND method = ? AND host = ? AND path = ?", 1, "POST", "blocked.example.com", "/blocked").First(&rec).Error
		if err == nil {
			break
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("load recorded resource: %v", err)
		}
		if time.Now().After(deadline) {
			var rows []store.RecordedResource
			if listErr := db.Order("id ASC").Find(&rows).Error; listErr != nil {
				t.Fatalf("timed out waiting for recorded resource row; list rows failed: %v", listErr)
			}
			t.Fatalf("timed out waiting for recorded resource row, existing rows=%#v", rows)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if rec.MatchedRuleIDs != "71" || rec.PrimaryRuleID != 71 {
		t.Fatalf("unexpected matched rule metadata: %#v", rec)
	}
	if rec.TLSVersion != "TLS13" || rec.TLSSNI != "blocked.example.com" || rec.TLSALPN != "h2" {
		t.Fatalf("unexpected TLS metadata: %#v", rec)
	}
	if rec.JA3Hash != "ja3-intercept-value" || rec.JA4 != "ja4-intercept-value" {
		t.Fatalf("unexpected TLS fingerprint metadata: %#v", rec)
	}
	if rec.QueryString != "redirect=%2Fconsole&token=%5Bredacted%5D" {
		t.Fatalf("QueryString = %q, want sanitized query", rec.QueryString)
	}
	if strings.Contains(rec.RequestBodySnippet, "body-secret") || !strings.Contains(rec.RequestBodySnippet, `[redacted]`) {
		t.Fatalf("request_body_snippet should redact secrets, got %q", rec.RequestBodySnippet)
	}
	if !strings.Contains(rec.ResponseBodySnippet, "访问被拒绝") {
		t.Fatalf("response_body_snippet should keep local intercept page preview, got %q", rec.ResponseBodySnippet)
	}
}

func TestHandlerRejectsTooManyRequestHeaders(t *testing.T) {
	holder := &snapshot.Holder{}
	sn := &snapshot.Snapshot{
		Revision:    1,
		Protection:  store.DefaultProtectionConfig(),
		HTTP2Config: snapshot.HTTP2Config{MaxHeaderFields: 3},
	}
	holder.Store(sn)
	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder: holder,
		Engine: eng,
		Log:    slog.Default(),
		Bind:   ":443",
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetHost("headers.example.com")
	for i := 0; i < 4; i++ {
		ctx.Request.Header.Add("X-Header-"+strconv.Itoa(i), "v")
	}

	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != 431 {
		t.Fatalf("status = %d, want 431", got)
	}
	if got := string(ctx.Response.Body()); !strings.Contains(got, "431") || !strings.Contains(got, "Request Header Field(s) Too Large") {
		t.Fatalf("body = %q, want 431 error page", got)
	}
}

func TestHandlerRecordsProtocolEarlyAccessLog(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer writer.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	holder.Store(&snapshot.Snapshot{
		Revision:    1,
		Protection:  protection,
		HTTP2Config: snapshot.HTTP2Config{MaxHeaderFields: 1},
	})
	handler := Handler(Options{
		Holder:                holder,
		Engine:                engine.New(holder, nil, nil, nil),
		Writer:                writer,
		AccessLogSamplingRate: 0,
		Bind:                  ":443",
	})
	ctx := app.NewContext(0)
	ctx.Request.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/protocol-limit")
	ctx.Request.Header.SetHost("headers.example.test")
	ctx.Request.Header.Add("X-Header", "v")
	fp := bot.TLSClientFingerprint{TLSVersion: "TLS13", JA3Hash: "ja3-431", JA4: "ja4-431"}
	handler(ContextWithTLSFingerprint(context.Background(), fp), ctx)
	writer.Close()

	if got := ctx.Response.StatusCode(); got != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want %d", got, http.StatusRequestHeaderFieldsTooLarge)
	}
	requestID := string(ctx.Response.Header.Peek("X-Request-ID"))
	var entry store.AccessLog
	if err := db.Where("request_id = ?", requestID).First(&entry).Error; err != nil {
		t.Fatalf("read protocol access log: %v", err)
	}
	if entry.StatusCode != http.StatusRequestHeaderFieldsTooLarge || entry.WAFAction != "protocol_error" || entry.Path != "/protocol-limit" {
		t.Fatalf("protocol access log = %#v", entry)
	}
	if entry.TLSVersion != fp.TLSVersion || entry.TLSJA3Hash != fp.JA3Hash || entry.TLSJA4 != fp.JA4 {
		t.Fatalf("protocol access log lost TLS fingerprint: %#v", entry)
	}
}

func TestScrubResponseHopByHopHeaders(t *testing.T) {
	ctx := app.NewContext(0)
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Transfer-Encoding", "chunked")
	ctx.Response.Header.Set("Upgrade", "websocket")

	scrubResponseHopByHopHeaders(ctx)

	for _, key := range []string{"Connection", "Transfer-Encoding", "Upgrade"} {
		if got := string(ctx.Response.Header.Peek(key)); got != "" {
			t.Fatalf("%s header was not scrubbed: %q", key, got)
		}
	}
}

func TestHandlerHEADCacheMissUsesStreamingForwardPath(t *testing.T) {
	payload := []byte(strings.Repeat("head-cache-miss-body-", 128))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("upstream method = %s, want HEAD", r.Method)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Header().Set("X-Upstream", "head-cache-miss")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:         ":80",
		UpstreamURLs: []string{upstream.URL},
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/cacheable", TTL: 60},
		},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): &rt,
		},
	}
	holder.Store(sn)

	responseCache := cache.NewResponseCache(16, 60)
	defer responseCache.Close()

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("HEAD")
	ctx.Request.SetRequestURI("/cacheable/head.txt")
	ctx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := len(ctx.Response.Body()); got != 0 {
		t.Fatalf("HEAD response body length = %d, want 0", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Encoding")); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != strconv.Itoa(len(payload)) {
		t.Fatalf("Content-Length = %q, want %d", got, len(payload))
	}
	if got := string(ctx.Response.Header.Peek("X-Upstream")); got != "head-cache-miss" {
		t.Fatalf("X-Upstream = %q, want head-cache-miss", got)
	}
	if entries, _ := responseCache.Stats(); entries != 0 {
		t.Fatalf("response cache entries = %d, want 0", entries)
	}
}

func TestHandlerHEADCacheHitWritesMetadataWithoutBody(t *testing.T) {
	payload := []byte(strings.Repeat("head-cache-hit-body-", 128))
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("upstream method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:         ":80",
		UpstreamURLs: []string{upstream.URL},
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/cacheable", TTL: 60},
		},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): &rt,
		},
	}
	holder.Store(sn)

	responseCache := cache.NewResponseCache(16, 60)
	defer responseCache.Close()

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})

	getCtx := app.NewContext(0)
	getCtx.Request.Header.SetMethod("GET")
	getCtx.Request.SetRequestURI("/cacheable/head-hit.txt")
	getCtx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), getCtx)

	if got := getCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", got, http.StatusOK)
	}
	if !bytes.Equal(getCtx.Response.Body(), payload) {
		t.Fatalf("GET body length = %d, want %d", len(getCtx.Response.Body()), len(payload))
	}
	if entries, _ := responseCache.Stats(); entries != 1 {
		t.Fatalf("response cache entries after GET = %d, want 1", entries)
	}

	headCtx := app.NewContext(0)
	headCtx.Request.Header.SetMethod("HEAD")
	headCtx.Request.SetRequestURI("/cacheable/head-hit.txt")
	headCtx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), headCtx)

	if got := headCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("HEAD status = %d, want %d", got, http.StatusOK)
	}
	if got := len(headCtx.Response.Body()); got != 0 {
		t.Fatalf("HEAD response body length = %d, want 0", got)
	}
	if got := string(headCtx.Response.Header.Peek("Content-Length")); got != strconv.Itoa(len(payload)) {
		t.Fatalf("HEAD Content-Length = %q, want %d", got, len(payload))
	}
	if got := string(headCtx.Response.Header.Peek("Content-Type")); got != "text/plain; charset=utf-8" {
		t.Fatalf("HEAD Content-Type = %q, want text/plain; charset=utf-8", got)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests = %d, want 1", got)
	}
}

func TestHandlerRecompressesDecodedCachedUpstreamCompressedResponses(t *testing.T) {
	upstreamBody := []byte(strings.Repeat("cached decoded handler gzip response.", 96))
	var encoded bytes.Buffer
	gzipWriter := gzip.NewWriter(&encoded)
	if _, err := gzipWriter.Write(upstreamBody); err != nil {
		t.Fatalf("write gzip body: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip body: %v", err)
	}
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(encoded.Len()))
		_, _ = w.Write(encoded.Bytes())
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:                           ":80",
		UpstreamURLs:                   []string{upstream.URL},
		CacheEnabled:                   true,
		ResponseCompressionConfigured:  true,
		ResponseCompressionEnabled:     true,
		ResponseCompressionGzipEnabled: true,
		ResponseCompressionMinBytes:    1024,
		BrotliEnabled:                  true,
		CacheRules:                     []store.SiteCacheRule{{Type: "prefix", Value: "/cacheable", TTL: 60}},
		EffectiveProtection:            &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): &rt,
		},
	}
	holder.Store(sn)

	responseCache := cache.NewResponseCache(16, 60)
	defer responseCache.Close()

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})

	request := func() *app.RequestContext {
		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod("GET")
		ctx.Request.SetRequestURI("/cacheable/compressed.txt")
		ctx.Request.Header.SetHost("cache.example.com")
		ctx.Request.Header.Set("Accept-Encoding", "br, gzip")
		handler(context.Background(), ctx)
		return ctx
	}

	missCtx := request()
	if got := missCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("miss status = %d, want %d", got, http.StatusOK)
	}
	if got := string(missCtx.Response.Header.Peek("Content-Encoding")); got != "br" {
		t.Fatalf("miss Content-Encoding = %q, want br", got)
	}
	if entries, _ := responseCache.Stats(); entries != 1 {
		t.Fatalf("response cache entries after miss = %d, want 1", entries)
	}

	hitCtx := request()
	if got := hitCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("hit status = %d, want %d", got, http.StatusOK)
	}
	if got := string(hitCtx.Response.Header.Peek("Content-Encoding")); got != "br" {
		t.Fatalf("hit Content-Encoding = %q, want br", got)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests = %d, want 1", got)
	}
}

func TestHandlerCacheHitBypassesRangeAndConditionalRequests(t *testing.T) {
	basePayload := []byte("cacheable-full-body")
	tests := []struct {
		name       string
		headerName string
		headerVal  string
		wantStatus int
		wantBody   []byte
	}{
		{
			name:       "range",
			headerName: "Range",
			headerVal:  "bytes=0-4",
			wantStatus: http.StatusPartialContent,
			wantBody:   []byte("cache"),
		},
		{
			name:       "if-none-match",
			headerName: "If-None-Match",
			headerVal:  `"cache-etag"`,
			wantStatus: http.StatusNotModified,
			wantBody:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var upstreamRequests atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamRequests.Add(1)
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("ETag", `"cache-etag"`)

				switch {
				case r.Header.Get("Range") != "":
					if got := r.Header.Get("Range"); got != tt.headerVal {
						t.Errorf("Range = %q, want %q", got, tt.headerVal)
					}
					w.Header().Set("Content-Range", "bytes 0-4/19")
					w.WriteHeader(http.StatusPartialContent)
					_, _ = w.Write(tt.wantBody)
				case r.Header.Get("If-None-Match") != "":
					if got := r.Header.Get("If-None-Match"); got != tt.headerVal {
						t.Errorf("If-None-Match = %q, want %q", got, tt.headerVal)
					}
					w.WriteHeader(http.StatusNotModified)
				default:
					_, _ = w.Write(basePayload)
				}
			}))
			defer upstream.Close()

			holder := &snapshot.Holder{}
			protection := store.DefaultProtectionConfig()
			protection.BotDetectionEnabled = false
			rt := snapshot.SiteRuntime{
				Site: store.Site{
					ID:   1,
					Host: "cache.example.com",
					Bind: ":80",
				},
				Bind:         ":80",
				UpstreamURLs: []string{upstream.URL},
				CacheEnabled: true,
				CacheRules: []store.SiteCacheRule{
					{Type: "prefix", Value: "/cacheable", TTL: 60},
				},
				EffectiveProtection: &protection,
			}
			sn := &snapshot.Snapshot{
				Revision:   1,
				Protection: protection,
				Sites: map[string]*snapshot.SiteRuntime{
					snapshot.SiteMapKey(":80", "cache.example.com"): &rt,
				},
			}
			holder.Store(sn)

			responseCache := cache.NewResponseCache(16, 60)
			defer responseCache.Close()

			eng := engine.New(holder, nil, nil, nil)
			handler := Handler(Options{
				Holder:        holder,
				Engine:        eng,
				Log:           slog.Default(),
				Bind:          ":80",
				ResponseCache: responseCache,
			})

			getCtx := app.NewContext(0)
			getCtx.Request.Header.SetMethod("GET")
			getCtx.Request.SetRequestURI("/cacheable/item.txt")
			getCtx.Request.Header.SetHost("cache.example.com")

			handler(context.Background(), getCtx)

			if got := getCtx.Response.StatusCode(); got != http.StatusOK {
				t.Fatalf("GET status = %d, want %d", got, http.StatusOK)
			}
			if !bytes.Equal(getCtx.Response.Body(), basePayload) {
				t.Fatalf("GET body = %q, want %q", getCtx.Response.Body(), basePayload)
			}
			if entries, _ := responseCache.Stats(); entries != 1 {
				t.Fatalf("response cache entries after GET = %d, want 1", entries)
			}

			bypassCtx := app.NewContext(0)
			bypassCtx.Request.Header.SetMethod("GET")
			bypassCtx.Request.SetRequestURI("/cacheable/item.txt")
			bypassCtx.Request.Header.SetHost("cache.example.com")
			bypassCtx.Request.Header.Set(tt.headerName, tt.headerVal)

			handler(context.Background(), bypassCtx)

			if got := bypassCtx.Response.StatusCode(); got != tt.wantStatus {
				t.Fatalf("%s status = %d, want %d", tt.name, got, tt.wantStatus)
			}
			if !bytes.Equal(bypassCtx.Response.Body(), tt.wantBody) {
				t.Fatalf("%s body = %q, want %q", tt.name, bypassCtx.Response.Body(), tt.wantBody)
			}
			if got := upstreamRequests.Load(); got != 2 {
				t.Fatalf("upstream requests = %d, want 2", got)
			}
		})
	}
}

func TestHandlerServesStaleCacheWhenUpstreamFailsAfterCacheExpiry(t *testing.T) {
	staleBody := []byte("stale cached body")
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(staleBody)))
		_, _ = w.Write(staleBody)
	}))

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:         ":80",
		UpstreamURLs: []string{upstream.URL},
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/cacheable", TTL: 1, StaleIfError: 60},
		},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): &rt,
		},
	}
	holder.Store(sn)

	responseCache := cache.NewResponseCache(16, 60)
	defer responseCache.Close()

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})

	fillCtx := app.NewContext(0)
	fillCtx.Request.Header.SetMethod("GET")
	fillCtx.Request.SetRequestURI("/cacheable/stale.txt")
	fillCtx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), fillCtx)

	if got := fillCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("fill status = %d, want %d", got, http.StatusOK)
	}
	if !bytes.Equal(fillCtx.Response.Body(), staleBody) {
		t.Fatalf("fill body = %q, want %q", fillCtx.Response.Body(), staleBody)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests after fill = %d, want 1", got)
	}

	time.Sleep(2 * time.Second)
	upstream.Close()

	staleCtx := app.NewContext(0)
	staleCtx.Request.Header.SetMethod("GET")
	staleCtx.Request.SetRequestURI("/cacheable/stale.txt")
	staleCtx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), staleCtx)

	if got := staleCtx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("stale status = %d, want %d", got, http.StatusOK)
	}
	if !bytes.Equal(staleCtx.Response.Body(), staleBody) {
		t.Fatalf("stale body = %q, want %q", staleCtx.Response.Body(), staleBody)
	}
	if got := string(staleCtx.Response.Header.Peek("Content-Type")); got != "text/plain; charset=utf-8" {
		t.Fatalf("stale Content-Type = %q, want text/plain; charset=utf-8", got)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests after stale fallback = %d, want 1", got)
	}
}

/**
 * TestHandlerDoesNotServeStaleAfterCacheGenerationPurge 验证回源期间发生
 * unsafe 失效后不会继续回放请求开始时捕获的 stale 指针。
 */
func TestHandlerDoesNotServeStaleAfterCacheGenerationPurge(t *testing.T) {
	const targetPath = "/cacheable/stale-generation.txt"
	staleBody := []byte("stale generation body")
	var responseCache *cache.ResponseCache
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟另一个 unsafe 请求在当前回源完成前清理同一站点资源。
		responseCache.PurgeSiteTarget(1, r.URL.RequestURI())
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("upstream writer does not support hijacking")
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack upstream connection: %v", err)
			return
		}
		_ = conn.Close()
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:         ":80",
		UpstreamURLs: []string{upstream.URL},
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/cacheable", TTL: 1, StaleIfError: 60},
		},
		EffectiveProtection: &protection,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): &rt,
		},
	})

	responseCache = cache.NewResponseCache(16, 60)
	defer responseCache.Close()
	key := cache.CacheKey("GET", ":80|1|cache.example.com", targetPath, "")
	if !responseCache.SetForSiteIfGeneration(responseCache.Generation(), 1, targetPath, key, http.StatusOK, "text/plain; charset=utf-8", staleBody, 1, nil) {
		t.Fatal("failed to seed stale cache entry")
	}
	// ResponseCache 使用秒级时间戳；确保条目已过期但仍在 stale-if-error 窗口内。
	time.Sleep(2100 * time.Millisecond)

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI(targetPath)
	ctx.Request.Header.SetHost("cache.example.com")
	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got == http.StatusOK {
		t.Fatalf("stale response was replayed after purge: body=%q", ctx.Response.Body())
	}
	if bytes.Contains(ctx.Response.Body(), staleBody) {
		t.Fatalf("purged stale body leaked into response: %q", ctx.Response.Body())
	}
}

/**
 * TestHandlerStaleFillFollowerRechecksFreshEntry 验证 stale 条目存在时，
 * follower 等待 leader 回源后会复用新鲜填充，不会再次击穿上游。
 */
func TestHandlerStaleFillFollowerRechecksFreshEntry(t *testing.T) {
	const targetPath = "/cacheable/stale-follower.txt"
	staleBody := []byte("old stale body")
	freshBody := []byte("new fresh body")
	var responseCache *cache.ResponseCache
	var upstreamRequests atomic.Int32
	firstUpstreamStarted := make(chan struct{})
	releaseFirstUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := upstreamRequests.Add(1)
		if count == 1 {
			close(firstUpstreamStarted)
			<-releaseFirstUpstream
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(freshBody)))
		_, _ = w.Write(freshBody)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:         ":80",
		UpstreamURLs: []string{upstream.URL},
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/cacheable", TTL: 1, StaleIfError: 60},
		},
		EffectiveProtection: &protection,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): &rt,
		},
	})

	responseCache = cache.NewResponseCache(16, 60)
	defer responseCache.Close()
	key := cache.CacheKey("GET", ":80|1|cache.example.com", targetPath, "")
	if !responseCache.SetForSiteIfGeneration(responseCache.Generation(), 1, targetPath, key, http.StatusOK, "text/plain; charset=utf-8", staleBody, 1, nil) {
		t.Fatal("failed to seed stale cache entry")
	}
	time.Sleep(2100 * time.Millisecond)

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})
	request := func() *app.RequestContext {
		ctx := app.NewContext(0)
		ctx.Request.Header.SetMethod(http.MethodGet)
		ctx.Request.SetRequestURI(targetPath)
		ctx.Request.Header.SetHost("cache.example.com")
		handler(context.Background(), ctx)
		return ctx
	}

	firstDone := make(chan *app.RequestContext, 1)
	go func() { firstDone <- request() }()
	select {
	case <-firstUpstreamStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not reach upstream")
	}
	secondDone := make(chan *app.RequestContext, 1)
	go func() { secondDone <- request() }()
	// 让第二个请求进入 BeginFill 等待，再放行 leader。
	time.Sleep(50 * time.Millisecond)
	close(releaseFirstUpstream)

	first := <-firstDone
	second := <-secondDone
	for name, ctx := range map[string]*app.RequestContext{"leader": first, "follower": second} {
		if got := ctx.Response.StatusCode(); got != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", name, got)
		}
		if !bytes.Equal(ctx.Response.Body(), freshBody) {
			t.Fatalf("%s body = %q, want fresh body %q", name, ctx.Response.Body(), freshBody)
		}
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests = %d, want one leader fill", got)
	}
}

func TestHandlerCacheMissLargeResponseStreamsWithoutCaching(t *testing.T) {
	payload := []byte(strings.Repeat("large-cache-miss-body-", 6000))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("upstream method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	}))
	defer upstream.Close()

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:   1,
			Host: "cache.example.com",
			Bind: ":80",
		},
		Bind:         ":80",
		UpstreamURLs: []string{upstream.URL},
		CacheEnabled: true,
		CacheRules: []store.SiteCacheRule{
			{Type: "prefix", Value: "/cacheable", TTL: 60},
		},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "cache.example.com"): &rt,
		},
	}
	holder.Store(sn)

	responseCache := cache.NewResponseCache(1, 60)
	defer responseCache.Close()
	if int64(len(payload)) <= responseCache.MaxEntryBodySize() {
		t.Fatalf("test payload length = %d, want above cache max entry size %d", len(payload), responseCache.MaxEntryBodySize())
	}

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder:        holder,
		Engine:        eng,
		Log:           slog.Default(),
		Bind:          ":80",
		ResponseCache: responseCache,
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/cacheable/large.txt")
	ctx.Request.Header.SetHost("cache.example.com")

	handler(context.Background(), ctx)

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if !bytes.Equal(ctx.Response.Body(), payload) {
		t.Fatalf("response body length = %d, want %d", len(ctx.Response.Body()), len(payload))
	}
	if got := string(ctx.Response.Header.Peek("Content-Length")); got != "" {
		t.Fatalf("Content-Length = %q, want empty for streamed overflow response", got)
	}
	if entries, _ := responseCache.Stats(); entries != 0 {
		t.Fatalf("response cache entries = %d, want 0", entries)
	}
}

func TestHandlerMatchesTLSHandshakeMetadataRuleWithoutClientHelloFingerprint(t *testing.T) {
	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:         1,
			Host:       "tls-rule.example.com",
			Bind:       ":443",
			TLSEnabled: true,
		},
		Bind:     ":443",
		PolicyID: 1,
		Rules: []snapshot.CompiledRule{
			{
				ID:       11,
				Phase:    store.PhaseCustom,
				Kind:     "tls_sni",
				Arg:      "client.example",
				Action:   store.ActionIntercept,
				Priority: 1,
			},
		},
		EffectiveProtection: &protection,
	}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":443", "tls-rule.example.com"): &rt,
		},
	}
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	handler := Handler(Options{
		Holder: holder,
		Engine: eng,
		Log:    slog.Default(),
		Bind:   ":443",
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetHost("tls-rule.example.com")

	handler(ContextWithTLSHandshakeInfo(context.Background(), "TLS13", "client.example", "h2"), ctx)

	if ctx.Response.StatusCode() != 403 {
		t.Fatalf("status = %d, want 403", ctx.Response.StatusCode())
	}
}

func TestHandlerMatchesInternalHTTP3TLSFingerprintRules(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		rules   []snapshot.CompiledRule
	}{
		{
			name: "ja3 hash rule",
			headers: map[string]string{
				InternalHTTP3TLSVersionHeader: "TLS13",
				InternalHTTP3TLSJA3HashHeader: "0123456789abcdef0123456789abcdef",
				InternalHTTP3TLSJA4Header:     "q13d0511h3_fea09b2e4d67_1234567890ab",
			},
			rules: []snapshot.CompiledRule{
				{
					ID:       11,
					Phase:    store.PhaseCustom,
					Kind:     "tls_ja3_hash",
					Arg:      "0123456789abcdef0123456789abcdef",
					Action:   store.ActionIntercept,
					Priority: 1,
				},
			},
		},
		{
			name: "cipher suites rule",
			headers: map[string]string{
				InternalHTTP3TLSVersionHeader:      "TLS13",
				InternalHTTP3TLSCipherSuitesHeader: "4865,4866",
				InternalHTTP3TLSCurvesHeader:       "29,23",
			},
			rules: []snapshot.CompiledRule{
				{
					ID:       12,
					Phase:    store.PhaseCustom,
					Kind:     "tls_cipher_suites",
					Arg:      "TLS_AES_128_GCM_SHA256",
					Action:   store.ActionIntercept,
					Priority: 1,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			holder := &snapshot.Holder{}
			protection := store.DefaultProtectionConfig()
			protection.BotDetectionEnabled = false
			rt := snapshot.SiteRuntime{
				Site: store.Site{
					ID:         1,
					Host:       "h3-rule.example.com",
					Bind:       ":443",
					TLSEnabled: true,
				},
				Bind:                ":443",
				PolicyID:            1,
				Rules:               tt.rules,
				EffectiveProtection: &protection,
			}
			sn := &snapshot.Snapshot{
				Revision:   1,
				Protection: protection,
				Sites: map[string]*snapshot.SiteRuntime{
					snapshot.SiteMapKey(":443", "h3-rule.example.com"): &rt,
				},
			}
			holder.Store(sn)

			eng := engine.New(holder, nil, nil, nil)
			handler := Handler(Options{
				Holder: holder,
				Engine: eng,
				Log:    slog.Default(),
				Bind:   ":443",
			})

			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod("GET")
			ctx.Request.SetRequestURI("/")
			ctx.Request.Header.SetHost("h3-rule.example.com")
			ctx.Request.Header.Set(InternalHTTP3ProtoHeader, "h3")
			ctx.Request.Header.Set("X-Forwarded-Proto", "h3")
			for key, value := range tt.headers {
				ctx.Request.Header.Set(key, value)
			}
			ctx.SetConn(&loopbackHertzConn{
				Conn: &testHertzConn{Conn: bot.WrapFingerprintConn(server, bot.TLSClientFingerprint{
					TLSVersion: "TLS13",
					JA3Hash:    "proxy-ja3",
					JA4:        "proxy-ja4",
				})},
				localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
				remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			})

			handler(context.Background(), ctx)

			if ctx.Response.StatusCode() != 403 {
				t.Fatalf("status = %d, want 403", ctx.Response.StatusCode())
			}
		})
	}
}

func TestHandlerAppliesSiteAntiReplayTTLToNonceHeaderPhase(t *testing.T) {
	holder := &snapshot.Holder{}
	sn := &snapshot.Snapshot{
		Revision:   1,
		Protection: store.DefaultProtectionConfig(),
		Sites:      make(map[string]*snapshot.SiteRuntime),
	}
	rt := snapshot.SiteRuntime{
		Site: store.Site{
			ID:               1,
			Host:             "ttl.example.com",
			AntiReplayTTL:    1,
			AntiReplayAction: "shield_challenge",
		},
		Bind:              ":80",
		AntiReplayEnabled: true,
	}
	sn.Sites[snapshot.SiteMapKey(":80", "ttl.example.com")] = &rt
	holder.Store(sn)

	eng := engine.New(holder, nil, nil, nil)
	mgr := antireplay.NewAntiReplayManager("handler-anti-replay-ttl", nil, 5*time.Minute)
	eng.SetAntiReplayManager(mgr)

	nonce := mgr.GenerateNonce("")
	time.Sleep(1100 * time.Millisecond)

	handler := Handler(Options{
		Holder: holder,
		Engine: eng,
		Log:    slog.Default(),
		Bind:   ":80",
	})

	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/")
	ctx.Request.Header.SetHost("ttl.example.com")
	ctx.Request.Header.Set("X-Nonce", nonce)

	handler(context.Background(), ctx)

	if ctx.Response.StatusCode() != 403 {
		t.Fatalf("status = %d, want 403", ctx.Response.StatusCode())
	}
}

func TestShouldApplyErrorRateLimitUsesHistoricalErrors(t *testing.T) {
	rl := ratelimit.NewRateLimiter(60, 1, true)
	defer rl.Close()
	eng := engine.New(&snapshot.Holder{}, nil, rl, nil)
	key := "1.2.3.4|example.com"
	prot := store.ProtectionConfig{
		ErrorRateLimitEnabled: true,
		ErrorRateLimitWindow:  60,
		ErrorRateLimitMax:     1,
	}

	rl.Increment(key)
	if shouldApplyErrorRateLimit(eng, prot, key) {
		t.Fatal("rate limit applied at threshold instead of above threshold")
	}
	rl.Increment(key)
	if !shouldApplyErrorRateLimit(eng, prot, key) {
		t.Fatal("rate limit did not apply after historical errors exceeded threshold")
	}
}

func TestIncrementErrorRateLimitStatusHonorsConfiguredBuckets(t *testing.T) {
	rl := ratelimit.NewRateLimiter(60, 1, true)
	defer rl.Close()
	eng := engine.New(&snapshot.Holder{}, nil, rl, nil)
	key := "1.2.3.4|example.com"
	prot := store.ProtectionConfig{
		ErrorRateLimitEnabled:  true,
		ErrorRateLimitWindow:   60,
		ErrorRateLimitMax:      1,
		ErrorRateLimitCount4xx: true,
	}

	incrementErrorRateLimitStatus(eng, prot, key, 500)
	if shouldApplyErrorRateLimit(eng, prot, key) {
		t.Fatal("5xx response was counted while only 4xx bucket is enabled")
	}
	incrementErrorRateLimitStatus(eng, prot, key, 404)
	incrementErrorRateLimitStatus(eng, prot, key, 401)
	if !shouldApplyErrorRateLimit(eng, prot, key) {
		t.Fatal("4xx responses were not counted")
	}
}

func TestIncrementErrorRateLimitBlockHonorsSwitch(t *testing.T) {
	rl := ratelimit.NewRateLimiter(60, 1, true)
	defer rl.Close()
	eng := engine.New(&snapshot.Holder{}, nil, rl, nil)
	key := "1.2.3.4|example.com"
	base := store.ProtectionConfig{
		ErrorRateLimitEnabled: true,
		ErrorRateLimitWindow:  60,
		ErrorRateLimitMax:     1,
	}

	incrementErrorRateLimitBlock(eng, base, key)
	if shouldApplyErrorRateLimit(eng, base, key) {
		t.Fatal("block was counted while error_ratelimit_count_block is disabled")
	}
	countBlocks := base
	countBlocks.ErrorRateLimitCountBlock = true
	incrementErrorRateLimitBlock(eng, countBlocks, key)
	incrementErrorRateLimitBlock(eng, countBlocks, key)
	if !shouldApplyErrorRateLimit(eng, base, key) {
		t.Fatal("block was not counted while error_ratelimit_count_block is enabled")
	}
}

func TestErrorRateLimitDisabledOrInvalidSnapshotNeverReadsOrWritesBackend(t *testing.T) {
	rl := ratelimit.NewRateLimiter(60, 1, true)
	defer rl.Close()
	eng := engine.New(&snapshot.Holder{}, nil, rl, nil)
	key := "1.2.3.4|example.com"
	base := store.ProtectionConfig{
		ErrorRateLimitWindow:     60,
		ErrorRateLimitMax:        1,
		ErrorRateLimitCount4xx:   true,
		ErrorRateLimitCount5xx:   true,
		ErrorRateLimitCountBlock: true,
	}

	// The runtime backend is enabled, but the current snapshot explicitly disables
	// error limiting. Neither the decision nor the historical counters may apply.
	incrementErrorRateLimitStatus(eng, base, key, 404)
	incrementErrorRateLimitStatus(eng, base, key, 500)
	incrementErrorRateLimitBlock(eng, base, key)
	incrementErrorRateLimitBlock(eng, base, key)
	if shouldApplyErrorRateLimit(eng, base, key) {
		t.Fatal("disabled snapshot applied or accumulated an error rate limit")
	}

	valid := base
	valid.ErrorRateLimitEnabled = true
	if shouldApplyErrorRateLimit(eng, valid, key) {
		t.Fatal("disabled snapshot wrote historical error counters")
	}

	invalid := valid
	invalid.ErrorRateLimitWindow = 0
	if shouldApplyErrorRateLimit(eng, invalid, key) {
		t.Fatal("invalid snapshot applied an error rate limit")
	}
	incrementErrorRateLimitStatus(eng, invalid, key, 404)
	if shouldApplyErrorRateLimit(eng, valid, key) {
		t.Fatal("invalid snapshot wrote historical error counters")
	}
}

func TestSiteErrorPageUsesConfiguredHTMLTemplate(t *testing.T) {
	rt := snapshot.SiteRuntime{Site: store.Site{CustomErrorPages: `{"502":{"status_code":502,"title":"Custom Upstream","html":"<h1>{{.StatusCode}}</h1><p>{{.Message}}</p>","content_type":"text/html"}}`}}

	cfg := siteErrorPage(&rt, 502)
	if cfg == nil {
		t.Fatal("siteErrorPage() returned nil for configured status code")
	}
	if cfg.Title != "Custom Upstream" || cfg.StatusCode != 502 {
		t.Fatalf("siteErrorPage() = %#v", cfg)
	}
	if got, want := string(pages.RenderErrorPage(502, cfg)), "<h1>502</h1><p>Custom Upstream</p>"; got != want {
		t.Fatalf("RenderErrorPage() = %q, want %q", got, want)
	}
	if cfg := siteErrorPage(&rt, 504); cfg != nil {
		t.Fatalf("siteErrorPage() returned %#v for unconfigured status code", cfg)
	}
}

func TestSiteErrorPageFillsMissingStatusCode(t *testing.T) {
	rt := snapshot.SiteRuntime{Site: store.Site{CustomErrorPages: `{"503":{"title":"Maintenance","html":"maintenance"}}`}}

	cfg := siteErrorPage(&rt, 503)
	if cfg == nil {
		t.Fatal("siteErrorPage() returned nil for configured status code")
	}
	if cfg.StatusCode != 503 {
		t.Fatalf("siteErrorPage().StatusCode = %d, want 503", cfg.StatusCode)
	}
}

func TestSetChallengeCookieSignsValue(t *testing.T) {
	value := challenge.SignChallengePassValue("example.com", nil, time.Unix(100, 0), time.Hour)
	if value == "1" {
		t.Fatal("challenge pass value must not be a forgeable boolean")
	}
	if !challenge.VerifyChallengePassValue(value, "example.com", nil, time.Unix(101, 0)) {
		t.Fatal("signed challenge pass value did not verify")
	}
	if challenge.VerifyChallengePassValue(value, "other.example", nil, time.Unix(101, 0)) {
		t.Fatal("signed challenge pass value verified for the wrong host")
	}
}

func TestShouldLogDropConsoleCount(t *testing.T) {
	cases := map[uint64]bool{
		1:    true,
		16:   true,
		17:   false,
		1023: false,
		1024: true,
		1025: false,
		2048: true,
	}
	for count, want := range cases {
		if got := shouldLogDropConsoleCount(count); got != want {
			t.Fatalf("shouldLogDropConsoleCount(%d) = %v, want %v", count, got, want)
		}
	}
}

func TestShouldLogNoSiteMatchConsoleCount(t *testing.T) {
	cases := map[uint64]bool{
		1:    true,
		16:   true,
		17:   false,
		1023: false,
		1024: true,
		1025: false,
		2048: true,
	}
	for count, want := range cases {
		if got := shouldLogNoSiteMatchConsoleCount(count); got != want {
			t.Fatalf("shouldLogNoSiteMatchConsoleCount(%d) = %v, want %v", count, got, want)
		}
	}
}

func TestHandlerRecordsAccessLogWhenNoUpstreamConfigured(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site:                store.Site{ID: 1, Host: "unavailable.example.test", Bind: ":80"},
		Bind:                ":80",
		EffectiveProtection: &protection,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "unavailable.example.test"): &rt,
		},
	})

	handler := Handler(Options{
		Holder:                holder,
		Engine:                engine.New(holder, nil, nil, nil),
		Writer:                writer,
		Log:                   slog.Default(),
		Bind:                  ":80",
		AccessLogSamplingRate: 1,
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/health")
	ctx.Request.Header.SetHost("unavailable.example.test")

	handler(context.Background(), ctx)
	writer.Close()

	if got := ctx.Response.StatusCode(); got != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", got, http.StatusBadGateway)
	}
	var entry store.AccessLog
	if err := db.Where("site_id = ?", rt.Site.ID).First(&entry).Error; err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if entry.StatusCode != http.StatusBadGateway || entry.WAFAction != "none" || entry.CacheState != "bypass" {
		t.Fatalf("access log = %#v", entry)
	}
	if entry.Path != "/health" || entry.Upstream != "" {
		t.Fatalf("access log path/upstream = %#v", entry)
	}
}

// TestHandlerFinalizesEarlyExitAccessLog 验证配置快照未加载时仍会留下最小
// 访问审计行，并保留已捕获的 TLS 指纹。无站点路由由独立用例覆盖。
func TestHandlerFinalizesEarlyExitAccessLog(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))

	holder := &snapshot.Holder{}
	handler := Handler(Options{
		Holder:                holder,
		Engine:                engine.New(holder, nil, nil, nil),
		Writer:                writer,
		Log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Bind:                  ":80",
		AccessLogSamplingRate: 0,
	})
	ctx := app.NewContext(0)
	ctx.Request.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/unmatched")
	ctx.Request.SetHost("unknown.example.test")
	handler(ContextWithTLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		JA3Hash:    "ja3-early",
		JA4:        "ja4-early",
		TLSVersion: "TLS13",
	}), ctx)
	writer.Close()

	requestID := string(ctx.Response.Header.Peek("X-Request-ID"))
	if requestID == "" {
		t.Fatal("early response is missing X-Request-ID")
	}
	var entry store.AccessLog
	if err := db.Where("request_id = ?", requestID).First(&entry).Error; err != nil {
		t.Fatalf("read early access log: %v", err)
	}
	if entry.StatusCode != http.StatusServiceUnavailable || entry.WAFAction != "configuration_error" || entry.Path != "/unmatched" {
		t.Fatalf("early access log = %#v", entry)
	}
	if entry.TLSJA3Hash != "ja3-early" || entry.TLSJA4 != "ja4-early" || entry.TLSVersion != "TLS13" {
		t.Fatalf("early access log lost TLS fingerprint: %#v", entry)
	}
}

// TestFinalizeUnrecordedAccessLogKeepsExplicitErrorAfterClientCancel 锁定早期
// 失败的审计边界：客户端取消不能把已经产生的 4xx/5xx 错误从日志中抹掉。
func TestFinalizeUnrecordedAccessLogKeepsExplicitErrorAfterClientCancel(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := app.NewContext(0)
	c.Request.SetMethod(http.MethodGet)
	c.Request.SetRequestURI("/early-error")
	c.Request.SetHost("early-error.example.test")
	c.Response.SetStatusCode(http.StatusBadGateway)

	finalizeUnrecordedAccessLog(ctx, c, Options{Writer: writer, AccessLogSamplingRate: 0}, "early-error-id")
	writer.Close()

	var entry store.AccessLog
	if err := db.Where("request_id = ?", "early-error-id").First(&entry).Error; err != nil {
		t.Fatalf("read canceled early error log: %v", err)
	}
	if entry.StatusCode != http.StatusBadGateway || entry.Path != "/early-error" {
		t.Fatalf("canceled early error log = %#v", entry)
	}
}

func TestFinalizeUnrecordedAccessLogRecordsClientCancelWithStatusZero(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := app.NewContext(0)
	c.Request.SetMethod(http.MethodGet)
	c.Request.SetRequestURI("/client-cancelled")
	c.Request.SetHost("cancelled.example.test")
	fp := bot.TLSClientFingerprint{TLSVersion: "TLS13", JA3Hash: "ja3-cancelled", JA4: "ja4-cancelled"}
	c.Set(tlsFingerprintContextKey, fp)
	c.Response.SetStatusCode(http.StatusOK)

	finalizeUnrecordedAccessLog(ctx, c, Options{Writer: writer, AccessLogSamplingRate: 0}, "client-cancelled-id")
	writer.Close()

	var entry store.AccessLog
	if err := db.Where("request_id = ?", "client-cancelled-id").First(&entry).Error; err != nil {
		t.Fatalf("read canceled pass log: %v", err)
	}
	if entry.StatusCode != 0 || entry.WAFAction != "none" || entry.Path != "/client-cancelled" {
		t.Fatalf("canceled pass log = %#v", entry)
	}
	if entry.TLSVersion != fp.TLSVersion || entry.TLSJA3Hash != fp.JA3Hash || entry.TLSJA4 != fp.JA4 {
		t.Fatalf("canceled pass log lost TLS fingerprint: %#v", entry)
	}
}

func TestHandlerRecordsAccessLogForUnmatchedSiteRoute(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	holder := &snapshot.Holder{}
	holder.Store(&snapshot.Snapshot{Revision: 1, Sites: map[string]*snapshot.SiteRuntime{}})
	handler := Handler(Options{Holder: holder, Engine: engine.New(holder, nil, nil, nil), Writer: writer, AccessLogSamplingRate: 0, Bind: ":80"})
	ctx := app.NewContext(0)
	ctx.Request.SetMethod(http.MethodGet)
	ctx.Request.SetRequestURI("/unmatched")
	ctx.Request.SetHost("unknown.example.test")
	handler(ContextWithTLSFingerprint(context.Background(), bot.TLSClientFingerprint{
		TLSVersion: "TLS13",
		JA3Hash:    "ja3-unmatched",
		JA4:        "ja4-unmatched",
	}), ctx)
	writer.Close()

	if got := ctx.Response.StatusCode(); got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	requestID := string(ctx.Response.Header.Peek("X-Request-ID"))
	var entry store.AccessLog
	if err := db.Where("request_id = ?", requestID).First(&entry).Error; err != nil {
		t.Fatalf("read unmatched access log: %v", err)
	}
	if entry.StatusCode != http.StatusOK || entry.WAFAction != "routing_error" || entry.Path != "/unmatched" {
		t.Fatalf("unmatched access log = %#v", entry)
	}
	if entry.TLSJA3Hash != "ja3-unmatched" || entry.TLSJA4 != "ja4-unmatched" || entry.TLSVersion != "TLS13" {
		t.Fatalf("unmatched access log lost TLS fingerprint: %#v", entry)
	}
}

func TestHandlerRecordsAccessLogForRequestBodyPrefetchError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	writer := observability.NewUnifiedWriter(db, slog.Default())

	holder := &snapshot.Holder{}
	protection := store.DefaultProtectionConfig()
	protection.BotDetectionEnabled = false
	rt := snapshot.SiteRuntime{
		Site:                store.Site{ID: 1, Host: "body-error.example.test", Bind: ":80"},
		Bind:                ":80",
		UpstreamURLs:        []string{"http://unused.example.test"},
		EffectiveProtection: &protection,
	}
	holder.Store(&snapshot.Snapshot{
		Revision:   1,
		Protection: protection,
		Sites: map[string]*snapshot.SiteRuntime{
			snapshot.SiteMapKey(":80", "body-error.example.test"): &rt,
		},
	})

	handler := Handler(Options{
		Holder:                holder,
		Engine:                engine.New(holder, nil, nil, nil),
		Writer:                writer,
		Log:                   slog.Default(),
		Bind:                  ":80",
		AccessLogSamplingRate: 0,
	})
	ctx := app.NewContext(0)
	ctx.Request.Header.SetMethod(http.MethodPost)
	ctx.Request.SetRequestURI("/upload")
	ctx.Request.Header.SetHost("body-error.example.test")
	ctx.Request.SetBodyStream(&unexpectedEOFRequestBodyStream{reader: bytes.NewReader([]byte("partial body"))}, -1)

	handler(context.Background(), ctx)
	writer.Close()

	var entry store.AccessLog
	if err := db.Where("site_id = ?", rt.Site.ID).First(&entry).Error; err != nil {
		t.Fatalf("read access log: %v", err)
	}
	if entry.StatusCode != 0 || entry.WAFAction != "none" || entry.CacheState != "bypass" {
		t.Fatalf("access log = %#v", entry)
	}
	if entry.Path != "/upload" || entry.Upstream != "" {
		t.Fatalf("access log path/upstream = %#v", entry)
	}
}

// TestHeaderOrderCacheSingleVisitAll 验证主路径头顺序缓存：整请求生命周期内
// requestHeaderOrder 只执行一次（第一条记录时槽已命中），且 WAF 安全事件与
// 访问日志共享同一顺序字符串。JSDoc 注释与契约同步。
func TestHeaderOrderCacheSingleVisitAll(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrateLogs(db); err != nil {
		t.Fatalf("migrate log db: %v", err)
	}
	_ = observability.NewUnifiedWriter(db, slog.Default())

	orderCtx := app.NewContext(0)
	orderCtx.Request.Header.SetMethod(http.MethodGet)
	orderCtx.Request.SetRequestURI("/")
	orderCtx.Request.Header.SetHost("127.0.0.1")
	orderCtx.Request.Header.Set("X-First", "1")
	orderCtx.Request.Header.Set("X-Second", "2")

	// 模拟主路径 populate：填 HeaderKeys 后 join 入槽。
	reqCtx := pipeline.AcquireCtx()
	defer pipeline.ReleaseCtx(reqCtx)
	populateRequestCtxHeaders(reqCtx, orderCtx)
	join := strings.Join(reqCtx.HeaderKeys, ",")
	orderCtx.Set(wafReqCtxHeaderOrderCacheKey, &join)

	if got, ok := headerOrderFromContext(orderCtx); !ok || got != join {
		t.Fatalf("headerOrderFromContext = %q, %v, want %q, true", got, ok, join)
	}
}

// encryptedEnvFingerprintForTest 以与真实挑战页一致的 v1 封套加密环境指纹。
func encryptedEnvFingerprintForTest(t *testing.T, fp *challenge.EnvFingerprint, key []byte, sessionID string, binding challenge.ChallengeSessionBinding) string {
	t.Helper()
	plaintext, err := json.Marshal(fp)
	if err != nil {
		t.Fatalf("marshal fingerprint: %v", err)
	}
	aad := challenge.EnvFingerprintAAD("captcha", sessionID, binding)
	raw, err := gm.Seal(key[:16], gm.DomainEnv, plaintext, []byte(aad))
	if err != nil {
		t.Fatalf("seal GM environment envelope: %v", err)
	}
	return gm.Encode(raw)
}

func TestCaptchaVerifyEnvFailClosed(t *testing.T) {
	tests := []struct {
		name     string
		envCheck bool // 站点开关；环境密钥已全量下发，仅决定验证是否闸门
		envFP    func(t *testing.T, key []byte, sessionID string, binding challenge.ChallengeSessionBinding) string
		wantPass bool
	}{
		{
			name:     "envCheck=false 纯答案空 env 提交 fail（密钥已全量下发必须加密）",
			envCheck: false,
			envFP: func(t *testing.T, key []byte, sessionID string, binding challenge.ChallengeSessionBinding) string {
				return ""
			},
			wantPass: false,
		},
		{
			name:     "envCheck=false 合法环境指纹放行",
			envCheck: false,
			envFP: func(t *testing.T, key []byte, sessionID string, binding challenge.ChallengeSessionBinding) string {
				return encryptedEnvFingerprintForTest(t, &challenge.EnvFingerprint{
					ChromePresent: true, Languages: "zh-CN", PluginsCount: 5, CanvasHash: "canvas",
					WebGLRenderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
					ScreenWidth:   1920, ScreenHeight: 1080, HardwareConcur: 8, ColorDepth: 24,
					PixelRatio: 1, SessionStorage: true, IndexedDB: true, CookieEnabled: true,
					FontCount: 12, WebAssembly: true, ServiceWorker: true, MediaDevices: true,
					PlatformStr: "Linux x86_64", AudioHash: "audio-hash",
					ScreenConsistency: true, TimezoneConsistency: true,
					LanguageConsistency: true, MathConsistency: true,
				}, key, sessionID, binding)
			},
			wantPass: true,
		},
		{
			name:     "空 env 提交 fail",
			envCheck: true,
			envFP: func(t *testing.T, key []byte, sessionID string, binding challenge.ChallengeSessionBinding) string {
				return ""
			},
			wantPass: false,
		},
		{
			name:     "乱码 env 解密失败 fail",
			envCheck: true,
			envFP: func(t *testing.T, key []byte, sessionID string, binding challenge.ChallengeSessionBinding) string {
				return "v1.!!not-base64!!"
			},
			wantPass: false,
		},
		{
			name:     "环境评分异常（navigator.webdriver 分值 100）fail",
			envCheck: true,
			envFP: func(t *testing.T, key []byte, sessionID string, binding challenge.ChallengeSessionBinding) string {
				return encryptedEnvFingerprintForTest(t, &challenge.EnvFingerprint{
					WebDriver: true, ScreenWidth: 1920, ScreenHeight: 1080,
				}, key, sessionID, binding)
			},
			wantPass: false,
		},
		{
			name:     "合法环境指纹放行",
			envCheck: true,
			envFP: func(t *testing.T, key []byte, sessionID string, binding challenge.ChallengeSessionBinding) string {
				return encryptedEnvFingerprintForTest(t, &challenge.EnvFingerprint{
					ChromePresent: true, Languages: "zh-CN", PluginsCount: 5, CanvasHash: "canvas",
					WebGLRenderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)",
					ScreenWidth:   1920, ScreenHeight: 1080, HardwareConcur: 8, ColorDepth: 24,
					PixelRatio: 1, SessionStorage: true, IndexedDB: true, CookieEnabled: true,
					FontCount: 12, WebAssembly: true, ServiceWorker: true, MediaDevices: true,
					PlatformStr: "Linux x86_64", AudioHash: "audio-hash",
					ScreenConsistency: true, TimezoneConsistency: true,
					LanguageConsistency: true, MathConsistency: true,
				}, key, sessionID, binding)
			},
			wantPass: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			holder := &snapshot.Holder{}
			protection := store.DefaultProtectionConfig()
			protection.ShieldEnableEnvCheck = tt.envCheck
			rt := snapshot.SiteRuntime{
				Site:                store.Site{ID: 1, Host: "captcha-env.example.test", Bind: ":80"},
				Bind:                ":80",
				EffectiveProtection: &protection,
			}
			holder.Store(&snapshot.Snapshot{
				Revision:   1,
				Protection: protection,
				Sites: map[string]*snapshot.SiteRuntime{
					snapshot.SiteMapKey(":80", rt.Site.Host): &rt,
				},
			})

			manager := challenge.NewCaptchaManager(nil, 0)
			defer manager.Close()
			binding := challenge.ChallengeSessionBinding{SiteID: rt.Site.ID, Host: rt.Site.Host, Bind: ":80"}
			pending, err := manager.GenerateWithBinding(challenge.CaptchaTypeMath, tt.envCheck, binding)
			if err != nil {
				t.Fatalf("generate captcha session: %v", err)
			}
			answer, envKey, _, found := challenge.CaptchaManagerPendingForTest(manager, pending.SessionID)
			if !found {
				t.Fatalf("pending captcha session %q not found", pending.SessionID)
			}
			// 全量下发语义：无论 envCheck 与否，新签发会话都必须持有环境密钥。
			if len(envKey) != 32 {
				t.Fatalf("pending captcha session %q env key length = %d, want 32 (envCheck=%v)", pending.SessionID, len(envKey), tt.envCheck)
			}

			handler := Handler(Options{
				Holder: holder, Engine: engine.New(holder, nil, nil, nil), Log: slog.Default(),
				Bind: ":80", CaptchaManager: manager,
			})
			ctx := app.NewContext(0)
			ctx.Request.Header.SetMethod(http.MethodPost)
			ctx.Request.SetRequestURI("/__owaf/captcha/verify")
			ctx.Request.Header.SetHost(rt.Site.Host)
			ctx.Request.Header.Set("Referer", "https://"+rt.Site.Host+"/original")
			answerEnvelope, err := challenge.EncryptCaptchaAnswer(answer, envKey)
			if err != nil {
				t.Fatalf("encrypt captcha answer: %v", err)
			}
			ctx.Request.SetFormDataFromValues(url.Values{
				"__waf_captcha_session": {pending.SessionID},
				"__waf_captcha_answer":  {answerEnvelope},
				"__waf_env_fp":          {tt.envFP(t, envKey, pending.SessionID, binding)},
			})

			handler(context.Background(), ctx)

			if got := ctx.Response.StatusCode(); got != http.StatusFound {
				t.Fatalf("status = %d, want %d", got, http.StatusFound)
			}
			if got := len(ctx.Response.Header.Peek("Set-Cookie")) > 0; got != tt.wantPass {
				t.Fatalf("captcha verify pass = %v, want %v", got, tt.wantPass)
			}
		})
	}
}
