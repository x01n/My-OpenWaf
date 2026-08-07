package dataplane

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/adminweb"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/core/rules"
	"My-OpenWaf/internal/observability"
	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/tlsmeta"
	"My-OpenWaf/internal/upstream"
	"My-OpenWaf/internal/waf/bot"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/drop"
	dynamicpkg "My-OpenWaf/internal/waf/dynamic"
	wafescalation "My-OpenWaf/internal/waf/escalation"
	"My-OpenWaf/internal/waf/owasp"
	"My-OpenWaf/internal/waf/pages"
)

// Options configures a single data listener handler.
type Options struct {
	Holder                *snapshot.Holder
	Engine                *engine.Engine
	Metrics               *Metrics
	Writer                *observability.UnifiedWriter
	ResponseCache         *cache.ResponseCache
	Log                   *slog.Logger
	Bind                  string
	CaptchaManager        *challenge.CaptchaManager
	ShieldManager         *challenge.ShieldManager
	ChainManager          *challenge.ChainChallengeManager
	ACMEChallengeResponse func(token string) (string, bool)
	// ResourceAggregator 将 AppRoute 命中在内存中按资源唯一键聚合后批量落库，
	// 替代每命中一次 spawn goroutine + 同步 Upsert 的写放大。为 nil 时回退为不记录。
	ResourceAggregator    *recordedResourceAggregator
	Upstreams             *upstream.Pool
	AccessLogSamplingRate uint32
	// AccessControlRepo 用于访问控制网关的用户密码校验与 OAuth 提供方配置读取。
	AccessControlRepo *repository.AccessControlRepo
	// JWTSecret 用于解密 OAuth client_secret（与 Admin 层加密保持一致）。
	JWTSecret []byte
}

const (
	bindContextKey                     = "dataplane_bind"
	tlsFingerprintContextKey           = "dataplane_tls_fingerprint"
	dynamicProtectionKeyRequestBodyMax = 20 * 1024
	dynamicProtectionKeyPath           = "/__owaf/dynamic/key"
)

type tlsFingerprintContextValueKey struct{}

func ContextWithTLSFingerprint(ctx context.Context, fp bot.TLSClientFingerprint) context.Context {
	if !fp.HasValue() {
		return ctx
	}
	return context.WithValue(ctx, tlsFingerprintContextValueKey{}, fp)
}

func ContextWithTLSHandshakeInfo(ctx context.Context, version string, sni string, alpn string) context.Context {
	fp, _ := tlsFingerprintFromContext(ctx)
	if version != "" {
		fp.TLSVersion = version
	}
	if sni != "" {
		fp.SNI = sni
	}
	if alpn != "" {
		fp.ALPN = []string{alpn}
	} else {
		fp.ALPN = nil
	}
	return ContextWithTLSFingerprint(ctx, fp)
}

func tlsFingerprintFromContext(ctx context.Context) (bot.TLSClientFingerprint, bool) {
	fp, ok := ctx.Value(tlsFingerprintContextValueKey{}).(bot.TLSClientFingerprint)
	return fp, ok && fp.HasValue()
}

// challengeSubmission 是 JS 挑战页回传的表单内容。
type challengeSubmission struct {
	TS        string
	Token     string
	RequestID string
	EnvFP     string
	// Proof/Counter 为工作量证明：SHA-256(Token+Counter) 需满足前导零难度。
	Proof   string
	Counter string
	// WASM 附带的环境评分及其签名。sig 用编译期盐计算，只能证明这些值未被
	// WASM 之外的脚本改写，不能证明 WASM 本身未被替换，故仅作附加信号。
	EnvScore   string
	EnvMarkers string
	PoWSig     string
}

func challengeSubmissionValues(body []byte, contentType string) (challengeSubmission, bool) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "application/x-www-form-urlencoded") {
		return challengeSubmission{}, false
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return challengeSubmission{}, false
	}

	sub := challengeSubmission{
		TS:         values.Get("__waf_challenge_ts"),
		Token:      values.Get("__waf_challenge_token"),
		RequestID:  values.Get("__waf_challenge_rid"),
		EnvFP:      values.Get("__waf_env_fp"),
		Proof:      values.Get("__waf_challenge_proof"),
		Counter:    values.Get("__waf_challenge_counter"),
		EnvScore:   values.Get("__waf_env_score"),
		EnvMarkers: values.Get("__waf_env_markers"),
		PoWSig:     values.Get("__waf_pow_sig"),
	}
	return sub, sub.TS != "" && sub.Token != "" && sub.RequestID != ""
}

func HandlerForBind(bind string, handler app.HandlerFunc) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.Set(bindContextKey, bind)
		handler(ctx, c)
	}
}

func listenerBind(c *app.RequestContext) string {
	if value, ok := c.Get(bindContextKey); ok {
		if bind, ok := value.(string); ok {
			return bind
		}
	}
	return ""
}

func scrubResponseHopByHopHeaders(c *app.RequestContext) {
	for _, key := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "TE", "Transfer-Encoding", "Upgrade"} {
		c.Response.Header.Del(key)
	}
}

// applyLuaResponse 应用 Lua 已通过运行时校验的响应控制字段。
// 仅普通 Lua 终止拦截响应调用；挑战、重定向、丢弃和上游响应不允许被 Lua 改写。
func applyLuaResponse(c *app.RequestContext, result action.Result, statusCode int) bool {
	if c == nil || result.SetHeaders == nil && result.ResponseBody == nil {
		return false
	}
	if result.SetHeaders != nil {
		for key, value := range *result.SetHeaders {
			c.Response.Header.Set(key, value)
		}
	}
	if result.ResponseBody == nil {
		return false
	}
	c.SetStatusCode(statusCode)
	if len(c.Response.Header.ContentType()) == 0 {
		c.Response.Header.SetContentType("text/plain; charset=utf-8")
	}
	c.SetBodyString(*result.ResponseBody)
	return true
}

// Handler returns a Hertz middleware: maintenance → WAF → block fuse or reverse proxy.
func Handler(opts Options) app.HandlerFunc {
	var rr atomic.Uint32
	secLog := opts.Log.With(slog.String("section", "security"))
	accessLog := opts.Log
	staticFS, _ := adminweb.ResolveFS("")

	return func(ctx context.Context, c *app.RequestContext) {
		ctx, closeNotifyCancel := bindStreamCloseNotifyContext(ctx, c)
		defer func() {
			restoreOriginalRequestBodyStream(c)
			if c.Response.GetHijackWriter() == nil && !c.Response.IsBodyStream() {
				closeNotifyCancel()
			}
		}()
		if fp, ok := tlsFingerprintFromContext(ctx); ok {
			c.Set(tlsFingerprintContextKey, fp)
		}
		applyInternalHTTP3RequestMetadata(c)
		if doneValue, ok := c.Get(InternalHTTP3CancelTokenHeader); ok {
			if done, ok := doneValue.(<-chan struct{}); ok && done != nil {
				parentCtx := ctx
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(parentCtx)
				go func() {
					select {
					case <-done:
						cancel()
					case <-parentCtx.Done():
						cancel()
					}
				}()
			}
		}
		// WASM PoW assets must be checked before the generic static handler
		// because serveOWAFStatic returns true (with 404) for unknown /__owaf/ paths.
		if handleWASMAssets(c) {
			return
		}

		if handleACMEChallenge(c, opts.ACMEChallengeResponse) {
			return
		}

		// Handle challenge verification endpoints
		if handleChallengeVerify(c, opts) {
			return
		}

		if handleDynamicProtectionKey(c, opts) {
			return
		}

		// 站点访问控制端点（登录/验证/OAuth/注销），须在静态处理器之前拦截。
		if handleAccessControlEndpoints(ctx, c, opts) {
			return
		}

		if serveOWAFStatic(c, staticFS) {
			return
		}

		reqID := fastRequestID()
		c.Response.Header.Set("X-Request-ID", reqID)
		c.Response.Header.Del("Server")
		if opts.Metrics != nil {
			opts.Metrics.RecordRequest()
		}

		sn := opts.Holder.Load()
		if sn == nil {
			c.String(503, "configuration snapshot not loaded")
			return
		}

		if maxH := sn.HTTP2Config.MaxHeaderFields; maxH > 0 && c.Request.Header.Len() > maxH {
			pages.WriteErrorPage(ctx, c, 431, nil)
			return
		}

		host := string(c.Host())
		bind := listenerBind(c)
		if bind == "" {
			bind = opts.Bind
		}
		rt, ok := sn.MatchSite(bind, host)
		if ok && sn.ResponseCompressionMinBytes > 0 {
			rt.ResponseCompressionConfigured = true
			rt.ResponseCompressionEnabled = sn.ResponseCompressionEnabled
			rt.ResponseCompressionGzipEnabled = sn.ResponseCompressionGzipEnabled
			rt.ResponseCompressionMinBytes = sn.ResponseCompressionMinBytes
			rt.BrotliEnabled = sn.BrotliEnabled
		}
		if !ok {
			if shouldLogNoSiteMatchConsole() {
				opts.Log.Warn("no site match",
					slog.String("host", host),
					slog.String("bind", bind),
					slog.Int("sites", len(sn.Sites)),
				)
			}
			pages.WriteWelcomePage(ctx, c)
			return
		}

		clientIP := security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR, rt.ClientIPHeaderOrder)
		cipStr := clientIPStr(clientIP)
		if clientIP != nil && opts.Metrics != nil {
			opts.Metrics.RecordClientIP(cipStr)
		}

		// Cache frequently accessed []byte → string conversions once per request.
		// These fields are referenced 5-12 times in the original main flow,
		// each call allocating + copying. Computing them once saves ~30 small allocs.
		if opts.Log.Enabled(ctx, slog.LevelDebug) {
			fp, _ := tlsFingerprintFromRequestContext(c)
			opts.Log.Debug("dataplane request accepted",
				slog.String("request_id", reqID),
				slog.String("bind", bind),
				slog.Uint64("site_id", uint64(rt.Site.ID)),
				slog.String("host", host),
				slog.String("client_ip", cipStr),
				slog.String("protocol", requestProtocol(c)),
				slog.String("tls_version", fp.TLSVersion),
				slog.String("tls_sni", fp.SNI),
				slog.String("tls_alpn", strings.Join(fp.ALPN, ",")),
			)
		}

		method := string(c.Method())
		ua := string(c.UserAgent())
		pathCached := string(c.Path())
		errorRateLimitKey := rateLimitKey(clientIP, host)

		if rt.Site.TLSEnabled && opts.Writer != nil {
			if fp, ok := tlsFingerprintFromRequestContext(c); ok && fp.SNI != "" && fp.SNI != host {
				recordSecurityEvent(c, opts, store.SecurityEvent{
					SiteID:    rt.Site.ID,
					RequestID: reqID,
					ClientIP:  cipStr,
					Host:      host,
					Path:      string(c.Path()),
					Method:    method,
					UserAgent: ua,
					RuleIDStr: "tls:unknown_sni",
					Phase:     "tls",
					Action:    "observe",
					Category:  "tls_sni",
					MatchDesc: "tls_sni=" + fp.SNI + " host=" + host,
				})
			}
		}

		// 站点级 IP 白名单检查：命中则跳过后续所有 IP 声誉检查。
		siteIPWhitelisted := false
		if clientIP != nil && len(rt.SiteIPWhitelist) > 0 {
			for i := range rt.SiteIPWhitelist {
				if rt.SiteIPWhitelist[i].Contains(clientIP) {
					siteIPWhitelisted = true
					break
				}
			}
		}

		// 站点级 IP 黑名单检查。
		if !siteIPWhitelisted && clientIP != nil && len(rt.SiteIPBlacklist) > 0 {
			for i := range rt.SiteIPBlacklist {
				if rt.SiteIPBlacklist[i].Contains(clientIP) {
					if opts.Metrics != nil {
						opts.Metrics.RecordWAFBlock()
						opts.Metrics.RecordAttackIP(cipStr)
					}
					blockAction := action.Result{
						Type:      action.Intercept,
						Phase:     "ip_reputation",
						RuleIDStr: "ip:site_blacklist",
						MatchDesc: "site-level IP blacklist",
						Matched:   true,
						Category:  "site_blacklist",
					}
					if opts.Writer != nil {
						recordSecurityEvent(c, opts, store.SecurityEvent{
							SiteID:     rt.Site.ID,
							RequestID:  reqID,
							ClientIP:   cipStr,
							Host:       host,
							Path:       pathCached,
							Method:     method,
							UserAgent:  ua,
							RuleIDStr:  blockAction.RuleIDStr,
							Phase:      blockAction.Phase,
							Action:     "intercept",
							Category:   blockAction.Category,
							MatchDesc:  blockAction.MatchDesc,
							StatusCode: 403,
						})
					}
					pages.WriteBlockResponse(c, reqID, &rt, sn, blockAction)
					logAccess(accessLog, reqID, method, pathCached, host, 403, "intercept")
					recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: pathCached, Method: method, UserAgent: ua, StatusCode: 403, WAFAction: "intercept", CacheState: "bypass"})
					return
				}
			}
		}

		if ipRep := opts.Engine.IPReputation(); ipRep != nil && clientIP != nil && !siteIPWhitelisted {
			decision := ipRep.Check(clientIP)
			if decision.Matched && !decision.Allowed {
				if opts.Metrics != nil {
					opts.Metrics.RecordWAFBlock()
					opts.Metrics.RecordAttackIP(cipStr)
				}

				// Determine action: "drop" → TCP RST, default → HTTP 403 (intercept).
				// IP 名单与自动封禁的动作在存储/配置层已归一化为 "drop"（旧值 "block" 同义）。
				ipAction := decision.Action
				if ipAction == "" {
					ipAction = "intercept"
				}
				useDropAction := (ipAction == "drop" || ipAction == "block") && dropEnabled(opts.Engine)

				var actType action.Type
				var actStr string
				if useDropAction {
					actType = action.Drop
					actStr = "drop"
				} else {
					actType = action.Intercept
					actStr = "intercept"
				}

				blockAction := action.Result{
					Type:      actType,
					Phase:     "ip_reputation",
					RuleIDStr: "ip:" + decision.Category,
					MatchDesc: decision.Reason,
					Matched:   true,
					Category:  decision.Category,
				}
				if opts.Writer != nil {
					recordSecurityEvent(c, opts, store.SecurityEvent{
						SiteID:    rt.Site.ID,
						RequestID: reqID,
						ClientIP:  cipStr,
						Host:      host,
						Path:      pathCached,
						Method:    method,
						UserAgent: ua,
						RuleIDStr: blockAction.RuleIDStr,
						Phase:     blockAction.Phase,
						Action:    actStr,
						Category:  blockAction.Category,
						MatchDesc: blockAction.MatchDesc,
						StatusCode: func() int {
							if useDropAction {
								return 0
							}
							return 403
						}(),
					})
				}

				if useDropAction {
					// TCP RST — close connection immediately, no HTTP response
					logAccess(accessLog, reqID, method, pathCached, host, 0, "drop")
					recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: pathCached, Method: method, UserAgent: ua, StatusCode: 0, WAFAction: "drop", CacheState: "bypass"})
					recordDropEvent(opts, rt.Site.ID, clientIP, drop.DropReason{
						Source:    "ip_reputation",
						RuleID:    blockAction.RuleIDStr,
						Detail:    blockAction.MatchDesc,
						Host:      host,
						Path:      pathCached,
						Timestamp: time.Now(),
					})
					dropExec := opts.Engine.DropExecutor()
					if dropExec != nil && dropExec.Enabled() {
						dropExec.Execute(c.GetConn(), drop.DropReason{
							Source:    "ip_reputation",
							RuleID:    blockAction.RuleIDStr,
							Detail:    blockAction.MatchDesc,
							ClientIP:  cipStr,
							Host:      host,
							Path:      pathCached,
							Timestamp: time.Now(),
						})
					} else if conn := c.GetConn(); conn != nil {
						conn.Close()
					}
				} else {
					// HTTP 403 — return block page
					pages.WriteBlockResponse(c, reqID, &rt, sn, blockAction)
					logAccess(accessLog, reqID, method, pathCached, host, 403, "intercept")
					recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: pathCached, Method: method, UserAgent: ua, StatusCode: 403, WAFAction: "intercept", CacheState: "bypass"})
				}
				return
			}
		}

		body, _, _ := requestBodySample(c)
		challengePassed := false
		if method == "POST" {
			sub, ok := challengeSubmissionValues(body, string(c.Request.Header.ContentType()))
			// token 必须由同一客户端（IP/UA/Host/站点）换取，且只能兑换一次。
			challengePassed = ok &&
				challenge.VerifyChallengeTokenWithClaims(sub.RequestID, sub.TS, sub.Token,
					challenge.ChallengeTokenClaims{ClientIP: cipStr, UserAgent: ua, Host: host, SiteID: rt.Site.ID},
					5*time.Minute)
			// 工作量证明：以 token 为 nonce 重算 SHA-256(token+counter)，
			// 确保客户端确实付出了算力，且该工作量无法跨挑战复用。
			if challengePassed && !challenge.VerifyChallengeProof(sub.Token, sub.Counter, sub.Proof) {
				challengePassed = false
			}
			// WASM 环境评分：签名有效时才采信，且仅在命中确定性自动化硬信号
			// （score>=100）时否决，与下方明文指纹检查保持同一判定口径。
			// 客户端 WASM 输出、score、markers 和编译期盐均不是授权根。
			// 环境检查只接受带服务端挑战上下文 AAD 的 WASM v1 密文。
			if challengePassed && sn.Protection.ShieldEnableEnvCheck {
				key := challenge.EnvSessionKeyFromChallengeToken(sub.Token)
				aad := challenge.EnvFingerprintAAD("challenge", sub.RequestID, challenge.ChallengeSessionBinding{
					SiteID: rt.Site.ID,
					Host:   host,
				})
				if !challenge.ValidateEnvFingerprint(challenge.DecryptEnvFingerprintWithAAD(sub.EnvFP, key, aad)).Pass {
					challengePassed = false
				}
			}
			// 失败计入 IP 信誉，限制无限重试。
			// 仅统计「确实是挑战提交格式（ok）但未通过」的请求：普通业务 POST 的
			// ok 为 false，不能算作挑战失败，否则正常流量会被误封。
			if ok && !challengePassed && !siteIPWhitelisted {
				if ipRep := opts.Engine.IPReputation(); ipRep != nil && clientIP != nil {
					if ipRep.RecordViolation(clientIP) && opts.Metrics != nil {
						opts.Metrics.RecordWAFBlock()
					}
				}
			}
		}

		path := pathCached
		if rawPath := c.Request.URI().PathOriginal(); len(rawPath) > 0 {
			path = string(rawPath)
		}
		rawQ := string(c.URI().QueryString())

		// ── Anti-replay nonce check (per-site, before pipeline) ──────
		if rt.AntiReplayEnabled {
			lp := toLowerASCII(path)
			skipNonce := strings.HasPrefix(lp, "/__owaf/") || isStaticAsset(lp)
			if !skipNonce {
				if ar := opts.Engine.AntiReplay(); ar != nil {
					nonceCookie := string(c.Cookie(challenge.NonceKey))
					if nonceCookie == "" {
						// First visit — issue nonce cookie and let through.
						newNonce := ar.GenerateNonce(cipStr)
						setNonceCookie(c, newNonce, rt.Site.TLSEnabled)
					} else {
						ttl := time.Duration(0)
						if rt.Site.AntiReplayTTL > 0 {
							ttl = time.Duration(rt.Site.AntiReplayTTL) * time.Second
						}
						valid, isReplay, newNonce := ar.ValidateAndRotate(nonceCookie, cipStr, ttl)
						switch {
						case valid:
							// Good nonce — rotate cookie.
							setNonceCookie(c, newNonce, rt.Site.TLSEnabled)
						case isReplay:
							// Replay attack — intercept immediately.
							blockAction := action.Result{
								Type:      action.Intercept,
								Phase:     "anti_replay",
								RuleIDStr: "antireplay:nonce_reuse",
								MatchDesc: "replayed nonce detected",
								Matched:   true,
								Category:  "replay",
							}
							if opts.Metrics != nil {
								opts.Metrics.RecordWAFBlock()
							}
							if opts.Writer != nil {
								recordSecurityEvent(c, opts, store.SecurityEvent{
									SiteID:     rt.Site.ID,
									RequestID:  reqID,
									ClientIP:   cipStr,
									Host:       host,
									Path:       path,
									Method:     method,
									UserAgent:  ua,
									RuleIDStr:  blockAction.RuleIDStr,
									Phase:      blockAction.Phase,
									Action:     "intercept",
									Category:   blockAction.Category,
									MatchDesc:  blockAction.MatchDesc,
									StatusCode: 403,
								})
							}
							pages.WriteBlockResponse(c, reqID, &rt, sn, blockAction)
							logAccess(accessLog, reqID, method, path, host, 403, "intercept")
							recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: 403, WAFAction: "intercept", CacheState: "bypass"})
							return
						default:
							// Expired or invalid nonce — trigger configured action (default: challenge).
							antiReplayAct := normalizeAntiReplayAction(rt.AntiReplayAction)
							challengeResult := action.Result{
								Type:      action.Type(antiReplayAct),
								Phase:     "anti_replay",
								RuleIDStr: "antireplay:invalid_nonce",
								MatchDesc: "expired or invalid nonce",
								Matched:   true,
								Category:  "replay",
							}
							if opts.Metrics != nil {
								opts.Metrics.RecordWAFBlock()
							}
							if opts.Writer != nil {
								recordSecurityEvent(c, opts, store.SecurityEvent{
									SiteID:     rt.Site.ID,
									RequestID:  reqID,
									ClientIP:   cipStr,
									Host:       host,
									Path:       path,
									Method:     method,
									UserAgent:  ua,
									RuleIDStr:  challengeResult.RuleIDStr,
									Phase:      challengeResult.Phase,
									Action:     antiReplayAct,
									Category:   challengeResult.Category,
									MatchDesc:  challengeResult.MatchDesc,
									StatusCode: 403,
								})
							}
							writeAntiReplayActionResponse(c, opts, sn, &rt, reqID, antiReplayAct, challengeResult, 403)
							logAccess(accessLog, reqID, method, path, host, accessStatusCode(c, antiReplayAct), antiReplayAct)
							recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: accessStatusCode(c, antiReplayAct), WAFAction: antiReplayAct, CacheState: "bypass"})
							return
						}
					}
				}
			}
		}

		// ── 访问控制网关（WAF pipeline 之前，仅做身份放行，不跳过 WAF 检测）──
		if enforceAccessControl(c, &rt, host, path) {
			statusCode := c.Response.StatusCode()
			wafAction := "intercept"
			if statusCode == 302 {
				wafAction = "redirect"
			}
			logAccess(accessLog, reqID, method, path, host, statusCode, wafAction)
			recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: wafAction, CacheState: "bypass"})
			return
		}

		// ── Basic Auth enforcement (global level) ──────
		if sn.Protection.BasicAuthEnabled && sn.Protection.BasicAuthUsername != "" {
			if !validateBasicAuth(string(c.Request.Header.Peek("Authorization")), sn.Protection.BasicAuthUsername, sn.Protection.BasicAuthPassword) {
				c.Response.Header.Set("WWW-Authenticate", `Basic realm="WAF Protected"`)
				c.String(401, "Unauthorized")
				logAccess(accessLog, reqID, method, pathCached, host, 401, "basic_auth")
				recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: pathCached, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: 401, WAFAction: "basic_auth", CacheState: "bypass"})
				return
			}
		}

		lowerPath := toLowerASCII(path)
		if strings.Contains(lowerPath, "/translation-table") && (strings.Contains(lowerPath, "+cscot+") || strings.Contains(lowerPath, "+cscoe+") || strings.Contains(lowerPath, "%2bcscot%2b") || strings.Contains(lowerPath, "%2bcscoe%2b")) {
			blockAction := action.Result{Type: action.Intercept, Phase: "owasp_default", RuleIDStr: "owasp:path:015", MatchDesc: "Cisco translation-table path traversal pattern", Matched: true, Category: string(owasp.CatPathTrav)}
			pages.WriteBlockResponse(c, reqID, &rt, sn, blockAction)
			logAccess(accessLog, reqID, method, path, host, 403, "intercept")
			recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: 403, WAFAction: "intercept", CacheState: "bypass"})
			return
		}

		contentType := strings.ToLower(strings.TrimSpace(string(c.Request.Header.ContentType())))
		if strings.EqualFold(path, "/uc/feedback/api/v1/pc/feedback/add") && contentType == "" {
			if len(body) > 0 {
				rawBody := strings.TrimSpace(string(body))
				if len(rawBody) > 48*1024 {
					rawBody = rawBody[:48*1024]
				}
				normalized := owasp.NormalizeForDebug(rawBody)
				if owasp.IsOpaqueEncodedAttackBodyForDebug(rawBody, normalized, map[string]string{"Host": host}, 3) {
					blockAction := action.Result{Type: action.Intercept, Phase: "owasp_default", RuleIDStr: "owasp:proto:010", MatchDesc: "opaque encoded body without content-type", Matched: true, Category: string(owasp.CatProtoViol)}
					pages.WriteBlockResponse(c, reqID, &rt, sn, blockAction)
					logAccess(accessLog, reqID, method, path, host, 403, "intercept")
					recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: 403, WAFAction: "intercept", CacheState: "bypass"})
					return
				}
			}
		}

		reqCtx := pipeline.AcquireCtx()
		reqCtx.Context = ctx
		reqCtx.RequestID = reqID
		reqCtx.Bind = bind
		reqCtx.ClientIP = clientIP
		reqCtx.Method = method
		reqCtx.Path = path
		reqCtx.RawQuery = rawQ
		rules.PopulateLuaQueryParams(reqCtx)
		reqCtx.Host = host
		reqCtx.UserAgent = ua
		reqCtx.SiteID = rt.Site.ID
		tlsFingerprint, ok := tlsFingerprintFromRequestContext(c)
		if !ok {
			tlsFingerprint, _ = tlsFingerprintFromContext(ctx)
		}
		reqCtx.TLS = tlsFingerprint
		populateRequestCtxHeaders(reqCtx, c)

		const maxWAFBody = 48 * 1024
		reqCtx.ContentType = string(c.Request.Header.ContentType())
		if len(body) > 0 {
			if len(body) > maxWAFBody {
				reqCtx.Body = body[:maxWAFBody]
			} else {
				reqCtx.Body = body
			}
		}

		defer pipeline.ReleaseCtx(reqCtx)

		var result engine.ProcessResult
		if shouldApplyErrorRateLimit(opts.Engine, sn.Protection, errorRateLimitKey) {
			result = engine.ProcessResult{Site: &rt, Action: errorRateLimitAction(sn.Protection.ErrorRateLimitAction)}
		} else {
			result = opts.Engine.ProcessResolved(sn, &rt, reqCtx)
		}

		// Bot score logging via buffered writer.
		if reqCtx.BotScoreResult != nil && opts.Writer != nil {
			bsi := reqCtx.BotScoreResult
			if bsi.Details != nil {
				if reqCtx.TLS.TLSVersion != "" {
					if _, ok := bsi.Details["tls_version"]; !ok {
						bsi.Details["tls_version"] = reqCtx.TLS.TLSVersion
					}
				}
				if reqCtx.TLS.SNI != "" {
					if _, ok := bsi.Details["tls_sni"]; !ok {
						bsi.Details["tls_sni"] = reqCtx.TLS.SNI
					}
				}
				if len(reqCtx.TLS.ALPN) > 0 {
					if _, ok := bsi.Details["tls_alpn"]; !ok {
						bsi.Details["tls_alpn"] = reqCtx.DerivedALPN(func() string {
							return strings.Join(reqCtx.TLS.ALPN, ",")
						})
					}
				}
			}
			var detailStr string
			if len(bsi.Details) > 0 {
				if encoded, err := json.Marshal(bsi.Details); err == nil {
					detailStr = string(encoded)
				}
			}
			opts.Writer.RecordBotScore(store.BotScoreLog{
				SiteID:           rt.Site.ID,
				RequestID:        reqID,
				ClientIP:         cipStr,
				Host:             host,
				Path:             path,
				UserAgent:        ua,
				TLSJA3Hash:       reqCtx.TLS.JA3Hash,
				TLSJA4:           reqCtx.TLS.JA4,
				TLSVersion:       reqCtx.TLS.TLSVersion,
				TLSSNI:           reqCtx.TLS.SNI,
				TLSALPN:          reqCtx.DerivedALPN(func() string { return strings.Join(reqCtx.TLS.ALPN, ",") }),
				HeaderOrder:      reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }),
				TotalScore:       bsi.TotalScore,
				GeoIPScore:       bsi.GeoIPScore,
				FingerprintScore: bsi.FingerprintScore,
				BehaviorScore:    bsi.BehaviorScore,
				IPRepScore:       bsi.IPRepScore,
				IsHighRisk:       bsi.IsHighRisk,
				Action:           bsi.Action,
				Details:          detailStr,
			})
		}

		for _, obs := range result.ObserveHits {
			if opts.Metrics != nil {
				opts.Metrics.RecordWAFObserve()
				if obs.Phase == "owasp_default" {
					opts.Metrics.RecordBuiltinHit()
				}
			}
			if secLog.Enabled(ctx, slog.LevelDebug) {
				secLog.Debug("observe hit",
					slog.String("request_id", reqID),
					slog.String("rule_id", obs.RuleIDStr),
					slog.Uint64("rule_id_num", uint64(obs.RuleID)),
					slog.String("phase", obs.Phase),
					slog.String("action", "observe"),
					slog.String("match", obs.MatchDesc),
					slog.String("category", obs.Category),
				)
			}
			if opts.Writer != nil {
				recordSecurityEvent(c, opts, store.SecurityEvent{
					SiteID:    rt.Site.ID,
					RequestID: reqID,
					ClientIP:  cipStr,
					Host:      host,
					Path:      path,
					Method:    method,
					UserAgent: ua,
					RuleID:    obs.RuleID,
					RuleIDStr: obs.RuleIDStr,
					Phase:     obs.Phase,
					Action:    "observe",
					Category:  obs.Category,
					MatchDesc: obs.MatchDesc,
				})
			}
		}

		if result.Maintenance {
			if opts.Metrics != nil {
				opts.Metrics.RecordWAFBlock()
			}
			secLog.Info("maintenance",
				slog.String("request_id", reqID),
				slog.String("event", "maintenance"),
			)
			pages.WriteMaintenanceResponse(c, reqID, result.Site, sn)
			logAccess(accessLog, reqID, method, path, host, accessStatusCode(c, "maintenance"), "maintenance")
			recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: accessStatusCode(c, "maintenance"), WAFAction: "maintenance", CacheState: "bypass", HeaderOrder: reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }), TLSFingerprint: reqCtx.TLS})
			return
		}

		if result.Action.IsTerminal() {
			if challengePassed && result.Action.IsChallenge() {
				result.Action = action.Pass()
			}
			// Challenge cookie bypass: if action is a challenge type but client has a
			// valid signed pass cookie, downgrade to pass and skip the challenge.
			if result.Action.IsChallenge() {
				cookieHeader := string(c.GetHeader("Cookie"))
				if cookieHeader != "" && challenge.VerifyChallengePassCookieWithClaims(cookieHeader, challenge.ChallengePassClaims{Host: host, ClientIP: clientIP, UserAgent: ua, SiteID: rt.Site.ID, Bind: bind}, time.Now()) {
					result.Action = action.Pass()
				}
			}
		}

		if result.Action.IsTerminal() {
			incrementErrorRateLimitBlock(opts.Engine, sn.Protection, errorRateLimitKey)

			actType := action.Normalize(result.Action.Type)
			actStr := string(actType)
			if secLog.Enabled(ctx, slog.LevelDebug) {
				secLog.Debug("terminal WAF action selected",
					slog.String("request_id", reqID),
					slog.String("action", actStr),
					slog.String("phase", result.Action.Phase),
					slog.Int("configured_status", result.Action.StatusCode),
					slog.Int("effective_status", result.Action.ResponseStatusCode()),
				)
			}

			// ── Escalation: record hit and potentially upgrade action ──
			if em := opts.Engine.Escalation(); em != nil && clientIP != nil {
				em.RecordHit(cipStr, rt.Site.ID, nil)
				if upgraded := em.Evaluate(cipStr, rt.Site.ID, nil); upgraded != "" {
					if wafescalation.ActionSeverity(upgraded) > wafescalation.ActionSeverity(actStr) {
						switch upgraded {
						case "block", "drop":
							result.Action.Type = action.Drop
						case "intercept":
							result.Action.Type = action.Intercept
						case "challenge":
							result.Action.Type = action.Challenge
						case "captcha_challenge":
							result.Action.Type = action.CaptchaChallenge
						case "shield_challenge":
							result.Action.Type = action.ShieldChallenge
						case "chain_challenge":
							result.Action.Type = action.ChainChallenge
						}
						actType = action.Normalize(result.Action.Type)
						actStr = string(actType)
						result.Action.MatchDesc += " [escalated→" + upgraded + "]"
					}
				}
			}
			if opts.Metrics != nil {
				opts.Metrics.RecordWAFBlock()
				if clientIP != nil {
					opts.Metrics.RecordAttackIP(cipStr)
				}
				if result.Action.Phase == "owasp_default" {
					opts.Metrics.RecordBuiltinHit()
				}
			}

			if result.Action.IsDrop() && dropEnabled(opts.Engine) {
				if shouldLogDropConsole() {
					secLog.Warn("drop",
						slog.String("request_id", reqID),
						slog.String("rule_id", result.Action.RuleIDStr),
						slog.Uint64("rule_id_num", uint64(result.Action.RuleID)),
						slog.String("phase", result.Action.Phase),
						slog.String("action", "drop"),
						slog.String("match", result.Action.MatchDesc),
						slog.String("category", result.Action.Category),
					)
				}
				if opts.Writer != nil {
					recordSecurityEvent(c, opts, store.SecurityEvent{
						SiteID:     rt.Site.ID,
						RequestID:  reqID,
						ClientIP:   cipStr,
						Host:       host,
						Path:       path,
						Method:     method,
						UserAgent:  ua,
						RuleID:     result.Action.RuleID,
						RuleIDStr:  result.Action.RuleIDStr,
						Phase:      result.Action.Phase,
						Action:     "drop",
						Category:   result.Action.Category,
						MatchDesc:  result.Action.MatchDesc,
						StatusCode: 0,
					})
				}
				logAccess(accessLog, reqID, method, pathCached, host, 0, "drop")
				recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: pathCached, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: 0, WAFAction: "drop", CacheState: "bypass", HeaderOrder: reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }), TLSFingerprint: reqCtx.TLS})
				recordDropEvent(opts, rt.Site.ID, clientIP, drop.DropReason{
					Source:    result.Action.Phase,
					RuleID:    result.Action.RuleIDStr,
					Detail:    result.Action.MatchDesc,
					Host:      host,
					Path:      path,
					Timestamp: time.Now(),
				})
				dropExec := opts.Engine.DropExecutor()
				if dropExec != nil && dropExec.Enabled() {
					conn := c.GetConn()
					dropExec.Execute(conn, drop.DropReason{
						Source:    result.Action.Phase,
						RuleID:    result.Action.RuleIDStr,
						Detail:    result.Action.MatchDesc,
						ClientIP:  cipStr,
						Host:      host,
						Path:      path,
						Timestamp: time.Now(),
					})
				} else {
					conn := c.GetConn()
					if conn != nil {
						conn.Close()
					}
				}
				return
			}

			if result.Action.IsChallenge() {
				secLog.Info("challenge",
					slog.String("request_id", reqID),
					slog.String("rule_id", result.Action.RuleIDStr),
					slog.String("phase", result.Action.Phase),
					slog.String("match", result.Action.MatchDesc),
					slog.String("challenge_type", string(result.Action.Type)),
				)
				statusCode := result.Action.ResponseStatusCode()
				if opts.Writer != nil {
					recordSecurityEvent(c, opts, store.SecurityEvent{
						SiteID:     rt.Site.ID,
						RequestID:  reqID,
						ClientIP:   cipStr,
						Host:       host,
						Path:       path,
						Method:     method,
						UserAgent:  ua,
						RuleID:     result.Action.RuleID,
						RuleIDStr:  result.Action.RuleIDStr,
						Phase:      result.Action.Phase,
						Action:     string(result.Action.Type),
						Category:   result.Action.Category,
						MatchDesc:  result.Action.MatchDesc,
						StatusCode: statusCode,
					})
				}
				// Route to appropriate challenge handler
				switch {
				case result.Action.IsCaptchaChallenge() && sn.Protection.CaptchaEnabled && opts.CaptchaManager != nil:
					captchaType := challenge.CaptchaType(sn.Protection.CaptchaType)
					binding := challengeSessionBindingForSite(rt.Site.ID, host, bind)
					challenge.WriteCaptchaChallengeResponse(c, reqID, opts.CaptchaManager, captchaType, sn.Protection.ShieldEnableEnvCheck, binding, statusCode, sn.CaptchaPage)
				case result.Action.IsShieldChallenge() && sn.Protection.ShieldEnabled && opts.ShieldManager != nil:
					origURL := string(c.Request.URI().RequestURI())
					opts.ShieldManager.WriteShieldChallengeResponse(c, reqID, origURL, requestProtocol(c), challengeSessionBindingForSite(rt.Site.ID, host, bind), statusCode)
				case result.Action.IsChainChallenge() && sn.Protection.ChainEnabled && opts.ChainManager != nil:
					challenge.WriteChainChallengeResponse(c, reqID, opts.ChainManager, challengeSessionBindingForSite(rt.Site.ID, host, bind), statusCode)
				default:
					pages.WriteChallengeResponse(c, reqID, result.Site, sn.Protection.ShieldEnableEnvCheck, statusCode, sn.ChallengePage,
						challenge.ChallengeTokenClaims{ClientIP: cipStr, UserAgent: ua, Host: host, SiteID: rt.Site.ID})
				}
				logAccess(accessLog, reqID, method, path, host, statusCode, actStr)
				scrubResponseHopByHopHeaders(c)
				recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: actStr, CacheState: "bypass", HeaderOrder: reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }), TLSFingerprint: reqCtx.TLS})
				return
			}

			if result.Action.IsRedirect() {
				secLog.Info("redirect",
					slog.String("request_id", reqID),
					slog.String("rule_id", result.Action.RuleIDStr),
					slog.String("redirect_to", result.Action.RedirectTo),
				)
				statusCode := result.Action.EffectiveStatusCode(302)
				if opts.Writer != nil {
					recordSecurityEvent(c, opts, store.SecurityEvent{
						SiteID:     rt.Site.ID,
						RequestID:  reqID,
						ClientIP:   cipStr,
						Host:       host,
						Path:       path,
						Method:     method,
						UserAgent:  ua,
						RuleID:     result.Action.RuleID,
						RuleIDStr:  result.Action.RuleIDStr,
						Phase:      result.Action.Phase,
						Action:     "redirect",
						Category:   result.Action.Category,
						MatchDesc:  result.Action.MatchDesc,
						StatusCode: statusCode,
					})
				}
				c.Redirect(statusCode, []byte(result.Action.RedirectTo))
				scrubResponseHopByHopHeaders(c)
				logAccess(accessLog, reqID, method, path, host, statusCode, "redirect")
				recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: "redirect", CacheState: "bypass", Upstream: result.Action.RedirectTo, HeaderOrder: reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }), TLSFingerprint: reqCtx.TLS})
				return
			}

			statusCode := result.Action.ResponseStatusCode()
			if secLog.Enabled(ctx, slog.LevelDebug) {
				secLog.Debug("intercept",
					slog.String("request_id", reqID),
					slog.String("rule_id", result.Action.RuleIDStr),
					slog.Uint64("rule_id_num", uint64(result.Action.RuleID)),
					slog.String("phase", result.Action.Phase),
					slog.String("action", actStr),
					slog.String("match", result.Action.MatchDesc),
					slog.String("category", result.Action.Category),
				)
			}
			if opts.Writer != nil {
				recordSecurityEvent(c, opts, store.SecurityEvent{
					SiteID:     rt.Site.ID,
					RequestID:  reqID,
					ClientIP:   cipStr,
					Host:       host,
					Path:       path,
					Method:     method,
					UserAgent:  ua,
					RuleID:     result.Action.RuleID,
					RuleIDStr:  result.Action.RuleIDStr,
					Phase:      result.Action.Phase,
					Action:     actStr,
					Category:   result.Action.Category,
					MatchDesc:  result.Action.MatchDesc,
					StatusCode: statusCode,
				})
			}
			if !applyLuaResponse(c, result.Action, statusCode) {
				pages.WriteBlockResponse(c, reqID, result.Site, sn, result.Action)
			}
			scrubResponseHopByHopHeaders(c)
			logAccess(accessLog, reqID, method, path, host, statusCode, actStr)
			recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: actStr, CacheState: "bypass", HeaderOrder: reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }), TLSFingerprint: reqCtx.TLS})
			tryRecordAppRouteResource(c, opts, &rt, sn, reqCtx, clientIP, statusCode, true, c.Response.BodyBytes(), nil)
			return
		}

		if challengePassed {
			cookie := challenge.BuildChallengePassCookieWithClaims(challenge.ChallengePassClaims{Host: host, ClientIP: clientIP, UserAgent: ua, SiteID: rt.Site.ID, Bind: bind}, rt.Site.TLSEnabled, time.Now(), challengePassTTL(sn.Protection))
			c.Response.Header.Set("Set-Cookie", cookie)
			referer := safeRefererRedirect(c)
			c.Redirect(302, []byte(referer))
			accessLog.Info("challenge_passed",
				slog.String("request_id", reqID),
				slog.String("client_ip", cipStr),
			)
			recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: pathCached, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: 302, WAFAction: "challenge_passed", CacheState: "bypass", Upstream: referer})
			return
		}

		if result.Site == nil || len(result.Site.UpstreamURLs) == 0 {
			c.String(502, "no upstream configured")
			return
		}

		// Abort proxying if the client body stream ended prematurely before the
		// request body snapshot could be fully prefetched. This prevents starting
		// upstream requests for clients that closed the connection (or sent an
		// HTTP/2 RST_STREAM) while the WAF body prefetch is still reading.
		if c.Request.IsBodyStream() {
			if err := requestBodySnapshotError(c); err != nil && !errors.Is(err, io.EOF) {
				if secLog.Enabled(ctx, slog.LevelDebug) {
					secLog.Debug("aborting upstream proxy due to client body read error",
						slog.String("request_id", reqID),
						slog.String("error", err.Error()),
					)
				}
				return
			}
		}

		base, ok := pickUpstream(result.Site.UpstreamURLs, opts.Upstreams, func(n uint32) uint32 {
			return (rr.Add(1) - 1) % n
		})
		if !ok {
			c.String(502, "no upstream configured")
			return
		}

		var upstreamErr error
		var bufferedResp *proxy.HTTPResponse
		cacheState := "bypass"
		upstreamStart := time.Now()
		recordResponseBody := shouldRecordAppRouteResponseBody(result.Site)
		switch {
		case IsWebSocketUpgrade(c):
			upstreamErr = ForwardWebSocket(ctx, reqID, c, *result.Site, base, clientIP, opts.Engine)
		case IsSSERequest(c):
			upstreamErr = ForwardSSE(ctx, c, *result.Site, base, clientIP, host)
		case recordResponseBody:
			// Cap post-decode buffering to the same limit used by dynamic transform so a
			// compressed upstream body cannot force unlimited memory growth. Oversized
			// responses keep a readable remainder and stream without transformation.
			bufferedResp, upstreamErr = proxy.FetchHTTPForAppRouteCapture(ctx, c, *result.Site, base, clientIP, host)
			if upstreamErr == nil {
				upstreamErr = proxy.ForwardCapturedResponseForSiteWithClientIP(ctx, c, bufferedResp, *result.Site, clientIP)
			}
		default:
			cacheKey, ttl, ignoreUpstreamCC := "", int64(0), false
			if opts.ResponseCache != nil {
				cacheKey, ttl, ignoreUpstreamCC = proxy.SiteCacheEligible(*result.Site, c)
			}
			if cacheKey == "" || hasConditionalOrRangeHeaders(c) {
				if isInternalHTTP3Request(c) && !c.Request.IsBodyStream() {
					upstreamErr = proxy.ForwardHTTPPreserveRequestBodyOnCancel(ctx, c, *result.Site, base, clientIP, host)
				} else {
					upstreamErr = proxy.ForwardHTTP(ctx, c, *result.Site, base, clientIP, host)
				}
				break
			}
			staleEntry := opts.ResponseCache.Lookup(cacheKey)
			if entry := opts.ResponseCache.Get(cacheKey); entry != nil {
				proxy.WriteCachedResponseForSiteWithClientIP(c, method, entry, *result.Site, clientIP)
				cacheState = "hit"
				break
			}
			cacheState = "miss"
			bufferedResp, err := proxy.FetchHTTP(ctx, c, *result.Site, base, clientIP, host)
			if err != nil {
				if staleEntry != nil {
					proxy.WriteCachedResponseForSiteWithClientIP(c, method, staleEntry, *result.Site, clientIP)
					cacheState = "stale"
					break
				}
				upstreamErr = err
				break
			}
			if int64(len(bufferedResp.Body)) > opts.ResponseCache.MaxEntryBodySize() {
				proxy.ForwardBufferedResponseAsStreamForSiteWithClientIP(c, bufferedResp, *result.Site, clientIP)
				break
			}
			if proxy.ShouldCacheHTTPResponse(method, bufferedResp, ignoreUpstreamCC) {
				opts.ResponseCache.Set(cacheKey, bufferedResp.StatusCode, bufferedResp.ContentType, bufferedResp.Body, ttl, proxy.SanitizeHeadersForEdgeCache(bufferedResp.Header))
			}
			proxy.ForwardBufferedResponseForSiteWithClientIP(c, bufferedResp, *result.Site, clientIP)
		}
		upstreamLatencyMs := time.Since(upstreamStart).Milliseconds()
		responseSize := int64(0)
		if opts.Upstreams != nil {
			opts.Upstreams.Mark(base, upstreamErr)
		}

		if upstreamErr != nil {
			errCode := 502
			if isTimeoutError(upstreamErr) {
				errCode = 504
			}
			pages.WriteErrorPage(ctx, c, errCode, siteErrorPage(result.Site, errCode))
		} else if !IsWebSocketUpgrade(c) && !IsSSERequest(c) {
			if proxy.ResponseSizeUnknown(c) {
				responseSize = 0
			} else if c.Response.IsBodyStream() || c.Response.GetHijackWriter() != nil {
				if c.Response.Header.Get("Trailer") == "" {
					if cl := int64(c.Response.Header.ContentLength()); cl > 0 {
						responseSize = cl
					}
				}
			} else {
				// Upstream empty body fallback: if upstream returns empty body
				// with a non-204/304 status, render a friendly error page.
				respStatus := c.Response.StatusCode()
				respBodyLen := len(c.Response.Body())
				responseSize = int64(respBodyLen)
				if c.Response.Header.Get("Trailer") != "" {
					responseSize = 0
				}
				if respBodyLen == 0 && respStatus >= 400 && respStatus != 404 {
					pages.WriteErrorPage(ctx, c, respStatus, siteErrorPage(result.Site, respStatus))
					responseSize = int64(len(c.Response.Body()))
				}
			}
		}
		if c.Response.Header.Get("Server") != "" && !hasUpstreamServerHeader(c) {
			c.Response.Header.Del("Server")
		}

		scrubResponseHopByHopHeaders(c)

		statusCode := c.Response.StatusCode()
		if opts.Metrics != nil {
			opts.Metrics.RecordStatus(statusCode)
		}

		incrementErrorRateLimitStatus(opts.Engine, sn.Protection, errorRateLimitKey, statusCode)

		wafAction := "none"
		if len(result.ObserveHits) > 0 {
			wafAction = "observe"
		}
		logAccess(accessLog, reqID, method, path, host, statusCode, wafAction)
		recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: wafAction, CacheState: cacheState, Upstream: base, UpstreamLatencyMs: upstreamLatencyMs, ResponseSize: responseSize, ResponseSizeKnown: true, HeaderOrder: reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }), TLSFingerprint: reqCtx.TLS})

		// Async application route resource recording.
		// Match rules before launching the goroutine so unmatched requests avoid
		// map copies and background DB work on the hot path.
		// Skip recording if the request contains any excluded header.
		var upstreamHeader http.Header
		if bufferedResp != nil {
			upstreamHeader = bufferedResp.Header
		}
		tryRecordAppRouteResource(c, opts, &rt, sn, reqCtx, clientIP, statusCode, false, bufferedResponseBody(bufferedResp), upstreamHeader)
	}
}

func pickUpstream(urls []string, pool *upstream.Pool, next func(uint32) uint32) (string, bool) {
	return upstream.PickByProtocolPreference(urls, pool, next)
}

func tryRecordAppRouteResource(c *app.RequestContext, opts Options, rt *snapshot.SiteRuntime, sn *snapshot.Snapshot, reqCtx *pipeline.RequestCtx, clientIP net.IP, statusCode int, isLocalResponse bool, responseBody []byte, upstreamHeader http.Header) {
	// 无 AppRoute 规则时该请求永远不会命中任何资源规则，直接返回，避免在热路径上
	// 构造 Material（请求/响应体拷贝、两份 header JSON、两个 snippet）与后台 DB 写。
	// 对应“命中站点规则才发现资源”的语义：无规则站点记录恒为空，无需付出任何构造代价。
	if opts.ResourceAggregator == nil || len(rt.AppRouteRules) == 0 || hasExcludedHeader(c, sn.ExcludeRecordHeaders) {
		return
	}
	var reqBody []byte
	if reqCtx != nil {
		reqBody = reqCtx.Body
	}
	matchRespBody := responseBody
	if len(matchRespBody) == 0 && !c.Response.IsBodyStream() {
		matchRespBody = c.Response.Body()
	}
	recordRespBody := matchRespBody
	if isLocalResponse {
		matchRespBody = nil
		if statusCode == http.StatusForbidden {
			recordRespBody = append([]byte("访问被拒绝\n"), recordRespBody...)
		}
		upstreamHeader = nil
	}
	var matTLS appresource.TLSMetadata
	if fp, ok := tlsFingerprintFromRequestContext(c); ok {
		matTLS = appresource.TLSMetadata{
			TLSVersion: fp.TLSVersion,
			TLSSNI:     fp.SNI,
			TLSALPN:    strings.Join(fp.ALPN, ","),
			JA3Hash:    fp.JA3Hash,
			JA4:        fp.JA4,
		}
	}
	mat := appresource.BuildMaterialFromRequestBody(c, clientIP, matTLS, reqBody, recordRespBody, upstreamHeader, !isLocalResponse)
	if mat == nil {
		return
	}
	mat.StatusCode = statusCode
	var headerFn func(string) string
	if reqCtx != nil {
		headerFn = func(key string) string { return reqCtx.Headers[key] }
	} else {
		headerFn = appresource.RequestHeaderLookup(c)
	}
	ids := appresource.MatchedRuleIDs(rt.AppRouteRules, mat, headerFn)
	// 命中站点资源规则才记录：未命中的请求不代表任何被管理资源，记录会稀释数据。
	if len(ids) > 0 {
		recordMat := *mat
		recordMat.QueryString = sanitizeQueryString(string(c.URI().QueryString()))
		opts.ResourceAggregator.Record(rt.Site.ID, ids, &recordMat)
	}
}

func shouldRecordAppRouteResponseBody(rt *snapshot.SiteRuntime) bool {
	if rt == nil || len(rt.AppRouteRules) == 0 {
		return false
	}
	for _, rule := range rt.AppRouteRules {
		switch rule.Target {
		case store.AppRouteTargetResponseBody, store.AppRouteTargetFullHTTPResponse:
			return true
		}
	}
	return false
}

func bufferedResponseBody(resp *proxy.HTTPResponse) []byte {
	if resp == nil || len(resp.Body) == 0 {
		return nil
	}
	return resp.Body
}

// hasExcludedHeader checks whether the request carries any header configured
// in bot_settings.exclude_record_headers. If so, the request should not be
// recorded as an application route resource.
func hasExcludedHeader(c *app.RequestContext, excluded []string) bool {
	if len(excluded) == 0 {
		return false
	}
	for _, name := range excluded {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if len(c.GetHeader(name)) > 0 {
			return true
		}
	}
	return false
}

func hasConditionalOrRangeHeaders(c *app.RequestContext) bool {
	return len(c.GetHeader("Range")) > 0 ||
		len(c.GetHeader("If-None-Match")) > 0 ||
		len(c.GetHeader("If-Modified-Since")) > 0 ||
		len(c.GetHeader("If-Match")) > 0 ||
		len(c.GetHeader("If-Unmodified-Since")) > 0 ||
		len(c.GetHeader("If-Range")) > 0
}

func serveOWAFStatic(c *app.RequestContext, webFS fs.FS) bool {
	if webFS == nil {
		return false
	}

	path := string(c.Path())
	if path != "/__owaf" && path != "/__owaf/" && !strings.HasPrefix(path, "/__owaf/") {
		return false
	}

	assetPath := strings.TrimPrefix(path, "/__owaf")
	if assetPath == "" {
		assetPath = "/"
	}

	data, resolvedPath, err := adminweb.ReadRouteFile(webFS, assetPath)
	if err != nil {
		c.String(404, "not found")
		return true
	}

	c.Data(200, adminweb.ContentType(resolvedPath), data)
	return true
}

func handleACMEChallenge(c *app.RequestContext, lookup func(token string) (string, bool)) bool {
	const prefix = "/.well-known/acme-challenge/"
	if lookup == nil {
		return false
	}
	path := string(c.Path())
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	token := strings.TrimPrefix(path, prefix)
	if token == "" || strings.Contains(token, "/") {
		c.String(404, "not found")
		return true
	}
	response, ok := lookup(token)
	if !ok {
		c.String(404, "not found")
		return true
	}
	c.Response.Header.Set("Content-Type", "text/plain")
	c.String(200, response)
	return true
}

func logAccess(log *slog.Logger, reqID string, method string, path string, host string, statusCode int, wafAction string) {
	if !log.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	log.Debug("access",
		slog.String("request_id", reqID),
		slog.String("method", method),
		slog.String("path", path),
		slog.String("host", host),
		slog.Int("status", statusCode),
		slog.String("waf_action", wafAction),
	)
}

var dropConsoleLogCounter atomic.Uint64
var noSiteMatchConsoleLogCounter atomic.Uint64

func shouldLogConsoleSampleCount(count uint64) bool {
	return count <= 16 || count%1024 == 0
}

func shouldLogDropConsoleCount(count uint64) bool {
	return shouldLogConsoleSampleCount(count)
}

func shouldLogDropConsole() bool {
	return shouldLogDropConsoleCount(dropConsoleLogCounter.Add(1))
}

func shouldLogNoSiteMatchConsoleCount(count uint64) bool {
	return shouldLogConsoleSampleCount(count)
}

func shouldLogNoSiteMatchConsole() bool {
	return shouldLogNoSiteMatchConsoleCount(noSiteMatchConsoleLogCounter.Add(1))
}

var accessLogSampleCounter atomic.Uint32

type accessLogInfo struct {
	SiteID               uint
	RequestID            string
	ClientIP             string
	Host                 string
	Path                 string
	QueryString          string
	Method               string
	UserAgent            string
	StatusCode           int
	WAFAction            string
	CacheState           string
	Upstream             string
	HTTPProtocol         string
	UpstreamHTTPProtocol string
	TLSFingerprint       bot.TLSClientFingerprint
	// HeaderOrder 是已 join 的请求头顺序字符串，主路径直接复用 DerivedHeaderOrder，避免再次 Join。
	HeaderOrder          string
	UpstreamLatencyMs    int64
	ResponseSize         int64
	ResponseSizeKnown    bool
	RequestHeaders       string
	RequestBodyPreview   string
	RequestBodyTruncated bool
	RequestSize          int64
	ResponseHeaders      string
	Detailed             bool
}

func shouldRecordDetailedSecurityEvent(ev store.SecurityEvent) bool {
	switch action.Normalize(action.Type(ev.Action)) {
	case action.Drop, action.Intercept, action.RateLimit, action.Challenge, action.CaptchaChallenge, action.ShieldChallenge, action.ChainChallenge, action.Redirect:
		return true
	default:
		return ev.StatusCode >= 400
	}
}

func recordSecurityEvent(c *app.RequestContext, opts Options, ev store.SecurityEvent) {
	if opts.Writer == nil {
		return
	}
	if ev.QueryString == "" {
		ev.QueryString = string(c.URI().QueryString())
	}
	ev.QueryString = sanitizeQueryString(ev.QueryString)
	if fp, ok := tlsFingerprintFromRequestContext(c); ok {
		if ev.TLSJA3 == "" {
			ev.TLSJA3 = fp.JA3
		}
		if ev.TLSJA3Hash == "" {
			ev.TLSJA3Hash = fp.JA3Hash
		}
		if ev.TLSJA4 == "" {
			ev.TLSJA4 = fp.JA4
		}
		if ev.TLSVersion == "" {
			ev.TLSVersion = fp.TLSVersion
		}
		if ev.TLSSNI == "" {
			ev.TLSSNI = fp.SNI
		}
		if ev.TLSALPN == "" && len(fp.ALPN) > 0 {
			ev.TLSALPN = strings.Join(fp.ALPN, ",")
		}
		if ev.TLSCipherSuites == "" && len(fp.CipherSuites) > 0 {
			ev.TLSCipherSuites = tlsmeta.FormatCipherSuites(fp.CipherSuites)
		}
		if ev.TLSExtensions == "" && len(fp.Extensions) > 0 {
			ev.TLSExtensions = formatUint16Slice(fp.Extensions)
		}
		if ev.TLSCurves == "" && len(fp.Curves) > 0 {
			ev.TLSCurves = formatUint16Slice(fp.Curves)
		}
		if ev.TLSPointFormats == "" && len(fp.PointFormats) > 0 {
			ev.TLSPointFormats = formatUint8Slice(fp.PointFormats)
		}
	}
	if ev.HeaderOrder == "" {
		ev.HeaderOrder = strings.Join(requestHeaderOrder(c), ",")
	}
	if shouldRecordDetailedSecurityEvent(ev) {
		reqBody, truncated, size := requestBodyPreview(c)
		ev.RequestHeaders = valueOrFallback(ev.RequestHeaders, requestHeadersJSON(c))
		ev.RequestBodyPreview = valueOrFallback(ev.RequestBodyPreview, reqBody)
		ev.RequestBodyTruncated = ev.RequestBodyTruncated || truncated
		ev.RequestSize = firstPositive(ev.RequestSize, size)
	}
	opts.Writer.RecordEvent(ev)
}

type accessLogRecorder interface {
	RecordAccessLog(store.AccessLog)
}

func buildAccessLogEntry(c *app.RequestContext, info accessLogInfo) store.AccessLog {
	if info.HTTPProtocol == "" {
		info.HTTPProtocol = requestProtocol(c)
	}
	if info.UpstreamHTTPProtocol == "" {
		info.UpstreamHTTPProtocol = proxy.UpstreamHTTPProtocol(c)
	}
	if isInternalHTTP3Request(c) {
		if fp, ok := tlsFingerprintFromRequestContext(c); ok {
			info.TLSFingerprint = fp
		} else {
			info.TLSFingerprint = bot.TLSClientFingerprint{}
		}
	} else {
		if fp, ok := tlsFingerprintFromRequestContext(c); ok {
			info.TLSFingerprint = mergeTLSFingerprint(info.TLSFingerprint, fp)
		}
	}
	if info.HeaderOrder == "" {
		info.HeaderOrder = strings.Join(requestHeaderOrder(c), ",")
	}
	requestBody := info.RequestBodyPreview
	requestBodyTruncated := info.RequestBodyTruncated
	requestSize := info.RequestSize
	requestHeaders := info.RequestHeaders
	responseHeaders := info.ResponseHeaders
	responseSize := info.ResponseSize
	if !info.ResponseSizeKnown && responseSize == 0 && c.Response.Header.Get("Trailer") == "" && string(c.Request.Method()) != "HEAD" {
		if cl := int64(c.Response.Header.ContentLength()); cl > 0 {
			responseSize = cl
		} else if !c.Response.IsBodyStream() {
			responseSize = int64(len(c.Response.Body()))
		}
	}
	if info.Detailed {
		if requestBody == "" || requestSize == 0 {
			var bodyTruncated bool
			requestBody, bodyTruncated, requestSize = requestBodyPreview(c)
			requestBodyTruncated = requestBodyTruncated || bodyTruncated
		}
		requestHeaders = valueOrFallback(requestHeaders, requestHeadersJSON(c))
		responseHeaders = valueOrFallback(responseHeaders, responseHeadersJSON(c))
	}
	if isDynamicProtectionKeyPath(c, info.Path) {
		requestBody = "[redacted]"
	}
	return store.AccessLog{
		SiteID:               info.SiteID,
		RequestID:            info.RequestID,
		ClientIP:             info.ClientIP,
		Host:                 info.Host,
		Path:                 info.Path,
		QueryString:          sanitizeQueryString(info.QueryString),
		Method:               info.Method,
		StatusCode:           info.StatusCode,
		WAFAction:            info.WAFAction,
		CacheState:           info.CacheState,
		Upstream:             info.Upstream,
		UserAgent:            info.UserAgent,
		RequestHeaders:       requestHeaders,
		RequestBodyPreview:   requestBody,
		RequestBodyTruncated: requestBodyTruncated,
		RequestSize:          requestSize,
		ResponseHeaders:      responseHeaders,
		HTTPProtocol:         info.HTTPProtocol,
		UpstreamHTTPProtocol: info.UpstreamHTTPProtocol,
		TLSVersion:           info.TLSFingerprint.TLSVersion,
		TLSSNI:               info.TLSFingerprint.SNI,
		TLSALPN:              strings.Join(info.TLSFingerprint.ALPN, ","),
		TLSJA3:               info.TLSFingerprint.JA3,
		TLSJA3Hash:           info.TLSFingerprint.JA3Hash,
		TLSJA4:               info.TLSFingerprint.JA4,
		TLSCipherSuites:      tlsmeta.FormatCipherSuites(info.TLSFingerprint.CipherSuites),
		TLSExtensions:        formatUint16Slice(info.TLSFingerprint.Extensions),
		TLSCurves:            formatUint16Slice(info.TLSFingerprint.Curves),
		TLSPointFormats:      formatUint8Slice(info.TLSFingerprint.PointFormats),
		HeaderOrder:          info.HeaderOrder,
		UpstreamLatencyMs:    info.UpstreamLatencyMs,
		ResponseSize:         responseSize,
	}
}

func mergeTLSFingerprint(base bot.TLSClientFingerprint, extra bot.TLSClientFingerprint) bot.TLSClientFingerprint {
	if base.JA3 == "" {
		base.JA3 = extra.JA3
	}
	if base.JA3Hash == "" {
		base.JA3Hash = extra.JA3Hash
	}
	if base.JA4 == "" {
		base.JA4 = extra.JA4
	}
	if base.TLSVersion == "" {
		base.TLSVersion = extra.TLSVersion
	}
	if base.SNI == "" {
		base.SNI = extra.SNI
	}
	if len(base.ALPN) == 0 {
		base.ALPN = extra.ALPN
	}
	if len(base.CipherSuites) == 0 {
		base.CipherSuites = extra.CipherSuites
	}
	if len(base.Extensions) == 0 {
		base.Extensions = extra.Extensions
	}
	if len(base.Curves) == 0 {
		base.Curves = extra.Curves
	}
	if len(base.PointFormats) == 0 {
		base.PointFormats = extra.PointFormats
	}
	return base
}

func formatUint16Slice(s []uint16) string {
	if len(s) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s) * 6)
	for i, v := range s {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

func formatUint8Slice(s []uint8) string {
	if len(s) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s) * 4)
	for i, v := range s {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

const (
	logBodyPreviewLimit  = 8192
	logHeaderValueLimit  = 2048
	logHeaderValuesLimit = 32
)

var sensitiveLogValuePattern = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|session|api[_-]?key|auth[_-]?token|csrf|code|ticket|env)(["'\s:=]+)([^&\s,"'}]+)`)

func requestHeadersJSON(c *app.RequestContext) string {
	headers := make(map[string][]string)
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		// toLowerASCII 对已是小写的输入零分配直接返回原串，header 名绝大多数如此。
		lower := toLowerASCII(key)
		if isSensitiveLogKeyLowered(lower) {
			headers[key] = []string{"[redacted]"}
			return
		}
		values := headers[key]
		if len(values) >= logHeaderValuesLimit {
			return
		}
		headers[key] = append(values, truncateLogValue(sanitizeLogText(string(v)), logHeaderValueLimit))
	})
	data, err := json.Marshal(headers)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func responseHeadersJSON(c *app.RequestContext) string {
	headers := make(map[string][]string)
	c.Response.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		// toLowerASCII 对已是小写的输入零分配直接返回原串，header 名绝大多数如此。
		lower := toLowerASCII(key)
		if isSensitiveLogKeyLowered(lower) {
			headers[key] = []string{"[redacted]"}
			return
		}
		values := headers[key]
		if len(values) >= logHeaderValuesLimit {
			return
		}
		headers[key] = append(values, truncateLogValue(sanitizeLogText(string(v)), logHeaderValueLimit))
	})
	data, err := json.Marshal(headers)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func requestBodyPreview(c *app.RequestContext) (string, bool, int64) {
	body, truncated, size := requestBodySample(c)
	if len(body) > logBodyPreviewLimit {
		body = body[:logBodyPreviewLimit]
		truncated = true
	}
	if isDynamicProtectionKeyPath(c, "") {
		return "[redacted]", truncated, size
	}
	if len(body) == 0 {
		return "", truncated, size
	}
	contentType := strings.ToLower(strings.TrimSpace(string(c.Request.Header.ContentType())))
	return sanitizeBodyPreview(string(body), contentType), truncated, size
}

func isDynamicProtectionKeyPath(c *app.RequestContext, loggedPath string) bool {
	if loggedPath == dynamicProtectionKeyPath {
		return true
	}
	return c != nil && string(c.Path()) == dynamicProtectionKeyPath
}

func sanitizeQueryString(raw string) string {
	if raw == "" {
		return ""
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return sanitizeLogText(raw)
	}
	for key := range values {
		if isSensitiveLogKey(key) {
			values[key] = []string{"[redacted]"}
		} else {
			for i, value := range values[key] {
				values[key][i] = sanitizeLogText(value)
			}
		}
	}
	return values.Encode()
}

// queryParams 以与 net/url 相同的解码规则生成 Lua 可见的查询参数。
// 重复键保留第一个值，与 dry-run 的 map 契约一致；解析失败时返回 nil。
func sanitizeBodyPreview(body, contentType string) string {
	if body == "" {
		return ""
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	switch mediaType {
	case "application/x-www-form-urlencoded":
		return sanitizeQueryString(body)
	case "application/json":
		var value any
		if json.Unmarshal([]byte(body), &value) == nil {
			return marshalSanitizedJSON(value)
		}
	}
	return sanitizeLogText(body)
}

func marshalSanitizedJSON(value any) string {
	data, err := json.Marshal(sanitizeJSONValue(value))
	if err != nil {
		return ""
	}
	return string(data)
}

func sanitizeJSONValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			if isSensitiveLogKey(key) {
				out[key] = "[redacted]"
			} else {
				out[key] = sanitizeJSONValue(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = sanitizeJSONValue(item)
		}
		return out
	case string:
		return sanitizeLogText(v)
	default:
		return value
	}
}

// sensitiveLogValueHints 是 sensitiveLogValuePattern 首个捕获组的字面量集合。
//
// 正则含 (?i)，故这里全部为小写，判定前先把输入转为小写比较。任何一项都不出现时，
// 正则必然无法匹配，可直接跳过 ReplaceAllString。
//
// 与正则保持同步：新增关键字时两处都要改，由 TestSensitiveLogValueHintsCoverPattern
// 兜住漏改。
var sensitiveLogValueHints = []string{
	"password", "passwd", "pwd", "token", "secret", "session",
	"api_key", "api-key", "apikey", "auth_token", "auth-token", "authtoken",
	"csrf", "code", "ticket", "env",
}

/**
 * sanitizeLogText 遮蔽文本中形如 key=value 的敏感取值。
 *
 * 绝大多数 header value 不含任何敏感关键字，而正则即使无匹配也要扫完整串。
 * 因此先做一次廉价的字面量预筛，命中才跑正则。
 *
 * @param value 待脱敏的原始文本。
 * @return 敏感取值已替换为 [redacted] 的文本；无敏感内容时原样返回。
 */
func sanitizeLogText(value string) string {
	if !containsSensitiveLogHint(value) {
		return value
	}
	return sensitiveLogValuePattern.ReplaceAllString(value, `${1}${2}[redacted]`)
}

// containsSensitiveLogHint 判断文本是否可能含敏感取值。
// 命中即需要跑正则；未命中则正则必然不匹配。
func containsSensitiveLogHint(value string) bool {
	if value == "" {
		return false
	}
	lower := toLowerASCII(value)
	for _, hint := range sensitiveLogValueHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func truncateLogValue(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}

// sensitiveLogKeyParts 是需要整体遮蔽取值的 header 名片段（全小写）。
var sensitiveLogKeyParts = []string{
	"authorization", "cookie", "token", "secret", "password", "passwd", "pwd",
	"session", "api-key", "apikey", "csrf", "credential", "key", "ticket", "env",
}

// isSensitiveLogKey 判断 header 名是否属于敏感项。接受任意大小写。
func isSensitiveLogKey(key string) bool {
	return isSensitiveLogKeyLowered(toLowerASCII(key))
}

/**
 * isSensitiveLogKeyLowered 与 isSensitiveLogKey 相同，但要求入参已是小写。
 *
 * 调用方通常已为别处算过一次小写形式，再在函数内重复转换是白做一遍 O(n) 扫描。
 *
 * @param lower 已转为小写的 header 名。
 * @return 属于敏感项则为 true。
 */
func isSensitiveLogKeyLowered(lower string) bool {
	for _, part := range sensitiveLogKeyParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}
func valueOrFallback(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func firstPositive(value, fallback int64) int64 {
	if value > 0 {
		return value
	}
	return fallback
}

func tlsFingerprintFromRequestContext(c *app.RequestContext) (bot.TLSClientFingerprint, bool) {
	if value, ok := c.Get(tlsFingerprintContextKey); ok {
		if fp, ok := value.(bot.TLSClientFingerprint); ok && fp.HasValue() {
			return fp, true
		}
	}
	if isInternalHTTP3Request(c) {
		return bot.TLSClientFingerprint{}, false
	}
	if fp, ok := bot.TLSFingerprintFromConn(c.GetConn()); ok {
		c.Set(tlsFingerprintContextKey, fp)
		return fp, true
	}
	return bot.TLSClientFingerprint{}, false
}

func enqueueAccessLog(writer accessLogRecorder, al store.AccessLog) {
	writer.RecordAccessLog(al)
}

func recordAccessLog(c *app.RequestContext, opts Options, info accessLogInfo) {
	if opts.Writer == nil || !shouldRecordAccessLog(info, opts.AccessLogSamplingRate) {
		return
	}
	info.Detailed = shouldRecordDetailedAccessLog(info)
	enqueueAccessLog(opts.Writer, buildAccessLogEntry(c, info))
}

func shouldRecordDetailedAccessLog(info accessLogInfo) bool {
	return info.WAFAction != "none" || info.StatusCode >= 400
}

func shouldRecordAccessLog(info accessLogInfo, rate uint32) bool {
	if info.WAFAction != "none" || info.StatusCode >= 400 {
		return true
	}
	if rate == 0 {
		return false
	}
	if rate <= 1 {
		return true
	}
	return accessLogSampleCounter.Add(1)%rate == 0
}

func requestHeaderOrder(c *app.RequestContext) []string {
	keys := make([]string, 0, 16)
	c.Request.Header.VisitAll(func(k, _ []byte) {
		keys = append(keys, string(k))
	})
	return keys
}

func isInternalHTTP3Request(c *app.RequestContext) bool {
	if value, ok := c.Get(internalHTTP3ContextKey); ok {
		if b, ok := value.(bool); ok && b {
			return true
		}
	}
	return false
}

func requestProtocol(c *app.RequestContext) string {
	if isInternalHTTP3Request(c) {
		return "h3"
	}
	if proto := normalizeHTTPProtocol(c.Request.Header.GetProtocol()); proto != "" {
		return proto
	}
	if fp, ok := tlsFingerprintFromRequestContext(c); ok {
		if len(fp.ALPN) > 0 {
			return strings.ToLower(fp.ALPN[0])
		}
		return "https"
	}
	return "http"
}

func normalizeHTTPProtocol(proto string) string {
	switch strings.ToUpper(proto) {
	case "HTTP/2.0", "HTTP/2":
		return "h2"
	case "HTTP/1.1":
		return "http/1.1"
	case "HTTP/1.0":
		return "http/1.0"
	case "H2":
		return "h2"
	case "H2C":
		return "h2c"
	case "H3":
		return "h3"
	default:
		return ""
	}
}

func recordDropEvent(opts Options, siteID uint, clientIP net.IP, reason drop.DropReason) {
	if opts.Writer == nil {
		return
	}
	opts.Writer.RecordDropEvent(store.DropEvent{
		SiteID:    siteID,
		ClientIP:  clientIPStr(clientIP),
		Source:    reason.Source,
		RuleID:    reason.RuleID,
		Detail:    reason.Detail,
		Host:      reason.Host,
		Path:      reason.Path,
		CreatedAt: reason.Timestamp,
	})
}

func dropEnabled(eng *engine.Engine) bool {
	dropExec := eng.DropExecutor()
	return dropExec != nil && dropExec.Enabled()
}

func rateLimitKey(clientIP net.IP, host string) string {
	return clientIPStr(clientIP) + "|" + host
}

func shouldApplyErrorRateLimit(eng *engine.Engine, prot store.ProtectionConfig, key string) bool {
	if eng == nil {
		return false
	}
	errRL := eng.ErrRateLimiter()
	return errRL != nil && errRL.Enabled() && errRL.IsOverLimit(key)
}

func errorRateLimitAction(configured string) action.Result {
	act := action.Normalize(action.Type(configured))
	if act == "" {
		act = action.RateLimit
	}
	res := action.Result{
		Type:      act,
		Phase:     "error_rate_limit",
		RuleIDStr: "error_rate_limit",
		MatchDesc: "error rate limit exceeded",
		Matched:   true,
		Category:  "rate_limit",
	}
	if act == action.RateLimit {
		res.StatusCode = 429
	}
	return res
}

func incrementErrorRateLimitBlock(eng *engine.Engine, prot store.ProtectionConfig, key string) {
	if !prot.ErrorRateLimitCountBlock {
		return
	}
	incrementErrorRateLimit(eng, key)
}

func incrementErrorRateLimitStatus(eng *engine.Engine, prot store.ProtectionConfig, key string, statusCode int) {
	switch {
	case prot.ErrorRateLimitCount4xx && statusCode >= 400 && statusCode < 500:
		incrementErrorRateLimit(eng, key)
	case prot.ErrorRateLimitCount5xx && statusCode >= 500:
		incrementErrorRateLimit(eng, key)
	}
}

func incrementErrorRateLimit(eng *engine.Engine, key string) {
	if eng == nil {
		return
	}
	errRL := eng.ErrRateLimiter()
	if errRL != nil && errRL.Enabled() {
		errRL.Increment(key)
	}
}

func clientIPStr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func accessPath(c *app.RequestContext) string {
	if rawPath := c.Request.URI().PathOriginal(); len(rawPath) > 0 {
		return string(rawPath)
	}
	return string(c.Path())
}

func accessStatusCode(c *app.RequestContext, wafAction string) int {
	if wafAction == "drop" {
		return 0
	}
	return c.Response.StatusCode()
}

func normalizeAntiReplayAction(raw string) string {
	switch action.Normalize(action.Type(raw)) {
	case action.CaptchaChallenge:
		return string(action.CaptchaChallenge)
	case action.ShieldChallenge:
		return string(action.ShieldChallenge)
	case action.ChainChallenge:
		return string(action.ChainChallenge)
	case action.Intercept:
		return string(action.Intercept)
	case action.Challenge:
		return string(action.Challenge)
	default:
		return string(action.Challenge)
	}
}

// challengeTokenClaims 组装 JS 挑战 token 的客户端绑定信息。
// 客户端 IP 按站点的 XFF 策略解析，与通行 cookie 使用同一套身份字段，
// 保证挑战页与其换取的通行凭证绑定到同一个客户端。
func challengeSessionBinding(c *app.RequestContext, opts Options) (challenge.ChallengeSessionBinding, bool) {
	if opts.Holder == nil {
		return challenge.ChallengeSessionBinding{}, false
	}
	sn := opts.Holder.Load()
	if sn == nil {
		return challenge.ChallengeSessionBinding{}, false
	}
	host := string(c.Host())
	bind := listenerBind(c)
	if bind == "" {
		bind = opts.Bind
	}
	rt, ok := sn.MatchSite(bind, host)
	if !ok {
		return challenge.ChallengeSessionBinding{}, false
	}
	return challengeSessionBindingForSite(rt.Site.ID, host, bind), true
}

func challengeSessionBindingForSite(siteID uint, host, bind string) challenge.ChallengeSessionBinding {
	return challenge.ChallengeSessionBinding{SiteID: siteID, Host: snapshot.NormalizeMatchHost(host), Bind: bind}
}

func challengeTokenClaims(c *app.RequestContext, rt *snapshot.SiteRuntime) challenge.ChallengeTokenClaims {
	claims := challenge.ChallengeTokenClaims{
		UserAgent: string(c.UserAgent()),
		Host:      string(c.Host()),
	}
	if rt != nil {
		claims.ClientIP = clientIPStr(security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR, rt.ClientIPHeaderOrder))
		claims.SiteID = rt.Site.ID
	}
	return claims
}

func writeAntiReplayActionResponse(c *app.RequestContext, opts Options, sn *snapshot.Snapshot, rt *snapshot.SiteRuntime, reqID, antiReplayAct string, result action.Result, statusCode int) {
	bind := listenerBind(c)
	if bind == "" {
		bind = opts.Bind
	}
	binding := challengeSessionBindingForSite(rt.Site.ID, string(c.Host()), bind)
	switch action.Type(antiReplayAct) {
	case action.CaptchaChallenge:
		if sn != nil && sn.Protection.CaptchaEnabled && opts.CaptchaManager != nil {
			captchaType := challenge.CaptchaType(sn.Protection.CaptchaType)
			challenge.WriteCaptchaChallengeResponse(c, reqID, opts.CaptchaManager, captchaType, sn.Protection.ShieldEnableEnvCheck, binding, statusCode, sn.CaptchaPage)
			return
		}
	case action.ShieldChallenge:
		if sn != nil && sn.Protection.ShieldEnabled && opts.ShieldManager != nil {
			origURL := string(c.Request.URI().RequestURI())
			opts.ShieldManager.WriteShieldChallengeResponse(c, reqID, origURL, requestProtocol(c), binding, statusCode)
			return
		}
	case action.ChainChallenge:
		if sn != nil && sn.Protection.ChainEnabled && opts.ChainManager != nil {
			challenge.WriteChainChallengeResponse(c, reqID, opts.ChainManager, binding, statusCode)
			return
		}
	case action.Challenge:
		envCheck := sn != nil && sn.Protection.ShieldEnableEnvCheck
		pages.WriteChallengeResponse(c, reqID, rt, envCheck, statusCode, sn.ChallengePage, challengeTokenClaims(c, rt))
		return
	}
	pages.WriteBlockResponse(c, reqID, rt, sn, result)
}

func hasUpstreamServerHeader(c *app.RequestContext) bool {
	sv := string(c.Response.Header.Peek("Server"))
	return sv != "" && sv != "hertz"
}

func siteErrorPage(rt *snapshot.SiteRuntime, statusCode int) *pages.ErrorPageConfig {
	if rt == nil || strings.TrimSpace(rt.Site.CustomErrorPages) == "" || rt.Site.CustomErrorPages == "{}" {
		return nil
	}
	epMap := make(map[string]pages.ErrorPageConfig)
	if err := json.Unmarshal([]byte(rt.Site.CustomErrorPages), &epMap); err != nil {
		return nil
	}
	cfg, ok := epMap[strconv.Itoa(statusCode)]
	if !ok {
		return nil
	}
	if cfg.StatusCode == 0 {
		cfg.StatusCode = statusCode
	}
	return &cfg
}

func isTimeoutError(err error) bool {
	if err == context.DeadlineExceeded {
		return true
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
		return true
	}
	return false
}

// handleWASMAssets serves the PoW WASM binary and JS glue.
func handleWASMAssets(c *app.RequestContext) bool {
	path := string(c.Path())
	switch path {
	case "/__owaf/pow.wasm":
		challenge.ServePoWWASM(c)
		return true
	case "/__owaf/pow_glue.js":
		challenge.ServePowGlueJS(c)
		return true
	}
	return false
}

// handleChallengeVerify handles POST requests to challenge verification endpoints.
// Returns true if the request was handled (caller should return early).
func handleChallengeVerify(c *app.RequestContext, opts Options) bool {
	if string(c.Method()) != "POST" {
		return false
	}

	path := string(c.Path())
	switch path {
	case "/__owaf/captcha/verify":
		return handleCaptchaVerify(c, opts)
	case "/__owaf/shield/verify":
		return handleShieldVerify(c, opts)
	case "/__owaf/chain/verify":
		return handleChainVerify(c, opts)
	}
	return false
}

type dynamicProtectionKeyRequest struct {
	Ticket string `json:"ticket"`
	Key    string `json:"key"`
}

// parseDynamicProtectionKeyRequest 仅解析服务端签发票据所需的字段。
// 浏览器环境信号可由客户端任意构造，不能作为 KEK 兑换授权条件。
func parseDynamicProtectionKeyRequest(body []byte) (dynamicProtectionKeyRequest, bool) {
	if len(body) == 0 {
		return dynamicProtectionKeyRequest{}, false
	}
	var req dynamicProtectionKeyRequest
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&req); err != nil {
		return dynamicProtectionKeyRequest{}, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return dynamicProtectionKeyRequest{}, false
	}
	if req.Ticket == "" || req.Key == "" {
		return dynamicProtectionKeyRequest{}, false
	}
	return req, true
}

func handleDynamicProtectionKey(c *app.RequestContext, opts Options) bool {
	if string(c.Path()) != dynamicProtectionKeyPath {
		return false
	}
	statusCode := http.StatusOK
	wafAction := "dynamic_key"
	requestID := fastRequestID()
	c.Response.Header.Set("X-Request-ID", requestID)
	c.Response.Header.Set("Cache-Control", "no-store")
	c.Response.Header.Set("Pragma", "no-cache")
	if opts.Metrics != nil {
		opts.Metrics.RecordRequest()
	}
	host := string(c.Host())
	bind := listenerBind(c)
	if bind == "" {
		bind = opts.Bind
	}
	var siteID uint
	var logClientIP net.IP
	defer func() {
		if opts.Metrics != nil {
			opts.Metrics.RecordStatus(statusCode)
		}
		if logClientIP == nil {
			logClientIP = security.ResolveClientIP(c, "", "", nil)
		}
		recordAccessLog(c, opts, accessLogInfo{SiteID: siteID, RequestID: requestID, ClientIP: clientIPStr(logClientIP), Host: host, Path: string(c.Path()), Method: string(c.Method()), UserAgent: string(c.UserAgent()), StatusCode: statusCode, WAFAction: wafAction, CacheState: "bypass"})
	}()
	if string(c.Method()) != http.MethodPost {
		statusCode = http.StatusMethodNotAllowed
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return true
	}
	body := c.Request.Body()
	if len(body) > dynamicProtectionKeyRequestBodyMax {
		statusCode = http.StatusRequestEntityTooLarge
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusRequestEntityTooLarge, map[string]string{"error": "dynamic key request body too large"})
		return true
	}
	req, ok := parseDynamicProtectionKeyRequest(body)
	if !ok {
		statusCode = http.StatusBadRequest
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid dynamic key request"})
		return true
	}
	sn := opts.Holder.Load()
	if sn == nil {
		statusCode = http.StatusServiceUnavailable
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "configuration snapshot not loaded"})
		return true
	}
	rt, ok := sn.MatchSite(bind, host)
	if !ok {
		statusCode = http.StatusNotFound
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusNotFound, map[string]string{"error": "site not found"})
		return true
	}
	siteID = rt.Site.ID
	clientIP := security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR, rt.ClientIPHeaderOrder)
	logClientIP = clientIP
	ttl := dynamicpkg.NormalizeDecryptCacheTTLSeconds(rt.DynamicProtection.DecryptCacheTTLSeconds)
	claims := challenge.DynamicProtectionClaims{Host: host, ClientIP: clientIP, UserAgent: string(c.UserAgent()), SiteID: rt.Site.ID, Bind: bind}
	kek, ok := challenge.VerifyDynamicProtectionKeyTicket(req.Ticket, challenge.DynamicProtectionKeyClaims{DynamicProtectionClaims: claims, Key: req.Key}, time.Now())
	if !ok {
		statusCode = http.StatusForbidden
		wafAction = "dynamic_key_error"
		c.JSON(http.StatusForbidden, map[string]string{"error": "invalid dynamic key ticket"})
		return true
	}
	cookie := challenge.BuildDynamicProtectionSessionCookieWithClaims(claims, rt.Site.TLSEnabled, time.Now(), time.Duration(ttl)*time.Second)
	c.Response.Header.Add("Set-Cookie", cookie)
	c.JSON(http.StatusOK, map[string]any{"kek": kek, "ttl": ttl})
	return true
}

/**
 * recordChallengeFailure 在服务端记录一次挑战验证失败。
 *
 * 三个 verify 端点原先失败即裸 redirect，服务端不留任何计数，客户端可无限重试。
 * ShieldMaxRetries 只在挑战页 JS 内判断，脚本化客户端重新 POST 即可绕过，
 * 因此必须由服务端把失败计入 IP 信誉。
 *
 * 复用既有的 iprep 违规计数（含滑动窗口、阈值与自动封禁 TTL），而不是新造一套
 * 计数器——避免对同一事实产生第二数据源，也让运维只需调一处阈值。
 *
 * 这些 verify 端点在站点匹配之前处理，拿不到站点级 XFF 配置，因此按 strip 模式
 * 解析（只认直连地址、不信任转发头）。这对计数场景更稳妥：伪造 XFF 无法把失败
 * 记到他人 IP 上。
 *
 * @param c    请求上下文。
 * @param opts 数据面选项，用于取 IP 信誉运行时与指标。
 */
func recordChallengeFailure(c *app.RequestContext, opts Options) {
	if opts.Engine == nil {
		return
	}
	ipRep := opts.Engine.IPReputation()
	if ipRep == nil {
		return
	}
	clientIP := security.ResolveClientIP(c, store.XFFModeStrip, "", nil)
	if clientIP == nil {
		return
	}
	if ipRep.RecordViolation(clientIP) && opts.Metrics != nil {
		opts.Metrics.RecordWAFBlock()
	}
}

// requestProtoFromContext extracts the request protocol from headers or TLS context.
func requestProtoFromContext(c *app.RequestContext) string {
	if v := strings.TrimSpace(string(c.GetHeader("X-Forwarded-Proto"))); v != "" {
		return strings.ToLower(v)
	}
	if fp, ok := tlsFingerprintFromRequestContext(c); ok && fp.TLSVersion != "" {
		return "https"
	}
	return "http"
}

func handleCaptchaVerify(c *app.RequestContext, opts Options) bool {
	if opts.CaptchaManager == nil {
		c.String(503, "captcha not configured")
		return true
	}
	binding, ok := challengeSessionBinding(c, opts)
	if !ok {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}

	sessionID := string(c.FormValue("__waf_captcha_session"))
	answer := string(c.FormValue("__waf_captcha_answer"))

	if sessionID == "" || answer == "" {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}

	ok, session := opts.CaptchaManager.VerifyAdvancedSessionWithBinding(sessionID, answer, binding)
	if ok && session != nil && len(session.EnvKey) > 0 {
		aad := challenge.EnvFingerprintAAD("captcha", session.ID, session.ChallengeSessionBinding)
		result := challenge.ValidateEnvFingerprint(challenge.DecryptEnvFingerprintWithAAD(string(c.FormValue("__waf_env_fp")), session.EnvKey, aad))
		if !result.Pass {
			ok = false
		}
	}

	if ok {
		setChallengeCookie(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
	} else {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
	}
	return true
}

func handleShieldVerify(c *app.RequestContext, opts Options) bool {
	if opts.ShieldManager == nil {
		c.String(503, "shield not configured")
		return true
	}
	binding, ok := challengeSessionBinding(c, opts)
	if !ok {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}

	sessionID := string(c.FormValue("__waf_shield_session"))
	captchaAnswer := string(c.FormValue("__waf_captcha_answer"))
	counterStr := string(c.FormValue("__waf_pow_counter"))
	hash := string(c.FormValue("__waf_pow_hash"))
	envFP := string(c.FormValue("__waf_env_fp"))

	counterText := strings.TrimSpace(counterStr)
	if counterText == "" {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}
	counter, err := strconv.ParseInt(counterText, 10, 64)
	if err != nil || counter < 0 {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}

	passed, originalURL := opts.ShieldManager.VerifyChallengeWithBinding(sessionID, captchaAnswer, counter, hash, envFP, requestProtocol(c), binding)
	if passed {
		setChallengeCookie(c, opts)
		if originalURL == "" {
			originalURL = "/"
		}
		c.Redirect(302, []byte(originalURL))
	} else {
		// Re-challenge。失败计入 IP 信誉：ShieldMaxRetries 只在页面 JS 内生效，
		// 脚本化客户端重新 POST 即可绕过，必须由服务端侧限制重试。
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
	}
	return true
}

func handleChainVerify(c *app.RequestContext, opts Options) bool {
	if opts.ChainManager == nil {
		c.String(503, "chain challenge not configured")
		return true
	}
	binding, ok := challengeSessionBinding(c, opts)
	if !ok {
		recordChallengeFailure(c, opts)
		c.Redirect(302, []byte(safeRefererRedirect(c)))
		return true
	}

	sessionID := string(c.FormValue("__waf_chain_session"))
	stepType := string(c.FormValue("__waf_chain_step"))

	formData := map[string]string{
		"env_fp":         string(c.FormValue("__waf_env_fp")),
		"pow_counter":    string(c.FormValue("__waf_pow_counter")),
		"pow_hash":       string(c.FormValue("__waf_pow_hash")),
		"captcha_answer": string(c.FormValue("__waf_captcha_answer")),
		"step_type":      stepType,
	}

	// 用 Detailed 版本：链内「正常推进到下一步」与「步内校验失败重渲染当前步」
	// 的三元返回值完全相同，只有 Failed 能区分，否则会把正常访客计为失败。
	outcome := opts.ChainManager.ProcessStepDetailedWithBinding(sessionID, formData, binding)
	if outcome.Failed {
		recordChallengeFailure(c, opts)
	}
	switch {
	case outcome.Passed:
		setChallengeCookie(c, opts)
		redirectURL := outcome.RedirectURL
		if redirectURL == "" {
			redirectURL = "/"
		}
		c.Redirect(302, []byte(redirectURL))
	case outcome.NextHTML != "":
		c.Data(403, "text/html; charset=utf-8", []byte(outcome.NextHTML))
	default:
		c.Redirect(302, []byte("/"))
	}
	return true
}

func setChallengeCookie(c *app.RequestContext, opts Options) {
	sn := opts.Holder.Load()
	if sn == nil {
		return
	}
	host := string(c.Host())
	bind := listenerBind(c)
	if bind == "" {
		bind = opts.Bind
	}
	rt, ok := sn.MatchSite(bind, host)
	if !ok {
		return
	}
	clientIP := security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR, rt.ClientIPHeaderOrder)
	cookie := challenge.BuildChallengePassCookieWithClaims(challenge.ChallengePassClaims{Host: host, ClientIP: clientIP, UserAgent: string(c.UserAgent()), SiteID: rt.Site.ID, Bind: bind}, rt.Site.TLSEnabled, time.Now(), challengePassTTL(sn.Protection))
	c.Response.Header.Set("Set-Cookie", cookie)
}

func challengePassTTL(prot store.ProtectionConfig) time.Duration {
	if prot.CaptchaPassTTL > 0 {
		return time.Duration(prot.CaptchaPassTTL) * time.Second
	}
	if prot.CaptchaTimeout > 0 {
		return time.Duration(prot.CaptchaTimeout) * time.Second
	}
	return time.Hour
}

// validateBasicAuth 校验 HTTP Basic Auth 凭据，使用常量时间比较防止时序攻击。
func validateBasicAuth(authHeader, expectedUser, expectedPass string) bool {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	userMatch := subtle.ConstantTimeCompare([]byte(parts[0]), []byte(expectedUser)) == 1
	passMatch := subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expectedPass)) == 1
	return userMatch && passMatch
}
