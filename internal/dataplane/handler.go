package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/adminweb"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/core/rules"
	dpreqid "My-OpenWaf/internal/dataplane/reqid"
	dpstream "My-OpenWaf/internal/dataplane/stream"
	"My-OpenWaf/internal/proxy"
	proxytransport "My-OpenWaf/internal/proxy/transport"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/challenge"
	challengepow "My-OpenWaf/internal/waf/challenge/pow"
	"My-OpenWaf/internal/waf/drop"
	wafescalation "My-OpenWaf/internal/waf/escalation"
	"My-OpenWaf/internal/waf/jsplugin"
	"My-OpenWaf/internal/waf/luaplugin"
	"My-OpenWaf/internal/waf/owasp"
	"My-OpenWaf/internal/waf/pages"
)

// Handler 返回 Hertz 中间件：维护模式 → WAF → 拦截熔断或反向代理。
func Handler(opts Options) app.HandlerFunc {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	// 注入响应阶段 JS 运行时的查找函数：proxy 无法导入 dataplane，查找
	// 函数把执行器与脚本从 hertz 请求上下文传递过去（见 js_response_runtime.go）。
	proxy.SetJSResponseRuntimeLookup(JSResponseRuntimeFromRequestContext)
	// 同理注入 Lua post 响应改写的查找函数；未注入时 proxy 跳过该阶段。
	proxy.SetLuaResponseRewriteLookup(LuaResponseMutationsFromRequestContext)
	var rr atomic.Uint32
	secLog := opts.Log.With(slog.String("section", "security"))
	accessLog := opts.Log
	staticFS, _ := adminweb.ResolveFS("")
	bindCloseNotify := dpstream.SelectStreamCloseNotifyBinding(opts.StreamCloseNotifyDisabled)

	return func(ctx context.Context, c *app.RequestContext) {
		ctx, closeNotifyCancel := bindCloseNotify(ctx, c)
		requestID := dpreqid.FastRequestID()
		c.Response.Header.Set("X-Request-ID", requestID)
		c.Response.Header.Del("Server")
		defer func() {
			finalizeUnrecordedAccessLog(ctx, c, opts, requestID)
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
		// WASM PoW 资产必须先于通用静态处理器检查，因为 serveOWAFStatic
		// 对未知的 /__owaf/ 路径会返回 true（并随之给出 404）。
		if handleWASMAssets(c) {
			return
		}

		if handleACMEChallenge(c, opts.ACMEChallengeResponse) {
			return
		}

		// 处理质询验证端点
		if handleChallengeVerify(c, opts) {
			recordChallengeVerifyAccessLog(c, opts)
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

		reqID := requestID
		if opts.Metrics != nil {
			opts.Metrics.RecordRequest()
		}

		var sn *snapshot.Snapshot
		if opts.Holder != nil {
			sn = opts.Holder.Load()
		}
		if sn == nil {
			c.String(http.StatusServiceUnavailable, "configuration snapshot not loaded")
			recordEarlyAccessLog(c, opts, requestID, http.StatusServiceUnavailable, "configuration_error")
			return
		}

		if maxH := sn.HTTP2Config.MaxHeaderFields; maxH > 0 && c.Request.Header.Len() > maxH {
			// 头字段超限仍要留下协议层审计行；早期身份解析只用于日志归属，不能驱动 WAF。
			pages.WriteErrorPage(ctx, c, http.StatusRequestHeaderFieldsTooLarge, nil)
			recordEarlyAccessLog(c, opts, requestID, http.StatusRequestHeaderFieldsTooLarge, "protocol_error")
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
			rt.ResponseCompressionDeflateEnabled = sn.ResponseCompressionDeflateEnabled
			rt.ResponseCompressionZstdEnabled = sn.ResponseCompressionZstdEnabled
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
			// 无站点匹配仍要留下路由层审计行；SiteID 保持为 0，避免伪造站点归属。
			pages.WriteWelcomePage(ctx, c)
			recordEarlyAccessLog(c, opts, requestID, http.StatusOK, "routing_error")
			return
		}
		if opts.Engine == nil {
			c.String(http.StatusServiceUnavailable, "waf engine unavailable")
			recordEarlyAccessLog(c, opts, requestID, http.StatusServiceUnavailable, "configuration_error")
			return
		}

		clientIP := security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR, rt.ClientIPHeaderOrder)
		cipStr := clientIPStr(clientIP)
		if clientIP != nil && opts.Metrics != nil {
			opts.Metrics.RecordClientIP(cipStr)
		}

		// 每请求只计算一次高频访问的 []byte → string 转换结果。
		// 这些字段在原先的主流程中被引用 5-12 次，每次调用都要分配并拷贝。
		// 只算一次可省下约 30 次小对象分配。
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
		challengeIdentityUA := ua
		challengeIdentityCookie := string(c.GetHeader("Cookie"))
		pathCached := string(c.Path())
		errorRateLimitKey := rateLimitKey(bind, rt.Site.ID, clientIP, host)

		if rt.Site.TLSEnabled && opts.Writer != nil {
			if fp, ok := tlsFingerprintFromRequestContext(c); ok {
				normalizedSNI := snapshot.NormalizeMatchHost(fp.SNI)
				normalizedHost := snapshot.NormalizeMatchHost(host)
				if normalizedSNI != "" && normalizedSNI != normalizedHost {
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
		}

		// 站点白名单需要在挑战失败计数前确定；实际名单决策由引擎 IP 声誉阶段统一执行。
		siteIPWhitelisted := siteIPWhitelistContains(rt.SiteIPWhitelist, clientIP)
		// 解压降级的接收端必须在取样本之前挂好：采样解压发生在
		// requestBodySampleBeforePipeline → ensureRequestBodySnapshot 里，
		// 挂晚了就收不到采样阶段的降级信号。只在请求真的带 Content-Encoding
		// 时挂载，绝大多数请求不为此多一次上下文写入。
		if len(requestBodyContentEncoding(c)) > 0 {
			ContextWithCompressionEventObserver(c, opts, rt.Site.ID, reqID, cipStr, host, method, ua)
		}
		body, _, _ := requestBodySampleBeforePipeline(c)
		recordUndetectedCompressedBodyEvent(c, opts, rt.Site.ID, reqID, cipStr, host, method, ua)
		challengePassed := false
		if method == "POST" {
			sub, ok := challengeSubmissionValues(body, string(c.Request.Header.ContentType()))
			// token 必须由同一客户端（IP/UA/Host/站点）换取，且只能兑换一次。
			challengePassed = ok &&
				challenge.VerifyChallengeTokenWithClaims(sub.RequestID, sub.TS, sub.Token,
					challenge.ChallengeTokenClaims{ClientIP: cipStr, UserAgent: challengeIdentityUA, Host: host, SiteID: rt.Site.ID},
					5*time.Minute)
			// 工作量证明：以 token 为 nonce 重算 SHA-256(token+counter)，
			// 确保客户端确实付出了算力，且该工作量无法跨挑战复用。
			if challengePassed && !challengepow.VerifyChallengeProof(sub.Token, sub.Counter, sub.Proof) {
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
		effectiveProtection := &sn.Protection
		protectionDerived := sn.ProtectionDerived
		if rt.EffectiveProtection != nil {
			effectiveProtection = rt.EffectiveProtection
			protectionDerived = rt.ProtectionDerived
		}
		if protectionDerived == nil {
			protectionDerived = snapshot.CompileProtectionDerived(effectiveProtection)
		}
		ciscoASAMode := owasp.NormalizeCiscoASAMode(protectionDerived.CiscoASAModeOverride)
		if strings.TrimSpace(protectionDerived.CiscoASAModeOverride) == "" {
			ciscoASAMode = owasp.CiscoASAModeScoped
		}
		skipPathByPhase := protectionDerived.SkipPathByPhase
		originalAntiReplaySkipped := owasp.MatchPathList(
			path,
			skipPathByPhase["anti_replay"],
		) || antiReplayCookieSkipPath(path)
		var antiReplayConsumedNonce string
		if rt.AntiReplayEnabled && !originalAntiReplaySkipped {
			handled, consumedNonce := handleAntiReplayCookie(
				c,
				opts,
				sn,
				&rt,
				reqID,
				cipStr,
				host,
				path,
				method,
				ua,
				rawQ,
				accessLog,
			)
			if handled {
				return
			}
			antiReplayConsumedNonce = consumedNonce
		}

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
		if sn.Protection.BasicAuthEnabled && sn.Protection.BasicAuthUsername != "" {
			if !validateBasicAuth(string(c.Request.Header.Peek("Authorization")), sn.Protection.BasicAuthUsername, sn.Protection.BasicAuthPassword) {
				c.Response.Header.Set("WWW-Authenticate", `Basic realm="WAF Protected"`)
				c.String(401, "Unauthorized")
				logAccess(accessLog, reqID, method, pathCached, host, 401, "basic_auth")
				recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: pathCached, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: 401, WAFAction: "basic_auth", CacheState: "bypass"})
				return
			}
		}

		contentType := strings.ToLower(strings.TrimSpace(string(c.Request.Header.ContentType())))
		if !owasp.MatchPathList(path, skipPathByPhase["owasp_default"]) {
			if blockAction, blocked := matchInlineOWASPGuards(path, rawQ, body, contentType, host, ciscoASAMode); blocked {
				pages.WriteBlockResponse(c, reqID, &rt, sn, blockAction)
				logAccess(accessLog, reqID, method, path, host, 403, "intercept")
				recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: 403, WAFAction: "intercept", CacheState: "bypass"})
				return
			}
		}

		reqCtx := pipeline.AcquireCtx()
		reqCtx.Context = ctx
		reqCtx.RequestID = reqID
		reqCtx.Bind = bind
		reqCtx.ClientIP = clientIP
		reqCtx.Method = method
		reqCtx.Path = path
		reqCtx.OriginalPath = path
		reqCtx.RawQuery = rawQ
		if lp := opts.Engine.LuaPlugins(); lp != nil && lp.HasScripts(luaplugin.StagePre) {
			rules.PopulateLuaQueryParams(reqCtx)
		}
		reqCtx.Host = host
		reqCtx.UserAgent = ua
		reqCtx.ChallengeIdentityCaptured = true
		reqCtx.ChallengeIdentityUserAgent = challengeIdentityUA
		reqCtx.ChallengeIdentityCookie = challengeIdentityCookie
		reqCtx.SiteID = rt.Site.ID

		// 请求走私协议违规审计：五类走私头在 hertz 协议解析层已被拒绝，
		// 此处把可观察到的字节层旁路信号与解析层残留形态转成审计/指标，
		// 不改变现有协议层拒绝行为，只做兜底审计与告警。
		if opts.Writer != nil {
			requestSmugglingSniff(c, opts, rt.Site.ID, reqID, host, cipStr)
		}
		reqCtx.AntiReplayTTL = rt.Site.AntiReplayTTL
		tlsFingerprint, ok := tlsFingerprintFromRequestContext(c)
		if !ok {
			tlsFingerprint, _ = tlsFingerprintFromContext(ctx)
		}
		reqCtx.TLS = tlsFingerprint
		populateRequestCtxHeaders(reqCtx, c)
		// HeaderOrder 惰性化：主路径（有 reqCtx 的 record 调用点）不再于
		// populate 后立即 Join 取址逃逸进 c.Set 缓存；第一条需要 HeaderOrder
		// 的记录由 reqCtx.DerivedHeaderOrder 计算一次并随 RequestCtx 缓存，
		// 全程至多一次 Join。无 reqCtx 的记录点回退 requestHeaderOrder。

		const maxWAFBody = 48 * 1024
		reqCtx.ContentType = string(c.Request.Header.ContentType())
		if len(body) > 0 {
			if len(body) > maxWAFBody {
				reqCtx.Body = headTailBodySample(body, maxWAFBody)
			} else {
				reqCtx.Body = body
			}
		}

		defer pipeline.ReleaseCtx(reqCtx)

		var jsExecutor jsplugin.Executor
		if current := opts.Engine.JSPlugins(); current != nil {
			jsExecutor = current
		}
		// 响应阶段执行器与脚本挂在 hertz 请求上下文上，由 internal/proxy 的响应
		// 变换链读取；请求阶段执行器保持原样走显式实参。
		ContextWithJSResponseRuntime(c, jspluginEngineAsResponseExecutor(jsExecutor), sn.JSPlugins)
		initialMethod, initialPath, initialRawQuery := method, path, rawQ
		initialContentType := string(c.Request.Header.ContentType())
		jsState, failedJSScript, jsErr := executeJSRequestStage(ctx, c, reqCtx, sn.JSPlugins, jsExecutor)
		jsRequestMutated := jsState.bodySet || jsState.method != initialMethod ||
			jsState.path != initialPath || jsState.rawQuery != initialRawQuery ||
			jsState.contentType != initialContentType
		method = jsState.method
		path = jsState.path
		pathCached = path
		rawQ = jsState.rawQuery
		if jsState.bodySet {
			body = []byte(jsState.body)
		}
		ua = jsState.userAgent
		contentType = jsState.contentType
		if jsErr != nil {
			scriptName := ""
			if failedJSScript != nil {
				scriptName = failedJSScript.Name()
			}
			opts.Log.Error("JavaScript request plugin failed closed",
				slog.String("request_id", reqID),
				slog.Uint64("site_id", uint64(rt.Site.ID)),
				slog.String("script", scriptName),
				slog.Any("err", jsErr),
			)
			pages.WriteErrorPage(ctx, c, http.StatusServiceUnavailable, siteErrorPage(&rt, http.StatusServiceUnavailable))
			if opts.Metrics != nil {
				opts.Metrics.RecordStatus(http.StatusServiceUnavailable)
			}
			logAccess(accessLog, reqID, method, path, host, http.StatusServiceUnavailable, "js_plugin_fail_closed")
			recordAccessLog(c, opts, accessLogInfo{
				SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host,
				Path: path, QueryString: rawQ, Method: method, UserAgent: ua,
				StatusCode: http.StatusServiceUnavailable, WAFAction: "js_plugin_fail_closed", CacheState: "bypass",
				HeaderOrder: reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }), TLSFingerprint: reqCtx.TLS,
			})
			return
		}

		// 请求阶段的 JavaScript 可能把请求改写到另一条受访问控制保护的路径。
		// 进入 WAF 管道前重新检查最终路径；先前那次检查保留着，用于阻止
		// 受保护的原始路径进入脚本阶段。内部 OWAF 端点只为原始请求派发；
		// 脚本构造出的内部路径绝不能代理到上游。
		if isScriptCreatedOWAFPath(path) {
			c.SetStatusCode(http.StatusNotFound)
			c.SetBodyString("not found")
			c.Abort()
			logAccess(accessLog, reqID, method, path, host, http.StatusNotFound, "intercept")
			recordAccessLog(c, opts, accessLogInfo{
				SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host,
				Path: path, QueryString: rawQ, Method: method, UserAgent: ua,
				StatusCode: http.StatusNotFound, WAFAction: "intercept", CacheState: "bypass",
				HeaderOrder:    reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }),
				TLSFingerprint: reqCtx.TLS,
			})
			return
		}
		finalAntiReplaySkipped := owasp.MatchPathList(
			path,
			skipPathByPhase["anti_replay"],
		) || antiReplayCookieSkipPath(path)
		if rt.AntiReplayEnabled && originalAntiReplaySkipped && !finalAntiReplaySkipped {
			handled, consumedNonce := handleAntiReplayCookie(
				c,
				opts,
				sn,
				&rt,
				reqID,
				cipStr,
				host,
				path,
				method,
				ua,
				rawQ,
				accessLog,
			)
			if handled {
				return
			}
			antiReplayConsumedNonce = consumedNonce
		}
		reqCtx.AntiReplayConsumedNonce = antiReplayConsumedNonce

		if enforceAccessControl(c, &rt, host, path) {
			statusCode := c.Response.StatusCode()
			wafAction := "intercept"
			if statusCode == http.StatusFound {
				wafAction = "redirect"
			}
			logAccess(accessLog, reqID, method, path, host, statusCode, wafAction)
			recordAccessLog(c, opts, accessLogInfo{
				SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host,
				Path: path, QueryString: rawQ, Method: method, UserAgent: ua,
				StatusCode: statusCode, WAFAction: wafAction, CacheState: "bypass",
				HeaderOrder:    reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }),
				TLSFingerprint: reqCtx.TLS,
			})
			return
		}

		skipInlineOWASP := owasp.MatchPathList(reqCtx.OriginalPath, skipPathByPhase["owasp_default"]) &&
			owasp.MatchPathList(path, skipPathByPhase["owasp_default"])
		if jsRequestMutated && !skipInlineOWASP {
			if blockAction, blocked := matchInlineOWASPGuards(path, rawQ, body, contentType, host, ciscoASAMode); blocked {
				pages.WriteBlockResponse(c, reqID, &rt, sn, blockAction)
				logAccess(accessLog, reqID, method, path, host, http.StatusForbidden, "intercept")
				recordAccessLog(c, opts, accessLogInfo{
					SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host,
					Path: path, QueryString: rawQ, Method: method, UserAgent: ua,
					StatusCode: http.StatusForbidden, WAFAction: "intercept", CacheState: "bypass",
					HeaderOrder:    reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }),
					TLSFingerprint: reqCtx.TLS,
				})
				return
			}
		}

		var result engine.ProcessResult
		// 请求阶段脚本的裁决优先于内置管道：脚本已经明确给出了请求的最终
		// 处置，再跑内置检测只会让更严重的检测结果盖掉脚本意图（例如脚本
		// 对内部标记路由放行、内置 OWASP 又把它拦下）。observe 不是终止动作，
		// 仍然进入管道，只作为 observe 命中记录。
		if verdict, ok := jsState.Verdict(); ok && verdict.IsTerminal() {
			result = engine.ProcessResult{Site: &rt, Action: verdict}
		} else if shouldApplyErrorRateLimit(opts.Engine, *effectiveProtection, errorRateLimitKey) {
			if errorRateLimitWhitelisted(opts.Engine, siteIPWhitelisted, clientIP) {
				result = opts.Engine.ProcessResolved(sn, &rt, reqCtx)
			} else {
				errorRateLimitResult := errorRateLimitAction(effectiveProtection.ErrorRateLimitAction)
				result = engine.ProcessResult{Site: &rt, Action: errorRateLimitResult}
				if errorRateLimitResult.Type == action.Observe {
					result.Action = action.Pass()
					result.ObserveHits = []action.Result{errorRateLimitResult}
				}
			}
		} else {
			result = opts.Engine.ProcessResolved(sn, &rt, reqCtx)
		}
		// Lua post 脚本的响应改写在此挂到请求上下文，由 proxy 的响应变换链
		// 在响应体到手后应用；没有改写时不写入任何值。
		ContextWithLuaResponseMutations(c, reqCtx.DrainResponseMutations())

		// Bot 评分日志经缓冲写入器落库。
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
				// 声明列表与协商结果分列两条：协商成 h1 时声明里的 h2 仍然可见。
				if len(reqCtx.TLS.ALPNRaw) > 0 {
					bsi.Details["tls_alpn_raw"] = strings.Join(reqCtx.TLS.ALPNRaw, ",")
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
				TLSSNIPresence:   reqCtx.TLS.SNIPresence(),
				TLSALPN:          reqCtx.DerivedALPN(func() string { return strings.Join(reqCtx.TLS.ALPN, ",") }),
				HeaderOrder:      reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }),
				TotalScore:       bsi.TotalScore,
				UAScore:          bsi.UAScore,
				GeoIPScore:       bsi.GeoIPScore,
				FingerprintScore: bsi.FingerprintScore,
				BehaviorScore:    bsi.BehaviorScore,
				IPRepScore:       bsi.IPRepScore,
				IsHighRisk:       bsi.IsHighRisk,
				Dangerous:        bsi.Dangerous,
				DangerReasons:    strings.Join(bsi.DangerReasons, ","),
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
			// 质询 cookie 放行：动作虽是质询类型，但客户端持有有效的签名通行
			// cookie 时，降级为放行并跳过质询。
			if result.Action.IsChallenge() {
				if challengeIdentityCookie != "" && challenge.VerifyChallengePassCookieWithClaims(challengeIdentityCookie, challenge.ChallengePassClaims{Host: host, ClientIP: clientIP, UserAgent: challengeIdentityUA, SiteID: rt.Site.ID, Bind: bind}, time.Now()) {
					result.Action = action.Pass()
				}
			}
		}

		if result.Action.IsTerminal() {
			incrementErrorRateLimitBlock(opts.Engine, *effectiveProtection, errorRateLimitKey)

			actType := action.Normalize(result.Action.Type)
			actStr := string(actType)
			if result.Action.IsDrop() && !dropEnabled(opts.Engine) {
				result.Action.Type = action.Intercept
				actType = action.Intercept
				actStr = string(actType)
			}
			if secLog.Enabled(ctx, slog.LevelDebug) {
				secLog.Debug("terminal WAF action selected",
					slog.String("request_id", reqID),
					slog.String("action", actStr),
					slog.String("phase", result.Action.Phase),
					slog.Int("configured_status", result.Action.StatusCode),
					slog.Int("effective_status", result.Action.ResponseStatusCode()),
				)
			}

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
				// drop 记录无条件按 drop 口径落库。协议级终止失败时也
				// 绝不再回写 403/502 拦截页：那等于把已经判定的 drop 降级
				// 成客户端可读的普通响应，且会污染审计口径。
				//
				// 守卫对所有相位无条件构造。此前只在 cve_detection /
				// owasp_default 构造，其余相位（bot_detection、rate_limit、
				// acl、signature 等）拿到 nil 守卫后走的是「伪成功」分支：
				// 既不关连接也不写响应，客户端收到 200 空响应且 keep-alive
				// 继续可用，drop 语义完全失效。构造本身是零反射的，热路径
				// 成本可忽略（见 NewInboundProtocolGuard 注释）。
				dropGuard := NewInboundProtocolGuard(c)
				dropExec := opts.Engine.DropExecutor()
				dropReason := drop.DropReason{
					Source:    result.Action.Phase,
					RuleID:    result.Action.RuleIDStr,
					Detail:    result.Action.MatchDesc,
					ClientIP:  cipStr,
					Host:      host,
					Path:      path,
					Timestamp: time.Now(),
				}
				if !dropGuard.AbortForDrop(c, dropExec, dropReason) {
					// 没有任何可用的协议级终止通道（通常意味着请求上下文
					// 没有底层连接，如单元测试环境）。记录告警便于定位，
					// 但响应阶段仍不得写入任何拦截内容。
					secLog.Error("drop-abort-unavailable",
						slog.String("request_id", reqID),
						slog.String("rule_id", result.Action.RuleIDStr),
						slog.String("phase", result.Action.Phase),
						slog.String("protocol", dropGuard.ProtocolName()),
					)
				}
				if opts.Writer != nil {
					recordSecurityEvent(c, opts, store.SecurityEvent{
						SiteID:       rt.Site.ID,
						RequestID:    reqID,
						ClientIP:     cipStr,
						Host:         host,
						Path:         path,
						Method:       method,
						UserAgent:    ua,
						RuleID:       result.Action.RuleID,
						RuleIDStr:    result.Action.RuleIDStr,
						Phase:        result.Action.Phase,
						Action:       "drop",
						Category:     result.Action.Category,
						MatchDesc:    result.Action.MatchDesc,
						RuleName:     result.Action.RuleName,
						RuleDesc:     result.Action.RuleDesc,
						MatchScore:   result.Action.MatchScore,
						MatchSnippet: result.Action.MatchSnippet,
						MatchPart:    result.Action.MatchPart,
						Severity:     result.Action.Severity,
						Source:       result.Action.Source,
						CVSSScore:    result.Action.CVSSScore,
						CWEType:      result.Action.CWEType,
						References:   result.Action.References,
						StatusCode:   0,
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
						SiteID:       rt.Site.ID,
						RequestID:    reqID,
						ClientIP:     cipStr,
						Host:         host,
						Path:         path,
						Method:       method,
						UserAgent:    ua,
						RuleID:       result.Action.RuleID,
						RuleIDStr:    result.Action.RuleIDStr,
						Phase:        result.Action.Phase,
						Action:       string(result.Action.Type),
						Category:     result.Action.Category,
						MatchDesc:    result.Action.MatchDesc,
						RuleName:     result.Action.RuleName,
						RuleDesc:     result.Action.RuleDesc,
						MatchScore:   result.Action.MatchScore,
						MatchSnippet: result.Action.MatchSnippet,
						MatchPart:    result.Action.MatchPart,
						Severity:     result.Action.Severity,
						Source:       result.Action.Source,
						CVSSScore:    result.Action.CVSSScore,
						CWEType:      result.Action.CWEType,
						References:   result.Action.References,
						StatusCode:   statusCode,
					})
				}
				// 路由到对应的质询处理器
				// 质询动作覆盖只作用于「泛化 challenge」终态：站点/全局的
				// challenge_action 决定具体渲染哪一页；规则显式选择的
				// captcha/shield/chain 保持原样，不被站点/全局默认值顶替。
				renderAct := actStr
				if actType == action.Challenge {
					if covered := siteChallengeAction(&rt, sn); covered != "" {
						renderAct = covered
					}
				}
				renderChallengeFallback := func() {
					pages.WriteChallengeResponse(c, reqID, result.Site, sn.Protection.ShieldEnableEnvCheck, statusCode, sn.ChallengePage,
						challenge.ChallengeTokenClaims{ClientIP: cipStr, UserAgent: challengeIdentityUA, Host: host, SiteID: rt.Site.ID})
				}
				switch renderAct {
				case string(action.CaptchaChallenge):
					if opts.CaptchaManager != nil {
						captchaType := effectiveCaptchaType(result.Action, &rt, sn)
						binding := challengeSessionBindingForSite(rt.Site.ID, host, bind)
						challenge.WriteCaptchaChallengeResponse(c, reqID, opts.CaptchaManager, captchaType, sn.Protection.ShieldEnableEnvCheck, binding, statusCode, sn.CaptchaPage)
						break
					}
					renderChallengeFallback()
				case string(action.ShieldChallenge):
					if opts.ShieldManager != nil {
						origURL := string(c.Request.URI().RequestURI())
						opts.ShieldManager.WriteShieldChallengeResponse(c, reqID, origURL, requestProtocol(c), challengeSessionBindingForSite(rt.Site.ID, host, bind), statusCode)
						break
					}
					renderChallengeFallback()
				case string(action.ChainChallenge):
					if opts.ChainManager != nil {
						challenge.WriteChainChallengeResponse(c, reqID, opts.ChainManager, challengeSessionBindingForSite(rt.Site.ID, host, bind), statusCode)
						break
					}
					renderChallengeFallback()
				default:
					renderChallengeFallback()
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
						SiteID:       rt.Site.ID,
						RequestID:    reqID,
						ClientIP:     cipStr,
						Host:         host,
						Path:         path,
						Method:       method,
						UserAgent:    ua,
						RuleID:       result.Action.RuleID,
						RuleIDStr:    result.Action.RuleIDStr,
						Phase:        result.Action.Phase,
						Action:       "redirect",
						Category:     result.Action.Category,
						MatchDesc:    result.Action.MatchDesc,
						RuleName:     result.Action.RuleName,
						RuleDesc:     result.Action.RuleDesc,
						MatchScore:   result.Action.MatchScore,
						MatchSnippet: result.Action.MatchSnippet,
						MatchPart:    result.Action.MatchPart,
						Severity:     result.Action.Severity,
						Source:       result.Action.Source,
						CVSSScore:    result.Action.CVSSScore,
						CWEType:      result.Action.CWEType,
						References:   result.Action.References,
						StatusCode:   statusCode,
					})
				}
				c.Redirect(statusCode, []byte(result.Action.RedirectTo))
				scrubResponseHopByHopHeaders(c)
				logAccess(accessLog, reqID, method, path, host, statusCode, "redirect")
				recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: "redirect", CacheState: "bypass", Upstream: result.Action.RedirectTo, TLSFingerprint: reqCtx.TLS})
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
					SiteID:       rt.Site.ID,
					RequestID:    reqID,
					ClientIP:     cipStr,
					Host:         host,
					Path:         path,
					Method:       method,
					UserAgent:    ua,
					RuleID:       result.Action.RuleID,
					RuleIDStr:    result.Action.RuleIDStr,
					Phase:        result.Action.Phase,
					Action:       actStr,
					Category:     result.Action.Category,
					MatchDesc:    result.Action.MatchDesc,
					RuleName:     result.Action.RuleName,
					RuleDesc:     result.Action.RuleDesc,
					MatchScore:   result.Action.MatchScore,
					MatchSnippet: result.Action.MatchSnippet,
					MatchPart:    result.Action.MatchPart,
					Severity:     result.Action.Severity,
					Source:       result.Action.Source,
					CVSSScore:    result.Action.CVSSScore,
					CWEType:      result.Action.CWEType,
					References:   result.Action.References,
					HeaderOrder:  reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }),
					StatusCode:   statusCode,
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
			cookie := challenge.BuildChallengePassCookieWithClaims(challenge.ChallengePassClaims{Host: host, ClientIP: clientIP, UserAgent: challengeIdentityUA, SiteID: rt.Site.ID, Bind: bind}, rt.Site.TLSEnabled, time.Now(), challengePassTTL(sn.Protection))
			c.Response.Header.Add("Set-Cookie", cookie)
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
			c.String(http.StatusBadGateway, "no upstream configured")
			recordAccessLog(c, opts, accessLogInfo{
				SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host,
				Path: path, QueryString: rawQ, Method: method, UserAgent: ua,
				StatusCode: http.StatusBadGateway, WAFAction: "none", CacheState: "bypass",
				HeaderOrder:    reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }),
				TLSFingerprint: reqCtx.TLS,
			})
			return
		}

		// Lua pre 脚本的请求改写在此写回真实请求：管道的其余阶段已经看到改写后的
		// 请求，代理与日志同样应当看到同一份视图。与 JS 请求改写共用 applyJSMutationPlan，
		// 两条路径的校验与写回语义完全一致；失败时放弃改写而不是中断请求（脚本笔误
		// 不应让站点不可用）。
		if luaMutation, ok := reqCtx.DrainRequestMutation(); ok {
			plan := pipelineMutationToJSPlan(luaMutation)
			if _, err := applyJSMutationPlan(c, reqCtx, jsRequestState{
				method:      method,
				path:        path,
				rawQuery:    rawQ,
				userAgent:   ua,
				contentType: contentType,
			}, plan); err != nil {
				secLog.Warn("lua request mutation could not be applied",
					slog.String("request_id", reqID),
					slog.String("error", err.Error()))
			} else {
				method = reqCtx.Method
				path = reqCtx.Path
				rawQ = reqCtx.RawQuery
				ua = reqCtx.UserAgent
				contentType = reqCtx.ContentType
				body = reqCtx.Body
			}
		}

		// 客户端请求体流在请求体快照被完整预取之前就提前结束的话，放弃
		// 代理。这样可避免在客户已关闭连接（或发来 HTTP/2 RST_STREAM）、
		// 而 WAF 请求体预取仍在读取时，就向上游发起请求。
		if c.Request.IsBodyStream() {
			if err := requestBodySnapshotError(c); err != nil && !errors.Is(err, io.EOF) {
				if secLog.Enabled(ctx, slog.LevelDebug) {
					secLog.Debug("aborting upstream proxy due to client body read error",
						slog.String("request_id", reqID),
						slog.String("error", err.Error()),
					)
				}
				recordAccessLog(c, opts, accessLogInfo{
					SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host,
					Path: path, QueryString: rawQ, Method: method, UserAgent: ua,
					StatusCode: 0, WAFAction: "none", CacheState: "bypass", ForceRecord: true,
					HeaderOrder:    reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }),
					TLSFingerprint: reqCtx.TLS,
				})
				return
			}
		}

		base, ok := pickUpstream(result.Site.UpstreamURLs, opts.Upstreams, func(n uint32) uint32 {
			return (rr.Add(1) - 1) % n
		})
		if !ok {
			c.String(http.StatusBadGateway, "no upstream configured")
			recordAccessLog(c, opts, accessLogInfo{
				SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host,
				Path: path, QueryString: rawQ, Method: method, UserAgent: ua,
				StatusCode: http.StatusBadGateway, WAFAction: "none", CacheState: "bypass",
				HeaderOrder:    reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }),
				TLSFingerprint: reqCtx.TLS,
			})
			return
		}

		var upstreamErr error
		var bufferedResp *proxy.HTTPResponse
		cacheState := "bypass"
		upstreamStart := time.Now()
		recordResponseBody := shouldRecordAppRouteResponseBody(result.Site)
		// 扩展 CONNECT 桥接（RFC 8441）在进入 switch 前注册入站流端点；
		// 本函数对非扩展 CONNECT 请求为空操作。
		registerH2WSInboundStream(c)
		switch {
		case IsH2ExtendedWebSocketConnect(c):
			// RFC 8441 扩展 CONNECT（CONNECT + :protocol 伪头）：
			// h2c 上游走帧层直通，其余走 h1 握手桥。
			upstreamErr = ForwardH2ExtendedConnectWebSocket(ctx, reqID, c, *result.Site, base, clientIP, opts.Engine)
		case IsWebSocketUpgrade(c):
			upstreamErr = ForwardWebSocket(ctx, reqID, c, *result.Site, base, clientIP, opts.Engine)
		case IsSSERequest(c):
			upstreamErr = ForwardSSE(ctx, c, *result.Site, base, clientIP, host)
		case recordResponseBody:
			// 解码后的缓冲上限与动态保护变换所用的一致，使压缩过的
			// 上游响应体无法撑出无限内存增长。超限的响应保留一段
			// 可读的剩余内容，不做变换直接流式转发。
			bufferedResp, upstreamErr = proxy.FetchHTTPForAppRouteCapture(ctx, c, *result.Site, base, clientIP, host)
			if upstreamErr == nil {
				upstreamErr = proxy.ForwardCapturedResponseForSiteWithClientIP(ctx, c, bufferedResp, *result.Site, clientIP)
			}
		default:
			cacheKey, ttl, staleIfError := "", int64(0), int64(0)
			if opts.ResponseCache != nil {
				cacheKey, ttl, staleIfError = proxy.SiteCacheEligibleWithStale(*result.Site, c)
			}
			if cacheKey == "" || hasConditionalOrRangeHeaders(c) {
				if isInternalHTTP3Request(c) && !c.Request.IsBodyStream() {
					upstreamErr = proxy.ForwardHTTPPreserveRequestBodyOnCancel(ctx, c, *result.Site, base, clientIP, host)
				} else {
					upstreamErr = proxy.ForwardHTTP(ctx, c, *result.Site, base, clientIP, host)
				}
				break
			}
			// 只记录开始回源时的 generation；真正回退到 stale 响应时必须
			// 再次按同一代读取。并发的 unsafe 请求或配置清理可能在等待填充
			// 期间使旧条目失效，不能把此前拿到的指针继续回放。
			staleGeneration := opts.ResponseCache.Generation()
			staleEntry := opts.ResponseCache.LookupStaleIfGeneration(staleGeneration, cacheKey, staleIfError)
			// Get 会在发现过期条目时将其删除；已经捕获到 stale 条目时
			// 保留它到回源失败分支，再由 generation 重查决定是否可回放。
			if staleEntry == nil {
				if entry := opts.ResponseCache.Get(cacheKey); entry != nil {
					proxy.WriteCachedResponseForSiteWithClientIP(c, method, entry, *result.Site, clientIP)
					cacheState = "hit"
					break
				}
			}
			cacheState = "miss"
			leader, releaseFill, fillErr := opts.ResponseCache.BeginFill(ctx, cacheKey)
			if fillErr != nil {
				upstreamErr = fillErr
				break
			}
			if leader {
				defer releaseFill()
			} else {
				// 等待 leader 后只查新鲜条目。不能调用 Get：它会删除
				// 过期备份，导致 leader 的 stale-if-error 回退失效。
				if entry := opts.ResponseCache.LookupFreshIfGeneration(opts.ResponseCache.Generation(), cacheKey); entry != nil {
					proxy.WriteCachedResponseForSiteWithClientIP(c, method, entry, *result.Site, clientIP)
					cacheState = "hit"
					break
				}
			}
			cacheGeneration := opts.ResponseCache.Generation()
			// 必须赋值给外层 bufferedResp：switch 之后的 tryRecordAppRouteResource
			// 依赖它取上游原始响应头；用 := 会遮蔽外层变量，使该记录退化为本进程响应头。
			var err error
			bufferedResp, err = proxy.FetchHTTPForCache(ctx, c, *result.Site, base, clientIP, host, opts.ResponseCache.MaxEntryBodySize())
			if err != nil {
				// 重新检查 generation，避免缓存清理/unsafe 失效发生在
				// BeginFill 等待或上游请求期间后仍然回放旧内容。
				if staleEntry := opts.ResponseCache.LookupStaleIfGeneration(staleGeneration, cacheKey, staleIfError); staleEntry != nil {
					proxy.WriteCachedResponseForSiteWithClientIP(c, method, staleEntry, *result.Site, clientIP)
					cacheState = "stale"
					break
				}
				upstreamErr = err
				break
			}
			if bufferedResp.HasRemainingBody() {
				upstreamErr = proxy.ForwardCapturedResponseForSiteWithClientIP(ctx, c, bufferedResp, *result.Site, clientIP)
				break
			}
			if proxy.ShouldCacheHTTPResponse(method, bufferedResp) {
				cacheTTL := proxy.EffectiveCacheTTL(ttl, bufferedResp)
				if cacheTTL > 0 {
					opts.ResponseCache.SetForSiteIfGeneration(cacheGeneration, rt.Site.ID, proxy.RuleMatchKey(c), cacheKey, bufferedResp.StatusCode, bufferedResp.ContentType, bufferedResp.Body, cacheTTL, proxy.SanitizeHeadersForEdgeCache(bufferedResp.Header))
				}
			}
			proxy.ForwardBufferedResponseForSiteWithClientIP(c, bufferedResp, *result.Site, clientIP)
		}
		upstreamLatencyMs := time.Since(upstreamStart).Milliseconds()
		responseSize := int64(0)
		if opts.Upstreams != nil {
			opts.Upstreams.Mark(base, upstreamErr)
		}

		// 任何已发出的非安全方法都可能在上游产生副作用，即使上游返回
		// 4xx/5xx 或连接中途失败；按路径清理缓存，避免继续提供旧内容。
		if opts.ResponseCache != nil && isUnsafeRequestMethod(method) {
			opts.ResponseCache.PurgeSiteTarget(rt.Site.ID, proxy.RuleMatchKey(c))
		}
		if upstreamErr != nil {
			errCode := 502
			if isTimeoutError(upstreamErr) {
				errCode = 504
			}
			pages.WriteErrorPage(ctx, c, errCode, siteErrorPage(result.Site, errCode))
		} else if !IsWebSocketUpgrade(c) && !IsSSERequest(c) {
			if proxytransport.ResponseSizeUnknown(c) {
				responseSize = 0
			} else if c.Response.IsBodyStream() || c.Response.GetHijackWriter() != nil {
				if c.Response.Header.Get("Trailer") == "" {
					if cl := int64(c.Response.Header.ContentLength()); cl > 0 {
						responseSize = cl
					}
				}
			} else {
				// 上游空响应体兜底：上游返回空响应体且状态码非 204/304 时，
				// 渲染一个友好的错误页。
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

		incrementErrorRateLimitStatus(opts.Engine, *effectiveProtection, errorRateLimitKey, statusCode)

		wafAction := "none"
		if len(result.ObserveHits) > 0 {
			wafAction = "observe"
		}
		logAccess(accessLog, reqID, method, path, host, statusCode, wafAction)
		if !isClientGoneForPlainAccessLog(ctx, wafAction) {
			recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: wafAction, CacheState: cacheState, Upstream: base, UpstreamLatencyMs: upstreamLatencyMs, ResponseSize: responseSize, ResponseSizeKnown: true, HeaderOrder: reqCtx.DerivedHeaderOrder(func() string { return strings.Join(reqCtx.HeaderKeys, ",") }), TLSFingerprint: reqCtx.TLS, VisitorFusionEligible: rt.Site.TLSEnabled, VisitorFusionAction: result.Action, VisitorFusionBotScore: reqCtx.BotScoreResult})
		}
		var upstreamHeader http.Header
		if bufferedResp != nil {
			upstreamHeader = bufferedResp.Header
		}
		tryRecordAppRouteResource(c, opts, &rt, sn, reqCtx, clientIP, statusCode, false, bufferedResponseBody(bufferedResp), upstreamHeader)
	}
}
