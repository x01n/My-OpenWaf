package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
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
	RecordedResourceRepo  *repository.RecordedResourceRepo
	Upstreams             *upstream.Pool
	AccessLogSamplingRate uint32
}

const (
	bindContextKey           = "dataplane_bind"
	tlsFingerprintContextKey = "dataplane_tls_fingerprint"
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

// Handler returns a Hertz middleware: maintenance → WAF → block fuse or reverse proxy.
func Handler(opts Options) app.HandlerFunc {
	var rr atomic.Uint32
	secLog := opts.Log.With(slog.String("section", "security"))
	accessLog := opts.Log
	staticFS, _ := adminweb.ResolveFS("")

	return func(ctx context.Context, c *app.RequestContext) {
		ctx, closeNotifyCancel := bindStreamCloseNotifyContext(ctx, c)
		defer func() {
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

		clientIP := security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR)
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

		if ipRep := opts.Engine.IPReputation(); ipRep != nil && clientIP != nil {
			decision := ipRep.Check(clientIP)
			if decision.Matched && !decision.Allowed {
				if opts.Metrics != nil {
					opts.Metrics.RecordWAFBlock()
					opts.Metrics.RecordAttackIP(cipStr)
				}

				// Determine action: "block" → TCP RST (drop), default → HTTP 403 (intercept)
				ipAction := decision.Action
				if ipAction == "" {
					ipAction = "intercept"
				}
				useDropAction := ipAction == "block" && dropEnabled(opts.Engine)

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

		if method == "POST" {
			challengeTS := string(c.FormValue("__waf_challenge_ts"))
			challengeToken := string(c.FormValue("__waf_challenge_token"))
			challengeRID := string(c.FormValue("__waf_challenge_rid"))
			if challengeTS != "" && challengeToken != "" && challengeRID != "" {
				if challenge.VerifyChallengeToken(challengeRID, challengeTS, challengeToken, 5*time.Minute) {
					cookie := challenge.BuildChallengePassCookieWithClaims(challenge.ChallengePassClaims{Host: host, ClientIP: clientIP, UserAgent: ua, SiteID: rt.Site.ID, Bind: bind}, rt.Site.TLSEnabled, time.Now(), challengePassTTL(sn.Protection))
					c.Response.Header.Set("Set-Cookie", cookie)
					referer := string(c.GetHeader("Referer"))
					if referer == "" {
						referer = "/"
					}
					c.Redirect(302, []byte(referer))
					accessLog.Info("challenge_passed",
						slog.String("request_id", reqID),
						slog.String("client_ip", cipStr),
					)
					recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: pathCached, Method: method, UserAgent: ua, StatusCode: 302, WAFAction: "challenge_passed", CacheState: "bypass", Upstream: referer})
					return
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
			lp := strings.ToLower(path)
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

		lowerPath := strings.ToLower(path)
		if strings.Contains(lowerPath, "/translation-table") && (strings.Contains(lowerPath, "+cscot+") || strings.Contains(lowerPath, "+cscoe+") || strings.Contains(lowerPath, "%2bcscot%2b") || strings.Contains(lowerPath, "%2bcscoe%2b")) {
			blockAction := action.Result{Type: action.Intercept, Phase: "owasp_default", RuleIDStr: "owasp:path:015", MatchDesc: "Cisco translation-table path traversal pattern", Matched: true, Category: string(owasp.CatPathTrav)}
			pages.WriteBlockResponse(c, reqID, &rt, sn, blockAction)
			logAccess(accessLog, reqID, method, path, host, 403, "intercept")
			recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: 403, WAFAction: "intercept", CacheState: "bypass"})
			return
		}

		contentType := strings.ToLower(strings.TrimSpace(string(c.Request.Header.ContentType())))
		if strings.EqualFold(path, "/uc/feedback/api/v1/pc/feedback/add") && contentType == "" {
			body := c.Request.Body()
			if len(body) == 0 {
				body = c.Request.BodyBytes()
			}
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
		reqCtx.RequestID = reqID
		reqCtx.Bind = bind
		reqCtx.ClientIP = clientIP
		reqCtx.Method = method
		reqCtx.Path = path
		reqCtx.RawQuery = rawQ
		reqCtx.Host = host
		reqCtx.UserAgent = ua
		reqCtx.SiteID = rt.Site.ID
		tlsFingerprint, ok := tlsFingerprintFromRequestContext(c)
		if !ok {
			tlsFingerprint, _ = tlsFingerprintFromContext(ctx)
		}
		reqCtx.TLS = tlsFingerprint
		c.Request.Header.VisitAll(func(k, v []byte) {
			key := string(k)
			value := string(v)
			reqCtx.Headers[key] = value
			if lower := strings.ToLower(key); lower != key {
				reqCtx.Headers[lower] = value
			}
			reqCtx.HeaderKeys = append(reqCtx.HeaderKeys, key)
		})

		const maxWAFBody = 48 * 1024
		body, _, _ := requestBodySample(c)
		if len(body) > 0 {
			if len(body) > maxWAFBody {
				reqCtx.Body = body[:maxWAFBody]
			} else {
				reqCtx.Body = body
			}
			reqCtx.ContentType = string(c.Request.Header.ContentType())
		}

		defer pipeline.ReleaseCtx(reqCtx)

		var result engine.ProcessResult
		if shouldApplyErrorRateLimit(opts.Engine, sn.Protection, errorRateLimitKey) {
			result = engine.ProcessResult{Site: &rt, Action: errorRateLimitAction(sn.Protection.ErrorRateLimitAction)}
		} else {
			result = opts.Engine.Process(reqCtx)
		}

		// Bot score logging via buffered writer.
		if reqCtx.BotScoreResult != nil && opts.Writer != nil {
			bsi := reqCtx.BotScoreResult
			if bsi.Details != "" {
				var details map[string]any
				if err := json.Unmarshal([]byte(bsi.Details), &details); err == nil {
					changed := false
					if reqCtx.TLS.TLSVersion != "" {
						if _, ok := details["tls_version"]; !ok {
							details["tls_version"] = reqCtx.TLS.TLSVersion
							changed = true
						}
					}
					if reqCtx.TLS.SNI != "" {
						if _, ok := details["tls_sni"]; !ok {
							details["tls_sni"] = reqCtx.TLS.SNI
							changed = true
						}
					}
					if len(reqCtx.TLS.ALPN) > 0 {
						if _, ok := details["tls_alpn"]; !ok {
							details["tls_alpn"] = strings.Join(reqCtx.TLS.ALPN, ",")
							changed = true
						}
					}
					if changed {
						if encoded, err := json.Marshal(details); err == nil {
							bsi.Details = string(encoded)
						}
					}
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
				TLSALPN:          strings.Join(reqCtx.TLS.ALPN, ","),
				HeaderOrder:      strings.Join(reqCtx.HeaderKeys, ","),
				TotalScore:       bsi.TotalScore,
				GeoIPScore:       bsi.GeoIPScore,
				FingerprintScore: bsi.FingerprintScore,
				BehaviorScore:    bsi.BehaviorScore,
				IPRepScore:       bsi.IPRepScore,
				IsHighRisk:       bsi.IsHighRisk,
				Action:           bsi.Action,
				Details:          bsi.Details,
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
			recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: accessStatusCode(c, "maintenance"), WAFAction: "maintenance", CacheState: "bypass"})
			return
		}

		if result.Action.IsTerminal() {
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
				recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: pathCached, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: 0, WAFAction: "drop", CacheState: "bypass"})
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
					challenge.WriteCaptchaChallengeResponse(c, reqID, opts.CaptchaManager, captchaType, statusCode)
				case result.Action.IsShieldChallenge() && sn.Protection.ShieldEnabled && opts.ShieldManager != nil:
					origURL := string(c.Request.URI().RequestURI())
					proto := inboundProto(c, rt.Site.TLSEnabled)
					opts.ShieldManager.WriteShieldChallengeResponse(c, reqID, origURL, proto, statusCode)
				case result.Action.IsChainChallenge() && sn.Protection.ChainEnabled && opts.ChainManager != nil:
					challenge.WriteChainChallengeResponse(c, reqID, opts.ChainManager, statusCode)
				default:
					pages.WriteChallengeResponse(c, reqID, result.Site, statusCode)
				}
				logAccess(accessLog, reqID, method, path, host, statusCode, actStr)
				scrubResponseHopByHopHeaders(c)
				recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: actStr, CacheState: "bypass"})
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
				recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: "redirect", CacheState: "bypass", Upstream: result.Action.RedirectTo})
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
					ClientIP:   clientIPStr(clientIP),
					Host:       host,
					Path:       path,
					Method:     string(c.Method()),
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
			pages.WriteBlockResponse(c, reqID, result.Site, sn, result.Action)
			scrubResponseHopByHopHeaders(c)
			logAccess(accessLog, reqID, method, path, host, statusCode, actStr)
			recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: actStr, CacheState: "bypass"})
			tryRecordAppRouteResource(c, opts, &rt, sn, reqCtx, method, host, path, rawQ, cipStr, ua, statusCode, true, nil)
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
			upstreamErr = ForwardWebSocket(c, *result.Site, base, clientIP, opts.Engine)
		case IsSSERequest(c):
			upstreamErr = ForwardSSE(ctx, c, *result.Site, base, clientIP, host)
		case recordResponseBody:
			bufferedResp, upstreamErr = proxy.FetchHTTP(ctx, c, *result.Site, base, clientIP, host)
			if upstreamErr == nil {
				proxy.ForwardBufferedResponse(c, bufferedResp)
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
				proxy.WriteCachedResponseForSite(c, method, entry, *result.Site)
				cacheState = "hit"
				break
			}
			cacheState = "miss"
			bufferedResp, err := proxy.FetchHTTP(ctx, c, *result.Site, base, clientIP, host)
			if err != nil {
				if staleEntry != nil {
					proxy.WriteCachedResponseForSite(c, method, staleEntry, *result.Site)
					cacheState = "stale"
					break
				}
				upstreamErr = err
				break
			}
			if int64(len(bufferedResp.Body)) > opts.ResponseCache.MaxEntryBodySize() {
				proxy.ForwardBufferedResponseAsStream(c, bufferedResp)
				break
			}
			if proxy.ShouldCacheHTTPResponse(method, bufferedResp, ignoreUpstreamCC) {
				opts.ResponseCache.Set(cacheKey, bufferedResp.StatusCode, bufferedResp.ContentType, bufferedResp.Body, ttl, proxy.SanitizeHeadersForEdgeCache(bufferedResp.Header))
			}
			proxy.ForwardBufferedResponseForSite(c, bufferedResp, *result.Site)
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
		aPath := accessPath(c)
		logAccess(accessLog, reqID, method, aPath, host, statusCode, wafAction)
		recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: aPath, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: wafAction, CacheState: cacheState, Upstream: base, UpstreamLatencyMs: upstreamLatencyMs, ResponseSize: responseSize, ResponseSizeKnown: true})

		// Async application route resource recording.
		// Match rules before launching the goroutine so unmatched requests avoid
		// map copies and background DB work on the hot path.
		// Skip recording if the request contains any excluded header.
		tryRecordAppRouteResource(c, opts, &rt, sn, reqCtx, method, host, path, rawQ, cipStr, ua, statusCode, false, bufferedResponseBody(bufferedResp))
	}
}

func pickUpstream(urls []string, pool *upstream.Pool, next func(uint32) uint32) (string, bool) {
	return upstream.PickByProtocolPreference(urls, pool, next)
}

func tryRecordAppRouteResource(c *app.RequestContext, opts Options, rt *snapshot.SiteRuntime, sn *snapshot.Snapshot, reqCtx *pipeline.RequestCtx, method, host, path, rawQ, cipStr, ua string, statusCode int, isLocalResponse bool, responseBody []byte) {
	if opts.RecordedResourceRepo == nil || hasExcludedHeader(c, sn.ExcludeRecordHeaders) {
		return
	}
	reqBody := string(c.Request.Body())
	if len(reqBody) > logBodyPreviewLimit {
		reqBody = reqBody[:logBodyPreviewLimit]
	}
	respBody := string(responseBody)
	if respBody == "" && !c.Response.IsBodyStream() {
		respBody = string(c.Response.Body())
	}
	if len(respBody) > logBodyPreviewLimit {
		respBody = respBody[:logBodyPreviewLimit]
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
	reqCT := strings.ToLower(strings.TrimSpace(string(c.Request.Header.ContentType())))
	matchRespBody := respBody
	if isLocalResponse {
		matchRespBody = ""
	}
	mat := &appresource.Material{
		Method:              method,
		Host:                host,
		Path:                path,
		QueryString:         rawQ,
		ClientIP:            cipStr,
		StatusCode:          statusCode,
		ContentType:         string(c.Response.Header.ContentType()),
		UserAgent:           ua,
		RequestBody:         reqBody,
		ResponseBody:        matchRespBody,
		TLSVersion:          matTLS.TLSVersion,
		TLSSNI:              matTLS.TLSSNI,
		TLSALPN:             matTLS.TLSALPN,
		JA3Hash:             matTLS.JA3Hash,
		JA4:                 matTLS.JA4,
		RequestHeadersJSON:  requestHeadersJSON(c),
		ResponseHeadersJSON: responseHeadersJSON(c),
		RequestBodySnippet:  sanitizeBodyPreview(reqBody, reqCT),
		ResponseBodySnippet: sanitizeBodyPreview(respBody, strings.ToLower(strings.TrimSpace(string(c.Response.Header.ContentType())))),
	}
	var headerFn func(string) string
	if reqCtx != nil {
		headerFn = func(key string) string { return reqCtx.Headers[key] }
	} else {
		headerFn = appresource.RequestHeaderLookup(c)
	}
	ids := appresource.MatchedRuleIDs(rt.AppRouteRules, mat, headerFn)
	if len(ids) > 0 || len(rt.AppRouteRules) == 0 {
		recordMat := *mat
		recordMat.QueryString = sanitizeQueryString(rawQ)
		go recordAppRouteResourceSafe(opts.RecordedResourceRepo, rt.Site.ID, &recordMat, ids)
	}
}

func recordAppRouteResourceSafe(repo *repository.RecordedResourceRepo, siteID uint, m *appresource.Material, ids []uint) {
	rec := appresource.BuildRecordedResource(siteID, ids, m)
	if rec == nil {
		return
	}
	rec.HitCount = 1
	rec.FirstSeen = time.Now()
	rec.LastSeen = rec.FirstSeen
	_ = repo.Upsert(rec)
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
	HeaderOrder          []string
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
	if len(info.HeaderOrder) == 0 {
		info.HeaderOrder = requestHeaderOrder(c)
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
		HeaderOrder:          strings.Join(info.HeaderOrder, ","),
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

var sensitiveLogValuePattern = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|session|api[_-]?key|auth[_-]?token|csrf|code)(["'\s:=]+)([^&\s,"'}]+)`)

func requestHeadersJSON(c *app.RequestContext) string {
	headers := make(map[string][]string)
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		lower := strings.ToLower(key)
		if isSensitiveLogKey(lower) {
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
		lower := strings.ToLower(key)
		if isSensitiveLogKey(lower) {
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
	body := c.Request.Body()
	size := int64(len(body))
	if len(body) == 0 {
		return "", false, size
	}
	truncated := len(body) > logBodyPreviewLimit
	if truncated {
		body = body[:logBodyPreviewLimit]
	}
	contentType := strings.ToLower(strings.TrimSpace(string(c.Request.Header.ContentType())))
	return sanitizeBodyPreview(string(body), contentType), truncated, size
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

func sanitizeLogText(value string) string {
	return sensitiveLogValuePattern.ReplaceAllString(value, `${1}${2}[redacted]`)
}

func truncateLogValue(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}

func isSensitiveLogKey(key string) bool {
	lower := strings.ToLower(key)
	for _, part := range []string{"authorization", "cookie", "token", "secret", "password", "passwd", "pwd", "session", "api-key", "apikey", "csrf", "credential", "key"} {
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
	return strings.TrimSpace(string(c.GetHeader("X-OpenWaf-Internal-Proto"))) == "h3" &&
		strings.TrimSpace(string(c.GetHeader("X-Forwarded-Proto"))) == "h3"
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
	if proto := strings.TrimSpace(string(c.GetHeader("X-Forwarded-Proto"))); proto != "" {
		return strings.ToLower(proto)
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

func ShouldBlock(res action.Result) bool {
	return res.IsTerminal()
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

func writeAntiReplayActionResponse(c *app.RequestContext, opts Options, sn *snapshot.Snapshot, rt *snapshot.SiteRuntime, reqID, antiReplayAct string, result action.Result, statusCode int) {
	switch action.Type(antiReplayAct) {
	case action.CaptchaChallenge:
		if sn != nil && sn.Protection.CaptchaEnabled && opts.CaptchaManager != nil {
			captchaType := challenge.CaptchaType(sn.Protection.CaptchaType)
			challenge.WriteCaptchaChallengeResponse(c, reqID, opts.CaptchaManager, captchaType, statusCode)
			return
		}
	case action.ShieldChallenge:
		if sn != nil && sn.Protection.ShieldEnabled && opts.ShieldManager != nil {
			origURL := string(c.Request.URI().RequestURI())
			opts.ShieldManager.WriteShieldChallengeResponse(c, reqID, origURL, inboundProto(c, rt.Site.TLSEnabled), statusCode)
			return
		}
	case action.ChainChallenge:
		if sn != nil && sn.Protection.ChainEnabled && opts.ChainManager != nil {
			challenge.WriteChainChallengeResponse(c, reqID, opts.ChainManager, statusCode)
			return
		}
	case action.Challenge:
		pages.WriteChallengeResponse(c, reqID, rt, statusCode)
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

// handleWASMAssets serves the PoW WASM binary and wasm_exec.js glue.
func handleWASMAssets(c *app.RequestContext) bool {
	path := string(c.Path())
	switch path {
	case "/__owaf/pow.wasm":
		challenge.ServePoWWASM(c)
		return true
	case "/__owaf/wasm_exec.js":
		challenge.ServeWasmExecJS(c)
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

	sessionID := string(c.FormValue("__waf_captcha_session"))
	answer := string(c.FormValue("__waf_captcha_answer"))

	if sessionID == "" || answer == "" {
		c.Redirect(302, []byte("/"))
		return true
	}

	if opts.CaptchaManager.VerifyAdvanced(sessionID, answer) {
		setChallengeCookie(c, opts)
		referer := string(c.GetHeader("Referer"))
		if referer == "" {
			referer = "/"
		}
		c.Redirect(302, []byte(referer))
	} else {
		c.Redirect(302, []byte(string(c.GetHeader("Referer"))))
	}
	return true
}

func handleShieldVerify(c *app.RequestContext, opts Options) bool {
	if opts.ShieldManager == nil {
		c.String(503, "shield not configured")
		return true
	}

	sessionID := string(c.FormValue("__waf_shield_session"))
	captchaAnswer := string(c.FormValue("__waf_captcha_answer"))
	counterStr := string(c.FormValue("__waf_pow_counter"))
	hash := string(c.FormValue("__waf_pow_hash"))
	envFP := string(c.FormValue("__waf_env_fp"))

	var counter int64
	if counterStr != "" {
		counter, _ = strconv.ParseInt(counterStr, 10, 64)
	}

	passed, originalURL := opts.ShieldManager.VerifyChallenge(sessionID, captchaAnswer, counter, hash, envFP, requestProtoFromContext(c))
	if passed {
		setChallengeCookie(c, opts)
		if originalURL == "" {
			originalURL = "/"
		}
		c.Redirect(302, []byte(originalURL))
	} else {
		// Re-challenge
		c.Redirect(302, []byte(string(c.GetHeader("Referer"))))
	}
	return true
}

func handleChainVerify(c *app.RequestContext, opts Options) bool {
	if opts.ChainManager == nil {
		c.String(503, "chain challenge not configured")
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

	passed, redirectURL, nextHTML := opts.ChainManager.ProcessStep(sessionID, formData)
	if passed {
		setChallengeCookie(c, opts)
		if redirectURL == "" {
			redirectURL = "/"
		}
		c.Redirect(302, []byte(redirectURL))
	} else if nextHTML != "" {
		c.Data(403, "text/html; charset=utf-8", []byte(nextHTML))
	} else {
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
	clientIP := security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR)
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
