package dataplane

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
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
	RecordedResourceRepo  *repository.RecordedResourceRepo
	Upstreams             *upstream.Pool
	AccessLogSamplingRate uint32
}

const (
	bindContextKey           = "dataplane_bind"
	tlsFingerprintContextKey = "dataplane_tls_fingerprint"
)

type tlsFingerprintContextValueKey struct{}

type tlsFingerprintConnKey struct {
	Local  string
	Remote string
}

var tlsFingerprintConns sync.Map

func RememberTLSFingerprintConn(conn net.Conn, fp bot.TLSClientFingerprint) {
	if !fp.HasValue() || conn == nil || conn.LocalAddr() == nil || conn.RemoteAddr() == nil {
		return
	}
	tlsFingerprintConns.Store(tlsFingerprintConnKey{Local: conn.LocalAddr().String(), Remote: conn.RemoteAddr().String()}, fp)
}

func takeTLSFingerprintConn(conn net.Conn) (bot.TLSClientFingerprint, bool) {
	if conn == nil || conn.LocalAddr() == nil || conn.RemoteAddr() == nil {
		return bot.TLSClientFingerprint{}, false
	}
	key := tlsFingerprintConnKey{Local: conn.LocalAddr().String(), Remote: conn.RemoteAddr().String()}
	if value, ok := tlsFingerprintConns.LoadAndDelete(key); ok {
		fp, ok := value.(bot.TLSClientFingerprint)
		return fp, ok && fp.HasValue()
	}
	return bot.TLSClientFingerprint{}, false
}

func ContextWithTLSFingerprint(ctx context.Context, fp bot.TLSClientFingerprint) context.Context {
	if !fp.HasValue() {
		return ctx
	}
	return context.WithValue(ctx, tlsFingerprintContextValueKey{}, fp)
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
	for _, key := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
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
		if fp, ok := tlsFingerprintFromContext(ctx); ok {
			c.Set(tlsFingerprintContextKey, fp)
		}
		// WASM PoW assets must be checked before the generic static handler
		// because serveOWAFStatic returns true (with 404) for unknown /__owaf/ paths.
		if handleWASMAssets(c) {
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

		host := string(c.Host())
		bind := listenerBind(c)
		if bind == "" {
			bind = opts.Bind
		}
		rt, ok := sn.MatchSite(bind, host)
		if !ok {
			opts.Log.Warn("no site match",
				slog.String("host", host),
				slog.String("bind", bind),
				slog.Int("sites", len(sn.Sites)),
			)
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
							antiReplayAct := rt.AntiReplayAction
							if antiReplayAct == "" || antiReplayAct == "shield_challenge" {
								antiReplayAct = "challenge"
							}
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
							if action.Type(antiReplayAct) == action.Challenge {
								pages.WriteChallengeResponse(c, reqID, &rt, 403)
							} else {
								pages.WriteBlockResponse(c, reqID, &rt, sn, challengeResult)
							}
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
		tlsFingerprint, _ := tlsFingerprintFromRequestContext(c)
		reqCtx.TLS = tlsFingerprint
		c.Request.Header.VisitAll(func(k, v []byte) {
			key := string(k)
			reqCtx.Headers[key] = string(v)
			reqCtx.HeaderKeys = append(reqCtx.HeaderKeys, key)
		})

		const maxWAFBody = 48 * 1024
		if body := c.Request.Body(); len(body) > 0 {
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
			if reqCtx.TLS.TLSVersion != "" && !strings.Contains(bsi.Details, "tls_version") {
				var details map[string]any
				if err := json.Unmarshal([]byte(bsi.Details), &details); err == nil {
					details["tls_version"] = reqCtx.TLS.TLSVersion
					if reqCtx.TLS.SNI != "" {
						details["tls_sni"] = reqCtx.TLS.SNI
					}
					if len(reqCtx.TLS.ALPN) > 0 {
						details["tls_alpn"] = reqCtx.TLS.ALPN
					}
					if encoded, err := json.Marshal(details); err == nil {
						bsi.Details = string(encoded)
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
				secLog.Warn("drop",
					slog.String("request_id", reqID),
					slog.String("rule_id", result.Action.RuleIDStr),
					slog.Uint64("rule_id_num", uint64(result.Action.RuleID)),
					slog.String("phase", result.Action.Phase),
					slog.String("action", "drop"),
					slog.String("match", result.Action.MatchDesc),
					slog.String("category", result.Action.Category),
				)
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
					opts.ShieldManager.WriteShieldChallengeResponse(c, reqID, origURL, statusCode)
				case result.Action.IsChainChallenge() && sn.Protection.ChainEnabled && opts.ChainManager != nil:
					challenge.WriteChainChallengeResponse(c, reqID, opts.ChainManager, statusCode)
				default:
					pages.WriteChallengeResponse(c, reqID, result.Site, statusCode)
				}
				logAccess(accessLog, reqID, method, path, host, statusCode, "challenge")
				scrubResponseHopByHopHeaders(c)
				recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: path, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: "challenge", CacheState: "bypass"})
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
			return
		}

		if result.Site == nil || len(result.Site.UpstreamURLs) == 0 {
			c.String(502, "no upstream configured")
			return
		}

		base, ok := pickUpstream(result.Site.UpstreamURLs, opts.Upstreams, func(n uint32) uint32 {
			return (rr.Add(1) - 1) % n
		})
		if !ok {
			c.String(502, "no upstream configured")
			return
		}

		var upstreamErr error
		cacheState := "bypass"
		upstreamStart := time.Now()
		switch {
		case IsWebSocketUpgrade(c):
			upstreamErr = ForwardWebSocket(c, *result.Site, base, clientIP, opts.Engine)
		case IsSSERequest(c):
			upstreamErr = ForwardSSE(ctx, c, *result.Site, base, clientIP, host)
		default:
			cacheKey, ttl, ignoreUpstreamCC := "", int64(0), false
			if opts.ResponseCache != nil {
				cacheKey, ttl, ignoreUpstreamCC = proxy.SiteCacheEligible(*result.Site, c)
			}
			if cacheKey == "" {
				upstreamErr = proxy.ForwardHTTP(ctx, c, *result.Site, base, clientIP, host)
				break
			}
			if entry := opts.ResponseCache.Get(cacheKey); entry != nil {
				proxy.WriteCachedResponse(c, method, entry)
				cacheState = "hit"
				break
			}
			cacheState = "miss"
			bufferedResp, err := proxy.FetchHTTP(ctx, c, *result.Site, base, clientIP, host)
			if err != nil {
				upstreamErr = err
				break
			}
			if proxy.ShouldCacheHTTPResponse(method, bufferedResp, ignoreUpstreamCC) {
				opts.ResponseCache.Set(cacheKey, bufferedResp.StatusCode, bufferedResp.ContentType, bufferedResp.Body, ttl, proxy.SanitizeHeadersForEdgeCache(bufferedResp.Header))
			}
			proxy.ForwardBufferedResponse(c, bufferedResp)
		}
		upstreamLatencyMs := time.Since(upstreamStart).Milliseconds()
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
			// Upstream empty body fallback: if upstream returns empty body
			// with a non-204/304 status, render a friendly error page.
			respStatus := c.Response.StatusCode()
			respBodyLen := len(c.Response.Body())
			if respBodyLen == 0 && respStatus >= 400 && respStatus != 404 {
				pages.WriteErrorPage(ctx, c, respStatus, siteErrorPage(result.Site, respStatus))
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
		recordAccessLog(c, opts, accessLogInfo{SiteID: rt.Site.ID, RequestID: reqID, ClientIP: cipStr, Host: host, Path: aPath, QueryString: rawQ, Method: method, UserAgent: ua, StatusCode: statusCode, WAFAction: wafAction, CacheState: cacheState, Upstream: base, UpstreamLatencyMs: upstreamLatencyMs, ResponseSize: int64(len(c.Response.Body()))})

		// Async application route resource recording.
		// IMPORTANT: Copy all fields from RequestContext BEFORE launching goroutine
		// because Hertz recycles the context after handler returns.
		if upstreamErr == nil && len(rt.AppRouteRules) > 0 && opts.RecordedResourceRepo != nil {
			mat := &appresource.Material{
				Method:      method,
				Host:        host,
				Path:        path,
				ClientIP:    cipStr,
				StatusCode:  statusCode,
				ContentType: string(c.Response.Header.ContentType()),
				UserAgent:   ua,
			}
			// Copy headers needed by rule matching before goroutine
			headerSnapshot := make(map[string]string)
			c.Request.Header.VisitAll(func(key, value []byte) {
				headerSnapshot[string(key)] = string(value)
			})
			go recordAppRouteResourceSafe(opts.RecordedResourceRepo, rt, mat, headerSnapshot)
		}
	}
}

func pickUpstream(urls []string, pool *upstream.Pool, next func(uint32) uint32) (string, bool) {
	if len(urls) == 0 {
		return "", false
	}
	if pool == nil {
		return urls[next(uint32(len(urls)))], true
	}
	return pool.Pick(urls, next)
}

func recordAppRouteResourceSafe(repo *repository.RecordedResourceRepo, rt snapshot.SiteRuntime, m *appresource.Material, headers map[string]string) {
	headerFn := func(key string) string { return headers[key] }
	ids := appresource.MatchedRuleIDs(rt.AppRouteRules, m, headerFn)
	if len(ids) == 0 {
		return
	}
	rec := appresource.BuildRecordedResource(rt.Site.ID, ids, m)
	if rec == nil {
		return
	}
	rec.HitCount = 1
	rec.FirstSeen = time.Now()
	rec.LastSeen = rec.FirstSeen
	_ = repo.Upsert(rec)
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
	TLSFingerprint       bot.TLSClientFingerprint
	HeaderOrder          []string
	UpstreamLatencyMs    int64
	ResponseSize         int64
	RequestHeaders       string
	RequestBodyPreview   string
	RequestBodyTruncated bool
	RequestSize          int64
	ResponseHeaders      string
}

func recordSecurityEvent(c *app.RequestContext, opts Options, ev store.SecurityEvent) {
	if opts.Writer == nil {
		return
	}
	if ev.QueryString == "" {
		ev.QueryString = string(c.URI().QueryString())
	}
	reqBody, truncated, size := requestBodyPreview(c)
	ev.RequestHeaders = valueOrFallback(ev.RequestHeaders, requestHeadersJSON(c))
	ev.RequestBodyPreview = valueOrFallback(ev.RequestBodyPreview, reqBody)
	ev.RequestBodyTruncated = ev.RequestBodyTruncated || truncated
	ev.RequestSize = firstPositive(ev.RequestSize, size)
	opts.Writer.RecordEvent(ev)
}

type accessLogRecorder interface {
	RecordAccessLog(store.AccessLog)
}

func buildAccessLogEntry(c *app.RequestContext, info accessLogInfo) store.AccessLog {
	if info.HTTPProtocol == "" {
		info.HTTPProtocol = requestProtocol(c)
	}
	if !(info.HTTPProtocol == "h3" && isInternalHTTP3Request(c)) && !info.TLSFingerprint.HasValue() {
		info.TLSFingerprint, _ = tlsFingerprintFromRequestContext(c)
	}
	if len(info.HeaderOrder) == 0 {
		info.HeaderOrder = requestHeaderOrder(c)
	}
	requestBody, requestBodyTruncated, requestSize := requestBodyPreview(c)
	return store.AccessLog{
		SiteID:               info.SiteID,
		RequestID:            info.RequestID,
		ClientIP:             info.ClientIP,
		Host:                 info.Host,
		Path:                 info.Path,
		QueryString:          info.QueryString,
		Method:               info.Method,
		StatusCode:           info.StatusCode,
		WAFAction:            info.WAFAction,
		CacheState:           info.CacheState,
		Upstream:             info.Upstream,
		UserAgent:            info.UserAgent,
		RequestHeaders:       valueOrFallback(info.RequestHeaders, requestHeadersJSON(c)),
		RequestBodyPreview:   valueOrFallback(info.RequestBodyPreview, requestBody),
		RequestBodyTruncated: info.RequestBodyTruncated || requestBodyTruncated,
		RequestSize:          firstPositive(info.RequestSize, requestSize),
		ResponseHeaders:      info.ResponseHeaders,
		HTTPProtocol:         info.HTTPProtocol,
		TLSVersion:           info.TLSFingerprint.TLSVersion,
		TLSSNI:               info.TLSFingerprint.SNI,
		TLSALPN:              strings.Join(info.TLSFingerprint.ALPN, ","),
		TLSJA3:               info.TLSFingerprint.JA3,
		TLSJA3Hash:           info.TLSFingerprint.JA3Hash,
		TLSJA4:               info.TLSFingerprint.JA4,
		HeaderOrder:          strings.Join(info.HeaderOrder, ","),
		UpstreamLatencyMs:    info.UpstreamLatencyMs,
		ResponseSize:         info.ResponseSize,
	}
}

const logBodyPreviewLimit = 8192

func requestHeadersJSON(c *app.RequestContext) string {
	headers := make(map[string][]string)
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		lower := strings.ToLower(key)
		if lower == "authorization" || lower == "cookie" || lower == "x-api-key" || lower == "x-auth-token" {
			headers[key] = []string{"[redacted]"}
			return
		}
		headers[key] = append(headers[key], string(v))
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
	return string(body), truncated, size
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
	if fp, ok := takeTLSFingerprintConn(c.GetConn()); ok {
		c.Set(tlsFingerprintContextKey, fp)
		return fp, true
	}
	return bot.TLSFingerprintFromConn(c.GetConn())
}

func enqueueAccessLog(writer accessLogRecorder, al store.AccessLog) {
	writer.RecordAccessLog(al)
}

func recordAccessLog(c *app.RequestContext, opts Options, info accessLogInfo) {
	if opts.Writer == nil || !shouldRecordAccessLog(info, opts.AccessLogSamplingRate) {
		return
	}
	enqueueAccessLog(opts.Writer, buildAccessLogEntry(c, info))
}

func shouldRecordAccessLog(info accessLogInfo, rate uint32) bool {
	if info.WAFAction != "none" || info.StatusCode >= 400 || rate <= 1 {
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
	return strings.TrimSpace(string(c.GetHeader("X-OpenWaf-Internal-Proto"))) == "h3" && strings.TrimSpace(string(c.GetHeader("X-Forwarded-Proto"))) == "h3"
}

func requestProtocol(c *app.RequestContext) string {
	if fp, ok := tlsFingerprintFromRequestContext(c); ok && fp.HasValue() {
		if isInternalHTTP3Request(c) {
			return "h3"
		}
		return "https"
	}
	if fp, ok := bot.TLSFingerprintFromConn(c.GetConn()); ok && fp.HasValue() {
		if isInternalHTTP3Request(c) {
			return "h3"
		}
		return "https"
	}
	if isInternalHTTP3Request(c) {
		return "h3"
	}
	if proto := strings.TrimSpace(string(c.GetHeader("X-Forwarded-Proto"))); proto != "" {
		return strings.ToLower(proto)
	}
	return "http"
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

	passed, originalURL := opts.ShieldManager.VerifyChallenge(sessionID, captchaAnswer, counter, hash, envFP)
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
