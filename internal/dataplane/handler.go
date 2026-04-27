package dataplane

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/google/uuid"

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
	"My-OpenWaf/internal/waf"
)

// Options configures a single data listener handler.
type Options struct {
	Bind            string
	Holder          *snapshot.Holder
	Engine          *engine.Engine
	Metrics         *Metrics
	EventWriter     *observability.EventWriter
	AccessLogWriter *observability.AccessLogWriter
	DropEventRepo   interface{ Create(item *store.DropEvent) error }
	ResponseCache   *cache.ResponseCache
	Log             *slog.Logger
}

// Handler returns a Hertz middleware: maintenance → WAF → block fuse or reverse proxy.
func Handler(opts Options) app.HandlerFunc {
	var rr atomic.Uint32
	secLog := opts.Log.With(slog.String("section", "security"))
	accessLog := opts.Log
	staticFS, _ := adminweb.ResolveFS("")

	return func(ctx context.Context, c *app.RequestContext) {
		if serveOWAFStatic(c, staticFS) {
			return
		}

		reqID := uuid.NewString()
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
		rt, ok := sn.MatchSite(opts.Bind, host)
		if !ok {
			opts.Log.Warn("no site match",
				slog.String("host", host),
				slog.String("bind", opts.Bind),
				slog.Int("sites", len(sn.Sites)),
			)
			c.String(404, "unknown virtual host")
			return
		}

		clientIP := security.ResolveClientIP(c, rt.XFFMode, rt.TrustedCIDR)
		if clientIP != nil && opts.Metrics != nil {
			opts.Metrics.RecordClientIP(clientIP.String())
		}

		if ipRep := opts.Engine.IPReputation(); ipRep != nil && clientIP != nil {
			decision := ipRep.Check(clientIP)
			if decision.Matched && !decision.Allowed && decision.Category == "blacklist" {
				if opts.Metrics != nil {
					opts.Metrics.RecordWAFBlock()
					opts.Metrics.RecordAttackIP(clientIP.String())
				}
				blockAction := action.Result{
					Type:      action.Drop,
					Phase:     "ip_reputation",
					RuleIDStr: "ip:blacklist",
					MatchDesc: decision.Reason,
					Matched:   true,
					Category:  "blacklist",
				}
				if opts.EventWriter != nil {
					opts.EventWriter.Record(store.SecurityEvent{
						SiteID:     rt.Site.ID,
						RequestID:  reqID,
						ClientIP:   clientIPStr(clientIP),
						Host:       host,
						Path:       string(c.Path()),
						Method:     string(c.Method()),
						UserAgent:  string(c.UserAgent()),
						RuleIDStr:  blockAction.RuleIDStr,
						Phase:      blockAction.Phase,
						Action:     "drop",
						Category:   blockAction.Category,
						MatchDesc:  blockAction.MatchDesc,
						StatusCode: 0,
					})
				}
				logAccess(accessLog, reqID, c, "drop")
				recordAccessLog(opts, rt.Site.ID, reqID, clientIP, c, "drop", "bypass", "")
				recordDropEvent(opts, rt.Site.ID, clientIP, waf.DropReason{
					Source:    "ip_reputation",
					RuleID:    blockAction.RuleIDStr,
					Detail:    blockAction.MatchDesc,
					Host:      host,
					Path:      string(c.Path()),
					Timestamp: time.Now(),
				})
				dropExec := opts.Engine.DropExecutor()
				if dropExec != nil && dropExec.Enabled() {
					dropExec.Execute(c.GetConn(), waf.DropReason{
						Source:    "ip_reputation",
						RuleID:    blockAction.RuleIDStr,
						Detail:    blockAction.MatchDesc,
						ClientIP:  clientIPStr(clientIP),
						Host:      host,
						Path:      string(c.Path()),
						Timestamp: time.Now(),
					})
				} else if conn := c.GetConn(); conn != nil {
					conn.Close()
				}
				return
			}
		}

		if string(c.Method()) == "POST" {
			challengeTS := string(c.FormValue("__waf_challenge_ts"))
			challengeToken := string(c.FormValue("__waf_challenge_token"))
			challengeRID := string(c.FormValue("__waf_challenge_rid"))
			if challengeTS != "" && challengeToken != "" && challengeRID != "" {
				if waf.VerifyChallengeToken(challengeRID, challengeTS, challengeToken, 5*time.Minute) {
					cookie := "__waf_passed=1; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600"
					if rt.Site.TLSEnabled {
						cookie += "; Secure"
					}
					c.Response.Header.Set("Set-Cookie", cookie)
					referer := string(c.GetHeader("Referer"))
					if referer == "" {
						referer = "/"
					}
					c.Redirect(302, []byte(referer))
					accessLog.Info("challenge_passed",
						slog.String("request_id", reqID),
						slog.String("client_ip", clientIPStr(clientIP)),
					)
					recordAccessLog(opts, rt.Site.ID, reqID, clientIP, c, "challenge_passed", "bypass", referer)
					return
				}
			}
		}

		path := string(c.Path())
		if rawPath := c.Request.URI().PathOriginal(); len(rawPath) > 0 {
			path = string(rawPath)
		}
		rawQ := string(c.URI().QueryString())

		lowerPath := strings.ToLower(path)
		if strings.Contains(lowerPath, "/translation-table") && (strings.Contains(lowerPath, "+cscot+") || strings.Contains(lowerPath, "+cscoe+") || strings.Contains(lowerPath, "%2bcscot%2b") || strings.Contains(lowerPath, "%2bcscoe%2b")) {
			blockAction := action.Result{Type: action.Intercept, Phase: "owasp_default", RuleIDStr: "owasp:path:015", MatchDesc: "Cisco translation-table path traversal pattern", Matched: true, Category: string(waf.CatPathTrav)}
			waf.WriteBlockResponse(c, reqID, &rt, sn, blockAction)
			logAccess(accessLog, reqID, c, "intercept")
			recordAccessLog(opts, rt.Site.ID, reqID, clientIP, c, "intercept", "bypass", "")
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
				normalized := waf.NormalizeForDebug(rawBody)
				if waf.IsOpaqueEncodedAttackBodyForDebug(rawBody, normalized, map[string]string{"Host": host}, 3) {
					blockAction := action.Result{Type: action.Intercept, Phase: "owasp_default", RuleIDStr: "owasp:proto:010", MatchDesc: "opaque encoded body without content-type", Matched: true, Category: string(waf.CatProtoViol)}
					waf.WriteBlockResponse(c, reqID, &rt, sn, blockAction)
					logAccess(accessLog, reqID, c, "intercept")
					recordAccessLog(opts, rt.Site.ID, reqID, clientIP, c, "intercept", "bypass", "")
					return
				}
			}
		}

		reqCtx := pipeline.AcquireCtx()
		reqCtx.RequestID = reqID
		reqCtx.Bind = opts.Bind
		reqCtx.ClientIP = clientIP
		reqCtx.Method = string(c.Method())
		reqCtx.Path = path
		reqCtx.RawQuery = rawQ
		reqCtx.Host = host
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

		result := opts.Engine.Process(reqCtx)
		ua := string(c.UserAgent())
		for _, obs := range result.ObserveHits {
			if opts.Metrics != nil {
				opts.Metrics.RecordWAFObserve()
				if obs.Phase == "owasp_default" {
					opts.Metrics.RecordBuiltinHit()
				}
			}
			secLog.Info("observe hit",
				slog.String("request_id", reqID),
				slog.String("rule_id", obs.RuleIDStr),
				slog.Uint64("rule_id_num", uint64(obs.RuleID)),
				slog.String("phase", obs.Phase),
				slog.String("action", "observe"),
				slog.String("match", obs.MatchDesc),
				slog.String("category", obs.Category),
			)
			if opts.EventWriter != nil {
				opts.EventWriter.Record(store.SecurityEvent{
					SiteID:    rt.Site.ID,
					RequestID: reqID,
					ClientIP:  clientIPStr(clientIP),
					Host:      host,
					Path:      path,
					Method:    string(c.Method()),
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
			waf.WriteMaintenanceResponse(c, reqID, result.Site, sn)
			logAccess(accessLog, reqID, c, "maintenance")
			recordAccessLog(opts, rt.Site.ID, reqID, clientIP, c, "maintenance", "bypass", "")
			return
		}

		if result.Action.IsTerminal() {
			actType := action.Normalize(result.Action.Type)
			actStr := string(actType)
			if opts.Metrics != nil {
				opts.Metrics.RecordWAFBlock()
				if clientIP != nil {
					opts.Metrics.RecordAttackIP(clientIP.String())
				}
				if result.Action.Phase == "owasp_default" {
					opts.Metrics.RecordBuiltinHit()
				}
			}

			if result.Action.IsDrop() {
				secLog.Warn("drop",
					slog.String("request_id", reqID),
					slog.String("rule_id", result.Action.RuleIDStr),
					slog.Uint64("rule_id_num", uint64(result.Action.RuleID)),
					slog.String("phase", result.Action.Phase),
					slog.String("action", "drop"),
					slog.String("match", result.Action.MatchDesc),
					slog.String("category", result.Action.Category),
				)
				if opts.EventWriter != nil {
					opts.EventWriter.Record(store.SecurityEvent{
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
						Action:     "drop",
						Category:   result.Action.Category,
						MatchDesc:  result.Action.MatchDesc,
						StatusCode: 0,
					})
				}
				logAccess(accessLog, reqID, c, "drop")
				recordAccessLog(opts, rt.Site.ID, reqID, clientIP, c, "drop", "bypass", "")
				recordDropEvent(opts, rt.Site.ID, clientIP, waf.DropReason{
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
					dropExec.Execute(conn, waf.DropReason{
						Source:    result.Action.Phase,
						RuleID:    result.Action.RuleIDStr,
						Detail:    result.Action.MatchDesc,
						ClientIP:  clientIPStr(clientIP),
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
				)
				statusCode := result.Action.EffectiveStatusCode(403)
				if opts.EventWriter != nil {
					opts.EventWriter.Record(store.SecurityEvent{
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
						Action:     "challenge",
						Category:   result.Action.Category,
						MatchDesc:  result.Action.MatchDesc,
						StatusCode: statusCode,
					})
				}
				waf.WriteChallengeResponse(c, reqID, result.Site, statusCode)
				logAccess(accessLog, reqID, c, "challenge")
				recordAccessLog(opts, rt.Site.ID, reqID, clientIP, c, "challenge", "bypass", "")
				return
			}

			if result.Action.IsRedirect() {
				secLog.Info("redirect",
					slog.String("request_id", reqID),
					slog.String("rule_id", result.Action.RuleIDStr),
					slog.String("redirect_to", result.Action.RedirectTo),
				)
				statusCode := result.Action.EffectiveStatusCode(302)
				if opts.EventWriter != nil {
					opts.EventWriter.Record(store.SecurityEvent{
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
						Action:     "redirect",
						Category:   result.Action.Category,
						MatchDesc:  result.Action.MatchDesc,
						StatusCode: statusCode,
					})
				}
				c.Redirect(statusCode, []byte(result.Action.RedirectTo))
				logAccess(accessLog, reqID, c, "redirect")
				recordAccessLog(opts, rt.Site.ID, reqID, clientIP, c, "redirect", "bypass", result.Action.RedirectTo)
				return
			}

			statusCode := result.Action.EffectiveStatusCode(403)
			secLog.Info("intercept",
				slog.String("request_id", reqID),
				slog.String("rule_id", result.Action.RuleIDStr),
				slog.Uint64("rule_id_num", uint64(result.Action.RuleID)),
				slog.String("phase", result.Action.Phase),
				slog.String("action", actStr),
				slog.String("match", result.Action.MatchDesc),
				slog.String("category", result.Action.Category),
			)
			if opts.EventWriter != nil {
				opts.EventWriter.Record(store.SecurityEvent{
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
			waf.WriteBlockResponse(c, reqID, result.Site, sn, result.Action)
			logAccess(accessLog, reqID, c, actStr)
			recordAccessLog(opts, rt.Site.ID, reqID, clientIP, c, actStr, "bypass", "")
			return
		}

		if result.Site == nil || len(result.Site.UpstreamURLs) == 0 {
			c.String(502, "no upstream configured")
			return
		}

		n := uint32(len(result.Site.UpstreamURLs))
		i := (rr.Add(1) - 1) % n
		base := result.Site.UpstreamURLs[i]

		var upstreamErr error
		cacheState := "bypass"
		switch {
		case IsWebSocketUpgrade(c):
			upstreamErr = ForwardWebSocket(c, *result.Site, base, opts.Engine)
		case IsSSERequest(c):
			upstreamErr = ForwardSSE(ctx, c, *result.Site, base, clientIP, host)
		default:
			cacheKey, ttl := "", int64(0)
			if opts.ResponseCache != nil {
				cacheKey, ttl = proxy.SiteCacheEligible(*result.Site, c)
			}
			if cacheKey == "" {
				upstreamErr = proxy.ForwardHTTP(ctx, c, *result.Site, base, clientIP, host)
				break
			}
			if entry := opts.ResponseCache.Get(cacheKey); entry != nil {
				proxy.ForwardCachedResponse(c, entry.StatusCode, entry.ContentType, entry.Body)
				cacheState = "hit"
				break
			}
			cacheState = "miss"
			bufferedResp, err := proxy.FetchHTTP(ctx, c, *result.Site, base, clientIP, host)
			if err != nil {
				upstreamErr = err
				break
			}
			if bufferedResp.Header.Get("Set-Cookie") == "" && proxy.ShouldCacheResponse(string(c.Method()), bufferedResp.StatusCode, bufferedResp.Body) {
				opts.ResponseCache.Set(cacheKey, bufferedResp.StatusCode, bufferedResp.ContentType, bufferedResp.Body, ttl)
			}
			proxy.ForwardBufferedResponse(c, bufferedResp)
		}

		if upstreamErr != nil {
			errCode := 502
			if isTimeoutError(upstreamErr) {
				errCode = 504
			}
			waf.WriteUpstreamErrorResponse(c, reqID, errCode)
		}
		if c.Response.Header.Get("Server") != "" && !hasUpstreamServerHeader(c) {
			c.Response.Header.Del("Server")
		}

		statusCode := c.Response.StatusCode()
		if opts.Metrics != nil {
			opts.Metrics.RecordStatus(statusCode)
		}

		errRL := opts.Engine.ErrRateLimiter()
		if errRL != nil && errRL.Enabled() {
			prot := sn.Protection
			isErr := false
			if prot.ErrorRateLimitCount4xx && statusCode >= 400 && statusCode < 500 {
				isErr = true
			}
			if prot.ErrorRateLimitCount5xx && statusCode >= 500 {
				isErr = true
			}
			if isErr {
				key := ""
				if clientIP != nil {
					key = clientIP.String()
				}
				key += "|" + host
				errRL.Increment(key)
			}
		}

		wafAction := "none"
		if len(result.ObserveHits) > 0 {
			wafAction = "observe"
		}
		logAccess(accessLog, reqID, c, wafAction)
		recordAccessLog(opts, rt.Site.ID, reqID, clientIP, c, wafAction, cacheState, base)
	}
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

func logAccess(log *slog.Logger, reqID string, c *app.RequestContext, wafAction string) {
	if !log.Enabled(context.Background(), slog.LevelInfo) {
		return
	}
	log.Info("access",
		slog.String("request_id", reqID),
		slog.String("method", string(c.Method())),
		slog.String("path", accessPath(c)),
		slog.String("host", string(c.Host())),
		slog.Int("status", accessStatusCode(c, wafAction)),
		slog.String("waf_action", wafAction),
	)
}

func recordAccessLog(opts Options, siteID uint, reqID string, clientIP net.IP, c *app.RequestContext, wafAction string, cacheState string, upstream string) {
	if opts.AccessLogWriter == nil {
		return
	}
	opts.AccessLogWriter.Record(store.AccessLog{
		SiteID:     siteID,
		RequestID:  reqID,
		ClientIP:   clientIPStr(clientIP),
		Host:       string(c.Host()),
		Path:       accessPath(c),
		Method:     string(c.Method()),
		StatusCode: accessStatusCode(c, wafAction),
		WAFAction:  wafAction,
		CacheState: cacheState,
		Upstream:   upstream,
		UserAgent:  string(c.UserAgent()),
	})
}

func recordDropEvent(opts Options, siteID uint, clientIP net.IP, reason waf.DropReason) {
	if opts.DropEventRepo == nil {
		return
	}
	_ = opts.DropEventRepo.Create(&store.DropEvent{
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

// ShouldBlock checks if an action result requires blocking (legacy helper).
func ShouldBlock(res action.Result) bool {
	return res.IsTerminal()
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
