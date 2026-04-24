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
	Bind        string
	Holder      *snapshot.Holder
	Engine      *engine.Engine
	Metrics     *Metrics
	EventWriter *observability.EventWriter
	Log         *slog.Logger
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
		// Remove framework-injected Server header — upstream's header will be set by proxy.
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

		// JS Challenge verification: if a POST carries valid challenge tokens,
		// set a short-lived cookie to bypass future challenges and redirect to GET.
		if string(c.Method()) == "POST" {
			challengeTS := string(c.FormValue("__waf_challenge_ts"))
			challengeToken := string(c.FormValue("__waf_challenge_token"))
			challengeRID := string(c.FormValue("__waf_challenge_rid"))
			if challengeTS != "" && challengeToken != "" && challengeRID != "" {
				if waf.VerifyChallengeToken(challengeRID, challengeTS, challengeToken, 5*time.Minute) {
					// Challenge passed — set cookie and redirect to original page.
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
					return
				}
			}
		}

		path := string(c.Path())
		rawQ := string(c.URI().QueryString())

		// Build request context from pool to reduce GC pressure.
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

		// Read body for WAF scanning (capped to avoid memory abuse).
		const maxWAFBody = 65536
		if body := c.Request.Body(); len(body) > 0 {
			if len(body) > maxWAFBody {
				reqCtx.Body = body[:maxWAFBody]
			} else {
				reqCtx.Body = body
			}
			reqCtx.ContentType = string(c.ContentType())
		}

		defer pipeline.ReleaseCtx(reqCtx)

		result := opts.Engine.Process(reqCtx)

		// Log observe hits.
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

		// Maintenance mode.
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
			return
		}

		// Terminal actions: drop, challenge, redirect, intercept.
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

			// Drop action: close TCP connection immediately, no response.
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

			// Challenge action: serve JS challenge page.
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
				return
			}

			// Redirect action: HTTP redirect.
			if result.Action.IsRedirect() {
				secLog.Info("redirect",
					slog.String("request_id", reqID),
					slog.String("rule_id", result.Action.RuleIDStr),
					slog.String("redirect_to", result.Action.RedirectTo),
				)
				statusCode := result.Action.EffectiveStatusCode(302)
				if opts.EventWriter != nil {
					opts.EventWriter.Record(store.SecurityEvent{
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
				return
			}

			// Intercept (block).
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
			return
		}

		// Forward to upstream.
		if result.Site == nil || len(result.Site.UpstreamURLs) == 0 {
			c.String(502, "no upstream configured")
			return
		}

		n := uint32(len(result.Site.UpstreamURLs))
		i := (rr.Add(1) - 1) % n
		base := result.Site.UpstreamURLs[i]

		var upstreamErr error
		switch {
		case IsWebSocketUpgrade(c):
			upstreamErr = ForwardWebSocket(c, *result.Site, base)
		case IsSSERequest(c):
			upstreamErr = ForwardSSE(ctx, c, *result.Site, base, clientIP, host)
		default:
			upstreamErr = proxy.ForwardHTTP(ctx, c, *result.Site, base, clientIP, host)
		}

		if upstreamErr != nil {
			errCode := 502
			if isTimeoutError(upstreamErr) {
				errCode = 504
			}
			waf.WriteUpstreamErrorResponse(c, reqID, errCode)
		}
		// Remove framework-injected Server header after proxy (upstream's header already set).
		if c.Response.Header.Get("Server") != "" && !hasUpstreamServerHeader(c) {
			c.Response.Header.Del("Server")
		}

		statusCode := c.Response.StatusCode()
		if opts.Metrics != nil {
			opts.Metrics.RecordStatus(statusCode)
		}

		// Error rate limiting (post-response).
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
		slog.String("path", string(c.Path())),
		slog.String("host", string(c.Host())),
		slog.Int("status", c.Response.StatusCode()),
		slog.String("waf_action", wafAction),
	)
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
