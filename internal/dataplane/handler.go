package dataplane

import (
	"context"
	"io/fs"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"

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
	Bind         string
	Holder       *snapshot.Holder
	Engine       *engine.Engine
	Metrics      *Metrics
	EventWriter  *observability.EventWriter
	Log          *slog.Logger
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
			reqCtx.Headers[string(k)] = string(v)
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

		// Intercept (block fuse).
		if result.Action.IsTerminal() {
			if opts.Metrics != nil {
				opts.Metrics.RecordWAFBlock()
				if result.Action.Phase == "owasp_default" {
					opts.Metrics.RecordBuiltinHit()
				}
			}
			secLog.Info("intercept",
				slog.String("request_id", reqID),
				slog.String("rule_id", result.Action.RuleIDStr),
				slog.Uint64("rule_id_num", uint64(result.Action.RuleID)),
				slog.String("phase", result.Action.Phase),
				slog.String("action", "intercept"),
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
					Action:     "intercept",
					Category:   result.Action.Category,
					MatchDesc:  result.Action.MatchDesc,
					StatusCode: 403,
				})
			}
			waf.WriteBlockResponse(c, reqID, result.Site, sn, result.Action)
			logAccess(accessLog, reqID, c, "intercept")
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
			c.String(502, "upstream error")
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
