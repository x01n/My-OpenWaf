package dataplane

import (
	"context"
	"io/fs"
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/google/uuid"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/adminweb"
	"My-OpenWaf/internal/core/engine"
	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/proxy"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/waf"
)

// Options configures a single data listener handler.
type Options struct {
	ListenerID uint
	Holder     *snapshot.Holder
	Engine     *engine.Engine
	Metrics    *Metrics
	Log        *slog.Logger
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
		rt, ok := sn.MatchSite(opts.ListenerID, host)
		if !ok {
			c.String(404, "unknown virtual host")
			return
		}

		clientIP := security.ResolveClientIP(c, rt.Forwarding)
		path := string(c.Path())
		rawQ := string(c.URI().QueryString())

		// Build request headers for WAF inspection.
		headers := make(map[string]string)
		c.Request.Header.VisitAll(func(k, v []byte) {
			headers[string(k)] = string(v)
		})

		// Run unified engine.
		reqCtx := &pipeline.RequestCtx{
			RequestID:  reqID,
			ListenerID: opts.ListenerID,
			ClientIP:   clientIP,
			Method:     string(c.Method()),
			Path:       path,
			RawQuery:   rawQ,
			Host:       host,
			Headers:    headers,
		}

		result := opts.Engine.Process(reqCtx)

		// Log observe hits.
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
