package admin

import (
	"context"
	"io/fs"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"

	acmepkg "My-OpenWaf/internal/acme"
	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/admin/detect"
	"My-OpenWaf/internal/admin/event"
	"My-OpenWaf/internal/admin/protect"
	"My-OpenWaf/internal/admin/rule"
	"My-OpenWaf/internal/admin/site"
	"My-OpenWaf/internal/admin/system"
	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/core/adminweb"
	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/pkg/logger"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/upstream"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/cve"
	"My-OpenWaf/internal/waf/escalation"

	"gorm.io/gorm"
)

type Dependencies struct {
	Repos         *repository.Repos
	Reload        func() error
	StaticFS      string
	JWTSecret     []byte
	Metrics       *dataplane.Metrics
	DB            *gorm.DB
	LogDB         *gorm.DB
	TokenMgr      *auth.TokenManager
	BruteForce    *auth.BruteForceDetector
	SessionMgr    *auth.SessionManager
	CVEFeedMgr    *cve.CVEFeedManager
	EscalationMgr *escalation.EscalationManager
	CaptchaMgr    *challenge.CaptchaManager
	ACMEMgr       *acmepkg.Manager
	Cache         *cache.RedisKV
	Upstreams     *upstream.Pool
}

func RegisterRoutes(h *server.Hertz, deps *Dependencies) {
	adminLog := logger.New("admin")
	h.Use(SecurityHeaders())
	h.Use(AccessLog(adminLog))

	h.GET("/api/v1/health", system.HealthCheck())

	authDeps := &AuthDeps{
		AccountRepo: deps.Repos.AdminAccount,
		RTRepo:      deps.Repos.RefreshToken,
		JWTSecret:   deps.JWTSecret,
		TokenMgr:    deps.TokenMgr,
		BruteForce:  deps.BruteForce,
		SessionMgr:  deps.SessionMgr,
		DB:          deps.DB,
	}
	h.POST("/api/v1/auth/login", LoginHandler(authDeps))
	h.POST("/api/v1/auth/refresh", RefreshHandler(authDeps))
	h.POST("/api/v1/auth/logout", LogoutHandler(authDeps))

	api := h.Group("/api/v1")
	api.Use(AuthMiddleware(deps.Repos.AdminAPIKey, deps.TokenMgr, deps.SessionMgr))

	api.GET("/auth/me", MeHandler(authDeps))

	api.GET("/auth/sessions", ListSessionsHandler(authDeps))
	api.POST("/auth/sessions/force-logout", RequireRole(auth.RoleAdmin), ForceLogoutSessionHandler(authDeps))

	r := deps.Repos
	reload := deps.Reload

	readGroup := api.Group("")
	readGroup.Use(RequireRole(auth.RoleAdmin, auth.RoleOperator, auth.RoleReadonly))
	{
		readGroup.GET("/sites", site.ListSites(r.Site, r.SiteListener))
		readGroup.GET("/sites/:id", site.GetSite(r.Site))
		readGroup.GET("/sites/:id/status", site.GetSiteStatus(r.Site))
		readGroup.GET("/sites/:id/listeners", site.ListSiteListeners(r.Site, r.SiteListener))

		readGroup.GET("/certificates", system.ListCertificates(r.Certificate))
		readGroup.GET("/certificates/:id", system.GetCertificate(r.Certificate))

		readGroup.GET("/policies", system.ListPolicies(r.Policy))
		readGroup.GET("/policies/:id", system.GetPolicy(r.Policy))

		readGroup.GET("/rules", rule.ListRules(r.Rule))
		readGroup.GET("/rules/:id", rule.GetRule(r.Rule))
		readGroup.GET("/rules/templates", rule.GetRuleTemplates())
		readGroup.GET("/rules/export", rule.ExportRules(r.Rule))

		readGroup.GET("/settings", system.ListSettings(r.SystemSettings))
		readGroup.GET("/settings/:key", system.GetSetting(r.SystemSettings))

		readGroup.GET("/protection-settings", protect.GetProtectionSettings(r.SystemSettings))

		readGroup.GET("/ip-lists", system.ListIPEntries(r.IPList))
		readGroup.GET("/ip-lists/:id", system.GetIPEntry(r.IPList))

		readGroup.GET("/security-events", event.ListSecurityEvents(r.SecurityEvent))
		readGroup.GET("/security-events/stats", event.SecurityEventStats(r.SecurityEvent))
		readGroup.GET("/security-events/timeline", event.SecurityEventTimeline(r.SecurityEvent))
		readGroup.GET("/security-events/:id", event.GetSecurityEvent(r.SecurityEvent))
		readGroup.GET("/access-logs", event.ListAccessLogs(r.AccessLog))
		readGroup.GET("/fingerprints", event.ListTLSFingerprints(r.AccessLog))
		readGroup.GET("/request/:request_id", event.GetRequestTrace(r.AccessLog, r.SecurityEvent))
		readGroup.GET("/sites/:id/security-events", event.ListSiteSecurityEvents(r.Site, r.SecurityEvent))
		readGroup.GET("/sites/:id/security-events/stats", event.SiteSecurityEventStats(r.Site, r.SecurityEvent))
		readGroup.GET("/sites/:id/security-events/timeline", event.SiteSecurityEventTimeline(r.Site, r.SecurityEvent))
		readGroup.GET("/sites/:id/access-logs", site.ListSiteAccessLogs(r.Site, r.AccessLog))
		readGroup.GET("/sites/:id/access-logs/stats", site.SiteAccessLogStats(r.Site, r.AccessLog))
		readGroup.GET("/sites/:id/drop-events", site.ListSiteDropEvents(r.Site, r.DropEvent))
		readGroup.GET("/sites/:id/drop-stats", site.SiteDropStats(r.Site, r.DropEvent))
		readGroup.GET("/sites/:id/rules", rule.ListSiteRules(r.Site, r.Rule))
		readGroup.GET("/sites/:id/application-route-rules", rule.ListApplicationRouteRules(r.Site, r.AppRouteRule))
		readGroup.GET("/sites/:id/recorded-resources", rule.ListRecordedResources(r.Site, r.RecordedResource))

		dashDeps := &system.DashboardDeps{Metrics: deps.Metrics, DB: deps.LogDB, Cache: deps.Cache}
		readGroup.GET("/dashboard/summary", system.DashboardSummary(dashDeps))

		readGroup.GET("/api-keys", system.ListAPIKeys(r.AdminAPIKey))

		readGroup.GET("/bot-settings", protect.GetBotSettings(r.SystemSettings))
		readGroup.GET("/bot-scores", protect.GetBotScores(r.BotScore))

		readGroup.GET("/cve-rules", detect.ListCVERules(r.CVERule))
		readGroup.GET("/cve-rules/stats", detect.GetCVERuleStats(r.CVERule))
		readGroup.GET("/cve-feed/status", detect.GetCVEFeedStatus(deps.CVEFeedMgr, r.CVERule))

		readGroup.GET("/owasp-rules", detect.ListOWASPRulesFromRegistry(r.SystemSettings))
		readGroup.GET("/owasp-rules/stats", detect.GetOWASPRuleStats(r.SystemSettings))

		readGroup.GET("/captcha/config", protect.GetCaptchaConfig(r.SystemSettings))

		readGroup.GET("/chain/config", protect.GetChainConfig(r.SystemSettings))
		readGroup.GET("/chain/sessions", protect.ListChainSessions())

		readGroup.GET("/protection/:id/sensitivity", protect.GetSensitivityConfig(r.SystemSettings))

		readGroup.GET("/protection/:id/escalation", protect.GetEscalationConfig(r.SystemSettings))
		readGroup.GET("/escalation/status/:ip", protect.GetEscalationIPStatus(deps.EscalationMgr))

		readGroup.GET("/sites/:id/error-pages", site.GetSiteErrorPages(r.Site))
		readGroup.GET("/error-pages/defaults", site.GetDefaultErrorPages())

		readGroup.GET("/drop-policy", protect.GetDropPolicy(r.SystemSettings))
		readGroup.GET("/drop-stats", protect.GetDropStats(r.DropEvent))
		readGroup.GET("/drop-events", protect.GetDropEvents(r.DropEvent))
		readGroup.GET("/upstreams/status", system.UpstreamStatus(deps.Upstreams))
	}

	opsGroup := api.Group("")
	opsGroup.Use(RequireRole(auth.RoleAdmin, auth.RoleOperator))
	{
		opsGroup.POST("/sites", site.CreateSite(r.Site, r.Certificate, reload))
		opsGroup.POST("/sites/:id/update", site.UpdateSite(r.Site, r.Certificate, reload))
		opsGroup.POST("/sites/:id/delete", site.DeleteSite(r.Site, r.SiteListener, reload))
		opsGroup.POST("/sites/:id/start", site.StartSite(r.Site, reload))
		opsGroup.POST("/sites/:id/stop", site.StopSite(r.Site, reload))
		opsGroup.POST("/sites/:id/listeners", site.CreateSiteListener(r.Site, r.SiteListener, r.Certificate, reload))
		opsGroup.POST("/sites/:id/listeners/:lid/update", site.UpdateSiteListener(r.Site, r.SiteListener, r.Certificate, reload))
		opsGroup.POST("/sites/:id/listeners/:lid/delete", site.DeleteSiteListener(r.Site, r.SiteListener, reload))

		opsGroup.POST("/certificates", system.CreateCertificate(r.Certificate, reload))
		opsGroup.POST("/certificates/:id/update", system.UpdateCertificate(r.Certificate, reload))
		opsGroup.POST("/certificates/:id/delete", system.DeleteCertificate(r.Certificate, reload))
		opsGroup.POST("/certificates/acme/apply", system.ACMEApply(deps.Repos, reload, deps.ACMEMgr))
		opsGroup.POST("/certificates/acme/:id/renew", system.ACMERenew(deps.Repos, reload, deps.ACMEMgr))

		opsGroup.POST("/policies", system.CreatePolicy(r.Policy, reload))
		opsGroup.POST("/policies/:id/update", system.UpdatePolicy(r.Policy, reload))
		opsGroup.POST("/policies/:id/delete", system.DeletePolicy(r.Policy, reload))

		opsGroup.POST("/rules", rule.CreateRule(r.Rule, reload))
		opsGroup.POST("/rules/:id/update", rule.UpdateRule(r.Rule, reload))
		opsGroup.POST("/rules/:id/delete", rule.DeleteRule(r.Rule, reload))
		opsGroup.POST("/rules/test", rule.TestRule())
		opsGroup.POST("/rules/validate", rule.ValidateRule())
		opsGroup.POST("/rules/import", rule.ImportRules(r.Rule, reload))

		opsGroup.POST("/protection-settings", protect.PutProtectionSettings(r.SystemSettings, reload))

		opsGroup.POST("/ip-lists", system.CreateIPEntry(r.IPList, reload))
		opsGroup.POST("/ip-lists/:id/update", system.UpdateIPEntry(r.IPList, reload))
		opsGroup.POST("/ip-lists/:id/delete", system.DeleteIPEntry(r.IPList, reload))

		opsGroup.POST("/reload", system.ReloadSnapshot(reload))

		opsGroup.POST("/bot-settings/update", protect.UpdateBotSettings(r.SystemSettings, reload))

		opsGroup.POST("/cve-rules/:id/toggle", detect.ToggleCVERule(r.CVERule, deps.CVEFeedMgr))
		opsGroup.POST("/cve-rules/:id/patch", detect.UpdateSingleCVERule(r.CVERule, deps.CVEFeedMgr))
		opsGroup.POST("/cve-rules/batch", detect.BatchUpdateCVERules(r.CVERule, deps.CVEFeedMgr))
		opsGroup.POST("/cve-rules/sync", detect.SyncCVERules(deps.CVEFeedMgr))

		opsGroup.POST("/owasp-rules/:id/update", detect.UpdateSingleOWASPRule(r.SystemSettings, reload))
		opsGroup.POST("/owasp-rules/batch", detect.BatchUpdateOWASPRules(r.SystemSettings, reload))

		opsGroup.POST("/captcha/config", protect.UpdateCaptchaConfig(r.SystemSettings, reload))
		opsGroup.POST("/captcha/test", protect.TestCaptcha(r.SystemSettings, deps.CaptchaMgr))

		opsGroup.POST("/chain/config", protect.UpdateChainConfig(r.SystemSettings, reload))
		opsGroup.POST("/chain/sessions/:id/delete", protect.DeleteChainSession())

		opsGroup.POST("/protection/:id/sensitivity", protect.UpdateSensitivityConfig(r.SystemSettings, reload))

		opsGroup.POST("/protection/:id/escalation", protect.UpdateEscalationConfig(r.SystemSettings, reload))
		opsGroup.POST("/escalation/status/:ip/reset", protect.ResetEscalationIPStatus(deps.EscalationMgr))

		opsGroup.POST("/sites/:id/application-route-rules", rule.CreateApplicationRouteRule(r.Site, r.AppRouteRule, reload))
		opsGroup.POST("/sites/:id/application-route-rules/:rid/update", rule.UpdateApplicationRouteRule(r.Site, r.AppRouteRule, reload))
		opsGroup.POST("/sites/:id/application-route-rules/:rid/delete", rule.DeleteApplicationRouteRule(r.Site, r.AppRouteRule, reload))
		opsGroup.POST("/sites/:id/recorded-resources/clear", rule.ClearRecordedResources(r.Site, r.RecordedResource))

		opsGroup.POST("/sites/:id/error-pages", site.UpdateSiteErrorPages(r.Site, reload))
		opsGroup.POST("/error-pages/preview", site.PreviewErrorPage())
	}

	adminGroup := api.Group("")
	adminGroup.Use(RequireRole(auth.RoleAdmin))
	{
		adminGroup.POST("/settings", system.CreateSetting(r.SystemSettings, reload))
		adminGroup.POST("/settings/:key", system.SetSetting(r.SystemSettings, reload))
		adminGroup.POST("/settings/:key/update", system.SetSetting(r.SystemSettings, reload))
		adminGroup.POST("/settings/:key/delete", system.DeleteSetting(r.SystemSettings, reload))

		adminGroup.GET("/network-config", system.GetNetworkConfig(r.SystemSettings))
		adminGroup.POST("/network-config", system.UpdateNetworkConfig(r.SystemSettings, reload))
		adminGroup.GET("/log-config", system.GetLogConfig(r.SystemSettings))
		adminGroup.POST("/log-config", system.UpdateLogConfig(r.SystemSettings))
		adminGroup.GET("/tls-config", system.GetTLSDefaultConfig(r.SystemSettings))
		adminGroup.POST("/tls-config", system.UpdateTLSDefaultConfig(r.SystemSettings, reload))
		adminGroup.GET("/tls-cipher-suites", system.ListCipherSuites())
		adminGroup.GET("/certificates/acme/status", system.ACMEStatus(deps.Repos))

		adminGroup.POST("/api-keys", system.CreateAPIKey(r.AdminAPIKey))
		adminGroup.POST("/api-keys/:id/delete", system.DeleteAPIKey(r.AdminAPIKey))

		adminGroup.POST("/drop-policy/update", protect.UpdateDropPolicy(r.SystemSettings, reload))

		adminGroup.POST("/cve-rules", detect.CreateCVERule(r.CVERule, deps.CVEFeedMgr))
		adminGroup.POST("/cve-rules/:id/update", detect.UpdateCVERule(r.CVERule, deps.CVEFeedMgr))
		adminGroup.POST("/cve-rules/:id/delete", detect.DeleteCVERule(r.CVERule, deps.CVEFeedMgr))
	}

	h.GET("/__owaf/pow.wasm", func(ctx context.Context, c *app.RequestContext) {
		challenge.ServePoWWASM(c)
	})
	h.GET("/__owaf/wasm_exec.js", func(ctx context.Context, c *app.RequestContext) {
		challenge.ServeWasmExecJS(c)
	})
	if deps.ACMEMgr != nil {
		h.GET("/.well-known/acme-challenge/:token", func(ctx context.Context, c *app.RequestContext) {
			token := strings.TrimSpace(c.Param("token"))
			if token == "" {
				c.Status(404)
				return
			}
			if resp, ok := deps.ACMEMgr.GetChallengeResponse(token); ok {
				c.Response.Header.Set("Content-Type", "text/plain")
				c.String(200, resp)
				return
			}
			c.Status(404)
		})
	}

	mountStaticHandler(h, deps.StaticFS)
}

func mountStaticHandler(h *server.Hertz, diskDir string) {
	webFS, err := adminweb.ResolveFS(diskDir)
	if err != nil {
		return
	}

	h.NoRoute(func(ctx context.Context, c *app.RequestContext) {
		path := string(c.Path())
		if strings.HasPrefix(path, "/api/") {
			c.JSON(404, map[string]string{"error": "endpoint not found"})
			return
		}
		serveStaticFile(c, webFS, path)
	})
}

func serveStaticFile(c *app.RequestContext, webFS fs.FS, path string) {
	data, resolvedPath, err := adminweb.ReadRouteFile(webFS, path)
	if err != nil {
		c.String(404, "not found")
		return
	}
	c.Data(200, adminweb.ContentType(resolvedPath), data)
}
