package admin

import (
	"context"
	"io/fs"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/core/adminweb"
	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/pkg/logger"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf"

	"gorm.io/gorm"
)

// Dependencies holds all admin API dependencies.
type Dependencies struct {
	Repos      *repository.Repos
	Reload     func() error
	StaticFS   string
	JWTSecret  []byte
	Metrics    *dataplane.Metrics
	DB         *gorm.DB
	TokenMgr   *auth.TokenManager
	BruteForce *auth.BruteForceDetector
	SessionMgr *auth.SessionManager
	CVEFeedMgr *waf.CVEFeedManager
}

// RegisterRoutes mounts the admin REST API and frontend static files on the Hertz server.
//
// NOTE: The admin API only uses GET and POST methods — no PUT/DELETE.
// This simplifies reverse-proxy / CORS setups and matches the project convention.
// Update and delete operations are exposed as:
//
//	POST /resource/:id/update  – update
//	POST /resource/:id/delete  – delete
//
// RBAC roles:
//   - admin: full access to everything
//   - operator: can manage sites, rules, policies, certificates, IP lists, protection
//   - readonly: can only view/read data
func RegisterRoutes(h *server.Hertz, deps *Dependencies) {
	adminLog := logger.New("admin")
	h.Use(SecurityHeaders())
	h.Use(AccessLog(adminLog))

	h.GET("/api/v1/health", HealthCheck())

	// Auth routes (no auth middleware).
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

	// Authenticated API group — all routes below require valid JWT or API Key.
	api := h.Group("/api/v1")
	api.Use(AuthMiddleware(deps.Repos.AdminAPIKey, deps.TokenMgr, deps.SessionMgr))

	// ── Auth info (any authenticated role) ──
	api.GET("/auth/me", MeHandler(authDeps))

	// ── Session management (any authenticated user can view own, admin can manage all) ──
	api.GET("/auth/sessions", ListSessionsHandler(authDeps))
	api.POST("/auth/sessions/force-logout", RequireRole(auth.RoleAdmin), ForceLogoutSessionHandler(authDeps))

	r := deps.Repos
	reload := deps.Reload

	// ── Read-only routes (all authenticated roles: admin, operator, readonly) ──
	readGroup := api.Group("")
	readGroup.Use(RequireRole(auth.RoleAdmin, auth.RoleOperator, auth.RoleReadonly))
	{
		readGroup.GET("/sites", ListSites(r.Site))
		readGroup.GET("/sites/:id", GetSite(r.Site))
		readGroup.GET("/sites/:id/status", GetSiteStatus(r.Site))

		readGroup.GET("/certificates", ListCertificates(r.Certificate))
		readGroup.GET("/certificates/:id", GetCertificate(r.Certificate))

		readGroup.GET("/policies", ListPolicies(r.Policy))
		readGroup.GET("/policies/:id", GetPolicy(r.Policy))

		readGroup.GET("/rules", ListRules(r.Rule))
		readGroup.GET("/rules/:id", GetRule(r.Rule))
		readGroup.GET("/rules/templates", GetRuleTemplates())
		readGroup.GET("/rules/export", ExportRules(r.Rule))

		readGroup.GET("/settings", ListSettings(r.SystemSettings))
		readGroup.GET("/settings/:key", GetSetting(r.SystemSettings))

		readGroup.GET("/protection-settings", GetProtectionSettings(r.SystemSettings))

		readGroup.GET("/ip-lists", ListIPEntries(r.IPList))
		readGroup.GET("/ip-lists/:id", GetIPEntry(r.IPList))

		readGroup.GET("/security-events", ListSecurityEvents(r.SecurityEvent))
		readGroup.GET("/security-events/stats", SecurityEventStats(r.SecurityEvent))
		readGroup.GET("/security-events/timeline", SecurityEventTimeline(r.SecurityEvent))
		readGroup.GET("/security-events/:id", GetSecurityEvent(r.SecurityEvent))

		// Dashboard
		dashDeps := &DashboardDeps{Metrics: deps.Metrics, DB: deps.DB}
		readGroup.GET("/dashboard/summary", DashboardSummary(dashDeps))

		// API Keys (list only for readonly)
		readGroup.GET("/api-keys", ListAPIKeys(r.AdminAPIKey))

		// Bot detection
		readGroup.GET("/bot-settings", GetBotSettings(r.SystemSettings))
		readGroup.GET("/bot-scores", GetBotScores(r.BotScore))
		readGroup.GET("/fingerprints", GetFingerprints(r.Fingerprint))

		// CVE rules
		readGroup.GET("/cve-rules", ListCVERules(r.CVERule))
		readGroup.GET("/cve-feed/status", GetCVEFeedStatus(deps.CVEFeedMgr, r.CVERule))

		// Drop policy
		readGroup.GET("/drop-policy", GetDropPolicy(r.SystemSettings))
		readGroup.GET("/drop-stats", GetDropStats(r.DropEvent))
		readGroup.GET("/drop-events", GetDropEvents(r.DropEvent))
	}

	// ── Operator routes (admin + operator: manage sites, rules, policies, certs, IP lists) ──
	opsGroup := api.Group("")
	opsGroup.Use(RequireRole(auth.RoleAdmin, auth.RoleOperator))
	{
		// Sites
		opsGroup.POST("/sites", CreateSite(r.Site, reload))
		opsGroup.POST("/sites/:id/update", UpdateSite(r.Site, reload))
		opsGroup.POST("/sites/:id/delete", DeleteSite(r.Site, reload))
		opsGroup.POST("/sites/:id/start", StartSite(r.Site))
		opsGroup.POST("/sites/:id/stop", StopSite(r.Site))

		// Certificates
		opsGroup.POST("/certificates", CreateCertificate(r.Certificate, reload))
		opsGroup.POST("/certificates/:id/update", UpdateCertificate(r.Certificate, reload))
		opsGroup.POST("/certificates/:id/delete", DeleteCertificate(r.Certificate, reload))

		// Policies
		opsGroup.POST("/policies", CreatePolicy(r.Policy, reload))
		opsGroup.POST("/policies/:id/update", UpdatePolicy(r.Policy, reload))
		opsGroup.POST("/policies/:id/delete", DeletePolicy(r.Policy, reload))

		// Rules
		opsGroup.POST("/rules", CreateRule(r.Rule, reload))
		opsGroup.POST("/rules/:id/update", UpdateRule(r.Rule, reload))
		opsGroup.POST("/rules/:id/delete", DeleteRule(r.Rule, reload))
		opsGroup.POST("/rules/test", TestRule())
		opsGroup.POST("/rules/validate", ValidateRule())
		opsGroup.POST("/rules/import", ImportRules(r.Rule, reload))

		// Protection Settings
		opsGroup.POST("/protection-settings", PutProtectionSettings(r.SystemSettings, reload))

		// IP Black/White List
		opsGroup.POST("/ip-lists", CreateIPEntry(r.IPList, reload))
		opsGroup.POST("/ip-lists/:id/update", UpdateIPEntry(r.IPList, reload))
		opsGroup.POST("/ip-lists/:id/delete", DeleteIPEntry(r.IPList, reload))

		// Snapshot reload
		opsGroup.POST("/reload", ReloadSnapshot(reload))

		// Bot settings (operator can update)
		opsGroup.POST("/bot-settings/update", UpdateBotSettings(r.SystemSettings, reload))

		// CVE rules (operator can toggle/sync)
		opsGroup.POST("/cve-rules/:id/toggle", ToggleCVERule(r.CVERule))
		opsGroup.POST("/cve-rules/sync", SyncCVERules(deps.CVEFeedMgr))
	}

	// ── Admin-only routes (system settings, API keys management) ──
	adminGroup := api.Group("")
	adminGroup.Use(RequireRole(auth.RoleAdmin))
	{
		// System Settings (write)
		adminGroup.POST("/settings", CreateSetting(r.SystemSettings, reload))
		adminGroup.POST("/settings/:key", SetSetting(r.SystemSettings, reload))
		adminGroup.POST("/settings/:key/update", SetSetting(r.SystemSettings, reload))
		adminGroup.POST("/settings/:key/delete", DeleteSetting(r.SystemSettings, reload))

		// API Keys (create/delete)
		adminGroup.POST("/api-keys", CreateAPIKey(r.AdminAPIKey))
		adminGroup.POST("/api-keys/:id/delete", DeleteAPIKey(r.AdminAPIKey))

		// Drop policy (admin only)
		adminGroup.POST("/drop-policy/update", UpdateDropPolicy(r.SystemSettings, reload))

		// CVE rules CRUD (admin only)
		adminGroup.POST("/cve-rules", CreateCVERule(r.CVERule))
		adminGroup.POST("/cve-rules/:id/update", UpdateCVERule(r.CVERule))
		adminGroup.POST("/cve-rules/:id/delete", DeleteCVERule(r.CVERule))
	}

	// Frontend static files (SPA fallback)
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
