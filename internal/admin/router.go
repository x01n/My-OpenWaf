package admin

import (
	"context"
	"io/fs"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"

	"My-OpenWaf/internal/core/adminweb"
	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/pkg/logger"
	"My-OpenWaf/internal/store/repository"

	"gorm.io/gorm"
)

// Dependencies holds all admin API dependencies.
type Dependencies struct {
	Repos     *repository.Repos
	Reload    func() error
	StaticFS  string
	JWTSecret []byte
	Metrics   *dataplane.Metrics
	DB        *gorm.DB
}

// RegisterRoutes mounts the admin REST API and frontend static files on the Hertz server.
//
// NOTE: The admin API only uses GET and POST methods — no PUT/DELETE.
// This simplifies reverse-proxy / CORS setups and matches the project convention.
// Update and delete operations are exposed as:
//   POST /resource/:id/update  – update
//   POST /resource/:id/delete  – delete
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
	}
	h.POST("/api/v1/auth/login", LoginHandler(authDeps))
	h.POST("/api/v1/auth/refresh", RefreshHandler(authDeps))
	h.POST("/api/v1/auth/logout", LogoutHandler(authDeps))

	// Authenticated API group.
	api := h.Group("/api/v1")
	api.Use(AuthMiddleware(deps.Repos.AdminAPIKey, deps.JWTSecret))

	api.GET("/auth/me", MeHandler(authDeps))

	r := deps.Repos
	reload := deps.Reload

	// Sites
	api.GET("/sites", ListSites(r.Site))
	api.GET("/sites/:id", GetSite(r.Site))
	api.POST("/sites", CreateSite(r.Site, reload))
	api.POST("/sites/:id/update", UpdateSite(r.Site, reload))
	api.POST("/sites/:id/delete", DeleteSite(r.Site, reload))
	api.POST("/sites/:id/start", StartSite(r.Site))
	api.POST("/sites/:id/stop", StopSite(r.Site))
	api.GET("/sites/:id/status", GetSiteStatus(r.Site))

	// Certificates
	api.GET("/certificates", ListCertificates(r.Certificate))
	api.GET("/certificates/:id", GetCertificate(r.Certificate))
	api.POST("/certificates", CreateCertificate(r.Certificate, reload))
	api.POST("/certificates/:id/update", UpdateCertificate(r.Certificate, reload))
	api.POST("/certificates/:id/delete", DeleteCertificate(r.Certificate, reload))

	// Policies
	api.GET("/policies", ListPolicies(r.Policy))
	api.GET("/policies/:id", GetPolicy(r.Policy))
	api.POST("/policies", CreatePolicy(r.Policy, reload))
	api.POST("/policies/:id/update", UpdatePolicy(r.Policy, reload))
	api.POST("/policies/:id/delete", DeletePolicy(r.Policy, reload))

	// Rules
	api.GET("/rules", ListRules(r.Rule))
	api.GET("/rules/:id", GetRule(r.Rule))
	api.POST("/rules", CreateRule(r.Rule, reload))
	api.POST("/rules/:id/update", UpdateRule(r.Rule, reload))
	api.POST("/rules/:id/delete", DeleteRule(r.Rule, reload))
	api.POST("/rules/test", TestRule())
	api.POST("/rules/validate", ValidateRule())
	api.GET("/rules/templates", GetRuleTemplates())
	api.GET("/rules/export", ExportRules(r.Rule))
	api.POST("/rules/import", ImportRules(r.Rule, reload))

	// System Settings
	api.GET("/settings", ListSettings(r.SystemSettings))
	api.GET("/settings/:key", GetSetting(r.SystemSettings))
	api.POST("/settings", CreateSetting(r.SystemSettings, reload))
	api.POST("/settings/:key", SetSetting(r.SystemSettings, reload))
	api.POST("/settings/:key/update", SetSetting(r.SystemSettings, reload))
	api.POST("/settings/:key/delete", DeleteSetting(r.SystemSettings, reload))

	// Protection Settings
	api.GET("/protection-settings", GetProtectionSettings(r.SystemSettings))
	api.POST("/protection-settings", PutProtectionSettings(r.SystemSettings, reload))

	// IP Black/White List
	api.GET("/ip-lists", ListIPEntries(r.IPList))
	api.GET("/ip-lists/:id", GetIPEntry(r.IPList))
	api.POST("/ip-lists", CreateIPEntry(r.IPList, reload))
	api.POST("/ip-lists/:id/update", UpdateIPEntry(r.IPList, reload))
	api.POST("/ip-lists/:id/delete", DeleteIPEntry(r.IPList, reload))

	// Security Events
	api.GET("/security-events", ListSecurityEvents(r.SecurityEvent))
	api.GET("/security-events/stats", SecurityEventStats(r.SecurityEvent))
	api.GET("/security-events/timeline", SecurityEventTimeline(r.SecurityEvent))
	api.GET("/security-events/:id", GetSecurityEvent(r.SecurityEvent))

	// Dashboard
	dashDeps := &DashboardDeps{Metrics: deps.Metrics, DB: deps.DB}
	api.GET("/dashboard/summary", DashboardSummary(dashDeps))

	// API Keys
	api.GET("/api-keys", ListAPIKeys(r.AdminAPIKey))
	api.POST("/api-keys", CreateAPIKey(r.AdminAPIKey))
	api.POST("/api-keys/:id/delete", DeleteAPIKey(r.AdminAPIKey))

	// Snapshot reload
	api.POST("/reload", ReloadSnapshot(reload))

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
