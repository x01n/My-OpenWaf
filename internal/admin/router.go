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

	// Listeners
	api.GET("/listeners", ListListeners(r.Listener))
	api.GET("/listeners/:id", GetListener(r.Listener))
	api.POST("/listeners", CreateListener(r.Listener, reload))
	api.PUT("/listeners/:id", UpdateListener(r.Listener, reload))
	api.DELETE("/listeners/:id", DeleteListener(r.Listener, reload))

	// Sites
	api.GET("/sites", ListSites(r.Site))
	api.GET("/sites/:id", GetSite(r.Site))
	api.POST("/sites", CreateSite(r.Site, reload))
	api.PUT("/sites/:id", UpdateSite(r.Site, reload))
	api.DELETE("/sites/:id", DeleteSite(r.Site, reload))

	// Certificates
	api.GET("/certificates", ListCertificates(r.Certificate))
	api.GET("/certificates/:id", GetCertificate(r.Certificate))
	api.POST("/certificates", CreateCertificate(r.Certificate, reload))
	api.PUT("/certificates/:id", UpdateCertificate(r.Certificate, reload))
	api.DELETE("/certificates/:id", DeleteCertificate(r.Certificate, reload))

	// Policies
	api.GET("/policies", ListPolicies(r.Policy))
	api.GET("/policies/:id", GetPolicy(r.Policy))
	api.POST("/policies", CreatePolicy(r.Policy, reload))
	api.PUT("/policies/:id", UpdatePolicy(r.Policy, reload))
	api.DELETE("/policies/:id", DeletePolicy(r.Policy, reload))

	// Rules
	api.GET("/rules", ListRules(r.Rule))
	api.GET("/rules/:id", GetRule(r.Rule))
	api.POST("/rules", CreateRule(r.Rule, reload))
	api.PUT("/rules/:id", UpdateRule(r.Rule, reload))
	api.DELETE("/rules/:id", DeleteRule(r.Rule, reload))

	// Forwarding Profiles
	api.GET("/forwarding-profiles", ListForwardingProfiles(r.ForwardingProfile))
	api.GET("/forwarding-profiles/:id", GetForwardingProfile(r.ForwardingProfile))
	api.POST("/forwarding-profiles", CreateForwardingProfile(r.ForwardingProfile, reload))
	api.PUT("/forwarding-profiles/:id", UpdateForwardingProfile(r.ForwardingProfile, reload))
	api.DELETE("/forwarding-profiles/:id", DeleteForwardingProfile(r.ForwardingProfile, reload))

	// System Settings
	api.GET("/settings", ListSettings(r.SystemSettings))
	api.GET("/settings/:key", GetSetting(r.SystemSettings))
	api.PUT("/settings/:key", SetSetting(r.SystemSettings, reload))
	api.DELETE("/settings/:key", DeleteSetting(r.SystemSettings, reload))

	// Protection Settings
	api.GET("/protection-settings", GetProtectionSettings(r.SystemSettings))
	api.PUT("/protection-settings", PutProtectionSettings(r.SystemSettings, reload))

	// Dashboard
	dashDeps := &DashboardDeps{Metrics: deps.Metrics, DB: deps.DB}
	api.GET("/dashboard/summary", DashboardSummary(dashDeps))

	// API Keys
	api.GET("/api-keys", ListAPIKeys(r.AdminAPIKey))
	api.POST("/api-keys", CreateAPIKey(r.AdminAPIKey))
	api.DELETE("/api-keys/:id", DeleteAPIKey(r.AdminAPIKey))

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
