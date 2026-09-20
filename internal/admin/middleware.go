package admin

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/google/uuid"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/security"
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

const (
	adminHSTSHeaderName           = "Strict-Transport-Security"
	adminHSTSHeaderValue          = "max-age=31536000"
	adminXSSHeaderName            = "X-XSS-Protection"
	adminXSSHeaderValue           = "1; mode=block"
	adminHPKPHeaderName           = "Public-Key-Pins"
	adminHPKPReportOnlyHeaderName = "Public-Key-Pins-Report-Only"
)

// AuthMiddleware supports JWT (Bearer) or API Key authentication.
// Whitelisted paths are skipped (health, auth endpoints).
func AuthMiddleware(keyRepo *repository.AdminAPIKeyRepo, tm *auth.TokenManager, sessionMgr *auth.SessionManager) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		path := string(c.Path())

		// Whitelist: health + auth endpoints (login/refresh/logout).
		if path == "/api/v1/health" ||
			path == "/api/v1/auth/login" ||
			path == "/api/v1/auth/refresh" ||
			path == "/api/v1/auth/logout" {
			c.Next(ctx)
			return
		}

		header := strings.TrimSpace(string(c.GetHeader("Authorization")))
		if header == "" {
			c.JSON(401, map[string]string{"error": "missing Authorization header"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(header, "Bearer ")
		if token == header {
			c.JSON(401, map[string]string{"error": "invalid Authorization format, use Bearer <token>"})
			c.Abort()
			return
		}

		// Try JWT first (via TokenManager with key rotation + blacklist support).
		if tm != nil {
			if claims, err := tm.VerifyAccessToken(token); err == nil {
				c.Set("auth_user", claims.Username)
				c.Set("auth_method", "jwt")
				c.Set("auth_role", claims.Role)
				c.Set("auth_jti", claims.ID)

				// Update session last active time.
				if claims.ID != "" && sessionMgr != nil {
					sessionMgr.UpdateLastActive(claims.ID)
				}

				c.Next(ctx)
				return
			} else if errors.Is(err, auth.ErrTokenBlacklistUnavailable) {
				c.JSON(503, map[string]string{"error": "authentication service unavailable"})
				c.Abort()
				return
			}
		}

		// Fallback: API Key.
		var key *store.AdminAPIKey
		ok := false
		if keyRepo != nil {
			key, ok = keyRepo.Verify(token)
		}
		if !ok {
			c.JSON(401, map[string]string{"error": "invalid or expired token"})
			c.Abort()
			return
		}
		c.Set("auth_user", key.Name)
		c.Set("auth_method", "api_key")
		c.Set("api_key_id", key.ID)
		c.Set("auth_role", auth.RoleAdmin) // API keys get admin role by default.
		c.Next(ctx)
	}
}

// RequireRole returns a middleware that checks if the authenticated user has one of the allowed roles.
// Usage: api.Use(RequireRole(auth.RoleAdmin, auth.RoleOperator))
func RequireRole(allowedRoles ...string) app.HandlerFunc {
	roleSet := make(map[string]bool, len(allowedRoles))
	for _, r := range allowedRoles {
		roleSet[r] = true
	}
	return func(ctx context.Context, c *app.RequestContext) {
		roleVal, exists := c.Get("auth_role")
		if !exists {
			c.JSON(403, map[string]string{"error": "access denied: no role"})
			c.Abort()
			return
		}
		role, _ := roleVal.(string)
		if !roleSet[role] {
			c.JSON(403, map[string]string{"error": "access denied: insufficient permissions"})
			c.Abort()
			return
		}
		c.Next(ctx)
	}
}

// AccessLog logs each admin API request with unified format.
func AccessLog(log *slog.Logger) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		reqID := uuid.NewString()
		c.Response.Header.Set("X-Request-ID", reqID)
		c.Set("request_id", reqID)

		start := time.Now()
		c.Next(ctx)
		latency := time.Since(start)

		authMethod, _ := c.Get("auth_method")
		log.Info("request",
			slog.String("request_id", reqID),
			slog.String("method", string(c.Method())),
			slog.String("path", string(c.Path())),
			slog.Int("status", c.Response.StatusCode()),
			slog.Duration("latency", latency),
			slog.Any("auth", authMethod),
		)
	}
}

func SecurityHeaders(holder *snapshot.Holder) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.Response.Header.Set("X-Content-Type-Options", "nosniff")
		c.Response.Header.Set("X-Frame-Options", "DENY")
		c.Response.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Response.Header.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		// 管理 API 的响应可能包含策略、日志和账号元数据，禁止浏览器及中间
		// 代理复用，认证接口也因此不会因遗漏单个 handler 而被缓存。
		if strings.HasPrefix(string(c.Path()), "/api/v1/") {
			c.Response.Header.Set("Cache-Control", "no-store")
		}
		c.Next(ctx)
		if strings.HasPrefix(string(c.Path()), "/api/v1/") {
			c.Response.Header.Set("Cache-Control", "no-store")
		}
		ensureAdminXSSProtection(c, holder)
		ensureAdminHPKP(c, holder)
		ensureAdminHPKPReportOnly(c, holder)
		ensureAdminStrictTransportSecurity(c, holder)
	}
}

func ensureAdminXSSProtection(c *app.RequestContext, holder *snapshot.Holder) {
	if !shouldWriteAdminXSSProtection(c, holder) {
		return
	}
	if len(c.Response.Header.Peek(adminXSSHeaderName)) != 0 {
		return
	}
	c.Response.Header.Set(adminXSSHeaderName, adminXSSHeaderValue)
}

func ensureAdminStrictTransportSecurity(c *app.RequestContext, holder *snapshot.Holder) {
	if !shouldWriteAdminStrictTransportSecurity(c, holder) {
		return
	}
	if len(c.Response.Header.Peek(adminHSTSHeaderName)) != 0 {
		return
	}
	c.Response.Header.Set(adminHSTSHeaderName, adminHSTSHeaderValue)
}

func ensureAdminHPKP(c *app.RequestContext, holder *snapshot.Holder) {
	if !shouldWriteAdminHPKP(c, holder) {
		return
	}
	if len(c.Response.Header.Peek(adminHPKPHeaderName)) != 0 {
		return
	}
	sn := holder.Load()
	if sn == nil {
		return
	}
	value := strings.TrimSpace(sn.HPKPValue)
	if value == "" {
		return
	}
	c.Response.Header.Set(adminHPKPHeaderName, value)
}

func ensureAdminHPKPReportOnly(c *app.RequestContext, holder *snapshot.Holder) {
	if !shouldWriteAdminHPKPReportOnly(c, holder) {
		return
	}
	if len(c.Response.Header.Peek(adminHPKPReportOnlyHeaderName)) != 0 {
		return
	}
	sn := holder.Load()
	if sn == nil {
		return
	}
	value := strings.TrimSpace(sn.HPKPReportOnlyValue)
	if value == "" {
		return
	}
	c.Response.Header.Set(adminHPKPReportOnlyHeaderName, value)
}

func shouldWriteAdminXSSProtection(c *app.RequestContext, holder *snapshot.Holder) bool {
	if holder == nil {
		return false
	}
	sn := holder.Load()
	return sn != nil && sn.XSSProtectionEnabled && c.Response.StatusCode() > 0
}

func shouldWriteAdminStrictTransportSecurity(c *app.RequestContext, holder *snapshot.Holder) bool {
	if holder == nil {
		return false
	}
	sn := holder.Load()
	if sn == nil || !sn.HSTSEnabled {
		return false
	}
	if c.Response.StatusCode() <= 0 {
		return false
	}
	switch adminRequestProtocol(c) {
	case "https", "h3":
		return true
	default:
		return false
	}
}

func shouldWriteAdminHPKP(c *app.RequestContext, holder *snapshot.Holder) bool {
	if holder == nil {
		return false
	}
	sn := holder.Load()
	if sn == nil || !sn.HPKPEnabled {
		return false
	}
	if c.Response.StatusCode() <= 0 {
		return false
	}
	switch adminRequestProtocol(c) {
	case "https", "h3":
		return true
	default:
		return false
	}
}

func shouldWriteAdminHPKPReportOnly(c *app.RequestContext, holder *snapshot.Holder) bool {
	if holder == nil {
		return false
	}
	sn := holder.Load()
	if sn == nil || !sn.HPKPReportOnlyEnabled {
		return false
	}
	if c.Response.StatusCode() <= 0 {
		return false
	}
	switch adminRequestProtocol(c) {
	case "https", "h3":
		return true
	default:
		return false
	}
}

func adminRequestProtocol(c *app.RequestContext) string {
	if proto := security.TrustedInboundForwardedProto(c); proto == "https" || proto == "h3" {
		return proto
	}
	directIP := security.ResolveClientIP(c, store.XFFModeStrip, "", nil)
	if directIP != nil && directIP.IsLoopback() {
		switch strings.ToLower(strings.TrimSpace(string(c.GetHeader("X-Forwarded-Proto")))) {
		case "https":
			return "https"
		case "h3":
			return "h3"
		case "http":
			return "http"
		}
	}
	if scheme := strings.TrimSpace(string(c.URI().Scheme())); scheme != "" {
		return strings.ToLower(scheme)
	}
	return "http"
}
