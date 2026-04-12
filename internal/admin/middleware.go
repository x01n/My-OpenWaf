package admin

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/google/uuid"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/store/repository"
)

// AuthMiddleware supports JWT (Bearer) or API Key authentication.
// Whitelisted paths are skipped (health, auth endpoints).
func AuthMiddleware(keyRepo *repository.AdminAPIKeyRepo, jwtSecret []byte) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		path := string(c.Path())

		// Whitelist: health + auth endpoints
		if path == "/api/v1/health" ||
			strings.HasPrefix(path, "/api/v1/auth/") {
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

		// Try JWT first.
		if claims, err := auth.VerifyAccessToken(token, jwtSecret); err == nil {
			c.Set("auth_user", claims.Username)
			c.Set("auth_method", "jwt")
			c.Next(ctx)
			return
		}

		// Fallback: API Key.
		key, ok := keyRepo.Verify(token)
		if !ok {
			c.JSON(401, map[string]string{"error": "invalid or expired token"})
			c.Abort()
			return
		}
		c.Set("auth_user", key.Name)
		c.Set("auth_method", "api_key")
		c.Set("api_key_id", key.ID)
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

func SecurityHeaders() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.Response.Header.Set("X-Content-Type-Options", "nosniff")
		c.Response.Header.Set("X-Frame-Options", "DENY")
		c.Response.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Response.Header.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		c.Next(ctx)
	}
}
