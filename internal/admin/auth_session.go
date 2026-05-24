package admin

import (
	"context"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/auth"
)

// ListSessionsHandler returns active sessions for the current user (or all for admin).
func ListSessionsHandler(d *AuthDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		if d.SessionMgr == nil {
			c.JSON(200, map[string]any{"sessions": []any{}})
			return
		}

		roleVal, _ := c.Get("auth_role")
		role, _ := roleVal.(string)
		usernameVal, _ := c.Get("auth_user")
		username, _ := usernameVal.(string)

		var sessions []auth.SessionInfo
		if c.Query("all") == "true" && role == auth.RoleAdmin {
			sessions = d.SessionMgr.ListAllSessions()
		} else {
			sessions = d.SessionMgr.ListUserSessions(username)
		}

		c.JSON(200, map[string]any{"sessions": sessions})
	}
}

// ForceLogoutSessionHandler forcibly terminates a specific session by JTI.
func ForceLogoutSessionHandler(d *AuthDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		type req struct {
			JTI string `json:"jti"`
		}
		var body req
		if err := c.BindJSON(&body); err != nil || body.JTI == "" {
			c.JSON(400, map[string]string{"error": "jti is required"})
			return
		}

		if d.SessionMgr == nil {
			c.JSON(404, map[string]string{"error": "session not found"})
			return
		}

		existed := d.SessionMgr.ForceLogout(body.JTI)
		if !existed {
			c.JSON(404, map[string]string{"error": "session not found"})
			return
		}

		if d.TokenMgr != nil {
			d.TokenMgr.BlacklistToken(body.JTI, time.Now().Add(auth.AccessTTL), "force_logout")
		}

		c.JSON(200, map[string]string{"status": "ok"})
	}
}
