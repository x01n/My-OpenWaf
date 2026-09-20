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
		setAuthNoStore(c)
		if d == nil || d.SessionMgr == nil {
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
		setAuthNoStore(c)
		type req struct {
			JTI string `json:"jti"`
		}
		var body req
		if err := c.BindJSON(&body); err != nil || body.JTI == "" {
			c.JSON(400, map[string]string{"error": "jti is required"})
			return
		}

		if d == nil || d.SessionMgr == nil {
			c.JSON(404, map[string]string{"error": "session not found"})
			return
		}

		session := d.SessionMgr.GetSession(body.JTI)
		refreshJTI := d.SessionMgr.RefreshTokenJTI(body.JTI)
		existed := d.SessionMgr.ForceLogout(body.JTI)
		if !existed {
			c.JSON(404, map[string]string{"error": "session not found"})
			return
		}

		if d.TokenMgr != nil {
			if err := d.TokenMgr.BlacklistTokenChecked(body.JTI, time.Now().Add(auth.AccessTTL), "force_logout"); err != nil {
				c.JSON(500, map[string]string{"error": "session removed but access token revocation failed"})
				return
			}
		}
		if session != nil && d.RTRepo != nil {
			if refreshJTI != "" {
				// 强制下线必须撤销完整轮换链；只撤销当前会话关联的旧 JTI
				// 会让已经完成 refresh 轮换的浏览器继续恢复登录。
				if err := d.RTRepo.RevokeFamily(refreshJTI); err != nil {
					c.JSON(500, map[string]string{"error": "session removed but refresh token revocation failed"})
					return
				}
			} else {
				// 兼容没有关联 refresh JTI 的旧会话：撤销该账号全部旧刷新令牌，
				// 防止强退后旧浏览器 cookie 立即重新建立访问令牌。
				if err := d.RTRepo.RevokeByUsername(session.Username); err != nil {
					c.JSON(500, map[string]string{"error": "session removed but refresh token revocation failed"})
					return
				}
			}
		}

		c.JSON(200, map[string]string{"status": "ok"})
	}
}
