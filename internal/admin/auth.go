package admin

import (
	"context"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/store/repository"

	"gorm.io/gorm"
)

// AuthDeps wires the dependencies needed by all auth-related handlers
// (login/refresh/logout/me and session management).
type AuthDeps struct {
	AccountRepo *repository.AdminAccountRepo
	RTRepo      *repository.RefreshTokenRepo
	JWTSecret   []byte
	TokenMgr    *auth.TokenManager
	BruteForce  *auth.BruteForceDetector
	SessionMgr  *auth.SessionManager
	DB          *gorm.DB
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func LoginHandler(d *AuthDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var body loginReq
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		clientIP := string(c.ClientIP())
		userAgent := string(c.GetHeader("User-Agent"))

		// Check brute force lockout.
		if d.BruteForce != nil && d.BruteForce.IsLocked(clientIP, body.Username) {
			remaining := d.BruteForce.LockoutRemaining(clientIP, body.Username)
			c.JSON(429, map[string]any{
				"error":            "account temporarily locked due to too many failed attempts",
				"retry_after_secs": int(remaining.Seconds()),
			})
			recordLoginAttempt(d.DB, body.Username, clientIP, userAgent, false)
			return
		}

		acct, ok := d.AccountRepo.VerifyPassword(body.Username, body.Password)
		if !ok {
			if d.BruteForce != nil {
				d.BruteForce.RecordFailure(clientIP, body.Username)
			}
			recordLoginAttempt(d.DB, body.Username, clientIP, userAgent, false)

			remaining := 0
			if d.BruteForce != nil {
				remaining = d.BruteForce.RemainingAttempts(clientIP, body.Username)
			}
			resp := map[string]any{"error": "invalid credentials"}
			if remaining > 0 && remaining <= 3 {
				resp["remaining_attempts"] = remaining
			}
			c.JSON(401, resp)
			return
		}

		// Login successful — clear brute force counter.
		if d.BruteForce != nil {
			d.BruteForce.RecordSuccess(clientIP, body.Username)
		}
		recordLoginAttempt(d.DB, acct.Username, clientIP, userAgent, true)

		// Determine role (default admin for backward compat if role column empty).
		role := acct.Role
		if role == "" {
			role = auth.RoleAdmin
		}

		var accessToken string
		var accessJTI string
		var accessExp time.Time
		var err error

		if d.TokenMgr != nil {
			accessToken, accessJTI, accessExp, err = d.TokenMgr.SignAccessToken(acct.Username, role, clientIP, userAgent)
		} else {
			accessToken, accessExp, err = auth.SignAccessToken(acct.Username, d.JWTSecret)
		}
		if err != nil {
			c.JSON(500, map[string]string{"error": "token generation failed"})
			return
		}

		jti, rawRT, hashRT, err := auth.GenerateRefreshToken()
		if err != nil {
			c.JSON(500, map[string]string{"error": "token generation failed"})
			return
		}
		if _, err := d.RTRepo.Create(jti, hashRT, acct.Username, string(role), time.Now().Add(auth.RefreshTTL)); err != nil {
			c.JSON(500, map[string]string{"error": "token storage failed"})
			return
		}

		if d.SessionMgr != nil && accessJTI != "" {
			d.SessionMgr.CreateSession(acct.Username, accessJTI, clientIP, userAgent, "", accessExp)
		}

		setRefreshCookie(c, jti+":"+rawRT, auth.RefreshTTL)
		c.JSON(200, map[string]any{
			"access_token": accessToken,
			"expires_at":   accessExp.Unix(),
			"username":     acct.Username,
			"role":         role,
		})
	}
}

func RefreshHandler(d *AuthDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cookie := string(c.Cookie("my_openwaf_rt"))
		if cookie == "" {
			c.JSON(401, map[string]string{"error": "missing refresh token"})
			return
		}

		jti, rawToken, ok := splitRefreshCookie(cookie)
		if !ok {
			c.JSON(401, map[string]string{"error": "malformed refresh token"})
			return
		}

		rt, err := d.RTRepo.FindByJTI(jti)
		if err != nil || rt == nil {
			c.JSON(401, map[string]string{"error": "refresh token expired or revoked"})
			return
		}
		if auth.HashToken(rawToken) != rt.TokenHash {
			c.JSON(401, map[string]string{"error": "invalid refresh token"})
			return
		}

		clientIP := string(c.ClientIP())
		userAgent := string(c.GetHeader("User-Agent"))
		role := rt.Role
		username := rt.Username
		if role == "" {
			role = auth.RoleAdmin
		}
		if username == "" {
			username = "admin"
		}

		// Rotate: revoke old, issue new.
		newJTI, newRaw, newHash, err := auth.GenerateRefreshToken()
		if err != nil {
			c.JSON(500, map[string]string{"error": "token generation failed"})
			return
		}
		_ = d.RTRepo.Revoke(jti, newJTI)
		if _, err := d.RTRepo.Create(newJTI, newHash, username, role, time.Now().Add(auth.RefreshTTL)); err != nil {
			c.JSON(500, map[string]string{"error": "token storage failed"})
			return
		}

		var accessToken string
		var accessJTI string
		var accessExp time.Time

		if d.TokenMgr != nil {
			accessToken, accessJTI, accessExp, err = d.TokenMgr.SignAccessToken(username, role, clientIP, userAgent)
		} else {
			accessToken, accessExp, err = auth.SignAccessToken(username, d.JWTSecret)
		}
		if err != nil {
			c.JSON(500, map[string]string{"error": "token generation failed"})
			return
		}

		if d.SessionMgr != nil && accessJTI != "" {
			d.SessionMgr.CreateSession(username, accessJTI, clientIP, userAgent, "", accessExp)
		}

		setRefreshCookie(c, newJTI+":"+newRaw, auth.RefreshTTL)
		c.JSON(200, map[string]any{
			"access_token": accessToken,
			"expires_at":   accessExp.Unix(),
			"username":     username,
			"role":         role,
		})
	}
}

func LogoutHandler(d *AuthDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		// Revoke refresh token.
		cookie := string(c.Cookie("my_openwaf_rt"))
		if cookie != "" {
			if jti, _, ok := splitRefreshCookie(cookie); ok {
				_ = d.RTRepo.Revoke(jti, "")
			}
		}

		// Blacklist access token JTI.
		// Logout is outside auth middleware, so parse the token here directly.
		if d.TokenMgr != nil {
			if header := strings.TrimSpace(string(c.GetHeader("Authorization"))); header != "" {
				if token := strings.TrimPrefix(header, "Bearer "); token != header {
					if claims, err := d.TokenMgr.VerifyAccessToken(token); err == nil && claims.ID != "" {
						d.TokenMgr.BlacklistToken(claims.ID, time.Now().Add(auth.AccessTTL), "logout")
						if d.SessionMgr != nil {
							d.SessionMgr.RemoveSession(claims.ID)
						}
					}
				}
			}
		}

		clearRefreshCookie(c)
		c.JSON(200, map[string]string{"status": "ok"})
	}
}

func MeHandler(d *AuthDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		username, _ := c.Get("auth_user")
		role, _ := c.Get("auth_role")
		c.JSON(200, map[string]any{
			"username": username,
			"role":     role,
		})
	}
}

func ChangeOwnPasswordHandler(d *AuthDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		usernameVal, _ := c.Get("auth_user")
		username, _ := usernameVal.(string)
		if username == "" {
			c.JSON(401, map[string]string{"error": "unauthorized"})
			return
		}

		var body struct {
			OldPassword string `json:"old_password"`
			NewPassword string `json:"new_password"`
		}
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		if body.OldPassword == "" || body.NewPassword == "" {
			c.JSON(400, map[string]string{"error": "old_password and new_password are required"})
			return
		}
		if len(body.NewPassword) < 8 {
			c.JSON(400, map[string]string{"error": "new password must be at least 8 characters"})
			return
		}

		if _, ok := d.AccountRepo.VerifyPassword(username, body.OldPassword); !ok {
			c.JSON(403, map[string]string{"error": "current password is incorrect"})
			return
		}

		if err := d.AccountRepo.UpdatePassword(username, body.NewPassword); err != nil {
			c.JSON(500, map[string]string{"error": "failed to update password"})
			return
		}
		c.JSON(200, map[string]string{"status": "ok"})
	}
}
