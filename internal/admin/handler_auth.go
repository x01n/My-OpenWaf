package admin

import (
	"context"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"gorm.io/gorm"
)

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
			// Record login attempt to DB.
			recordLoginAttempt(d.DB, body.Username, clientIP, userAgent, false)
			return
		}

		acct, ok := d.AccountRepo.VerifyPassword(body.Username, body.Password)
		if !ok {
			// Record failure.
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

		// Determine role (default admin for now; extend with DB-based roles later).
		role := auth.RoleAdmin

		// Sign access token via TokenManager.
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

		// Create session.
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

		// Extract user identity from the old refresh token.
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

		// Create new session for refreshed token.
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
		if jtiVal, exists := c.Get("auth_jti"); exists {
			if jti, ok := jtiVal.(string); ok && jti != "" {
				if d.TokenMgr != nil {
					d.TokenMgr.BlacklistToken(jti, time.Now().Add(auth.AccessTTL), "logout")
				}
				// Remove session.
				if d.SessionMgr != nil {
					d.SessionMgr.RemoveSession(jti)
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

// ─── Session Management Handlers ───────────────────────────────────

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
		// Query param to list all sessions (admin only).
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

		// Blacklist the token.
		if d.TokenMgr != nil {
			d.TokenMgr.BlacklistToken(body.JTI, time.Now().Add(auth.AccessTTL), "force_logout")
		}

		c.JSON(200, map[string]string{"status": "ok"})
	}
}

// ── cookie helpers ──

func setRefreshCookie(c *app.RequestContext, value string, ttl time.Duration) {
	// Secure flag only when request came over TLS; otherwise browsers reject the cookie on HTTP.
	isSecure := string(c.URI().Scheme()) == "https"
	c.SetCookie("my_openwaf_rt", value, int(ttl.Seconds()), "/api/v1/auth", "",
		protocol.CookieSameSiteLaxMode, isSecure, true)
}

func clearRefreshCookie(c *app.RequestContext) {
	isSecure := string(c.URI().Scheme()) == "https"
	c.SetCookie("my_openwaf_rt", "", -1, "/api/v1/auth", "",
		protocol.CookieSameSiteLaxMode, isSecure, true)
}

func splitRefreshCookie(val string) (jti, raw string, ok bool) {
	for i := 0; i < len(val); i++ {
		if val[i] == ':' {
			return val[:i], val[i+1:], true
		}
	}
	return "", "", false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ── DB helpers ──

func recordLoginAttempt(db *gorm.DB, username, ip, userAgent string, success bool) {
	if db == nil {
		return
	}
	db.Create(&store.LoginAttempt{
		Username:  username,
		IP:        ip,
		Success:   success,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
	})
}
