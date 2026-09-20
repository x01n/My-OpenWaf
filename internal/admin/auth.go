package admin

import (
	"context"
	"errors"
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
		setAuthNoStore(c)
		if d == nil || d.AccountRepo == nil || d.RTRepo == nil {
			c.JSON(503, map[string]string{"error": "authentication service unavailable"})
			return
		}
		var body loginReq
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
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
			accessToken, accessExp, err = auth.SignAccessTokenWithRole(acct.Username, role, d.JWTSecret)
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
		_ = d.RTRepo.CleanExpired(64)

		if d.SessionMgr != nil && accessJTI != "" {
			d.SessionMgr.CreateSessionWithRefresh(acct.Username, accessJTI, jti, clientIP, userAgent, "", accessExp)
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
		setAuthNoStore(c)
		if d == nil || d.AccountRepo == nil || d.RTRepo == nil {
			c.JSON(503, map[string]string{"error": "authentication service unavailable"})
			return
		}
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
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(401, map[string]string{"error": "refresh token expired or revoked"})
				return
			}
			// 仓储暂时不可用不等于 refresh 凭据失效；返回服务不可用，
			// 让客户端保留当前 access token 并稍后重试。
			c.JSON(503, map[string]string{"error": "authentication service unavailable"})
			return
		}
		if rt == nil {
			c.JSON(401, map[string]string{"error": "refresh token expired or revoked"})
			return
		}
		if auth.HashToken(rawToken) != rt.TokenHash {
			c.JSON(401, map[string]string{"error": "invalid refresh token"})
			return
		}

		username := rt.Username
		if username == "" {
			username = "admin"
		}
		acct, err := d.AccountRepo.GetByUsername(username)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 账号已删除时也必须撤销完整轮换链，不能留下旧 JTI 的后继
			// refresh token 供浏览器在删除账号后继续恢复会话。
			_ = d.RTRepo.RevokeFamily(jti)
			clearRefreshCookie(c)
			c.JSON(401, map[string]string{"error": "refresh token account no longer exists"})
			return
		}
		if err != nil {
			c.JSON(500, map[string]string{"error": "account lookup failed"})
			return
		}
		role := acct.Role
		if role == "" {
			role = auth.RoleAdmin
		}

		clientIP := string(c.ClientIP())
		userAgent := string(c.GetHeader("User-Agent"))
		var accessToken string
		var accessJTI string
		var accessExp time.Time

		if d.TokenMgr != nil {
			accessToken, accessJTI, accessExp, err = d.TokenMgr.SignAccessToken(username, role, clientIP, userAgent)
		} else {
			accessToken, accessExp, err = auth.SignAccessTokenWithRole(username, role, d.JWTSecret)
		}
		if err != nil {
			c.JSON(500, map[string]string{"error": "token generation failed"})
			return
		}

		newJTI, newRaw, newHash, err := auth.GenerateRefreshToken()
		if err != nil {
			c.JSON(500, map[string]string{"error": "token generation failed"})
			return
		}
		if _, err := d.RTRepo.Rotate(jti, newJTI, newHash, username, role, time.Now().Add(auth.RefreshTTL)); err != nil {
			if errors.Is(err, repository.ErrRefreshTokenUnavailable) {
				// 旧 refresh 可能已经被另一标签页成功轮换。此时不能
				// 用失败请求的 Set-Cookie 清除共享 cookie 中的新令牌。
				// 客户端会按 401 处理当前会话，后续登录或成功轮换会
				// 正常覆盖失效令牌。
				c.JSON(401, map[string]string{"error": "refresh token expired or revoked"})
				return
			}
			c.JSON(500, map[string]string{"error": "token storage failed"})
			return
		}
		_ = d.RTRepo.CleanExpired(64)

		if d.SessionMgr != nil && accessJTI != "" {
			if !d.SessionMgr.ReplaceSessionForRefresh(jti, accessJTI, newJTI, clientIP, userAgent, "", accessExp) {
				d.SessionMgr.CreateSessionWithRefresh(username, accessJTI, newJTI, clientIP, userAgent, "", accessExp)
			}
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
		setAuthNoStore(c)
		if d == nil {
			clearRefreshCookie(c)
			c.JSON(200, map[string]string{"status": "ok"})
			return
		}
		// 撤销完整的 refresh 令牌轮换链。浏览器发起访问请求到登出之间，
		// refresh 请求可能已经轮换 Cookie；只撤销请求中的 JTI 会留下可用
		// 的后继令牌，页面重载后仍可能恢复会话。
		var refreshRevokeErr error
		cookie := string(c.Cookie("my_openwaf_rt"))
		if cookie != "" && d.RTRepo != nil {
			if jti, _, ok := splitRefreshCookie(cookie); ok {
				refreshRevokeErr = d.RTRepo.RevokeFamily(jti)
			}
		}
		if refreshRevokeErr != nil {
			clearRefreshCookie(c)
			c.JSON(500, map[string]string{"error": "logout failed to revoke refresh token"})
			return
		}

		// Blacklist access token JTI.
		// Logout is outside auth middleware, so parse the token here directly.
		if d.TokenMgr != nil {
			var blacklistErr error
			if header := strings.TrimSpace(string(c.GetHeader("Authorization"))); header != "" {
				if token := strings.TrimPrefix(header, "Bearer "); token != header {
					if claims, err := d.TokenMgr.VerifyAccessToken(token); err == nil && claims.ID != "" {
						blacklistErr = d.TokenMgr.BlacklistTokenChecked(claims.ID, time.Now().Add(auth.AccessTTL), "logout")
						if d.SessionMgr != nil {
							d.SessionMgr.RemoveSession(claims.ID)
						}
					}
				}
			}
			if blacklistErr != nil {
				clearRefreshCookie(c)
				c.JSON(500, map[string]string{"error": "logout completed but access token revocation failed"})
				return
			}
		}

		clearRefreshCookie(c)
		c.JSON(200, map[string]string{"status": "ok"})
	}
}

func MeHandler(d *AuthDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		setAuthNoStore(c)
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
		setAuthNoStore(c)
		if d == nil || d.AccountRepo == nil {
			c.JSON(503, map[string]string{"error": "authentication service unavailable"})
			return
		}
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
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
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
		clearRefreshCookie(c)
		if err := revokeUserCredentials(d, username, "password_changed"); err != nil {
			c.JSON(500, map[string]string{"error": "password changed but credential revocation failed"})
			return
		}
		c.JSON(200, map[string]string{"status": "ok"})
	}
}
