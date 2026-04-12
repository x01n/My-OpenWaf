package admin

import (
	"context"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/store/repository"
)

type AuthDeps struct {
	AccountRepo *repository.AdminAccountRepo
	RTRepo      *repository.RefreshTokenRepo
	JWTSecret   []byte
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
		acct, ok := d.AccountRepo.VerifyPassword(body.Username, body.Password)
		if !ok {
			c.JSON(401, map[string]string{"error": "invalid credentials"})
			return
		}

		accessToken, accessExp, err := auth.SignAccessToken(acct.Username, d.JWTSecret)
		if err != nil {
			c.JSON(500, map[string]string{"error": "token generation failed"})
			return
		}

		jti, rawRT, hashRT, err := auth.GenerateRefreshToken()
		if err != nil {
			c.JSON(500, map[string]string{"error": "token generation failed"})
			return
		}
		if _, err := d.RTRepo.Create(jti, hashRT, time.Now().Add(auth.RefreshTTL)); err != nil {
			c.JSON(500, map[string]string{"error": "token storage failed"})
			return
		}

		setRefreshCookie(c, jti+":"+rawRT, auth.RefreshTTL)
		c.JSON(200, map[string]any{
			"access_token": accessToken,
			"expires_at":   accessExp.Unix(),
			"username":     acct.Username,
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

		// Rotate: revoke old, issue new.
		newJTI, newRaw, newHash, err := auth.GenerateRefreshToken()
		if err != nil {
			c.JSON(500, map[string]string{"error": "token generation failed"})
			return
		}
		_ = d.RTRepo.Revoke(jti, newJTI)
		if _, err := d.RTRepo.Create(newJTI, newHash, time.Now().Add(auth.RefreshTTL)); err != nil {
			c.JSON(500, map[string]string{"error": "token storage failed"})
			return
		}

		accessToken, accessExp, err := auth.SignAccessToken("admin", d.JWTSecret)
		if err != nil {
			c.JSON(500, map[string]string{"error": "token generation failed"})
			return
		}

		setRefreshCookie(c, newJTI+":"+newRaw, auth.RefreshTTL)
		c.JSON(200, map[string]any{
			"access_token": accessToken,
			"expires_at":   accessExp.Unix(),
			"username":     "admin",
		})
	}
}

func LogoutHandler(d *AuthDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cookie := string(c.Cookie("my_openwaf_rt"))
		if cookie != "" {
			if jti, _, ok := splitRefreshCookie(cookie); ok {
				_ = d.RTRepo.Revoke(jti, "")
			}
		}
		clearRefreshCookie(c)
		c.JSON(200, map[string]string{"status": "ok"})
	}
}

func MeHandler(d *AuthDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		username, _ := c.Get("auth_user")
		c.JSON(200, map[string]any{"username": username})
	}
}

// ── cookie helpers ──

func setRefreshCookie(c *app.RequestContext, value string, ttl time.Duration) {
	c.SetCookie("my_openwaf_rt", value, int(ttl.Seconds()), "/api/v1/auth", "",
		protocol.CookieSameSiteLaxMode, false, true)
}

func clearRefreshCookie(c *app.RequestContext) {
	c.SetCookie("my_openwaf_rt", "", -1, "/api/v1/auth", "",
		protocol.CookieSameSiteLaxMode, false, true)
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
