package admin

import (
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

// setRefreshCookie writes the rotating refresh-token cookie.
// Path is "/" to ensure the cookie is sent on all requests including refresh.
// Secure flag follows the authenticated connection protocol or a loopback reverse proxy.
func setRefreshCookie(c *app.RequestContext, value string, ttl time.Duration) {
	proto := adminRequestProtocol(c)
	isSecure := proto == "https" || proto == "h3"
	c.SetCookie("my_openwaf_rt", value, int(ttl.Seconds()), "/", "",
		protocol.CookieSameSiteLaxMode, isSecure, true)
}

func clearRefreshCookie(c *app.RequestContext) {
	proto := adminRequestProtocol(c)
	isSecure := proto == "https" || proto == "h3"
	c.SetCookie("my_openwaf_rt", "", -1, "/", "",
		protocol.CookieSameSiteLaxMode, isSecure, true)
}

func setAuthNoStore(c *app.RequestContext) {
	c.Response.Header.Set("Cache-Control", "no-store")
}

func splitRefreshCookie(val string) (jti, raw string, ok bool) {
	for i := 0; i < len(val); i++ {
		if val[i] == ':' {
			return val[:i], val[i+1:], true
		}
	}
	return "", "", false
}

// recordLoginAttempt asynchronously persists a login attempt for audit.
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
