package admin

import (
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

// setRefreshCookie writes the rotating refresh-token cookie.
// Secure flag only when request came over TLS; otherwise browsers reject the cookie on HTTP.
func setRefreshCookie(c *app.RequestContext, value string, ttl time.Duration) {
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
