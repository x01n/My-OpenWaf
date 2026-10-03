package admin

import (
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

// refreshCookieName is the admin refresh-token cookie.
const refreshCookieName = "my_openwaf_rt"

// refreshCookieSeparator joins the server-side JTI with the raw token inside the
// cookie value. A dot keeps the value percent-encoding free: hertz writes the
// cookie through url.QueryEscape but reads it back verbatim without decoding, so
// a separator that QueryEscape rewrites in place (a colon becomes %3A) can never
// round-trip and every refresh attempt fails with "malformed refresh token".
const refreshCookieSeparator = '.'

// setRefreshCookie writes the rotating refresh-token cookie.
// Path is "/" to ensure the cookie is sent on all requests including refresh.
// Secure flag follows the authenticated connection protocol or a loopback reverse proxy.
func setRefreshCookie(c *app.RequestContext, value string, ttl time.Duration) {
	proto := adminRequestProtocol(c)
	isSecure := proto == "https" || proto == "h3"
	c.SetCookie(refreshCookieName, value, int(ttl.Seconds()), "/", "",
		protocol.CookieSameSiteLaxMode, isSecure, true)
}

func clearRefreshCookie(c *app.RequestContext) {
	proto := adminRequestProtocol(c)
	isSecure := proto == "https" || proto == "h3"
	c.SetCookie(refreshCookieName, "", -1, "/", "",
		protocol.CookieSameSiteLaxMode, isSecure, true)
}

func setAuthNoStore(c *app.RequestContext) {
	c.Response.Header.Set("Cache-Control", "no-store")
}

// refreshCookieLegacyEscapedSeparator is how a browser that logged in before the
// separator change still carries the value: hertz escaped the colon on write, so
// the stored cookie literally reads "<jti>%3A<raw>". JTI and raw token are both
// hex, so the marker can only ever be the separator.
const refreshCookieLegacyEscapedSeparator = "%3A"

func splitRefreshCookie(val string) (jti, raw string, ok bool) {
	// 兼容旧格式：登录时间早于分隔符变更的浏览器仍持有 "jti%3Araw"，
	// 没有这个分支这些会话会从「可用」变成强制重新登录。
	if i := strings.Index(val, refreshCookieLegacyEscapedSeparator); i >= 0 {
		return val[:i], val[i+len(refreshCookieLegacyEscapedSeparator):], true
	}
	for i := 0; i < len(val); i++ {
		if val[i] == refreshCookieSeparator {
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
