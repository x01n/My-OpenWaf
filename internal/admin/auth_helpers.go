package admin

import (
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/protocol"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

// refreshCookieName 是管理端 refresh-token Cookie 名。
const refreshCookieName = "my_openwaf_rt"

// refreshCookieSeparator 在 Cookie 值内连接服务端 JTI 与原始令牌。
// 用点号可让取值免于百分号编码：hertz 写 Cookie 时走 url.QueryEscape，
// 读回时却原样不解码，因此任何会被 QueryEscape 就地改写的分隔符
// （例如冒号会变成 %3A）都无法往返，刷新时会一律报 "malformed refresh token"。
const refreshCookieSeparator = '.'

// setRefreshCookie 写入轮换中的 refresh-token Cookie。
// Path 为 "/"，保证包括 refresh 在内的所有请求都会带上该 Cookie。
// Secure 标志跟随已认证的连接协议，或回环反向代理的场景。
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

// refreshCookieLegacyEscapedSeparator 描述分隔符变更之前登录的浏览器仍会携带的形态：
// hertz 写入时把冒号转义了，所以存下来的 Cookie 字面读作 "<jti>%3A<raw>"。
// JTI 与原始令牌都是十六进制，因此这个标记只可能是分隔符。
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

// recordLoginAttempt 异步持久化一次登录尝试，用于审计。
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
