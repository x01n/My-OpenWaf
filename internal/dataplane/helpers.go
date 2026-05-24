package dataplane

import (
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/waf/challenge"
)

// isStaticAsset returns true for common static asset paths that should skip nonce validation.
func isStaticAsset(lowerPath string) bool {
	staticExts := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map"}
	for _, ext := range staticExts {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	staticPrefixes := []string{"/static/", "/assets/", "/public/", "/favicon"}
	for _, prefix := range staticPrefixes {
		if strings.HasPrefix(lowerPath, prefix) {
			return true
		}
	}
	return false
}

// setNonceCookie sets the anti-replay nonce cookie on the response.
func setNonceCookie(c *app.RequestContext, nonce string, secure bool) {
	cookie := challenge.NonceKey + "=" + nonce + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400"
	if secure {
		cookie += "; Secure"
	}
	c.Response.Header.Add("Set-Cookie", cookie)
}
