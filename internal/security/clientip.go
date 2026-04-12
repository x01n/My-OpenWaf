package security

import (
	"net"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
)

// ResolveClientIP applies forwarding profile XFF semantics for WAF decisions.
func ResolveClientIP(c *app.RequestContext, fwd *store.ForwardingProfile) net.IP {
	remoteHost, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		remoteHost = c.RemoteAddr().String()
	}
	direct := net.ParseIP(remoteHost)
	if direct == nil {
		return nil
	}

	mode := store.XFFModeStrip
	if fwd != nil && fwd.XFFMode != "" {
		mode = fwd.XFFMode
	}

	switch mode {
	case store.XFFModeStrip:
		return direct
	case store.XFFModeTrustOuter:
		if fwd == nil || !remoteInTrustedCIDR(direct, fwd.TrustedCIDR) {
			return direct
		}
		xff := strings.TrimSpace(c.Request.Header.Get("X-Forwarded-For"))
		if xff == "" {
			return direct
		}
		parts := strings.Split(xff, ",")
		for _, p := range parts {
			ip := net.ParseIP(strings.TrimSpace(p))
			if ip != nil {
				return ip
			}
		}
		return direct
	default:
		return direct
	}
}

func remoteInTrustedCIDR(ip net.IP, raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	for _, line := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';'
	}) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_, n, err := net.ParseCIDR(line)
		if err != nil {
			single := net.ParseIP(line)
			if single == nil {
				continue
			}
			if single.Equal(ip) {
				return true
			}
			continue
		}
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
