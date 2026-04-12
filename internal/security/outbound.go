package security

import (
	"net"
	"net/http"
	"strings"

	"My-OpenWaf/internal/store"
)

// ApplyOutboundForwarding sets XFF / Host on the outgoing request to origin.
func ApplyOutboundForwarding(out *http.Request, clientIP net.IP, origHost string, fwd *store.ForwardingProfile) {
	if clientIP != nil {
		out.Header.Set("X-Forwarded-For", clientIP.String())
	}
	if origHost != "" {
		if fwd != nil && fwd.PreserveOriginalHost {
			out.Header.Set("X-Forwarded-Host", origHost)
		}
	}
	if fwd != nil && strings.TrimSpace(fwd.OutboundHostRewrite) != "" {
		out.Host = strings.TrimSpace(fwd.OutboundHostRewrite)
		out.Header.Set("Host", out.Host)
	}
}
