package security

import (
	"net"
	"net/http"
	"strings"
)

// ApplyOutboundForwarding sets XFF / Host on the outgoing request to origin.
func ApplyOutboundForwarding(out *http.Request, clientIP net.IP, origHost string, preserveOriginalHost bool, proto string) {
	if clientIP != nil {
		if prior := strings.TrimSpace(out.Header.Get("X-Forwarded-For")); prior != "" {
			out.Header.Set("X-Forwarded-For", prior+", "+clientIP.String())
		} else {
			out.Header.Set("X-Forwarded-For", clientIP.String())
		}
	}
	if proto != "" {
		out.Header.Set("X-Forwarded-Proto", proto)
	}
	if origHost != "" && preserveOriginalHost {
		out.Host = origHost
		out.Header.Set("X-Forwarded-Host", origHost)
	}
}
