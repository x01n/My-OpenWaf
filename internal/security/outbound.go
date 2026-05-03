package security

import (
	"net"
	"net/http"
)

// ApplyOutboundForwarding sets XFF / Host on the outgoing request to origin.
func ApplyOutboundForwarding(out *http.Request, clientIP net.IP, origHost string, preserveOriginalHost bool) {
	if clientIP != nil {
		out.Header.Set("X-Forwarded-For", clientIP.String())
	}
	if origHost != "" && preserveOriginalHost {
		out.Host = origHost
		out.Header.Set("X-Forwarded-Host", origHost)
	}
}
