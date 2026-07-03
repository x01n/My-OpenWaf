package security

import (
	"net"
	"net/http"
)

var (
	forwardedProtoHTTPValues  = []string{"http"}
	forwardedProtoHTTPSValues = []string{"https"}
	forwardedProtoH3Values    = []string{"h3"}
)

// ApplyOutboundForwarding sets XFF / Host on the outgoing request to origin.
func ApplyOutboundForwarding(out *http.Request, clientIP net.IP, origHost string, preserveOriginalHost bool, upstreamHost string, proto string) {
	if clientIP != nil {
		if prior := ForwardedForHeaderValue(out.Header.Values("X-Forwarded-For")); prior != "" {
			out.Header["X-Forwarded-For"] = []string{prior + ", " + clientIP.String()}
		} else {
			out.Header["X-Forwarded-For"] = []string{clientIP.String()}
		}
	}
	if proto != "" {
		out.Header["X-Forwarded-Proto"] = forwardedProtoHeaderValues(proto)
	}
	if upstreamHost != "" {
		out.Host = upstreamHost
	} else if origHost != "" && preserveOriginalHost {
		out.Host = origHost
	}
	if origHost != "" && preserveOriginalHost {
		out.Header["X-Forwarded-Host"] = []string{origHost}
	}
}

func forwardedProtoHeaderValues(proto string) []string {
	switch proto {
	case "http":
		return forwardedProtoHTTPValues
	case "https":
		return forwardedProtoHTTPSValues
	case "h3":
		return forwardedProtoH3Values
	default:
		return []string{proto}
	}
}
