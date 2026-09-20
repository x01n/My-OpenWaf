package security

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

var (
	forwardedProtoHTTPValues  = []string{"http"}
	forwardedProtoHTTPSValues = []string{"https"}
)

const trustedInboundHTTP3ContextKey = "security_trusted_inbound_http3"

// MarkTrustedInboundHTTP3 records that the data plane authenticated HTTP/3 loopback metadata.
func MarkTrustedInboundHTTP3(c *app.RequestContext) {
	if c != nil {
		c.Set(trustedInboundHTTP3ContextKey, true)
	}
}

func trustedInboundHTTP3(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	value, ok := c.Get(trustedInboundHTTP3ContextKey)
	marked, ok := value.(bool)
	return ok && marked
}

// RebuildOutboundForwardingHeaders replaces client-supplied forwarding identity headers.
func RebuildOutboundForwardingHeaders(headers http.Header, clientIP net.IP, origHost string, preserveOriginalHost bool, proto string) {
	for key := range headers {
		switch {
		case strings.EqualFold(key, "Forwarded"),
			strings.EqualFold(key, "X-Forwarded-For"),
			strings.EqualFold(key, "X-Forwarded-Host"),
			strings.EqualFold(key, "X-Forwarded-Proto"):
			delete(headers, key)
		}
	}

	if clientIP != nil {
		headers.Set("X-Forwarded-For", clientIP.String())
	}
	if proto != "" {
		headers["X-Forwarded-Proto"] = forwardedProtoHeaderValues(proto)
	}
	if preserveOriginalHost && origHost != "" {
		headers.Set("X-Forwarded-Host", origHost)
	}
}

// TrustedInboundForwardedProto reports the scheme negotiated on the client connection.
func TrustedInboundForwardedProto(c *app.RequestContext) string {
	if trustedInboundHTTP3(c) {
		return "h3"
	}
	if c != nil {
		if conn := c.GetConn(); conn != nil {
			if tlsConn, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok && tlsConn.ConnectionState().Version != 0 {
				return "https"
			}
		}
	}
	return "http"
}

// ApplyOutboundForwarding rebuilds forwarding identity headers and sets the outbound Host.
func ApplyOutboundForwarding(out *http.Request, clientIP net.IP, origHost string, preserveOriginalHost bool, upstreamHost string, proto string) {
	RebuildOutboundForwardingHeaders(out.Header, clientIP, origHost, preserveOriginalHost, proto)
	if upstreamHost != "" {
		out.Host = upstreamHost
	} else if origHost != "" && preserveOriginalHost {
		out.Host = origHost
	}
}

func forwardedProtoHeaderValues(proto string) []string {
	switch proto {
	case "http":
		return forwardedProtoHTTPValues
	case "https":
		return forwardedProtoHTTPSValues
	default:
		return []string{proto}
	}
}
