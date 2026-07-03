package dataplane

import (
	"net"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/pipeline"
	"My-OpenWaf/internal/waf/bot"
)

const (
	InternalHTTP3ProtoHeader           = "X-OpenWaf-Internal-Proto"
	InternalHTTP3TLSVersionHeader      = "X-OpenWaf-Internal-TLS-Version"
	InternalHTTP3TLSSNIHeader          = "X-OpenWaf-Internal-TLS-SNI"
	InternalHTTP3TLSALPNHeader         = "X-OpenWaf-Internal-TLS-ALPN"
	InternalHTTP3TLSJA3Header          = "X-OpenWaf-Internal-TLS-JA3"
	InternalHTTP3TLSJA3HashHeader      = "X-OpenWaf-Internal-TLS-JA3-Hash"
	InternalHTTP3TLSJA4Header          = "X-OpenWaf-Internal-TLS-JA4"
	InternalHTTP3TLSCipherSuitesHeader = "X-OpenWaf-Internal-TLS-Cipher-Suites"
	InternalHTTP3TLSExtensionsHeader   = "X-OpenWaf-Internal-TLS-Extensions"
	InternalHTTP3TLSCurvesHeader       = "X-OpenWaf-Internal-TLS-Curves"
	InternalHTTP3TLSPointFormatsHeader = "X-OpenWaf-Internal-TLS-Point-Formats"

	internalHTTP3ContextKey = "dataplane_internal_http3"
)

// populateRequestCtxHeaders copies request headers into RequestCtx using
// lowercase keys only. HeaderKeys still preserves the original order and case
// for header-order fingerprinting and logging.
func populateRequestCtxHeaders(reqCtx *pipeline.RequestCtx, c *app.RequestContext) {
	reqCtx.HeadersLowercase = true
	c.Request.Header.VisitAll(func(k, v []byte) {
		key := string(k)
		lower := lowerRequestHeaderName(key)
		reqCtx.AppendHeaderKey(key)
		reqCtx.Headers[lower] = string(v)
	})
}

func lowerRequestHeaderName(name string) string {
	switch name {
	case "Accept":
		return "accept"
	case "Accept-Encoding":
		return "accept-encoding"
	case "Accept-Language":
		return "accept-language"
	case "Authorization":
		return "authorization"
	case "Cache-Control":
		return "cache-control"
	case "Connection":
		return "connection"
	case "Content-Length":
		return "content-length"
	case "Content-Type":
		return "content-type"
	case "Cookie":
		return "cookie"
	case "DNT":
		return "dnt"
	case "Host":
		return "host"
	case "If-Modified-Since":
		return "if-modified-since"
	case "If-None-Match":
		return "if-none-match"
	case "Origin":
		return "origin"
	case "Pragma":
		return "pragma"
	case "Referer":
		return "referer"
	case "Sec-Ch-Ua":
		return "sec-ch-ua"
	case "Sec-Ch-Ua-Arch":
		return "sec-ch-ua-arch"
	case "Sec-Ch-Ua-Bitness":
		return "sec-ch-ua-bitness"
	case "Sec-Ch-Ua-Full-Version":
		return "sec-ch-ua-full-version"
	case "Sec-Ch-Ua-Full-Version-List":
		return "sec-ch-ua-full-version-list"
	case "Sec-Ch-Ua-Mobile":
		return "sec-ch-ua-mobile"
	case "Sec-Ch-Ua-Model":
		return "sec-ch-ua-model"
	case "Sec-Ch-Ua-Platform":
		return "sec-ch-ua-platform"
	case "Sec-Ch-Ua-Platform-Version":
		return "sec-ch-ua-platform-version"
	case "Sec-Fetch-Dest":
		return "sec-fetch-dest"
	case "Sec-Fetch-Mode":
		return "sec-fetch-mode"
	case "Sec-Fetch-Site":
		return "sec-fetch-site"
	case "Sec-Fetch-User":
		return "sec-fetch-user"
	case "TE":
		return "te"
	case "Upgrade":
		return "upgrade"
	case "Upgrade-Insecure-Requests":
		return "upgrade-insecure-requests"
	case "User-Agent":
		return "user-agent"
	case "X-Client-Data":
		return "x-client-data"
	case "X-Forwarded-For":
		return "x-forwarded-for"
	case "X-Forwarded-Proto":
		return "x-forwarded-proto"
	case "X-Request-Id":
		return "x-request-id"
	}
	if isLowerASCIIRequestHeaderName(name) {
		return name
	}
	return strings.ToLower(name)
}

func isLowerASCIIRequestHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b >= 'A' && b <= 'Z' {
			return false
		}
		if b >= 0x80 {
			return false
		}
	}
	return true
}

func applyInternalHTTP3RequestMetadata(c *app.RequestContext) {
	if c == nil {
		return
	}
	proto := trimRequestHeaderValue(c.GetHeader(InternalHTTP3ProtoHeader))
	forwardedProto := trimRequestHeaderValue(c.GetHeader("X-Forwarded-Proto"))
	if !strings.EqualFold(proto, "h3") || !strings.EqualFold(forwardedProto, "h3") || !isLoopbackRemoteAddr(c) {
		clearInternalHTTP3RequestMetadataHeaders(c)
		return
	}

	version := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSVersionHeader))
	sni := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSSNIHeader))
	alpn := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSALPNHeader))
	ja3 := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSJA3Header))
	ja3Hash := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSJA3HashHeader))
	ja4 := trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSJA4Header))
	cipherSuites := parseInternalHTTP3Uint16List(trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSCipherSuitesHeader)))
	extensions := parseInternalHTTP3Uint16List(trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSExtensionsHeader)))
	curves := parseInternalHTTP3Uint16List(trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSCurvesHeader)))
	pointFormats := parseInternalHTTP3Uint8List(trimRequestHeaderValue(c.GetHeader(InternalHTTP3TLSPointFormatsHeader)))

	clearInternalHTTP3RequestMetadataHeaders(c)
	c.Set(internalHTTP3ContextKey, true)

	if version == "" && sni == "" && alpn == "" && ja3 == "" && ja3Hash == "" && ja4 == "" &&
		len(cipherSuites) == 0 && len(extensions) == 0 && len(curves) == 0 && len(pointFormats) == 0 {
		return
	}

	fp := bot.TLSClientFingerprint{}
	if version != "" {
		fp.TLSVersion = version
	}
	if sni != "" {
		fp.SNI = sni
	}
	if alpn != "" {
		fp.ALPN = []string{alpn}
	}
	if ja3 != "" {
		fp.JA3 = ja3
	}
	if ja3Hash != "" {
		fp.JA3Hash = ja3Hash
	}
	if ja4 != "" {
		fp.JA4 = ja4
	}
	if len(cipherSuites) > 0 {
		fp.CipherSuites = cipherSuites
	}
	if len(extensions) > 0 {
		fp.Extensions = extensions
	}
	if len(curves) > 0 {
		fp.Curves = curves
	}
	if len(pointFormats) > 0 {
		fp.PointFormats = pointFormats
	}
	c.Set(tlsFingerprintContextKey, fp)
}

func clearInternalHTTP3RequestMetadataHeaders(c *app.RequestContext) {
	if c == nil {
		return
	}
	c.Request.Header.Del(InternalHTTP3ProtoHeader)
	c.Request.Header.Del(InternalHTTP3TLSVersionHeader)
	c.Request.Header.Del(InternalHTTP3TLSSNIHeader)
	c.Request.Header.Del(InternalHTTP3TLSALPNHeader)
	c.Request.Header.Del(InternalHTTP3TLSJA3Header)
	c.Request.Header.Del(InternalHTTP3TLSJA3HashHeader)
	c.Request.Header.Del(InternalHTTP3TLSJA4Header)
	c.Request.Header.Del(InternalHTTP3TLSCipherSuitesHeader)
	c.Request.Header.Del(InternalHTTP3TLSExtensionsHeader)
	c.Request.Header.Del(InternalHTTP3TLSCurvesHeader)
	c.Request.Header.Del(InternalHTTP3TLSPointFormatsHeader)
}

func trimRequestHeaderValue(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func isLoopbackRemoteAddr(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	return isLoopbackNetAddr(c.RemoteAddr())
}

func isLoopbackNetAddr(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	switch typed := addr.(type) {
	case *net.TCPAddr:
		if typed != nil && typed.IP != nil {
			return typed.IP.IsLoopback()
		}
	case *net.UDPAddr:
		if typed != nil && typed.IP != nil {
			return typed.IP.IsLoopback()
		}
	case *net.IPAddr:
		if typed != nil && typed.IP != nil {
			return typed.IP.IsLoopback()
		}
	}
	host := addr.String()
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func parseInternalHTTP3Uint16List(raw string) []uint16 {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]uint16, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil
		}
		parsed, err := strconv.ParseUint(part, 10, 16)
		if err != nil {
			return nil
		}
		values = append(values, uint16(parsed))
	}
	return values
}

func parseInternalHTTP3Uint8List(raw string) []uint8 {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]uint8, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil
		}
		parsed, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return nil
		}
		values = append(values, uint8(parsed))
	}
	return values
}

func hasInternalHTTP3Marker(c *app.RequestContext) bool {
	if c == nil {
		return false
	}
	if value, ok := c.Get(internalHTTP3ContextKey); ok {
		if marked, ok := value.(bool); ok && marked {
			return true
		}
	}
	if !isLoopbackRemoteAddr(c) {
		return false
	}
	return strings.EqualFold(trimRequestHeaderValue(c.GetHeader(InternalHTTP3ProtoHeader)), "h3") &&
		strings.EqualFold(trimRequestHeaderValue(c.GetHeader("X-Forwarded-Proto")), "h3")
}
