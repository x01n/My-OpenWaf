package security

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"unsafe"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
)

// ResolveClientIP applies XFF semantics for WAF decisions.
func ResolveClientIP(c *app.RequestContext, xffMode, trustedCIDR string, headerOrder []string) net.IP {
	direct := remoteIPFromAddr(c.RemoteAddr())
	if direct == nil {
		return nil
	}

	if xffMode != store.XFFModeTrustOuter || !remoteInTrustedCIDR(direct, trustedCIDR) {
		return direct
	}
	if len(headerOrder) == 0 {
		headerOrder = []string{store.ClientIPHeaderXForwardedFor}
	}
	for _, header := range headerOrder {
		if ip := clientIPFromHeader(c, header); ip != nil {
			return ip
		}
	}
	return direct
}

func clientIPFromHeader(c *app.RequestContext, header string) net.IP {
	switch header {
	case store.ClientIPHeaderXForwardedFor:
		return forwardedForFirstValidIPBytes(c.Request.Header.PeekAll("X-Forwarded-For"))
	case store.ClientIPHeaderXRealIP:
		return singleHeaderFirstValidIP(c.Request.Header.PeekAll("X-Real-IP"))
	case store.ClientIPHeaderForwarded:
		return forwardedHeaderFirstValidIP(c.Request.Header.PeekAll("Forwarded"))
	default:
		return nil
	}
}

func singleHeaderFirstValidIP(values [][]byte) net.IP {
	for _, raw := range values {
		for len(raw) > 0 {
			segment := raw
			if comma := bytes.IndexByte(raw, ','); comma >= 0 {
				segment = raw[:comma]
				raw = raw[comma+1:]
			} else {
				raw = nil
			}
			if ip, ok := forwardedForSegmentIP(bytes.TrimSpace(segment)); ok {
				return ip
			}
		}
	}
	return nil
}

func forwardedHeaderFirstValidIP(values [][]byte) net.IP {
	for _, raw := range values {
		for len(raw) > 0 {
			entry := raw
			if comma := bytes.IndexByte(raw, ','); comma >= 0 {
				entry = raw[:comma]
				raw = raw[comma+1:]
			} else {
				raw = nil
			}
			for len(entry) > 0 {
				part := entry
				if semicolon := bytes.IndexByte(entry, ';'); semicolon >= 0 {
					part = entry[:semicolon]
					entry = entry[semicolon+1:]
				} else {
					entry = nil
				}
				part = bytes.TrimSpace(part)
				if len(part) < 4 || !bytes.EqualFold(part[:4], []byte("for=")) {
					continue
				}
				if ip, ok := forwardedForSegmentIP(trimForwardedForValue(part[4:])); ok {
					return ip
				}
			}
		}
	}
	return nil
}

func trimForwardedForValue(raw []byte) []byte {
	raw = bytes.TrimSpace(raw)
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	if len(raw) > 0 && raw[0] == '[' {
		if closing := bytes.IndexByte(raw, ']'); closing > 0 {
			return raw[1:closing]
		}
	}
	return raw
}

func remoteIPFromAddr(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.TCPAddr:
		if v != nil {
			return v.IP
		}
	case *net.UDPAddr:
		if v != nil {
			return v.IP
		}
	case *net.IPAddr:
		if v != nil {
			return v.IP
		}
	}
	if addr == nil {
		return nil
	}
	remoteHost, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		remoteHost = addr.String()
	}
	return net.ParseIP(remoteHost)
}

func forwardedForFirstValidIPBytes(values [][]byte) net.IP {
	for _, raw := range values {
		for len(raw) > 0 {
			segment := raw
			if comma := bytes.IndexByte(raw, ','); comma >= 0 {
				segment = raw[:comma]
				raw = raw[comma+1:]
			} else {
				raw = nil
			}
			segment = bytes.TrimSpace(segment)
			if len(segment) == 0 {
				continue
			}
			if ip, ok := forwardedForSegmentIP(segment); ok {
				return ip
			}
		}
	}
	return nil
}

func forwardedForSegmentIP(segment []byte) (net.IP, bool) {
	if len(segment) == 0 {
		return nil, false
	}
	addr, err := netip.ParseAddr(unsafe.String(unsafe.SliceData(segment), len(segment)))
	if err != nil {
		return nil, false
	}
	addr = addr.Unmap()
	return net.IP(addr.AsSlice()), true
}

func remoteInTrustedCIDR(ip net.IP, raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	ipAddr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	ipAddr = ipAddr.Unmap()
	matched := false
	forEachTrustedCIDRToken(raw, func(token string) bool {
		if prefix, err := netip.ParsePrefix(token); err == nil {
			if prefix.Contains(ipAddr) {
				matched = true
				return false
			}
		} else if single, err := netip.ParseAddr(token); err == nil && single.Unmap() == ipAddr {
			matched = true
			return false
		}
		return true
	})
	return matched
}

// ValidateTrustedCIDR validates the site trusted proxy list using the same token syntax as runtime resolution.
func ValidateTrustedCIDR(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	hasToken := false
	valid := true
	forEachTrustedCIDRToken(raw, func(token string) bool {
		hasToken = true
		if !validTrustedCIDRToken(token) {
			valid = false
			return false
		}
		return true
	})
	return hasToken && valid
}

func validTrustedCIDRToken(token string) bool {
	if _, err := netip.ParsePrefix(token); err == nil {
		return true
	}
	_, err := netip.ParseAddr(token)
	return err == nil
}

// ValidateClientIPHeaderOrder validates the persisted JSON header-priority list.
func ValidateClientIPHeaderOrder(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	var headers []string
	if err := json.Unmarshal([]byte(raw), &headers); err != nil || len(headers) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(headers))
	for _, header := range headers {
		if !store.IsClientIPHeader(header) {
			return false
		}
		if _, exists := seen[header]; exists {
			return false
		}
		seen[header] = struct{}{}
	}
	return true
}

func forEachTrustedCIDRToken(raw string, visit func(string) bool) {
	for start := 0; start < len(raw); {
		for start < len(raw) && isCIDRTokenDelimiter(raw[start]) {
			start++
		}
		if start >= len(raw) {
			break
		}
		end := start
		for end < len(raw) && !isCIDRTokenDelimiter(raw[end]) {
			end++
		}
		token := strings.TrimSpace(raw[start:end])
		if token != "" && !visit(token) {
			return
		}
		start = end + 1
	}
}

func isCIDRTokenDelimiter(b byte) bool {
	return b == ',' || b == '\n' || b == ';' || isASCIIWhitespace(b)
}

func isASCIIWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\v' || b == '\f'
}
