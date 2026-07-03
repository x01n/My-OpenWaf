package security

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"unsafe"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
)

// ResolveClientIP applies XFF semantics for WAF decisions.
func ResolveClientIP(c *app.RequestContext, xffMode, trustedCIDR string) net.IP {
	direct := remoteIPFromAddr(c.RemoteAddr())
	if direct == nil {
		return nil
	}

	if xffMode == "" {
		xffMode = store.XFFModeStrip
	}

	switch xffMode {
	case store.XFFModeStrip:
		return direct
	case store.XFFModeTrustOuter:
		if !remoteInTrustedCIDR(direct, trustedCIDR) {
			return direct
		}
		if ip := forwardedForFirstValidIPBytes(c.Request.Header.PeekAll("X-Forwarded-For")); ip != nil {
			return ip
		}
		return direct
	default:
		return direct
	}
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
		if token == "" {
			start = end + 1
			continue
		}
		if prefix, err := netip.ParsePrefix(token); err == nil {
			if prefix.Contains(ipAddr) {
				return true
			}
		} else if single, err := netip.ParseAddr(token); err == nil {
			if single == ipAddr {
				return true
			}
		}
		start = end + 1
	}
	return false
}

func isCIDRTokenDelimiter(b byte) bool {
	return b == ',' || b == '\n' || b == ';' || isASCIIWhitespace(b)
}

func isASCIIWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\v' || b == '\f'
}
