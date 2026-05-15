package snapshot

import (
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"

	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/store"
)

// CompiledRule is a lightweight runtime rule (MVP ACL parser).
type CompiledRule struct {
	ID         uint
	Phase      store.RulePhase
	Action     store.RuleAction
	Priority   int
	Kind       string
	Arg        string
	StatusCode int    // custom HTTP status code (0 = default)
	RedirectTo string // URL for redirect action
}

// SiteRuntime holds resolved site for routing.
type SiteRuntime struct {
	Site         store.Site
	PolicyID     uint
	Rules        []CompiledRule
	UpstreamURLs []string
	Certificate  *store.Certificate

	// Listener configuration (now embedded in Site)
	Bind      string
	TLSConfig *tls.Config

	// Bot and attack protection
	BotProtection    store.BotProtectionConfig
	AttackProtection store.AttackProtectionConfig

	// Forwarding settings (now in Site model)
	XFFMode              string
	TrustedCIDR          string
	PreserveOriginalHost bool

	// Per-site maintenance
	MaintenanceEnabled bool
	MaintenanceHTML    string
	MaintenanceStatus  int

	// Per-site block page
	BlockHTML   string
	BlockStatus int

	// Per-site response cache
	CacheEnabled    bool
	CacheDefaultTTL int
	CacheRules      []store.SiteCacheRule

	// Anti-replay nonce protection
	AntiReplayEnabled bool
	AntiReplayAction  string // action when nonce invalid (default: "challenge")

	// Per-site protection overrides (merged from Site fields).
	// nil = use global ProtectionConfig.
	EffectiveProtection *store.ProtectionConfig

	// Application route rules (compiled per snapshot).
	AppRouteRules []appresource.CompiledRule
}

// Snapshot is an immutable view for the dataplane (atomic pointer swap).
type Snapshot struct {
	Revision uint64

	Sites map[string]SiteRuntime

	DefaultBlockHTML string

	SiteTLSCertBySNI map[string]tls.Certificate

	// Protection settings loaded from SystemSettings.
	Protection store.ProtectionConfig
}

func SiteMapKey(bind string, host string) string {
	return bind + "\x00" + strings.ToLower(strings.TrimSpace(host))
}

func SNICertKey(bind string, sni string) string {
	return "sni:" + bind + "\x00" + strings.ToLower(strings.TrimSpace(sni))
}

func (sn *Snapshot) MatchSite(bind string, hostHeader string) (SiteRuntime, bool) {
	host := NormalizeMatchHost(hostHeader)
	if host == "" {
		return SiteRuntime{}, false
	}

	// 1. Exact match on bind+host
	key := SiteMapKey(bind, host)
	if rt, ok := sn.Sites[key]; ok {
		return rt, true
	}

	// 2. Wildcard match (only for domain names, not IP addresses)
	if !isIPAddress(host) {
		if idx := strings.Index(host, "."); idx > 0 {
			wild := "*." + host[idx+1:]
			if rt, ok := sn.Sites[SiteMapKey(bind, wild)]; ok {
				return rt, true
			}
		}
	}

	// 3. Fallback: match any site on this bind address whose host matches
	for _, rt := range sn.Sites {
		if rt.Bind == bind && NormalizeMatchHost(rt.Site.Host) == host {
			return rt, true
		}
	}

	// 4. Fallback: any site on this bind address only when it is unambiguous (single host key).
	prefix := bind + "\x00"
	var sole SiteRuntime
	n := 0
	for k, rt := range sn.Sites {
		if strings.HasPrefix(k, prefix) {
			sole = rt
			n++
			if n > 1 {
				break
			}
		}
	}
	if n == 1 {
		return sole, true
	}

	return SiteRuntime{}, false
}

// NormalizeMatchHost lowercases, trims, and strips the port from a host header.
func NormalizeMatchHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	// Strip port: find last colon and verify everything after is digits.
	if i := strings.LastIndex(host, ":"); i >= 0 {
		port := host[i+1:]
		allDigits := len(port) > 0
		for _, ch := range port {
			if ch < '0' || ch > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			host = host[:i]
		}
	}
	return host
}

// isIPAddress checks whether the host string is an IP address (v4 or v6).
func isIPAddress(host string) bool {
	return net.ParseIP(host) != nil
}

// Holder stores current snapshot atomically.
type Holder struct {
	ptr atomic.Pointer[Snapshot]
}

func (h *Holder) Store(s *Snapshot) { h.ptr.Store(s) }
func (h *Holder) Load() *Snapshot   { return h.ptr.Load() }
