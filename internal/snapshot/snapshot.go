package snapshot

import (
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"

	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/dynamic"
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

	NetworkDefaults NetworkDefaults
	TLSDefaults     TLSDefaults

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

	// DynamicProtection holds the dynamic protection config (HTML obfuscation, JS obfuscation, watermark).
	DynamicProtection dynamic.ProtectionConfig

	// AccessControl holds the site access control gate config (nil = disabled).
	AccessControl *AccessControlConfig

	ResponseCompressionConfigured  bool
	ResponseCompressionEnabled     bool
	ResponseCompressionGzipEnabled bool
	ResponseCompressionMinBytes    int
	BrotliEnabled                  bool

	// Upstream host header override (for explicit upstream host resolution).
	UpstreamHostHeader string

	// 站点级 IP 黑白名单（仅对该站点生效）。
	SiteIPWhitelist []net.IPNet
	SiteIPBlacklist []net.IPNet
}

// AccessControlConfig 站点访问控制运行时配置。
type AccessControlConfig struct {
	Enabled            bool
	SharedPasswordHash string
	SessionTTL         int
	Providers          []AccessControlProvider
	PathRules          []AccessControlPathRule
}

// AccessControlProvider 认证提供方运行时配置。
type AccessControlProvider struct {
	ID       uint
	Type     string
	Name     string
	Priority int
	Config   string // OAuth/OIDC 配置 JSON（密文形式，数据面解密后使用）
}

// AccessControlPathRule 路径访问控制规则。
type AccessControlPathRule struct {
	Path     string
	Action   string
	Priority int
}

// Snapshot is an immutable view for the dataplane (atomic pointer swap).
type Snapshot struct {
	Revision uint64

	Sites map[string]SiteRuntime

	NetworkDefaults NetworkDefaults
	TLSDefaults     TLSDefaults

	DefaultBlockHTML string

	SiteTLSCertBySNI map[string]tls.Certificate

	// Protection settings loaded from SystemSettings.
	Protection store.ProtectionConfig

	// HTTP2 configuration
	HTTP2Config HTTP2Config

	// HSTS
	HSTSEnabled bool

	// XSS protection
	XSSProtectionEnabled bool

	// Expect-CT
	ExpectCTEnabled bool
	ExpectCTValue   string

	// HPKP
	HPKPEnabled           bool
	HPKPValue             string
	HPKPReportOnlyEnabled bool
	HPKPReportOnlyValue   string

	// Response compression
	ResponseCompressionEnabled     bool
	ResponseCompressionGzipEnabled bool
	ResponseCompressionMinBytes    int

	// Brotli
	BrotliEnabled bool

	// ExcludeRecordHeaders holds header names that should skip resource recording.
	ExcludeRecordHeaders []string
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

	key := SiteMapKey(bind, host)
	if rt, ok := sn.Sites[key]; ok {
		return rt, true
	}

	if !isIPAddress(host) {
		if idx := strings.Index(host, "."); idx > 0 {
			wild := "*." + host[idx+1:]
			if rt, ok := sn.Sites[SiteMapKey(bind, wild)]; ok {
				return rt, true
			}
		}
	}

	if rt, ok := sn.Sites[SiteMapKey(bind, "*")]; ok {
		return rt, true
	}

	return SiteRuntime{}, false
}

// MatchSitePtr finds the SiteRuntime pointer for a bind address + host combination.
func (sn *Snapshot) MatchSitePtr(bind string, hostHeader string) (*SiteRuntime, bool) {
	host := NormalizeMatchHost(hostHeader)
	if host == "" {
		return nil, false
	}

	key := SiteMapKey(bind, host)
	if rt, ok := sn.Sites[key]; ok {
		return &rt, true
	}

	if !isIPAddress(host) {
		if idx := strings.Index(host, "."); idx > 0 {
			wild := "*." + host[idx+1:]
			if rt, ok := sn.Sites[SiteMapKey(bind, wild)]; ok {
				return &rt, true
			}
		}
	}

	if rt, ok := sn.Sites[SiteMapKey(bind, "*")]; ok {
		return &rt, true
	}

	return nil, false
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
	for _, ch := range host {
		if ch == '.' || ch == ':' || (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			continue
		}
		return false
	}
	return net.ParseIP(host) != nil
}

// Holder stores current snapshot atomically.
type Holder struct {
	ptr atomic.Pointer[Snapshot]
}

func (h *Holder) Store(s *Snapshot) { h.ptr.Store(s) }
func (h *Holder) Load() *Snapshot   { return h.ptr.Load() }

// Shared runtime limits.
const (
	WAFBodyScanLimit = 48 * 1024 // 48 KB
)

// Time constants (seconds).
const (
	OneDaySeconds = 86400
)

// Default security header values.
const (
	DefaultExpectCTValue       = "max-age=86400, enforce"
	DefaultHPKPValue           = ""
	DefaultHPKPReportOnlyValue = ""
)

// Default response compression settings.
const (
	DefaultResponseCompressionEnabled     = true
	DefaultResponseCompressionGzipEnabled = true
	DefaultResponseCompressionMinBytes    = 1024
)
