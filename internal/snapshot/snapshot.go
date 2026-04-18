package snapshot

import (
	"crypto/tls"
	"strings"
	"sync/atomic"

	"My-OpenWaf/internal/store"
)

// CompiledRule is a lightweight runtime rule (MVP ACL parser).
type CompiledRule struct {
	ID       uint
	Phase    store.RulePhase
	Action   store.RuleAction
	Priority int
	Kind     string
	Arg      string
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
	host := strings.ToLower(strings.TrimSpace(hostHeader))
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	key := bind + "\x00" + host
	if rt, ok := sn.Sites[key]; ok {
		return rt, true
	}
	if idx := strings.Index(host, "."); idx > 0 {
		wild := "*." + host[idx+1:]
		if rt, ok := sn.Sites[bind+"\x00"+wild]; ok {
			return rt, true
		}
	}
	// Fallback: match any site on this bind address
	for k, rt := range sn.Sites {
		if strings.HasPrefix(k, bind+"\x00") {
			return rt, true
		}
	}
	return SiteRuntime{}, false
}

// Holder stores current snapshot atomically.
type Holder struct {
	ptr atomic.Pointer[Snapshot]
}

func (h *Holder) Store(s *Snapshot) { h.ptr.Store(s) }
func (h *Holder) Load() *Snapshot   { return h.ptr.Load() }
