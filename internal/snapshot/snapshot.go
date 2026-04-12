package snapshot

import (
	"crypto/tls"
	"strconv"
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
	Forwarding   *store.ForwardingProfile
	UpstreamURLs []string
	Certificate  *store.Certificate
	ListenerCert *store.Certificate
	Listener     store.Listener

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

	DataListeners map[uint]store.Listener
	Sites         map[string]SiteRuntime

	DefaultBlockHTML string

	ListenerTLSCert  map[uint]tls.Certificate
	SiteTLSCertBySNI map[string]tls.Certificate

	// Protection settings loaded from SystemSettings.
	Protection store.ProtectionConfig
}

func SiteMapKey(listenerID uint, host string) string {
	return strconv.FormatUint(uint64(listenerID), 10) + "\x00" + strings.ToLower(strings.TrimSpace(host))
}

func SNICertKey(listenerID uint, sni string) string {
	return "sni:" + strconv.FormatUint(uint64(listenerID), 10) + "\x00" + strings.ToLower(strings.TrimSpace(sni))
}

func (sn *Snapshot) MatchSite(listenerID uint, hostHeader string) (SiteRuntime, bool) {
	host := strings.ToLower(strings.TrimSpace(hostHeader))
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return SiteRuntime{}, false
	}
	if rt, ok := sn.Sites[SiteMapKey(listenerID, host)]; ok {
		return rt, true
	}
	if idx := strings.Index(host, "."); idx > 0 {
		wild := "*." + host[idx+1:]
		if rt, ok := sn.Sites[SiteMapKey(listenerID, wild)]; ok {
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
