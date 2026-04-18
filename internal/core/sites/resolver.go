package sites

import (
	"My-OpenWaf/internal/snapshot"
)

// Resolver maps incoming (bind, host) pairs to site configurations
// using the current atomic snapshot.
type Resolver struct {
	holder *snapshot.Holder
}

// NewResolver creates a resolver backed by the given snapshot holder.
func NewResolver(h *snapshot.Holder) *Resolver {
	return &Resolver{holder: h}
}

// Match finds the SiteRuntime for a bind address + host combination.
// It performs exact match first, then wildcard (*.example.com).
func (r *Resolver) Match(bind string, host string) (snapshot.SiteRuntime, bool) {
	sn := r.holder.Load()
	if sn == nil {
		return snapshot.SiteRuntime{}, false
	}
	return sn.MatchSite(bind, host)
}

// Snapshot returns the current snapshot (may be nil before first load).
func (r *Resolver) Snapshot() *snapshot.Snapshot {
	return r.holder.Load()
}
