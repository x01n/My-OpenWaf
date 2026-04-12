package sites

import (
	"My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
)

// Resolver maps incoming (listenerID, host) pairs to site configurations
// using the current atomic snapshot.
type Resolver struct {
	holder *snapshot.Holder
}

// NewResolver creates a resolver backed by the given snapshot holder.
func NewResolver(h *snapshot.Holder) *Resolver {
	return &Resolver{holder: h}
}

// Match finds the SiteRuntime for a listener + host combination.
// It performs exact match first, then wildcard (*.example.com).
func (r *Resolver) Match(listenerID uint, host string) (snapshot.SiteRuntime, bool) {
	sn := r.holder.Load()
	if sn == nil {
		return snapshot.SiteRuntime{}, false
	}
	return sn.MatchSite(listenerID, host)
}

// Snapshot returns the current snapshot (may be nil before first load).
func (r *Resolver) Snapshot() *snapshot.Snapshot {
	return r.holder.Load()
}

// DataListeners returns active data-plane listeners from the snapshot.
func (r *Resolver) DataListeners() map[uint]store.Listener {
	sn := r.holder.Load()
	if sn == nil {
		return nil
	}
	return sn.DataListeners
}
