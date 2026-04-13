package waf

import (
	"net"
	"sync/atomic"
)

// GeoInfo holds geolocation data for an IP.
type GeoInfo struct {
	Country string // ISO 3166-1 alpha-2
	City    string
}

// GeoResolver is a pluggable interface. The default implementation returns
// empty; users can plug in a MaxMind MMDB reader by replacing the resolver.
type GeoResolver interface {
	Lookup(ip net.IP) GeoInfo
}

// NoopGeoResolver returns empty geo info.
type NoopGeoResolver struct{}

func (NoopGeoResolver) Lookup(ip net.IP) GeoInfo { return GeoInfo{} }

// Global resolver (atomic swap-able).
var globalGeo atomic.Pointer[GeoResolver]

func init() {
	var r GeoResolver = NoopGeoResolver{}
	globalGeo.Store(&r)
}

// SetGeoResolver installs a custom resolver at runtime.
func SetGeoResolver(r GeoResolver) {
	globalGeo.Store(&r)
}

// LookupGeo returns geo info for the given IP using the current resolver.
func LookupGeo(ip net.IP) GeoInfo {
	p := globalGeo.Load()
	if p == nil {
		return GeoInfo{}
	}
	return (*p).Lookup(ip)
}
