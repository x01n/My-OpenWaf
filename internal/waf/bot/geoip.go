package bot

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"My-OpenWaf/internal/core"

	"github.com/oschwald/maxminddb-golang"
)

type GeoInfo struct {
	Country string
	City    string
	ASN     uint
	ASNOrg  string
}

type MaxMindResolver struct {
	mu     sync.RWMutex
	cityDB *maxminddb.Reader
	asnDB  *maxminddb.Reader
	dcASNs      map[uint]struct{}
	vpnASNs     map[uint]struct{}
	hrCountries map[string]struct{}
}

type maxmindCity struct {
	Country struct { ISOCode string `maxminddb:"iso_code"` } `maxminddb:"country"`
	City struct { Names map[string]string `maxminddb:"names"` } `maxminddb:"city"`
}

type maxmindASN struct {
	ASN uint `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

func NewMaxMindResolver(cityPath, asnPath string, cfg core.BotConfig) *MaxMindResolver {
	r := &MaxMindResolver{dcASNs: toUintSet(cfg.DataCenterASNs), vpnASNs: toUintSet(cfg.VPNProxyASNs), hrCountries: toStringSet(cfg.HighRiskCountries)}
	r.loadDBs(cityPath, asnPath)
	return r
}

func (r *MaxMindResolver) loadDBs(cityPath, asnPath string) {
	if cityPath != "" {
		db, err := maxminddb.Open(cityPath)
		if err != nil {
			slog.Warn("geoip: failed to open city database, degrading gracefully", slog.String("path", cityPath), slog.String("err", err.Error()))
		} else {
			r.mu.Lock(); old := r.cityDB; r.cityDB = db; r.mu.Unlock(); if old != nil { old.Close() }
		}
	}
	if asnPath != "" {
		db, err := maxminddb.Open(asnPath)
		if err != nil {
			slog.Warn("geoip: failed to open ASN database, degrading gracefully", slog.String("path", asnPath), slog.String("err", err.Error()))
		} else {
			r.mu.Lock(); old := r.asnDB; r.asnDB = db; r.mu.Unlock(); if old != nil { old.Close() }
		}
	}
}

func (r *MaxMindResolver) Reload(cityPath, asnPath string) { r.loadDBs(cityPath, asnPath) }
func (r *MaxMindResolver) UpdateConfig(cfg core.BotConfig) {
	r.mu.Lock(); r.dcASNs = toUintSet(cfg.DataCenterASNs); r.vpnASNs = toUintSet(cfg.VPNProxyASNs); r.hrCountries = toStringSet(cfg.HighRiskCountries); r.mu.Unlock()
}
func (r *MaxMindResolver) Close() {
	r.mu.Lock(); if r.cityDB != nil { r.cityDB.Close(); r.cityDB = nil }; if r.asnDB != nil { r.asnDB.Close(); r.asnDB = nil }; r.mu.Unlock()
}
func (r *MaxMindResolver) Lookup(ip net.IP) GeoInfo {
	var info GeoInfo
	r.mu.RLock(); defer r.mu.RUnlock()
	if r.cityDB != nil {
		var rec maxmindCity
		if err := r.cityDB.Lookup(ip, &rec); err == nil { info.Country = rec.Country.ISOCode; if name, ok := rec.City.Names["en"]; ok { info.City = name } }
	}
	if r.asnDB != nil {
		var rec maxmindASN
		if err := r.asnDB.Lookup(ip, &rec); err == nil { info.ASN = rec.ASN; info.ASNOrg = rec.Org }
	}
	return info
}
func (r *MaxMindResolver) IsHighRisk(ip net.IP) bool {
	if ip == nil { return false }
	r.mu.RLock(); defer r.mu.RUnlock()
	if r.cityDB == nil && r.asnDB == nil { return false }
	if r.asnDB != nil {
		var rec maxmindASN
		if err := r.asnDB.Lookup(ip, &rec); err == nil && rec.ASN != 0 { if _, ok := r.dcASNs[rec.ASN]; ok { return true }; if _, ok := r.vpnASNs[rec.ASN]; ok { return true } }
	}
	if r.cityDB != nil && len(r.hrCountries) > 0 {
		var rec maxmindCity
		if err := r.cityDB.Lookup(ip, &rec); err == nil && rec.Country.ISOCode != "" { if _, ok := r.hrCountries[rec.Country.ISOCode]; ok { return true } }
	}
	return false
}
func (r *MaxMindResolver) ScoreIP(ip net.IP) int {
	if ip == nil { return 0 }
	r.mu.RLock(); defer r.mu.RUnlock()
	score := 0
	if r.asnDB != nil {
		var rec maxmindASN
		if err := r.asnDB.Lookup(ip, &rec); err == nil && rec.ASN != 0 { if _, ok := r.dcASNs[rec.ASN]; ok { score += 25 }; if _, ok := r.vpnASNs[rec.ASN]; ok { score += 15 } }
	}
	if r.cityDB != nil && len(r.hrCountries) > 0 {
		var rec maxmindCity
		if err := r.cityDB.Lookup(ip, &rec); err == nil && rec.Country.ISOCode != "" { if _, ok := r.hrCountries[rec.Country.ISOCode]; ok { score += 20 } }
	}
	return score
}

type GeoResolver interface { Lookup(ip net.IP) GeoInfo }
type noopGeoResolver struct{}
func (noopGeoResolver) Lookup(ip net.IP) GeoInfo { return GeoInfo{} }
var globalGeo atomic.Pointer[GeoResolver]
func init() { var r GeoResolver = noopGeoResolver{}; globalGeo.Store(&r) }
func SetGeoResolver(r GeoResolver) { globalGeo.Store(&r) }
func LookupGeo(ip net.IP) GeoInfo { p := globalGeo.Load(); if p == nil { return GeoInfo{} }; return (*p).Lookup(ip) }
func toUintSet(s []uint) map[uint]struct{} { m := make(map[uint]struct{}, len(s)); for _, v := range s { m[v] = struct{}{} }; return m }
func toStringSet(s []string) map[string]struct{} { m := make(map[string]struct{}, len(s)); for _, v := range s { m[v] = struct{}{} }; return m }
