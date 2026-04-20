package waf

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"My-OpenWaf/internal/core"

	"github.com/oschwald/maxminddb-golang"
)

// ── GeoIP data structures ──

// GeoInfo describes the geolocation and network metadata for an IP.
type GeoInfo struct {
	Country string // ISO 3166-1 alpha-2
	City    string
	ASN     uint   // Autonomous System Number
	ASNOrg  string // Organisation name for the ASN
}

// ── MaxMind-backed resolver ──

// MaxMindResolver wraps one or two MaxMind MMDB readers (GeoLite2-City / ASN).
type MaxMindResolver struct {
	mu     sync.RWMutex
	cityDB *maxminddb.Reader
	asnDB  *maxminddb.Reader

	// Pre-computed lookup sets built from BotConfig for O(1) checks.
	dcASNs      map[uint]struct{}
	vpnASNs     map[uint]struct{}
	hrCountries map[string]struct{}
}

// maxmindCity is the minimal structure we decode from GeoLite2-City.
type maxmindCity struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
}

// maxmindASN is the minimal structure we decode from GeoLite2-ASN.
type maxmindASN struct {
	ASN uint   `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

// NewMaxMindResolver opens the supplied database files.
// Either path may be empty; the corresponding lookups will return zero values.
func NewMaxMindResolver(cityPath, asnPath string, cfg core.BotConfig) *MaxMindResolver {
	r := &MaxMindResolver{
		dcASNs:      toUintSet(cfg.DataCenterASNs),
		vpnASNs:     toUintSet(cfg.VPNProxyASNs),
		hrCountries: toStringSet(cfg.HighRiskCountries),
	}
	r.loadDBs(cityPath, asnPath)
	return r
}

func (r *MaxMindResolver) loadDBs(cityPath, asnPath string) {
	if cityPath != "" {
		db, err := maxminddb.Open(cityPath)
		if err != nil {
			slog.Warn("geoip: failed to open city database, degrading gracefully",
				slog.String("path", cityPath), slog.String("err", err.Error()))
		} else {
			r.mu.Lock()
			old := r.cityDB
			r.cityDB = db
			r.mu.Unlock()
			if old != nil {
				old.Close()
			}
		}
	}
	if asnPath != "" {
		db, err := maxminddb.Open(asnPath)
		if err != nil {
			slog.Warn("geoip: failed to open ASN database, degrading gracefully",
				slog.String("path", asnPath), slog.String("err", err.Error()))
		} else {
			r.mu.Lock()
			old := r.asnDB
			r.asnDB = db
			r.mu.Unlock()
			if old != nil {
				old.Close()
			}
		}
	}
}

// Reload re-opens both database files, supporting hot-reload at runtime.
func (r *MaxMindResolver) Reload(cityPath, asnPath string) {
	r.loadDBs(cityPath, asnPath)
}

// UpdateConfig replaces the risk lists at runtime without reopening DBs.
func (r *MaxMindResolver) UpdateConfig(cfg core.BotConfig) {
	r.mu.Lock()
	r.dcASNs = toUintSet(cfg.DataCenterASNs)
	r.vpnASNs = toUintSet(cfg.VPNProxyASNs)
	r.hrCountries = toStringSet(cfg.HighRiskCountries)
	r.mu.Unlock()
}

// Close releases both database files.
func (r *MaxMindResolver) Close() {
	r.mu.Lock()
	if r.cityDB != nil {
		r.cityDB.Close()
		r.cityDB = nil
	}
	if r.asnDB != nil {
		r.asnDB.Close()
		r.asnDB = nil
	}
	r.mu.Unlock()
}

// Lookup returns full GeoInfo for an IP. Never panics; returns zero GeoInfo on error.
func (r *MaxMindResolver) Lookup(ip net.IP) GeoInfo {
	var info GeoInfo

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.cityDB != nil {
		var rec maxmindCity
		if err := r.cityDB.Lookup(ip, &rec); err == nil {
			info.Country = rec.Country.ISOCode
			if name, ok := rec.City.Names["en"]; ok {
				info.City = name
			}
		}
	}
	if r.asnDB != nil {
		var rec maxmindASN
		if err := r.asnDB.Lookup(ip, &rec); err == nil {
			info.ASN = rec.ASN
			info.ASNOrg = rec.Org
		}
	}
	return info
}

// IsHighRisk performs a fast pre-screening: returns true when the IP belongs
// to a datacenter ASN, a known VPN/proxy ASN, or originates from a
// high-risk country. The check is O(1) per criterion (hash-set lookups).
func (r *MaxMindResolver) IsHighRisk(ip net.IP) bool {
	if ip == nil {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// No databases loaded → graceful degradation, nothing is high-risk.
	if r.cityDB == nil && r.asnDB == nil {
		return false
	}

	if r.asnDB != nil {
		var rec maxmindASN
		if err := r.asnDB.Lookup(ip, &rec); err == nil && rec.ASN != 0 {
			if _, ok := r.dcASNs[rec.ASN]; ok {
				return true
			}
			if _, ok := r.vpnASNs[rec.ASN]; ok {
				return true
			}
		}
	}
	if r.cityDB != nil && len(r.hrCountries) > 0 {
		var rec maxmindCity
		if err := r.cityDB.Lookup(ip, &rec); err == nil && rec.Country.ISOCode != "" {
			if _, ok := r.hrCountries[rec.Country.ISOCode]; ok {
				return true
			}
		}
	}
	return false
}

// ScoreIP returns the GeoIP risk score for an IP (0 if no risk signals found).
// Only meaningful for IPs that passed IsHighRisk; callers should gate on that first.
func (r *MaxMindResolver) ScoreIP(ip net.IP) int {
	if ip == nil {
		return 0
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	score := 0

	if r.asnDB != nil {
		var rec maxmindASN
		if err := r.asnDB.Lookup(ip, &rec); err == nil && rec.ASN != 0 {
			if _, ok := r.dcASNs[rec.ASN]; ok {
				score += 25 // datacenter IP
			}
			if _, ok := r.vpnASNs[rec.ASN]; ok {
				score += 15 // VPN/proxy ASN
			}
		}
	}
	if r.cityDB != nil && len(r.hrCountries) > 0 {
		var rec maxmindCity
		if err := r.cityDB.Lookup(ip, &rec); err == nil && rec.Country.ISOCode != "" {
			if _, ok := r.hrCountries[rec.Country.ISOCode]; ok {
				score += 20 // high-risk country
			}
		}
	}
	return score
}

// ── Global resolver (kept for backward-compatibility with LookupGeo) ──

// GeoResolver is the legacy interface kept for callers that only need basic geo.
type GeoResolver interface {
	Lookup(ip net.IP) GeoInfo
}

type noopGeoResolver struct{}

func (noopGeoResolver) Lookup(ip net.IP) GeoInfo { return GeoInfo{} }

var globalGeo atomic.Pointer[GeoResolver]

func init() {
	var r GeoResolver = noopGeoResolver{}
	globalGeo.Store(&r)
}

// SetGeoResolver replaces the global GeoResolver (also accepts *MaxMindResolver).
func SetGeoResolver(r GeoResolver) {
	globalGeo.Store(&r)
}

// LookupGeo returns geo info via the global resolver.
func LookupGeo(ip net.IP) GeoInfo {
	p := globalGeo.Load()
	if p == nil {
		return GeoInfo{}
	}
	return (*p).Lookup(ip)
}

// ── helpers ──

func toUintSet(s []uint) map[uint]struct{} {
	m := make(map[uint]struct{}, len(s))
	for _, v := range s {
		m[v] = struct{}{}
	}
	return m
}

func toStringSet(s []string) map[string]struct{} {
	m := make(map[string]struct{}, len(s))
	for _, v := range s {
		m[v] = struct{}{}
	}
	return m
}
