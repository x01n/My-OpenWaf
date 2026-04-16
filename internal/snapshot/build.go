package snapshot

import (
	"crypto/tls"
	"encoding/json"
	"sort"
	"strings"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

// Build loads DB into an immutable Snapshot.
func Build(db *gorm.DB, rev uint64) (*Snapshot, error) {
	var listeners []store.Listener
	if err := db.Where("enabled = ?", true).Find(&listeners).Error; err != nil {
		return nil, err
	}
	dataListeners := make(map[uint]store.Listener)
	for _, l := range listeners {
		if l.Role == store.ListenerRoleData {
			dataListeners[l.ID] = l
		}
	}

	var sites []store.Site
	if err := db.Find(&sites).Error; err != nil {
		return nil, err
	}
	var certs []store.Certificate
	if err := db.Find(&certs).Error; err != nil {
		return nil, err
	}
	certByID := make(map[uint]store.Certificate)
	for _, c := range certs {
		certByID[c.ID] = c
	}

	var profiles []store.ForwardingProfile
	if err := db.Find(&profiles).Error; err != nil {
		return nil, err
	}
	profByID := make(map[uint]store.ForwardingProfile)
	for _, p := range profiles {
		profByID[p.ID] = p
	}

	var rules []store.Rule
	if err := db.Where("enabled = ?", true).Find(&rules).Error; err != nil {
		return nil, err
	}
	rulesByPolicy := make(map[uint][]store.Rule)
	for _, r := range rules {
		rulesByPolicy[r.PolicyID] = append(rulesByPolicy[r.PolicyID], r)
	}
	for pid := range rulesByPolicy {
		rs := rulesByPolicy[pid]
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].Priority != rs[j].Priority {
				return rs[i].Priority < rs[j].Priority
			}
			return rs[i].ID < rs[j].ID
		})
		rulesByPolicy[pid] = rs
	}

	listenerTLS := make(map[uint]tls.Certificate)
	for lid, l := range dataListeners {
		if l.CertID != nil {
			if c, ok := certByID[*l.CertID]; ok {
				if cert, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM)); err == nil {
					listenerTLS[lid] = cert
				}
			}
		}
	}

	sniCerts := make(map[string]tls.Certificate)
	siteMap := make(map[string]SiteRuntime)
	for _, s := range sites {
		l, ok := dataListeners[s.ListenerID]
		if !ok {
			continue
		}

		// TLS/443 policy: if listener is TLS-enabled and site has no cert, skip it.
		if l.TLSEnabled {
			hasCert := s.CertID != nil
			hasInherited := s.InheritListenerCert && l.CertID != nil
			if !hasCert && !hasInherited {
				continue
			}
		}

		urls := parseUpstreamURLs(s.UpstreamURLs)
		if len(urls) == 0 {
			continue
		}
		var fwd *store.ForwardingProfile
		if s.ForwardingProfileID != nil {
			if p, ok := profByID[*s.ForwardingProfileID]; ok {
				fwd = &p
			}
		}
		var cert *store.Certificate
		if s.CertID != nil {
			if c, ok := certByID[*s.CertID]; ok {
				cert = &c
			}
		}
		var lcert *store.Certificate
		if l.CertID != nil {
			if c, ok := certByID[*l.CertID]; ok {
				lcert = &c
			}
		}
		policyID := uint(0)
		if s.PolicyID != nil {
			policyID = *s.PolicyID
		}
		compiled := compileRules(rulesByPolicy[policyID])

		rt := SiteRuntime{
			Site:               s,
			PolicyID:           policyID,
			Rules:              compiled,
			Forwarding:         fwd,
			UpstreamURLs:       urls,
			Certificate:        cert,
			ListenerCert:       lcert,
			Listener:           l,
			MaintenanceEnabled: s.MaintenanceEnabled,
			MaintenanceHTML:    s.MaintenanceHTML,
			MaintenanceStatus:  s.MaintenanceStatus,
			BlockHTML:          s.BlockHTML,
			BlockStatus:        s.BlockStatus,
		}
		registerSiteKeys(siteMap, rt)

		h := strings.ToLower(strings.TrimSpace(s.Host))
		if h != "" {
			if s.CertID != nil {
				if c, ok := certByID[*s.CertID]; ok {
					if cert, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM)); err == nil {
						sniCerts[SNICertKey(s.ListenerID, h)] = cert
					}
				}
			} else if s.InheritListenerCert {
				if cert, ok := listenerTLS[s.ListenerID]; ok {
					sniCerts[SNICertKey(s.ListenerID, h)] = cert
				}
			}
		}
	}

	// Load protection settings from SystemSettings.
	protection := loadProtectionConfig(db)

	return &Snapshot{
		Revision:         rev,
		DataListeners:    dataListeners,
		Sites:            siteMap,
		DefaultBlockHTML: "",
		ListenerTLSCert:  listenerTLS,
		SiteTLSCertBySNI: sniCerts,
		Protection:       protection,
	}, nil
}

func registerSiteKeys(m map[string]SiteRuntime, rt SiteRuntime) {
	h := strings.ToLower(strings.TrimSpace(rt.Site.Host))
	if h == "" {
		return
	}
	lid := rt.Site.ListenerID
	m[SiteMapKey(lid, h)] = rt
}

func parseUpstreamURLs(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func compileRules(rs []store.Rule) []CompiledRule {
	var out []CompiledRule
	for _, r := range rs {
		kind, arg := ParsePattern(r.Pattern)
		if kind == "" {
			continue
		}
		out = append(out, CompiledRule{
			ID: r.ID, Phase: r.Phase, Action: r.Action, Priority: r.Priority, Kind: kind, Arg: arg,
		})
	}
	return out
}

// ParsePattern extracts kind and arg from DSL string like "block_ip:1.2.3.0/24".
func ParsePattern(p string) (kind, arg string) {
	p = strings.TrimSpace(p)

	// Check if it's a compound JSON pattern
	if strings.HasPrefix(p, "{") {
		return "compound", p
	}

	prefixes := []string{
		"allow_ip:", "block_ip:",
		"block_path:", "block_path_regex:", "block_path_exact:",
		"block_query_contains:", "block_query_regex:",
		"block_header:", "block_header_regex:",
		"block_method:", "block_content_type:",
	}
	for _, pfx := range prefixes {
		if strings.HasPrefix(p, pfx) {
			return strings.TrimSuffix(pfx, ":"), strings.TrimSpace(strings.TrimPrefix(p, pfx))
		}
	}
	return "", ""
}

func loadProtectionConfig(db *gorm.DB) store.ProtectionConfig {
	var setting store.SystemSettings
	if err := db.Where("key = ?", "protection").First(&setting).Error; err != nil {
		return store.DefaultProtectionConfig()
	}
	var cfg store.ProtectionConfig
	if err := json.Unmarshal([]byte(setting.Value), &cfg); err != nil {
		return store.DefaultProtectionConfig()
	}
	return cfg
}
