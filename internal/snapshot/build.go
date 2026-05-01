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
	var sites []store.Site
	if err := db.Where("enabled = ?", true).Find(&sites).Error; err != nil {
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

	sniCerts := make(map[string]tls.Certificate)
	siteMap := make(map[string]SiteRuntime)

	for _, s := range sites {
		urls := parseUpstreamURLs(s.UpstreamURLs)
		if len(urls) == 0 {
			continue
		}

		// Build TLS config if site has certificate
		var tlsConfig *tls.Config
		var cert *store.Certificate
		if s.CertID != nil {
			if c, ok := certByID[*s.CertID]; ok {
				cert = &c
				if tlsCert, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM)); err == nil {
					tlsConfig = &tls.Config{
						Certificates: []tls.Certificate{tlsCert},
						MinVersion:   tls.VersionTLS12,
					}
					// Register SNI cert
					h := strings.ToLower(strings.TrimSpace(s.Host))
					if h != "" {
						sniCerts[SNICertKey(s.Bind, h)] = tlsCert
					}
				}
			}
		}

		policyID := uint(0)
		if s.PolicyID != nil {
			policyID = *s.PolicyID
		}
		compiled := compileRules(rulesByPolicy[policyID])

		// Build protection configs from site fields
		botProtection := store.BotProtectionConfig{
			Enabled: s.BotProtectionEnabled,
			Level:   s.BotProtectionLevel,
			Action:  "intercept",
		}
		if botProtection.Level == "" {
			botProtection.Level = "medium"
		}

		attackProtection := store.AttackProtectionConfig{
			OWASPEnabled:     true,
			OWASPSensitivity: s.AttackProtectionLevel,
			OWASPAction:      "intercept",
			SignatureEnabled: false,
			SignatureAction:  "intercept",
		}
		if attackProtection.OWASPSensitivity == "" {
			attackProtection.OWASPSensitivity = "medium"
		}

		// Get forwarding settings from site
		xffMode := s.XFFMode
		if xffMode == "" {
			xffMode = store.XFFModeStrip
		}
		cacheRules := parseSiteCacheRules(s.CacheRules)

		rt := SiteRuntime{
			Site:                 s,
			PolicyID:             policyID,
			Rules:                compiled,
			UpstreamURLs:         urls,
			Certificate:          cert,
			Bind:                 s.Bind,
			TLSConfig:            tlsConfig,
			BotProtection:        botProtection,
			AttackProtection:     attackProtection,
			XFFMode:              xffMode,
			TrustedCIDR:          s.TrustedCIDR,
			PreserveOriginalHost: s.PreserveOriginalHost,
			CacheEnabled:         s.CacheEnabled,
			CacheDefaultTTL:      s.CacheDefaultTTL,
			CacheRules:           cacheRules,
			MaintenanceEnabled:   s.MaintenanceEnabled,
			MaintenanceHTML:      s.MaintenanceHTML,
			MaintenanceStatus:    s.MaintenanceStatus,
			BlockHTML:            s.BlockHTML,
			BlockStatus:          s.BlockStatus,
			AntiReplayEnabled:    s.AntiReplayEnabled,
			AntiReplayAction:     s.AntiReplayAction,
		}
		registerSiteKeys(siteMap, rt)
		// EffectiveProtection is computed later once global protection is loaded.
	}

	// Load protection settings from SystemSettings.
	protection := loadProtectionConfig(db)

	// Compute effective per-site protection by merging site overrides onto global config.
	for key, rt := range siteMap {
		ep := mergeProtection(protection, rt.Site)
		rt.EffectiveProtection = &ep
		siteMap[key] = rt
	}

	return &Snapshot{
		Revision:         rev,
		Sites:            siteMap,
		DefaultBlockHTML: "",
		SiteTLSCertBySNI: sniCerts,
		Protection:       protection,
	}, nil
}

// mergeProtection creates a ProtectionConfig for a site by overlaying
// per-site overrides onto the global config. nil/*false = inherit global.
func mergeProtection(global store.ProtectionConfig, site store.Site) store.ProtectionConfig {
	p := global // shallow copy

	// Bot detection: per-site override
	if site.BotProtectionEnabled {
		p.BotDetectionEnabled = true
	}

	// OWASP override
	if site.OWASPEnabled != nil {
		p.OWASPEnabled = *site.OWASPEnabled
	}
	if site.OWASPSensitivity != "" {
		p.OWASPSensitivity = site.OWASPSensitivity
	}
	if site.OWASPAction != "" {
		p.OWASPAction = site.OWASPAction
	}

	// CVE override
	if site.CVEEnabled != nil {
		p.CVEEnabled = *site.CVEEnabled
	}
	if site.CVEAction != "" {
		p.CVEAction = site.CVEAction
	}

	// Rate limit override
	if site.RateLimitEnabled != nil {
		p.RequestRateLimitEnabled = *site.RateLimitEnabled
	}
	if site.RateLimitWindow > 0 {
		p.RequestRateLimitWindow = site.RateLimitWindow
	}
	if site.RateLimitMax > 0 {
		p.RequestRateLimitMax = site.RateLimitMax
	}
	if site.RateLimitAction != "" {
		p.RequestRateLimitAction = site.RateLimitAction
	}

	return p
}

func registerSiteKeys(m map[string]SiteRuntime, rt SiteRuntime) {
	h := strings.ToLower(strings.TrimSpace(rt.Site.Host))
	if h == "" {
		return
	}
	bind := rt.Bind
	m[SiteMapKey(bind, h)] = rt
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
			ID: r.ID, Phase: r.Phase, Action: r.Action, Priority: r.Priority,
			Kind: kind, Arg: arg, StatusCode: r.StatusCode, RedirectTo: r.RedirectTo,
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
		"block_user_agent:", "block_user_agent_regex:",
		"header_regex:", "body_contains:", "body_regex:", "query_param:",
		"host:", "cookie_contains:", "referer_contains:",
	}
	for _, pfx := range prefixes {
		if strings.HasPrefix(p, pfx) {
			return strings.TrimSuffix(pfx, ":"), strings.TrimSpace(strings.TrimPrefix(p, pfx))
		}
	}
	return "", ""
}

func parseSiteCacheRules(raw string) []store.SiteCacheRule {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var rules []store.SiteCacheRule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return nil
	}
	filtered := make([]store.SiteCacheRule, 0, len(rules))
	for _, rule := range rules {
		rule.Path = strings.TrimSpace(rule.Path)
		if rule.Path == "" || rule.TTL <= 0 {
			continue
		}
		if !strings.HasPrefix(rule.Path, "/") {
			rule.Path = "/" + rule.Path
		}
		filtered = append(filtered, rule)
	}
	sort.Slice(filtered, func(i, j int) bool {
		return len(filtered[i].Path) > len(filtered[j].Path)
	})
	return filtered
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
