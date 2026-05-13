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

	protection := loadProtectionConfig(db)
	ccRules := compileCCRules(protection)

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
		compiled := append(compileRules(rulesByPolicy[policyID]), ccRules...)

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
	// Normalize the host the same way MatchSite does: lowercase, trim, strip port.
	// This ensures the map key matches what MatchSite will look up.
	h := normalizeMatchHost(rt.Site.Host)
	if h == "" {
		return
	}
	bind := rt.Bind
	key := SiteMapKey(bind, h)
	if _, exists := m[key]; exists {
		return
	}
	m[key] = rt
}

func parseUpstreamURLs(raw string) []string {
	var values []string
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "[") {
		_ = json.Unmarshal([]byte(trimmed), &values)
	}
	if len(values) == 0 {
		values = strings.Split(raw, ",")
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
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

func compileCCRules(protection store.ProtectionConfig) []CompiledRule {
	if !protection.CCUseCustom || strings.TrimSpace(protection.CCRules) == "" {
		return nil
	}
	var raw []struct {
		Enabled    *bool `json:"enabled"`
		Conditions []struct {
			Target   string `json:"target"`
			Operator string `json:"operator"`
			Value    string `json:"value"`
		} `json:"conditions"`
		Window    int    `json:"window"`
		Threshold int    `json:"threshold"`
		Duration  int    `json:"duration"`
		Action    string `json:"action"`
	}
	if err := json.Unmarshal([]byte(protection.CCRules), &raw); err != nil {
		return nil
	}
	out := make([]CompiledRule, 0, len(raw))
	for i, rule := range raw {
		if rule.Enabled != nil && !*rule.Enabled {
			continue
		}
		children := make([]map[string]string, 0, len(rule.Conditions))
		for _, cond := range rule.Conditions {
			kind, arg, ok := ccConditionPattern(cond.Target, cond.Operator, cond.Value)
			if !ok {
				children = nil
				break
			}
			children = append(children, map[string]string{"kind": kind, "arg": arg})
		}
		if len(children) == 0 {
			continue
		}
		kind := children[0]["kind"]
		arg := children[0]["arg"]
		if len(children) > 1 || rule.Window > 0 || rule.Threshold > 0 {
			compound := map[string]any{
				"op":        "cc_rate",
				"window":    rule.Window,
				"threshold": rule.Threshold,
				"duration":  rule.Duration,
				"children":  children,
			}
			if len(children) > 1 {
				compound["children"] = []map[string]any{{"op": "and", "children": children}}
			}
			b, err := json.Marshal(compound)
			if err != nil {
				continue
			}
			kind = "compound"
			arg = string(b)
		}
		action := store.RuleAction(strings.TrimSpace(rule.Action))
		switch action {
		case "", "block":
			action = store.ActionIntercept
		case "captcha":
			action = store.ActionChallenge
		}
		out = append(out, CompiledRule{ID: uint(900000 + i), Phase: store.PhaseCustom, Action: action, Priority: 1000 + i, Kind: kind, Arg: arg})
	}
	return out
}

func ccConditionPattern(target, operator, value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}
	switch strings.TrimSpace(target) {
	case "url_path":
		switch strings.TrimSpace(operator) {
		case "equals":
			return "block_path_exact", value, true
		case "contains", "prefix":
			return "block_path", value, true
		}
	case "header":
		if strings.TrimSpace(operator) == "contains" {
			return "block_header", value, true
		}
	case "method":
		if strings.TrimSpace(operator) == "equals" {
			return "block_method", strings.ToUpper(value), true
		}
	}
	return "", "", false
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
