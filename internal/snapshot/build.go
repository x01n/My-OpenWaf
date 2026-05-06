package snapshot

import (
	"crypto/tls"
	"encoding/json"
	"sort"
	"strings"
	"sync/atomic"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

// Build loads DB into an immutable Snapshot.
func Build(db *gorm.DB, rev uint64) (*Snapshot, error) {
	var sites []store.Site
	if err := db.Where("enabled = ?", true).Find(&sites).Error; err != nil {
		return nil, err
	}

	var listeners []store.SiteListener
	if err := db.Order("site_id ASC, bind ASC, id ASC").Find(&listeners).Error; err != nil {
		return nil, err
	}
	enabledListenersBySite := make(map[uint][]store.SiteListener)
	hasListenerRowsBySite := make(map[uint]bool)
	for _, listener := range listeners {
		hasListenerRowsBySite[listener.SiteID] = true
		if listener.Enabled {
			enabledListenersBySite[listener.SiteID] = append(enabledListenersBySite[listener.SiteID], listener)
		}
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

	// Load protection settings from SystemSettings.
	protection := loadProtectionConfig(db)
	ccRules := compileCCRules(protection)

	sniCerts := make(map[string]tls.Certificate)
	siteMap := make(map[string]SiteRuntime)

	for _, s := range sites {
		urls := parseUpstreamURLs(s.UpstreamURLs)
		if len(urls) == 0 {
			continue
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

		siteListeners := enabledListenersBySite[s.ID]
		if len(siteListeners) == 0 && !hasListenerRowsBySite[s.ID] && s.Bind != "" {
			siteListeners = append(siteListeners, store.SiteListener{
				SiteID:     s.ID,
				Bind:       s.Bind,
				Network:    s.Network,
				TLSEnabled: s.TLSEnabled,
				CertID:     s.CertID,
				Enabled:    true,
			})
		}

		for _, listener := range siteListeners {
			if strings.TrimSpace(listener.Bind) == "" {
				continue
			}

			listenerSite := s
			listenerSite.Bind = listener.Bind
			listenerSite.Network = listener.Network
			listenerSite.TLSEnabled = listener.TLSEnabled
			listenerSite.CertID = listener.CertID

			var tlsConfig *tls.Config
			var cert *store.Certificate
			if listenerSite.CertID != nil {
				if c, ok := certByID[*listenerSite.CertID]; ok {
					cert = &c
					if tlsCert, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM)); err == nil {
						tlsConfig = &tls.Config{
							Certificates: []tls.Certificate{tlsCert},
							MinVersion:   tls.VersionTLS12,
						}
						h := strings.ToLower(strings.TrimSpace(listenerSite.Host))
						if h != "" {
							sniCerts[SNICertKey(listenerSite.Bind, h)] = tlsCert
						}
					}
				}
			}

			rt := SiteRuntime{
				Site:                 listenerSite,
				PolicyID:             policyID,
				Rules:                compiled,
				UpstreamURLs:         urls,
				Certificate:          cert,
				Bind:                 listenerSite.Bind,
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
		}
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
	m[SiteMapKey(bind, h)] = rt
}

func parseUpstreamURLs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "[") {
		var values []string
		if err := json.Unmarshal([]byte(raw), &values); err == nil {
			out := make([]string, 0, len(values))
			for _, p := range values {
				p = strings.TrimSpace(p)
				if p != "" {
					out = append(out, p)
				}
			}
			return out
		}
	}

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

type ccRuleConfig struct {
	Enabled    *bool             `json:"enabled"`
	Action     string            `json:"action"`
	Conditions []ccRuleCondition `json:"conditions"`
	Window     int               `json:"window"`
	Threshold  int               `json:"threshold"`
	Duration   int               `json:"duration"`
}

type ccRuleCondition struct {
	Target   string `json:"target"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

var ccRuleIDCounter atomic.Uint64

func compileCCRules(protection store.ProtectionConfig) []CompiledRule {
	if !protection.CCUseCustom {
		return nil
	}
	if strings.TrimSpace(protection.CCRules) == "" {
		return nil
	}
	var configs []ccRuleConfig
	if err := json.Unmarshal([]byte(protection.CCRules), &configs); err != nil {
		return nil
	}
	out := make([]CompiledRule, 0, len(configs))
	for _, cfg := range configs {
		if cfg.Enabled != nil && !*cfg.Enabled {
			continue
		}
		children := make([]map[string]string, 0, len(cfg.Conditions))
		for _, cond := range cfg.Conditions {
			kind, arg, ok := compileCCCondition(cond)
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
		var compiled any = map[string]string{"kind": kind, "arg": arg}
		if len(children) > 1 {
			compiled = map[string]any{"op": "and", "children": children}
		}
		if cfg.Window > 0 && cfg.Threshold > 0 {
			raw, err := json.Marshal(map[string]any{
				"op":        "cc_rate",
				"children":  []any{compiled},
				"window":    cfg.Window,
				"threshold": cfg.Threshold,
				"duration":  cfg.Duration,
			})
			if err != nil {
				continue
			}
			kind = "compound"
			arg = string(raw)
		} else if len(children) > 1 {
			raw, err := json.Marshal(compiled)
			if err != nil {
				continue
			}
			kind = "compound"
			arg = string(raw)
		}
		out = append(out, CompiledRule{
			ID:       uint(ccRuleIDCounter.Add(1)),
			Phase:    store.PhaseCustom,
			Action:   normalizeCCAction(cfg.Action),
			Priority: 10_000,
			Kind:     kind,
			Arg:      arg,
		})
	}
	return out
}

func compileCCCondition(cond ccRuleCondition) (string, string, bool) {
	value := strings.TrimSpace(cond.Value)
	if value == "" {
		return "", "", false
	}
	operator := strings.ToLower(strings.TrimSpace(cond.Operator))
	switch strings.ToLower(strings.TrimSpace(cond.Target)) {
	case "url_path", "path":
		switch operator {
		case "equals":
			return "block_path_exact", value, true
		case "prefix", "contains":
			return "block_path", value, true
		}
	case "method":
		if operator == "equals" {
			return "block_method", strings.ToUpper(value), true
		}
	case "header":
		name, headerValue := splitCCHeaderValue(value)
		if name == "" || headerValue == "" {
			return "", "", false
		}
		switch operator {
		case "equals", "contains", "prefix":
			return "block_header", name + ":" + headerValue, true
		}
	}
	return "", "", false
}

func splitCCHeaderValue(value string) (string, string) {
	for _, sep := range []string{":", "="} {
		if name, val, ok := strings.Cut(value, sep); ok {
			return strings.TrimSpace(name), strings.TrimSpace(val)
		}
	}
	return "", ""
}

func normalizeCCAction(action string) store.RuleAction {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "captcha", "challenge":
		return store.ActionChallenge
	case "block", "intercept":
		return store.ActionIntercept
	case "drop":
		return store.ActionDrop
	case "observe", "log_only":
		return store.ActionObserve
	default:
		return store.ActionChallenge
	}
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
	cfg := store.DefaultProtectionConfig()
	if err := json.Unmarshal([]byte(setting.Value), &cfg); err != nil {
		return store.DefaultProtectionConfig()
	}
	return cfg
}
