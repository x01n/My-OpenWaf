package snapshot

import (
	"crypto/tls"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"My-OpenWaf/internal/appresource"
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
	// Load settings from SystemSettings (used for listener defaults, CC rules and mergeProtection).
	networkDefaults := loadNetworkDefaults(db)
	tlsDefaults := loadTLSDefaults(db)
	protection := loadProtectionConfig(db)
	ccRules := compileCCRules(protection)
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

	// Load application route rules and compile per-site.
	var appRulesRaw []store.ApplicationRouteRule
	db.Where("enabled = ?", true).Find(&appRulesRaw)
	rawBySite := make(map[uint][]store.ApplicationRouteRule)
	for _, ar := range appRulesRaw {
		rawBySite[ar.SiteID] = append(rawBySite[ar.SiteID], ar)
	}
	appRulesBySite := make(map[uint][]appresource.CompiledRule)
	for sid, raws := range rawBySite {
		appRulesBySite[sid] = appresource.CompileRules(raws)
	}

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
			listenerSite.Network, listenerSite.ALPN = EffectiveSiteNetwork(listenerSite.ALPN, listenerSite.Network, networkDefaults, tlsDefaults)
			listenerSite.MinTLSVersion, listenerSite.MaxTLSVersion, listenerSite.CipherSuites = EffectiveSiteTLS(listenerSite.MinTLSVersion, listenerSite.MaxTLSVersion, listenerSite.CipherSuites, tlsDefaults)

			var tlsConfig *tls.Config
			var cert *store.Certificate
			if listenerSite.CertID != nil {
				if c, ok := certByID[*listenerSite.CertID]; ok {
					cert = &c
					if tlsCert, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM)); err == nil {
						minVer := ParseTLSVersion(listenerSite.MinTLSVersion)
						if minVer == 0 {
							minVer = tls.VersionTLS12
						}
						maxVer := ParseTLSVersion(listenerSite.MaxTLSVersion)
						if maxVer == 0 {
							maxVer = tls.VersionTLS13
						}
						cipherSuites := parseTLSCipherSuites(listenerSite.CipherSuites)
						curves := ParseCurvePreferences(tlsDefaults.CurvePreferences)
						if len(curves) == 0 {
							curves = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
						}
						tlsConfig = &tls.Config{
							Certificates:             []tls.Certificate{tlsCert},
							MinVersion:               minVer,
							MaxVersion:               maxVer,
							NextProtos:               parseALPNProtocols(listenerSite.ALPN),
							CipherSuites:             cipherSuites,
							CurvePreferences:         curves,
							PreferServerCipherSuites: tlsDefaults.PreferServerCipherSuites,
						}
						for _, rawHost := range splitHosts(listenerSite.Host) {
							h := strings.ToLower(strings.TrimSpace(rawHost))
							if h != "" {
								sniCerts[SNICertKey(listenerSite.Bind, h)] = tlsCert
							}
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
				NetworkDefaults:      networkDefaults,
				TLSDefaults:          tlsDefaults,
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
				AppRouteRules:        appRulesBySite[s.ID],
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
		NetworkDefaults:  networkDefaults,
		TLSDefaults:      tlsDefaults,
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
	bind := rt.Bind
	for _, host := range splitHosts(rt.Site.Host) {
		h := NormalizeMatchHost(host)
		if h == "" {
			continue
		}
		k := SiteMapKey(bind, h)
		if _, exists := m[k]; exists {
			continue
		}
		m[k] = rt
	}
}

// splitHosts splits a host field by comma, supporting multi-host per site.
func splitHosts(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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

func parseALPNProtocols(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return strings.Split(DefaultTLSDefaults().DefaultALPN, ",")
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, 3)
	for _, item := range strings.Split(raw, ",") {
		proto := strings.TrimSpace(item)
		if proto == "" {
			continue
		}
		if _, ok := seen[proto]; ok {
			continue
		}
		seen[proto] = struct{}{}
		out = append(out, proto)
	}
	if len(out) == 0 {
		return strings.Split(DefaultTLSDefaults().DefaultALPN, ",")
	}
	return out
}

func parseTLSCipherSuites(raw string) []uint16 {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	nameToID := make(map[string]uint16)
	for _, suite := range tls.CipherSuites() {
		nameToID[suite.Name] = suite.ID
		nameToID[strings.ToUpper(suite.Name)] = suite.ID
		short := strings.TrimPrefix(suite.Name, "TLS_")
		nameToID[short] = suite.ID
		nameToID[strings.ToUpper(short)] = suite.ID
	}
	for _, suite := range tls.InsecureCipherSuites() {
		nameToID[suite.Name] = suite.ID
		nameToID[strings.ToUpper(suite.Name)] = suite.ID
		short := strings.TrimPrefix(suite.Name, "TLS_")
		nameToID[short] = suite.ID
		nameToID[strings.ToUpper(short)] = suite.ID
	}
	seen := make(map[uint16]struct{})
	var suites []uint16
	for _, item := range strings.Split(raw, ",") {
		key := strings.TrimSpace(item)
		if key == "" {
			continue
		}
		id, ok := nameToID[key]
		if !ok {
			id, ok = nameToID[strings.ToUpper(key)]
		}
		if !ok {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		suites = append(suites, id)
	}
	return suites
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
	var inbound []store.SiteCacheRule
	if err := json.Unmarshal([]byte(raw), &inbound); err != nil {
		return nil
	}
	filtered := make([]store.SiteCacheRule, 0, len(inbound))
	for _, rule := range inbound {
		if rule.TTL <= 0 {
			continue
		}
		ruleType := strings.ToLower(strings.TrimSpace(rule.Type))
		val := strings.TrimSpace(rule.Value)
		path := strings.TrimSpace(rule.Path)

		// Legacy JSON: path + ttl only (prefix match).
		if ruleType == "" && val == "" && path != "" {
			p := path
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			filtered = append(filtered, store.SiteCacheRule{
				Type:            "prefix",
				Path:            p,
				TTL:             rule.TTL,
				IgnoreQuery:     rule.IgnoreQuery,
				CaseInsensitive: rule.CaseInsensitive,
			})
			continue
		}
		if val == "" {
			continue
		}
		for _, tok := range strings.Split(val, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			nr := store.SiteCacheRule{
				TTL:             rule.TTL,
				IgnoreQuery:     rule.IgnoreQuery,
				CaseInsensitive: rule.CaseInsensitive,
			}
			switch ruleType {
			case "suffix":
				nr.Type = "suffix"
				if strings.Contains(tok, ".") {
					nr.Path = tok
				} else {
					nr.Path = "." + tok
				}
			case "contains":
				nr.Type = "contains"
				nr.Path = tok
			case "regex":
				nr.Type = "regex"
				pat := tok
				if rule.CaseInsensitive {
					pat = "(?i)" + pat
				}
				re, err := regexp.Compile(pat)
				if err != nil {
					continue
				}
				nr.Regex = re
				nr.Value = tok
			case "exact":
				nr.Type = "exact"
				if !strings.HasPrefix(tok, "/") {
					tok = "/" + tok
				}
				nr.Path = tok
			default:
				nr.Type = "prefix"
				if !strings.HasPrefix(tok, "/") {
					tok = "/" + tok
				}
				nr.Path = tok
			}
			filtered = append(filtered, nr)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		li := len(strings.TrimSpace(filtered[i].Path))
		if strings.TrimSpace(filtered[i].Value) != "" {
			li = len(strings.TrimSpace(filtered[i].Value))
		}
		lj := len(strings.TrimSpace(filtered[j].Path))
		if strings.TrimSpace(filtered[j].Value) != "" {
			lj = len(strings.TrimSpace(filtered[j].Value))
		}
		return li > lj
	})
	return filtered
}

func loadNetworkDefaults(db *gorm.DB) NetworkDefaults {
	var setting store.SystemSettings
	if err := db.Where("key = ?", "network_config").First(&setting).Error; err != nil {
		return DefaultNetworkDefaults()
	}
	return LoadNetworkDefaults(setting.Value)
}

func loadTLSDefaults(db *gorm.DB) TLSDefaults {
	var setting store.SystemSettings
	if err := db.Where("key = ?", "tls_default_config").First(&setting).Error; err != nil {
		return DefaultTLSDefaults()
	}
	return LoadTLSDefaults(setting.Value)
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
