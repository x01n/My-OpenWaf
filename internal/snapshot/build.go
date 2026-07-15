package snapshot

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/waf/dynamic"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	// 一次性加载所有 system_settings 到 map，避免多次独立 DB 查询。
	settingsMap := loadAllSettings(db)

	networkDefaults := networkDefaultsFromMap(settingsMap)
	tlsDefaults := tlsDefaultsFromMap(settingsMap)
	protection, err := protectionConfigFromMap(settingsMap)
	if err != nil {
		return nil, err
	}
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
	if err := db.Where("enabled = ?", true).Find(&appRulesRaw).Error; err != nil {
		return nil, fmt.Errorf("load app route rules: %w", err)
	}
	rawBySite := make(map[uint][]store.ApplicationRouteRule)
	for _, ar := range appRulesRaw {
		rawBySite[ar.SiteID] = append(rawBySite[ar.SiteID], ar)
	}
	appRulesBySite := make(map[uint][]appresource.CompiledRule)
	for sid, raws := range rawBySite {
		appRulesBySite[sid] = appresource.CompileRules(raws)
	}

	// 从预加载的 settingsMap 中读取动态保护和排除记录头（共用 bot_settings 数据）。
	botSettingsJSON := settingsMap["bot_settings"]
	dynamicProtection := parseDynamicProtection(botSettingsJSON)
	excludeRecordHeaders := parseExcludeRecordHeaders(botSettingsJSON)

	// Load access control configs per site.
	accessControlBySite := loadAccessControlConfigs(db)

	// 加载站点级 IP 黑白名单。
	siteIPLists := loadSiteIPLists(db)

	http2Config := http2ConfigFromMap(settingsMap)
	hstsEnabled := settingBool(settingsMap, "hsts_enabled")
	xssProtectionEnabled := settingBool(settingsMap, "xss_protection_enabled")
	expectCTEnabled := settingBool(settingsMap, "expect_ct_enabled")
	expectCTValue := settingStr(settingsMap, "expect_ct_value", DefaultExpectCTValue)
	hpkpEnabled := settingBool(settingsMap, store.SettingKeyHPKP)
	hpkpValue := settingStr(settingsMap, store.SettingKeyHPKPValue, DefaultHPKPValue)
	hpkpReportOnlyEnabled := settingBool(settingsMap, store.SettingKeyHPKPReportOnly)
	hpkpReportOnlyValue := settingStr(settingsMap, store.SettingKeyHPKPReportOnlyValue, DefaultHPKPReportOnlyValue)
	brotliEnabled := settingBool(settingsMap, "brotli_enabled")
	responseCompressionEnabled := settingBool(settingsMap, "response_compression_enabled")
	responseCompressionGzipEnabled := settingBool(settingsMap, "response_compression_gzip_enabled")
	responseCompressionMinBytes := settingInt(settingsMap, "response_compression_min_bytes", DefaultResponseCompressionMinBytes)

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
		compiled := append(compileRules(rulesByPolicy[policyID]), siteCCRules(s, ccRules)...)

		// Build protection configs from site fields
		botProtection := store.BotProtectionConfig{
			Enabled: s.BotProtectionEnabled != nil && *s.BotProtectionEnabled,
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
						if staple, ok := ParseOCSPStaple(c.OCSPStaplePEM); ok {
							tlsCert.OCSPStaple = staple
						}
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
				Site:                           listenerSite,
				PolicyID:                       policyID,
				Rules:                          compiled,
				UpstreamURLs:                   urls,
				Certificate:                    cert,
				NetworkDefaults:                networkDefaults,
				TLSDefaults:                    tlsDefaults,
				Bind:                           listenerSite.Bind,
				TLSConfig:                      tlsConfig,
				BotProtection:                  botProtection,
				AttackProtection:               attackProtection,
				XFFMode:                        xffMode,
				TrustedCIDR:                    s.TrustedCIDR,
				PreserveOriginalHost:           s.PreserveOriginalHost,
				CacheEnabled:                   s.CacheEnabled,
				CacheDefaultTTL:                s.CacheDefaultTTL,
				CacheRules:                     cacheRules,
				MaintenanceEnabled:             s.MaintenanceEnabled,
				MaintenanceHTML:                s.MaintenanceHTML,
				MaintenanceStatus:              s.MaintenanceStatus,
				BlockHTML:                      s.BlockHTML,
				BlockStatus:                    s.BlockStatus,
				AntiReplayEnabled:              s.AntiReplayEnabled,
				AntiReplayAction:               s.AntiReplayAction,
				AppRouteRules:                  appRulesBySite[s.ID],
				DynamicProtection:              buildSiteDynamicProtection(dynamicProtection, s),
				AccessControl:                  accessControlBySite[s.ID],
				SiteIPWhitelist:                siteIPLists[s.ID].whitelist,
				SiteIPBlacklist:                siteIPLists[s.ID].blacklist,
				ResponseCompressionConfigured:  true,
				ResponseCompressionEnabled:     responseCompressionEnabled,
				ResponseCompressionGzipEnabled: responseCompressionGzipEnabled,
				ResponseCompressionMinBytes:    responseCompressionMinBytes,
				BrotliEnabled:                  brotliEnabled,
			}
			if err := registerSiteKeys(siteMap, rt); err != nil {
				return nil, err
			}
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
		Revision:                       rev,
		Sites:                          siteMap,
		NetworkDefaults:                networkDefaults,
		TLSDefaults:                    tlsDefaults,
		DefaultBlockHTML:               "",
		SiteTLSCertBySNI:               sniCerts,
		Protection:                     protection,
		HTTP2Config:                    http2Config,
		HSTSEnabled:                    hstsEnabled,
		XSSProtectionEnabled:           xssProtectionEnabled,
		ExpectCTEnabled:                expectCTEnabled,
		ExpectCTValue:                  expectCTValue,
		HPKPEnabled:                    hpkpEnabled,
		HPKPValue:                      hpkpValue,
		HPKPReportOnlyEnabled:          hpkpReportOnlyEnabled,
		HPKPReportOnlyValue:            hpkpReportOnlyValue,
		ResponseCompressionEnabled:     responseCompressionEnabled,
		ResponseCompressionGzipEnabled: responseCompressionGzipEnabled,
		ResponseCompressionMinBytes:    responseCompressionMinBytes,
		BrotliEnabled:                  brotliEnabled,
		ExcludeRecordHeaders:           excludeRecordHeaders,
	}, nil
}

// mergeProtection creates a ProtectionConfig for a site by overlaying
// per-site overrides onto the global config. nil = inherit global.
func mergeProtection(global store.ProtectionConfig, site store.Site) store.ProtectionConfig {
	p := global // shallow copy

	// Bot detection: per-site override
	if site.BotProtectionEnabled != nil {
		p.BotDetectionEnabled = *site.BotProtectionEnabled
	}

	// OWASP override
	if site.OWASPEnabled != nil {
		p.OWASPEnabled = *site.OWASPEnabled
		if site.OWASPSensitivity != "" {
			p.OWASPSensitivity = site.OWASPSensitivity
		}
		if site.OWASPAction != "" {
			p.OWASPAction = site.OWASPAction
		}
	}

	// CVE override
	if site.CVEEnabled != nil {
		p.CVEEnabled = *site.CVEEnabled
		if site.CVEAction != "" {
			p.CVEAction = site.CVEAction
		}
		if site.CVEAction == string(store.ActionObserve) {
			p.CVEAutoDropCritical = false
			p.CVEAutoDropHigh = false
		}
	}

	// Rate limit override
	if site.RateLimitEnabled != nil {
		p.RequestRateLimitEnabled = *site.RateLimitEnabled
		if site.RateLimitWindow > 0 {
			p.RequestRateLimitWindow = site.RateLimitWindow
		}
		if site.RateLimitMax > 0 {
			p.RequestRateLimitMax = site.RateLimitMax
		}
		if site.RateLimitAction != "" {
			p.RequestRateLimitAction = site.RateLimitAction
		}
	}

	return p
}

func registerSiteKeys(m map[string]SiteRuntime, rt SiteRuntime) error {
	bind := rt.Bind
	for _, host := range splitHosts(rt.Site.Host) {
		h := NormalizeMatchHost(host)
		if h == "" {
			continue
		}
		k := SiteMapKey(bind, h)
		if existing, exists := m[k]; exists {
			if existing.Site.ID == rt.Site.ID {
				continue
			}
			return fmt.Errorf("duplicate site route bind=%q host=%q site_ids=%d,%d", bind, h, existing.Site.ID, rt.Site.ID)
		}
		m[k] = rt
	}
	return nil
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
	return compileCCRulesFromJSON(protection.CCRules)
}

// siteCCRules 返回站点生效的 CC 规则。
// 站点 CCUseCustom 为 nil 时继承全局（globalCCRules）；非 nil 时按站点自身配置：
// true 用站点 CCRules 编译，false 表示站点显式关闭 CC 规则（返回空）。
func siteCCRules(s store.Site, globalCCRules []CompiledRule) []CompiledRule {
	if s.CCUseCustom == nil {
		return globalCCRules
	}
	if !*s.CCUseCustom {
		return nil
	}
	return compileCCRulesFromJSON(s.CCRules)
}

// compileCCRulesFromJSON 从 CC 规则 JSON 编译出运行时规则。
// 全局配置与站点级覆盖共用此逻辑。
func compileCCRulesFromJSON(rulesJSON string) []CompiledRule {
	if strings.TrimSpace(rulesJSON) == "" {
		return nil
	}
	var configs []ccRuleConfig
	if err := json.Unmarshal([]byte(rulesJSON), &configs); err != nil {
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
	case "captcha_challenge":
		return store.ActionCaptchaChallenge
	case "shield_challenge":
		return store.ActionShieldChallenge
	case "chain_challenge":
		return store.ActionChainChallenge
	case "block", "intercept":
		return store.ActionIntercept
	case "drop":
		return store.ActionDrop
	case "rate_limit":
		return store.ActionRateLimit
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
		"tls_ja3:", "tls_ja3_hash:", "tls_ja4:", "tls_version:", "tls_sni:", "tls_alpn:", "tls_cipher_suite:", "tls_cipher_suites:", "header_order_contains:", "header_order_regex:",
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

// networkDefaultsFromMap 从预加载的 settings map 中读取网络默认配置。
func networkDefaultsFromMap(m map[string]string) NetworkDefaults {
	v, ok := m["network_config"]
	if !ok || v == "" {
		return DefaultNetworkDefaults()
	}
	return LoadNetworkDefaults(v)
}

func loadTLSDefaults(db *gorm.DB) TLSDefaults {
	var setting store.SystemSettings
	if err := db.Where("key = ?", "tls_default_config").First(&setting).Error; err != nil {
		return DefaultTLSDefaults()
	}
	return LoadTLSDefaults(setting.Value)
}

// tlsDefaultsFromMap 从预加载的 settings map 中读取 TLS 默认配置。
func tlsDefaultsFromMap(m map[string]string) TLSDefaults {
	v, ok := m["tls_default_config"]
	if !ok || v == "" {
		return DefaultTLSDefaults()
	}
	return LoadTLSDefaults(v)
}

func loadProtectionConfig(db *gorm.DB) (store.ProtectionConfig, error) {
	var setting store.SystemSettings
	if err := db.Where("key = ?", "protection").First(&setting).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return store.DefaultProtectionConfig(), nil
		}
		return store.ProtectionConfig{}, fmt.Errorf("load protection config: %w", err)
	}
	cfg := store.DefaultProtectionConfig()
	if err := json.Unmarshal([]byte(setting.Value), &cfg); err != nil {
		return store.ProtectionConfig{}, fmt.Errorf("invalid protection config JSON: %w", err)
	}
	return cfg, nil
}

// protectionConfigFromMap 从预加载的 settings map 中读取 protection 配置。
func protectionConfigFromMap(m map[string]string) (store.ProtectionConfig, error) {
	v, ok := m["protection"]
	if !ok || v == "" {
		return store.DefaultProtectionConfig(), nil
	}
	cfg := store.DefaultProtectionConfig()
	if err := json.Unmarshal([]byte(v), &cfg); err != nil {
		return store.ProtectionConfig{}, fmt.Errorf("invalid protection config JSON: %w", err)
	}
	return cfg, nil
}
func loadDynamicProtection(db *gorm.DB) dynamic.ProtectionConfig {
	var setting store.SystemSettings
	if err := db.Where("key = ?", "bot_settings").First(&setting).Error; err != nil {
		return dynamic.ProtectionConfig{}
	}
	return parseDynamicProtection(setting.Value)
}

// parseDynamicProtection 从 bot_settings JSON 字符串解析动态保护配置。
func parseDynamicProtection(raw string) dynamic.ProtectionConfig {
	if raw == "" {
		return dynamic.ProtectionConfig{}
	}

	var bs struct {
		DynamicProtectionEnabled bool     `json:"dynamic_protection_enabled"`
		HTMLObfuscation          bool     `json:"html_obfuscation"`
		JSObfuscation            bool     `json:"js_obfuscation"`
		ImageWatermark           bool     `json:"image_watermark"`
		JSObfuscationPaths       []string `json:"js_obfuscation_paths,omitempty"`
		JSProtectionMode         string   `json:"js_protection_mode,omitempty"`
		DecryptCacheTTLSeconds   int      `json:"decrypt_cache_ttl_seconds,omitempty"`
		ImageWatermarkPaths      []string `json:"image_watermark_paths,omitempty"`
		WatermarkText            string   `json:"watermark_text,omitempty"`
	}
	if err := json.Unmarshal([]byte(raw), &bs); err != nil {
		return dynamic.ProtectionConfig{}
	}

	return dynamic.ProtectionConfig{
		HTMLObfuscationEnabled: bs.DynamicProtectionEnabled && bs.HTMLObfuscation,
		JSObfuscationEnabled:   bs.DynamicProtectionEnabled && bs.JSObfuscation,
		ImageWatermarkEnabled:  bs.DynamicProtectionEnabled && bs.ImageWatermark,
		JSProtectionMode:       bs.JSProtectionMode,
		DecryptCacheTTLSeconds: bs.DecryptCacheTTLSeconds,
		JSObfuscationPaths:     bs.JSObfuscationPaths,
		ImageWatermarkPaths:    bs.ImageWatermarkPaths,
		WatermarkText:          bs.WatermarkText,
	}
}

// buildSiteDynamicProtection 基于全局动态保护配置，合并站点级覆盖字段。
func buildSiteDynamicProtection(global dynamic.ProtectionConfig, site store.Site) dynamic.ProtectionConfig {
	cfg := global
	cfg.SiteID = site.ID

	if site.DynamicProtectionEnabled != nil && !*site.DynamicProtectionEnabled {
		cfg.HTMLObfuscationEnabled = false
		cfg.JSObfuscationEnabled = false
		return cfg
	}
	if site.DynamicHTMLEnabled != nil {
		cfg.HTMLObfuscationEnabled = *site.DynamicHTMLEnabled
	}
	if site.DynamicJSEnabled != nil {
		cfg.JSObfuscationEnabled = *site.DynamicJSEnabled
	}
	if site.DynamicJSMode != "" {
		cfg.JSProtectionMode = site.DynamicJSMode
	}
	if site.DynamicJSPaths != "" {
		var paths []string
		if err := json.Unmarshal([]byte(site.DynamicJSPaths), &paths); err == nil && len(paths) > 0 {
			cfg.JSObfuscationPaths = paths
		}
	}
	if site.DynamicDecryptCacheTTL != nil {
		cfg.DecryptCacheTTLSeconds = *site.DynamicDecryptCacheTTL
	}
	return cfg
}

func loadExcludeRecordHeaders(db *gorm.DB) []string {
	var setting store.SystemSettings
	if err := db.Where("key = ?", "bot_settings").First(&setting).Error; err != nil {
		return nil
	}
	return parseExcludeRecordHeaders(setting.Value)
}

// parseExcludeRecordHeaders 从 bot_settings JSON 字符串解析排除记录头列表。
func parseExcludeRecordHeaders(raw string) []string {
	if raw == "" {
		return nil
	}
	var bs struct {
		ExcludeRecordHeaders []string `json:"exclude_record_headers,omitempty"`
	}
	if err := json.Unmarshal([]byte(raw), &bs); err != nil {
		return nil
	}
	return bs.ExcludeRecordHeaders
}

func loadHTTP2Config(db *gorm.DB) HTTP2Config {
	var setting store.SystemSettings
	if err := db.Where("key = ?", "http2_config").First(&setting).Error; err != nil {
		return DefaultHTTP2Config()
	}
	return LoadHTTP2Config(setting.Value)
}

// http2ConfigFromMap 从预加载的 settings map 中读取 HTTP/2 配置。
func http2ConfigFromMap(m map[string]string) HTTP2Config {
	v, ok := m["http2_config"]
	if !ok || v == "" {
		return DefaultHTTP2Config()
	}
	return LoadHTTP2Config(v)
}

func loadBoolSetting(db *gorm.DB, key string) bool {
	var setting store.SystemSettings
	if err := db.Where("key = ?", key).First(&setting).Error; err != nil {
		return false
	}
	v := strings.TrimSpace(strings.ToLower(setting.Value))
	return v == "true" || v == "1" || v == "yes"
}

func loadStringSetting(db *gorm.DB, key string, defaultValue string) string {
	var setting store.SystemSettings
	if err := db.Where("key = ?", key).First(&setting).Error; err != nil {
		return defaultValue
	}
	if strings.TrimSpace(setting.Value) == "" {
		return defaultValue
	}
	return setting.Value
}

func loadIntSetting(db *gorm.DB, key string, defaultValue int) int {
	var setting store.SystemSettings
	if err := db.Where("key = ?", key).First(&setting).Error; err != nil {
		return defaultValue
	}
	v, err := strconv.Atoi(strings.TrimSpace(setting.Value))
	if err != nil {
		return defaultValue
	}
	return v
}

// loadAllSettings 一次性加载所有 system_settings 到 map，避免多次独立查询。
func loadAllSettings(db *gorm.DB) map[string]string {
	var all []store.SystemSettings
	db.Find(&all)
	m := make(map[string]string, len(all))
	for _, s := range all {
		m[s.Key] = s.Value
	}
	return m
}

// settingBool 从预加载的 settings map 中读取布尔值。
func settingBool(m map[string]string, key string) bool {
	v := strings.TrimSpace(strings.ToLower(m[key]))
	return v == "true" || v == "1" || v == "yes"
}

// settingStr 从预加载的 settings map 中读取字符串，为空时返回默认值。
func settingStr(m map[string]string, key string, defaultValue string) string {
	v := m[key]
	if strings.TrimSpace(v) == "" {
		return defaultValue
	}
	return v
}

// settingInt 从预加载的 settings map 中读取整数，解析失败时返回默认值。
func settingInt(m map[string]string, key string, defaultValue int) int {
	raw := strings.TrimSpace(m[key])
	if raw == "" {
		return defaultValue
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return defaultValue
	}
	return v
}

// systemSettingKeyEquals returns a GORM clause for querying system settings by key.
func systemSettingKeyEquals(key string) clause.Eq {
	return clause.Eq{Column: clause.Column{Name: "key"}, Value: key}
}

// ResolveOutboundHost resolves the upstream host for a request.
// It prefers the site's explicit upstream host, then the upstream host header, and falls back to the incoming host.
func ResolveOutboundHost(rt SiteRuntime, upstreamHost string, incomingHost string) (string, error) {
	if rt.Site.UpstreamHost != "" {
		return rt.Site.UpstreamHost, nil
	}
	if rt.UpstreamHostHeader != "" {
		return rt.UpstreamHostHeader, nil
	}
	if upstreamHost != "" {
		return upstreamHost, nil
	}
	return incomingHost, nil
}

// loadAccessControlConfigs 从数据库批量加载所有站点的访问控制配置，避免 N+1 查询。
func loadAccessControlConfigs(db *gorm.DB) map[uint]*AccessControlConfig {
	result := make(map[uint]*AccessControlConfig)

	var configs []store.SiteAccessConfig
	if err := db.Where("enabled = ?", true).Find(&configs).Error; err != nil {
		return result
	}

	// 批量加载所有启用的 provider，按 site_id 分组。
	var allProviders []store.AccessProvider
	db.Where("enabled = ?", true).Order("site_id ASC, priority ASC").Find(&allProviders)
	providersBySite := make(map[uint][]store.AccessProvider)
	for _, p := range allProviders {
		providersBySite[p.SiteID] = append(providersBySite[p.SiteID], p)
	}

	// 批量加载所有启用的路径规则，按 site_id 分组。
	var allPathRules []store.AccessPathRule
	db.Where("enabled = ?", true).Order("site_id ASC, priority ASC").Find(&allPathRules)
	pathRulesBySite := make(map[uint][]store.AccessPathRule)
	for _, r := range allPathRules {
		pathRulesBySite[r.SiteID] = append(pathRulesBySite[r.SiteID], r)
	}

	for _, cfg := range configs {
		ac := &AccessControlConfig{
			Enabled:            true,
			SharedPasswordHash: cfg.SharedPasswordHash,
			SessionTTL:         cfg.SessionTTL,
		}

		for _, p := range providersBySite[cfg.SiteID] {
			ac.Providers = append(ac.Providers, AccessControlProvider{
				ID:       p.ID,
				Type:     p.Type,
				Name:     p.Name,
				Priority: p.Priority,
				Config:   p.Config,
			})
		}

		for _, r := range pathRulesBySite[cfg.SiteID] {
			ac.PathRules = append(ac.PathRules, AccessControlPathRule{
				Path:     r.Path,
				Action:   r.Action,
				Priority: r.Priority,
			})
		}

		result[cfg.SiteID] = ac
	}
	return result
}

// siteIPListPair 存储一个站点的已解析黑白名单。
type siteIPListPair struct {
	whitelist []net.IPNet
	blacklist []net.IPNet
}

// loadSiteIPLists 从数据库加载所有站点级 IP 黑白名单（不含全局条目）。
func loadSiteIPLists(db *gorm.DB) map[uint]siteIPListPair {
	result := make(map[uint]siteIPListPair)
	var items []store.IPListEntry
	if err := db.Where("enabled = ? AND site_id IS NOT NULL", true).Find(&items).Error; err != nil {
		return result
	}
	for _, it := range items {
		if it.SiteID == nil {
			continue
		}
		siteID := *it.SiteID
		pair := result[siteID]
		val := strings.TrimSpace(it.Value)
		if val == "" {
			continue
		}
		var ipNet net.IPNet
		if _, cidr, err := net.ParseCIDR(val); err == nil {
			ipNet = *cidr
		} else if ip := net.ParseIP(val); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				ipNet = net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
			} else {
				ipNet = net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		} else {
			continue
		}
		if it.Kind == store.IPListWhite {
			pair.whitelist = append(pair.whitelist, ipNet)
		} else if it.Kind == store.IPListBlack {
			pair.blacklist = append(pair.blacklist, ipNet)
		}
		result[siteID] = pair
	}
	return result
}
