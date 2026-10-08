package snapshot

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"My-OpenWaf/internal/appresource"
	"My-OpenWaf/internal/pkg/schemealias"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/access"
	"My-OpenWaf/internal/store/approute"
	cvestore "My-OpenWaf/internal/store/cve"
	"My-OpenWaf/internal/store/iplist"
	owaspstore "My-OpenWaf/internal/store/owasp"
	"My-OpenWaf/internal/store/upstream"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/cve"
	"My-OpenWaf/internal/waf/dynamic"
	"My-OpenWaf/internal/waf/iprep"
	"My-OpenWaf/internal/waf/owasp"
	"My-OpenWaf/internal/waf/pageconfig"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/**
 * Build 从数据库加载全部运行期配置，构建一个不可变快照。
 *
 * 这是配置生效的唯一入口：站点、监听、证书、规则、策略、访问控制、动态防护与各类
 * 保护设置都在这里一次性读取并编译。构建期发现的问题按严重程度分流——致命错误直接
 * 返回 error 让 reload 失败，可跳过的无效项记入 ConfigDiagnostics 随快照一起发布，
 * 由管理端展示。
 *
 * @param db 主库句柄。
 * @param rev 本次快照的配置修订号，用于 Holder 的 StoreIfNewer 比较。
 * @param dynamicKeyBase 动态防护加密密钥的基值。
 * @return 构建完成的快照。
 */
func Build(db *gorm.DB, rev uint64, dynamicKeyBase []byte) (*Snapshot, error) {
	var sites []store.Site
	if err := db.Where("enabled = ?", true).Find(&sites).Error; err != nil {
		return nil, err
	}

	hasPolicyTable := db.Migrator().HasTable(&store.Policy{})
	policyByID := make(map[uint]store.Policy)
	defaultPolicyID := uint(0)
	if hasPolicyTable {
		var policies []store.Policy
		if err := db.Find(&policies).Error; err != nil {
			return nil, fmt.Errorf("load policies: %w", err)
		}
		policyByID = make(map[uint]store.Policy, len(policies))
		for _, policy := range policies {
			policyByID[policy.ID] = policy
			if policy.DefaultSlot != nil && *policy.DefaultSlot == 1 {
				if defaultPolicyID != 0 {
					return nil, fmt.Errorf("multiple default policies configured")
				}
				defaultPolicyID = policy.ID
			}
		}
		if defaultPolicyID == 0 {
			return nil, fmt.Errorf("default policy not configured")
		}
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
	settingsMap, err := loadAllSettings(db)
	if err != nil {
		return nil, fmt.Errorf("load system settings: %w", err)
	}

	networkDefaults := networkDefaultsFromMap(settingsMap)
	tlsDefaults := tlsDefaultsFromMap(settingsMap)
	protection, err := protectionConfigFromMap(settingsMap)
	if err != nil {
		return nil, err
	}
	ccRules := compileCCRules(protection)
	owaspConfigsByPolicy, owaspDiagnostics, err := loadPolicyOWASPConfigs(db)
	if err != nil {
		return nil, err
	}
	cveConfigsBySite, err := loadSiteCVEConfigs(db, sites, defaultPolicyID)
	if err != nil {
		return nil, err
	}
	rulesByPolicy := make(map[uint][]store.Rule)
	for _, r := range rules {
		if hasPolicyTable && r.PolicyID == 0 {
			return nil, fmt.Errorf("rule %d has invalid policy_id 0", r.ID)
		}
		if hasPolicyTable {
			if _, ok := policyByID[r.PolicyID]; !ok {
				return nil, fmt.Errorf("rule %d references missing policy %d", r.ID, r.PolicyID)
			}
		}
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

	// 加载应用路由规则并按站点编译。
	var appRulesRaw []approute.ApplicationRouteRule
	if err := db.Where("enabled = ?", true).Find(&appRulesRaw).Error; err != nil {
		return nil, fmt.Errorf("load app route rules: %w", err)
	}
	rawBySite := make(map[uint][]approute.ApplicationRouteRule)
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
	if len(dynamicKeyBase) != 32 {
		return nil, fmt.Errorf("dynamic protection key base must be 32 bytes")
	}
	dynamicProtection.EncryptionKeyBase = append([]byte(nil), dynamicKeyBase...)
	excludeRecordHeaders := parseExcludeRecordHeaders(botSettingsJSON)

	// 加载各站点的访问控制配置。
	accessControlBySite, err := loadAccessControlConfigs(db)
	if err != nil {
		return nil, fmt.Errorf("load access control configs: %w", err)
	}

	// 加载站点级 IP 黑白名单。
	siteIPLists, ipListDiagnostics, err := loadSiteIPLists(db)
	if err != nil {
		return nil, fmt.Errorf("load site IP lists: %w", err)
	}

	http2Config := http2ConfigFromMap(settingsMap)
	hstsEnabled := settingBool(settingsMap, "hsts_enabled")
	xssProtectionEnabled := settingBool(settingsMap, "xss_protection_enabled")
	expectCTEnabled := settingBool(settingsMap, "expect_ct_enabled")
	expectCTValue := settingStr(settingsMap, "expect_ct_value", DefaultExpectCTValue)
	hpkpEnabled := settingBool(settingsMap, store.SettingKeyHPKP)
	hpkpValue := settingStr(settingsMap, store.SettingKeyHPKPValue, DefaultHPKPValue)
	hpkpReportOnlyEnabled := settingBool(settingsMap, store.SettingKeyHPKPReportOnly)
	hpkpReportOnlyValue := settingStr(settingsMap, store.SettingKeyHPKPReportOnlyValue, DefaultHPKPReportOnlyValue)
	// 响应压缩：这四个开关的缺省值是「开」——DB 里没有对应设置行时按启用处理
	// （用户裁定「支持全部都开启」）。显式写入 "false"/"0"/"no" 仍然关闭。
	brotliEnabled := settingBoolDefault(settingsMap, store.SettingKeyBrotliEnabled, DefaultBrotliEnabled)
	responseCompressionEnabled := settingBoolDefault(settingsMap, store.SettingKeyResponseCompressionEnabled, DefaultResponseCompressionEnabled)
	responseCompressionGzipEnabled := settingBoolDefault(settingsMap, store.SettingKeyResponseCompressionGzipEnabled, DefaultResponseCompressionGzipEnabled)
	responseCompressionDeflateEnabled := settingBoolDefault(settingsMap, store.SettingKeyResponseCompressionDeflateEnabled, DefaultResponseCompressionDeflate)
	responseCompressionZstdEnabled := settingBoolDefault(settingsMap, store.SettingKeyResponseCompressionZstdEnabled, DefaultResponseCompressionZstd)
	responseCompressionMinBytes := settingInt(settingsMap, store.SettingKeyResponseCompressionMinBytes, DefaultResponseCompressionMinBytes)
	captchaPage := pageconfig.ParseCaptchaPageConfig(settingsMap[pageconfig.SettingKeyCaptchaPage])
	challengePage := pageconfig.ParseChallengePageConfig(settingsMap[pageconfig.SettingKeyChallengePage])
	blockPage := pageconfig.ParseBlockPageConfig(settingsMap[pageconfig.SettingKeyBlockPage])

	sniCerts := make(map[string]tls.Certificate)
	sniCertStates := make(map[string]TLSCertificateState)
	certificateDiagnostics := make([]SnapshotConfigDiagnostic, 0)
	siteMap := make(map[string]*SiteRuntime)

	// 上游 mTLS 的构建期认定：用下标预计算一次并写入切片元素，主循环的 s 取
	// 同一份已算好的 DER/Key/Bad，构建全程只做一次 PEM 解析。
	for i := range sites {
		pre := &sites[i]
		pre.PrepareUpstreamMTLSRuntime()
		if pre.UpstreamTLSClientCertPEM != nil && len(*pre.UpstreamTLSClientCertPEM) > upstream.MaxUpstreamMTLSPEMBytes {
			certificateDiagnostics = append(certificateDiagnostics, SnapshotConfigDiagnostic{
				Source: DiagnosticSourceSites, Field: DiagnosticFieldUpstreamMTLS,
				Error: "upstream_mtls_pem_overflow", HandlingStrategy: DiagnosticHandlingSkipInvalidField,
				Kind: "upstream_mtls", Reason: "upstream_mtls_pem_overflow", SiteID: pre.ID,
			})
		} else if pre.UpstreamTLSClientKeyPEM != nil && len(*pre.UpstreamTLSClientKeyPEM) > upstream.MaxUpstreamMTLSPEMBytes {
			certificateDiagnostics = append(certificateDiagnostics, SnapshotConfigDiagnostic{
				Source: DiagnosticSourceSites, Field: DiagnosticFieldUpstreamMTLS,
				Error: "upstream_mtls_pem_overflow", HandlingStrategy: DiagnosticHandlingSkipInvalidField,
				Kind: "upstream_mtls", Reason: "upstream_mtls_pem_overflow", SiteID: pre.ID,
			})
		} else {
			hasCert := pre.UpstreamTLSClientCertPEM != nil && strings.TrimSpace(*pre.UpstreamTLSClientCertPEM) != ""
			hasKey := pre.UpstreamTLSClientKeyPEM != nil && strings.TrimSpace(*pre.UpstreamTLSClientKeyPEM) != ""
			if hasCert != hasKey {
				certificateDiagnostics = append(certificateDiagnostics, SnapshotConfigDiagnostic{
					Source: DiagnosticSourceSites, Field: DiagnosticFieldUpstreamMTLS,
					Error: "upstream_mtls_unpaired", HandlingStrategy: DiagnosticHandlingSkipInvalidField,
					Kind: "upstream_mtls", Reason: "upstream_mtls_unpaired", SiteID: pre.ID,
				})
			} else if pre.UpstreamTLSClientCertBad {
				certificateDiagnostics = append(certificateDiagnostics, SnapshotConfigDiagnostic{
					Source: DiagnosticSourceSites, Field: DiagnosticFieldUpstreamMTLS,
					Error: "upstream_mtls_unparseable_pair", HandlingStrategy: DiagnosticHandlingSkipInvalidField,
					Kind: "upstream_mtls", Reason: "upstream_mtls_unparseable_pair", SiteID: pre.ID,
				})
			}
		}
	}

	for _, s := range sites {
		urls := parseUpstreamURLs(s.UpstreamURLs)
		if len(urls) == 0 {
			continue
		}

		policyID := defaultPolicyID
		if s.PolicyID != nil && *s.PolicyID != 0 {
			if hasPolicyTable {
				if _, ok := policyByID[*s.PolicyID]; !ok {
					return nil, fmt.Errorf("site %d references missing policy %d", s.ID, *s.PolicyID)
				}
			}
			policyID = *s.PolicyID
		}
		compiled := append(compileRules(rulesByPolicy[policyID]), siteCCRules(s, ccRules)...)

		// 由站点字段构建保护配置
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

		// 从站点取转发设置
		xffMode := s.XFFMode
		if xffMode == "" {
			xffMode = store.XFFModeStrip
		}
		cacheRules, err := store.ValidateAndCompileSiteCacheRules(s.CacheRules, s.CacheDefaultTTL)
		if err != nil {
			return nil, fmt.Errorf("site %d cache_rules: %w", s.ID, err)
		}
		clientIPHeaderOrder := parseClientIPHeaderOrder(s.ClientIPHeaderOrder)

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
			certificateState := TLSCertificateState("")
			certificateDiagnosticSource := DiagnosticSourceListeners
			if listener.ID == 0 {
				certificateDiagnosticSource = DiagnosticSourceSites
			}
			if listenerSite.CertID == nil {
				if listenerSite.TLSEnabled {
					certificateState = TLSCertificateStateUnconfigured
				}
			} else if listenerSite.TLSEnabled {
				certificateID := *listenerSite.CertID
				c, ok := certByID[certificateID]
				if !ok {
					if listenerSite.TLSEnabled {
						certificateState = TLSCertificateStateInvalid
						certificateDiagnostics = append(certificateDiagnostics, SnapshotConfigDiagnostic{
							Source:           certificateDiagnosticSource,
							Field:            DiagnosticFieldCertificateID,
							Error:            "certificate_not_found",
							HandlingStrategy: DiagnosticHandlingRejectInvalidCertificate,
							Kind:             "tls_certificate",
							Reason:           "certificate_not_found",
							CertificateID:    certificateID,
							ListenerID:       listener.ID,
							SiteID:           s.ID,
						})
					}
				} else {
					cert = &c
					tlsCert, err := tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
					if err != nil {
						certificateState = TLSCertificateStateInvalid
						reason := "invalid_certificate_or_key"
						if strings.TrimSpace(c.CertPEM) == "" || strings.TrimSpace(c.KeyPEM) == "" {
							reason = "empty_certificate_or_key"
						}
						certificateDiagnostics = append(certificateDiagnostics, SnapshotConfigDiagnostic{
							Source:           DiagnosticSourceCertificates,
							Field:            DiagnosticFieldCertificatePair,
							Error:            reason,
							HandlingStrategy: DiagnosticHandlingRejectInvalidCertificate,
							Kind:             "tls_certificate",
							Reason:           reason,
							CertificateID:    certificateID,
							ListenerID:       listener.ID,
							SiteID:           s.ID,
						})
					} else {
						certificateState = TLSCertificateStateValid
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
					}
				}
			}
			for _, rawHost := range splitHosts(listenerSite.Host) {
				h := NormalizeMatchHost(rawHost)
				if h == "" {
					continue
				}
				if listenerSite.TLSEnabled && certificateState != "" {
					sniCertStates[SNICertKey(listenerSite.Bind, h)] = certificateState
				}
				if certificateState == TLSCertificateStateValid && tlsConfig != nil {
					sniCerts[SNICertKey(listenerSite.Bind, h)] = tlsConfig.Certificates[0]
				}
			}

			siteDynamicProtection := buildSiteDynamicProtection(dynamicProtection, s)
			if (siteDynamicProtection.HTMLObfuscationEnabled || siteDynamicProtection.JSObfuscationEnabled) && len(siteDynamicProtection.EncryptionKeyBase) != 32 {
				return nil, fmt.Errorf("site %d dynamic protection requires a 32-byte encryption key base", s.ID)
			}

			rt := SiteRuntime{
				Site:                 listenerSite, // 含预计算的 UpstreamTLSClientCertDER/Key/Bad
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
				ClientIPHeaderOrder:  clientIPHeaderOrder,
				PreserveOriginalHost: s.PreserveOriginalHost,
				CacheEnabled:         s.CacheEnabled,
				CacheDefaultTTL:      s.CacheDefaultTTL,
				CacheRules:           cacheRules,
				MaintenanceEnabled:   s.MaintenanceEnabled,
				MaintenanceHTML:      s.MaintenanceHTML,
				MaintenanceStatus:    s.MaintenanceStatus,
				// 站点级质询策略（nil = 继承全局，数据面渲染时再回退）。
				ChallengeAction:                   maybeSiteString(s.ChallengeAction),
				ChallengeCaptchaType:              maybeSiteString(s.SiteCaptchaType),
				BlockHTML:                         s.BlockHTML,
				BlockStatus:                       s.BlockStatus,
				AntiReplayEnabled:                 protection.AntiReplayEnabled,
				AntiReplayAction:                  s.AntiReplayAction,
				AppRouteRules:                     appRulesBySite[s.ID],
				DynamicProtection:                 siteDynamicProtection,
				AccessControl:                     accessControlBySite[s.ID],
				SiteIPWhitelist:                   siteIPLists[s.ID].whitelist,
				SiteIPBlacklist:                   siteIPLists[s.ID].blacklist,
				ResponseCompressionConfigured:     true,
				ResponseCompressionEnabled:        responseCompressionEnabled,
				ResponseCompressionGzipEnabled:    responseCompressionGzipEnabled,
				ResponseCompressionDeflateEnabled: responseCompressionDeflateEnabled,
				ResponseCompressionZstdEnabled:    responseCompressionZstdEnabled,
				ResponseCompressionMinBytes:       responseCompressionMinBytes,
				BrotliEnabled:                     brotliEnabled,
			}
			if err := registerSiteKeys(siteMap, &rt); err != nil {
				return nil, err
			}
		}
		// EffectiveProtection 的合并要等全局保护配置加载完之后再做。
	}

	// 把站点覆盖值叠加到全局配置上，算出每站点的生效保护配置。
	for _, rt := range siteMap {
		ep := mergeProtection(protection, rt.Site)
		if raw, ok := owaspConfigsByPolicy[rt.PolicyID]; ok {
			ep.OWASPRulesConfig = raw
		} else if rt.PolicyID != defaultPolicyID {
			ep.OWASPRulesConfig = "{}"
		}
		if raw, ok := cveConfigsBySite[rt.Site.ID]; ok {
			ep.CVERulesConfig = raw
		}
		rt.AntiReplayEnabled = ep.AntiReplayEnabled
		rt.AntiReplayCookieMode = NormalizeAntiReplayCookieMode(ep.AntiReplayCookieMode)
		rt.EffectiveProtection = &ep
	}

	// 自定义 Lua 策略：在此编译，语法错误在 reload 时即暴露。
	// 单脚本编译失败只记错误、不中断构建（见 loadLuaPlugins）。
	luaScripts, luaErrs, err := loadLuaPlugins(db)
	if err != nil {
		return nil, fmt.Errorf("load lua plugins: %w", err)
	}
	jsScripts, jsErrs, err := loadJSPlugins(db)
	if err != nil {
		return nil, fmt.Errorf("load js plugins: %w", err)
	}

	configDiagnostics := make(
		[]SnapshotConfigDiagnostic,
		0,
		len(owaspDiagnostics)+len(ipListDiagnostics)+len(certificateDiagnostics),
	)
	configDiagnostics = append(configDiagnostics, owaspDiagnostics...)
	configDiagnostics = append(configDiagnostics, ipListDiagnostics...)
	configDiagnostics = append(configDiagnostics, certificateDiagnostics...)

	return &Snapshot{
		LuaPlugins:                        luaScripts,
		LuaPluginErrors:                   luaErrs,
		JSPlugins:                         jsScripts,
		JSPluginErrors:                    jsErrs,
		ConfigDiagnostics:                 configDiagnostics,
		Revision:                          rev,
		Sites:                             siteMap,
		NetworkDefaults:                   networkDefaults,
		TLSDefaults:                       tlsDefaults,
		DefaultBlockHTML:                  "",
		CaptchaPage:                       captchaPage,
		ChallengePage:                     challengePage,
		BlockPage:                         blockPage,
		SiteTLSCertBySNI:                  sniCerts,
		SiteTLSCertStateBySNI:             sniCertStates,
		Protection:                        protection,
		HTTP2Config:                       http2Config,
		HSTSEnabled:                       hstsEnabled,
		XSSProtectionEnabled:              xssProtectionEnabled,
		ExpectCTEnabled:                   expectCTEnabled,
		ExpectCTValue:                     expectCTValue,
		HPKPEnabled:                       hpkpEnabled,
		HPKPValue:                         hpkpValue,
		HPKPReportOnlyEnabled:             hpkpReportOnlyEnabled,
		HPKPReportOnlyValue:               hpkpReportOnlyValue,
		ResponseCompressionEnabled:        responseCompressionEnabled,
		ResponseCompressionGzipEnabled:    responseCompressionGzipEnabled,
		ResponseCompressionDeflateEnabled: responseCompressionDeflateEnabled,
		ResponseCompressionZstdEnabled:    responseCompressionZstdEnabled,
		ResponseCompressionMinBytes:       responseCompressionMinBytes,
		BrotliEnabled:                     brotliEnabled,
		ExcludeRecordHeaders:              excludeRecordHeaders,
	}, nil
}

func loadPolicyOWASPConfigs(db *gorm.DB) (map[uint]string, []SnapshotConfigDiagnostic, error) {
	result := make(map[uint]string)
	diagnostics := make([]SnapshotConfigDiagnostic, 0)
	if !db.Migrator().HasTable(&owaspstore.PolicyOWASPRuleConfig{}) {
		return result, diagnostics, nil
	}
	var configs []owaspstore.PolicyOWASPRuleConfig
	if err := db.Order("policy_id ASC, rule_id ASC, id ASC").Find(&configs).Error; err != nil {
		return nil, nil, fmt.Errorf("load policy OWASP configs: %w", err)
	}
	grouped := make(map[uint]map[string]owasp.OWASPRuleOverride)
	for _, config := range configs {
		override := owasp.OWASPRuleOverride{}
		if config.Enabled != nil {
			override.Enabled = config.Enabled
		}
		if config.Action != nil {
			override.Action = *config.Action
		}
		if config.Sensitivity != nil {
			override.Sensitivity = *config.Sensitivity
		}
		if config.StatusCode != nil {
			override.StatusCode = *config.StatusCode
		}
		if config.RedirectTo != nil {
			override.RedirectTo = *config.RedirectTo
		}
		if config.CaptchaType != nil {
			override.CaptchaType = normalizeRuleCaptchaType(*config.CaptchaType)
		}
		if config.Whitelist != nil && strings.TrimSpace(*config.Whitelist) != "" {
			var whitelist []string
			if err := json.Unmarshal([]byte(*config.Whitelist), &whitelist); err != nil {
				diagnostics = append(diagnostics, SnapshotConfigDiagnostic{
					Source:           DiagnosticSourcePolicyOWASP,
					Field:            DiagnosticFieldWhitelistJSON,
					Error:            "invalid_json",
					HandlingStrategy: DiagnosticHandlingSkipInvalidField,
					Kind:             "owasp_whitelist",
					Reason:           "invalid_json",
					PolicyID:         config.PolicyID,
					RuleID:           config.RuleID,
				})
			} else {
				override.Whitelist = whitelist
			}
		}
		if grouped[config.PolicyID] == nil {
			grouped[config.PolicyID] = make(map[string]owasp.OWASPRuleOverride)
		}
		grouped[config.PolicyID][config.RuleID] = override
	}
	for policyID, overrides := range grouped {
		result[policyID] = owasp.SerializeOWASPRulesConfig(overrides)
	}
	return result, diagnostics, nil
}

func loadSiteCVEConfigs(db *gorm.DB, sites []store.Site, defaultPolicyID uint) (map[uint]string, error) {
	if !db.Migrator().HasTable(&cvestore.CVERuleRecord{}) || !db.Migrator().HasTable(&cvestore.CVERuleScopeOverride{}) {
		return map[uint]string{}, nil
	}
	var rules []cvestore.CVERuleRecord
	if err := db.Where("approved = ?", true).Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("load CVE catalog: %w", err)
	}
	var scoped []cvestore.CVERuleScopeOverride
	if err := db.Find(&scoped).Error; err != nil {
		return nil, fmt.Errorf("load CVE scope overrides: %w", err)
	}
	byRule := make(map[uint][]cvestore.CVERuleScopeOverride)
	for _, item := range scoped {
		byRule[item.RuleID] = append(byRule[item.RuleID], item)
	}
	result := make(map[uint]string, len(sites))
	cveIDCounts := make(map[string]int, len(rules))
	for _, rule := range rules {
		if id := strings.TrimSpace(rule.CVEID); id != "" {
			cveIDCounts[id]++
		}
	}
	for _, site := range sites {
		policyID := defaultPolicyID
		if site.PolicyID != nil && *site.PolicyID != 0 {
			policyID = *site.PolicyID
		}
		profile := make(map[string]cve.CVERuleOverride, len(rules))
		for _, rule := range rules {
			enabled := rule.Enabled
			override := cve.CVERuleOverride{Enabled: &enabled, Action: rule.Action, CaptchaType: normalizeRuleCaptchaType(rule.CaptchaType)}
			apply := func(scopeType string, scopeID uint) {
				for _, item := range byRule[rule.ID] {
					if item.ScopeType != scopeType || item.ScopeID != scopeID {
						continue
					}
					if item.Enabled != nil {
						override.Enabled = item.Enabled
					}
					if item.Action != nil && strings.TrimSpace(*item.Action) != "" {
						override.Action = *item.Action
					}
					if item.Sensitivity != nil && strings.TrimSpace(*item.Sensitivity) != "" {
						override.Sensitivity = *item.Sensitivity
					}
					if item.StatusCode != nil && *item.StatusCode != 0 {
						override.StatusCode = *item.StatusCode
					}
					if item.RedirectTo != nil && strings.TrimSpace(*item.RedirectTo) != "" {
						override.RedirectTo = *item.RedirectTo
					}
					if item.CaptchaType != nil && strings.TrimSpace(*item.CaptchaType) != "" {
						override.CaptchaType = normalizeRuleCaptchaType(*item.CaptchaType)
					}
				}
			}
			apply(cvestore.CVEScopeGlobal, 0)
			apply(cvestore.CVEScopePolicy, policyID)
			apply(cvestore.CVEScopeSite, site.ID)
			// 运行时先按 Pattern 查找覆盖；必须保留规则级键，否则两个
			// 自定义规则使用同一 CVE 编号时会互相覆盖。编号键仅在唯一
			// 时保留，用于兼容旧快照和内置规则配置。
			if pattern := strings.TrimSpace(rule.Pattern); pattern != "" {
				profile[pattern] = override
			}
			if cveID := strings.TrimSpace(rule.CVEID); cveID != "" && cveIDCounts[cveID] == 1 {
				profile[cveID] = override
			}
		}
		raw, err := json.Marshal(profile)
		if err != nil {
			return nil, err
		}
		result[site.ID] = string(raw)
	}
	return result, nil
}

/**
 * mergeProtection 把站点的覆盖值叠加到全局配置上，生成该站点的生效保护配置。
 *
 * 站点字段是「可空覆盖」语义：nil 表示继承全局，非 nil 才覆盖，
 * 因此这里逐字段判空，而不是整体替换。
 *
 * @param global 全局保护配置。
 * @param site 站点模型（含可空覆盖字段）。
 * @return 合并后的保护配置。
 */
func mergeProtection(global store.ProtectionConfig, site store.Site) store.ProtectionConfig {
	p := global // shallow copy

	// bot 检测：站点级覆盖
	if site.BotProtectionEnabled != nil {
		p.BotDetectionEnabled = *site.BotProtectionEnabled
	}

	// 防重放：nil 表示继承全局开关；非 nil 才是显式覆盖。
	if site.AntiReplayEnabled != nil {
		p.AntiReplayEnabled = *site.AntiReplayEnabled
	}
	// Anti-replay Cookie 校验模式：nil 继承全局，非 nil 显式覆盖，终值统一规范化。
	if site.AntiReplayCookieMode != nil {
		p.AntiReplayCookieMode = *site.AntiReplayCookieMode
	}
	p.AntiReplayCookieMode = NormalizeAntiReplayCookieMode(p.AntiReplayCookieMode)

	// OWASP 覆盖
	if site.OWASPEnabled != nil {
		p.OWASPEnabled = *site.OWASPEnabled
		if site.OWASPSensitivity != "" {
			p.OWASPSensitivity = site.OWASPSensitivity
		}
		if site.OWASPAction != "" {
			p.OWASPAction = site.OWASPAction
		}
	}

	// CVE 覆盖
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

	// 请求频率限制覆盖
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

	// 按 phase 跳过检测：nil 继承全局，非 nil 整体覆盖。
	// 不做 per-phase 深合并——否则站点无法关掉全局配置的某个 phase 跳过项。
	if site.SkipPathByPhase != nil {
		p.SkipPathByPhase = *site.SkipPathByPhase
	}

	return p
}

// maybeSiteString 把站点级可空覆盖字段解析为快照运行时值：
// nil = 未覆盖（返回空串），非 nil = 覆盖值（原样返回）。
func maybeSiteString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func NormalizeAntiReplayCookieMode(raw string) string {
	if raw == "dual" {
		return "dual"
	}
	return "standard"
}

func registerSiteKeys(m map[string]*SiteRuntime, rt *SiteRuntime) error {
	bind := rt.Bind
	for _, host := range splitHosts(rt.Site.Host) {
		h := NormalizeMatchHost(host)
		if h == "" {
			continue
		}
		k := siteMapKeyNorm(bind, h)
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

/**
 * splitHosts 按逗号切分站点 host 字段，支持单站点绑定多个 Host。
 *
 * @param raw 站点 Host 字段原值。
 * @return 切分后的 Host 列表。
 */
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
					out = append(out, schemealias.NormalizeURLPrefix(p))
				}
			}
			return out
		}
	}

	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			// RPC 别名归一（大小写折叠 + tls/grpc 前缀展开）后进入站点快照，
			// 保证下游按 https/h2c 的既有语义处理。
			out = append(out, schemealias.NormalizeURLPrefix(p))
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
		kind, arg = applyRuleFrequencyLimit(r, kind, arg)
		out = append(out, CompiledRule{
			ID: r.ID, Phase: r.Phase, Action: r.Action, Priority: r.Priority,
			Kind: kind, Arg: arg, StatusCode: r.StatusCode, RedirectTo: r.RedirectTo,
			CaptchaType:    r.CaptchaType,
			CaptchaMinutes: r.CaptchaMinutes,
		})
	}
	return out
}

/**
 * applyRuleFrequencyLimit 把规则自带的频次参数包装成 cc_rate 复合条件。
 *
 * 规则表单的「时间窗口（秒）+ 请求次数」是规则级频次限制：窗口内命中本条
 * 条件的请求达到阈值后执行本规则的 Action。它与 CC 防护页的 cc_rules 使用
 * 同一个 ccRateMatcher（计数键为 clientIP|host，见 internal/core/rules/matcher.go），
 * 区别只在条件来源——这里是规则自身的 pattern。
 *
 * WindowSeconds 与 RequestCount 必须同时大于 0 才生效；任一为 0 或负数
 * 表示不做频次限制，原样返回。pattern 已是复合 JSON（cc_rate 或 and/or 等）
 * 时不叠加包装，避免生成 cc_rate 嵌套 cc_rate 这种无法从表单还原的结构。
 *
 * @param r    规则模型，读取 WindowSeconds / RequestCount
 * @param kind 已解析的匹配器类型
 * @param arg  已解析的匹配器参数
 * @return 包装后的 kind/arg；不满足条件时原样返回
 */
func applyRuleFrequencyLimit(r store.Rule, kind, arg string) (string, string) {
	if r.WindowSeconds <= 0 || r.RequestCount <= 0 || kind == "compound" {
		return kind, arg
	}
	raw, err := json.Marshal(map[string]any{
		"op":        "cc_rate",
		"children":  []any{map[string]string{"kind": kind, "arg": arg}},
		"window":    r.WindowSeconds,
		"threshold": r.RequestCount,
	})
	if err != nil {
		return kind, arg
	}
	return "compound", string(raw)
}

type ccRuleConfig struct {
	Enabled      *bool             `json:"enabled"`
	Action       string            `json:"action"`
	CaptchaType  string            `json:"captcha_type"`
	Conditions   []ccRuleCondition `json:"conditions"`
	Window       int               `json:"window"`
	Threshold    int               `json:"threshold"`
	Duration     int               `json:"duration"`
	DurationUnit string            `json:"duration_unit"`
}

/**
 * normalizeRuleCaptchaType 对规则级验证码类型做严格且失败的规范化。
 *
 * 只接受已知取值；未知取值一律归一为空串（即继承全局），避免手写配置里的
 * 拼写错误被当成一个新类型放行。
 *
 * @param value 规则里配置的验证码类型。
 * @return 规范化后的类型；非法值为空串。
 */
func normalizeRuleCaptchaType(value string) string {
	switch value {
	case "", "math", "click", "slide", "rotate":
		return value
	default:
		return ""
	}
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

func normalizedCCDurationUnit(unit string) string {
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "seconds", "second", "sec", "s":
		return "seconds"
	case "minutes", "minute", "min", "m":
		return "minutes"
	default:
		return "minutes"
	}
}

func ccDurationSeconds(duration int, unit string) int {
	if duration <= 0 {
		return 0
	}
	if normalizedCCDurationUnit(unit) == "seconds" {
		return duration
	}
	return duration * 60
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
				"op":               "cc_rate",
				"children":         []any{compiled},
				"window":           cfg.Window,
				"threshold":        cfg.Threshold,
				"duration":         cfg.Duration,
				"duration_unit":    normalizedCCDurationUnit(cfg.DurationUnit),
				"duration_seconds": ccDurationSeconds(cfg.Duration, cfg.DurationUnit),
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
			ID:          uint(ccRuleIDCounter.Add(1)),
			Phase:       store.PhaseCustom,
			Action:      normalizeCCAction(cfg.Action),
			Priority:    10_000,
			Kind:        kind,
			Arg:         arg,
			CaptchaType: normalizeRuleCaptchaType(cfg.CaptchaType),
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
		case "prefix":
			return "block_path", value, true
		case "contains":
			return "path_contains", value, true
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
		case "equals":
			return "block_header_exact", name + ":" + headerValue, true
		case "contains":
			return "block_header", name + ":" + headerValue, true
		case "prefix":
			return "block_header_prefix", name + ":" + headerValue, true
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
	case "captcha":
		return store.ActionCaptchaChallenge
	case "challenge":
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

/**
 * ParsePattern 从 DSL 字符串中拆出 kind 与 arg，例如 "block_ip:1.2.3.0/24"。
 *
 * 以 "{" 开头的字符串视为复合 JSON 规则，整串作为 arg 返回，kind 固定为 "compound"。
 *
 * @param p 规则模式原串。
 * @return kind 与 arg；复合规则返回 "compound" 与原始 JSON。
 */
func ParsePattern(p string) (kind, arg string) {
	p = strings.TrimSpace(p)

	// 判断是否为复合 JSON 规则
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

func parseClientIPHeaderOrder(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var inbound []string
	if err := json.Unmarshal([]byte(raw), &inbound); err != nil {
		return nil
	}
	return append([]string(nil), inbound...)
}

// networkDefaultsFromMap 从预加载的 settings map 中读取网络默认配置。
func networkDefaultsFromMap(m map[string]string) NetworkDefaults {
	v, ok := m["network_config"]
	if !ok || v == "" {
		return DefaultNetworkDefaults()
	}
	return LoadNetworkDefaults(v)
}

// tlsDefaultsFromMap 从预加载的 settings map 中读取 TLS 默认配置。
func tlsDefaultsFromMap(m map[string]string) TLSDefaults {
	v, ok := m["tls_default_config"]
	if !ok || v == "" {
		return DefaultTLSDefaults()
	}
	return LoadTLSDefaults(v)
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
	if !challenge.IsValidCaptchaType(challenge.CaptchaType(cfg.CaptchaType)) {
		return store.ProtectionConfig{}, fmt.Errorf("invalid protection captcha_type %q", cfg.CaptchaType)
	}
	return cfg, nil
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
	mode := bs.JSProtectionMode
	if !dynamic.IsValidJSProtectionMode(mode) {
		mode = ""
	}

	return dynamic.ProtectionConfig{
		HTMLObfuscationEnabled:    bs.DynamicProtectionEnabled && bs.HTMLObfuscation,
		JSObfuscationEnabled:      bs.DynamicProtectionEnabled && bs.JSObfuscation,
		ImageWatermarkEnabled:     bs.DynamicProtectionEnabled && bs.ImageWatermark,
		GlobalHTMLConfigured:      bs.HTMLObfuscation,
		GlobalJSConfigured:        bs.JSObfuscation,
		GlobalWatermarkConfigured: bs.ImageWatermark,
		JSProtectionMode:          mode,
		DecryptCacheTTLSeconds:    dynamic.NormalizeDecryptCacheTTLSeconds(bs.DecryptCacheTTLSeconds),
		JSObfuscationPaths:        bs.JSObfuscationPaths,
		ImageWatermarkPaths:       bs.ImageWatermarkPaths,
		WatermarkText:             bs.WatermarkText,
	}
}

// buildSiteDynamicProtection 基于全局动态保护配置，合并站点级覆盖字段。
func buildSiteDynamicProtection(global dynamic.ProtectionConfig, site store.Site) dynamic.ProtectionConfig {
	cfg := global
	cfg.SiteID = site.ID

	if site.DynamicProtectionEnabled != nil {
		if !*site.DynamicProtectionEnabled {
			cfg.HTMLObfuscationEnabled = false
			cfg.JSObfuscationEnabled = false
			cfg.ImageWatermarkEnabled = false
			return cfg
		}
		cfg.HTMLObfuscationEnabled = cfg.GlobalHTMLConfigured
		cfg.JSObfuscationEnabled = cfg.GlobalJSConfigured
		cfg.ImageWatermarkEnabled = cfg.GlobalWatermarkConfigured
	}
	if site.DynamicHTMLEnabled != nil {
		cfg.HTMLObfuscationEnabled = *site.DynamicHTMLEnabled
	}
	if site.DynamicJSEnabled != nil {
		cfg.JSObfuscationEnabled = *site.DynamicJSEnabled
	}
	if site.DynamicJSMode != "" {
		if dynamic.IsValidJSProtectionMode(site.DynamicJSMode) {
			cfg.JSProtectionMode = site.DynamicJSMode
		} else {
			cfg.JSProtectionMode = ""
		}
	}
	if site.DynamicJSPaths != "" {
		var paths []string
		if err := json.Unmarshal([]byte(site.DynamicJSPaths), &paths); err == nil {
			// 显式空数组是站点覆盖，不应继续继承全局路径。
			cfg.JSObfuscationPaths = paths
		}
	}
	if site.DynamicDecryptCacheTTL != nil {
		cfg.DecryptCacheTTLSeconds = dynamic.NormalizeDecryptCacheTTLSeconds(*site.DynamicDecryptCacheTTL)
	}
	return cfg
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

// loadAllSettings 一次性加载所有 system_settings 到 map，避免多次独立查询。
func loadAllSettings(db *gorm.DB) (map[string]string, error) {
	var all []store.SystemSettings
	if err := db.Find(&all).Error; err != nil {
		return nil, err
	}
	m := make(map[string]string, len(all))
	for _, s := range all {
		m[s.Key] = s.Value
	}
	return m, nil
}

// settingBool 从预加载的 settings map 中读取布尔值。
func settingBool(m map[string]string, key string) bool {
	v := strings.TrimSpace(strings.ToLower(m[key]))
	return v == "true" || v == "1" || v == "yes"
}

/**
 * settingBoolDefault 读取布尔设置，缺行时回退到给定默认值。
 *
 * 与 settingBool 的区别只在「键不存在或值为空」这一种情形：此时返回
 * defaultValue 而不是 false。显式写入的值仍按 settingBool 的口径解析，
 * 因此 "false"/"0"/"no" 一律是关闭，其余非空取值一律按开启处理——
 * 这与 settingBool 的判定完全一致。
 *
 * @param m 预加载的 settings map。
 * @param key 设置键。
 * @param defaultValue 键缺失或值为空时的取值。
 * @returns 解析后的布尔值。
 */
func settingBoolDefault(m map[string]string, key string, defaultValue bool) bool {
	v := strings.TrimSpace(strings.ToLower(m[key]))
	if v == "" {
		return defaultValue
	}
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

// systemSettingKeyEquals 返回按 key 查询系统设置的 GORM 条件子句。
func systemSettingKeyEquals(key string) clause.Eq {
	return clause.Eq{Column: clause.Column{Name: "key"}, Value: key}
}

/**
 * ResolveOutboundHost 解析发往上游时使用的 Host。
 *
 * 优先级：站点显式配置的 upstream host > 上游 host header > 传入的请求 Host。
 *
 * @param rt 站点运行时。
 * @param upstreamHost 上游地址。
 * @param incomingHost 客户端请求的 Host。
 * @return 解析出的上游 Host。
 */
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
func loadAccessControlConfigs(db *gorm.DB) (map[uint]*AccessControlConfig, error) {
	result := make(map[uint]*AccessControlConfig)
	if !db.Migrator().HasTable(&access.SiteAccessConfig{}) {
		return result, nil
	}

	var configs []access.SiteAccessConfig
	if err := db.Where("enabled = ?", true).Find(&configs).Error; err != nil {
		return nil, err
	}

	// 批量加载所有启用的 provider，按 site_id 分组。
	var allProviders []access.AccessProvider
	providersBySite := make(map[uint][]access.AccessProvider)
	if db.Migrator().HasTable(&access.AccessProvider{}) {
		if err := db.Where("enabled = ?", true).
			Order("site_id ASC, priority ASC, id ASC").Find(&allProviders).Error; err != nil {
			return nil, err
		}
	}
	for _, p := range allProviders {
		providersBySite[p.SiteID] = append(providersBySite[p.SiteID], p)
	}

	// 批量加载所有启用的路径规则，按 site_id 分组。
	var allPathRules []access.AccessPathRule
	pathRulesBySite := make(map[uint][]access.AccessPathRule)
	if db.Migrator().HasTable(&access.AccessPathRule{}) {
		if err := db.Where("enabled = ?", true).
			Order("site_id ASC, priority ASC, id ASC").Find(&allPathRules).Error; err != nil {
			return nil, err
		}
	}
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
	return result, nil
}

// siteIPListPair 存储一个站点的已解析黑白名单。
type siteIPListPair struct {
	whitelist []iprep.IPListEntry
	blacklist []iprep.IPListEntry
}

// loadSiteIPLists 从数据库加载所有站点级 IP 黑白名单（不含全局条目）。
func loadSiteIPLists(db *gorm.DB) (map[uint]siteIPListPair, []SnapshotConfigDiagnostic, error) {
	result := make(map[uint]siteIPListPair)
	diagnostics := make([]SnapshotConfigDiagnostic, 0)
	if !db.Migrator().HasTable(&iplist.IPListEntry{}) {
		return result, diagnostics, nil
	}

	var items []iplist.IPListEntry
	if err := db.Where("enabled = ?", true).Order("id ASC").Find(&items).Error; err != nil {
		return nil, nil, err
	}
	for _, it := range items {
		entry, ok := iprep.ParseIPListEntry(it.Value, it.Note, it.Action)
		if !ok {
			reason := "invalid_ip_or_cidr"
			if strings.TrimSpace(it.Value) == "" {
				reason = "empty_value"
			}
			diagnostic := SnapshotConfigDiagnostic{
				Source:           DiagnosticSourceIPList,
				Field:            DiagnosticFieldValue,
				Error:            reason,
				HandlingStrategy: DiagnosticHandlingSkipInvalidEntry,
				Kind:             "ip_list_entry",
				Reason:           reason,
				IPListEntryID:    it.ID,
				Scope:            "global",
			}
			if it.SiteID != nil {
				diagnostic.Scope = "site"
				diagnostic.SiteID = *it.SiteID
			}
			diagnostics = append(diagnostics, diagnostic)
			continue
		}
		if it.SiteID == nil {
			continue
		}
		siteID := *it.SiteID
		pair := result[siteID]
		if it.Kind == iplist.IPListWhite {
			pair.whitelist = append(pair.whitelist, entry)
		} else if it.Kind == iplist.IPListBlack {
			pair.blacklist = append(pair.blacklist, entry)
		}
		result[siteID] = pair
	}
	return result, diagnostics, nil
}
