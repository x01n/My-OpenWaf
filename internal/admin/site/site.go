package site

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/security"
	snapshotpkg "My-OpenWaf/internal/snapshot"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/tlsmeta"
	"My-OpenWaf/internal/utils"
	dynamicpkg "My-OpenWaf/internal/waf/dynamic"
)

var (
	errInvalidSiteAction        = errors.New("invalid action")
	errInvalidSiteNetwork       = errors.New("invalid network")
	errInvalidSiteXFFMode       = errors.New("invalid xff_mode")
	errInvalidSiteTrustedCIDR   = errors.New("invalid trusted_cidr")
	errInvalidSiteHeaderOrder   = errors.New("invalid client_ip_header_order")
	errInvalidSiteDynamicJSMode = errors.New("dynamic_js_mode must be one of: all, paths")
	errInvalidSiteDynamicTTL    = errors.New("dynamic_decrypt_cache_ttl must be between 0 and 1800 seconds")
)

type siteListItem struct {
	store.Site
	ListenerSummary      string `json:"listener_summary"`
	TLSSummary           string `json:"tls_summary"`
	ManagedListenerCount int    `json:"managed_listener_count"`
}

func ListSites(repo *repository.SiteRepo, listenerRepo *repository.SiteListenerRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, size)
		items, total, err := repo.List(offset, limit)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		listeners, err := listenerRepo.AllEnabled()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		listenersBySite := make(map[uint][]store.SiteListener)
		for _, listener := range listeners {
			listenersBySite[listener.SiteID] = append(listenersBySite[listener.SiteID], listener)
		}

		respItems := make([]siteListItem, 0, len(items))
		for _, item := range items {
			listeners := listenersBySite[item.ID]
			managed := make([]store.SiteListener, 0, len(listeners))
			for _, listener := range listeners {
				if listener.ID > 0 {
					managed = append(managed, listener)
				}
			}

			listenerSummary := item.Bind
			tlsSummary := map[bool]string{true: "HTTPS", false: "HTTP"}[item.TLSEnabled]
			managedCount := len(managed)
			if managedCount > 0 {
				binds := make([]string, 0, managedCount)
				hasTLS := false
				for _, listener := range managed {
					binds = append(binds, listener.Bind)
					if listener.TLSEnabled {
						hasTLS = true
					}
				}
				listenerSummary = strings.Join(binds, " / ")
				if hasTLS {
					tlsSummary = "多监听（含 HTTPS）"
				} else {
					tlsSummary = "多监听（HTTP）"
				}
			}

			respItems = append(respItems, siteListItem{
				Site:                 item,
				ListenerSummary:      listenerSummary,
				TLSSummary:           tlsSummary,
				ManagedListenerCount: managedCount,
			})
		}

		c.JSON(200, map[string]any{"items": respItems, "total": total})
	}
}

func GetSite(repo *repository.SiteRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		item, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		c.JSON(200, item)
	}
}

func CreateSite(repo *repository.SiteRepo, certRepo *repository.CertificateRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var item store.Site
		// 先填模型声明的默认值，再让请求体覆盖：json 只写出现过的字段，
		// 这样「未提供」保留默认值，「显式传 false/0」才能如实落库。
		_ = store.ApplyModelDefaults(&item)
		body := c.Request.Body()
		if err := shared.BindSiteFromRequestBody(body, &item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if siteRequestHasField(body, "attack_protection_level") {
			item.ApplyProtectionModeOverrides()
		}
		clearInheritedProtectionOverrides(&item)
		if err := repo.NormalizePolicyID(&item.PolicyID); err != nil {
			c.JSON(400, map[string]string{"error": "policy_id must reference an existing policy"})
			return
		}
		if err := validateSiteRuntimeTLSVersions(&item, body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteTLSCipherSuites(&item, body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteALPN(&item, body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteNetwork(&item, body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteClientIP(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteDynamicProtection(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := shared.ValidateSiteUpstreamURLs(item.UpstreamURLs); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := shared.ValidateSiteUpstreamHost(item.UpstreamHost); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteActions(&item, func(string) bool { return true }); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if siteRequestHasField(body, "cc_rules") || (item.CCUseCustom != nil && *item.CCUseCustom) {
			if err := shared.ValidateCCRules(item.CCRules); err != nil {
				c.JSON(400, map[string]string{"error": err.Error()})
				return
			}
		}
		if err := shared.ValidateCCRules(item.CCRules); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := shared.ValidateSiteTLSCertificate(item.TLSEnabled, item.CertID, certRepo); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.Create(&item); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": item})
			return
		}
		c.JSON(201, item)
	}
}

func UpdateSite(repo *repository.SiteRepo, certRepo *repository.CertificateRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		existing, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		body := c.Request.Body()
		if err := shared.BindSiteFromRequestBody(body, existing); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		existing.ID = id
		if siteRequestHasField(body, "attack_protection_level") {
			existing.ApplyProtectionModeOverrides()
		}
		clearInheritedProtectionOverrides(existing)
		if err := repo.NormalizePolicyID(&existing.PolicyID); err != nil {
			c.JSON(400, map[string]string{"error": "policy_id must reference an existing policy"})
			return
		}
		if err := validateSiteRuntimeTLSVersions(existing, body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteTLSCipherSuites(existing, body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteALPN(existing, body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteNetwork(existing, body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteClientIP(existing); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteDynamicProtection(existing); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if siteRequestHasField(body, "upstream_urls") {
			if err := shared.ValidateSiteUpstreamURLs(existing.UpstreamURLs); err != nil {
				c.JSON(400, map[string]string{"error": err.Error()})
				return
			}
		}
		if siteRequestHasField(body, "upstream_host") {
			if err := shared.ValidateSiteUpstreamHost(existing.UpstreamHost); err != nil {
				c.JSON(400, map[string]string{"error": err.Error()})
				return
			}
		}
		shouldValidateAction := func(field string) bool {
			switch field {
			case "owasp_action":
				return siteRequestHasField(body, field) || (siteRequestHasField(body, "owasp_enabled") && existing.OWASPEnabled != nil && *existing.OWASPEnabled) || siteRequestHasField(body, "attack_protection_level")
			case "cve_action":
				return siteRequestHasField(body, field) || (siteRequestHasField(body, "cve_enabled") && existing.CVEEnabled != nil && *existing.CVEEnabled) || siteRequestHasField(body, "attack_protection_level")
			case "rate_limit_action":
				return siteRequestHasField(body, field) || (siteRequestHasField(body, "rate_limit_enabled") && existing.RateLimitEnabled != nil && *existing.RateLimitEnabled) || siteRequestHasField(body, "attack_protection_level")
			case "anti_replay_action":
				return siteRequestHasField(body, field) || (siteRequestHasField(body, "anti_replay_enabled") && existing.AntiReplayEnabled != nil && *existing.AntiReplayEnabled)
			default:
				return false
			}
		}
		if err := validateSiteActions(existing, shouldValidateAction); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if siteRequestHasField(body, "cc_rules") || (siteRequestHasField(body, "cc_use_custom") && existing.CCUseCustom != nil && *existing.CCUseCustom) {
			if err := shared.ValidateCCRules(existing.CCRules); err != nil {
				c.JSON(400, map[string]string{"error": err.Error()})
				return
			}
		}
		if err := shared.ValidateCCRules(existing.CCRules); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := shared.ValidateSiteTLSCertificate(existing.TLSEnabled, existing.CertID, certRepo); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": existing})
			return
		}
		c.JSON(200, existing)
	}
}

func siteRequestHasField(body []byte, field string) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}
	_, ok := raw[field]
	return ok
}

// validateSiteDynamicProtection 校验站点级动态保护的枚举和 TTL 覆盖。
func validateSiteDynamicProtection(item *store.Site) error {
	if !dynamicpkg.IsValidJSProtectionMode(item.DynamicJSMode) {
		return errInvalidSiteDynamicJSMode
	}
	if item.DynamicDecryptCacheTTL != nil && (*item.DynamicDecryptCacheTTL < 0 || *item.DynamicDecryptCacheTTL > dynamicpkg.MaxDecryptCacheTTLSeconds) {
		return errInvalidSiteDynamicTTL
	}
	return nil
}

func validateSiteRuntimeTLSVersions(item *store.Site, body []byte) error {
	if siteRequestHasField(body, "min_tls_version") {
		normalized, ok := normalizeSiteRuntimeTLSVersion(item.MinTLSVersion)
		if !ok {
			return errors.New("unsupported min_tls_version")
		}
		item.MinTLSVersion = normalized
	}
	if siteRequestHasField(body, "max_tls_version") {
		normalized, ok := normalizeSiteRuntimeTLSVersion(item.MaxTLSVersion)
		if !ok {
			return errors.New("unsupported max_tls_version")
		}
		item.MaxTLSVersion = normalized
	}
	if !tlsmeta.RuntimeVersionRangeValid(item.MinTLSVersion, item.MaxTLSVersion) {
		return errors.New("invalid tls version range")
	}
	return nil
}

func validateSiteTLSCipherSuites(item *store.Site, body []byte) error {
	if !siteRequestHasField(body, "cipher_suites") {
		return nil
	}
	if invalid := tlsmeta.InvalidTLSConfigCipherSuiteToken(item.CipherSuites); invalid != "" {
		return errors.New("unsupported cipher_suites: " + invalid)
	}
	return nil
}

func validateSiteALPN(item *store.Site, body []byte) error {
	if !siteRequestHasField(body, "alpn") {
		return nil
	}
	item.ALPN = snapshotpkg.NormalizeALPNList(item.ALPN)
	return nil
}

func validateSiteNetwork(item *store.Site, body []byte) error {
	if !siteRequestHasField(body, "network") {
		return nil
	}
	raw := strings.TrimSpace(item.Network)
	if raw == "" {
		item.Network = ""
		return nil
	}
	normalized := snapshotpkg.NormalizeNetwork(raw)
	if normalized == "" {
		return errInvalidSiteNetwork
	}
	item.Network = normalized
	return nil
}

func validateSiteClientIP(item *store.Site) error {
	if item.XFFMode == "" {
		item.XFFMode = store.XFFModeStrip
	}
	switch item.XFFMode {
	case store.XFFModeStrip, store.XFFModeTrustOuter:
	default:
		return errInvalidSiteXFFMode
	}
	if !security.ValidateTrustedCIDR(item.TrustedCIDR) {
		return errInvalidSiteTrustedCIDR
	}
	if !security.ValidateClientIPHeaderOrder(item.ClientIPHeaderOrder) {
		return errInvalidSiteHeaderOrder
	}
	return nil
}

func normalizeSiteRuntimeTLSVersion(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", true
	}
	normalized := tlsmeta.NormalizeRuntimeVersionToken(raw)
	if normalized == "" {
		return "", false
	}
	return normalized, true
}

func clearInheritedProtectionOverrides(item *store.Site) {
	if item.BotProtectionEnabled == nil {
		item.BotProtectionLevel = ""
	}
	if item.OWASPEnabled == nil {
		item.OWASPSensitivity = ""
		item.OWASPAction = ""
	}
	if item.CVEEnabled == nil {
		item.CVEAction = ""
	}
	if item.RateLimitEnabled == nil {
		item.RateLimitWindow = 0
		item.RateLimitMax = 0
		item.RateLimitAction = ""
	}
}

func validateSiteActions(item *store.Site, shouldValidate func(string) bool) error {
	if shouldValidate("owasp_action") && item.OWASPAction != "" {
		normalized, ok := shared.ValidateActionWithoutRedirectTarget(item.OWASPAction)
		if !ok {
			return errInvalidSiteAction
		}
		item.OWASPAction = normalized
	}
	if shouldValidate("cve_action") && item.CVEAction != "" {
		normalized, ok := shared.ValidateActionWithoutRedirectTarget(item.CVEAction)
		if !ok {
			return errInvalidSiteAction
		}
		item.CVEAction = normalized
	}
	if shouldValidate("rate_limit_action") && item.RateLimitAction != "" {
		normalized, ok := shared.ValidateActionWithoutRedirectTarget(item.RateLimitAction)
		if !ok {
			return errInvalidSiteAction
		}
		item.RateLimitAction = normalized
	}
	if shouldValidate("anti_replay_action") && item.AntiReplayAction != "" {
		normalized, ok := shared.ValidateAntiReplayAction(item.AntiReplayAction)
		if !ok {
			return errInvalidSiteAction
		}
		item.AntiReplayAction = normalized
	}
	return nil
}

func DeleteSite(repo *repository.SiteRepo, listenerRepo *repository.SiteListenerRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if err := repo.DeleteWithListeners(id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}

func StartSite(repo *repository.SiteRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		site, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}

		site.Enabled = true
		if err := repo.Update(site); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": site})
			return
		}

		c.JSON(200, map[string]string{"status": "running", "message": "site started"})
	}
}

func StopSite(repo *repository.SiteRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		site, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}

		site.Enabled = false
		if err := repo.Update(site); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": site})
			return
		}

		c.JSON(200, map[string]string{"status": "stopped", "message": "site stopped"})
	}
}

func GetSiteStatus(repo *repository.SiteRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		site, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}

		// 站点运行状态的唯一真相源是 site.Enabled：StartSite/StopSite 正是通过写该
		// 字段实现的，UpdateSite 也能改它。此处不再维护额外的进程级状态缓存，
		// 否则常规站点编辑改动 enabled 后状态接口会返回陈旧值。
		status := "stopped"
		if site.Enabled {
			status = "running"
		}

		c.JSON(200, map[string]any{
			"id":     site.ID,
			"host":   site.Host,
			"status": status,
		})
	}
}
