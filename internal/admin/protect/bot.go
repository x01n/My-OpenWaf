package protect

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
	dynamicpkg "My-OpenWaf/internal/waf/dynamic"
)

// BotSettingsUpdate represents the request body for updating bot settings.
type BotSettingsUpdate struct {
	Enabled                  *bool    `json:"enabled"`
	ScoreThreshold           *int     `json:"score_threshold"`
	HighRiskCountries        []string `json:"high_risk_countries"`
	DatacenterASNs           []uint32 `json:"datacenter_asns"`
	VPNProxyASNs             []uint32 `json:"vpn_proxy_asns"`
	GeoIPDBPath              *string  `json:"geoip_db_path"`
	CaptchaEnabled           *bool    `json:"captcha_enabled"`
	DynamicProtectionEnabled *bool    `json:"dynamic_protection_enabled"`
	HTMLObfuscation          *bool    `json:"html_obfuscation"`
	JSObfuscation            *bool    `json:"js_obfuscation"`
	ImageWatermark           *bool    `json:"image_watermark"`
	AntiReplayEnabled        *bool    `json:"anti_replay_enabled"`
	BrowserSignEnabled       *bool    `json:"browser_sign_enabled"`
	BrowserSignTTL           *int     `json:"browser_sign_ttl"`
	BrowserSignAction        *string  `json:"browser_sign_action"`
	JSObfuscationPaths       []string `json:"js_obfuscation_paths,omitempty"`
	JSProtectionMode         *string  `json:"js_protection_mode,omitempty"`
	DecryptCacheTTLSeconds   *int     `json:"decrypt_cache_ttl_seconds,omitempty"`
	ImageWatermarkPaths      []string `json:"image_watermark_paths,omitempty"`
	WatermarkText            *string  `json:"watermark_text,omitempty"`
	ExcludeRecordHeaders     []string `json:"exclude_record_headers,omitempty"`
}

func defaultBotSettingsResponse(settingsRepo *repository.SystemSettingsRepo) shared.BotSettingsResponse {
	protectionCfg := shared.LoadProtectionConfig(settingsRepo)
	resp := shared.BotSettingsResponse{
		Enabled:            protectionCfg.BotDetectionEnabled,
		ScoreThreshold:     60,
		CaptchaEnabled:     protectionCfg.CaptchaEnabled,
		AntiReplayEnabled:  protectionCfg.AntiReplayEnabled,
		BrowserSignEnabled: protectionCfg.BrowserSignEnabled,
		BrowserSignTTL:     protectionCfg.BrowserSignTTL,
		BrowserSignAction:  protectionCfg.BrowserSignAction,
	}
	if resp.BrowserSignTTL <= 0 {
		resp.BrowserSignTTL = 300
	}
	if resp.BrowserSignAction == "" {
		resp.BrowserSignAction = "challenge"
	}
	if val, err := settingsRepo.Get("drop_policy"); err == nil && val != "" {
		var dropPolicy struct {
			BotScoreThreshold int `json:"bot_score_threshold"`
		}
		if json.Unmarshal([]byte(val), &dropPolicy) == nil && dropPolicy.BotScoreThreshold > 0 {
			resp.ScoreThreshold = dropPolicy.BotScoreThreshold
		}
	}
	return resp
}

func GetBotSettings(settingsRepo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		val, err := settingsRepo.Get("bot_settings")
		if err != nil || val == "" {
			c.JSON(200, defaultBotSettingsResponse(settingsRepo))
			return
		}
		resp := defaultBotSettingsResponse(settingsRepo)
		if err := json.Unmarshal([]byte(val), &resp); err != nil {
			c.JSON(200, defaultBotSettingsResponse(settingsRepo))
			return
		}
		// bot_settings JSON 可能尚未包含保护字段；以 protection 为权威源回填。
		prot := shared.LoadProtectionConfig(settingsRepo)
		resp.CaptchaEnabled = prot.CaptchaEnabled
		resp.AntiReplayEnabled = prot.AntiReplayEnabled
		resp.BrowserSignEnabled = prot.BrowserSignEnabled
		if prot.BrowserSignTTL > 0 {
			resp.BrowserSignTTL = prot.BrowserSignTTL
		}
		if prot.BrowserSignAction != "" {
			resp.BrowserSignAction = prot.BrowserSignAction
		}
		if resp.BrowserSignTTL <= 0 {
			resp.BrowserSignTTL = 300
		}
		if resp.BrowserSignAction == "" {
			resp.BrowserSignAction = "challenge"
		}
		c.JSON(200, resp)
	}
}

func UpdateBotSettings(settingsRepo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req BotSettingsUpdate
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if req.ScoreThreshold != nil && !shared.ValidateBotScoreThreshold(*req.ScoreThreshold) {
			c.JSON(400, map[string]string{"error": "score_threshold must be between 1 and 100"})
			return
		}
		if req.JSProtectionMode != nil && !dynamicpkg.IsValidJSProtectionMode(*req.JSProtectionMode) {
			c.JSON(400, map[string]string{"error": "js_protection_mode must be one of: all, paths"})
			return
		}
		if req.DecryptCacheTTLSeconds != nil && (*req.DecryptCacheTTLSeconds < 0 || *req.DecryptCacheTTLSeconds > dynamicpkg.MaxDecryptCacheTTLSeconds) {
			c.JSON(400, map[string]string{"error": "decrypt_cache_ttl_seconds must be between 0 and 1800"})
			return
		}

		// Load current settings
		current := defaultBotSettingsResponse(settingsRepo)
		if val, err := settingsRepo.Get("bot_settings"); err == nil && val != "" {
			_ = json.Unmarshal([]byte(val), &current)
		}
		// protection.captcha_enabled 是运行时权威源，避免部分更新把旧投影写回。
		current.CaptchaEnabled = shared.LoadProtectionConfig(settingsRepo).CaptchaEnabled

		// Apply updates
		if req.Enabled != nil {
			current.Enabled = *req.Enabled
		}
		if req.ScoreThreshold != nil {
			current.ScoreThreshold = *req.ScoreThreshold
		}
		if req.HighRiskCountries != nil {
			current.HighRiskCountries = req.HighRiskCountries
		}
		if req.DatacenterASNs != nil {
			current.DatacenterASNs = req.DatacenterASNs
		}
		if req.VPNProxyASNs != nil {
			current.VPNProxyASNs = req.VPNProxyASNs
		}
		if req.GeoIPDBPath != nil {
			current.GeoIPDBPath = *req.GeoIPDBPath
		}
		if req.CaptchaEnabled != nil {
			current.CaptchaEnabled = *req.CaptchaEnabled
		}
		if req.DynamicProtectionEnabled != nil {
			current.DynamicProtectionEnabled = *req.DynamicProtectionEnabled
		}
		if req.HTMLObfuscation != nil {
			current.HTMLObfuscation = *req.HTMLObfuscation
		}
		if req.JSObfuscation != nil {
			current.JSObfuscation = *req.JSObfuscation
		}
		if req.ImageWatermark != nil {
			current.ImageWatermark = *req.ImageWatermark
		}
		if req.AntiReplayEnabled != nil {
			current.AntiReplayEnabled = *req.AntiReplayEnabled
		}
		if req.BrowserSignEnabled != nil {
			current.BrowserSignEnabled = *req.BrowserSignEnabled
		}
		if req.BrowserSignTTL != nil && *req.BrowserSignTTL > 0 {
			current.BrowserSignTTL = *req.BrowserSignTTL
		}
		if req.BrowserSignAction != nil && *req.BrowserSignAction != "" {
			current.BrowserSignAction = *req.BrowserSignAction
		}
		if req.JSObfuscationPaths != nil {
			current.JSObfuscationPaths = req.JSObfuscationPaths
		}
		if req.JSProtectionMode != nil {
			current.JSProtectionMode = *req.JSProtectionMode
		}
		if req.DecryptCacheTTLSeconds != nil {
			current.DecryptCacheTTLSeconds = *req.DecryptCacheTTLSeconds
		}
		if req.ImageWatermarkPaths != nil {
			current.ImageWatermarkPaths = req.ImageWatermarkPaths
		}
		if req.WatermarkText != nil {
			current.WatermarkText = *req.WatermarkText
		}
		if req.ExcludeRecordHeaders != nil {
			current.ExcludeRecordHeaders = req.ExcludeRecordHeaders
		}

		data, err := json.Marshal(current)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := settingsRepo.Transaction(func(txRepo *repository.SystemSettingsRepo) error {
			if err := txRepo.Set("bot_settings", string(data)); err != nil {
				return err
			}

			if req.Enabled != nil {
				// Sync BotDetectionEnabled into the protection config so the engine
				// sees a consistent value regardless of which page the user toggles.
				if err := shared.SyncBotEnabledToProtection(txRepo, current.Enabled); err != nil {
					return err
				}
			}
			if req.CaptchaEnabled != nil {
				if err := shared.SyncCaptchaEnabledToProtection(txRepo, current.CaptchaEnabled); err != nil {
					return err
				}
			}
			if req.AntiReplayEnabled != nil {
				if err := shared.SyncAntiReplayEnabledToProtection(txRepo, current.AntiReplayEnabled); err != nil {
					return err
				}
			}
			if req.BrowserSignEnabled != nil || req.BrowserSignTTL != nil || req.BrowserSignAction != nil {
				if err := shared.SyncBrowserSignToProtection(txRepo, current.BrowserSignEnabled, current.BrowserSignTTL, current.BrowserSignAction); err != nil {
					return err
				}
			}
			if req.ScoreThreshold != nil {
				if err := shared.SyncBotThresholdToDropPolicy(txRepo, current.ScoreThreshold); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		if reload != nil {
			if err := reload(); err != nil {
				c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "settings": current})
				return
			}
		}
		c.JSON(200, current)
	}
}

func GetBotStats(repo *repository.BotScoreRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		stats, err := repo.Stats24h()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, stats)
	}
}

func GetBotScores(repo *repository.BotScoreRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, size)

		f := repository.BotScoreFilter{
			ClientIP:  c.DefaultQuery("ip", ""),
			Host:      c.DefaultQuery("host", ""),
			Path:      c.DefaultQuery("path", ""),
			UserAgent: c.DefaultQuery("user_agent", ""),
			RequestID: c.DefaultQuery("request_id", ""),
			JA3Hash:   c.DefaultQuery("ja3_hash", ""),
			JA4:       c.DefaultQuery("ja4", ""),
			TLSSNI:    c.DefaultQuery("tls_sni", ""),
		}
		if v := c.DefaultQuery("high_risk", ""); v != "" {
			if b, err := strconv.ParseBool(v); err == nil {
				f.HighRisk = &b
			}
		}
		if v := c.DefaultQuery("min_score", ""); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				f.MinScore = &n
			}
		}
		if v := c.DefaultQuery("max_score", ""); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				f.MaxScore = &n
			}
		}
		if v := c.DefaultQuery("start_time", ""); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.StartTime = &t
			}
		}
		if v := c.DefaultQuery("end_time", ""); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.EndTime = &t
			}
		}

		items, total, err := repo.List(offset, limit, f)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total})
	}
}
