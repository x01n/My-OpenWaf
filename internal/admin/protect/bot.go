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
)

// BotSettingsUpdate represents the request body for updating bot settings.
type BotSettingsUpdate struct {
	Enabled           *bool    `json:"enabled"`
	ScoreThreshold    *int     `json:"score_threshold"`
	HighRiskCountries []string `json:"high_risk_countries"`
	DatacenterASNs    []uint32 `json:"datacenter_asns"`
	VPNProxyASNs      []uint32 `json:"vpn_proxy_asns"`
	GeoIPDBPath       *string  `json:"geoip_db_path"`
}

func defaultBotSettingsResponse(settingsRepo *repository.SystemSettingsRepo) shared.BotSettingsResponse {
	resp := shared.BotSettingsResponse{
		Enabled:        shared.LoadProtectionConfig(settingsRepo).BotDetectionEnabled,
		ScoreThreshold: 60,
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

		// Load current settings
		current := defaultBotSettingsResponse(settingsRepo)
		if val, err := settingsRepo.Get("bot_settings"); err == nil && val != "" {
			_ = json.Unmarshal([]byte(val), &current)
		}

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

		data, _ := json.Marshal(current)
		if err := settingsRepo.Set("bot_settings", string(data)); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		if req.Enabled != nil {
			// Sync BotDetectionEnabled into the protection config so the engine
			// sees a consistent value regardless of which page the user toggles.
			if err := shared.SyncBotEnabledToProtection(settingsRepo, current.Enabled); err != nil {
				c.JSON(500, map[string]string{"error": err.Error()})
				return
			}
		}
		if req.ScoreThreshold != nil {
			if err := shared.SyncBotThresholdToDropPolicy(settingsRepo, current.ScoreThreshold); err != nil {
				c.JSON(500, map[string]string{"error": err.Error()})
				return
			}
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
