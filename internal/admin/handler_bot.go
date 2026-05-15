package admin

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

// syncBotEnabledToProtection updates ProtectionConfig.BotDetectionEnabled
// so the engine stays consistent when the bot settings page toggles the flag.
func syncBotEnabledToProtection(settingsRepo *repository.SystemSettingsRepo, enabled bool) {
	cfg := store.DefaultProtectionConfig()
	if val, err := settingsRepo.Get("protection"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &cfg)
	}
	if cfg.BotDetectionEnabled == enabled {
		return // already in sync
	}
	cfg.BotDetectionEnabled = enabled
	data, _ := json.Marshal(cfg)
	_ = settingsRepo.Set("protection", string(data))
}

// syncProtectionBotToSettings updates bot_settings.Enabled so the bot page
// stays consistent when the protection page toggles bot_detection_enabled.
func syncProtectionBotToSettings(settingsRepo *repository.SystemSettingsRepo, enabled bool) {
	current := BotSettingsResponse{ScoreThreshold: 60}
	if val, err := settingsRepo.Get("bot_settings"); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &current)
	}
	if current.Enabled == enabled {
		return // already in sync
	}
	current.Enabled = enabled
	data, _ := json.Marshal(current)
	_ = settingsRepo.Set("bot_settings", string(data))
}

// BotSettingsResponse represents the bot detection configuration returned by the API.
type BotSettingsResponse struct {
	Enabled           bool     `json:"enabled"`
	ScoreThreshold    int      `json:"score_threshold"`
	HighRiskCountries []string `json:"high_risk_countries"`
	DatacenterASNs    []uint32 `json:"datacenter_asns"`
	VPNProxyASNs      []uint32 `json:"vpn_proxy_asns"`
	GeoIPDBPath       string   `json:"geoip_db_path"`
}

// BotSettingsUpdate represents the request body for updating bot settings.
type BotSettingsUpdate struct {
	Enabled           *bool    `json:"enabled"`
	ScoreThreshold    *int     `json:"score_threshold"`
	HighRiskCountries []string `json:"high_risk_countries"`
	DatacenterASNs    []uint32 `json:"datacenter_asns"`
	VPNProxyASNs      []uint32 `json:"vpn_proxy_asns"`
	GeoIPDBPath       *string  `json:"geoip_db_path"`
}

func GetBotSettings(settingsRepo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		val, err := settingsRepo.Get("bot_settings")
		if err != nil || val == "" {
			c.JSON(200, BotSettingsResponse{
				Enabled:        false,
				ScoreThreshold: 60,
			})
			return
		}
		var resp BotSettingsResponse
		if err := json.Unmarshal([]byte(val), &resp); err != nil {
			c.JSON(200, BotSettingsResponse{
				Enabled:        false,
				ScoreThreshold: 60,
			})
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

		// Load current settings
		current := BotSettingsResponse{ScoreThreshold: 60}
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

		// Sync BotDetectionEnabled into the protection config so the engine
		// sees a consistent value regardless of which page the user toggles.
		syncBotEnabledToProtection(settingsRepo, current.Enabled)

		if reload != nil {
			if err := reload(); err != nil {
				c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "settings": current})
				return
			}
		}
		c.JSON(200, current)
	}
}

func GetBotScores(repo *repository.BotScoreRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, size)

		f := repository.BotScoreFilter{
			ClientIP: c.DefaultQuery("ip", ""),
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

func GetFingerprints(repo *repository.FingerprintRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		stats, err := repo.GetStats()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, stats)
	}
}
