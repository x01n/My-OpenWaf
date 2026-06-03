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

// DropPolicyResponse represents the drop policy configuration.
type DropPolicyResponse struct {
	Enabled             bool `json:"enabled"`
	BotScoreThreshold   int  `json:"bot_score_threshold"`
	CVEAutoDropCritical bool `json:"cve_auto_drop_critical"`
	CVEAutoDropHigh     bool `json:"cve_auto_drop_high"`
}

// DropPolicyUpdate represents the request body for updating drop policy.
type DropPolicyUpdate struct {
	Enabled             *bool `json:"enabled"`
	BotScoreThreshold   *int  `json:"bot_score_threshold"`
	CVEAutoDropCritical *bool `json:"cve_auto_drop_critical"`
	CVEAutoDropHigh     *bool `json:"cve_auto_drop_high"`
}

func defaultDropPolicyResponse(settingsRepo *repository.SystemSettingsRepo) DropPolicyResponse {
	resp := DropPolicyResponse{
		Enabled:             true,
		BotScoreThreshold:   80,
		CVEAutoDropCritical: true,
		CVEAutoDropHigh:     true,
	}
	if settingsRepo == nil {
		return resp
	}
	protection := shared.LoadProtectionConfig(settingsRepo)
	resp.CVEAutoDropCritical = protection.CVEAutoDropCritical
	resp.CVEAutoDropHigh = protection.CVEAutoDropHigh
	if val, err := settingsRepo.Get("bot_settings"); err == nil && val != "" {
		var bot shared.BotSettingsResponse
		if json.Unmarshal([]byte(val), &bot) == nil && bot.ScoreThreshold > 0 {
			resp.BotScoreThreshold = bot.ScoreThreshold
		}
	}
	return resp
}

func GetDropPolicy(settingsRepo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		resp := defaultDropPolicyResponse(settingsRepo)
		val, err := settingsRepo.Get("drop_policy")
		if err != nil || val == "" {
			c.JSON(200, resp)
			return
		}
		if err := json.Unmarshal([]byte(val), &resp); err != nil {
			c.JSON(200, defaultDropPolicyResponse(settingsRepo))
			return
		}
		c.JSON(200, resp)
	}
}

func UpdateDropPolicy(settingsRepo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req DropPolicyUpdate
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		current := defaultDropPolicyResponse(settingsRepo)
		if val, err := settingsRepo.Get("drop_policy"); err == nil && val != "" {
			_ = json.Unmarshal([]byte(val), &current)
		}

		if req.Enabled != nil {
			current.Enabled = *req.Enabled
		}
		if req.BotScoreThreshold != nil {
			current.BotScoreThreshold = *req.BotScoreThreshold
		}
		if req.CVEAutoDropCritical != nil {
			current.CVEAutoDropCritical = *req.CVEAutoDropCritical
		}
		if req.CVEAutoDropHigh != nil {
			current.CVEAutoDropHigh = *req.CVEAutoDropHigh
		}

		data, _ := json.Marshal(current)
		if err := settingsRepo.Set("drop_policy", string(data)); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		protection := shared.LoadProtectionConfig(settingsRepo)
		if req.CVEAutoDropCritical != nil {
			protection.CVEAutoDropCritical = current.CVEAutoDropCritical
		}
		if req.CVEAutoDropHigh != nil {
			protection.CVEAutoDropHigh = current.CVEAutoDropHigh
		}
		if req.BotScoreThreshold != nil {
			if err := shared.SyncDropThresholdToBotSettings(settingsRepo, current.BotScoreThreshold); err != nil {
				c.JSON(500, map[string]string{"error": err.Error()})
				return
			}
		}
		if err := shared.SaveProtectionConfig(settingsRepo, protection); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		if reload != nil {
			if err := reload(); err != nil {
				c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "policy": current})
				return
			}
		}
		c.JSON(200, current)
	}
}

func GetDropStats(repo *repository.DropEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		stats, err := repo.Stats24h()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, stats)
	}
}

func GetDropEvents(repo *repository.DropEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, size)

		f := repository.DropEventFilter{
			ClientIP: c.DefaultQuery("ip", ""),
			Source:   c.DefaultQuery("source", ""),
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
