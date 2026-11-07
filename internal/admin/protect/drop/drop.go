package drop

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

// DropPolicyResponse 是 drop 策略配置。
type DropPolicyResponse struct {
	Enabled             bool `json:"enabled"`
	BotScoreThreshold   int  `json:"bot_score_threshold"`
	CVEAutoDropCritical bool `json:"cve_auto_drop_critical"`
	CVEAutoDropHigh     bool `json:"cve_auto_drop_high"`
}

// DropPolicyUpdate 是更新 drop 策略的请求体。
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
		if req.BotScoreThreshold != nil && !shared.ValidateBotScoreThreshold(*req.BotScoreThreshold) {
			c.JSON(400, map[string]string{"error": "bot_score_threshold must be between 1 and 100"})
			return
		}

		// 已持久化的策略行原文。只回写请求中显式提交的键，避免把缺失键按默认值物化。
		storedPolicy := make(map[string]json.RawMessage)
		storedPolicyJSON := ""
		storedPolicyExists := false
		storedPolicyValidObject := false
		if val, err := settingsRepo.Get("drop_policy"); err == nil {
			storedPolicyExists = strings.TrimSpace(val) != ""
			if storedPolicyExists && json.Unmarshal([]byte(val), &storedPolicy) == nil && storedPolicy != nil {
				storedPolicyJSON = val
				storedPolicyValidObject = true
			}
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(500, map[string]string{"error": "load drop policy: " + err.Error()})
			return
		}

		if storedPolicyExists && !storedPolicyValidObject {
			c.JSON(500, map[string]string{"error": "stored drop policy is not a valid JSON object"})
			return
		}

		current := defaultDropPolicyResponse(settingsRepo)
		if storedPolicyValidObject {
			if err := json.Unmarshal([]byte(storedPolicyJSON), &current); err != nil {
				c.JSON(500, map[string]string{"error": "decode stored drop policy: " + err.Error()})
				return
			}
		}

		updates := make(map[string]any, 4)
		if req.Enabled != nil {
			current.Enabled = *req.Enabled
			updates["enabled"] = current.Enabled
		}
		if req.BotScoreThreshold != nil {
			current.BotScoreThreshold = *req.BotScoreThreshold
			updates["bot_score_threshold"] = current.BotScoreThreshold
		}
		if req.CVEAutoDropCritical != nil {
			current.CVEAutoDropCritical = *req.CVEAutoDropCritical
			updates["cve_auto_drop_critical"] = current.CVEAutoDropCritical
		}
		if req.CVEAutoDropHigh != nil {
			current.CVEAutoDropHigh = *req.CVEAutoDropHigh
			updates["cve_auto_drop_high"] = current.CVEAutoDropHigh
		}

		// 首次创建记录时完整持久化默认值；非空损坏值维持旧策略并拒绝写入，
		// 有效对象仅合并请求中显式提交的键。
		var data []byte
		var err error
		if storedPolicyValidObject {
			for key, value := range updates {
				encoded, marshalErr := json.Marshal(value)
				if marshalErr != nil {
					c.JSON(500, map[string]string{"error": marshalErr.Error()})
					return
				}
				storedPolicy[key] = encoded
			}
			data, err = json.Marshal(storedPolicy)
		} else {
			data, err = json.Marshal(current)
		}
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := settingsRepo.Transaction(func(txRepo *repository.SystemSettingsRepo) error {
			if err := txRepo.Set("drop_policy", string(data)); err != nil {
				return err
			}
			protection := shared.LoadProtectionConfig(txRepo)
			if req.CVEAutoDropCritical != nil {
				protection.CVEAutoDropCritical = current.CVEAutoDropCritical
			}
			if req.CVEAutoDropHigh != nil {
				protection.CVEAutoDropHigh = current.CVEAutoDropHigh
			}
			if req.BotScoreThreshold != nil {
				if err := shared.SyncDropThresholdToBotSettingsRuntime(txRepo, current.BotScoreThreshold); err != nil {
					return err
				}
			}
			return shared.SaveProtectionConfig(txRepo, protection)
		}); err != nil {
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
