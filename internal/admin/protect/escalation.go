package protect

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
	wafescalation "My-OpenWaf/internal/waf/escalation"
)

func GetEscalationConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id := c.Param("id")
		if id != "global" {
			if _, err := utils.ParseUint(id); err != nil {
				c.JSON(400, map[string]string{"error": "invalid id"})
				return
			}
		}
		cfg := shared.LoadProtectionConfig(repo)
		steps := cfg.GetEscalationSteps()
		if steps == nil {
			steps = []store.EscalationStepDef{}
		}
		c.JSON(200, map[string]any{
			"escalation_enabled":     cfg.EscalationEnabled,
			"escalation_window_secs": cfg.EscalationWindowSecs,
			"escalation_steps":       steps,
		})
	}
}

func UpdateEscalationConfig(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id := c.Param("id")
		if id != "global" {
			if _, err := utils.ParseUint(id); err != nil {
				c.JSON(400, map[string]string{"error": "invalid id"})
				return
			}
		}
		var req struct {
			EscalationEnabled    *bool                      `json:"escalation_enabled"`
			EscalationWindowSecs *int                       `json:"escalation_window_secs"`
			EscalationSteps      *[]store.EscalationStepDef `json:"escalation_steps"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		if req.EscalationWindowSecs != nil && *req.EscalationWindowSecs <= 0 {
			c.JSON(400, map[string]string{"error": "escalation_window_secs must be positive"})
			return
		}
		if req.EscalationSteps != nil {
			for i, step := range *req.EscalationSteps {
				if step.Threshold <= 0 {
					c.JSON(400, map[string]string{"error": "step threshold must be positive"})
					return
				}
				if step.Action == "" {
					c.JSON(400, map[string]string{"error": "step action required"})
					return
				}
				if i > 0 && step.Threshold <= (*req.EscalationSteps)[i-1].Threshold {
					c.JSON(400, map[string]string{"error": "steps must have increasing thresholds"})
					return
				}
			}
		}
		cfg := shared.LoadProtectionConfig(repo)
		if req.EscalationEnabled != nil {
			cfg.EscalationEnabled = *req.EscalationEnabled
		}
		if req.EscalationWindowSecs != nil {
			cfg.EscalationWindowSecs = *req.EscalationWindowSecs
		}
		if req.EscalationSteps != nil {
			cfg.SetEscalationSteps(*req.EscalationSteps)
		}
		if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{
			"escalation_enabled":     cfg.EscalationEnabled,
			"escalation_window_secs": cfg.EscalationWindowSecs,
			"escalation_steps":       escalationStepsResponse(cfg),
		})
	}
}

func escalationStepsResponse(cfg store.ProtectionConfig) []store.EscalationStepDef {
	steps := cfg.GetEscalationSteps()
	if steps == nil {
		return []store.EscalationStepDef{}
	}
	return steps
}

func GetEscalationIPStatus(mgr *wafescalation.EscalationManager) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		ip := c.Param("ip")
		if ip == "" {
			c.JSON(400, map[string]string{"error": "ip required"})
			return
		}
		if mgr == nil {
			c.JSON(200, map[string]any{
				"ip":           ip,
				"current_step": 0,
				"hit_count":    0,
				"message":      "escalation manager not initialized",
			})
			return
		}
		status := mgr.GetIPStatus(ip, 0)
		c.JSON(200, status)
	}
}

func ResetEscalationIPStatus(mgr *wafescalation.EscalationManager) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		ip := c.Param("ip")
		if ip == "" {
			c.JSON(400, map[string]string{"error": "ip required"})
			return
		}
		if mgr != nil {
			mgr.ResetIP(ip, 0)
		}
		c.JSON(200, map[string]string{"message": "escalation state reset for " + ip})
	}
}
