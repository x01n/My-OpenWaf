package admin

import (
	"context"
	"sync"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

type escalationStatus struct {
	IP          string `json:"ip"`
	CurrentStep int    `json:"current_step"`
	HitCount    int    `json:"hit_count"`
	LastHit     string `json:"last_hit"`
}

var (
	escalationStatusMap   = make(map[string]*escalationStatus)
	escalationStatusMapMu sync.RWMutex
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
		cfg := loadProtectionConfig(repo)
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
			EscalationEnabled    bool                      `json:"escalation_enabled"`
			EscalationWindowSecs int                       `json:"escalation_window_secs"`
			EscalationSteps      []store.EscalationStepDef `json:"escalation_steps"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		for i, step := range req.EscalationSteps {
			if step.Threshold <= 0 {
				c.JSON(400, map[string]string{"error": "step threshold must be positive"})
				return
			}
			if step.Action == "" {
				c.JSON(400, map[string]string{"error": "step action required"})
				return
			}
			if i > 0 && step.Threshold <= req.EscalationSteps[i-1].Threshold {
				c.JSON(400, map[string]string{"error": "steps must have increasing thresholds"})
				return
			}
		}
		cfg := loadProtectionConfig(repo)
		cfg.EscalationEnabled = req.EscalationEnabled
		if req.EscalationWindowSecs > 0 {
			cfg.EscalationWindowSecs = req.EscalationWindowSecs
		}
		cfg.SetEscalationSteps(req.EscalationSteps)
		if err := saveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "saved but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{
			"escalation_enabled":     cfg.EscalationEnabled,
			"escalation_window_secs": cfg.EscalationWindowSecs,
			"escalation_steps":       req.EscalationSteps,
		})
	}
}

func GetEscalationIPStatus() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		ip := c.Param("ip")
		if ip == "" {
			c.JSON(400, map[string]string{"error": "ip required"})
			return
		}
		escalationStatusMapMu.RLock()
		status, exists := escalationStatusMap[ip]
		escalationStatusMapMu.RUnlock()
		if !exists {
			c.JSON(200, map[string]any{
				"ip":           ip,
				"current_step": 0,
				"hit_count":    0,
				"message":      "no escalation state found for this IP",
			})
			return
		}
		c.JSON(200, status)
	}
}

func ResetEscalationIPStatus() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		ip := c.Param("ip")
		if ip == "" {
			c.JSON(400, map[string]string{"error": "ip required"})
			return
		}
		escalationStatusMapMu.Lock()
		delete(escalationStatusMap, ip)
		escalationStatusMapMu.Unlock()
		c.JSON(200, map[string]string{"message": "escalation state reset for " + ip})
	}
}
