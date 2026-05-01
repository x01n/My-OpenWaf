package admin

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
)

type chainSession struct {
	ID        string `json:"id"`
	ClientIP  string `json:"client_ip"`
	Step      int    `json:"current_step"`
	StartedAt string `json:"started_at"`
}

var (
	chainSessions   = make(map[string]*chainSession)
	chainSessionsMu sync.RWMutex
)

type chainConfigResponse struct {
	ChainEnabled bool            `json:"chain_enabled"`
	ChainSteps   json.RawMessage `json:"chain_steps"`
}

func GetChainConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := loadProtectionConfig(repo)
		var steps json.RawMessage
		if cfg.ChainSteps != "" {
			steps = json.RawMessage(cfg.ChainSteps)
		} else {
			steps = json.RawMessage("[]")
		}
		c.JSON(200, chainConfigResponse{
			ChainEnabled: cfg.ChainEnabled,
			ChainSteps:   steps,
		})
	}
}

func UpdateChainConfig(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			ChainEnabled bool            `json:"chain_enabled"`
			ChainSteps   json.RawMessage `json:"chain_steps"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		cfg := loadProtectionConfig(repo)
		cfg.ChainEnabled = req.ChainEnabled
		if len(req.ChainSteps) > 0 && string(req.ChainSteps) != "null" {
			cfg.ChainSteps = string(req.ChainSteps)
		}

		if err := saveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "saved but reload failed: " + err.Error()})
			return
		}

		var steps json.RawMessage
		if cfg.ChainSteps != "" {
			steps = json.RawMessage(cfg.ChainSteps)
		} else {
			steps = json.RawMessage("[]")
		}
		c.JSON(200, chainConfigResponse{
			ChainEnabled: cfg.ChainEnabled,
			ChainSteps:   steps,
		})
	}
}

func ListChainSessions() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		chainSessionsMu.RLock()
		defer chainSessionsMu.RUnlock()
		sessions := make([]*chainSession, 0, len(chainSessions))
		for _, s := range chainSessions {
			sessions = append(sessions, s)
		}
		c.JSON(200, map[string]any{"items": sessions, "total": len(sessions)})
	}
}

func DeleteChainSession() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id := c.Param("id")
		if id == "" {
			c.JSON(400, map[string]string{"error": "id required"})
			return
		}
		chainSessionsMu.Lock()
		defer chainSessionsMu.Unlock()
		if _, ok := chainSessions[id]; !ok {
			c.JSON(404, map[string]string{"error": "session not found"})
			return
		}
		delete(chainSessions, id)
		c.JSON(200, map[string]string{"message": "session cleared"})
	}
}
