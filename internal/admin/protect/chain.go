package protect

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/challenge"
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

type chainStepPayload struct {
	Type      challenge.ChainStepType `json:"type"`
	Condition string            `json:"condition,omitempty"`
	Match     string            `json:"match,omitempty"`
}

func GetChainConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := shared.LoadProtectionConfig(repo)
		c.JSON(200, chainConfigResponse{
			ChainEnabled: cfg.ChainEnabled,
			ChainSteps:   normalizedChainStepsJSON(cfg.ChainSteps),
		})
	}
}

func normalizedChainStepsJSON(raw string) json.RawMessage {
	if raw == "" {
		return json.RawMessage("[]")
	}
	if steps, ok := normalizeChainStepPayload(json.RawMessage(raw)); ok && steps != "" {
		return json.RawMessage(steps)
	}
	return json.RawMessage("[]")
}

func normalizeChainStepPayload(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", true
	}
	var payload []chainStepPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", false
	}
	steps := make([]challenge.ChainStepConfig, 0, len(payload))
	for _, step := range payload {
		condition := step.Condition
		if condition == "" {
			condition = step.Match
		}
		switch step.Type {
		case challenge.ChainStepEnv, challenge.ChainStepPoW, challenge.ChainStepCaptcha:
			steps = append(steps, challenge.ChainStepConfig{Type: step.Type, Condition: condition})
		default:
			return "", false
		}
	}
	data, err := json.Marshal(steps)
	if err != nil {
		return "", false
	}
	return string(data), true
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

		cfg := shared.LoadProtectionConfig(repo)
		cfg.ChainEnabled = req.ChainEnabled
		if steps, ok := normalizeChainStepPayload(req.ChainSteps); !ok {
			c.JSON(400, map[string]string{"error": "chain_steps contains unsupported step type"})
			return
		} else if steps != "" {
			cfg.ChainSteps = steps
		}

		if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "saved but reload failed: " + err.Error()})
			return
		}

		c.JSON(200, chainConfigResponse{
			ChainEnabled: cfg.ChainEnabled,
			ChainSteps:   normalizedChainStepsJSON(cfg.ChainSteps),
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
