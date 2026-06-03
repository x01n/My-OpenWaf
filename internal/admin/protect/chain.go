package protect

import (
	"context"
	"encoding/json"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/challenge"
)

type chainConfigResponse struct {
	ChainEnabled bool            `json:"chain_enabled"`
	ChainSteps   json.RawMessage `json:"chain_steps"`
}

type chainStepPayload struct {
	Type        challenge.ChainStepType `json:"type"`
	Condition   string                  `json:"condition,omitempty"`
	Match       string                  `json:"match,omitempty"`
	CaptchaType challenge.CaptchaType   `json:"captcha_type,omitempty"`
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

func normalizeChainStepCondition(condition string) string {
	switch condition {
	case "", "all", "env_score>30", "env_score<30", "score>50", "score>80":
		return condition
	default:
		return ""
	}
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
		condition := normalizeChainStepCondition(step.Condition)
		if condition == "" {
			condition = normalizeChainStepCondition(step.Match)
		}
		switch step.Type {
		case challenge.ChainStepEnv, challenge.ChainStepPoW, challenge.ChainStepCaptcha:
			captchaType := step.CaptchaType
			if step.Type != challenge.ChainStepCaptcha {
				captchaType = ""
			}
			steps = append(steps, challenge.ChainStepConfig{Type: step.Type, Condition: condition, CaptchaType: captchaType})
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
			ChainEnabled *bool            `json:"chain_enabled"`
			ChainSteps   *json.RawMessage `json:"chain_steps"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		cfg := shared.LoadProtectionConfig(repo)
		if req.ChainEnabled != nil {
			cfg.ChainEnabled = *req.ChainEnabled
		}
		if req.ChainSteps != nil {
			if steps, ok := normalizeChainStepPayload(*req.ChainSteps); !ok {
				c.JSON(400, map[string]string{"error": "chain_steps contains unsupported step type"})
				return
			} else if steps != "" {
				cfg.ChainSteps = steps
			}
		}

		if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}

		c.JSON(200, chainConfigResponse{
			ChainEnabled: cfg.ChainEnabled,
			ChainSteps:   normalizedChainStepsJSON(cfg.ChainSteps),
		})
	}
}

func ListChainSessions(manager *challenge.ChainChallengeManager) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		if manager == nil {
			c.JSON(200, map[string]any{"items": []challenge.ChainSessionInfo{}, "total": 0})
			return
		}
		sessions := manager.ListSessions()
		c.JSON(200, map[string]any{"items": sessions, "total": len(sessions)})
	}
}

func DeleteChainSession(manager *challenge.ChainChallengeManager) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id := c.Param("id")
		if id == "" {
			c.JSON(400, map[string]string{"error": "id required"})
			return
		}
		if manager == nil || !manager.DeleteSession(id) {
			c.JSON(404, map[string]string{"error": "session not found"})
			return
		}
		c.JSON(200, map[string]string{"message": "session cleared"})
	}
}
