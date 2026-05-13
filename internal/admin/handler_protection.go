package admin

import (
	"context"
	"encoding/json"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// protectionDTO mirrors ProtectionConfig but accepts JSON object/array fields from the frontend, then converts them to strings.
type protectionDTO struct {
	store.ProtectionConfig
	OWASPModulesRaw    json.RawMessage `json:"owasp_modules,omitempty"`
	CCRulesRaw         json.RawMessage `json:"cc_rules,omitempty"`
	ChainStepsRaw      json.RawMessage `json:"chain_steps,omitempty"`
	EscalationStepsRaw json.RawMessage `json:"escalation_steps,omitempty"`
}

func GetProtectionSettings(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		val, err := repo.Get("protection")
		if err != nil {
			c.JSON(200, buildProtectionResponse(store.DefaultProtectionConfig()))
			return
		}
		var cfg store.ProtectionConfig
		if json.Unmarshal([]byte(val), &cfg) != nil {
			c.JSON(200, buildProtectionResponse(store.DefaultProtectionConfig()))
			return
		}
		c.JSON(200, buildProtectionResponse(cfg))
	}
}

// buildProtectionResponse converts stored string fields back to JSON objects for the frontend.
func buildProtectionResponse(cfg store.ProtectionConfig) map[string]any {
	out := make(map[string]any)
	raw, _ := json.Marshal(cfg)
	_ = json.Unmarshal(raw, &out)

	// Expand owasp_modules string → object
	if cfg.OWASPModules != "" {
		var modules map[string]string
		if json.Unmarshal([]byte(cfg.OWASPModules), &modules) == nil {
			out["owasp_modules"] = modules
		}
	}
	// Expand cc_rules string → array
	if cfg.CCRules != "" {
		var rules []any
		if json.Unmarshal([]byte(cfg.CCRules), &rules) == nil {
			out["cc_rules"] = rules
		}
	}
	if cfg.ChainSteps != "" {
		var steps []any
		if json.Unmarshal([]byte(cfg.ChainSteps), &steps) == nil {
			out["chain_steps"] = steps
		}
	}
	if cfg.EscalationSteps != "" {
		var steps []any
		if json.Unmarshal([]byte(cfg.EscalationSteps), &steps) == nil {
			out["escalation_steps"] = steps
		}
	}
	return out
}

func PutProtectionSettings(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		// Parse into a generic map first to capture raw owasp_modules / cc_rules
		var raw map[string]json.RawMessage
		if err := c.BindJSON(&raw); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		// Re-marshal to ProtectionConfig (string fields will be set below)
		plainBytes, _ := json.Marshal(raw)
		cfg := store.DefaultProtectionConfig()
		if err := json.Unmarshal(plainBytes, &cfg); err != nil {
			c.JSON(400, map[string]string{"error": "invalid config"})
			return
		}

		// If frontend sent owasp_modules as an object, stringify it
		if v, ok := raw["owasp_modules"]; ok && len(v) > 0 && string(v) != "null" {
			// Check if it's an object (not already a string)
			if v[0] == '{' {
				cfg.OWASPModules = string(v)
			}
		}
		// If frontend sent cc_rules as an array, stringify it
		if v, ok := raw["cc_rules"]; ok && len(v) > 0 && string(v) != "null" {
			if v[0] == '[' {
				cfg.CCRules = string(v)
			}
		}
		if v, ok := raw["chain_steps"]; ok && len(v) > 0 && string(v) != "null" {
			if v[0] == '[' {
				cfg.ChainSteps = string(v)
			}
		}
		if v, ok := raw["escalation_steps"]; ok && len(v) > 0 && string(v) != "null" {
			if v[0] == '[' {
				cfg.EscalationSteps = string(v)
			}
		}

		for _, candidate := range []string{cfg.RequestRateLimitAction, cfg.ErrorRateLimitAction, cfg.OWASPAction, cfg.CVEAction, cfg.AutoBanAction} {
			if candidate == "" {
				continue
			}
			if !action.IsValid(action.Type(candidate)) || action.Normalize(action.Type(candidate)) == action.Allow || action.Normalize(action.Type(candidate)) == action.Tag {
				c.JSON(400, map[string]string{"error": "invalid action"})
				return
			}
		}

		data, err := json.Marshal(cfg)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.Set("protection", string(data)); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "saved but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, buildProtectionResponse(cfg))
	}
}
