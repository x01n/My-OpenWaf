package protect

import (
	"context"
	"encoding/json"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func GetProtectionSettings(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := shared.LoadProtectionConfig(repo)
		c.JSON(200, buildProtectionResponse(cfg))
	}
}

// buildProtectionResponse converts stored string fields back to JSON objects for the frontend.
func buildProtectionResponse(cfg store.ProtectionConfig) map[string]any {
	out := make(map[string]any)
	raw, _ := json.Marshal(cfg)
	_ = json.Unmarshal(raw, &out)

	// Expand legacy owasp_modules string and expose category_sensitivity as the UI source.
	if cfg.OWASPModules != "" {
		var modules map[string]string
		if json.Unmarshal([]byte(cfg.OWASPModules), &modules) == nil {
			out["owasp_modules"] = modules
		}
	}
	categorySensitivity := cfg.EffectiveCategorySensitivity()
	if categorySensitivity == nil {
		categorySensitivity = map[string]string{}
	}
	out["category_sensitivity"] = categorySensitivity
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
		// Parse into a generic map first so we can peel object/array fields before unmarshaling
		// into ProtectionConfig (several DB-backed JSON blobs are typed as string in Go).
		var raw map[string]json.RawMessage
		if err := c.BindJSON(&raw); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		present := make(map[string]bool, len(raw))
		for key := range raw {
			present[key] = true
		}
		preserved := shared.PeelJSONStringBlobs(raw, shared.ProtectionJSONBlobKeys())

		plainBytes, err := json.Marshal(raw)
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid config"})
			return
		}
		cfg := shared.LoadProtectionConfig(repo)
		if err := json.Unmarshal(plainBytes, &cfg); err != nil {
			c.JSON(400, map[string]string{"error": "invalid config"})
			return
		}

		if s, ok := preserved["cc_rules"]; ok {
			cfg.CCRules = s
		}
		if s, ok := preserved["owasp_modules"]; ok {
			cfg.OWASPModules = s
		}
		if s, ok := preserved["chain_steps"]; ok {
			cfg.ChainSteps = s
		}
		if s, ok := preserved["escalation_steps"]; ok {
			cfg.EscalationSteps = s
		}
		if s, ok := preserved["category_sensitivity"]; ok {
			cfg.CategorySensitivity = s
		}
		if s, ok := preserved["owasp_rules_config"]; ok {
			cfg.OWASPRulesConfig = s
		}
		if s, ok := preserved["cve_rules_config"]; ok {
			cfg.CVERulesConfig = s
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

		// Sync bot_detection_enabled to bot_settings.Enabled so the bot page
		// reflects changes made on the protection page.
		if present["bot_detection_enabled"] {
			if err := shared.SyncProtectionBotToSettings(repo, cfg.BotDetectionEnabled); err != nil {
				c.JSON(500, map[string]string{"error": err.Error()})
				return
			}
		}
		if present["cve_auto_drop_critical"] || present["cve_auto_drop_high"] {
			if err := shared.SyncCVEAutoDropToDropPolicy(repo, cfg.CVEAutoDropCritical, cfg.CVEAutoDropHigh); err != nil {
				c.JSON(500, map[string]string{"error": err.Error()})
				return
			}
		}

		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, buildProtectionResponse(cfg))
	}
}
