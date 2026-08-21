package protect

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func GetProtectionSettings(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg, err := shared.LoadProtectionConfigStrict(repo)
		if err != nil {
			c.JSON(500, map[string]string{"error": "invalid protection configuration"})
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
	delete(out, "basic_auth_password")

	out["cc_rules"] = []any{}
	out["owasp_modules"] = map[string]string{}
	out["owasp_rules_config"] = map[string]any{}
	out["cve_rules_config"] = map[string]any{}
	out["chain_steps"] = []any{}
	out["escalation_steps"] = []any{}
	out["skip_path_by_phase"] = map[string][]string{}

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
	if cfg.OWASPRulesConfig != "" {
		var rulesConfig map[string]any
		if json.Unmarshal([]byte(cfg.OWASPRulesConfig), &rulesConfig) == nil {
			out["owasp_rules_config"] = rulesConfig
		}
	}
	if cfg.CVERulesConfig != "" {
		var rulesConfig map[string]any
		if json.Unmarshal([]byte(cfg.CVERulesConfig), &rulesConfig) == nil {
			out["cve_rules_config"] = rulesConfig
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
	if cfg.SkipPathByPhase != "" {
		var pathsByPhase map[string][]string
		if json.Unmarshal([]byte(cfg.SkipPathByPhase), &pathsByPhase) == nil && pathsByPhase != nil {
			out["skip_path_by_phase"] = pathsByPhase
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
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}

		if passwordRaw, ok := raw["basic_auth_password"]; ok {
			var password string
			if err := json.Unmarshal(passwordRaw, &password); err != nil {
				c.JSON(400, map[string]string{"error": "invalid basic auth password"})
				return
			}
			if strings.TrimSpace(password) == "" {
				delete(raw, "basic_auth_password")
			}
		}

		present := make(map[string]bool, len(raw))
		for key := range raw {
			present[key] = true
		}

		// skip_path_by_phase 需要区分 JSON null（清除全局配置）与空字符串
		// （非法值，与站点端 bindSiteFromRaw 保持一致的 400 拒绝）。
		// PeelJSONStringBlobs 会把 null 和空字符串都规范化为 ""，丢失原始语义，
		// 因此在 peel 之前先记录原始 token。
		skipPathRaw, skipPathPresent := raw["skip_path_by_phase"]
		skipPathNull := skipPathPresent && strings.TrimSpace(string(skipPathRaw)) == "null"

		preserved := shared.PeelJSONStringBlobs(raw, shared.ProtectionJSONBlobKeys())

		plainBytes, err := json.Marshal(raw)
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid config"})
			return
		}
		cfg, err := shared.LoadProtectionConfigStrict(repo)
		if err != nil {
			c.JSON(500, map[string]string{"error": "invalid protection configuration"})
			return
		}
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
		if s, ok := preserved["skip_path_by_phase"]; ok {
			if !skipPathNull {
				if err := shared.ValidateSkipPathByPhase(s); err != nil {
					c.JSON(400, map[string]string{"error": err.Error()})
					return
				}
			}
			cfg.SkipPathByPhase = s
		}

		challengePresent := map[string]bool{
			"captcha_type":            present["captcha_type"],
			"captcha_timeout":         present["captcha_timeout"],
			"captcha_pass_ttl":        present["captcha_pass_ttl"],
			"shield_difficulty":       present["shield_difficulty"],
			"shield_timeout_secs":     present["shield_timeout_secs"],
			"shield_auto_start_delay": present["shield_auto_start_delay"],
			"shield_max_retries":      present["shield_max_retries"],
			"shield_env_strictness":   present["shield_env_strictness"],
		}
		if err := validateChallengeConfig(cfg, challengePresent); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if present["chain_steps"] {
			steps, ok := normalizeChainStepPayload(json.RawMessage(cfg.ChainSteps))
			if !ok {
				c.JSON(400, map[string]string{"error": "chain_steps contains unsupported step type or captcha_type"})
				return
			}
			cfg.ChainSteps = steps
		}

		actionFields := map[string]struct {
			value       string
			enableField string
			enabled     bool
		}{
			"request_ratelimit_action": {value: cfg.RequestRateLimitAction, enableField: "request_ratelimit_enabled", enabled: cfg.RequestRateLimitEnabled},
			"error_ratelimit_action":   {value: cfg.ErrorRateLimitAction, enableField: "error_ratelimit_enabled", enabled: cfg.ErrorRateLimitEnabled},
			"builtin_owasp_on_hit":     {value: cfg.OWASPAction, enableField: "builtin_owasp_enabled", enabled: cfg.OWASPEnabled},
			"cve_action":               {value: cfg.CVEAction, enableField: "cve_enabled", enabled: cfg.CVEEnabled},
			"auto_ban_action":          {value: cfg.AutoBanAction, enableField: "auto_ban_enabled", enabled: cfg.AutoBanEnabled},
		}
		for field, spec := range actionFields {
			if (!present[field] && !(present[spec.enableField] && spec.enabled)) || spec.value == "" {
				continue
			}
			normalized, ok := shared.ValidateActionWithoutRedirectTarget(spec.value)
			if ok && field == "auto_ban_action" {
				switch normalized {
				case "intercept", "drop":
				default:
					ok = false
				}
			}
			if ok {
				setProtectionActionField(&cfg, field, normalized)
			} else {
				c.JSON(400, map[string]string{"error": "invalid action"})
				return
			}
		}
		if present["cc_rules"] || (present["cc_use_custom"] && cfg.CCUseCustom) {
			if err := shared.ValidateCCRules(cfg.CCRules); err != nil {
				c.JSON(400, map[string]string{"error": err.Error()})
				return
			}
		}

		data, err := json.Marshal(cfg)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.Transaction(func(txRepo *repository.SystemSettingsRepo) error {
			if err := txRepo.Set("protection", string(data)); err != nil {
				return err
			}

			// Sync bot_detection_enabled to bot_settings.Enabled so the bot page
			// reflects changes made on the protection page.
			if present["bot_detection_enabled"] {
				if err := shared.SyncProtectionBotToSettings(txRepo, cfg.BotDetectionEnabled); err != nil {
					return err
				}
			}
			if present["captcha_enabled"] {
				if err := shared.SyncProtectionCaptchaToSettings(txRepo, cfg.CaptchaEnabled); err != nil {
					return err
				}
			}
			if present["anti_replay_enabled"] {
				if err := shared.SyncProtectionAntiReplayToSettings(txRepo, cfg.AntiReplayEnabled); err != nil {
					return err
				}
			}
			if present["cve_auto_drop_critical"] || present["cve_auto_drop_high"] {
				if err := shared.SyncCVEAutoDropToDropPolicy(txRepo, cfg.CVEAutoDropCritical, cfg.CVEAutoDropHigh); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, buildProtectionResponse(cfg))
	}
}

func setProtectionActionField(cfg *store.ProtectionConfig, field string, value string) {
	switch field {
	case "request_ratelimit_action":
		cfg.RequestRateLimitAction = value
	case "error_ratelimit_action":
		cfg.ErrorRateLimitAction = value
	case "builtin_owasp_on_hit":
		cfg.OWASPAction = value
	case "cve_action":
		cfg.CVEAction = value
	case "auto_ban_action":
		cfg.AutoBanAction = value
	}
}

func validateCCRuleActions(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return true
	}
	var rules []struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return false
	}
	for _, rule := range rules {
		if _, ok := shared.ValidateCCRuleAction(rule.Action); !ok && strings.TrimSpace(rule.Action) != "" {
			return false
		}
	}
	return true
}
