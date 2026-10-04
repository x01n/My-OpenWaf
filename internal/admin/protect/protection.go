package protect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/protect/captcha"
	"My-OpenWaf/internal/admin/protect/chain"
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

// buildProtectionResponse 把以字符串存储的字段还原成 JSON 对象，供前端使用。
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

	// 展开 legacy 形态的 owasp_modules 字符串，并把 category_sensitivity 作为 UI 的权威来源。
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
	// 把 cc_rules 字符串展开为数组
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
		// 先解析成通用 map，才能在反序列化进 ProtectionConfig 之前
		// 摘出对象/数组字段（若干 DB 侧 JSON blob 在 Go 里是 string 类型）。
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
		if err := captcha.ValidateChallengeConfig(cfg, challengePresent); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateRateLimitConfig(cfg, present); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if present["chain_steps"] {
			steps, ok := chain.NormalizeChainStepPayload(json.RawMessage(cfg.ChainSteps))
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
		// 全局质询动作：空串合法（继承语义 = 默认 challenge 渲染），
		// 非空必须是合法质询动作之一，防旧数据/手工写入的非法值带入快照。
		if !shared.ValidateGlobalChallengeAction(cfg.ChallengeAction) {
			c.JSON(400, map[string]string{"error": "invalid action"})
			return
		}
		if _, ok := shared.ValidateAntiReplayCookieMode(cfg.AntiReplayCookieMode, false); !ok {
			c.JSON(400, map[string]string{"error": "invalid anti_replay_cookie_mode"})
			return
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

			// 把 bot_detection_enabled 同步到 bot_settings.Enabled，
			// 让 bot 页面能反映在 protection 页面所做的修改。
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
			if present["anti_replay_cookie_mode"] {
				if err := shared.SyncProtectionAntiReplayCookieModeToSettings(txRepo, cfg.AntiReplayCookieMode); err != nil {
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

// validateRateLimitConfig 防止「已启用但窗口为零或配额为零」的限流器
// 把每个请求都变成人为的 429。即使限流器处于关闭状态也拒绝负值，
// 以免之后一旦打开就启用了坏配置。
func validateRateLimitConfig(cfg store.ProtectionConfig, present map[string]bool) error {
	if (present["request_ratelimit_window"] && cfg.RequestRateLimitWindow < 0) ||
		(present["request_ratelimit_max"] && cfg.RequestRateLimitMax < 0) {
		return errors.New("request rate limit window and max must not be negative")
	}
	if (present["error_ratelimit_window"] && cfg.ErrorRateLimitWindow < 0) ||
		(present["error_ratelimit_max"] && cfg.ErrorRateLimitMax < 0) {
		return errors.New("error rate limit window and max must not be negative")
	}
	if err := cfg.ValidateRateLimits(); err != nil {
		return err
	}
	return nil
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
