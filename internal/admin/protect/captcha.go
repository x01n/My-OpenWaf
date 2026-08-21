package protect

import (
	"context"
	"fmt"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/challenge"
)

// captchaConfigResponse is the API response for captcha configuration.
type captchaConfigResponse struct {
	CaptchaEnabled          bool   `json:"captcha_enabled"`
	CaptchaType             string `json:"captcha_type"`
	CaptchaTimeout          int    `json:"captcha_timeout"`
	CaptchaPassTTL          int    `json:"captcha_pass_ttl"`
	ShieldEnabled           bool   `json:"shield_enabled"`
	ShieldDifficulty        int    `json:"shield_difficulty"`
	ShieldTimeoutSecs       int    `json:"shield_timeout_secs"`
	ShieldAutoStartDelay    int    `json:"shield_auto_start_delay"`
	ShieldMaxRetries        int    `json:"shield_max_retries"`
	ShieldEnvStrictness     int    `json:"shield_env_strictness"`
	ShieldRequireHTTP2      bool   `json:"shield_require_http2"`
	ShieldRequireHTTP3      bool   `json:"shield_require_http3"`
	ShieldAllowHTTP1        bool   `json:"shield_allow_http1"`
	ShieldEnableJSChallenge bool   `json:"shield_enable_js_challenge"`
	ShieldEnableEnvCheck    bool   `json:"shield_enable_env_check"`
	ShieldEnableDevTools    bool   `json:"shield_enable_devtools"`
}

type captchaConfigRequest struct {
	CaptchaEnabled          *bool  `json:"captcha_enabled"`
	CaptchaType             string `json:"captcha_type"`
	CaptchaTimeout          *int   `json:"captcha_timeout"`
	CaptchaPassTTL          *int   `json:"captcha_pass_ttl"`
	ShieldEnabled           *bool  `json:"shield_enabled"`
	ShieldDifficulty        *int   `json:"shield_difficulty"`
	ShieldTimeoutSecs       *int   `json:"shield_timeout_secs"`
	ShieldAutoStartDelay    *int   `json:"shield_auto_start_delay"`
	ShieldMaxRetries        *int   `json:"shield_max_retries"`
	ShieldEnvStrictness     *int   `json:"shield_env_strictness"`
	ShieldRequireHTTP2      *bool  `json:"shield_require_http2"`
	ShieldRequireHTTP3      *bool  `json:"shield_require_http3"`
	ShieldAllowHTTP1        *bool  `json:"shield_allow_http1"`
	ShieldEnableJSChallenge *bool  `json:"shield_enable_js_challenge"`
	ShieldEnableEnvCheck    *bool  `json:"shield_enable_env_check"`
	ShieldEnableDevTools    *bool  `json:"shield_enable_devtools"`
}

// GetCaptchaConfig returns the current captcha/shield challenge configuration.
func GetCaptchaConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := shared.LoadProtectionConfig(repo)
		c.JSON(200, buildCaptchaConfigResponse(cfg))
	}
}

// validateChallengeConfig validates challenge fields that are part of an update payload.
func validateChallengeConfig(cfg store.ProtectionConfig, present map[string]bool) error {
	if present["captcha_type"] {
		if err := shared.ValidateGlobalCaptchaType(cfg.CaptchaType); err != nil {
			return err
		}
	}
	if present["captcha_timeout"] && cfg.CaptchaTimeout <= 0 {
		return fmt.Errorf("captcha_timeout must be greater than 0")
	}
	if present["captcha_pass_ttl"] && cfg.CaptchaPassTTL <= 0 {
		return fmt.Errorf("captcha_pass_ttl must be greater than 0")
	}
	if present["shield_difficulty"] && (cfg.ShieldDifficulty < 1 || cfg.ShieldDifficulty > 7) {
		return fmt.Errorf("shield_difficulty must be between 1 and 7")
	}
	if present["shield_timeout_secs"] && cfg.ShieldTimeoutSecs <= 0 {
		return fmt.Errorf("shield_timeout_secs must be greater than 0")
	}
	if present["shield_auto_start_delay"] && cfg.ShieldAutoStartDelay <= 0 {
		return fmt.Errorf("shield_auto_start_delay must be greater than 0")
	}
	if present["shield_max_retries"] && cfg.ShieldMaxRetries <= 0 {
		return fmt.Errorf("shield_max_retries must be greater than 0")
	}
	if present["shield_env_strictness"] && (cfg.ShieldEnvStrictness < 0 || cfg.ShieldEnvStrictness > 2) {
		return fmt.Errorf("shield_env_strictness must be one of: 0, 1, 2")
	}
	return nil
}

func buildCaptchaConfigResponse(cfg store.ProtectionConfig) captchaConfigResponse {
	return captchaConfigResponse{
		CaptchaEnabled:          cfg.CaptchaEnabled,
		CaptchaType:             cfg.CaptchaType,
		CaptchaTimeout:          cfg.CaptchaTimeout,
		CaptchaPassTTL:          cfg.CaptchaPassTTL,
		ShieldEnabled:           cfg.ShieldEnabled,
		ShieldDifficulty:        cfg.ShieldDifficulty,
		ShieldTimeoutSecs:       cfg.ShieldTimeoutSecs,
		ShieldAutoStartDelay:    cfg.ShieldAutoStartDelay,
		ShieldMaxRetries:        cfg.ShieldMaxRetries,
		ShieldEnvStrictness:     cfg.ShieldEnvStrictness,
		ShieldRequireHTTP2:      cfg.ShieldRequireHTTP2,
		ShieldRequireHTTP3:      cfg.ShieldRequireHTTP3,
		ShieldAllowHTTP1:        cfg.ShieldAllowHTTP1,
		ShieldEnableJSChallenge: cfg.ShieldEnableJSChallenge,
		ShieldEnableEnvCheck:    cfg.ShieldEnableEnvCheck,
		ShieldEnableDevTools:    cfg.ShieldEnableDevTools,
	}
}

// UpdateCaptchaConfig updates captcha/shield challenge configuration.
func UpdateCaptchaConfig(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req captchaConfigRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}

		present := map[string]bool{
			"captcha_type":            req.CaptchaType != "",
			"captcha_timeout":         req.CaptchaTimeout != nil,
			"captcha_pass_ttl":        req.CaptchaPassTTL != nil,
			"shield_difficulty":       req.ShieldDifficulty != nil,
			"shield_timeout_secs":     req.ShieldTimeoutSecs != nil,
			"shield_auto_start_delay": req.ShieldAutoStartDelay != nil,
			"shield_max_retries":      req.ShieldMaxRetries != nil,
			"shield_env_strictness":   req.ShieldEnvStrictness != nil,
		}

		cfg := shared.LoadProtectionConfig(repo)
		if req.CaptchaEnabled != nil {
			cfg.CaptchaEnabled = *req.CaptchaEnabled
		}
		if req.CaptchaType != "" {
			cfg.CaptchaType = req.CaptchaType
		}
		if req.CaptchaTimeout != nil {
			cfg.CaptchaTimeout = *req.CaptchaTimeout
		}
		if req.CaptchaPassTTL != nil {
			cfg.CaptchaPassTTL = *req.CaptchaPassTTL
		}
		if req.ShieldEnabled != nil {
			cfg.ShieldEnabled = *req.ShieldEnabled
		}
		if req.ShieldDifficulty != nil {
			cfg.ShieldDifficulty = *req.ShieldDifficulty
		}
		if req.ShieldTimeoutSecs != nil {
			cfg.ShieldTimeoutSecs = *req.ShieldTimeoutSecs
		}
		if req.ShieldAutoStartDelay != nil {
			cfg.ShieldAutoStartDelay = *req.ShieldAutoStartDelay
		}
		if req.ShieldMaxRetries != nil {
			cfg.ShieldMaxRetries = *req.ShieldMaxRetries
		}
		if req.ShieldEnvStrictness != nil {
			cfg.ShieldEnvStrictness = *req.ShieldEnvStrictness
		}
		if req.ShieldRequireHTTP2 != nil {
			cfg.ShieldRequireHTTP2 = *req.ShieldRequireHTTP2
		}
		if req.ShieldRequireHTTP3 != nil {
			cfg.ShieldRequireHTTP3 = *req.ShieldRequireHTTP3
		}
		if req.ShieldAllowHTTP1 != nil {
			cfg.ShieldAllowHTTP1 = *req.ShieldAllowHTTP1
		}
		if req.ShieldEnableJSChallenge != nil {
			cfg.ShieldEnableJSChallenge = *req.ShieldEnableJSChallenge
		}
		if req.ShieldEnableEnvCheck != nil {
			cfg.ShieldEnableEnvCheck = *req.ShieldEnableEnvCheck
		}
		if req.ShieldEnableDevTools != nil {
			cfg.ShieldEnableDevTools = *req.ShieldEnableDevTools
		}
		if err := validateChallengeConfig(cfg, present); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		if err := repo.Transaction(func(txRepo *repository.SystemSettingsRepo) error {
			if err := shared.SaveProtectionConfig(txRepo, cfg); err != nil {
				return err
			}
			if req.CaptchaEnabled != nil {
				return shared.SyncProtectionCaptchaToSettings(txRepo, cfg.CaptchaEnabled)
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
		c.JSON(200, buildCaptchaConfigResponse(cfg))
	}
}

// TestCaptcha generates a test captcha preview.
func TestCaptcha(repo *repository.SystemSettingsRepo, mgr *challenge.CaptchaManager) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		if mgr == nil {
			c.JSON(503, map[string]string{"error": "captcha manager not initialized"})
			return
		}
		cfg := shared.LoadProtectionConfig(repo)
		captchaType := challenge.CaptchaType(cfg.CaptchaType)
		if captchaType == "" {
			captchaType = challenge.CaptchaTypeMath
		}
		captchaChallenge, err := mgr.Generate(captchaType, false)
		if err != nil {
			c.JSON(500, map[string]string{"error": "captcha generation failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{
			"session_id":   captchaChallenge.SessionID,
			"captcha_type": cfg.CaptchaType,
			"type":         captchaChallenge.Type,
			"master_img":   captchaChallenge.MasterImg,
			"thumb_img":    captchaChallenge.ThumbImg,
			"prompt":       captchaChallenge.Prompt,
			"width":        captchaChallenge.Width,
			"height":       captchaChallenge.Height,
			"timeout":      cfg.CaptchaTimeout,
			"pass_ttl":     cfg.CaptchaPassTTL,
			"fallback":     captchaChallenge.Fallback,
		})
	}
}
