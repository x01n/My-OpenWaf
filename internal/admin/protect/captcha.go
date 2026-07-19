package protect

import (
	"context"

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
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		validTypes := map[string]bool{"math": true, "click": true, "slide": true, "rotate": true}
		if req.CaptchaType != "" && !validTypes[req.CaptchaType] {
			c.JSON(400, map[string]string{"error": "captcha_type must be one of: math, click, slide, rotate"})
			return
		}

		cfg := shared.LoadProtectionConfig(repo)
		if req.CaptchaEnabled != nil {
			cfg.CaptchaEnabled = *req.CaptchaEnabled
		}
		if req.CaptchaType != "" {
			cfg.CaptchaType = req.CaptchaType
		}
		if req.CaptchaTimeout != nil && *req.CaptchaTimeout > 0 {
			cfg.CaptchaTimeout = *req.CaptchaTimeout
		}
		if req.CaptchaPassTTL != nil && *req.CaptchaPassTTL > 0 {
			cfg.CaptchaPassTTL = *req.CaptchaPassTTL
		}
		if req.ShieldEnabled != nil {
			cfg.ShieldEnabled = *req.ShieldEnabled
		}
		if req.ShieldDifficulty != nil && *req.ShieldDifficulty > 0 {
			cfg.ShieldDifficulty = *req.ShieldDifficulty
		}
		if req.ShieldTimeoutSecs != nil && *req.ShieldTimeoutSecs > 0 {
			cfg.ShieldTimeoutSecs = *req.ShieldTimeoutSecs
		}
		if req.ShieldAutoStartDelay != nil && *req.ShieldAutoStartDelay >= 0 {
			cfg.ShieldAutoStartDelay = *req.ShieldAutoStartDelay
		}
		if req.ShieldMaxRetries != nil && *req.ShieldMaxRetries > 0 {
			cfg.ShieldMaxRetries = *req.ShieldMaxRetries
		}
		if req.ShieldEnvStrictness != nil && *req.ShieldEnvStrictness >= 0 {
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

		if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
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
		captchaChallenge, err := mgr.Generate(captchaType)
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
