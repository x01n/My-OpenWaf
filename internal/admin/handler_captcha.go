package admin

import (
	"context"
	"encoding/json"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// captchaConfigResponse is the API response for captcha configuration.
type captchaConfigResponse struct {
	CaptchaEnabled   bool   `json:"captcha_enabled"`
	CaptchaType      string `json:"captcha_type"`
	CaptchaTimeout   int    `json:"captcha_timeout"`
	ShieldEnabled    bool   `json:"shield_enabled"`
	ShieldDifficulty int    `json:"shield_difficulty"`
}

// GetCaptchaConfig returns the current captcha/shield challenge configuration.
func GetCaptchaConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := loadProtectionConfig(repo)
		c.JSON(200, captchaConfigResponse{
			CaptchaEnabled:   cfg.CaptchaEnabled,
			CaptchaType:      cfg.CaptchaType,
			CaptchaTimeout:   cfg.CaptchaTimeout,
			ShieldEnabled:    cfg.ShieldEnabled,
			ShieldDifficulty: cfg.ShieldDifficulty,
		})
	}
}

// UpdateCaptchaConfig updates captcha/shield challenge configuration.
func UpdateCaptchaConfig(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req captchaConfigResponse
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		// Validate captcha type
		validTypes := map[string]bool{"math": true, "click": true, "slide": true, "rotate": true, "drag": true}
		if req.CaptchaType != "" && !validTypes[req.CaptchaType] {
			c.JSON(400, map[string]string{"error": "captcha_type must be one of: math, click, slide, rotate, drag"})
			return
		}

		cfg := loadProtectionConfig(repo)
		cfg.CaptchaEnabled = req.CaptchaEnabled
		if req.CaptchaType != "" {
			cfg.CaptchaType = req.CaptchaType
		}
		if req.CaptchaTimeout > 0 {
			cfg.CaptchaTimeout = req.CaptchaTimeout
		}
		cfg.ShieldEnabled = req.ShieldEnabled
		if req.ShieldDifficulty > 0 {
			cfg.ShieldDifficulty = req.ShieldDifficulty
		}

		if err := saveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "saved but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, captchaConfigResponse{
			CaptchaEnabled:   cfg.CaptchaEnabled,
			CaptchaType:      cfg.CaptchaType,
			CaptchaTimeout:   cfg.CaptchaTimeout,
			ShieldEnabled:    cfg.ShieldEnabled,
			ShieldDifficulty: cfg.ShieldDifficulty,
		})
	}
}

// TestCaptcha generates a test captcha preview (stub implementation).
func TestCaptcha(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := loadProtectionConfig(repo)
		c.JSON(200, map[string]any{
			"captcha_type": cfg.CaptchaType,
			"difficulty":   cfg.ShieldDifficulty,
			"preview":      "captcha-test-token-placeholder",
			"message":      "captcha test generated successfully",
		})
	}
}

// ── Shared helpers for loading/saving ProtectionConfig ──

func loadProtectionConfig(repo *repository.SystemSettingsRepo) store.ProtectionConfig {
	val, err := repo.Get("protection")
	if err != nil {
		return store.DefaultProtectionConfig()
	}
	var cfg store.ProtectionConfig
	if json.Unmarshal([]byte(val), &cfg) != nil {
		return store.DefaultProtectionConfig()
	}
	return cfg
}

func saveProtectionConfig(repo *repository.SystemSettingsRepo, cfg store.ProtectionConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return repo.Set("protection", string(data))
}
