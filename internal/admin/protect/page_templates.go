package protect

import (
	"context"
	"encoding/json"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/pageconfig"
)

const (
	settingKeyCaptchaPage   = "page_template_captcha"
	settingKeyChallengePage = "page_template_challenge"
	settingKeyBlockPage     = "page_template_block"
)

// GetPageTemplates returns all page template configurations.
func GetPageTemplates(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		captchaCfg := loadCaptchaPageConfig(repo)
		challengeCfg := loadChallengePageConfig(repo)
		blockCfg := loadBlockPageConfig(repo)

		c.JSON(200, map[string]any{
			"captcha":   captchaCfg,
			"challenge": challengeCfg,
			"block":     blockCfg,
		})
	}
}

// GetPageTemplate returns a specific page template configuration by type.
func GetPageTemplate(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		pageType := c.Param("type")
		switch pageType {
		case "captcha":
			c.JSON(200, loadCaptchaPageConfig(repo))
		case "challenge":
			c.JSON(200, loadChallengePageConfig(repo))
		case "block":
			c.JSON(200, loadBlockPageConfig(repo))
		default:
			c.JSON(400, map[string]string{"error": "invalid page type, must be one of: captcha, challenge, block"})
		}
	}
}

// UpdatePageTemplate updates a specific page template configuration.
func UpdatePageTemplate(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		pageType := c.Param("type")
		body := c.Request.Body()

		var settingKey string
		switch pageType {
		case "captcha":
			var cfg pageconfig.CaptchaPageConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				c.JSON(400, map[string]string{"error": "invalid request body: " + err.Error()})
				return
			}
			cfg.CustomCSS = sanitizePageCSS(cfg.CustomCSS)
			settingKey = settingKeyCaptchaPage
		case "challenge":
			var cfg pageconfig.ChallengePageConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				c.JSON(400, map[string]string{"error": "invalid request body: " + err.Error()})
				return
			}
			cfg.CustomCSS = sanitizePageCSS(cfg.CustomCSS)
			settingKey = settingKeyChallengePage
		case "block":
			var cfg pageconfig.BlockPageConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				c.JSON(400, map[string]string{"error": "invalid request body: " + err.Error()})
				return
			}
			cfg.CustomCSS = sanitizePageCSS(cfg.CustomCSS)
			settingKey = settingKeyBlockPage
		default:
			c.JSON(400, map[string]string{"error": "invalid page type, must be one of: captcha, challenge, block"})
			return
		}

		if err := repo.Set(settingKey, string(body)); err != nil {
			c.JSON(500, map[string]string{"error": "failed to save page template: " + err.Error()})
			return
		}

		if reload != nil {
			_ = reload()
		}

		c.JSON(200, map[string]string{"status": "ok"})
	}
}

// ResetPageTemplate resets a page template to defaults.
func ResetPageTemplate(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		pageType := c.Param("type")
		var settingKey string
		switch pageType {
		case "captcha":
			settingKey = settingKeyCaptchaPage
		case "challenge":
			settingKey = settingKeyChallengePage
		case "block":
			settingKey = settingKeyBlockPage
		default:
			c.JSON(400, map[string]string{"error": "invalid page type, must be one of: captcha, challenge, block"})
			return
		}

		if err := repo.Delete(settingKey); err != nil {
			c.JSON(500, map[string]string{"error": "failed to reset page template: " + err.Error()})
			return
		}

		if reload != nil {
			_ = reload()
		}

		c.JSON(200, map[string]string{"status": "ok"})
	}
}

// PreviewPageTemplate renders a preview of the page template.
func PreviewPageTemplate(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		pageType := c.Param("type")
		switch pageType {
		case "captcha":
			cfg := loadCaptchaPageConfig(repo)
			c.JSON(200, map[string]any{"config": cfg, "preview_note": "captcha preview requires live captcha generation"})
		case "challenge":
			cfg := loadChallengePageConfig(repo)
			c.JSON(200, map[string]any{"config": cfg, "preview_note": "challenge preview requires token generation"})
		case "block":
			cfg := loadBlockPageConfig(repo)
			c.JSON(200, map[string]any{"config": cfg, "preview_note": "block page preview"})
		default:
			c.JSON(400, map[string]string{"error": "invalid page type"})
		}
	}
}

func loadCaptchaPageConfig(repo *repository.SystemSettingsRepo) pageconfig.CaptchaPageConfig {
	cfg := pageconfig.DefaultCaptchaPageConfig()
	val, err := repo.Get(settingKeyCaptchaPage)
	if err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &cfg)
	}
	return cfg
}

func loadChallengePageConfig(repo *repository.SystemSettingsRepo) pageconfig.ChallengePageConfig {
	cfg := pageconfig.DefaultChallengePageConfig()
	val, err := repo.Get(settingKeyChallengePage)
	if err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &cfg)
	}
	return cfg
}

func loadBlockPageConfig(repo *repository.SystemSettingsRepo) pageconfig.BlockPageConfig {
	cfg := pageconfig.DefaultBlockPageConfig()
	val, err := repo.Get(settingKeyBlockPage)
	if err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), &cfg)
	}
	return cfg
}

func sanitizePageCSS(css string) string {
	if css == "" {
		return ""
	}
	dangerous := []string{"expression(", "javascript:", "@import", "behavior:", "binding:"}
	lower := css
	for _, pattern := range dangerous {
		for {
			idx := indexCaseInsensitive(lower, pattern)
			if idx == -1 {
				break
			}
			css = css[:idx] + css[idx+len(pattern):]
			lower = css
		}
	}
	return css
}

func indexCaseInsensitive(s, substr string) int {
	sLower := make([]byte, len(s))
	subLower := make([]byte, len(substr))
	for i := range s {
		if s[i] >= 'A' && s[i] <= 'Z' {
			sLower[i] = s[i] + 32
		} else {
			sLower[i] = s[i]
		}
	}
	for i := range substr {
		if substr[i] >= 'A' && substr[i] <= 'Z' {
			subLower[i] = substr[i] + 32
		} else {
			subLower[i] = substr[i]
		}
	}
	for i := 0; i <= len(sLower)-len(subLower); i++ {
		match := true
		for j := range subLower {
			if sLower[i+j] != subLower[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
