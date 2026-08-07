package protect

import (
	"context"
	"encoding/json"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/challenge"
	"My-OpenWaf/internal/waf/pageconfig"
	wafpages "My-OpenWaf/internal/waf/pages"
)

const (
	settingKeyCaptchaPage   = pageconfig.SettingKeyCaptchaPage
	settingKeyChallengePage = pageconfig.SettingKeyChallengePage
	settingKeyBlockPage     = pageconfig.SettingKeyBlockPage
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

		// 必须持久化清洗后的配置：直接存原始 body 会让 sanitizePageCSS 形同虚设，
		// expression()/javascript: 等载荷将原样渲染进挑战页与拦截页。
		var (
			settingKey string
			sanitized  []byte
		)
		switch pageType {
		case "captcha":
			var cfg pageconfig.CaptchaPageConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				c.JSON(400, map[string]string{"error": "invalid request body: " + err.Error()})
				return
			}
			cfg.CustomCSS = sanitizePageCSS(cfg.CustomCSS)
			settingKey = settingKeyCaptchaPage
			sanitized, _ = json.Marshal(&cfg)
		case "challenge":
			var cfg pageconfig.ChallengePageConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				c.JSON(400, map[string]string{"error": "invalid request body: " + err.Error()})
				return
			}
			cfg.CustomCSS = sanitizePageCSS(cfg.CustomCSS)
			settingKey = settingKeyChallengePage
			sanitized, _ = json.Marshal(&cfg)
		case "block":
			var cfg pageconfig.BlockPageConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				c.JSON(400, map[string]string{"error": "invalid request body: " + err.Error()})
				return
			}
			cfg.CustomCSS = sanitizePageCSS(cfg.CustomCSS)
			settingKey = settingKeyBlockPage
			sanitized, _ = json.Marshal(&cfg)
		default:
			c.JSON(400, map[string]string{"error": "invalid page type, must be one of: captcha, challenge, block"})
			return
		}

		if err := repo.Set(settingKey, string(sanitized)); err != nil {
			c.JSON(500, map[string]string{"error": "failed to save page template: " + err.Error()})
			return
		}

		if reload != nil {
			if err := reload(); err != nil {
				c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
				return
			}
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
			if err := reload(); err != nil {
				c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
				return
			}
		}

		c.JSON(200, map[string]string{"status": "ok"})
	}
}

// PreviewPageTemplate renders a preview of the page template.
func PreviewPageTemplate(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		pageType := c.Param("type")
		var html []byte
		switch pageType {
		case "captcha":
			html = challenge.RenderCaptchaPreview(loadCaptchaPageConfig(repo))
		case "challenge":
			html = wafpages.RenderChallengePreview(loadChallengePageConfig(repo))
		case "block":
			html = wafpages.RenderBlockPreview(loadBlockPageConfig(repo))
		default:
			c.JSON(400, map[string]string{"error": "invalid page type"})
			return
		}
		c.Data(200, "text/html; charset=utf-8", html)
	}
}

// PreviewPageTemplateDraft renders a preview using the submitted draft config without persisting it.
func PreviewPageTemplateDraft(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		pageType := c.Param("type")
		body := c.Request.Body()
		var html []byte
		switch pageType {
		case "captcha":
			var cfg pageconfig.CaptchaPageConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				c.JSON(400, map[string]string{"error": "invalid request body: " + err.Error()})
				return
			}
			cfg.CustomCSS = sanitizePageCSS(cfg.CustomCSS)
			html = challenge.RenderCaptchaPreview(cfg)
		case "challenge":
			var cfg pageconfig.ChallengePageConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				c.JSON(400, map[string]string{"error": "invalid request body: " + err.Error()})
				return
			}
			cfg.CustomCSS = sanitizePageCSS(cfg.CustomCSS)
			html = wafpages.RenderChallengePreview(cfg)
		case "block":
			var cfg pageconfig.BlockPageConfig
			if err := json.Unmarshal(body, &cfg); err != nil {
				c.JSON(400, map[string]string{"error": "invalid request body: " + err.Error()})
				return
			}
			cfg.CustomCSS = sanitizePageCSS(cfg.CustomCSS)
			html = wafpages.RenderBlockPreview(cfg)
		default:
			c.JSON(400, map[string]string{"error": "invalid page type"})
			return
		}
		c.Data(200, "text/html; charset=utf-8", html)
	}
}

func loadCaptchaPageConfig(repo *repository.SystemSettingsRepo) pageconfig.CaptchaPageConfig {
	val, _ := repo.Get(settingKeyCaptchaPage)
	return pageconfig.ParseCaptchaPageConfig(val)
}

func loadChallengePageConfig(repo *repository.SystemSettingsRepo) pageconfig.ChallengePageConfig {
	val, _ := repo.Get(settingKeyChallengePage)
	return pageconfig.ParseChallengePageConfig(val)
}

func loadBlockPageConfig(repo *repository.SystemSettingsRepo) pageconfig.BlockPageConfig {
	val, _ := repo.Get(settingKeyBlockPage)
	return pageconfig.ParseBlockPageConfig(val)
}

func sanitizePageCSS(css string) string {
	return pageconfig.SanitizeCSS(css)
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
