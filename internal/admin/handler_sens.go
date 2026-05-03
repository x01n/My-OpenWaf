package admin

import (
	"context"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

type sensitivityRequest struct {
	CategorySensitivity map[string]string `json:"category_sensitivity"`
}

func normalizeSensitivityLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "off", "none":
		return "off"
	case "low":
		return "low"
	case "medium", "mid":
		return "mid"
	case "high":
		return "high"
	case "very_high", "very-high", "veryhigh":
		return "very_high"
	case "strict":
		return "strict"
	default:
		return ""
	}
}

func GetSensitivityConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id := c.Param("id")
		if id != "global" {
			if _, err := utils.ParseUint(id); err != nil {
				c.JSON(400, map[string]string{"error": "invalid id"})
				return
			}
		}
		cfg := loadProtectionConfig(repo)
		sens := cfg.GetCategorySensitivity()
		if sens == nil {
			sens = make(map[string]string)
		}
		c.JSON(200, sensitivityRequest{CategorySensitivity: sens})
	}
}

func UpdateSensitivityConfig(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id := c.Param("id")
		if id != "global" {
			if _, err := utils.ParseUint(id); err != nil {
				c.JSON(400, map[string]string{"error": "invalid id"})
				return
			}
		}
		var req sensitivityRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		normalized := make(map[string]string, len(req.CategorySensitivity))
		for cat, level := range req.CategorySensitivity {
			normalizedLevel := normalizeSensitivityLevel(level)
			if normalizedLevel == "" {
				c.JSON(400, map[string]string{"error": "invalid sensitivity level for " + cat + ": " + level})
				return
			}
			normalized[cat] = normalizedLevel
		}
		cfg := loadProtectionConfig(repo)
		cfg.SetCategorySensitivity(normalized)
		if err := saveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "saved but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, sensitivityRequest{CategorySensitivity: normalized})
	}
}
