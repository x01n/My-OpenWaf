package admin

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

type sensitivityRequest struct {
	CategorySensitivity map[string]string `json:"category_sensitivity"`
}

func GetSensitivityConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		_, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
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
		_, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		var req sensitivityRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		validLevels := map[string]bool{"off": true, "low": true, "medium": true, "high": true, "very_high": true}
		for cat, level := range req.CategorySensitivity {
			if !validLevels[level] {
				c.JSON(400, map[string]string{"error": "invalid sensitivity level for " + cat + ": " + level})
				return
			}
		}
		cfg := loadProtectionConfig(repo)
		cfg.SetCategorySensitivity(req.CategorySensitivity)
		if err := saveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "saved but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, sensitivityRequest{CategorySensitivity: req.CategorySensitivity})
	}
}
