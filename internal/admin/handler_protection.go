package admin

import (
	"context"
	"encoding/json"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

func GetProtectionSettings(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		val, err := repo.Get("protection")
		if err != nil {
			c.JSON(200, store.DefaultProtectionConfig())
			return
		}
		var cfg store.ProtectionConfig
		if json.Unmarshal([]byte(val), &cfg) != nil {
			c.JSON(200, store.DefaultProtectionConfig())
			return
		}
		c.JSON(200, cfg)
	}
}

func PutProtectionSettings(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var cfg store.ProtectionConfig
		if err := c.BindJSON(&cfg); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
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
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "saved but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, cfg)
	}
}
