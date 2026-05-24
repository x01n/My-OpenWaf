package system

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
)

func ListSettings(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		items, err := repo.All()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items})
	}
}

type createSettingBody struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func CreateSetting(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var body createSettingBody
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if body.Key == "" {
			c.JSON(400, map[string]string{"error": "key is required"})
			return
		}
		if err := repo.Set(body.Key, body.Value); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "key": body.Key, "value": body.Value})
			return
		}
		c.JSON(201, map[string]string{"key": body.Key, "value": body.Value})
	}
}

func GetSetting(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		key := c.Param("key")
		val, err := repo.Get(key)
		if err != nil {
			c.JSON(404, map[string]string{"error": "setting not found"})
			return
		}
		c.JSON(200, map[string]string{"key": key, "value": val})
	}
}

type settingBody struct {
	Value string `json:"value"`
}

func SetSetting(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		key := c.Param("key")
		var body settingBody
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.Set(key, body.Value); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "key": key, "value": body.Value})
			return
		}
		c.JSON(200, map[string]string{"key": key, "value": body.Value})
	}
}

func DeleteSetting(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		key := c.Param("key")
		if err := repo.Delete(key); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}

func ReloadSnapshot(reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]string{"status": "ok"})
	}
}

func HealthCheck() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, map[string]string{"status": "ok"})
	}
}

