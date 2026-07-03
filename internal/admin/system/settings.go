package system

import (
	"context"
	"encoding/json"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

var protectedSettingKeys = map[string]string{
	"protection":                        "/api/v1/protection-settings",
	"bot_settings":                      "/api/v1/bot-settings/update",
	"drop_policy":                       "/api/v1/drop-policy/update",
	store.SettingKeyRedisConfig:         "/api/v1/redis-config",
	store.SettingKeyHPKP:                "/api/v1/protection-settings",
	store.SettingKeyHPKPValue:           "/api/v1/protection-settings",
	store.SettingKeyHPKPReportOnly:      "/api/v1/protection-settings",
	store.SettingKeyHPKPReportOnlyValue: "/api/v1/protection-settings",
	settingKeyNetwork:                   "/api/v1/network-config",
	settingKeyHTTP2:                     "/api/v1/http2-config",
	settingKeyLog:                       "/api/v1/log-config",
	settingKeyTLSDefault:                "/api/v1/tls-config",
	store.SettingKeyACMEConfig:          "/api/v1/certificates/acme/config",
}

func rejectProtectedSettingWrite(c *app.RequestContext, key string) bool {
	if endpoint, ok := protectedSettingKeys[key]; ok {
		c.JSON(400, map[string]string{
			"error":    "setting is managed by a dedicated endpoint",
			"key":      key,
			"endpoint": endpoint,
		})
		return true
	}
	return false
}

func redactSettingValue(key string, value string) string {
	if key != store.SettingKeyRedisConfig || value == "" {
		return value
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(value), &payload); err != nil {
		return "[redacted]"
	}
	if password, ok := payload["password"].(string); ok && password != "" {
		payload["password"] = "[redacted]"
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "[redacted]"
	}
	return string(data)
}

func redactSettingItem(item store.SystemSettings) store.SystemSettings {
	item.Value = redactSettingValue(item.Key, item.Value)
	return item
}

func ListSettings(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		items, err := repo.All()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		for i := range items {
			items[i] = redactSettingItem(items[i])
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
		if rejectProtectedSettingWrite(c, body.Key) {
			return
		}
		if err := repo.Set(body.Key, body.Value); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "key": body.Key})
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
		val = redactSettingValue(key, val)
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
		if rejectProtectedSettingWrite(c, key) {
			return
		}
		if err := repo.Set(key, body.Value); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "key": key})
			return
		}
		c.JSON(200, map[string]string{"key": key, "value": body.Value})
	}
}

func DeleteSetting(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		key := c.Param("key")
		if rejectProtectedSettingWrite(c, key) {
			return
		}
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
