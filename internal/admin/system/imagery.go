package system

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/imagery"
	"My-OpenWaf/internal/store/repository"
)

// ImageTransformConfigResponse 是图像转换配置的响应体。
//
// 直接复用 imagery.Config 的 JSON 结构，避免在这一层再造一份字段定义
// （前端与数据面读到的必须是同一组键）。
type ImageTransformConfigResponse = imagery.Config

// imagerySettingKey 是图像转换配置在 protectedSettingKeys 中的键名别名。
//
// 单独取个别名是为了让 settings.go 的白名单引用不直接依赖 imagery 包名，
// 同时保证两边永远指向同一个键。
const imagerySettingKey = imagery.SettingKey

// GetImageTransformConfig 获取图像转换全局配置。
//
// @param repo system_settings 仓储。
// @return Hertz 处理函数。
func GetImageTransformConfig(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		cfg := loadImageTransformConfig(repo)
		c.JSON(200, cfg)
	}
}

// UpdateImageTransformConfig 更新图像转换全局配置。
//
// 遵循项目既有的「局部合并保存」惯例：请求体中的字段用指针表达「是否参与本次
// 更新」，未出现的字段保留既有值，因此快捷配置页不会把未展示的字段清成零值。
//
// @param repo system_settings 仓储。
// @param reload 配置重载函数。
// @return Hertz 处理函数。
func UpdateImageTransformConfig(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			Enabled        *bool   `json:"enabled"`
			AdaptiveWebP   *bool   `json:"adaptive_webp"`
			MaxPixels      *int64  `json:"max_pixels"`
			MaxSide        *int    `json:"max_side"`
			MaxBytes       *int64  `json:"max_bytes"`
			TimeoutMS      *int    `json:"timeout_ms"`
			Concurrency    *int    `json:"concurrency"`
			DefaultQuality *int    `json:"default_quality"`
			Reset          *string `json:"reset"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}

		cfg := loadImageTransformConfig(repo)
		if req.Reset != nil && strings.EqualFold(strings.TrimSpace(*req.Reset), "true") {
			cfg = imagery.DefaultConfig()
		}
		if req.Enabled != nil {
			cfg.Enabled = *req.Enabled
		}
		if req.AdaptiveWebP != nil {
			cfg.AdaptiveWebP = *req.AdaptiveWebP
		}
		if req.MaxPixels != nil {
			cfg.MaxPixels = *req.MaxPixels
		}
		if req.MaxSide != nil {
			cfg.MaxSide = *req.MaxSide
		}
		if req.MaxBytes != nil {
			cfg.MaxBytes = *req.MaxBytes
		}
		if req.TimeoutMS != nil {
			cfg.TimeoutMS = *req.TimeoutMS
		}
		if req.Concurrency != nil {
			cfg.Concurrency = *req.Concurrency
		}
		if req.DefaultQuality != nil {
			cfg.DefaultQuality = *req.DefaultQuality
		}
		cfg = cfg.Normalize()

		data, err := json.Marshal(cfg)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.Set(imagery.SettingKey, string(data)); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]interface{}{"error": "config applied but reload failed: " + err.Error(), "config": cfg})
			return
		}
		c.JSON(200, cfg)
	}
}

// loadImageTransformConfig 读取并规范化图像转换配置。
//
// 配置缺失或损坏时返回默认（关闭）配置：与快照构建期的处置保持一致，
// 即一个可选能力的配置问题不应让管理端接口报错。
//
// @param repo system_settings 仓储。
// @return 规范化后的配置。
func loadImageTransformConfig(repo *repository.SystemSettingsRepo) imagery.Config {
	raw, err := repo.Get(imagery.SettingKey)
	if err != nil || raw == "" {
		return imagery.DefaultConfig()
	}
	cfg, err := imagery.LoadConfig(raw)
	if err != nil {
		return imagery.DefaultConfig()
	}
	return cfg
}
