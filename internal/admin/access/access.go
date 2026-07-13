// Package access 实现站点访问控制的 Admin API 处理器。
package access

import (
	"context"
	"errors"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

// defaultSessionTTL 会话默认有效期（秒），24 小时。
const defaultSessionTTL = 86400

// bcryptCost 共享密码与用户密码的 bcrypt 哈希强度。
const bcryptCost = 10

// SaveAccessConfigReq 保存站点访问控制配置的请求体。
type SaveAccessConfigReq struct {
	Enabled bool `json:"enabled"`
	// SharedPassword 共享密码明文，非空时以 bcrypt 哈希后覆盖存储；空字符串表示保持原密码不变。
	SharedPassword string `json:"shared_password,omitempty"`
	// ClearSharedPassword 为 true 时清空已保存的共享密码。
	ClearSharedPassword bool `json:"clear_shared_password,omitempty"`
	SessionTTL          int  `json:"session_ttl"`
}

// accessConfigResp 站点访问控制配置的脱敏响应体，不返回共享密码哈希。
type accessConfigResp struct {
	SiteID            uint `json:"site_id"`
	Enabled           bool `json:"enabled"`
	SharedPasswordSet bool `json:"shared_password_set"`
	SessionTTL        int  `json:"session_ttl"`
}

/**
 * newAccessConfigResp 将存储模型转换为脱敏响应体。
 *
 * @param cfg 站点访问控制配置存储模型。
 * @return 脱敏后的响应体，仅暴露共享密码是否已设置。
 */
func newAccessConfigResp(cfg *store.SiteAccessConfig) accessConfigResp {
	return accessConfigResp{
		SiteID:            cfg.SiteID,
		Enabled:           cfg.Enabled,
		SharedPasswordSet: cfg.SharedPasswordHash != "",
		SessionTTL:        cfg.SessionTTL,
	}
}

/**
 * GetAccessConfig 返回指定站点的访问控制配置。
 * 站点尚未配置时返回默认关闭态配置。
 *
 * @param repo 访问控制仓库。
 * @return Hertz 处理器。
 */
func GetAccessConfig(repo *repository.AccessControlRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		cfg, err := repo.GetSiteAccessConfig(siteID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(200, newAccessConfigResp(&store.SiteAccessConfig{SiteID: siteID, SessionTTL: defaultSessionTTL}))
				return
			}
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, newAccessConfigResp(cfg))
	}
}

/**
 * SaveAccessConfig 创建或更新指定站点的访问控制配置。
 * 共享密码以 bcrypt（cost 10）哈希后存储，配置变更后触发 reload 重建 snapshot。
 *
 * @param repo   访问控制仓库。
 * @param reload snapshot 重建回调。
 * @return Hertz 处理器。
 */
func SaveAccessConfig(repo *repository.AccessControlRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		var req SaveAccessConfigReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		// 读取既有配置以保留未变更的字段（如共享密码哈希）。
		cfg, err := repo.GetSiteAccessConfig(siteID)
		if err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(500, map[string]string{"error": err.Error()})
				return
			}
			cfg = &store.SiteAccessConfig{SiteID: siteID}
		}

		cfg.Enabled = req.Enabled
		cfg.SessionTTL = req.SessionTTL
		if cfg.SessionTTL <= 0 {
			cfg.SessionTTL = defaultSessionTTL
		}

		switch {
		case req.ClearSharedPassword:
			cfg.SharedPasswordHash = ""
		case strings.TrimSpace(req.SharedPassword) != "":
			hash, herr := bcrypt.GenerateFromPassword([]byte(req.SharedPassword), bcryptCost)
			if herr != nil {
				c.JSON(500, map[string]string{"error": "failed to hash shared password"})
				return
			}
			cfg.SharedPasswordHash = string(hash)
		}

		if err := repo.SaveSiteAccessConfig(cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, newAccessConfigResp(cfg))
	}
}
