package system

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
)

/**
 * ExportBackup 导出全部配置为 JSON 备份文件。
 *
 * 触发浏览器下载（Content-Disposition: attachment）。包含站点、证书、规则、
 * 策略、IP 名单、威胁情报订阅、访问控制、系统设置等配置类数据，不含运行日志、
 * 会话和管理员凭证。
 *
 * @param db 数据库句柄。
 * @return Hertz 处理器。
 */
func ExportBackup(db *gorm.DB) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		data, err := store.ExportBackup(db)
		if err != nil {
			slog.Error("[admin] backup export failed", "error", err)
			c.JSON(500, map[string]string{"error": "export failed"})
			return
		}
		data.SystemSettings = filterInternalSettingItems(data.SystemSettings)
		for i := range data.SystemSettings {
			data.SystemSettings[i] = redactSettingItem(data.SystemSettings[i])
		}
		backupMaskThreatIntelFeeds(data.ThreatIntelFeeds)
		backupMaskOAuthClientSecrets(data.AccessProviders)
		filename := fmt.Sprintf("owaf-backup-%s.json", time.Now().Format("20060102-150405"))
		c.Response.Header.Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
		c.JSON(200, data)
	}
}

// backupMaskThreatIntelFeeds 遮蔽备份中的威胁情报认证头值：订阅源拉取令牌
// 属于敏感凭据，不应随备份文件明文导出。maskAuthHeaderValue 返回的是掩码值而非
// 空串（长度 >= 5 的保留前 4 位加 "***"，更短的非空值整体替换为 "***"，空值保持
// 为空），该掩码值随导入侧 upsertBatch 的 OnConflict{UpdateAll} 覆盖目标库原凭据
// （字段无 default 标签，不触发 restoreZeroValuedDefaults 回写），语义是
// "凭据不随备份走、导入后需重新录入"，故无需在导入侧再做特殊处理。
func backupMaskThreatIntelFeeds(feeds []store.ThreatIntelFeed) {
	for i := range feeds {
		feeds[i].AuthHeaderValue = maskAuthHeaderValue(feeds[i].AuthHeaderValue)
	}
}

// backupMaskOAuthClientSecrets 遮蔽备份中 OAuth/OIDC 提供方的 client_secret。
// 落库形态 Config 是 JSON 字符串，其中 client_secret 为 AES-256-GCM 密文
// （internal/admin/access 的 encryptClientSecret 用 JWT 主密钥经 HKDF 派生密钥），
// 换机导入不可解密，随备份导出既无用处又扩大泄密面。
// 这里把 client_secret 替换为掩码值（非空值保留前 4 位 + "***"，空值保持为空），
// 掩码针对 base64 密文，取前 4 位不泄露任何明文内容；形态与威胁情报认证头遮蔽
// 保持一致。掩码值随导入侧 upsertBatch 的 OnConflict{UpdateAll} 写入目标库，
// 成为无法解密的坏密文，任何后续 OAuth 令牌换取都会失败，管理员在 UI 重新录入
// 密钥后恢复——凭据不随备份走。解析失败的 Config 保持原样，不改变既有导出行为。
func backupMaskOAuthClientSecrets(providers []store.AccessProvider) {
	for i := range providers {
		if providers[i].Config == "" {
			continue
		}
		var cfg store.OAuthProviderConfig
		if json.Unmarshal([]byte(providers[i].Config), &cfg) != nil {
			continue // 配置 JSON 解析失败时保持原样，避免破坏既有备份行为
		}
		cfg.ClientSecret = maskAuthHeaderValue(cfg.ClientSecret)
		masked, err := json.Marshal(&cfg)
		if err != nil {
			continue
		}
		providers[i].Config = string(masked)
	}
}

/**
 * ImportBackupReq 是恢复配置的请求体。
 */
type ImportBackupReq struct {
	Data        store.BackupData `json:"data"`
	ReplaceMode bool             `json:"replace_mode"`
}

/**
 * ImportBackup 从上传的备份 JSON 恢复配置。
 *
 * 高危操作，仅 admin 角色可用。整体在事务中执行，失败回滚。恢复成功后触发
 * reload 重建 snapshot。replace_mode=true 时先清空配置表再导入（整体替换）。
 *
 * @param db          数据库句柄。
 * @param reload      snapshot 重建回调。
 * @param invalidates 备份写入后需要立即失效的进程内只读缓存。备份导入可能改写
 *                    SiteAccessConfig / AccessProvider / AccessUser / AccessPathRule，
 *                    而已登录用户持有的访问控制会话存放在数据面的
 *                    dataplane.globalAccessSessionStore（内存/Redis，与库表无关）。
 *                    接入点经核实的接线方式为：在 router.go 现有 invalidates 回调
 *                    （r.CVERule.InvalidateCanonicalSnapshot /
 *                    detect.InvalidateOWASPReadSnapshots，router.go:356-358）之后
 *                    追加一个会话吊销回调。当前 dataplane 包没有暴露"清空/吊销
 *                    全部会话"的入口（仅 CleanExpired，access_control.go:43，只清
 *                    过期不吊销；accessgate.SessionStore 接口 gate.go:65 无
 *                    ClearAll 方法），因此本文件无法在不新造会话管理逻辑的前提
 *                    下完成该接线，待 dataplane/accessgate 侧补一个全量吊销入口后
 *                    在此回调内调用。
 * @return Hertz 处理器。
 */
func ImportBackup(db *gorm.DB, reload func() error, invalidates ...func()) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req ImportBackupReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid backup json: " + err.Error()})
			return
		}
		if req.Data.Version == 0 {
			c.JSON(400, map[string]string{"error": "missing or invalid backup version"})
			return
		}
		if req.Data.Version > store.BackupVersion {
			c.JSON(400, map[string]string{"error": fmt.Sprintf("unsupported backup version %d (max supported %d)", req.Data.Version, store.BackupVersion)})
			return
		}

		req.Data.SystemSettings = filterInternalSettingItems(req.Data.SystemSettings)
		if err := store.ImportBackup(db, &req.Data, req.ReplaceMode); err != nil {
			if errors.Is(err, store.ErrInvalidBackupJSPlugin) ||
				errors.Is(err, store.ErrInvalidBackupProtectionConfig) ||
				errors.Is(err, store.ErrInvalidBackupRuleConfig) {
				c.JSON(400, map[string]string{"error": err.Error()})
				return
			}
			slog.Error("[admin] backup import failed", "error", err)
			c.JSON(500, map[string]string{"error": "import failed, check server logs for details"})
			return
		}
		for i := range invalidates {
			if invalidates[i] != nil {
				invalidates[i]()
			}
		}

		if err := reload(); err != nil {
			slog.Error("[admin] backup imported but reload failed", "error", err)
			c.JSON(500, map[string]string{"error": "backup imported but reload failed, check server logs"})
			return
		}

		c.JSON(200, map[string]any{
			"status":       "restored",
			"replace_mode": req.ReplaceMode,
			"sites":        len(req.Data.Sites),
			"certificates": len(req.Data.Certificates),
			"rules":        len(req.Data.Rules),
			"ip_entries":   len(req.Data.IPListEntries),
		})
	}
}
