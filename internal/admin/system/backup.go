package system

import (
	"context"
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
		for i := range data.SystemSettings {
			data.SystemSettings[i] = redactSettingItem(data.SystemSettings[i])
		}
		filename := fmt.Sprintf("owaf-backup-%s.json", time.Now().Format("20060102-150405"))
		c.Response.Header.Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
		c.JSON(200, data)
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
 * @param db     数据库句柄。
 * @param reload snapshot 重建回调。
 * @return Hertz 处理器。
 */
func ImportBackup(db *gorm.DB, reload func() error) app.HandlerFunc {
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

		if err := store.ImportBackup(db, &req.Data, req.ReplaceMode); err != nil {
			slog.Error("[admin] backup import failed", "error", err)
			c.JSON(500, map[string]string{"error": "import failed, check server logs for details"})
			return
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
