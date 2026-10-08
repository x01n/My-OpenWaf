package migrations

import (
	"fmt"

	"gorm.io/gorm"
)

/**
 * V15MigrateAPIKeyOwner 把历史 API 令牌回填到首个 admin 账号名下。
 *
 * 令牌模型改为必须归属某个 AdminAccount 后，旧库里的令牌 user_id 为 0。
 * 这些令牌在中间件里会因「归属账号不存在」被拒绝 —— 若不回填，升级后
 * 所有既有令牌会静默失效。回填目标取 role='admin' 的最小 id 账号：
 * 令牌在旧模型下本就等同 admin 权限，把这一语义映射到真实账号上最贴近
 * 原有行为，且管理员随后可在界面上重建令牌。
 *
 * 只在 user_id = 0 的行上执行，天然幂等；无 admin 账号时不回填，
 * 让这些令牌保持失效状态（此时系统尚未完成初始化，也没有可以登录的人）。
 */
func V15MigrateAPIKeyOwner(db *gorm.DB) error {
	if db == nil || !db.Migrator().HasTable("admin_api_keys") || !db.Migrator().HasTable("admin_accounts") {
		return nil
	}
	if !db.Migrator().HasColumn("admin_api_keys", "user_id") {
		return nil
	}

	var ownerID uint
	row := db.Table("admin_accounts").
		Select("id").
		Where("role = ? AND deleted_at IS NULL", "admin").
		Order("id ASC").
		Limit(1).
		Row()
	if err := row.Scan(&ownerID); err != nil {
		// 没有 admin 账号：无可回填目标，保持现状。
		return nil
	}
	if ownerID == 0 {
		return nil
	}

	if err := db.Exec(
		"UPDATE admin_api_keys SET user_id = ? WHERE user_id = 0 OR user_id IS NULL",
		ownerID,
	).Error; err != nil {
		return fmt.Errorf("backfill admin_api_keys.user_id: %w", err)
	}
	return nil
}
