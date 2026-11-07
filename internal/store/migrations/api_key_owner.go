package migrations

import (
	"fmt"

	"gorm.io/gorm"
)
func V15MigrateAPIKeyOwner(db *gorm.DB) error {
	if db == nil || !db.Migrator().HasTable("admin_api_keys") || !db.Migrator().HasTable("admin_accounts") {
		return nil
	}
	if !db.Migrator().HasColumn("admin_api_keys", "user_id") {
		return nil
	}

	var ownerID uint
	if err := db.Table("admin_accounts").
		Select("id").
		Where("role = ?", "admin").
		Order("id ASC").
		Limit(1).
		Scan(&ownerID).Error; err != nil {
		return fmt.Errorf("select admin account for api key backfill: %w", err)
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
