package migrations

import (
	"fmt"

	"gorm.io/gorm"
)

// V4MigrateRecordedResourceQueryString expands the recorded resource identity
// from method+host+path to method+host+path+query_string.
func V4MigrateRecordedResourceQueryString(db *gorm.DB) error {
	if !db.Migrator().HasTable(&recordedResourceTable{}) {
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if !tx.Migrator().HasColumn(&recordedResourceTable{}, "QueryString") {
			if err := tx.Migrator().AddColumn(&recordedResourceTable{}, "QueryString"); err != nil {
				return fmt.Errorf("failed to add recorded_resources.query_string: %w", err)
			}
		}

		if err := tx.Exec("UPDATE recorded_resources SET query_string = '' WHERE query_string IS NULL").Error; err != nil {
			return fmt.Errorf("failed to backfill recorded_resources.query_string: %w", err)
		}

		if tx.Migrator().HasIndex(&recordedResourceTable{}, "ux_recorded_res_key") {
			if err := tx.Migrator().DropIndex(&recordedResourceTable{}, "ux_recorded_res_key"); err != nil {
				return fmt.Errorf("failed to drop recorded resource index: %w", err)
			}
		}
		if err := tx.Migrator().CreateIndex(&recordedResourceTable{}, "ux_recorded_res_key"); err != nil {
			return fmt.Errorf("failed to recreate recorded resource index: %w", err)
		}

		return nil
	})
}

type recordedResourceTable struct {
	SiteID      uint   `gorm:"column:site_id;not null;uniqueIndex:ux_recorded_res_key"`
	Method      string `gorm:"column:method;size:16;uniqueIndex:ux_recorded_res_key"`
	Host        string `gorm:"column:host;size:255;uniqueIndex:ux_recorded_res_key"`
	Path        string `gorm:"column:path;size:2048;uniqueIndex:ux_recorded_res_key"`
	QueryString string `gorm:"column:query_string;size:2048;uniqueIndex:ux_recorded_res_key"`
}

func (recordedResourceTable) TableName() string {
	return "recorded_resources"
}
