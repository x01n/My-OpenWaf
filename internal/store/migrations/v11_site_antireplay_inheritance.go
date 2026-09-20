package migrations

import (
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const siteAntiReplayInheritanceMigrationKey = "migration_v11_site_antireplay_inheritance"

// V11MigrateSiteAntiReplayInheritance converts the historical false value into
// the nullable inheritance marker. The marker preserves explicit false overrides
// created after this migration.
func V11MigrateSiteAntiReplayInheritance(db *gorm.DB) error {
	if !db.Migrator().HasTable(&siteAntiReplayInheritanceTable{}) ||
		!db.Migrator().HasTable(&migrationSystemSetting{}) ||
		!db.Migrator().HasColumn(&siteAntiReplayInheritanceTable{}, "anti_replay_enabled") {
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		var marker migrationSystemSetting
		markerQuery := tx.Where(clause.Eq{
			Column: clause.Column{Name: "key"},
			Value:  siteAntiReplayInheritanceMigrationKey,
		}).Limit(1).Find(&marker)
		if markerQuery.Error != nil {
			return fmt.Errorf("failed to load site anti-replay inheritance migration marker: %w", markerQuery.Error)
		}
		if markerQuery.RowsAffected > 0 {
			return nil
		}

		if err := tx.Model(&siteAntiReplayInheritanceTable{}).
			Where("anti_replay_enabled = ?", false).
			UpdateColumn("anti_replay_enabled", nil).Error; err != nil {
			return fmt.Errorf("failed to migrate sites.anti_replay_enabled inheritance values: %w", err)
		}

		if err := tx.Create(&migrationSystemSetting{
			Key:   siteAntiReplayInheritanceMigrationKey,
			Value: "true",
		}).Error; err != nil {
			return fmt.Errorf("failed to store site anti-replay inheritance migration marker: %w", err)
		}
		return nil
	})
}

type siteAntiReplayInheritanceTable struct {
	AntiReplayEnabled *bool `gorm:"column:anti_replay_enabled"`
}

func (siteAntiReplayInheritanceTable) TableName() string {
	return "sites"
}
