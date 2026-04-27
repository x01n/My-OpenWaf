package store

import (
	"My-OpenWaf/internal/store/migrations"

	"gorm.io/gorm"
)

// AutoMigrate applies schema for all domain models.
func AutoMigrate(db *gorm.DB) error {
	// Run data migrations first
	if err := migrations.V2MigrateSingleSite(db); err != nil {
		return err
	}

	// Then apply schema migrations
	return db.AutoMigrate(
		&Certificate{},
		&Policy{},
		&Rule{},
		&Site{},
		&SystemSettings{},
		&AdminAPIKey{},
		&ConfigRevision{},
		&AdminAccount{},
		&RefreshToken{},
		&SecurityEvent{},
		&AccessLog{},
		&IPListEntry{},
		&TokenBlacklist{},
		&LoginAttempt{},
		&ActiveSession{},
		&DropEvent{},
		&BotScoreLog{},
		&FingerprintRecord{},
		&CVERuleRecord{},
		&CVESyncLog{},
	)
}

func BumpRevision(db *gorm.DB) error {
	var cr ConfigRevision
	tx := db.FirstOrCreate(&cr, ConfigRevision{ID: 1})
	if tx.Error != nil {
		return tx.Error
	}
	cr.Revision++
	return db.Save(&cr).Error
}

func CurrentRevision(db *gorm.DB) (uint64, error) {
	var cr ConfigRevision
	if err := db.FirstOrCreate(&cr, ConfigRevision{ID: 1}).Error; err != nil {
		return 0, err
	}
	return cr.Revision, nil
}
