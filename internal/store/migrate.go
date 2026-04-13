package store

import (
	"gorm.io/gorm"
)

// AutoMigrate applies schema for all domain models.
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&Listener{},
		&Certificate{},
		&ForwardingProfile{},
		&Policy{},
		&Rule{},
		&Site{},
		&SystemSettings{},
		&AdminAPIKey{},
		&ConfigRevision{},
		&AdminAccount{},
		&RefreshToken{},
		&SecurityEvent{},
		&IPListEntry{},
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
