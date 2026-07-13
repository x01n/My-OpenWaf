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
	if err := migrations.V3MigrateLegacyRulePhases(db); err != nil {
		return err
	}
	if err := migrations.V4MigrateRecordedResourceQueryString(db); err != nil {
		return err
	}
	if err := migrations.V5MigrateSiteTLSInheritanceDefaults(db); err != nil {
		return err
	}
	if err := migrations.V6MigrateSiteTLSMinVersionInheritance(db); err != nil {
		return err
	}

	// Then apply schema migrations
	if err := db.AutoMigrate(
		&Certificate{},
		&Policy{},
		&Rule{},
		&Site{},
		&SiteListener{},
		&SystemSettings{},
		&AdminAPIKey{},
		&ConfigRevision{},
		&AdminAccount{},
		&RefreshToken{},

		&IPListEntry{},
		&TokenBlacklist{},
		&LoginAttempt{},
		&ActiveSession{},

		&CVERuleRecord{},
		&CVESyncLog{},
		&ApplicationRouteRule{},
		&RecordedResource{},

		&SiteAccessConfig{},
		&AccessProvider{},
		&AccessUser{},
		&AccessPathRule{},
		&AccessSession{},

		&ThreatIntelFeed{},
		&ThreatIntelSyncLog{},
		&FalsePositiveReport{},
	); err != nil {
		return err
	}

	// 访问控制表的建表与索引补齐，均为新表，幂等执行。
	if err := migrations.V7MigrateAccessControl(db); err != nil {
		return err
	}

	// V6 needs both legacy sites and the system_settings marker table. Running
	// it again after schema migration handles older databases that did not yet
	// have system_settings when the pre-schema data migrations ran.
	return migrations.V6MigrateSiteTLSMinVersionInheritance(db)
}

func AutoMigrateLogs(db *gorm.DB) error {
	return db.AutoMigrate(
		&SecurityEvent{},
		&AccessLog{},
		&DropEvent{},
		&BotScoreLog{},
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
