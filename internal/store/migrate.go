package store

import (
	"fmt"

	"My-OpenWaf/internal/store/migrations"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AutoMigrate applies schema for all domain models.
func AutoMigrate(db *gorm.DB) error {
	// Run data migrations first
	if err := migrations.V2MigrateSingleSite(db); err != nil {
		return err
	}
	if err := migrations.V10MigrateSiteXFFModes(db); err != nil {
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
	if err := migrations.V11MigrateSiteAntiReplayInheritance(db); err != nil {
		return err
	}
	// 必须在 AutoMigrate 之前：AutoMigrate 会创建 ux_recorded_res_dedup 唯一索引，
	// 而旧库的 dedup_key 尚未回填，先建索引会因重复值冲突而失败。
	if err := migrations.V8MigrateRecordedResourceDedupKey(db); err != nil {
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

		&OWASPRuleCatalog{},
		&PolicyOWASPRuleConfig{},
		&CVERuleRecord{},
		&CVERuleScopeOverride{},
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

		&LuaPlugin{},
		&JSPlugin{},
	); err != nil {
		return err
	}
	if err := migrations.V9EnsureDefaultPolicy(db); err != nil {
		return err
	}

	// 访问控制表的建表与索引补齐，均为新表，幂等执行。
	if err := migrations.V7MigrateAccessControl(db); err != nil {
		return err
	}

	// V6 and V11 need both legacy sites and the system_settings marker table.
	// Running them again after schema migration handles older databases that did
	// not yet have system_settings when the pre-schema data migrations ran.
	if err := migrations.V6MigrateSiteTLSMinVersionInheritance(db); err != nil {
		return err
	}
	return migrations.V11MigrateSiteAntiReplayInheritance(db)
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
	seed := ConfigRevision{ID: 1, Revision: 0}
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoNothing: true,
	}).Create(&seed).Error; err != nil {
		return err
	}

	result := db.Model(&ConfigRevision{}).
		Where("id = ?", seed.ID).
		UpdateColumn("revision", gorm.Expr("revision + ?", 1))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("config revision row %d was not updated", seed.ID)
	}
	return nil
}

func CurrentRevision(db *gorm.DB) (uint64, error) {
	var cr ConfigRevision
	if err := db.FirstOrCreate(&cr, ConfigRevision{ID: 1}).Error; err != nil {
		return 0, err
	}
	return cr.Revision, nil
}
