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

	// cve_rules 由 cve.CVERuleModel（internal/waf/cve/feed.go）定义，不在
	// AutoMigrate 的模型清单里；启动期的 CVE catalog reconcile 会立刻写入
	// 该表，因此必须在 reconcile 之前补齐列。
	if err := migrations.V13MigrateCVERuleReferences(db); err != nil {
		return err
	}

	// 访问控制表的建表与索引补齐，均为新表，幂等执行。
	if err := migrations.V7MigrateAccessControl(db); err != nil {
		return err
	}

	// 规则级频次/验证码有效期三列：AutoMigrate 已经覆盖，这里补一次幂等
	// 修复，保证按历史顺序执行或跳过 AutoMigrate 步骤的库也能拿到列。
	if err := migrations.V14MigrateRuleExecutionParams(db); err != nil {
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
	if err := db.AutoMigrate(
		&SecurityEvent{},
		&AccessLog{},
		&DropEvent{},
		&BotScoreLog{},
	); err != nil {
		return err
	}
	if err := migrations.V12MigrateAccessLogFingerprintKey(db); err != nil {
		return err
	}
	return migrations.V13MigrateSecurityEventRuleInfo(db)
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
