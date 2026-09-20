package migrations

import "testing"

type legacySiteAntiReplay struct {
	ID                uint `gorm:"primaryKey"`
	AntiReplayEnabled bool `gorm:"column:anti_replay_enabled;default:false"`
}

func (legacySiteAntiReplay) TableName() string {
	return "sites"
}

func TestV11MigrateSiteAntiReplayInheritancePreservesExplicitFalseAfterMigration(t *testing.T) {
	db := openMemDB(t)
	if err := db.AutoMigrate(&legacySiteAntiReplay{}, &migrationSystemSetting{}); err != nil {
		t.Fatalf("migrate legacy fixture: %v", err)
	}
	if err := db.Create(&legacySiteAntiReplay{ID: 1, AntiReplayEnabled: false}).Error; err != nil {
		t.Fatalf("seed inherited site: %v", err)
	}
	if err := db.Create(&legacySiteAntiReplay{ID: 2, AntiReplayEnabled: true}).Error; err != nil {
		t.Fatalf("seed enabled site: %v", err)
	}

	if err := V11MigrateSiteAntiReplayInheritance(db); err != nil {
		t.Fatalf("first V11 migration: %v", err)
	}

	var rows []struct {
		ID                uint  `gorm:"column:id"`
		AntiReplayEnabled *bool `gorm:"column:anti_replay_enabled"`
	}
	if err := db.Table("sites").Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("load migrated sites: %v", err)
	}
	if len(rows) != 2 || rows[0].AntiReplayEnabled != nil || rows[1].AntiReplayEnabled == nil || !*rows[1].AntiReplayEnabled {
		t.Fatalf("migrated anti-replay states = %+v, want nil and true", rows)
	}

	if err := db.Exec("INSERT INTO sites (id, anti_replay_enabled) VALUES (?, ?)", 3, false).Error; err != nil {
		t.Fatalf("seed explicit false after migration: %v", err)
	}
	if err := V11MigrateSiteAntiReplayInheritance(db); err != nil {
		t.Fatalf("second V11 migration: %v", err)
	}

	var explicitFalse struct {
		AntiReplayEnabled *bool `gorm:"column:anti_replay_enabled"`
	}
	if err := db.Table("sites").Select("anti_replay_enabled").Where("id = ?", 3).Take(&explicitFalse).Error; err != nil {
		t.Fatalf("load explicit false site: %v", err)
	}
	if explicitFalse.AntiReplayEnabled == nil || *explicitFalse.AntiReplayEnabled {
		t.Fatalf("explicit false after migration = %v, want false", explicitFalse.AntiReplayEnabled)
	}
}
