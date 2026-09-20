package migrations

import "gorm.io/gorm"

const (
	xffModeStrip      = "strip_all_and_set_remote"
	xffModeTrustOuter = "trust_outer_waf_cidr_then_take_leftmost"
)

// V10MigrateSiteXFFModes normalizes legacy XFF mode values to the current contract.
func V10MigrateSiteXFFModes(db *gorm.DB) error {
	if !db.Migrator().HasTable(&siteTable{}) || !db.Migrator().HasColumn(&siteTable{}, "xff_mode") {
		return nil
	}

	return db.Model(&siteTable{}).
		Where("xff_mode IS NULL OR xff_mode NOT IN ?", []string{xffModeStrip, xffModeTrustOuter}).
		UpdateColumn("xff_mode", xffModeStrip).Error
}
