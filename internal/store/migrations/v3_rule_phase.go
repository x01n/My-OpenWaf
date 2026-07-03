package migrations

import (
	"fmt"

	"gorm.io/gorm"
)

var legacyExecutableRulePhases = []string{"rate_limit", "owasp_default"}

// V3MigrateLegacyRulePhases rewrites historical custom-rule rows that were
// persisted with non-executable phases into the executable custom phase.
func V3MigrateLegacyRulePhases(db *gorm.DB) error {
	if !db.Migrator().HasTable("rules") {
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&ruleTable{}).
			Where("phase IN ?", legacyExecutableRulePhases).
			UpdateColumn("phase", "custom").Error; err != nil {
			return fmt.Errorf("failed to migrate legacy rule phases: %w", err)
		}
		return nil
	})
}

type ruleTable struct {
	Phase string
}

func (ruleTable) TableName() string {
	return "rules"
}
