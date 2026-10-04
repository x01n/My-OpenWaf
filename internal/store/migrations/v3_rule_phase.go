package migrations

import (
	"fmt"

	"gorm.io/gorm"
)

var legacyExecutableRulePhases = []string{"rate_limit", "owasp_default"}

// V3MigrateLegacyRulePhases 把历史上以不可执行 phase 持久化的自定义规则行
// 改写为可执行的 custom phase。
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
