package migrations

import (
	"fmt"

	"gorm.io/gorm"
)

// v14RuleExecutionParamsTable 独立于 store.Rule 声明，避免 migrations 包
// 反向依赖 store 造成导入环。列类型与模型标签保持一致。
type v14RuleExecutionParamsTable struct {
	WindowSeconds  int `gorm:"column:window_seconds;default:0"`
	RequestCount   int `gorm:"column:request_count;default:0"`
	CaptchaMinutes int `gorm:"column:captcha_minutes;default:0"`
}

func (v14RuleExecutionParamsTable) TableName() string { return "rules" }

/**
 * V14MigrateRuleExecutionParams adds the rule-level frequency and CAPTCHA
 * validity columns that the rule form has collected since the rule dialog was
 * introduced but that no column ever stored: window_seconds, request_count and
 * captcha_minutes.
 *
 * The columns are non-nullable with a zero default, so historical rows read
 * back as "not configured" (no frequency limiting, inherit the global CAPTCHA
 * pass TTL) and no backfill is required. AutoMigrate already covers these
 * columns through store.Rule; this migration is the idempotent repair path for
 * databases whose migration order or driver skips that step.
 *
 * Called after AutoMigrate so a fresh database has already created rules.
 */
func V14MigrateRuleExecutionParams(db *gorm.DB) error {
	if db == nil || !db.Migrator().HasTable("rules") {
		return nil
	}
	table := &v14RuleExecutionParamsTable{}
	for _, column := range []string{"WindowSeconds", "RequestCount", "CaptchaMinutes"} {
		if db.Migrator().HasColumn(table, column) {
			continue
		}
		if err := db.Migrator().AddColumn(table, column); err != nil {
			return fmt.Errorf("failed to add rules.%s: %w", column, err)
		}
	}
	return nil
}
