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
 * V14MigrateRuleExecutionParams 新增规则级频次与 CAPTCHA 有效期列：
 * window_seconds、request_count 与 captcha_minutes。规则表单自规则对话框
 * 引入以来就一直在采集这些字段，但从未有列真正存储它们。
 *
 * 这些列非空且默认值为零，历史行读回即为「未配置」（不做频次限制、
 * 继承全局 CAPTCHA 通过 TTL），因此无需回填。AutoMigrate 已通过
 * store.Rule 覆盖这些列；本迁移只是为「迁移顺序或驱动跳过该步骤」的
 * 数据库提供幂等的修复路径。
 *
 * 本函数在 AutoMigrate 之后调用，此时全新数据库已建好 rules。
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
