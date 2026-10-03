package migrations

import (
	"fmt"

	"gorm.io/gorm"
)

// v13SecurityEventRuleInfoTable 独立于 store.SecurityEvent 声明，避免
// migrations 包反向依赖 store 造成导入环。列类型与模型标签保持一致。
type v13SecurityEventRuleInfoTable struct {
	RuleName     string  `gorm:"column:rule_name;size:255"`
	RuleDesc     string  `gorm:"column:rule_desc;size:512"`
	MatchScore   int     `gorm:"column:match_score;default:0"`
	MatchSnippet string  `gorm:"column:match_snippet;size:256"`
	MatchPart    string  `gorm:"column:match_part;size:32"`
	Severity     string  `gorm:"column:severity;size:16"`
	Source       string  `gorm:"column:source;size:32"`
	CVSSScore    float64 `gorm:"column:cvss_score;default:0"`
	CWEType      string  `gorm:"column:cwe_type;size:32"`
	References   string  `gorm:"column:references;type:text"`
}

func (v13SecurityEventRuleInfoTable) TableName() string { return "security_events" }

// v13CVERuleReferencesTable 同样独立声明：references 是 SQL 保留字，
// 用 GORM 标签生成列定义，避免手写 SQL 时的转义问题。
type v13CVERuleReferencesTable struct {
	References string `gorm:"column:references;type:text"`
}

func (v13CVERuleReferencesTable) TableName() string { return "cve_rules" }

/**
 * V13MigrateSecurityEventRuleInfo adds the rule-explanation columns used by the
 * security-event detail view: rule name/description, OWASP match score and
 * snippet, and the CVE severity/source/CVSS/CWE/reference fields.
 *
 * Also adds cve_rules.references, which the CVE feed fills from NVD. That table
 * is defined by cve.CVERuleModel (internal/waf/cve/feed.go) rather than a store
 * model, so GORM's AutoMigrate does not cover it.
 *
 * Columns carry database defaults or are nullable, so historical rows stay
 * readable and no backfill is required. Called after AutoMigrateLogs so a
 * fresh database has already created security_events.
 */
func V13MigrateSecurityEventRuleInfo(db *gorm.DB) error {
	if db != nil && db.Migrator().HasTable("security_events") {
		table := &v13SecurityEventRuleInfoTable{}
		for _, column := range []string{
			"RuleName", "RuleDesc", "MatchScore", "MatchSnippet", "MatchPart",
			"Severity", "Source", "CVSSScore", "CWEType", "References",
		} {
			if db.Migrator().HasColumn(table, column) {
				continue
			}
			if err := db.Migrator().AddColumn(table, column); err != nil {
				return fmt.Errorf("failed to add security_events.%s: %w", column, err)
			}
		}
	}
	if db != nil && db.Migrator().HasTable("cve_rules") {
		cveTable := &v13CVERuleReferencesTable{}
		if !db.Migrator().HasColumn(cveTable, "References") {
			if err := db.Migrator().AddColumn(cveTable, "References"); err != nil {
				return fmt.Errorf("failed to add cve_rules.references: %w", err)
			}
		}
	}
	return nil
}

/**
 * V13MigrateCVERuleReferences is the main-database half of V13: it only adds
 * cve_rules.references, which the catalog reconciler writes during startup
 * before AutoMigrateLogs runs.
 */
func V13MigrateCVERuleReferences(db *gorm.DB) error {
	if db == nil || !db.Migrator().HasTable("cve_rules") {
		return nil
	}
	cveTable := &v13CVERuleReferencesTable{}
	if db.Migrator().HasColumn(cveTable, "References") {
		return nil
	}
	if err := db.Migrator().AddColumn(cveTable, "References"); err != nil {
		return fmt.Errorf("failed to add cve_rules.references: %w", err)
	}
	return nil
}
