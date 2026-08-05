package owasp

import (
	"fmt"

	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// BuiltinRuleDefinitions returns the complete metadata inventory for every stable RuleID emitted by the detector.
func BuiltinRuleDefinitions() []store.OWASPRuleCatalog {
	definitions := make(map[string]store.OWASPRuleCatalog)
	for _, rule := range DefaultOWASPRegistry.All() {
		definitions[rule.ID] = store.OWASPRuleCatalog{
			RuleID: rule.ID, Category: rule.Category, Name: rule.Name, Description: rule.Description,
			DefaultEnabled: rule.Enabled, DefaultAction: "intercept", BuiltinVersion: "1", Active: true,
		}
	}
	add := func(ruleID, category, description string) {
		if _, exists := definitions[ruleID]; exists {
			return
		}
		definitions[ruleID] = store.OWASPRuleCatalog{
			RuleID: ruleID, Category: category, Name: description, Description: description,
			DefaultEnabled: true, DefaultAction: "intercept", BuiltinVersion: "1", Active: true,
		}
	}
	for i := 1; i <= 7; i++ {
		add(fmt.Sprintf("owasp:upload:%03d", i), string(CatFileUpload), "File upload validation rule")
	}
	for i := 1; i <= 10; i++ {
		add(fmt.Sprintf("owasp:proto:%03d", i), string(CatProtoViol), "HTTP protocol validation rule")
	}
	pathCategories := []OWASPCategory{CatCmdInject, CatDeserial, CatDeserial, CatDeserial, CatExprLang, CatPathTrav, CatWebshell, CatSSRF, CatCmdInject, CatPathTrav, CatPathTrav, CatCmdInject, CatXXE, CatPathTrav, CatPathTrav, CatCmdInject, CatCmdInject}
	for i, category := range pathCategories {
		add(fmt.Sprintf("owasp:path:%03d", i+1), string(category), "High-risk request path rule")
	}
	add("owasp:deser:012", string(CatDeserial), "URL-encoded Java serialization magic bytes")
	add("owasp:crlf:005", string(CatCRLF), "Bare CR/LF in URL path")

	items := make([]store.OWASPRuleCatalog, 0, len(definitions))
	for _, item := range definitions {
		items = append(items, item)
	}
	return items
}

// ReconcileBuiltinCatalog upserts current metadata and retires definitions no longer emitted by this build.
func ReconcileBuiltinCatalog(db *gorm.DB) error {
	definitions := BuiltinRuleDefinitions()
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&store.OWASPRuleCatalog{}).Where("active = ?", true).Update("active", false).Error; err != nil {
			return err
		}
		for i := range definitions {
			item := definitions[i]
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "rule_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"category", "name", "description", "default_enabled", "default_action", "default_sensitivity", "builtin_version", "active", "updated_at"}),
			}).Create(&item).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
