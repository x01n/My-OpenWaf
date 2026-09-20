package cve

import (
	"fmt"
	"sort"
	"strings"

	"gorm.io/gorm"
)

const builtinCatalogSource = "catalog"

// ReconcileBuiltinCatalog synchronizes executable built-in rule metadata into
// cve_rules. Existing duplicate rows are preserved because scope overrides
// reference their numeric IDs; reconciliation only makes their metadata
// consistent with the current executable registry.
func ReconcileBuiltinCatalog(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("reconcile CVE catalog: nil database")
	}

	definitions := builtinCatalogModels()
	return db.Transaction(func(tx *gorm.DB) error {
		var existing []CVERuleModel
		if err := tx.Where("source = ?", builtinCatalogSource).Find(&existing).Error; err != nil {
			return fmt.Errorf("load CVE catalog: %w", err)
		}

		byPattern := make(map[string][]CVERuleModel, len(existing))
		for i := range existing {
			item := existing[i]
			byPattern[item.Pattern] = append(byPattern[item.Pattern], item)
		}

		missing := make([]CVERuleModel, 0)
		for i := range definitions {
			desired := definitions[i]
			matches := byPattern[desired.Pattern]
			if len(matches) == 0 {
				missing = append(missing, desired)
				continue
			}
			for j := range matches {
				item := matches[j]
				if catalogMetadataEqual(item, desired) {
					continue
				}
				updates := map[string]any{
					"cve_id":       desired.CVEID,
					"category":     desired.Category,
					"pattern":      desired.Pattern,
					"target":       desired.Target,
					"severity":     desired.Severity,
					"captcha_type": desired.CaptchaType,
					"enabled":      desired.Enabled,
					"description":  desired.Description,
					"source":       desired.Source,
					"approved":     desired.Approved,
				}
				if err := tx.Model(&item).Updates(updates).Error; err != nil {
					return fmt.Errorf("update CVE catalog rule %q: %w", desired.Pattern, err)
				}
			}
		}

		if len(missing) > 0 {
			if err := tx.Create(&missing).Error; err != nil {
				return fmt.Errorf("create CVE catalog rules: %w", err)
			}
		}
		return nil
	})
}

func builtinCatalogModels() []CVERuleModel {
	registry := GetGlobalCVERuleRegistry()
	if registry == nil {
		return nil
	}
	rules := registry.All()
	items := make([]CVERuleModel, 0, len(rules))
	for i := range rules {
		rule := rules[i]
		if strings.TrimSpace(rule.CVE) == "" || strings.TrimSpace(rule.ID) == "" {
			continue
		}
		description := rule.Description
		if strings.TrimSpace(description) == "" {
			description = rule.Name
		}
		category := rule.Category
		if strings.TrimSpace(category) == "" {
			category = "cve_general"
		}
		severity := rule.Severity
		if strings.TrimSpace(severity) == "" {
			severity = "medium"
		}
		items = append(items, CVERuleModel{
			CVEID:       rule.CVE,
			Category:    category,
			Pattern:     rule.ID,
			Target:      "all",
			Severity:    severity,
			Enabled:     rule.Enabled,
			Description: description,
			Source:      builtinCatalogSource,
			Approved:    true,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Pattern < items[j].Pattern })
	return items
}

func catalogMetadataEqual(current, desired CVERuleModel) bool {
	return current.CVEID == desired.CVEID &&
		current.Category == desired.Category &&
		current.Pattern == desired.Pattern &&
		current.Target == desired.Target &&
		current.Severity == desired.Severity &&
		current.CaptchaType == desired.CaptchaType &&
		current.Enabled == desired.Enabled &&
		current.Description == desired.Description &&
		current.Source == desired.Source &&
		current.Approved == desired.Approved
}
