package detect

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
	"My-OpenWaf/internal/waf/cve"
)

type cveEffectiveConfig struct {
	Enabled     bool   `json:"enabled"`
	Action      string `json:"action"`
	Sensitivity string `json:"sensitivity,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
	RedirectTo  string `json:"redirect_to,omitempty"`
}

type cveScopedRuleView struct {
	cve.CVERuleModel
	Effective     cveEffectiveConfig          `json:"effective"`
	Override      *store.CVERuleScopeOverride `json:"override"`
	Overridden    bool                        `json:"overridden"`
	InheritedFrom string                      `json:"inherited_from"`
}

type cveScopeContext struct {
	ScopeType string
	ScopeID   uint
	PolicyID  uint
	SiteID    uint
}

func resolveCVEScope(db *gorm.DB, c *app.RequestContext, bodyScope string, bodyPolicyID, bodySiteID uint) (cveScopeContext, error) {
	scope := strings.TrimSpace(bodyScope)
	if queryScope := strings.TrimSpace(string(c.Query("scope"))); queryScope != "" {
		scope = queryScope
	}
	if scope == "" {
		scope = store.CVEScopeGlobal
	}
	parseQueryID := func(key string, current uint) (uint, error) {
		raw := strings.TrimSpace(string(c.Query(key)))
		if raw == "" {
			return current, nil
		}
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || value == 0 {
			return 0, errors.New("invalid " + key)
		}
		return uint(value), nil
	}
	policyID, err := parseQueryID("policy_id", bodyPolicyID)
	if err != nil {
		return cveScopeContext{}, err
	}
	siteID, err := parseQueryID("site_id", bodySiteID)
	if err != nil {
		return cveScopeContext{}, err
	}
	result := cveScopeContext{ScopeType: scope, PolicyID: policyID, SiteID: siteID}
	switch scope {
	case store.CVEScopeGlobal:
		result.ScopeID = 0
	case store.CVEScopePolicy:
		if policyID == 0 {
			return result, errors.New("policy_id required")
		}
		var count int64
		if err := db.Model(&store.Policy{}).Where("id = ?", policyID).Count(&count).Error; err != nil || count != 1 {
			return result, errors.New("policy not found")
		}
		result.ScopeID = policyID
	case store.CVEScopeSite:
		if siteID == 0 {
			return result, errors.New("site_id required")
		}
		var site store.Site
		if err := db.First(&site, siteID).Error; err != nil {
			return result, errors.New("site not found")
		}
		result.ScopeID = siteID
		if site.PolicyID != nil && *site.PolicyID != 0 {
			result.PolicyID = *site.PolicyID
		} else {
			var policy store.Policy
			if err := db.Where("default_slot = ?", 1).First(&policy).Error; err != nil {
				return result, errors.New("default policy not configured")
			}
			result.PolicyID = policy.ID
		}
	default:
		return result, errors.New("scope must be global, policy, or site")
	}
	return result, nil
}

func loadCVEOverrides(db *gorm.DB, ruleIDs []uint) (map[uint][]store.CVERuleScopeOverride, error) {
	result := make(map[uint][]store.CVERuleScopeOverride)
	if len(ruleIDs) == 0 {
		return result, nil
	}
	var items []store.CVERuleScopeOverride
	if err := db.Where("rule_id IN ?", ruleIDs).Find(&items).Error; err != nil {
		return nil, err
	}
	for _, item := range items {
		result[item.RuleID] = append(result[item.RuleID], item)
	}
	return result, nil
}

func effectiveCVERule(rule cve.CVERuleModel, scope cveScopeContext, overrides []store.CVERuleScopeOverride) cveScopedRuleView {
	effective := cveEffectiveConfig{Enabled: rule.Enabled, Action: rule.Action}
	view := cveScopedRuleView{CVERuleModel: rule, Effective: effective, InheritedFrom: "catalog"}
	apply := func(scopeType string, scopeID uint) {
		for i := range overrides {
			item := overrides[i]
			if item.ScopeType != scopeType || item.ScopeID != scopeID {
				continue
			}
			if item.Enabled != nil {
				view.Effective.Enabled = *item.Enabled
			}
			if item.Action != nil {
				view.Effective.Action = *item.Action
			}
			if item.Sensitivity != nil {
				view.Effective.Sensitivity = *item.Sensitivity
			}
			if item.StatusCode != nil {
				view.Effective.StatusCode = *item.StatusCode
			}
			if item.RedirectTo != nil {
				view.Effective.RedirectTo = *item.RedirectTo
			}
			view.InheritedFrom = scopeType
			if scope.ScopeType == scopeType && scope.ScopeID == scopeID {
				copy := item
				view.Override = &copy
				view.Overridden = true
			}
		}
	}
	apply(store.CVEScopeGlobal, 0)
	if scope.ScopeType == store.CVEScopePolicy || scope.ScopeType == store.CVEScopeSite {
		apply(store.CVEScopePolicy, scope.PolicyID)
	}
	if scope.ScopeType == store.CVEScopeSite {
		apply(store.CVEScopeSite, scope.SiteID)
	}
	return view
}

func ensureCatalogCVERules(repo *repository.CVERuleRepo) error {
	registry := cve.GetGlobalCVERuleRegistry()
	if registry == nil {
		return nil
	}
	for _, rule := range registry.All() {
		if strings.TrimSpace(rule.CVE) == "" || strings.TrimSpace(rule.ID) == "" {
			continue
		}
		var existing cve.CVERuleModel
		res := repo.DB().Where("source = ? AND pattern = ?", "catalog", rule.ID).Limit(1).Find(&existing)
		if res.Error != nil {
			return res.Error
		}
		model := cve.CVERuleModel{
			CVEID:       rule.CVE,
			Category:    rule.Category,
			Pattern:     rule.ID,
			Target:      "all",
			Severity:    rule.Severity,
			Enabled:     rule.Enabled,
			Description: rule.Description,
			Source:      "catalog",
			Approved:    true,
		}
		if strings.TrimSpace(model.Description) == "" {
			model.Description = rule.Name
		}
		if strings.TrimSpace(model.Category) == "" {
			model.Category = "cve_general"
		}
		if strings.TrimSpace(model.Severity) == "" {
			model.Severity = "medium"
		}
		if res.RowsAffected == 0 {
			if err := repo.DB().Create(&model).Error; err != nil {
				return err
			}
			continue
		}
		updates := map[string]any{
			"cve_id":      model.CVEID,
			"category":    model.Category,
			"target":      model.Target,
			"severity":    model.Severity,
			"enabled":     model.Enabled,
			"description": model.Description,
			"approved":    true,
		}
		if err := repo.DB().Model(&existing).Updates(updates).Error; err != nil {
			return err
		}
	}
	return nil
}

func listEffectiveCVERules(repo *repository.CVERuleRepo, scope cveScopeContext, filter repository.CVERuleFilter) ([]cveScopedRuleView, error) {
	if err := ensureCatalogCVERules(repo); err != nil {
		return nil, err
	}
	dbFilter := filter
	dbFilter.Enabled = nil
	items, _, err := repo.List(0, 10000, dbFilter)
	if err != nil {
		return nil, err
	}
	ruleIDs := make([]uint, 0, len(items))
	for _, item := range items {
		ruleIDs = append(ruleIDs, item.ID)
	}
	overrides, err := loadCVEOverrides(repo.DB(), ruleIDs)
	if err != nil {
		return nil, err
	}
	views := make([]cveScopedRuleView, 0, len(items))
	for _, item := range items {
		view := effectiveCVERule(item, scope, overrides[item.ID])
		if filter.Enabled != nil && view.Effective.Enabled != *filter.Enabled {
			continue
		}
		views = append(views, view)
	}
	return views, nil
}

func validateCVEScopePatch(patch *store.CVERuleScopeOverride) error {
	if patch.Action != nil && *patch.Action != "" {
		normalized, ok := shared.ValidateActionWithRedirectTarget(*patch.Action, patch.RedirectTo)
		if !ok {
			return errors.New("invalid action")
		}
		patch.Action = &normalized
	}
	if patch.StatusCode != nil && (*patch.StatusCode < 100 || *patch.StatusCode > 599) {
		return errors.New("status_code must be between 100 and 599")
	}
	return nil
}

func saveCVEScopeOverride(db *gorm.DB, ruleID uint, scope cveScopeContext, patch store.CVERuleScopeOverride) error {
	var existing store.CVERuleScopeOverride
	result := db.Where("rule_id = ? AND scope_type = ? AND scope_id = ?", ruleID, scope.ScopeType, scope.ScopeID).Limit(1).Find(&existing)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 1 {
		if patch.Enabled == nil {
			patch.Enabled = existing.Enabled
		}
		if patch.Action == nil {
			patch.Action = existing.Action
		}
		if patch.Sensitivity == nil {
			patch.Sensitivity = existing.Sensitivity
		}
		if patch.StatusCode == nil {
			patch.StatusCode = existing.StatusCode
		}
		if patch.RedirectTo == nil {
			patch.RedirectTo = existing.RedirectTo
		}
	}
	patch.ID = 0
	patch.RuleID = ruleID
	patch.ScopeType = scope.ScopeType
	patch.ScopeID = scope.ScopeID
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "rule_id"}, {Name: "scope_type"}, {Name: "scope_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"enabled", "action", "sensitivity", "status_code", "redirect_to", "updated_at"}),
	}).Create(&patch).Error
}

func ResetCVERuleOverride(repo *repository.CVERuleRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		scope, err := resolveCVEScope(repo.DB(), c, "", 0, 0)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.DB().Where("rule_id = ? AND scope_type = ? AND scope_id = ?", id, scope.ScopeType, scope.ScopeID).Delete(&store.CVERuleScopeOverride{}).Error; err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if reload != nil {
			if err := reload(); err != nil {
				c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
				return
			}
		}
		c.JSON(200, map[string]any{"id": id, "scope": scope.ScopeType, "scope_id": scope.ScopeID, "overridden": false})
	}
}
