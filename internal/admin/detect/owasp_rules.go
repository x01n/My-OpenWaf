package detect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

type owaspRulePatch struct {
	Enabled     *bool     `json:"enabled,omitempty"`
	Whitelist   *[]string `json:"whitelist,omitempty"`
	Action      *string   `json:"action,omitempty"`
	StatusCode  *int      `json:"status_code,omitempty"`
	RedirectTo  *string   `json:"redirect_to,omitempty"`
	Sensitivity *string   `json:"sensitivity,omitempty"`
}

type owaspRuleView struct {
	ID                 string   `json:"id"`
	CatalogID          uint     `json:"catalog_id"`
	BuiltinID          string   `json:"builtin_id"`
	PolicyID           uint     `json:"policy_id"`
	Category           string   `json:"category"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	DefaultEnabled     bool     `json:"default_enabled"`
	DefaultAction      string   `json:"default_action"`
	DefaultSensitivity string   `json:"default_sensitivity,omitempty"`
	Enabled            bool     `json:"enabled"`
	Whitelist          []string `json:"whitelist,omitempty"`
	Action             string   `json:"action"`
	StatusCode         int      `json:"status_code,omitempty"`
	RedirectTo         string   `json:"redirect_to,omitempty"`
	Sensitivity        string   `json:"sensitivity,omitempty"`
	Overridden         bool     `json:"overridden"`
}

func resolveOWASPPolicyID(db *gorm.DB, c *app.RequestContext, bodyPolicyID uint) (uint, error) {
	policyID := bodyPolicyID
	if raw := strings.TrimSpace(c.Param("policyId")); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || parsed == 0 {
			return 0, errors.New("invalid policy_id")
		}
		policyID = uint(parsed)
	}
	if raw := strings.TrimSpace(string(c.Query("policy_id"))); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || parsed == 0 {
			return 0, errors.New("invalid policy_id")
		}
		policyID = uint(parsed)
	}
	if policyID == 0 {
		var policy store.Policy
		if err := db.Where("default_slot = ?", 1).First(&policy).Error; err != nil {
			return 0, errors.New("default policy not configured")
		}
		policyID = policy.ID
	}
	var count int64
	if err := db.Model(&store.Policy{}).Where("id = ?", policyID).Count(&count).Error; err != nil {
		return 0, err
	}
	if count != 1 {
		return 0, errors.New("policy not found")
	}
	return policyID, nil
}

func loadOWASPViews(db *gorm.DB, policyID uint, c *app.RequestContext, paginate bool) ([]owaspRuleView, int64, error) {
	query := db.Model(&store.OWASPRuleCatalog{}).Where("active = ?", true)
	if category := strings.TrimSpace(string(c.Query("category"))); category != "" {
		query = query.Where("category = ?", category)
	}
	if q := strings.TrimSpace(string(c.Query("q"))); q != "" {
		like := "%" + q + "%"
		query = query.Where("rule_id LIKE ? OR name LIKE ? OR description LIKE ?", like, like, like)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var catalog []store.OWASPRuleCatalog
	query = query.Order("rule_id ASC")
	if paginate {
		page, _ := strconv.Atoi(string(c.Query("page")))
		pageSize, _ := strconv.Atoi(string(c.Query("page_size")))
		if page <= 0 {
			page = 1
		}
		if pageSize <= 0 || pageSize > 500 {
			pageSize = 100
		}
		query = query.Offset((page - 1) * pageSize).Limit(pageSize)
	}
	if err := query.Find(&catalog).Error; err != nil {
		return nil, 0, err
	}
	var configs []store.PolicyOWASPRuleConfig
	if err := db.Where("policy_id = ?", policyID).Find(&configs).Error; err != nil {
		return nil, 0, err
	}
	byRule := make(map[string]store.PolicyOWASPRuleConfig, len(configs))
	for _, cfg := range configs {
		byRule[cfg.RuleID] = cfg
	}
	views := make([]owaspRuleView, 0, len(catalog))
	for _, item := range catalog {
		view := owaspRuleView{ID: item.RuleID, CatalogID: item.ID, BuiltinID: item.RuleID, PolicyID: policyID, Category: item.Category, Name: item.Name, Description: item.Description, DefaultEnabled: item.DefaultEnabled, DefaultAction: item.DefaultAction, DefaultSensitivity: item.DefaultSensitivity, Enabled: item.DefaultEnabled, Action: item.DefaultAction, Sensitivity: item.DefaultSensitivity}
		if cfg, ok := byRule[item.RuleID]; ok {
			view.Overridden = true
			if cfg.Enabled != nil {
				view.Enabled = *cfg.Enabled
			}
			if cfg.Action != nil {
				view.Action = *cfg.Action
			}
			if cfg.Sensitivity != nil {
				view.Sensitivity = *cfg.Sensitivity
			}
			if cfg.StatusCode != nil {
				view.StatusCode = *cfg.StatusCode
			}
			if cfg.RedirectTo != nil {
				view.RedirectTo = *cfg.RedirectTo
			}
			if cfg.Whitelist != nil && strings.TrimSpace(*cfg.Whitelist) != "" {
				_ = json.Unmarshal([]byte(*cfg.Whitelist), &view.Whitelist)
			}
		}
		views = append(views, view)
	}
	return views, total, nil
}

func ListOWASPRulesFromRegistry(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		policyID, err := resolveOWASPPolicyID(repo.DB(), c, 0)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		views, total, err := loadOWASPViews(repo.DB(), policyID, c, true)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		grouped := make(map[string][]owaspRuleView)
		for _, view := range views {
			grouped[view.Category] = append(grouped[view.Category], view)
		}
		c.JSON(200, map[string]any{"items": views, "grouped": grouped, "total": total, "policy_id": policyID})
	}
}

func findOWASPCatalog(db *gorm.DB, rawID string) (*store.OWASPRuleCatalog, error) {
	var item store.OWASPRuleCatalog
	if numericID, err := strconv.ParseUint(rawID, 10, 64); err == nil && numericID > 0 {
		return &item, db.First(&item, uint(numericID)).Error
	}
	return &item, db.Where("rule_id = ? AND active = ?", rawID, true).First(&item).Error
}

func validateOWASPPatch(patch *owaspRulePatch) error {
	if patch.Action != nil && *patch.Action != "" {
		normalized := action.Normalize(action.Type(*patch.Action))
		if !action.IsValid(action.Type(*patch.Action)) || normalized == action.Allow || normalized == action.Tag {
			return errors.New("invalid action")
		}
		value := string(normalized)
		patch.Action = &value
	}
	if patch.StatusCode != nil && *patch.StatusCode != 0 && (*patch.StatusCode < 100 || *patch.StatusCode > 599) {
		return errors.New("status_code must be between 100 and 599")
	}
	if patch.Sensitivity != nil && *patch.Sensitivity != "" {
		switch *patch.Sensitivity {
		case "low", "mid", "medium", "high", "very_high", "strict", "off":
		default:
			return errors.New("invalid sensitivity")
		}
	}
	if patch.Action != nil && action.Normalize(action.Type(*patch.Action)) == action.Redirect &&
		(patch.Enabled == nil || *patch.Enabled) && (patch.RedirectTo == nil || strings.TrimSpace(*patch.RedirectTo) == "") {
		return errors.New("redirect_to required")
	}
	return nil
}

func applyOWASPPatch(config *store.PolicyOWASPRuleConfig, patch owaspRulePatch) {
	if patch.Enabled != nil {
		config.Enabled = patch.Enabled
	}
	if patch.Action != nil {
		if strings.TrimSpace(*patch.Action) == "" {
			config.Action = nil
		} else {
			config.Action = patch.Action
		}
	}
	if patch.Sensitivity != nil {
		if strings.TrimSpace(*patch.Sensitivity) == "" {
			config.Sensitivity = nil
		} else {
			config.Sensitivity = patch.Sensitivity
		}
	}
	if patch.StatusCode != nil {
		if *patch.StatusCode == 0 {
			config.StatusCode = nil
		} else {
			config.StatusCode = patch.StatusCode
		}
	}
	if patch.RedirectTo != nil {
		if strings.TrimSpace(*patch.RedirectTo) == "" {
			config.RedirectTo = nil
		} else {
			config.RedirectTo = patch.RedirectTo
		}
	}
	if patch.Whitelist != nil {
		raw, _ := json.Marshal(*patch.Whitelist)
		value := string(raw)
		config.Whitelist = &value
	}
}

func overrideHasRedirectActionWithoutTarget(override map[string]interface{}) bool {
	if enabled, ok := override["enabled"].(bool); ok && !enabled {
		return false
	}
	actionValue, ok := override["action"].(string)
	if !ok || action.Normalize(action.Type(actionValue)) != action.Redirect {
		return false
	}
	redirectTo, _ := override["redirect_to"].(string)
	return strings.TrimSpace(redirectTo) == ""
}

func UpdateSingleOWASPRule(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			PolicyID uint `json:"policy_id"`
			owaspRulePatch
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateOWASPPatch(&req.owaspRulePatch); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		policyID, err := resolveOWASPPolicyID(repo.DB(), c, req.PolicyID)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		catalog, err := findOWASPCatalog(repo.DB(), c.Param("id"))
		if err != nil {
			c.JSON(404, map[string]string{"error": "OWASP rule not found"})
			return
		}
		var config store.PolicyOWASPRuleConfig
		err = repo.DB().Where("policy_id = ? AND rule_id = ?", policyID, catalog.RuleID).First(&config).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		config.PolicyID = policyID
		config.RuleID = catalog.RuleID
		applyOWASPPatch(&config, req.owaspRulePatch)
		if err := repo.DB().Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "policy_id"}, {Name: "rule_id"}}, DoUpdates: clause.AssignmentColumns([]string{"enabled", "action", "sensitivity", "status_code", "redirect_to", "whitelist", "updated_at"})}).Create(&config).Error; err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"rule_id": catalog.RuleID, "policy_id": policyID, "override": config})
	}
}

func ResetOWASPRuleOverride(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		policyID, err := resolveOWASPPolicyID(repo.DB(), c, 0)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		catalog, err := findOWASPCatalog(repo.DB(), c.Param("id"))
		if err != nil {
			c.JSON(404, map[string]string{"error": "OWASP rule not found"})
			return
		}
		if err := repo.DB().Where("policy_id = ? AND rule_id = ?", policyID, catalog.RuleID).Delete(&store.PolicyOWASPRuleConfig{}).Error; err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"rule_id": catalog.RuleID, "policy_id": policyID, "overridden": false})
	}
}

func BatchUpdateOWASPRules(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			PolicyID uint           `json:"policy_id"`
			IDs      []uint         `json:"ids"`
			Patch    owaspRulePatch `json:"patch"`
			Rules    []struct {
				ID string `json:"id"`
				owaspRulePatch
			} `json:"rules"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}
		policyID, err := resolveOWASPPolicyID(repo.DB(), c, req.PolicyID)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if len(req.IDs) == 0 && len(req.Rules) == 0 {
			c.JSON(400, map[string]string{"error": "rules required"})
			return
		}
		if len(req.IDs) > 0 && validateOWASPPatch(&req.Patch) != nil {
			c.JSON(400, map[string]string{"error": validateOWASPPatch(&req.Patch).Error()})
			return
		}
		updated := 0
		err = repo.DB().Transaction(func(tx *gorm.DB) error {
			for _, id := range req.IDs {
				catalog, err := findOWASPCatalog(tx, strconv.FormatUint(uint64(id), 10))
				if err != nil {
					return errors.New("unknown OWASP rule id")
				}
				config := store.PolicyOWASPRuleConfig{PolicyID: policyID, RuleID: catalog.RuleID}
				_ = tx.Where("policy_id = ? AND rule_id = ?", policyID, catalog.RuleID).First(&config).Error
				applyOWASPPatch(&config, req.Patch)
				if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "policy_id"}, {Name: "rule_id"}}, DoUpdates: clause.AssignmentColumns([]string{"enabled", "action", "sensitivity", "status_code", "redirect_to", "whitelist", "updated_at"})}).Create(&config).Error; err != nil {
					return err
				}
				updated++
			}
			for _, item := range req.Rules {
				if err := validateOWASPPatch(&item.owaspRulePatch); err != nil {
					return err
				}
				catalog, err := findOWASPCatalog(tx, item.ID)
				if err != nil {
					return errors.New("unknown OWASP rule id")
				}
				config := store.PolicyOWASPRuleConfig{PolicyID: policyID, RuleID: catalog.RuleID}
				_ = tx.Where("policy_id = ? AND rule_id = ?", policyID, catalog.RuleID).First(&config).Error
				applyOWASPPatch(&config, item.owaspRulePatch)
				if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "policy_id"}, {Name: "rule_id"}}, DoUpdates: clause.AssignmentColumns([]string{"enabled", "action", "sensitivity", "status_code", "redirect_to", "whitelist", "updated_at"})}).Create(&config).Error; err != nil {
					return err
				}
				updated++
			}
			return nil
		})
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"updated": updated, "policy_id": policyID})
	}
}

func GetOWASPRuleStats(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		policyID, err := resolveOWASPPolicyID(repo.DB(), c, 0)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		views, total, err := loadOWASPViews(repo.DB(), policyID, c, false)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		categoryCount := make(map[string]int)
		enabledCount := 0
		for _, view := range views {
			categoryCount[view.Category]++
			if view.Enabled {
				enabledCount++
			}
		}
		c.JSON(200, map[string]any{"total": total, "enabled_count": enabledCount, "disabled_count": int(total) - enabledCount, "by_category": categoryCount, "policy_id": policyID})
	}
}
