package detect

import (
	"context"
	"encoding/json"
	"errors"

	"gorm.io/gorm"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
	"My-OpenWaf/internal/waf/cve"
)

// cveRuleView is the API representation of a CVE rule from the global registry.
type cveRuleView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CVE         string `json:"cve"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Enabled     bool   `json:"enabled"`
	Sensitivity string `json:"sensitivity"`
}

// ListCVERulesFromRegistry lists all CVE rules from the global registry with filtering.
func ListCVERulesFromRegistry(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		registry := cve.GetGlobalCVERuleRegistry()
		if registry == nil {
			c.JSON(200, map[string]any{"items": []cveRuleView{}, "total": 0})
			return
		}

		// Get filter params
		categoryFilter := string(c.Query("category"))
		severityFilter := string(c.Query("severity"))
		enabledFilter := string(c.Query("enabled"))

		// Get all rules from registry
		cfg := shared.LoadProtectionConfig(repo)
		var overrides map[string]cve.CVERuleOverride
		if cfg.CVERulesConfig != "" && cfg.CVERulesConfig != "{}" {
			_ = parseJSON(cfg.CVERulesConfig, &overrides)
		}

		// We need to access the rules - use DetectAll to get info (registry doesn't have All())
		// Since CVERuleRegistry doesn't expose All(), we work with the DB repo for listing
		// and use the registry for stats. Return from DB-based listing.
		c.JSON(200, map[string]any{
			"message":         "use /api/v1/cve-rules for database-backed listing",
			"category_filter": categoryFilter,
			"severity_filter": severityFilter,
			"enabled_filter":  enabledFilter,
		})
	}
}

// GetCVERuleStats returns statistics about CVE rules.
func GetCVERuleStats(repo *repository.CVERuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		scope, err := resolveCVEScope(repo.DB(), c, "", 0, 0)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		views, err := listEffectiveCVERules(repo, scope, repository.CVERuleFilter{})
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		categoryCount := make(map[string]int)
		severityCount := make(map[string]int)
		enabledCount := 0
		disabledCount := 0

		for _, item := range views {
			categoryCount[item.Category]++
			severityCount[item.Severity]++
			if item.Effective.Enabled {
				enabledCount++
			} else {
				disabledCount++
			}
		}

		c.JSON(200, map[string]any{
			"total":          int64(len(views)),
			"enabled_count":  enabledCount,
			"disabled_count": disabledCount,
			"by_category":    categoryCount,
			"by_severity":    severityCount,
			"scope":          scope.ScopeType,
			"scope_id":       scope.ScopeID,
		})
	}
}

// BatchUpdateCVERules updates multiple CVE rules at once.
func BatchUpdateCVERules(repo *repository.CVERuleRepo, feedMgr *cve.CVEFeedManager, reload ...func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			Scope       string  `json:"scope"`
			PolicyID    uint    `json:"policy_id"`
			SiteID      uint    `json:"site_id"`
			IDs         []uint  `json:"ids"`
			Enabled     *bool   `json:"enabled,omitempty"`
			Action      *string `json:"action,omitempty"`
			Sensitivity *string `json:"sensitivity,omitempty"`
			StatusCode  *int    `json:"status_code,omitempty"`
			RedirectTo  *string `json:"redirect_to,omitempty"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "请求体格式无效"})
			return
		}
		if len(req.IDs) == 0 {
			c.JSON(400, map[string]string{"error": "ids required"})
			return
		}
		scope, err := resolveCVEScope(repo.DB(), c, req.Scope, req.PolicyID, req.SiteID)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		patch := store.CVERuleScopeOverride{Enabled: req.Enabled, Action: req.Action, Sensitivity: req.Sensitivity, StatusCode: req.StatusCode, RedirectTo: req.RedirectTo}
		if err := validateCVEScopePatch(&patch); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		err = repo.DB().Transaction(func(tx *gorm.DB) error {
			for _, id := range req.IDs {
				var count int64
				if err := tx.Model(&store.CVERuleRecord{}).Where("id = ?", id).Count(&count).Error; err != nil {
					return err
				}
				if count != 1 {
					return errors.New("unknown CVE rule id")
				}
				if err := saveCVEScopeOverride(tx, id, scope, patch); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if len(reload) > 0 && reload[0] != nil {
			if err := reload[0](); err != nil {
				c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
				return
			}
		}
		c.JSON(200, map[string]any{"updated": len(req.IDs), "scope": scope.ScopeType, "scope_id": scope.ScopeID})
	}
}

// UpdateSingleCVERule updates a single CVE rule by ID (enable/disable/sensitivity).
func UpdateSingleCVERule(repo *repository.CVERuleRepo, feedMgr *cve.CVEFeedManager, reload ...func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if _, err := repo.Get(id); err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		var req struct {
			Scope       string  `json:"scope"`
			PolicyID    uint    `json:"policy_id"`
			SiteID      uint    `json:"site_id"`
			Enabled     *bool   `json:"enabled,omitempty"`
			Action      *string `json:"action,omitempty"`
			Sensitivity *string `json:"sensitivity,omitempty"`
			StatusCode  *int    `json:"status_code,omitempty"`
			RedirectTo  *string `json:"redirect_to,omitempty"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		scope, err := resolveCVEScope(repo.DB(), c, req.Scope, req.PolicyID, req.SiteID)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		patch := store.CVERuleScopeOverride{Enabled: req.Enabled, Action: req.Action, Sensitivity: req.Sensitivity, StatusCode: req.StatusCode, RedirectTo: req.RedirectTo}
		if err := validateCVEScopePatch(&patch); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := saveCVEScopeOverride(repo.DB(), id, scope, patch); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if len(reload) > 0 && reload[0] != nil {
			if err := reload[0](); err != nil {
				c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
				return
			}
		}
		c.JSON(200, map[string]any{"id": id, "scope": scope.ScopeType, "scope_id": scope.ScopeID, "override": patch})
	}
}

// parseJSON is a helper to parse JSON strings.
func parseJSON(s string, v interface{}) error {
	return json.Unmarshal([]byte(s), v)
}
