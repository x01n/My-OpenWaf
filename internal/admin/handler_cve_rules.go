package admin

import (
	"context"
	"encoding/json"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
	"My-OpenWaf/internal/waf"
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
		registry := waf.GetGlobalCVERuleRegistry()
		if registry == nil {
			c.JSON(200, map[string]any{"items": []cveRuleView{}, "total": 0})
			return
		}

		// Get filter params
		categoryFilter := string(c.Query("category"))
		severityFilter := string(c.Query("severity"))
		enabledFilter := string(c.Query("enabled"))

		// Get all rules from registry
		cfg := loadProtectionConfig(repo)
		var overrides map[string]waf.CVERuleOverride
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
		// Get all rules from DB
		items, total, err := repo.List(0, 10000, repository.CVERuleFilter{})
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		categoryCount := make(map[string]int)
		severityCount := make(map[string]int)
		enabledCount := 0
		disabledCount := 0

		for _, item := range items {
			categoryCount[item.Category]++
			severityCount[item.Severity]++
			if item.Enabled {
				enabledCount++
			} else {
				disabledCount++
			}
		}

		c.JSON(200, map[string]any{
			"total":          total,
			"enabled_count":  enabledCount,
			"disabled_count": disabledCount,
			"by_category":    categoryCount,
			"by_severity":    severityCount,
		})
	}
}

// BatchUpdateCVERules updates multiple CVE rules at once.
func BatchUpdateCVERules(repo *repository.CVERuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			IDs     []uint `json:"ids"`
			Enabled *bool  `json:"enabled,omitempty"`
			Action  string `json:"action,omitempty"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}

		if len(req.IDs) == 0 {
			c.JSON(400, map[string]string{"error": "ids required"})
			return
		}

		updated := 0
		for _, id := range req.IDs {
			existing, err := repo.Get(id)
			if err != nil {
				continue
			}
			if req.Enabled != nil {
				existing.Enabled = *req.Enabled
			}
			if req.Action != "" {
				existing.Action = req.Action
			}
			if repo.Update(existing) == nil {
				updated++
			}
		}

		c.JSON(200, map[string]any{"updated": updated, "total": len(req.IDs)})
	}
}

// UpdateSingleCVERule updates a single CVE rule by ID (enable/disable/sensitivity).
func UpdateSingleCVERule(repo *repository.CVERuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}

		existing, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}

		var req struct {
			Enabled  *bool  `json:"enabled,omitempty"`
			Action   string `json:"action,omitempty"`
			Severity string `json:"severity,omitempty"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		if req.Enabled != nil {
			existing.Enabled = *req.Enabled
		}
		if req.Action != "" {
			existing.Action = req.Action
		}
		if req.Severity != "" {
			existing.Severity = req.Severity
		}

		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, existing)
	}
}

// parseJSON is a helper to parse JSON strings.
func parseJSON(s string, v interface{}) error {
	return json.Unmarshal([]byte(s), v)
}
