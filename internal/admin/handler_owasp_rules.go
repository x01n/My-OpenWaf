package admin

import (
	"context"
	"sort"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf"
)

type owaspRuleView struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

func ListOWASPRulesFromRegistry(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		allRules := waf.DefaultOWASPRegistry.All()
		cfg := loadProtectionConfig(repo)
		overrides := cfg.GetOWASPRulesConfig()
		categoryFilter := string(c.Query("category"))

		var views []owaspRuleView
		for _, rule := range allRules {
			if categoryFilter != "" && rule.Category != categoryFilter {
				continue
			}
			enabled := rule.Enabled
			if overrides != nil {
				if ov, ok := overrides[rule.ID]; ok {
					if ovMap, ok2 := ov.(map[string]interface{}); ok2 {
						if e, ok3 := ovMap["enabled"]; ok3 {
							if b, ok4 := e.(bool); ok4 {
								enabled = b
							}
						}
					}
				}
			}
			views = append(views, owaspRuleView{
				ID:          rule.ID,
				Category:    rule.Category,
				Name:        rule.Name,
				Description: rule.Description,
				Enabled:     enabled,
			})
		}
		sort.Slice(views, func(i, j int) bool { return views[i].ID < views[j].ID })

		grouped := make(map[string][]owaspRuleView)
		for _, v := range views {
			grouped[v.Category] = append(grouped[v.Category], v)
		}
		c.JSON(200, map[string]any{"items": views, "grouped": grouped, "total": len(views)})
	}
}

func UpdateSingleOWASPRule(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		ruleID := c.Param("id")
		if ruleID == "" {
			c.JSON(400, map[string]string{"error": "rule id required"})
			return
		}
		if _, ok := waf.DefaultOWASPRegistry.Get(ruleID); !ok {
			c.JSON(404, map[string]string{"error": "OWASP rule not found: " + ruleID})
			return
		}
		var req struct {
			Enabled   *bool    `json:"enabled,omitempty"`
			Whitelist []string `json:"whitelist,omitempty"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		cfg := loadProtectionConfig(repo)
		rulesConfig := cfg.GetOWASPRulesConfig()
		if rulesConfig == nil {
			rulesConfig = make(map[string]interface{})
		}
		override := make(map[string]interface{})
		if existing, ok := rulesConfig[ruleID]; ok {
			if m, ok2 := existing.(map[string]interface{}); ok2 {
				override = m
			}
		}
		if req.Enabled != nil {
			override["enabled"] = *req.Enabled
		}
		if req.Whitelist != nil {
			override["whitelist"] = req.Whitelist
		}
		rulesConfig[ruleID] = override
		cfg.SetOWASPRulesConfig(rulesConfig)
		if err := saveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "saved but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"rule_id": ruleID, "override": override})
	}
}

func BatchUpdateOWASPRules(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			Rules []struct {
				ID        string   `json:"id"`
				Enabled   *bool    `json:"enabled,omitempty"`
				Whitelist []string `json:"whitelist,omitempty"`
			} `json:"rules"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		if len(req.Rules) == 0 {
			c.JSON(400, map[string]string{"error": "rules array required"})
			return
		}
		cfg := loadProtectionConfig(repo)
		rulesConfig := cfg.GetOWASPRulesConfig()
		if rulesConfig == nil {
			rulesConfig = make(map[string]interface{})
		}
		updated := 0
		for _, r := range req.Rules {
			if _, ok := waf.DefaultOWASPRegistry.Get(r.ID); !ok {
				continue
			}
			override := make(map[string]interface{})
			if existing, ok := rulesConfig[r.ID]; ok {
				if m, ok2 := existing.(map[string]interface{}); ok2 {
					override = m
				}
			}
			if r.Enabled != nil {
				override["enabled"] = *r.Enabled
			}
			if r.Whitelist != nil {
				override["whitelist"] = r.Whitelist
			}
			rulesConfig[r.ID] = override
			updated++
		}
		cfg.SetOWASPRulesConfig(rulesConfig)
		if err := saveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "saved but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"updated": updated, "total": len(req.Rules)})
	}
}

func GetOWASPRuleStats(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		allRules := waf.DefaultOWASPRegistry.All()
		cfg := loadProtectionConfig(repo)
		overrides := cfg.GetOWASPRulesConfig()
		categoryCount := make(map[string]int)
		enabledCount := 0
		disabledCount := 0
		for _, rule := range allRules {
			categoryCount[rule.Category]++
			enabled := rule.Enabled
			if overrides != nil {
				if ov, ok := overrides[rule.ID]; ok {
					if ovMap, ok2 := ov.(map[string]interface{}); ok2 {
						if e, ok3 := ovMap["enabled"]; ok3 {
							if b, ok4 := e.(bool); ok4 {
								enabled = b
							}
						}
					}
				}
			}
			if enabled {
				enabledCount++
			} else {
				disabledCount++
			}
		}
		c.JSON(200, map[string]any{
			"total":          len(allRules),
			"enabled_count":  enabledCount,
			"disabled_count": disabledCount,
			"by_category":    categoryCount,
		})
	}
}
