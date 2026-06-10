package detect

import (
	"context"
	"sort"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/waf/owasp"
)

type owaspRuleView struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	Whitelist   []string `json:"whitelist,omitempty"`
	Action      string   `json:"action,omitempty"`
	StatusCode  int      `json:"status_code,omitempty"`
	RedirectTo  string   `json:"redirect_to,omitempty"`
	Sensitivity string   `json:"sensitivity,omitempty"`
}

func ListOWASPRulesFromRegistry(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		allRules := owasp.DefaultOWASPRegistry.All()
		cfg := shared.LoadProtectionConfig(repo)
		overrides := cfg.GetOWASPRulesConfig()
		categoryFilter := string(c.Query("category"))

		var views []owaspRuleView
		for _, rule := range allRules {
			if categoryFilter != "" && rule.Category != categoryFilter {
				continue
			}
			enabled := rule.Enabled
			view := owaspRuleView{
				ID:          rule.ID,
				Category:    rule.Category,
				Name:        rule.Name,
				Description: rule.Description,
				Enabled:     enabled,
			}
			if overrides != nil {
				if ov, ok := overrides[rule.ID]; ok {
					if ovMap, ok2 := ov.(map[string]interface{}); ok2 {
						if e, ok3 := ovMap["enabled"]; ok3 {
							if b, ok4 := e.(bool); ok4 {
								view.Enabled = b
							}
						}
						if wl, ok3 := ovMap["whitelist"].([]interface{}); ok3 {
							for _, item := range wl {
								if s, ok4 := item.(string); ok4 {
									view.Whitelist = append(view.Whitelist, s)
								}
							}
						}
						if s, ok3 := ovMap["action"].(string); ok3 {
							view.Action = s
						}
						if n, ok3 := ovMap["status_code"].(float64); ok3 {
							view.StatusCode = int(n)
						}
						if s, ok3 := ovMap["redirect_to"].(string); ok3 {
							view.RedirectTo = s
						}
						if s, ok3 := ovMap["sensitivity"].(string); ok3 {
							view.Sensitivity = s
						}
					}
				}
			}
			views = append(views, view)
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
		if _, ok := owasp.DefaultOWASPRegistry.Get(ruleID); !ok {
			c.JSON(404, map[string]string{"error": "OWASP rule not found: " + ruleID})
			return
		}
		var req struct {
			Enabled     *bool    `json:"enabled,omitempty"`
			Whitelist   []string `json:"whitelist,omitempty"`
			Action      *string  `json:"action,omitempty"`
			StatusCode  *int     `json:"status_code,omitempty"`
			RedirectTo  *string  `json:"redirect_to,omitempty"`
			Sensitivity *string  `json:"sensitivity,omitempty"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		cfg := shared.LoadProtectionConfig(repo)
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
		if req.Action != nil {
			if *req.Action == "" {
				delete(override, "action")
			} else {
				if !action.IsValid(action.Type(*req.Action)) || action.Normalize(action.Type(*req.Action)) == action.Allow || action.Normalize(action.Type(*req.Action)) == action.Tag {
					c.JSON(400, map[string]string{"error": "invalid action"})
					return
				}
				override["action"] = string(action.Normalize(action.Type(*req.Action)))
			}
		}
		if req.StatusCode != nil {
			if *req.StatusCode <= 0 {
				delete(override, "status_code")
			} else {
				override["status_code"] = *req.StatusCode
			}
		}
		if req.RedirectTo != nil {
			if *req.RedirectTo == "" {
				delete(override, "redirect_to")
			} else {
				override["redirect_to"] = *req.RedirectTo
			}
		}
		if req.Sensitivity != nil {
			if *req.Sensitivity == "" {
				delete(override, "sensitivity")
			} else {
				override["sensitivity"] = *req.Sensitivity
			}
		}
		if overrideHasRedirectActionWithoutTarget(override) {
			c.JSON(400, map[string]string{"error": "redirect_to required"})
			return
		}
		rulesConfig[ruleID] = override
		cfg.SetOWASPRulesConfig(rulesConfig)
		if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"rule_id": ruleID, "override": override})
	}
}

func BatchUpdateOWASPRules(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			Rules []struct {
				ID          string   `json:"id"`
				Enabled     *bool    `json:"enabled,omitempty"`
				Whitelist   []string `json:"whitelist,omitempty"`
				Action      *string  `json:"action,omitempty"`
				StatusCode  *int     `json:"status_code,omitempty"`
				RedirectTo  *string  `json:"redirect_to,omitempty"`
				Sensitivity *string  `json:"sensitivity,omitempty"`
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
		cfg := shared.LoadProtectionConfig(repo)
		rulesConfig := cfg.GetOWASPRulesConfig()
		if rulesConfig == nil {
			rulesConfig = make(map[string]interface{})
		}
		updated := 0
		for _, r := range req.Rules {
			if _, ok := owasp.DefaultOWASPRegistry.Get(r.ID); !ok {
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
			if r.Action != nil {
				if *r.Action == "" {
					delete(override, "action")
				} else {
					if !action.IsValid(action.Type(*r.Action)) || action.Normalize(action.Type(*r.Action)) == action.Allow || action.Normalize(action.Type(*r.Action)) == action.Tag {
						continue
					}
					override["action"] = string(action.Normalize(action.Type(*r.Action)))
				}
			}
			if r.StatusCode != nil {
				if *r.StatusCode <= 0 {
					delete(override, "status_code")
				} else {
					override["status_code"] = *r.StatusCode
				}
			}
			if r.RedirectTo != nil {
				if *r.RedirectTo == "" {
					delete(override, "redirect_to")
				} else {
					override["redirect_to"] = *r.RedirectTo
				}
			}
			if r.Sensitivity != nil {
				if *r.Sensitivity == "" {
					delete(override, "sensitivity")
				} else {
					override["sensitivity"] = *r.Sensitivity
				}
			}
			if overrideHasRedirectActionWithoutTarget(override) {
				continue
			}
			rulesConfig[r.ID] = override
			updated++
		}
		cfg.SetOWASPRulesConfig(rulesConfig)
		if err := shared.SaveProtectionConfig(repo, cfg); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"updated": updated, "total": len(req.Rules)})
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

func GetOWASPRuleStats(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		allRules := owasp.DefaultOWASPRegistry.All()
		cfg := shared.LoadProtectionConfig(repo)
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
