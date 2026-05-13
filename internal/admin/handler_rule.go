package admin

import (
	"context"
	"net"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/core/action"
	"My-OpenWaf/internal/core/rules"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

func ListRules(repo *repository.RuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, size)
		items, total, err := repo.List(offset, limit)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total})
	}
}

func ListSiteRules(siteRepo *repository.SiteRepo, repo *repository.RuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		site, err := siteRepo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		if site.PolicyID == nil {
			c.JSON(200, map[string]any{"items": []store.Rule{}, "total": 0})
			return
		}
		items, err := repo.ListByPolicy(*site.PolicyID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": len(items), "policy_id": *site.PolicyID})
	}
}

func GetRule(repo *repository.RuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		item, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		c.JSON(200, item)
	}
}

func validatePersistedRuleAction(value store.RuleAction) (store.RuleAction, bool) {
	act := action.Normalize(action.Type(value))
	if !action.IsValid(act) {
		return "", false
	}
	return store.RuleAction(act), true
}

func CreateRule(repo *repository.RuleRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var item store.Rule
		if err := c.BindJSON(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if normalized, ok := validatePersistedRuleAction(item.Action); ok {
			item.Action = normalized
		} else {
			c.JSON(400, map[string]string{"error": "invalid action"})
			return
		}
		if err := repo.Create(&item); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": item})
			return
		}
		c.JSON(201, item)
	}
}

func UpdateRule(repo *repository.RuleRepo, reload func() error) app.HandlerFunc {
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
		if err := c.BindJSON(existing); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if normalized, ok := validatePersistedRuleAction(existing.Action); ok {
			existing.Action = normalized
		} else {
			c.JSON(400, map[string]string{"error": "invalid action"})
			return
		}
		existing.ID = id
		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": existing})
			return
		}
		c.JSON(200, existing)
	}
}

func DeleteRule(repo *repository.RuleRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if err := repo.Delete(id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}

// TestRuleRequest is the request body for the rule-test API.
type TestRuleRequest struct {
	Pattern  string            `json:"pattern"`
	ClientIP string            `json:"client_ip"`
	Path     string            `json:"path"`
	Query    string            `json:"query"`
	Headers  map[string]string `json:"headers"`
}

// TestRule lets callers dry-run a pattern against a synthetic request
// without persisting the rule.
func TestRule() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req TestRuleRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		kind, arg := rules.ParsePattern(req.Pattern)
		if kind == "" {
			c.JSON(400, map[string]string{"error": "invalid pattern"})
			return
		}

		compiled := rules.Compile([]store.Rule{
			{Phase: store.PhaseCustom, Pattern: req.Pattern, Action: store.ActionObserve, Priority: 1, Enabled: true},
		})
		if len(compiled) == 0 {
			c.JSON(400, map[string]string{"error": "pattern compiled to no rules"})
			return
		}

		var clientIP net.IP
		if req.ClientIP != "" {
			clientIP = net.ParseIP(req.ClientIP)
		}

		mc := rules.MatchCtx{
			ClientIP: clientIP,
			Path:     req.Path,
			Query:    req.Query,
			Headers:  req.Headers,
		}
		matched := compiled[0].Match(mc)

		c.JSON(200, map[string]any{
			"matched": matched,
			"kind":    kind,
			"arg":     arg,
		})
	}
}

// ExportRules returns all rules as a JSON array for backup/migration.
func ExportRules(repo *repository.RuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		items, _, err := repo.List(0, 10000)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"rules": items})
	}
}

// ImportRules accepts a JSON array of rules and bulk-creates them.
func ImportRules(repo *repository.RuleRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var body struct {
			Rules []store.Rule `json:"rules"`
		}
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if len(body.Rules) == 0 {
			c.JSON(400, map[string]string{"error": "no rules provided"})
			return
		}

		for i := range body.Rules {
			if normalized, ok := validatePersistedRuleAction(body.Rules[i].Action); ok {
				body.Rules[i].Action = normalized
			} else {
				c.JSON(400, map[string]any{"error": "invalid action", "index": i})
				return
			}
			body.Rules[i].ID = 0
		}
		if err := repo.BatchCreate(body.Rules); err != nil {
			c.JSON(500, map[string]any{"error": err.Error(), "imported": 0, "total": len(body.Rules)})
			return
		}
		created := len(body.Rules)
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "imported": created, "total": len(body.Rules)})
			return
		}
		c.JSON(200, map[string]any{"imported": created, "total": len(body.Rules)})
	}
}
