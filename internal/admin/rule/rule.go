package rule

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
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
		filter := repository.RuleFilter{Query: strings.TrimSpace(c.DefaultQuery("q", ""))}
		if policyID := strings.TrimSpace(c.DefaultQuery("policy_id", "")); policyID != "" {
			id, err := strconv.ParseUint(policyID, 10, 64)
			if err != nil {
				c.JSON(400, map[string]string{"error": "invalid policy_id"})
				return
			}
			pid := uint(id)
			filter.PolicyID = &pid
		}
		items, total, err := repo.ListFiltered(offset, limit, filter)
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
		policyID := uint(0)
		inherited := site.PolicyID == nil || *site.PolicyID == 0
		if inherited {
			policyID, err = repo.DefaultPolicyID()
			if err != nil {
				c.JSON(500, map[string]string{"error": "default policy not configured"})
				return
			}
		} else {
			policyID = *site.PolicyID
		}
		items, err := repo.ListByPolicy(policyID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": len(items), "policy_id": policyID, "inherited": inherited})
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

func CreateRule(repo *repository.RuleRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var item store.Rule
		// 先填模型声明的默认值，再让请求体覆盖：json 只写出现过的字段，
		// 这样「未提供」保留默认值，「显式传 false/0」才能如实落库。
		_ = store.ApplyModelDefaults(&item)
		if err := c.BindJSON(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		exists, err := repo.PolicyExists(item.PolicyID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if !exists {
			c.JSON(400, map[string]string{"error": "policy_id must reference an existing policy"})
			return
		}
		if errMsg := normalizePersistedRuleConfig(&item); errMsg != "" {
			c.JSON(400, map[string]string{"error": errMsg})
			return
		}
		if errMsg, err := validatePersistedRulePriorityConflict(repo, &item, 0); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		} else if errMsg != "" {
			c.JSON(400, map[string]string{"error": errMsg})
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
		existing.ID = id
		exists, err := repo.PolicyExists(existing.PolicyID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if !exists {
			c.JSON(400, map[string]string{"error": "policy_id must reference an existing policy"})
			return
		}
		if errMsg := normalizePersistedRuleConfig(existing); errMsg != "" {
			c.JSON(400, map[string]string{"error": errMsg})
			return
		}
		if errMsg, err := validatePersistedRulePriorityConflict(repo, existing, id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		} else if errMsg != "" {
			c.JSON(400, map[string]string{"error": errMsg})
			return
		}
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
	Method   string            `json:"method"`
	Body     string            `json:"body"`
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
			Method:   req.Method,
			Path:     req.Path,
			Query:    req.Query,
			Headers:  req.Headers,
			Body:     []byte(req.Body),
		}
		matched := compiled[0].Match(mc)

		c.JSON(200, map[string]any{
			"matched": matched,
			"kind":    kind,
			"arg":     arg,
		})
	}
}

// validatePersistedRuleAction checks persisted rule Action values and returns the canonical store.RuleAction.
func validatePersistedRuleAction(phase store.RulePhase, a store.RuleAction) (store.RuleAction, bool) {
	s := strings.TrimSpace(string(a))
	if s == "" {
		return "", false
	}
	t := action.Normalize(action.Type(s))
	if !action.IsValid(t) {
		return "", false
	}
	if t == action.Tag {
		return "", false
	}
	if t == action.Allow && phase != store.PhaseACL {
		return "", false
	}
	return store.RuleAction(string(t)), true
}

func validatePersistedRulePhase(phase store.RulePhase) (store.RulePhase, bool) {
	normalized := store.RulePhase(strings.TrimSpace(string(phase)))
	switch normalized {
	case store.PhaseACL, store.PhaseSignature, store.PhaseCustom:
		return normalized, true
	default:
		return "", false
	}
}

func normalizePersistedRuleConfig(item *store.Rule) string {
	normalizedPhase, ok := validatePersistedRulePhase(item.Phase)
	if !ok {
		return "unsupported phase: only acl, signature, custom are executable custom rule phases"
	}
	item.Phase = normalizedPhase

	if _, _, errs := rules.ValidatePattern(item.Pattern); len(errs) > 0 {
		return "invalid pattern: " + strings.Join(errs, "; ")
	}

	normalized, ok := validatePersistedRuleAction(item.Phase, item.Action)
	if !ok {
		return "invalid action"
	}
	item.Action = normalized
	if action.Normalize(action.Type(item.Action)) == action.Redirect && strings.TrimSpace(item.RedirectTo) == "" {
		return "redirect_to required"
	}
	if item.CaptchaType != "" {
		if normalizedType, valid := shared.ValidateCaptchaType(item.CaptchaType); !valid {
			return "invalid captcha_type"
		} else {
			item.CaptchaType = normalizedType
		}
		if action.Normalize(action.Type(item.Action)) != action.CaptchaChallenge {
			return "captcha_type requires captcha_challenge action"
		}
	}
	return ""
}

type persistedRulePriorityKey struct {
	PolicyID uint
	Phase    store.RulePhase
	Priority int
}

func validatePersistedRulePriorityConflict(repo *repository.RuleRepo, item *store.Rule, excludeID uint) (string, error) {
	if repo == nil || item == nil {
		return "", nil
	}
	conflict, err := repo.FindPriorityConflict(item.PolicyID, item.Phase, item.Priority, excludeID)
	if err != nil {
		return "", fmt.Errorf("validate rule priority conflict: %w", err)
	}
	if conflict == nil {
		return "", nil
	}
	return fmt.Sprintf(
		"priority %d already exists in policy %d phase %s (rule id %d)",
		item.Priority,
		item.PolicyID,
		item.Phase,
		conflict.ID,
	), nil
}

func validateImportedRulePriorityConflicts(repo *repository.RuleRepo, items []store.Rule) (string, error) {
	seen := make(map[persistedRulePriorityKey]int, len(items))
	for i := range items {
		key := persistedRulePriorityKey{
			PolicyID: items[i].PolicyID,
			Phase:    items[i].Phase,
			Priority: items[i].Priority,
		}
		if prev, ok := seen[key]; ok {
			return fmt.Sprintf(
				"import rules at indexes %d and %d share priority %d in policy %d phase %s",
				prev,
				i,
				key.Priority,
				key.PolicyID,
				key.Phase,
			), nil
		}
		seen[key] = i
		if errMsg, err := validatePersistedRulePriorityConflict(repo, &items[i], 0); err != nil {
			return "", err
		} else if errMsg != "" {
			return errMsg, nil
		}
	}
	return "", nil
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
			exists, err := repo.PolicyExists(body.Rules[i].PolicyID)
			if err != nil {
				c.JSON(500, map[string]any{"error": err.Error(), "index": i})
				return
			}
			if !exists {
				c.JSON(400, map[string]any{"error": "policy_id must reference an existing policy", "index": i})
				return
			}
			if errMsg := normalizePersistedRuleConfig(&body.Rules[i]); errMsg != "" {
				c.JSON(400, map[string]any{"error": errMsg, "index": i})
				return
			}
		}
		if errMsg, err := validateImportedRulePriorityConflicts(repo, body.Rules); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		} else if errMsg != "" {
			c.JSON(400, map[string]any{"error": errMsg})
			return
		}

		for i := range body.Rules {
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
