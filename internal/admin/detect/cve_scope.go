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
	"My-OpenWaf/internal/core/action"
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
	CaptchaType string `json:"captcha_type,omitempty"`
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

func effectiveCVERule(rule cve.CVERuleModel, scope cveScopeContext, overrides []store.CVERuleScopeOverride) cveScopedRuleView {
	effective := cveEffectiveConfig{Enabled: rule.Enabled, Action: rule.Action, CaptchaType: rule.CaptchaType}
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
			if item.Action != nil && strings.TrimSpace(*item.Action) != "" {
				view.Effective.Action = *item.Action
			}
			if item.Sensitivity != nil && strings.TrimSpace(*item.Sensitivity) != "" {
				view.Effective.Sensitivity = *item.Sensitivity
			}
			if item.StatusCode != nil && *item.StatusCode != 0 {
				view.Effective.StatusCode = *item.StatusCode
			}
			if item.RedirectTo != nil && strings.TrimSpace(*item.RedirectTo) != "" {
				view.Effective.RedirectTo = *item.RedirectTo
			}
			if item.CaptchaType != nil && strings.TrimSpace(*item.CaptchaType) != "" {
				view.Effective.CaptchaType = *item.CaptchaType
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
	// 非 CAPTCHA 动作下的验证码类型没有语义；从有效视图清除历史脏值，
	// 避免前端展示运行时不会渲染的挑战类型。
	if action.Normalize(action.Type(view.Effective.Action)) != action.CaptchaChallenge {
		view.Effective.CaptchaType = ""
		view.CVERuleModel.CaptchaType = ""
	}
	return view
}

func ensureCatalogCVERules(repo *repository.CVERuleRepo) error {
	return repo.EnsureBuiltinCatalog()
}

func listEffectiveCVERules(repo *repository.CVERuleRepo, scope cveScopeContext, filter repository.CVERuleFilter) ([]cveScopedRuleView, error) {
	if err := ensureCatalogCVERules(repo); err != nil {
		return nil, err
	}
	snapshot, err := repo.CanonicalSnapshot()
	if err != nil {
		return nil, err
	}
	views := make([]cveScopedRuleView, 0, len(snapshot.Rules))
	for i := range snapshot.Rules {
		rule := snapshot.Rules[i]
		view := effectiveCVERule(rule, scope, snapshot.OverridesByRule[rule.ID])
		if !cveRuleMatchesFilter(view, filter) {
			continue
		}
		views = append(views, view)
	}
	return views, nil
}

func cveRuleMatchesFilter(view cveScopedRuleView, filter repository.CVERuleFilter) bool {
	if filter.Category != "" && view.Category != filter.Category {
		return false
	}
	if filter.Severity != "" && view.Severity != filter.Severity {
		return false
	}
	if filter.Source != "" && view.Source != filter.Source {
		return false
	}
	if filter.Enabled != nil && view.Effective.Enabled != *filter.Enabled {
		return false
	}
	query := strings.ToLower(strings.TrimSpace(filter.Query))
	if query == "" {
		return true
	}
	return strings.Contains(strings.ToLower(view.CVEID), query) ||
		strings.Contains(strings.ToLower(view.Description), query)
}

func validateCVEScopePatch(patch *store.CVERuleScopeOverride) error {
	if patch.Action != nil && *patch.Action != "" {
		normalized, ok := shared.ValidateActionWithRedirectTarget(*patch.Action, patch.RedirectTo)
		if !ok {
			return errors.New("invalid action")
		}
		patch.Action = &normalized
	}
	if patch.StatusCode != nil && *patch.StatusCode != 0 && (*patch.StatusCode < 100 || *patch.StatusCode > 599) {
		return errors.New("status_code must be between 100 and 599")
	}
	if patch.CaptchaType != nil {
		normalized, ok := shared.ValidateCaptchaType(*patch.CaptchaType)
		if !ok {
			return errors.New("invalid captcha_type")
		}
		patch.CaptchaType = &normalized
		// 作用域覆盖中的验证码类型只能与同一请求明确选择的
		// captcha_challenge 动作一起提交；动作为空表示继承，留给
		// 作用域合并逻辑决定是否实际使用该类型。
		if normalized != "" && patch.Action != nil {
			actionValue := strings.TrimSpace(*patch.Action)
			if actionValue != "" {
				actionValue = strings.ToLower(actionValue)
				if actionValue == "block" {
					actionValue = "intercept"
				}
				if actionValue != string(store.ActionCaptchaChallenge) {
					return errors.New("captcha_type requires captcha_challenge action")
				}
			}
		}
	}
	return nil
}

/**
 * validateStoredCVEScopeOverride 校验合并后的 CVE 作用域覆盖。
 *
 * 作用域 API 支持部分更新；仅校验本次请求字段会让已有的 redirect 或
 * captcha_type 在后续更新中留下不可执行组合，因此必须对合并结果再校验。
 */
func validateStoredCVEScopeOverride(patch *store.CVERuleScopeOverride) error {
	if patch == nil {
		return errors.New("override is required")
	}
	if patch.Action != nil && strings.TrimSpace(*patch.Action) != "" {
		normalized, ok := shared.ValidateActionWithRedirectTarget(*patch.Action, patch.RedirectTo)
		if !ok {
			return errors.New("invalid action")
		}
		patch.Action = &normalized
	}
	if patch.StatusCode != nil && *patch.StatusCode != 0 && (*patch.StatusCode < 100 || *patch.StatusCode > 599) {
		return errors.New("status_code must be between 100 and 599")
	}
	if patch.Sensitivity != nil && strings.TrimSpace(*patch.Sensitivity) != "" {
		switch strings.TrimSpace(*patch.Sensitivity) {
		case "low", "mid", "medium", "high", "very_high", "strict", "off":
		default:
			return errors.New("invalid sensitivity")
		}
	}
	if patch.CaptchaType != nil && strings.TrimSpace(*patch.CaptchaType) != "" {
		normalized, ok := shared.ValidateCaptchaType(*patch.CaptchaType)
		if !ok {
			return errors.New("invalid captcha_type")
		}
		patch.CaptchaType = &normalized
		if patch.Action == nil || action.Normalize(action.Type(strings.TrimSpace(*patch.Action))) != action.CaptchaChallenge {
			return errors.New("captcha_type requires captcha_challenge action")
		}
	}
	if patch.Action != nil && action.Normalize(action.Type(strings.TrimSpace(*patch.Action))) == action.Redirect &&
		(patch.RedirectTo == nil || strings.TrimSpace(*patch.RedirectTo) == "") {
		return errors.New("redirect_to required")
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
		if patch.CaptchaType == nil {
			patch.CaptchaType = existing.CaptchaType
		}
	}
	if err := validateStoredCVEScopeOverride(&patch); err != nil {
		return err
	}
	patch.ID = 0
	patch.RuleID = ruleID
	patch.ScopeType = scope.ScopeType
	patch.ScopeID = scope.ScopeID
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "rule_id"}, {Name: "scope_type"}, {Name: "scope_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"enabled", "action", "sensitivity", "status_code", "redirect_to", "captcha_type", "updated_at"}),
	}).Create(&patch).Error
}

func ResetCVERuleOverride(repo *repository.CVERuleRepo, reload func() error) app.HandlerFunc {
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
		// 兼容旧版前端把作用域放在 JSON body 的请求；路径/查询参数仍由
		// resolveCVEScope 按既定优先级处理，避免 body 覆盖显式路由作用域。
		var body struct {
			Scope    string `json:"scope"`
			PolicyID uint   `json:"policy_id"`
			SiteID   uint   `json:"site_id"`
		}
		if len(c.Request.Body()) > 0 {
			if err := c.BindJSON(&body); err != nil {
				c.JSON(400, map[string]string{"error": "请求体格式无效"})
				return
			}
		}
		scope, err := resolveCVEScope(repo.DB(), c, body.Scope, body.PolicyID, body.SiteID)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.DB().Where("rule_id = ? AND scope_type = ? AND scope_id = ?", id, scope.ScopeType, scope.ScopeID).Delete(&store.CVERuleScopeOverride{}).Error; err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		repo.InvalidateCanonicalSnapshot()
		if reload != nil {
			if err := reload(); err != nil {
				c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
				return
			}
		}
		c.JSON(200, map[string]any{"id": id, "scope": scope.ScopeType, "scope_id": scope.ScopeID, "overridden": false})
	}
}
