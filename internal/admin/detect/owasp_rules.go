package detect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"My-OpenWaf/internal/admin/shared"
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
	CaptchaType *string   `json:"captcha_type,omitempty"`
	Sensitivity *string   `json:"sensitivity,omitempty"`
	Note        *string   `json:"note,omitempty"`
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
	CaptchaType        string   `json:"captcha_type,omitempty"`
	Sensitivity        string   `json:"sensitivity,omitempty"`
	Note               string   `json:"note,omitempty"`
	Overridden         bool     `json:"overridden"`
}

const owaspRuleNoteMaxBytes = 4096
const (
	owaspRuleWhitelistMaxEntries = 64
	owaspRuleWhitelistMaxBytes   = 512
	owaspRuleBatchMaxEntries     = 1000
)

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

func ListOWASPRulesFromRegistry(repo *repository.SystemSettingsRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		policyID, err := resolveOWASPPolicyID(repo.DB(), c, 0)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		filteredViews, err := loadOWASPViews(repo.DB(), policyID, c)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		views := paginateOWASPViews(c, filteredViews)
		response := map[string]any{
			"items":     views,
			"total":     len(filteredViews),
			"policy_id": policyID,
			"stats":     buildOWASPRuleStats(policyID, filteredViews),
		}
		if strings.TrimSpace(string(c.Query("include_grouped"))) != "false" {
			grouped := make(map[string][]owaspRuleView)
			for i := range views {
				view := views[i]
				grouped[view.Category] = append(grouped[view.Category], view)
			}
			response["grouped"] = grouped
		}
		c.JSON(200, response)
	}
}

func findOWASPCatalog(db *gorm.DB, rawID string) (*store.OWASPRuleCatalog, error) {
	var item store.OWASPRuleCatalog
	if numericID, err := strconv.ParseUint(rawID, 10, 64); err == nil && numericID > 0 {
		return &item, db.Where("id = ? AND active = ?", uint(numericID), true).First(&item).Error
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
	if patch.CaptchaType != nil {
		normalized, ok := shared.ValidateCaptchaType(*patch.CaptchaType)
		if !ok {
			return errors.New("invalid captcha_type")
		}
		patch.CaptchaType = &normalized
		// 非空验证码类型必须和同一覆盖请求中的 CAPTCHA 动作配对。
		// action 为空表示继承，运行时会根据最终有效动作决定是否使用。
		if normalized != "" && patch.Action != nil {
			actionValue := strings.ToLower(strings.TrimSpace(*patch.Action))
			switch actionValue {
			case "block":
				actionValue = string(store.ActionIntercept)
			case "captcha":
				actionValue = string(store.ActionCaptchaChallenge)
			}
			if actionValue != "" && actionValue != string(store.ActionCaptchaChallenge) {
				return errors.New("captcha_type requires captcha_challenge action")
			}
		}
	}
	if patch.Note != nil && len(*patch.Note) > owaspRuleNoteMaxBytes {
		return errors.New("note exceeds 4096 bytes")
	}
	if patch.Whitelist != nil {
		if len(*patch.Whitelist) > owaspRuleWhitelistMaxEntries {
			return errors.New("whitelist exceeds 64 entries")
		}
		normalized := make([]string, 0, len(*patch.Whitelist))
		seen := make(map[string]struct{}, len(*patch.Whitelist))
		for _, raw := range *patch.Whitelist {
			value := strings.TrimSpace(raw)
			if value == "" {
				continue
			}
			if len(value) > owaspRuleWhitelistMaxBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
				return errors.New("whitelist entry is too long or contains control characters")
			}
			if value != "*" && !strings.HasPrefix(value, "/") {
				return errors.New("whitelist entry must be * or start with /")
			}
			if strings.Contains(value, "*") && value != "*" && (!strings.HasSuffix(value, "*") || strings.Count(value, "*") != 1) {
				return errors.New("whitelist wildcard is only allowed as the final character")
			}
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			normalized = append(normalized, value)
		}
		patch.Whitelist = &normalized
	}
	if patch.Action != nil && action.Normalize(action.Type(*patch.Action)) == action.Redirect &&
		(patch.Enabled == nil || *patch.Enabled) && (patch.RedirectTo == nil || strings.TrimSpace(*patch.RedirectTo) == "") {
		return errors.New("redirect_to required")
	}
	return nil
}

/**
 * validateOWASPStoredConfig 校验合并后的规则覆盖，防止部分更新留下
 * 可执行动作与其附属字段不一致的配置。
 */
func validateOWASPStoredConfig(config *store.PolicyOWASPRuleConfig, fallbackAction string) error {
	effectiveAction := strings.TrimSpace(fallbackAction)
	if config.Action != nil && strings.TrimSpace(*config.Action) != "" {
		effectiveAction = strings.TrimSpace(*config.Action)
	}
	if effectiveAction == "" {
		effectiveAction = string(action.Intercept)
	}
	normalized := action.Normalize(action.Type(effectiveAction))
	if !action.IsValid(action.Type(effectiveAction)) || normalized == action.Allow || normalized == action.Tag {
		return errors.New("invalid action")
	}
	if normalized == action.Redirect && (config.Enabled == nil || *config.Enabled) &&
		(config.RedirectTo == nil || strings.TrimSpace(*config.RedirectTo) == "") {
		return errors.New("redirect_to required")
	}
	if config.CaptchaType != nil && strings.TrimSpace(*config.CaptchaType) != "" && normalized != action.CaptchaChallenge {
		return errors.New("captcha_type requires captcha_challenge action")
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
		value := strings.TrimSpace(*patch.RedirectTo)
		if value == "" {
			config.RedirectTo = nil
		} else {
			config.RedirectTo = &value
		}
	}
	if patch.CaptchaType != nil {
		if strings.TrimSpace(*patch.CaptchaType) == "" {
			config.CaptchaType = nil
		} else {
			config.CaptchaType = patch.CaptchaType
		}
	}
	if patch.Whitelist != nil {
		raw, _ := json.Marshal(*patch.Whitelist)
		value := string(raw)
		config.Whitelist = &value
	}
	if patch.Note != nil {
		value := strings.TrimSpace(*patch.Note)
		if value == "" {
			config.Note = nil
		} else {
			config.Note = &value
		}
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
		if err := validateOWASPStoredConfig(&config, shared.LoadProtectionConfig(repo).OWASPAction); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.DB().Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "policy_id"}, {Name: "rule_id"}}, DoUpdates: clause.AssignmentColumns([]string{"enabled", "action", "sensitivity", "status_code", "redirect_to", "captcha_type", "whitelist", "note", "updated_at"})}).Create(&config).Error; err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		invalidateOWASPReadSnapshot(repo.DB(), policyID)
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"rule_id": catalog.RuleID, "policy_id": policyID, "override": config})
	}
}

func ResetOWASPRuleOverride(repo *repository.SystemSettingsRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		// 兼容旧版前端把 policy_id 放在 JSON body 的请求，同时优先使用
		// 路径和查询参数（resolveOWASPPolicyID 会按既定优先级覆盖 body）。
		var body struct {
			PolicyID uint `json:"policy_id"`
		}
		if len(c.Request.Body()) > 0 {
			if err := c.BindJSON(&body); err != nil {
				c.JSON(400, map[string]string{"error": "请求体格式无效"})
				return
			}
		}
		policyID, err := resolveOWASPPolicyID(repo.DB(), c, body.PolicyID)
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
		invalidateOWASPReadSnapshot(repo.DB(), policyID)
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
			ResetAll bool           `json:"reset_all"`
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
		if len(req.IDs) == 0 && len(req.Rules) == 0 && !req.ResetAll {
			c.JSON(400, map[string]string{"error": "rules required"})
			return
		}
		if req.ResetAll && (len(req.IDs) > 0 || len(req.Rules) > 0) {
			c.JSON(400, map[string]string{"error": "reset_all cannot be combined with rule updates"})
			return
		}
		if len(req.IDs)+len(req.Rules) > owaspRuleBatchMaxEntries {
			c.JSON(400, map[string]string{"error": "batch exceeds 1000 rules"})
			return
		}
		if len(req.IDs) > 0 && validateOWASPPatch(&req.Patch) != nil {
			c.JSON(400, map[string]string{"error": validateOWASPPatch(&req.Patch).Error()})
			return
		}
		fallbackAction := shared.LoadProtectionConfig(repo).OWASPAction
		updated := 0
		err = repo.DB().Transaction(func(tx *gorm.DB) error {
			if req.ResetAll {
				result := tx.Where("policy_id = ?", policyID).
					Delete(&store.PolicyOWASPRuleConfig{})
				if result.Error != nil {
					return result.Error
				}
				updated = int(result.RowsAffected)
				return nil
			}
			for _, id := range req.IDs {
				catalog, err := findOWASPCatalog(tx, strconv.FormatUint(uint64(id), 10))
				if err != nil {
					return errors.New("unknown OWASP rule id")
				}
				config := store.PolicyOWASPRuleConfig{PolicyID: policyID, RuleID: catalog.RuleID}
				if err := tx.Where("policy_id = ? AND rule_id = ?", policyID, catalog.RuleID).First(&config).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
				applyOWASPPatch(&config, req.Patch)
				if err := validateOWASPStoredConfig(&config, fallbackAction); err != nil {
					return err
				}
				if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "policy_id"}, {Name: "rule_id"}}, DoUpdates: clause.AssignmentColumns([]string{"enabled", "action", "sensitivity", "status_code", "redirect_to", "captcha_type", "whitelist", "note", "updated_at"})}).Create(&config).Error; err != nil {
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
				if err := tx.Where("policy_id = ? AND rule_id = ?", policyID, catalog.RuleID).First(&config).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
				applyOWASPPatch(&config, item.owaspRulePatch)
				if err := validateOWASPStoredConfig(&config, fallbackAction); err != nil {
					return err
				}
				if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "policy_id"}, {Name: "rule_id"}}, DoUpdates: clause.AssignmentColumns([]string{"enabled", "action", "sensitivity", "status_code", "redirect_to", "captcha_type", "whitelist", "note", "updated_at"})}).Create(&config).Error; err != nil {
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
		invalidateOWASPReadSnapshot(repo.DB(), policyID)
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
		views, err := loadOWASPViews(repo.DB(), policyID, c)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, buildOWASPRuleStats(policyID, views))
	}
}
