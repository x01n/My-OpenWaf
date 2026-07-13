package access

import (
	"context"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

// validPathRuleActions 路径规则允许的动作集合。
var validPathRuleActions = map[string]bool{
	store.AccessActionRequireAuth: true,
	store.AccessActionAllow:       true,
	store.AccessActionDeny:        true,
}

// CreatePathRuleReq 创建路径访问控制规则的请求体。
type CreatePathRuleReq struct {
	Path     string `json:"path"`
	Action   string `json:"action"`
	Priority int    `json:"priority"`
	Enabled  *bool  `json:"enabled,omitempty"`
}

// UpdatePathRuleReq 更新路径访问控制规则的请求体，字段为空则保持原值。
type UpdatePathRuleReq struct {
	Path     *string `json:"path,omitempty"`
	Action   *string `json:"action,omitempty"`
	Priority *int    `json:"priority,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
}

/**
 * ListPathRules 按优先级列出站点的路径访问控制规则。
 *
 * @param repo 访问控制仓库。
 * @return Hertz 处理器。
 */
func ListPathRules(repo *repository.AccessControlRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		rules, err := repo.ListAccessPathRules(siteID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"site_id": siteID, "rules": rules})
	}
}

/**
 * CreatePathRule 为站点创建路径访问控制规则。
 *
 * @param repo   访问控制仓库。
 * @param reload snapshot 重建回调。
 * @return Hertz 处理器。
 */
func CreatePathRule(repo *repository.AccessControlRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		var req CreatePathRuleReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		req.Path = strings.TrimSpace(req.Path)
		if req.Path == "" {
			c.JSON(400, map[string]string{"error": "path is required"})
			return
		}
		if req.Action == "" {
			req.Action = store.AccessActionRequireAuth
		}
		if !validPathRuleActions[req.Action] {
			c.JSON(400, map[string]string{"error": "invalid action, must be one of require_auth, allow, deny"})
			return
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		rule := &store.AccessPathRule{
			SiteID:   siteID,
			Path:     req.Path,
			Action:   req.Action,
			Priority: req.Priority,
			Enabled:  enabled,
		}
		if err := repo.CreateAccessPathRule(rule); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "rule created but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, rule)
	}
}

/**
 * UpdatePathRule 更新站点的路径访问控制规则，仅覆盖请求中提供的字段。
 *
 * @param repo   访问控制仓库。
 * @param reload snapshot 重建回调。
 * @return Hertz 处理器。
 */
func UpdatePathRule(repo *repository.AccessControlRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		ruleID, err := utils.ParseUint(c.Param("rid"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid rule id"})
			return
		}
		var req UpdatePathRuleReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": "invalid request body"})
			return
		}
		rule, err := findSitePathRule(repo, siteID, ruleID)
		if err != nil {
			c.JSON(404, map[string]string{"error": "rule not found"})
			return
		}
		if req.Path != nil {
			path := strings.TrimSpace(*req.Path)
			if path == "" {
				c.JSON(400, map[string]string{"error": "path cannot be empty"})
				return
			}
			rule.Path = path
		}
		if req.Action != nil {
			if !validPathRuleActions[*req.Action] {
				c.JSON(400, map[string]string{"error": "invalid action, must be one of require_auth, allow, deny"})
				return
			}
			rule.Action = *req.Action
		}
		if req.Priority != nil {
			rule.Priority = *req.Priority
		}
		if req.Enabled != nil {
			rule.Enabled = *req.Enabled
		}
		if err := repo.UpdateAccessPathRule(rule); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "rule updated but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, rule)
	}
}

/**
 * DeletePathRule 删除站点的路径访问控制规则。
 *
 * @param repo   访问控制仓库。
 * @param reload snapshot 重建回调。
 * @return Hertz 处理器。
 */
func DeletePathRule(repo *repository.AccessControlRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		ruleID, err := utils.ParseUint(c.Param("rid"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid rule id"})
			return
		}
		if _, err := findSitePathRule(repo, siteID, ruleID); err != nil {
			c.JSON(404, map[string]string{"error": "rule not found"})
			return
		}
		if err := repo.DeleteAccessPathRule(ruleID); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "rule deleted but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]any{"site_id": siteID, "id": ruleID, "deleted": true})
	}
}

/**
 * findSitePathRule 在指定站点范围内按 ID 查找路径规则，防止跨站点越权访问。
 *
 * @param repo   访问控制仓库。
 * @param siteID 站点 ID。
 * @param ruleID 规则 ID。
 * @return 命中的规则；未找到或不属于该站点时返回错误。
 */
func findSitePathRule(repo *repository.AccessControlRepo, siteID, ruleID uint) (*store.AccessPathRule, error) {
	rules, err := repo.ListAccessPathRules(siteID)
	if err != nil {
		return nil, err
	}
	for i := range rules {
		if rules[i].ID == ruleID {
			return &rules[i], nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}
