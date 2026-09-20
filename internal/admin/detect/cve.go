package detect

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
	"My-OpenWaf/internal/waf/cve"
)

const (
	maxCustomCVEPatternBytes     = 64 << 10
	maxCustomCVEDescriptionBytes = 64 << 10
	maxRuleSearchQueryBytes      = 256
)

func validateCustomCVERule(item *cve.CVERuleModel, requireFields bool) error {
	if item == nil {
		return fmt.Errorf("rule is required")
	}
	item.CVEID = strings.TrimSpace(item.CVEID)
	item.Category = strings.TrimSpace(item.Category)
	// 保留正则表达式首尾空格；只用 TrimSpace 判断是否为空，避免改变
	// 用户明确提交的匹配语义。
	item.Target = strings.TrimSpace(item.Target)
	item.Severity = strings.TrimSpace(item.Severity)
	item.Action = strings.TrimSpace(item.Action)
	item.Description = strings.TrimSpace(item.Description)
	item.CaptchaType = strings.TrimSpace(item.CaptchaType)
	if requireFields {
		if item.Category == "" {
			return fmt.Errorf("category is required")
		}
		if strings.TrimSpace(item.Pattern) == "" {
			return fmt.Errorf("pattern is required")
		}
		if item.Target == "" {
			return fmt.Errorf("target is required")
		}
		if item.Severity == "" {
			return fmt.Errorf("severity is required")
		}
	}
	switch item.Target {
	case "all", "url", "url_body", "body", "header", "cookie":
	default:
		return fmt.Errorf("invalid target")
	}
	fields := []struct {
		name  string
		value string
		limit int
	}{
		{name: "cve_id", value: item.CVEID, limit: 32},
		{name: "category", value: item.Category, limit: 32},
		{name: "target", value: item.Target, limit: 32},
		{name: "severity", value: item.Severity, limit: 16},
		{name: "captcha_type", value: item.CaptchaType, limit: 16},
		{name: "pattern", value: item.Pattern, limit: maxCustomCVEPatternBytes},
		{name: "description", value: item.Description, limit: maxCustomCVEDescriptionBytes},
	}
	for _, field := range fields {
		if !utf8.ValidString(field.value) {
			return fmt.Errorf("%s must be valid UTF-8", field.name)
		}
		if len(field.value) > field.limit {
			return fmt.Errorf("%s exceeds %d bytes", field.name, field.limit)
		}
	}
	if item.Pattern != "" {
		if _, err := regexp.Compile(item.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	}
	if item.Action != "" {
		normalized, ok := shared.ValidateActionWithoutRedirectTarget(item.Action)
		if !ok {
			return fmt.Errorf("invalid action")
		}
		item.Action = normalized
	} else if requireFields {
		return fmt.Errorf("action is required")
	}
	if item.CaptchaType != "" {
		normalized, ok := shared.ValidateCaptchaType(item.CaptchaType)
		if !ok {
			return fmt.Errorf("invalid captcha_type")
		}
		item.CaptchaType = normalized
		if actionIs := cveActionNormalized(item.Action); actionIs != "captcha_challenge" {
			return fmt.Errorf("captcha_type requires captcha_challenge action")
		}
	}
	return nil
}

func cveActionNormalized(value string) string {
	if normalized, ok := shared.ValidateActionWithoutRedirectTarget(value); ok {
		return normalized
	}
	return value
}

func ListCVERules(repo *repository.CVERuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, size)
		scope, err := resolveCVEScope(repo.DB(), c, "", 0, 0)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		filter := repository.CVERuleFilter{Category: c.DefaultQuery("category", ""), Severity: c.DefaultQuery("severity", ""), Source: c.DefaultQuery("source", ""), Query: c.DefaultQuery("q", "")}
		if len(filter.Query) > maxRuleSearchQueryBytes {
			c.JSON(400, map[string]string{"error": "q exceeds 256 bytes"})
			return
		}
		if raw := c.DefaultQuery("enabled", ""); raw != "" {
			want := raw == "true" || raw == "1"
			filter.Enabled = &want
		}
		allViews, err := listEffectiveCVERules(repo, scope, repository.CVERuleFilter{})
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		views := make([]cveScopedRuleView, 0, len(allViews))
		for i := range allViews {
			if cveRuleMatchesFilter(allViews[i], filter) {
				views = append(views, allViews[i])
			}
		}
		total := int64(len(views))
		end := offset + limit
		if offset > len(views) {
			offset = len(views)
		}
		if end > len(views) {
			end = len(views)
		}
		c.JSON(200, map[string]any{
			"items":    views[offset:end],
			"total":    total,
			"scope":    scope.ScopeType,
			"scope_id": scope.ScopeID,
			"stats":    summarizeCVERules(allViews, scope),
		})
	}
}

func CreateCVERule(repo *repository.CVERuleRepo, feedMgr *cve.CVEFeedManager, reload ...func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var item cve.CVERuleModel
		if err := c.BindJSON(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		if err := validateCustomCVERule(&item, true); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		item.Source = "custom"
		item.Approved = true
		item.ID = 0

		if err := repo.Create(&item); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		shared.ReloadCVERules(feedMgr)
		if len(reload) > 0 && reload[0] != nil {
			if err := reload[0](); err != nil {
				c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
				return
			}
		}
		c.JSON(201, item)
	}
}

func UpdateCVERule(repo *repository.CVERuleRepo, feedMgr *cve.CVEFeedManager, reload ...func() error) app.HandlerFunc {
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
		if existing.Source != "custom" {
			c.JSON(403, map[string]string{"error": "only custom rules can be edited"})
			return
		}

		// 使用指针区分“未提交 enabled”和显式提交 false，避免部分更新
		// 把省略字段误写成 false。
		var req struct {
			CVEID       *string `json:"cve_id"`
			Category    string  `json:"category"`
			Pattern     string  `json:"pattern"`
			Target      string  `json:"target"`
			Severity    string  `json:"severity"`
			Action      string  `json:"action"`
			Description *string `json:"description"`
			CaptchaType *string `json:"captcha_type"`
			Enabled     *bool   `json:"enabled"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		// Apply updates
		if req.CVEID != nil {
			existing.CVEID = strings.TrimSpace(*req.CVEID)
		}
		if req.Category != "" {
			existing.Category = strings.TrimSpace(req.Category)
		}
		if req.Pattern != "" {
			existing.Pattern = req.Pattern
		}
		if req.Target != "" {
			existing.Target = strings.TrimSpace(req.Target)
		}
		if req.Severity != "" {
			existing.Severity = strings.TrimSpace(req.Severity)
		}
		if req.Action != "" {
			if normalized, ok := shared.ValidateActionWithoutRedirectTarget(req.Action); ok {
				existing.Action = normalized
			} else {
				c.JSON(400, map[string]string{"error": "invalid action"})
				return
			}
		}
		if req.Description != nil {
			existing.Description = strings.TrimSpace(*req.Description)
		}
		if req.Enabled != nil {
			existing.Enabled = *req.Enabled
		}
		if req.CaptchaType != nil {
			existing.CaptchaType = *req.CaptchaType
		}
		existing.Approved = true
		if err := validateCustomCVERule(existing, false); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		shared.ReloadCVERules(feedMgr)
		if len(reload) > 0 && reload[0] != nil {
			if err := reload[0](); err != nil {
				c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
				return
			}
		}
		c.JSON(200, existing)
	}
}

func DeleteCVERule(repo *repository.CVERuleRepo, feedMgr *cve.CVEFeedManager, reload ...func() error) app.HandlerFunc {
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

		// Only allow deleting custom rules
		if existing.Source != "custom" {
			c.JSON(403, map[string]string{"error": "only custom rules can be deleted"})
			return
		}

		if err := repo.Delete(id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		shared.ReloadCVERules(feedMgr)
		if len(reload) > 0 && reload[0] != nil {
			if err := reload[0](); err != nil {
				c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
				return
			}
		}
		c.JSON(200, map[string]string{"message": "deleted"})
	}
}

func ToggleCVERule(repo *repository.CVERuleRepo, feedMgr *cve.CVEFeedManager, reload ...func() error) app.HandlerFunc {
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
			Enabled *bool `json:"enabled"`
		}
		if len(c.Request.Body()) > 0 {
			if err := c.BindJSON(&req); err != nil {
				c.JSON(400, map[string]string{"error": err.Error()})
				return
			}
		}

		enabled := !existing.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		existing.Enabled = enabled
		if enabled {
			existing.Approved = true
		}

		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		shared.ReloadCVERules(feedMgr)
		if len(reload) > 0 && reload[0] != nil {
			if err := reload[0](); err != nil {
				c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
				return
			}
		}
		c.JSON(200, map[string]any{"id": id, "enabled": existing.Enabled, "approved": existing.Approved})
	}
}

func SyncCVERules(feedMgr *cve.CVEFeedManager, repos ...*repository.CVERuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		if feedMgr == nil {
			c.JSON(503, map[string]string{"error": "CVE feed manager not available"})
			return
		}
		err := feedMgr.SyncNow()
		if len(repos) > 0 && repos[0] != nil {
			repos[0].InvalidateCanonicalSnapshot()
		}
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]string{"message": "sync completed"})
	}
}

func GetCVEFeedStatus(feedMgr *cve.CVEFeedManager, repo *repository.CVERuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var status map[string]any
		if feedMgr != nil {
			ss := feedMgr.GetSyncStatus()
			pendingCount, _ := repo.PendingApprovalCount()
			status = map[string]any{
				"last_sync":      ss.LastSync,
				"last_error":     ss.LastError,
				"syncing":        ss.Syncing,
				"pending_review": pendingCount,
			}
		} else {
			status = map[string]any{
				"last_sync":      nil,
				"last_error":     "feed manager not initialized",
				"syncing":        false,
				"pending_review": 0,
			}
		}
		c.JSON(200, status)
	}
}
