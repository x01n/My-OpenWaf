package detect

import (
	"context"
	"regexp"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
	"My-OpenWaf/internal/waf/cve"
)

func ListCVERules(repo *repository.CVERuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, size)

		f := repository.CVERuleFilter{
			Category: c.DefaultQuery("category", ""),
			Severity: c.DefaultQuery("severity", ""),
			Source:   c.DefaultQuery("source", ""),
		}
		if v := c.DefaultQuery("enabled", ""); v != "" {
			b := v == "true" || v == "1"
			f.Enabled = &b
		}

		items, total, err := repo.List(offset, limit, f)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total})
	}
}

func CreateCVERule(repo *repository.CVERuleRepo, feedMgr *cve.CVEFeedManager) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var item cve.CVERuleModel
		if err := c.BindJSON(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		// Validate regex pattern
		if item.Pattern != "" {
			if _, err := regexp.Compile(item.Pattern); err != nil {
				c.JSON(400, map[string]string{"error": "invalid regex pattern: " + err.Error()})
				return
			}
		}

		if normalized, ok := shared.ValidateActionWithoutRedirectTarget(item.Action); !ok {
			c.JSON(400, map[string]string{"error": "invalid action"})
			return
		} else if normalized != "" {
			item.Action = normalized
		}

		item.Source = "custom"
		item.Approved = true
		item.ID = 0

		if err := repo.Create(&item); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		shared.ReloadCVERules(feedMgr)
		c.JSON(201, item)
	}
}

func UpdateCVERule(repo *repository.CVERuleRepo, feedMgr *cve.CVEFeedManager) app.HandlerFunc {
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

		var req cve.CVERuleModel
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		// Validate regex pattern if provided
		if req.Pattern != "" {
			if _, err := regexp.Compile(req.Pattern); err != nil {
				c.JSON(400, map[string]string{"error": "invalid regex pattern: " + err.Error()})
				return
			}
		}

		// Apply updates
		if req.CVEID != "" {
			existing.CVEID = req.CVEID
		}
		if req.Category != "" {
			existing.Category = req.Category
		}
		if req.Pattern != "" {
			existing.Pattern = req.Pattern
		}
		if req.Target != "" {
			existing.Target = req.Target
		}
		if req.Severity != "" {
			existing.Severity = req.Severity
		}
		if req.Action != "" {
			if normalized, ok := shared.ValidateActionWithoutRedirectTarget(req.Action); ok {
				existing.Action = normalized
			} else {
				c.JSON(400, map[string]string{"error": "invalid action"})
				return
			}
		}
		if req.Description != "" {
			existing.Description = req.Description
		}
		existing.Enabled = req.Enabled
		existing.Approved = true

		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		shared.ReloadCVERules(feedMgr)
		c.JSON(200, existing)
	}
}

func DeleteCVERule(repo *repository.CVERuleRepo, feedMgr *cve.CVEFeedManager) app.HandlerFunc {
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
		c.JSON(200, map[string]string{"message": "deleted"})
	}
}

func ToggleCVERule(repo *repository.CVERuleRepo, feedMgr *cve.CVEFeedManager) app.HandlerFunc {
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
		c.JSON(200, map[string]any{"id": id, "enabled": existing.Enabled, "approved": existing.Approved})
	}
}

func SyncCVERules(feedMgr *cve.CVEFeedManager) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		if feedMgr == nil {
			c.JSON(503, map[string]string{"error": "CVE feed manager not available"})
			return
		}
		if err := feedMgr.SyncNow(); err != nil {
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
