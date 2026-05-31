package site

import (
	"context"
	"strconv"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

func ListSiteAccessLogs(siteRepo *repository.SiteRepo, repo *repository.AccessLogRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if _, err := siteRepo.Get(siteID); err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, pageSize)
		logID := uint(0)
		if rawID := string(c.Query("id")); rawID != "" {
			if parsedID, err := strconv.ParseUint(rawID, 10, 32); err == nil {
				logID = uint(parsedID)
			}
		}
		f := repository.AccessLogFilter{
			SiteID:      siteID,
			ID:          logID,
			RequestID:   string(c.Query("request_id")),
			ClientIP:    string(c.Query("client_ip")),
			Host:        string(c.Query("host")),
			Path:        string(c.Query("path")),
			Method:      string(c.Query("method")),
			WAFAction:   string(c.Query("waf_action")),
			CacheState:  string(c.Query("cache_state")),
			StatusGroup: string(c.Query("status_group")),
		}
		if since := string(c.Query("since")); since != "" {
			if t, err := time.Parse(time.RFC3339, since); err == nil {
				f.Since = &t
			}
		}
		if until := string(c.Query("until")); until != "" {
			if t, err := time.Parse(time.RFC3339, until); err == nil {
				f.Until = &t
			}
		}
		items, total, err := repo.List(offset, limit, f)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page})
	}
}

func SiteAccessLogStats(siteRepo *repository.SiteRepo, repo *repository.AccessLogRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if _, err := siteRepo.Get(siteID); err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
		if hours <= 0 || hours > 24*30 {
			hours = 24
		}
		stats, err := repo.StatsBySite(siteID, time.Now().Add(-time.Duration(hours)*time.Hour))
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, stats)
	}
}

func ListSiteDropEvents(siteRepo *repository.SiteRepo, repo *repository.DropEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if _, err := siteRepo.Get(siteID); err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, pageSize)
		f := repository.DropEventFilter{
			SiteID:   siteID,
			ClientIP: string(c.Query("client_ip")),
			Source:   string(c.Query("source")),
		}
		items, total, err := repo.List(offset, limit, f)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page})
	}
}

func SiteDropStats(siteRepo *repository.SiteRepo, repo *repository.DropEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if _, err := siteRepo.Get(siteID); err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		stats, err := repo.Stats24hBySite(siteID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, stats)
	}
}
