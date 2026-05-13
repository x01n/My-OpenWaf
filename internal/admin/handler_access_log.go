package admin

import (
	"context"
	"strconv"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

func ListAccessLogs(repo *repository.AccessLogRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, pageSize)

		f := repository.AccessLogFilter{
			ClientIP:    string(c.Query("client_ip")),
			Host:        string(c.Query("host")),
			Path:        string(c.Query("path")),
			Method:      string(c.Query("method")),
			WAFAction:   string(c.Query("waf_action")),
			CacheState:  string(c.Query("cache_state")),
			StatusGroup: string(c.Query("status_group")),
		}
		if siteID := string(c.Query("site_id")); siteID != "" {
			if v, err := strconv.ParseUint(siteID, 10, 64); err == nil {
				f.SiteID = uint(v)
			}
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
