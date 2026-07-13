package system

import (
	"context"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store/repository"
)

/**
 * ListThreatIntelSyncLogs 分页列出威胁情报同步历史。
 *
 * 支持 query: feed_id 过滤单个订阅源、status="success"/"failed" 过滤成功/失败。
 */
func ListThreatIntelSyncLogs(repo *repository.ThreatIntelSyncLogRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(string(c.Query("page")))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(string(c.Query("page_size")))
		if pageSize < 1 || pageSize > 200 {
			pageSize = 20
		}
		var feedID uint
		if v := string(c.Query("feed_id")); v != "" {
			if id, err := strconv.ParseUint(v, 10, 64); err == nil {
				feedID = uint(id)
			}
		}
		status := string(c.Query("status"))
		items, total, err := repo.List((page-1)*pageSize, pageSize, feedID, status)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page, "page_size": pageSize})
	}
}
