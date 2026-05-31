package system

import (
	"context"
	"sort"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/upstream"
)

type upstreamStatusItem struct {
	URL       string `json:"url"`
	Healthy   bool   `json:"healthy"`
	FailCount int    `json:"fail_count"`
	CheckedAt string `json:"checked_at,omitempty"`
}

func UpstreamStatus(pool *upstream.Pool) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		states := pool.Snapshot()
		items := make([]upstreamStatusItem, 0, len(states))
		for raw, st := range states {
			item := upstreamStatusItem{URL: raw, Healthy: st.Healthy, FailCount: st.FailCount}
			if !st.CheckedAt.IsZero() {
				item.CheckedAt = st.CheckedAt.Format("2006-01-02T15:04:05Z07:00")
			}
			items = append(items, item)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].URL < items[j].URL })
		c.JSON(200, map[string]any{"items": items, "total": len(items)})
	}
}
