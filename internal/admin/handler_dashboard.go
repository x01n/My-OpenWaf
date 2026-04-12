package admin

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type DashboardDeps struct {
	Metrics *dataplane.Metrics
	DB      *gorm.DB
}

func DashboardSummary(d *DashboardDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		s := d.Metrics.Summary()

		rev, _ := store.CurrentRevision(d.DB)

		c.JSON(200, map[string]any{
			"qps_1s":              s.QPS1s,
			"qps_5s":              s.QPS5s,
			"requests_total":      s.ReqTotal,
			"status_2xx":          s.Status2xx,
			"errors_upstream_4xx": s.Status4xx,
			"errors_upstream_5xx": s.Status5xx,
			"waf_blocks":          s.WAFBlocks,
			"waf_observes":        s.WAFObserves,
			"builtin_hits":        s.BuiltinHits,
			"uptime_sec":          s.UptimeSec,
			"revision":            rev,
		})
	}
}
