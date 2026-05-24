package system

import (
	"context"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/store"

	"gorm.io/gorm"
)

type DashboardDeps struct {
	Metrics *dataplane.Metrics
	DB      *gorm.DB
	Cache   *cache.RedisKV
}

const dashboardCacheKey = "dashboard:summary"
const dashboardCacheTTL = 10 * time.Second

func DashboardSummary(d *DashboardDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		// Real-time metrics (always fresh, no cache).
		s := d.Metrics.Summary()
		rev, _ := store.CurrentRevision(d.DB)

		// Try Redis cache for expensive DB aggregation stats.
		var cached dashboardDBStats
		if d.Cache != nil && d.Cache.GetJSON(dashboardCacheKey, &cached) {
			c.JSON(200, buildDashboardResponse(s, rev, cached))
			return
		}

		// Cache miss: query DB.
		since24h := time.Now().Add(-24 * time.Hour)
		var botTotal24h, botBlocked24h, botHighRisk24h int64
		d.DB.Model(&store.BotScoreLog{}).Where("created_at >= ?", since24h).Count(&botTotal24h)
		d.DB.Model(&store.BotScoreLog{}).Where("created_at >= ? AND action IN ('block','drop')", since24h).Count(&botBlocked24h)
		d.DB.Model(&store.BotScoreLog{}).Where("created_at >= ? AND is_high_risk = ?", since24h, true).Count(&botHighRisk24h)

		var cveTotal24h int64
		d.DB.Model(&store.SecurityEvent{}).Where("created_at >= ? AND category = 'cve'", since24h).Count(&cveTotal24h)

		var cveByType []cveCatStat
		d.DB.Model(&store.SecurityEvent{}).
			Select("phase as category, COUNT(*) as count").
			Where("created_at >= ? AND category = 'cve'", since24h).
			Group("phase").
			Scan(&cveByType)

		var dropTotal24h, dropByBot, dropByCVE, dropByRule, dropByIPRep int64
		d.DB.Model(&store.DropEvent{}).Where("created_at >= ?", since24h).Count(&dropTotal24h)
		d.DB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'bot'", since24h).Count(&dropByBot)
		d.DB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'cve'", since24h).Count(&dropByCVE)
		d.DB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'rule'", since24h).Count(&dropByRule)
		d.DB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'ip_reputation'", since24h).Count(&dropByIPRep)

		stats := dashboardDBStats{
			BotTotal24h:    botTotal24h,
			BotBlocked24h:  botBlocked24h,
			BotHighRisk24h: botHighRisk24h,
			CVETotal24h:    cveTotal24h,
			CVEByType:      cveByType,
			DropTotal24h:   dropTotal24h,
			DropBySource: map[string]int64{
				"bot":           dropByBot,
				"cve":           dropByCVE,
				"rule":          dropByRule,
				"ip_reputation": dropByIPRep,
			},
		}

		// Store in Redis cache.
		if d.Cache != nil {
			_ = d.Cache.SetJSON(dashboardCacheKey, stats, dashboardCacheTTL)
		}

		c.JSON(200, buildDashboardResponse(s, rev, stats))
	}
}

type cveCatStat struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

type dashboardDBStats struct {
	BotTotal24h    int64            `json:"bot_total_24h"`
	BotBlocked24h  int64            `json:"bot_blocked_24h"`
	BotHighRisk24h int64            `json:"bot_high_risk_24h"`
	CVETotal24h    int64            `json:"cve_total_24h"`
	CVEByType      []cveCatStat     `json:"cve_by_type_24h"`
	DropTotal24h   int64            `json:"drop_total_24h"`
	DropBySource   map[string]int64 `json:"drop_by_source_24h"`
}

func buildDashboardResponse(s dataplane.Summary, rev uint64, ds dashboardDBStats) map[string]any {
	return map[string]any{
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
		"bot_total_24h":       ds.BotTotal24h,
		"bot_blocked_24h":     ds.BotBlocked24h,
		"bot_high_risk_24h":   ds.BotHighRisk24h,
		"cve_total_24h":       ds.CVETotal24h,
		"cve_by_type_24h":     ds.CVEByType,
		"drop_total_24h":      ds.DropTotal24h,
		"drop_by_source_24h":  ds.DropBySource,
	}
}
