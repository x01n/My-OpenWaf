package system

import (
	"context"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/cache"
	"My-OpenWaf/internal/dataplane"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"

	"gorm.io/gorm"
)

type DashboardDeps struct {
	Metrics    *dataplane.Metrics
	ConfigDB   *gorm.DB
	LogDB      *gorm.DB
	Cache      *cache.RedisKV
	AccessRepo *repository.AccessLogRepo
}

const dashboardCacheKey = "dashboard:summary"
const dashboardCacheTTL = 10 * time.Second

func DashboardSummary(d *DashboardDeps) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(200, BuildDashboardSnapshot(d))
	}
}

type cveCatStat struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

type dashboardDBStats struct {
	UniqueVisitors24h int64 `json:"unique_visitors_24h"`
	HumanVisits24h    int64 `json:"human_visits_24h"`
	BotVisits24h      int64 `json:"bot_visits_24h"`
	// UnclassifiedIntercept24h 为「未经 bot 判定即被拦截」的唯一 request_id 数。
	// VisitKindTotal24h 为窗口内唯一 request_id 总数；三类之和与它的差额是其他非安全类动作。
	UnclassifiedIntercept24h           int64            `json:"unclassified_intercept_24h"`
	VisitKindTotal24h                  int64            `json:"visit_kind_total_24h"`
	VisitorFusionHTTPSReleasedTotal24h int64            `json:"visitor_fusion_https_released_total_24h"`
	VisitorFusionHuman24h              int64            `json:"visitor_fusion_human_24h"`
	VisitorFusionBot24h                int64            `json:"visitor_fusion_bot_24h"`
	VisitorFusionUnknown24h            int64            `json:"visitor_fusion_unknown_24h"`
	BotTotal24h                        int64            `json:"bot_total_24h"`
	BotBlocked24h                      int64            `json:"bot_blocked_24h"`
	BotHighRisk24h                     int64            `json:"bot_high_risk_24h"`
	CVETotal24h                        int64            `json:"cve_total_24h"`
	CVEByType                          []cveCatStat     `json:"cve_by_type_24h"`
	DropTotal24h                       int64            `json:"drop_total_24h"`
	DropBySource                       map[string]int64 `json:"drop_by_source_24h"`
}

func buildDashboardResponse(s dataplane.Summary, rev uint64, ds dashboardDBStats) map[string]any {
	return map[string]any{
		"qps_1s":                     s.QPS1s,
		"qps_5s":                     s.QPS5s,
		"requests_total":             s.ReqTotal,
		"status_2xx":                 s.Status2xx,
		"errors_upstream_4xx":        s.Status4xx,
		"errors_upstream_5xx":        s.Status5xx,
		"waf_blocks":                 s.WAFBlocks,
		"waf_observes":               s.WAFObserves,
		"builtin_hits":               s.BuiltinHits,
		"uptime_sec":                 s.UptimeSec,
		"unique_ips":                 s.UniqueIPs,
		"attack_ips":                 s.AttackIPs,
		"unique_visitors_24h":        ds.UniqueVisitors24h,
		"revision":                   rev,
		"human_visits_24h":           ds.HumanVisits24h,
		"bot_visits_24h":             ds.BotVisits24h,
		"unclassified_intercept_24h": ds.UnclassifiedIntercept24h,
		"visit_kind_total_24h":       ds.VisitKindTotal24h,
		"visitor_fusion_https_released_total_24h": ds.VisitorFusionHTTPSReleasedTotal24h,
		"visitor_fusion_human_24h":                ds.VisitorFusionHuman24h,
		"visitor_fusion_bot_24h":                  ds.VisitorFusionBot24h,
		"visitor_fusion_unknown_24h":              ds.VisitorFusionUnknown24h,
		"bot_total_24h":                           ds.BotTotal24h,
		"bot_blocked_24h":                         ds.BotBlocked24h,
		"bot_high_risk_24h":                       ds.BotHighRisk24h,
		"cve_total_24h":                           ds.CVETotal24h,
		"cve_by_type_24h":                         ds.CVEByType,
		"drop_total_24h":                          ds.DropTotal24h,
		"drop_by_source_24h":                      ds.DropBySource,
	}
}

func BuildDashboardSnapshot(d *DashboardDeps) map[string]any {
	s := d.Metrics.Summary()
	rev, _ := store.CurrentRevision(d.ConfigDB)

	var cached dashboardDBStats
	if d.Cache != nil && d.Cache.GetJSON(dashboardCacheKey, &cached) {
		return buildDashboardResponse(s, rev, cached)
	}

	since24h := time.Now().Add(-24 * time.Hour)
	var uniqueVisitors24h int64
	d.LogDB.Model(&store.AccessLog{}).Distinct("client_ip").Where("created_at >= ?", since24h).Count(&uniqueVisitors24h)

	var humanVisits24h, botVisits24h, unclassifiedIntercept24h, visitKindTotal24h int64
	if d.AccessRepo != nil {
		// 复用 AccessLogRepo 的窗口聚合方法（LogDB 共享，保证关联一致）。
		// 口径二：三类正向枚举，缺表时 bot 恒为 0 但拦截类仍单独拆出。
		// 三类之和与 visit_kind_total_24h 的差额是「其他非安全类」动作，前端须标注。
		if stats, err := d.AccessRepo.VisitorKindStatsGlobal(since24h); err == nil {
			humanVisits24h = stats.HumanVisits
			botVisits24h = stats.BotVisits
			unclassifiedIntercept24h = stats.UnclassifiedIntercept
			visitKindTotal24h = stats.TotalVisits
		}
	}

	var visitorFusionTotal24h, visitorFusionHuman24h, visitorFusionBot24h, visitorFusionUnknown24h int64
	visitorFusionWindow := "created_at >= ? AND visitor_fusion_evidence_sufficient = ?"
	d.LogDB.Model(&store.AccessLog{}).Where(visitorFusionWindow, since24h, true).Count(&visitorFusionTotal24h)
	d.LogDB.Model(&store.AccessLog{}).Where(visitorFusionWindow+" AND visitor_fusion_class = ?", since24h, true, "human").Count(&visitorFusionHuman24h)
	d.LogDB.Model(&store.AccessLog{}).Where(visitorFusionWindow+" AND visitor_fusion_class = ?", since24h, true, "bot").Count(&visitorFusionBot24h)
	d.LogDB.Model(&store.AccessLog{}).Where(visitorFusionWindow+" AND visitor_fusion_class = ?", since24h, true, "unknown").Count(&visitorFusionUnknown24h)

	var botTotal24h, botBlocked24h, botHighRisk24h int64
	d.LogDB.Model(&store.BotScoreLog{}).Where("created_at >= ?", since24h).Count(&botTotal24h)
	d.LogDB.Model(&store.BotScoreLog{}).Where("created_at >= ? AND action IN ('block','drop')", since24h).Count(&botBlocked24h)
	d.LogDB.Model(&store.BotScoreLog{}).Where("created_at >= ? AND is_high_risk = ?", since24h, true).Count(&botHighRisk24h)

	var cveTotal24h int64
	d.LogDB.Model(&store.SecurityEvent{}).Where("created_at >= ? AND category = 'cve'", since24h).Count(&cveTotal24h)

	var cveByType []cveCatStat
	d.LogDB.Model(&store.SecurityEvent{}).
		Select("phase as category, COUNT(*) as count").
		Where("created_at >= ? AND category = 'cve'", since24h).
		Group("phase").
		Scan(&cveByType)

	var dropTotal24h, dropByBot, dropByCVE, dropByRule, dropByIPRep int64
	d.LogDB.Model(&store.DropEvent{}).Where("created_at >= ?", since24h).Count(&dropTotal24h)
	d.LogDB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'bot'", since24h).Count(&dropByBot)
	d.LogDB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'cve'", since24h).Count(&dropByCVE)
	d.LogDB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'rule'", since24h).Count(&dropByRule)
	d.LogDB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'ip_reputation'", since24h).Count(&dropByIPRep)

	stats := dashboardDBStats{
		UniqueVisitors24h: uniqueVisitors24h,
		HumanVisits24h:    humanVisits24h,
		BotVisits24h:      botVisits24h,

		UnclassifiedIntercept24h: unclassifiedIntercept24h,
		VisitKindTotal24h:        visitKindTotal24h,

		VisitorFusionHTTPSReleasedTotal24h: visitorFusionTotal24h,
		VisitorFusionHuman24h:              visitorFusionHuman24h,
		VisitorFusionBot24h:                visitorFusionBot24h,
		VisitorFusionUnknown24h:            visitorFusionUnknown24h,
		BotTotal24h:                        botTotal24h,
		BotBlocked24h:                      botBlocked24h,
		BotHighRisk24h:                     botHighRisk24h,
		CVETotal24h:                        cveTotal24h,
		CVEByType:                          cveByType,
		DropTotal24h:                       dropTotal24h,
		DropBySource: map[string]int64{
			"bot":           dropByBot,
			"cve":           dropByCVE,
			"rule":          dropByRule,
			"ip_reputation": dropByIPRep,
		},
	}

	if d.Cache != nil {
		_ = d.Cache.SetJSON(dashboardCacheKey, stats, dashboardCacheTTL)
	}
	return buildDashboardResponse(s, rev, stats)
}
