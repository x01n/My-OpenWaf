package system

import (
	"context"
	"fmt"
	"sync"
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

	localCacheMu        sync.Mutex
	localCacheStats     dashboardDBStats
	localCacheExpiresAt time.Time
	localCacheRetryAt   time.Time
	localCacheValid     bool
}

const dashboardCacheKey = "dashboard:summary"
const dashboardCacheTTL = 30 * time.Second
const dashboardCacheFailureBackoff = 2 * time.Second

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

type dashboardVisitorFusionStats struct {
	Total   int64
	Human   int64
	Bot     int64
	Unknown int64
}

type dashboardBotStats struct {
	Total    int64
	Blocked  int64
	HighRisk int64
}

type dashboardDropStats struct {
	Total        int64
	Bot          int64
	CVE          int64
	Rule         int64
	IPReputation int64
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

	now := time.Now()
	d.localCacheMu.Lock()
	defer d.localCacheMu.Unlock()
	if d.localCacheValid && now.Before(d.localCacheExpiresAt) {
		return buildDashboardResponse(s, rev, d.localCacheStats)
	}
	if d.localCacheValid && now.Before(d.localCacheRetryAt) {
		return buildDashboardResponse(s, rev, d.localCacheStats)
	}

	var cached dashboardDBStats
	if d.Cache != nil && d.Cache.Available() && d.Cache.GetJSON(dashboardCacheKey, &cached) {
		d.localCacheStats = cached
		d.localCacheExpiresAt = now.Add(dashboardCacheTTL)
		d.localCacheRetryAt = time.Time{}
		d.localCacheValid = true
		return buildDashboardResponse(s, rev, cached)
	}

	stats, err := loadDashboardDBStats(d, now.Add(-24*time.Hour))
	if err != nil {
		if d.localCacheValid {
			d.localCacheRetryAt = now.Add(dashboardCacheFailureBackoff)
			return buildDashboardResponse(s, rev, d.localCacheStats)
		}
		return buildDashboardResponse(s, rev, dashboardDBStats{})
	}

	d.localCacheStats = stats
	d.localCacheExpiresAt = now.Add(dashboardCacheTTL)
	d.localCacheRetryAt = time.Time{}
	d.localCacheValid = true
	if d.Cache != nil && d.Cache.Available() {
		_ = d.Cache.SetJSON(dashboardCacheKey, stats, dashboardCacheTTL)
	}
	return buildDashboardResponse(s, rev, stats)
}

// loadDashboardVisitorFusionStats 把同一时间窗口内的四个访客融合计数合并为一条
// CASE 聚合，避免 Dashboard 冷读为每个分类重复扫描 access_logs。
func loadDashboardVisitorFusionStats(db *gorm.DB, since time.Time) (dashboardVisitorFusionStats, error) {
	var stats dashboardVisitorFusionStats
	err := db.Model(&store.AccessLog{}).
		Select(`
			COALESCE(SUM(CASE WHEN visitor_fusion_evidence_sufficient = ? THEN 1 ELSE 0 END), 0) AS total,
			COALESCE(SUM(CASE WHEN visitor_fusion_evidence_sufficient = ? AND visitor_fusion_class = ? THEN 1 ELSE 0 END), 0) AS human,
			COALESCE(SUM(CASE WHEN visitor_fusion_evidence_sufficient = ? AND visitor_fusion_class = ? THEN 1 ELSE 0 END), 0) AS bot,
			COALESCE(SUM(CASE WHEN visitor_fusion_evidence_sufficient = ? AND visitor_fusion_class = ? THEN 1 ELSE 0 END), 0) AS unknown`,
			true, true, "human", true, "bot", true, "unknown").
		Where("created_at >= ?", since).
		Scan(&stats).Error
	return stats, err
}

// loadDashboardBotStats 把 BotScoreLog 的总量、拦截量和高风险量合并为一次扫描。
func loadDashboardBotStats(db *gorm.DB, since time.Time) (dashboardBotStats, error) {
	var stats dashboardBotStats
	err := db.Model(&store.BotScoreLog{}).
		Select(`
			COUNT(*) AS total,
			COALESCE(SUM(CASE WHEN action IN ('block', 'drop') THEN 1 ELSE 0 END), 0) AS blocked,
			COALESCE(SUM(CASE WHEN is_high_risk = ? THEN 1 ELSE 0 END), 0) AS high_risk`, true).
		Where("created_at >= ?", since).
		Scan(&stats).Error
	return stats, err
}

// loadDashboardDropStats 把 DropEvent 各来源统计合并为一次条件聚合。
func loadDashboardDropStats(db *gorm.DB, since time.Time) (dashboardDropStats, error) {
	var stats dashboardDropStats
	err := db.Model(&store.DropEvent{}).
		Select(`
			COUNT(*) AS total,
			COALESCE(SUM(CASE WHEN source = ? THEN 1 ELSE 0 END), 0) AS bot,
			COALESCE(SUM(CASE WHEN source = ? THEN 1 ELSE 0 END), 0) AS cve,
			COALESCE(SUM(CASE WHEN source = ? THEN 1 ELSE 0 END), 0) AS rule,
			COALESCE(SUM(CASE WHEN source = ? THEN 1 ELSE 0 END), 0) AS ip_reputation`,
			"bot", "cve", "rule", "ip_reputation").
		Where("created_at >= ?", since).
		Scan(&stats).Error
	return stats, err
}

func loadDashboardDBStats(d *DashboardDeps, since24h time.Time) (dashboardDBStats, error) {
	var uniqueVisitors24h int64
	if err := d.LogDB.Model(&store.AccessLog{}).Distinct("client_ip").Where("created_at >= ?", since24h).Count(&uniqueVisitors24h).Error; err != nil {
		return dashboardDBStats{}, fmt.Errorf("count unique visitors: %w", err)
	}

	var humanVisits24h, botVisits24h, unclassifiedIntercept24h, visitKindTotal24h int64
	if d.AccessRepo != nil {
		// 复用 AccessLogRepo 的窗口聚合方法（LogDB 共享，保证关联一致）。
		// 口径二：三类正向枚举，缺表时 bot 恒为 0 但拦截类仍单独拆出。
		// 三类之和与 visit_kind_total_24h 的差额是「其他非安全类」动作，前端须标注。
		stats, err := d.AccessRepo.VisitorKindStatsGlobal(since24h)
		if err != nil {
			return dashboardDBStats{}, fmt.Errorf("aggregate visitor kinds: %w", err)
		}
		humanVisits24h = stats.HumanVisits
		botVisits24h = stats.BotVisits
		unclassifiedIntercept24h = stats.UnclassifiedIntercept
		visitKindTotal24h = stats.TotalVisits
	}

	visitorFusion, err := loadDashboardVisitorFusionStats(d.LogDB, since24h)
	if err != nil {
		return dashboardDBStats{}, fmt.Errorf("aggregate visitor fusion: %w", err)
	}

	botStats, err := loadDashboardBotStats(d.LogDB, since24h)
	if err != nil {
		return dashboardDBStats{}, fmt.Errorf("aggregate bot scores: %w", err)
	}

	var cveTotal24h int64
	if err := d.LogDB.Model(&store.SecurityEvent{}).Where("created_at >= ? AND category = 'cve'", since24h).Count(&cveTotal24h).Error; err != nil {
		return dashboardDBStats{}, fmt.Errorf("count CVE events: %w", err)
	}

	var cveByType []cveCatStat
	if err := d.LogDB.Model(&store.SecurityEvent{}).
		Select("phase as category, COUNT(*) as count").
		Where("created_at >= ? AND category = 'cve'", since24h).
		Group("phase").
		Scan(&cveByType).Error; err != nil {
		return dashboardDBStats{}, fmt.Errorf("group CVE events: %w", err)
	}

	dropStats, err := loadDashboardDropStats(d.LogDB, since24h)
	if err != nil {
		return dashboardDBStats{}, fmt.Errorf("aggregate drops: %w", err)
	}

	return dashboardDBStats{
		UniqueVisitors24h: uniqueVisitors24h,
		HumanVisits24h:    humanVisits24h,
		BotVisits24h:      botVisits24h,

		UnclassifiedIntercept24h: unclassifiedIntercept24h,
		VisitKindTotal24h:        visitKindTotal24h,

		VisitorFusionHTTPSReleasedTotal24h: visitorFusion.Total,
		VisitorFusionHuman24h:              visitorFusion.Human,
		VisitorFusionBot24h:                visitorFusion.Bot,
		VisitorFusionUnknown24h:            visitorFusion.Unknown,
		BotTotal24h:                        botStats.Total,
		BotBlocked24h:                      botStats.Blocked,
		BotHighRisk24h:                     botStats.HighRisk,
		CVETotal24h:                        cveTotal24h,
		CVEByType:                          cveByType,
		DropTotal24h:                       dropStats.Total,
		DropBySource: map[string]int64{
			"bot":           dropStats.Bot,
			"cve":           dropStats.CVE,
			"rule":          dropStats.Rule,
			"ip_reputation": dropStats.IPReputation,
		},
	}, nil
}
