package admin

import (
	"context"
	"time"

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

		// Bot stats (24h)
		since24h := time.Now().Add(-24 * time.Hour)
		var botTotal24h, botBlocked24h, botHighRisk24h int64
		d.DB.Model(&store.BotScoreLog{}).Where("created_at >= ?", since24h).Count(&botTotal24h)
		d.DB.Model(&store.BotScoreLog{}).Where("created_at >= ? AND action IN ('block','drop')", since24h).Count(&botBlocked24h)
		d.DB.Model(&store.BotScoreLog{}).Where("created_at >= ? AND is_high_risk = ?", since24h, true).Count(&botHighRisk24h)

		// CVE stats (24h) - count from security events with category 'cve'
		var cveTotal24h int64
		d.DB.Model(&store.SecurityEvent{}).Where("created_at >= ? AND category = 'cve'", since24h).Count(&cveTotal24h)

		type cveCategoryStat struct {
			Category string `json:"category"`
			Count    int64  `json:"count"`
		}
		var cveByType []cveCategoryStat
		d.DB.Model(&store.SecurityEvent{}).
			Select("phase as category, COUNT(*) as count").
			Where("created_at >= ? AND category = 'cve'", since24h).
			Group("phase").
			Scan(&cveByType)

		// Drop stats (24h)
		var dropTotal24h, dropByBot, dropByCVE, dropByRule, dropByIPRep int64
		d.DB.Model(&store.DropEvent{}).Where("created_at >= ?", since24h).Count(&dropTotal24h)
		d.DB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'bot'", since24h).Count(&dropByBot)
		d.DB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'cve'", since24h).Count(&dropByCVE)
		d.DB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'rule'", since24h).Count(&dropByRule)
		d.DB.Model(&store.DropEvent{}).Where("created_at >= ? AND source = 'ip_reputation'", since24h).Count(&dropByIPRep)

		// Fingerprint anomaly count (unknown fingerprints seen recently)
		var fpAnomalyCount int64
		d.DB.Model(&store.FingerprintRecord{}).Where("is_known_good = ? AND last_seen >= ?", false, since24h).Count(&fpAnomalyCount)

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
			// Bot detection stats
			"bot_total_24h":     botTotal24h,
			"bot_blocked_24h":   botBlocked24h,
			"bot_high_risk_24h": botHighRisk24h,
			// CVE attack stats
			"cve_total_24h":   cveTotal24h,
			"cve_by_type_24h": cveByType,
			// Drop stats
			"drop_total_24h": dropTotal24h,
			"drop_by_source_24h": map[string]int64{
				"bot":           dropByBot,
				"cve":           dropByCVE,
				"rule":          dropByRule,
				"ip_reputation": dropByIPRep,
			},
			// Fingerprint anomalies
			"fingerprint_anomaly_24h": fpAnomalyCount,
		})
	}
}
