package event

import (
	"context"
	"strconv"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

func ListSecurityEvents(repo *repository.SecurityEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(string(c.Query("page")))
		pageSize, _ := strconv.Atoi(string(c.Query("page_size")))
		offset, limit := utils.Paginate(page, pageSize)

		f := repository.SecurityEventFilter{
			RequestID:   string(c.Query("request_id")),
			Action:      string(c.Query("action")),
			Phase:       string(c.Query("phase")),
			Category:    string(c.Query("category")),
			ClientIP:    string(c.Query("client_ip")),
			Host:        string(c.Query("host")),
			Path:        string(c.Query("path")),
			RuleIDStr:   string(c.Query("rule_id_str")),
			TLSVersion:  string(c.Query("tls_version")),
			TLSSNI:      string(c.Query("tls_sni")),
			TLSALPN:     string(c.Query("tls_alpn")),
			TLSJA3Hash:  string(c.Query("tls_ja3_hash")),
			TLSJA4:      string(c.Query("tls_ja4")),
			HeaderOrder: string(c.Query("header_order")),
		}
		if id := string(c.Query("id")); id != "" {
			if v, err := strconv.ParseUint(id, 10, 64); err == nil {
				f.ID = uint(v)
			}
		}
		if rid := string(c.Query("rule_id")); rid != "" {
			if v, err := strconv.ParseUint(rid, 10, 64); err == nil {
				f.RuleID = uint(v)
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
		c.JSON(200, map[string]any{
			"items": items,
			"total": total,
			"page":  page,
		})
	}
}

func GetSecurityEvent(repo *repository.SecurityEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		item, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "event not found"})
			return
		}
		c.JSON(200, item)
	}
}

func ListSiteSecurityEvents(siteRepo *repository.SiteRepo, repo *repository.SecurityEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		site, err := siteRepo.Get(siteID)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		page, _ := strconv.Atoi(string(c.Query("page")))
		pageSize, _ := strconv.Atoi(string(c.Query("page_size")))
		offset, limit := utils.Paginate(page, pageSize)
		f := repository.SecurityEventFilter{
			RequestID:   string(c.Query("request_id")),
			Action:      string(c.Query("action")),
			Phase:       string(c.Query("phase")),
			Category:    string(c.Query("category")),
			ClientIP:    string(c.Query("client_ip")),
			Path:        string(c.Query("path")),
			Host:        site.Host,
			TLSVersion:  string(c.Query("tls_version")),
			TLSSNI:      string(c.Query("tls_sni")),
			TLSALPN:     string(c.Query("tls_alpn")),
			TLSJA3Hash:  string(c.Query("tls_ja3_hash")),
			TLSJA4:      string(c.Query("tls_ja4")),
			HeaderOrder: string(c.Query("header_order")),
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
		items, total, err := repo.ListBySite(siteID, offset, limit, f)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page})
	}
}

func SiteSecurityEventStats(siteRepo *repository.SiteRepo, repo *repository.SecurityEventRepo) app.HandlerFunc {
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
		hours := 24
		if h := string(c.Query("hours")); h != "" {
			if v, err := strconv.Atoi(h); err == nil && v > 0 {
				hours = v
			}
		}
		since := time.Now().Add(-time.Duration(hours) * time.Hour)
		categories, _ := repo.CategoryStatsBySite(siteID, since)
		topIPs, _ := repo.TopIPsBySite(siteID, since, 10)
		topPaths, _ := repo.TopPathsBySite(siteID, since, 10)
		topRules, _ := repo.TopRulesBySite(siteID, since, 10)
		total, _ := repo.CountBySite(siteID, repository.SecurityEventFilter{Since: &since})
		intercepts, _ := repo.CountTerminalBySite(siteID, since)
		observes, _ := repo.CountObserveBySite(siteID, since)
		requestCount, _ := repo.DistinctRequestCountBySite(siteID, since)
		challenges, _ := repo.CountChallengeBySite(siteID, since)
		c.JSON(200, map[string]any{
			"total":      total,
			"hours":      hours,
			"categories": categories,
			"top_ips":    topIPs,
			"top_paths":  topPaths,
			"top_rules":  topRules,
			"intercepts": intercepts,
			"observes":   observes,
			"requests":   requestCount,
			"challenges": challenges,
		})
	}
}

func SiteSecurityEventTimeline(siteRepo *repository.SiteRepo, repo *repository.SecurityEventRepo) app.HandlerFunc {
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
		hours := 24
		if h := string(c.Query("hours")); h != "" {
			if v, err := strconv.Atoi(h); err == nil && v > 0 {
				hours = v
			}
		}
		until := time.Now()
		since := until.Add(-time.Duration(hours) * time.Hour)
		buckets, err := repo.TimelineBySite(siteID, since, until)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"buckets": buckets, "hours": hours})
	}
}

func SecurityEventStats(repo *repository.SecurityEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		hours := 24
		if h := string(c.Query("hours")); h != "" {
			if v, err := strconv.Atoi(h); err == nil && v > 0 {
				hours = v
			}
		}
		since := time.Now().Add(-time.Duration(hours) * time.Hour)

		categories, _ := repo.CategoryStats(since)
		topIPs, _ := repo.TopIPs(since, 10)
		topPaths, _ := repo.TopPaths(since, 10)
		topRules, _ := repo.TopRules(since, 10)

		total, _ := repo.Count(repository.SecurityEventFilter{Since: &since})
		intercepts, _ := repo.CountTerminal(since)
		observes, _ := repo.CountObserve(since)
		requestCount, _ := repo.DistinctRequestCount(since)
		challenges, _ := repo.CountChallenge(since)

		c.JSON(200, map[string]any{
			"total":      total,
			"hours":      hours,
			"categories": categories,
			"top_ips":    topIPs,
			"top_paths":  topPaths,
			"top_rules":  topRules,
			"intercepts": intercepts,
			"observes":   observes,
			"requests":   requestCount,
			"challenges": challenges,
		})
	}
}

func SecurityEventTimeline(repo *repository.SecurityEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		hours := 24
		if h := string(c.Query("hours")); h != "" {
			if v, err := strconv.Atoi(h); err == nil && v > 0 {
				hours = v
			}
		}
		until := time.Now()
		since := until.Add(-time.Duration(hours) * time.Hour)

		buckets, err := repo.Timeline(since, until)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{
			"buckets": buckets,
			"hours":   hours,
		})
	}
}
