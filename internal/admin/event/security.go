package event

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

const (
	defaultSecurityEventAggregateHours = 24
	maxSecurityEventAggregateHours     = 24 * 30
)

/**
 * securityEventAggregateHours 解析统计窗口并限制为站点观测接口既有的 30 天上限。
 * 未提供参数时使用 24 小时；显式非法值返回错误，避免把 24 小时数据误报为调用方
 * 请求的更大窗口。
 */
func securityEventAggregateHours(c *app.RequestContext) (int, error) {
	raw := strings.TrimSpace(string(c.Query("hours")))
	if raw == "" {
		return defaultSecurityEventAggregateHours, nil
	}
	hours, err := strconv.Atoi(raw)
	if err != nil || hours <= 0 || hours > maxSecurityEventAggregateHours {
		return 0, errors.New("hours must be between 1 and 720")
	}
	return hours, nil
}

func ListSecurityEvents(repo *repository.SecurityEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(string(c.Query("page")))
		pageSize, _ := strconv.Atoi(string(c.Query("page_size")))
		offset, limit := utils.Paginate(page, pageSize)

		items, total, err := repo.List(offset, limit, securityEventFilterFromQuery(c))
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

/**
 * ListSecurityEventRequests 返回按 request_id 聚合的请求级安全事件列表。
 *
 * 与 ListSecurityEvents 共用同一套筛选参数解析，避免两个列表的筛选面漂移；
 * total 为去重后的请求数，而非事件条数。
 */
func ListSecurityEventRequests(repo *repository.SecurityEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(string(c.Query("page")))
		pageSize, _ := strconv.Atoi(string(c.Query("page_size")))
		offset, limit := utils.Paginate(page, pageSize)

		items, total, err := repo.ListRequests(offset, limit, securityEventFilterFromQuery(c))
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

/**
 * securityEventFilterFromQuery 从查询串解析全局安全事件筛选条件。
 *
 * 站点级列表（ListSiteSecurityEvents）的字段集与此不同（无 id/rule_id/site_id/
 * rule_id_str），故不复用该函数。
 */
func securityEventFilterFromQuery(c *app.RequestContext) repository.SecurityEventFilter {
	f := repository.SecurityEventFilter{
		Query:           string(c.Query("q")),
		RequestID:       string(c.Query("request_id")),
		Action:          string(c.Query("action")),
		Phase:           string(c.Query("phase")),
		Category:        string(c.Query("category")),
		ClientIP:        string(c.Query("client_ip")),
		Host:            string(c.Query("host")),
		Path:            string(c.Query("path")),
		QueryString:     string(c.Query("query_string")),
		RuleIDStr:       string(c.Query("rule_id_str")),
		TLSVersion:      string(c.Query("tls_version")),
		TLSSNI:          string(c.Query("tls_sni")),
		TLSALPN:         string(c.Query("tls_alpn")),
		TLSJA3Hash:      string(c.Query("tls_ja3_hash")),
		TLSJA4:          string(c.Query("tls_ja4")),
		TLSCipherSuites: string(c.Query("tls_cipher_suites")),
		TLSExtensions:   string(c.Query("tls_extensions")),
		TLSCurves:       string(c.Query("tls_curves")),
		TLSPointFormats: string(c.Query("tls_point_formats")),
		HeaderOrder:     string(c.Query("header_order")),
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
	return f
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
		if _, err := siteRepo.Get(siteID); err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		page, _ := strconv.Atoi(string(c.Query("page")))
		pageSize, _ := strconv.Atoi(string(c.Query("page_size")))
		offset, limit := utils.Paginate(page, pageSize)
		f := repository.SecurityEventFilter{
			Query:           string(c.Query("q")),
			RequestID:       string(c.Query("request_id")),
			Action:          string(c.Query("action")),
			Phase:           string(c.Query("phase")),
			Category:        string(c.Query("category")),
			ClientIP:        string(c.Query("client_ip")),
			Path:            string(c.Query("path")),
			QueryString:     string(c.Query("query_string")),
			Host:            string(c.Query("host")),
			TLSVersion:      string(c.Query("tls_version")),
			TLSSNI:          string(c.Query("tls_sni")),
			TLSALPN:         string(c.Query("tls_alpn")),
			TLSJA3Hash:      string(c.Query("tls_ja3_hash")),
			TLSJA4:          string(c.Query("tls_ja4")),
			TLSCipherSuites: string(c.Query("tls_cipher_suites")),
			TLSExtensions:   string(c.Query("tls_extensions")),
			TLSCurves:       string(c.Query("tls_curves")),
			TLSPointFormats: string(c.Query("tls_point_formats")),
			HeaderOrder:     string(c.Query("header_order")),
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
		hours, err := securityEventAggregateHours(c)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		snapshot, err := repo.StatsSnapshotBySite(siteID, hours)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, snapshot)
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
		hours, err := securityEventAggregateHours(c)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		buckets, err := repo.TimelineSnapshotBySite(siteID, hours)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"buckets": buckets, "hours": hours})
	}
}

func SecurityEventStats(repo *repository.SecurityEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		hours, err := securityEventAggregateHours(c)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		snapshot, err := repo.StatsSnapshot(hours)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, snapshot)
	}
}

func SecurityEventTimeline(repo *repository.SecurityEventRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		hours, err := securityEventAggregateHours(c)
		if err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		buckets, err := repo.TimelineSnapshot(hours)
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
