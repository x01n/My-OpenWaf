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

func ListAccessLogs(repo *repository.AccessLogRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, pageSize)

		f := repository.AccessLogFilter{
			Query:           string(c.Query("q")),
			RequestID:       string(c.Query("request_id")),
			ClientIP:        string(c.Query("client_ip")),
			Host:            string(c.Query("host")),
			Path:            string(c.Query("path")),
			QueryString:     string(c.Query("query_string")),
			Method:          string(c.Query("method")),
			WAFAction:       string(c.Query("waf_action")),
			CacheState:      string(c.Query("cache_state")),
			StatusGroup:     string(c.Query("status_group")),
			TLSVersion:      string(c.Query("tls_version")),
			TLSSNI:          string(c.Query("tls_sni")),
			TLSALPN:         string(c.Query("tls_alpn")),
			TLSJA3Hash:      string(c.Query("tls_ja3_hash")),
			TLSJA4:          string(c.Query("tls_ja4")),
			TLSCipherSuites: string(c.Query("tls_cipher_suites")),
			TLSExtensions:   string(c.Query("tls_extensions")),
			TLSCurves:       string(c.Query("tls_curves")),
			TLSPointFormats: string(c.Query("tls_point_formats")),
		}
		if id := string(c.Query("id")); id != "" {
			if v, err := strconv.ParseUint(id, 10, 64); err == nil {
				f.ID = uint(v)
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

		items, total, err := repo.List(offset, limit, f)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page})
	}
}

func GetAccessLog(repo *repository.AccessLogRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		item, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "access log not found"})
			return
		}
		c.JSON(200, item)
	}
}

func ListTLSFingerprints(repo *repository.AccessLogRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, pageSize)

		filter := repository.FingerprintFilter{
			TLSJA3Hash:      string(c.Query("tls_ja3_hash")),
			TLSJA4:          string(c.Query("tls_ja4")),
			TLSVersion:      string(c.Query("tls_version")),
			TLSALPN:         string(c.Query("tls_alpn")),
			TLSSNI:          string(c.Query("tls_sni")),
			TLSCipherSuites: string(c.Query("tls_cipher_suites")),
			TLSExtensions:   string(c.Query("tls_extensions")),
			TLSCurves:       string(c.Query("tls_curves")),
			TLSPointFormats: string(c.Query("tls_point_formats")),
		}

		items, total, err := repo.ListFingerprints(offset, limit, filter)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page})
	}
}
