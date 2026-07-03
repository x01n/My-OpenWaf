package rule

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

func validAppRouteTarget(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case store.AppRouteTargetRequestHeader,
		store.AppRouteTargetRequestBody,
		store.AppRouteTargetResponseBody,
		store.AppRouteTargetRequestHeadersFull,
		store.AppRouteTargetResponseHeadersFull,
		store.AppRouteTargetFullHTTPRequest,
		store.AppRouteTargetFullHTTPResponse,
		store.AppRouteTargetRequestMethod,
		store.AppRouteTargetFingerprint:
		return true
	default:
		return false
	}
}

func validAppRouteOp(op string) bool {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case store.AppRouteOpEq,
		store.AppRouteOpNe,
		store.AppRouteOpContains,
		store.AppRouteOpNotContains,
		store.AppRouteOpPrefix,
		store.AppRouteOpSuffix,
		store.AppRouteOpRegex,
		store.AppRouteOpFuzzy:
		return true
	default:
		return false
	}
}

func validateApplicationRouteRule(r *store.ApplicationRouteRule) error {
	if r == nil {
		return errors.New("nil rule")
	}
	if !validAppRouteTarget(r.Target) {
		return errors.New("invalid target")
	}
	if !validAppRouteOp(r.Op) {
		return errors.New("invalid op")
	}
	if strings.TrimSpace(r.Pattern) == "" {
		return errors.New("pattern required")
	}
	if strings.EqualFold(strings.TrimSpace(r.Target), store.AppRouteTargetRequestHeader) {
		if strings.TrimSpace(r.HeaderKey) == "" {
			return errors.New("header_key required for request_header target")
		}
	}
	return nil
}

type applicationRouteRuleRequest struct {
	Name      string `json:"name"`
	Enabled   *bool  `json:"enabled"`
	Priority  int    `json:"priority"`
	Target    string `json:"target"`
	Op        string `json:"op"`
	Pattern   string `json:"pattern"`
	HeaderKey string `json:"header_key"`
}

func (req applicationRouteRuleRequest) toStore(siteID uint, defaultEnabled bool) store.ApplicationRouteRule {
	enabled := defaultEnabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return store.ApplicationRouteRule{
		SiteID:    siteID,
		Name:      req.Name,
		Enabled:   enabled,
		Priority:  req.Priority,
		Target:    req.Target,
		Op:        req.Op,
		Pattern:   req.Pattern,
		HeaderKey: req.HeaderKey,
	}
}

func ListApplicationRouteRules(siteRepo *repository.SiteRepo, repo *repository.ApplicationRouteRuleRepo) app.HandlerFunc {
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
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
		offset, limit := utils.Paginate(page, pageSize)
		items, total, err := repo.ListBySitePaged(siteID, offset, limit)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page})
	}
}

func CreateApplicationRouteRule(siteRepo *repository.SiteRepo, repo *repository.ApplicationRouteRuleRepo, reload func() error) app.HandlerFunc {
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
		var req applicationRouteRuleRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		body := req.toStore(siteID, true)
		body.ID = 0
		if err := validateApplicationRouteRule(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.Create(&body); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": body})
			return
		}
		c.JSON(201, body)
	}
}

func UpdateApplicationRouteRule(siteRepo *repository.SiteRepo, repo *repository.ApplicationRouteRuleRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		ruleID, err := shared.ParseUintParam(c, "rid")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid rule id"})
			return
		}
		if _, err := siteRepo.Get(siteID); err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		existing, err := repo.Get(ruleID)
		if err != nil || existing.SiteID != siteID {
			c.JSON(404, map[string]string{"error": "rule not found"})
			return
		}
		var req applicationRouteRuleRequest
		if err := c.BindJSON(&req); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		body := req.toStore(siteID, existing.Enabled)
		body.ID = ruleID
		body.CreatedAt = existing.CreatedAt
		if err := validateApplicationRouteRule(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.Update(&body); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": body})
			return
		}
		c.JSON(200, body)
	}
}

func DeleteApplicationRouteRule(siteRepo *repository.SiteRepo, repo *repository.ApplicationRouteRuleRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		ruleID, err := shared.ParseUintParam(c, "rid")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid rule id"})
			return
		}
		if _, err := siteRepo.Get(siteID); err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		existing, err := repo.Get(ruleID)
		if err != nil || existing.SiteID != siteID {
			c.JSON(404, map[string]string{"error": "rule not found"})
			return
		}
		if err := repo.Delete(ruleID); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]string{"status": "ok"})
	}
}

func ListRecordedResources(siteRepo *repository.SiteRepo, repo *repository.RecordedResourceRepo) app.HandlerFunc {
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
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
		var filter repository.RecordedResourceFilter
		filter.Query = strings.TrimSpace(c.Query("q"))
		filter.Method = strings.TrimSpace(c.Query("method"))
		filter.Host = strings.TrimSpace(c.Query("host"))
		filter.Path = strings.TrimSpace(c.Query("path"))
		filter.QueryString = strings.TrimSpace(c.Query("query_string"))
		filter.ClientIP = strings.TrimSpace(c.Query("client_ip"))
		filter.TLSVersion = strings.TrimSpace(c.Query("tls_version"))
		filter.TLSSNI = strings.TrimSpace(c.Query("tls_sni"))
		filter.TLSALPN = strings.TrimSpace(c.Query("tls_alpn"))
		filter.JA3Hash = strings.TrimSpace(c.Query("ja3_hash"))
		filter.JA4 = strings.TrimSpace(c.Query("ja4"))
		filter.UserAgent = strings.TrimSpace(c.Query("user_agent"))
		if raw := strings.TrimSpace(c.Query("status_code")); raw != "" {
			statusCode, parseErr := strconv.Atoi(raw)
			if parseErr != nil || statusCode <= 0 {
				c.JSON(400, map[string]string{"error": "invalid status_code"})
				return
			}
			filter.StatusCode = statusCode
		}
		if raw := strings.TrimSpace(c.Query("rule_id")); raw != "" {
			ruleID, parseErr := strconv.ParseUint(raw, 10, 64)
			if parseErr != nil || ruleID == 0 {
				c.JSON(400, map[string]string{"error": "invalid rule_id"})
				return
			}
			filter.RuleID = uint(ruleID)
		}
		offset, limit := utils.Paginate(page, pageSize)
		items, total, err := repo.ListBySite(siteID, offset, limit, filter)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page})
	}
}

func ClearRecordedResources(siteRepo *repository.SiteRepo, repo *repository.RecordedResourceRepo) app.HandlerFunc {
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
		if err := repo.ClearSite(siteID); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]string{"status": "ok"})
	}
}
