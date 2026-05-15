package admin

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

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

func ListApplicationRouteRules(siteRepo *repository.SiteRepo, repo *repository.ApplicationRouteRuleRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := parseUintParam(c, "id")
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
		siteID, err := parseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if _, err := siteRepo.Get(siteID); err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		var body store.ApplicationRouteRule
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		body.SiteID = siteID
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
			c.JSON(500, map[string]any{"error": "saved but reload failed: " + err.Error(), "item": body})
			return
		}
		c.JSON(201, body)
	}
}

func UpdateApplicationRouteRule(siteRepo *repository.SiteRepo, repo *repository.ApplicationRouteRuleRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := parseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		ruleID, err := parseUintParam(c, "rid")
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
		var body store.ApplicationRouteRule
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		body.ID = ruleID
		body.SiteID = siteID
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
			c.JSON(500, map[string]any{"error": "saved but reload failed: " + err.Error(), "item": body})
			return
		}
		c.JSON(200, body)
	}
}

func DeleteApplicationRouteRule(siteRepo *repository.SiteRepo, repo *repository.ApplicationRouteRuleRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := parseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		ruleID, err := parseUintParam(c, "rid")
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
			c.JSON(500, map[string]string{"error": "deleted but reload failed: " + err.Error()})
			return
		}
		c.JSON(200, map[string]string{"status": "ok"})
	}
}

func ListRecordedResources(siteRepo *repository.SiteRepo, repo *repository.RecordedResourceRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := parseUintParam(c, "id")
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
		items, total, err := repo.ListBySite(siteID, offset, limit)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page})
	}
}

func ClearRecordedResources(siteRepo *repository.SiteRepo, repo *repository.RecordedResourceRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := parseUintParam(c, "id")
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
