package system

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

func ListIPEntries(repo *repository.IPListRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(string(c.Query("page")))
		pageSize, _ := strconv.Atoi(string(c.Query("page_size")))
		offset, limit := utils.Paginate(page, pageSize)
		kind := string(c.Query("kind"))

		var siteID *uint
		if raw := string(c.Query("site_id")); raw != "" {
			if v, err := strconv.ParseUint(raw, 10, 64); err == nil {
				sid := uint(v)
				siteID = &sid
			}
		}

		items, total, err := repo.List(offset, limit, kind, siteID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page})
	}
}

func GetIPEntry(repo *repository.IPListRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		item, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		c.JSON(200, item)
	}
}

func CreateIPEntry(repo *repository.IPListRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var body store.IPListEntry
		// 先填模型声明的默认值，再让请求体覆盖：json 只写出现过的字段，
		// 这样「未提供」保留默认值，「显式传 false/0」才能如实落库。
		_ = store.ApplyModelDefaults(&body)
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if body.Kind != store.IPListBlack && body.Kind != store.IPListWhite {
			c.JSON(400, map[string]string{"error": "kind must be blacklist or whitelist"})
			return
		}
		if !validIPListValue(body.Value) {
			c.JSON(400, map[string]string{"error": "value must be a valid IP address or CIDR"})
			return
		}
		normalized, ok := normalizeIPListAction(body.Action)
		if !ok {
			c.JSON(400, map[string]string{"error": "action must be intercept or drop"})
			return
		}
		body.Action = normalized
		if body.Kind == store.IPListWhite {
			body.Action = "intercept"
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

func UpdateIPEntry(repo *repository.IPListRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		existing, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		var body struct {
			Kind    *store.IPListKind `json:"kind"`
			Value   *string           `json:"value"`
			Note    *string           `json:"note"`
			Enabled *bool             `json:"enabled"`
			Action  *string           `json:"action"`
			SiteID  json.RawMessage   `json:"site_id"`
		}
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if body.Kind != nil {
			existing.Kind = *body.Kind
		}
		if existing.Kind != store.IPListBlack && existing.Kind != store.IPListWhite {
			c.JSON(400, map[string]string{"error": "kind must be blacklist or whitelist"})
			return
		}
		if body.Value != nil {
			existing.Value = *body.Value
		}
		if !validIPListValue(existing.Value) {
			c.JSON(400, map[string]string{"error": "value must be a valid IP address or CIDR"})
			return
		}
		if body.Note != nil {
			existing.Note = *body.Note
		}
		if body.Enabled != nil {
			existing.Enabled = *body.Enabled
		}
		if body.Action != nil {
			if normalized, ok := normalizeIPListAction(*body.Action); ok {
				existing.Action = normalized
			} else {
				c.JSON(400, map[string]string{"error": "action must be intercept or drop"})
				return
			}
		}
		if existing.Kind == store.IPListWhite {
			existing.Action = "intercept"
		}
		if present, siteID, scopeErr := parseSiteScope(body.SiteID); scopeErr != nil {
			c.JSON(400, map[string]string{"error": scopeErr.Error()})
			return
		} else if present {
			existing.SiteID = siteID
		}
		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": existing})
			return
		}
		c.JSON(200, existing)
	}
}

func normalizeIPListAction(action string) (string, bool) {
	switch action {
	case "", "intercept":
		return "intercept", true
	case "drop", "block":
		return "drop", true
	default:
		return "", false
	}
}

func validIPListValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

func DeleteIPEntry(repo *repository.IPListRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if err := repo.Delete(id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}
