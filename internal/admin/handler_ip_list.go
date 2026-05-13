package admin

import (
	"context"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"

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

		items, total, err := repo.List(offset, limit, kind)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total, "page": page})
	}
}

func GetIPEntry(repo *repository.IPListRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := parseUintParam(c, "id")
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
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if body.Kind != store.IPListBlack && body.Kind != store.IPListWhite {
			c.JSON(400, map[string]string{"error": "kind must be blacklist or whitelist"})
			return
		}
		if body.Value == "" {
			c.JSON(400, map[string]string{"error": "value required"})
			return
		}
		if normalized, ok := normalizeIPListAction(body.Action); ok {
			body.Action = normalized
		} else {
			c.JSON(400, map[string]string{"error": "action must be intercept or drop"})
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

func UpdateIPEntry(repo *repository.IPListRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := parseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		existing, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		var body store.IPListEntry
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if normalized, ok := normalizeIPListAction(body.Action); ok {
			body.Action = normalized
		} else {
			c.JSON(400, map[string]string{"error": "action must be intercept or drop"})
			return
		}
		body.ID = existing.ID
		body.CreatedAt = existing.CreatedAt
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

func DeleteIPEntry(repo *repository.IPListRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := parseUintParam(c, "id")
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
