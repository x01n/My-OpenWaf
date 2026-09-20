package system

import (
	"context"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store/repository"
)

const maxAPIKeyNameBytes = 128

type createKeyBody struct {
	Name string `json:"name"`
}

func ListAPIKeys(repo *repository.AdminAPIKeyRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		items, err := repo.List()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items})
	}
}

func CreateAPIKey(repo *repository.AdminAPIKeyRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var body createKeyBody
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		body.Name = strings.TrimSpace(body.Name)
		if body.Name == "" {
			body.Name = "unnamed"
		}
		if len([]byte(body.Name)) > maxAPIKeyNameBytes {
			c.JSON(400, map[string]string{"error": "name exceeds 128 bytes"})
			return
		}
		token, key, err := repo.Create(body.Name)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(201, map[string]any{"token": token, "id": key.ID, "name": key.Name})
	}
}

func DeleteAPIKey(repo *repository.AdminAPIKeyRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if _, err := repo.Get(id); err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		if err := repo.Delete(id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}
