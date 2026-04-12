package admin

import (
	"context"
	"strconv"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

func ListForwardingProfiles(repo *repository.ForwardingProfileRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, size)
		items, total, err := repo.List(offset, limit)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": total})
	}
}

func GetForwardingProfile(repo *repository.ForwardingProfileRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
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

func CreateForwardingProfile(repo *repository.ForwardingProfileRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var item store.ForwardingProfile
		if err := c.BindJSON(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.Create(&item); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		_ = reload()
		c.JSON(201, item)
	}
}

func UpdateForwardingProfile(repo *repository.ForwardingProfileRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		existing, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "not found"})
			return
		}
		if err := c.BindJSON(existing); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		existing.ID = id
		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		_ = reload()
		c.JSON(200, existing)
	}
}

func DeleteForwardingProfile(repo *repository.ForwardingProfileRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if err := repo.Delete(id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		_ = reload()
		c.JSON(204, nil)
	}
}
