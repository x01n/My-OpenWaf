package admin

import (
	"context"
	"strconv"
	"sync"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

// siteStatusMap tracks runtime status of sites (running/stopped).
var (
	siteStatusMap   = make(map[uint]string)
	siteStatusMutex sync.RWMutex
)

func ListSites(repo *repository.SiteRepo) app.HandlerFunc {
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

func GetSite(repo *repository.SiteRepo) app.HandlerFunc {
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

func CreateSite(repo *repository.SiteRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var item store.Site
		if err := c.BindJSON(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := repo.Create(&item); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": item})
			return
		}
		c.JSON(201, item)
	}
}

func UpdateSite(repo *repository.SiteRepo, reload func() error) app.HandlerFunc {
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
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": existing})
			return
		}
		c.JSON(200, existing)
	}
}

func DeleteSite(repo *repository.SiteRepo, reload func() error) app.HandlerFunc {
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
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}

func StartSite(repo *repository.SiteRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		_, err = repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}

		siteStatusMutex.Lock()
		siteStatusMap[id] = "running"
		siteStatusMutex.Unlock()

		c.JSON(200, map[string]string{"status": "running", "message": "site started"})
	}
}

func StopSite(repo *repository.SiteRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		_, err = repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}

		siteStatusMutex.Lock()
		siteStatusMap[id] = "stopped"
		siteStatusMutex.Unlock()

		c.JSON(200, map[string]string{"status": "stopped", "message": "site stopped"})
	}
}

func GetSiteStatus(repo *repository.SiteRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		site, err := repo.Get(id)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}

		siteStatusMutex.RLock()
		status, exists := siteStatusMap[id]
		siteStatusMutex.RUnlock()

		if !exists {
			status = "stopped"
		}

		c.JSON(200, map[string]any{
			"id":     site.ID,
			"host":   site.Host,
			"status": status,
		})
	}
}
