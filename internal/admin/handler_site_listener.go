package admin

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

// ListSiteListeners returns every listener row attached to a site.
// When the site has no rows we synthesise a single virtual entry from the
// legacy Site.Bind/TLSEnabled/CertID triplet so the UI can always render
// at least one entry and offer "添加监听端口".
func ListSiteListeners(siteRepo *repository.SiteRepo, repo *repository.SiteListenerRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		site, err := siteRepo.Get(siteID)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		items, err := repo.ListBySite(siteID)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if len(items) == 0 {
			items = append(items, store.SiteListener{
				SiteID:     site.ID,
				Bind:       site.Bind,
				Network:    site.Network,
				TLSEnabled: site.TLSEnabled,
				CertID:     site.CertID,
				Enabled:    site.Enabled,
				Note:       "legacy",
			})
		}
		c.JSON(200, map[string]any{"items": items, "total": len(items)})
	}
}

// CreateSiteListener attaches a new listener to a site.
// First explicit listener migrates the legacy single-bind config: the
// existing legacy entry is folded in by the snapshot fallback path, but
// once an explicit row exists for the site the legacy fields are ignored.
func CreateSiteListener(siteRepo *repository.SiteRepo, repo *repository.SiteListenerRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		site, err := siteRepo.Get(siteID)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}

		var item store.SiteListener
		if err := c.BindJSON(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		item.ID = 0
		item.SiteID = site.ID
		if item.Network == "" {
			item.Network = "tcp"
		}
		if item.Bind == "" {
			c.JSON(400, map[string]string{"error": "bind is required"})
			return
		}
		if item.TLSEnabled && (item.CertID == nil || *item.CertID == 0) {
			c.JSON(400, map[string]string{"error": "TLS-enabled listener requires cert_id"})
			return
		}

		// Promote the legacy single-bind entry the first time the user
		// explicitly defines a listener: persist it as a real row so the
		// snapshot fallback path is never re-engaged afterwards.
		existing, _ := repo.ListBySite(site.ID)
		if len(existing) == 0 && site.Bind != "" && site.Bind != item.Bind {
			legacy := store.SiteListener{
				SiteID:     site.ID,
				Bind:       site.Bind,
				Network:    site.Network,
				TLSEnabled: site.TLSEnabled,
				CertID:     site.CertID,
				Enabled:    true,
				Note:       "migrated from legacy bind",
			}
			if err := repo.Create(&legacy); err != nil {
				c.JSON(500, map[string]string{"error": err.Error()})
				return
			}
		}

		if err := repo.Create(&item); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "saved but reload failed: " + err.Error(), "item": item})
			return
		}
		c.JSON(201, item)
	}
}

func UpdateSiteListener(siteRepo *repository.SiteRepo, repo *repository.SiteListenerRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		listenerID, err := utils.ParseUint(c.Param("lid"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid listener id"})
			return
		}
		if _, err := siteRepo.Get(siteID); err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		existing, err := repo.Get(listenerID)
		if err != nil || existing.SiteID != siteID {
			c.JSON(404, map[string]string{"error": "listener not found"})
			return
		}
		if err := c.BindJSON(existing); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		existing.ID = listenerID
		existing.SiteID = siteID
		if existing.TLSEnabled && (existing.CertID == nil || *existing.CertID == 0) {
			c.JSON(400, map[string]string{"error": "TLS-enabled listener requires cert_id"})
			return
		}
		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "saved but reload failed: " + err.Error(), "item": existing})
			return
		}
		c.JSON(200, existing)
	}
}

func DeleteSiteListener(siteRepo *repository.SiteRepo, repo *repository.SiteListenerRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		siteID, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid site id"})
			return
		}
		listenerID, err := utils.ParseUint(c.Param("lid"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid listener id"})
			return
		}
		existing, err := repo.Get(listenerID)
		if err != nil || existing.SiteID != siteID {
			c.JSON(404, map[string]string{"error": "listener not found"})
			return
		}
		if err := repo.Delete(listenerID); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]string{"error": "deleted but reload failed: " + err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}
