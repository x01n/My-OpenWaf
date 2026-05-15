package admin

import (
	"context"
	"errors"
	"strconv"
	"strings"
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

type siteListItem struct {
	store.Site
	ListenerSummary      string `json:"listener_summary"`
	TLSSummary           string `json:"tls_summary"`
	ManagedListenerCount int    `json:"managed_listener_count"`
}

func ListSites(repo *repository.SiteRepo, listenerRepo *repository.SiteListenerRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		size, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))
		offset, limit := utils.Paginate(page, size)
		items, total, err := repo.List(offset, limit)
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}

		listeners, err := listenerRepo.AllEnabled()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		listenersBySite := make(map[uint][]store.SiteListener)
		for _, listener := range listeners {
			listenersBySite[listener.SiteID] = append(listenersBySite[listener.SiteID], listener)
		}

		respItems := make([]siteListItem, 0, len(items))
		for _, item := range items {
			listeners := listenersBySite[item.ID]
			managed := make([]store.SiteListener, 0, len(listeners))
			for _, listener := range listeners {
				if listener.ID > 0 {
					managed = append(managed, listener)
				}
			}

			listenerSummary := item.Bind
			tlsSummary := map[bool]string{true: "HTTPS", false: "HTTP"}[item.TLSEnabled]
			managedCount := len(managed)
			if managedCount > 0 {
				binds := make([]string, 0, managedCount)
				hasTLS := false
				for _, listener := range managed {
					binds = append(binds, listener.Bind)
					if listener.TLSEnabled {
						hasTLS = true
					}
				}
				listenerSummary = strings.Join(binds, " / ")
				if hasTLS {
					tlsSummary = "多监听（含 HTTPS）"
				} else {
					tlsSummary = "多监听（HTTP）"
				}
			}

			respItems = append(respItems, siteListItem{
				Site:                 item,
				ListenerSummary:      listenerSummary,
				TLSSummary:           tlsSummary,
				ManagedListenerCount: managedCount,
			})
		}

		c.JSON(200, map[string]any{"items": respItems, "total": total})
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

func CreateSite(repo *repository.SiteRepo, certRepo *repository.CertificateRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var item store.Site
		if err := BindSiteFromRequestBody(c.Request.Body(), &item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if err := validateSiteTLSCertificate(item.TLSEnabled, item.CertID, certRepo); err != nil {
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

func UpdateSite(repo *repository.SiteRepo, certRepo *repository.CertificateRepo, reload func() error) app.HandlerFunc {
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
		if err := BindSiteFromRequestBody(c.Request.Body(), existing); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		existing.ID = id
		if err := validateSiteTLSCertificate(existing.TLSEnabled, existing.CertID, certRepo); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
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

func validateSiteTLSCertificate(tlsEnabled bool, certID *uint, certRepo *repository.CertificateRepo) error {
	if !tlsEnabled {
		return nil
	}
	if certID == nil || *certID == 0 {
		return errors.New("TLS-enabled site requires cert_id")
	}
	if certRepo == nil {
		return nil
	}
	if _, err := certRepo.Get(*certID); err != nil {
		return errors.New("certificate not found")
	}
	return nil
}

func DeleteSite(repo *repository.SiteRepo, listenerRepo *repository.SiteListenerRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := utils.ParseUint(c.Param("id"))
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if err := repo.DeleteWithListeners(id); err != nil {
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

func StartSite(repo *repository.SiteRepo, reload func() error) app.HandlerFunc {
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

		site.Enabled = true
		if err := repo.Update(site); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": site})
			return
		}

		siteStatusMutex.Lock()
		siteStatusMap[id] = "running"
		siteStatusMutex.Unlock()

		c.JSON(200, map[string]string{"status": "running", "message": "site started"})
	}
}

func StopSite(repo *repository.SiteRepo, reload func() error) app.HandlerFunc {
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

		site.Enabled = false
		if err := repo.Update(site); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		if err := reload(); err != nil {
			c.JSON(500, map[string]any{"error": "config applied but reload failed: " + err.Error(), "item": site})
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
			if site.Enabled {
				status = "running"
			} else {
				status = "stopped"
			}
		}

		c.JSON(200, map[string]any{
			"id":     site.ID,
			"host":   site.Host,
			"status": status,
		})
	}
}
