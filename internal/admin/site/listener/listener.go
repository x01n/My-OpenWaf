package listener

import (
	"context"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	sitepkg "My-OpenWaf/internal/admin/site"
	snapshotpkg "My-OpenWaf/internal/snapshot"

	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
	"My-OpenWaf/internal/utils"
)

// ListSiteListeners 返回挂在某个站点下的全部监听记录。
// 站点没有任何记录时，用 legacy 的 Site.Bind/TLSEnabled/CertID 三元组
// 合成一条虚拟条目，保证 UI 至少能渲染出条目并提供「添加监听端口」。
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

// CreateSiteListener 给站点挂上一条新的监听。
// 第一条显式监听会迁移 legacy 的单 bind 配置：既有 legacy 条目由快照的
// 兜底路径纳入，但一旦站点存在显式记录，legacy 字段就不再被采用。
func CreateSiteListener(siteRepo *repository.SiteRepo, repo *repository.SiteListenerRepo, certRepo *repository.CertificateRepo, reload func() error) app.HandlerFunc {
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
		// 先填模型声明的默认值，再让请求体覆盖：json 只写出现过的字段，
		// 这样「未提供」保留默认值，「显式传 false/0」才能如实落库。
		_ = store.ApplyModelDefaults(&item)
		if err := c.BindJSON(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		item.ID = 0
		item.SiteID = site.ID
		if item.Network == "" {
			item.Network = "tcp"
		}
		if err := validateListenerNetwork(&item); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if item.Bind == "" {
			c.JSON(400, map[string]string{"error": "bind is required"})
			return
		}
		if err := shared.ValidateSiteTLSCertificate(item.TLSEnabled, item.CertID, certRepo); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}

		// 用户第一次显式定义监听时把 legacy 的单 bind 条目提升上来：
		// 把它持久化成真实记录，此后快照的兜底路径就再也不会被启用。
		existing, _ := repo.ListBySite(site.ID)
		var legacy *store.SiteListener
		if len(existing) == 0 && site.Bind != "" && site.Bind != item.Bind {
			legacy = &store.SiteListener{
				SiteID:     site.ID,
				Bind:       site.Bind,
				Network:    site.Network,
				TLSEnabled: site.TLSEnabled,
				CertID:     site.CertID,
				Enabled:    true,
				Note:       "migrated from legacy bind",
			}
		}

		if err := repo.CreateWithLegacyPromotion(&item, legacy); err != nil {
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

func UpdateSiteListener(siteRepo *repository.SiteRepo, repo *repository.SiteListenerRepo, certRepo *repository.CertificateRepo, reload func() error) app.HandlerFunc {
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
		site, err := siteRepo.Get(siteID)
		if err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}

		var existing *store.SiteListener
		if listenerID == 0 {
			existing = &store.SiteListener{
				SiteID:     site.ID,
				Bind:       site.Bind,
				Network:    site.Network,
				TLSEnabled: site.TLSEnabled,
				CertID:     site.CertID,
				Enabled:    site.Enabled,
				Note:       "migrated from legacy bind",
			}
		} else {
			existing, err = repo.Get(listenerID)
			if err != nil || existing.SiteID != siteID {
				c.JSON(404, map[string]string{"error": "listener not found"})
				return
			}
		}
		if err := c.BindJSON(existing); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		existing.ID = listenerID
		existing.SiteID = siteID
		if existing.Network == "" {
			existing.Network = "tcp"
		}
		if err := validateListenerNetwork(existing); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if existing.Bind == "" {
			c.JSON(400, map[string]string{"error": "bind is required"})
			return
		}
		if err := shared.ValidateSiteTLSCertificate(existing.TLSEnabled, existing.CertID, certRepo); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if listenerID == 0 {
			created, err := repo.CreateLegacyReplacement(existing)
			if err != nil {
				c.JSON(500, map[string]string{"error": err.Error()})
				return
			}
			if !created {
				c.JSON(404, map[string]string{"error": "listener not found"})
				return
			}
		} else if err := repo.Update(existing); err != nil {
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

func validateListenerNetwork(item *store.SiteListener) error {
	raw := strings.TrimSpace(item.Network)
	normalized := snapshotpkg.NormalizeNetwork(raw)
	if normalized == "" {
		return sitepkg.ErrInvalidSiteNetwork
	}
	item.Network = normalized
	return nil
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
		if _, err := siteRepo.Get(siteID); err != nil {
			c.JSON(404, map[string]string{"error": "site not found"})
			return
		}
		if listenerID == 0 {
			c.JSON(400, map[string]string{"error": "legacy listener cannot be deleted"})
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
			c.JSON(500, map[string]string{"error": "config applied but reload failed: " + err.Error()})
			return
		}
		c.JSON(204, nil)
	}
}
