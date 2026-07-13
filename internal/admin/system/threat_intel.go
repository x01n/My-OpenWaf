package system

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// ThreatIntelSyncer 抽象订阅管理器的手动同步能力，避免 admin 直接依赖具体实现。
type ThreatIntelSyncer interface {
	SyncNow(feedID uint) error
}

// ListThreatIntelFeeds 列出全部威胁情报订阅源。
func ListThreatIntelFeeds(repo *repository.ThreatIntelRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		items, err := repo.List()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": items, "total": len(items)})
	}
}

// normalizeFeedFields 校验并归一化订阅源的 kind/action 字段。
func normalizeFeedFields(kind, action string) (string, string, bool) {
	if kind != string(store.IPListBlack) && kind != string(store.IPListWhite) {
		return "", "", false
	}
	normAction, ok := normalizeIPListAction(action)
	if !ok {
		return "", "", false
	}
	return kind, normAction, true
}

// CreateThreatIntelFeed 新建订阅源。
func CreateThreatIntelFeed(repo *repository.ThreatIntelRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var body store.ThreatIntelFeed
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if body.Name == "" {
			c.JSON(400, map[string]string{"error": "name required"})
			return
		}
		if body.URL == "" {
			c.JSON(400, map[string]string{"error": "url required"})
			return
		}
		kind, action, ok := normalizeFeedFields(body.Kind, body.Action)
		if !ok {
			c.JSON(400, map[string]string{"error": "kind must be blacklist or whitelist; action must be intercept or drop"})
			return
		}
		body.Kind = kind
		body.Action = action
		if body.SyncInterval <= 0 {
			body.SyncInterval = 3600
		}
		// 忽略客户端传入的运行态字段。
		body.LastSyncAt = nil
		body.LastError = ""
		body.EntryCount = 0

		if err := repo.Create(&body); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(201, body)
	}
}

// UpdateThreatIntelFeed 更新订阅源。仅覆盖显式提供的字段。
func UpdateThreatIntelFeed(repo *repository.ThreatIntelRepo, reload func() error) app.HandlerFunc {
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
			Name         *string `json:"name"`
			URL          *string `json:"url"`
			Kind         *string `json:"kind"`
			Action       *string `json:"action"`
			Enabled      *bool   `json:"enabled"`
			SyncInterval *int    `json:"sync_interval"`
			SiteID       **uint  `json:"site_id"`
		}
		if err := c.BindJSON(&body); err != nil {
			c.JSON(400, map[string]string{"error": err.Error()})
			return
		}
		if body.Name != nil {
			existing.Name = *body.Name
		}
		if existing.Name == "" {
			c.JSON(400, map[string]string{"error": "name required"})
			return
		}
		if body.URL != nil {
			existing.URL = *body.URL
		}
		if existing.URL == "" {
			c.JSON(400, map[string]string{"error": "url required"})
			return
		}
		if body.Kind != nil {
			existing.Kind = *body.Kind
		}
		if body.Action != nil {
			existing.Action = *body.Action
		}
		kind, action, ok := normalizeFeedFields(existing.Kind, existing.Action)
		if !ok {
			c.JSON(400, map[string]string{"error": "kind must be blacklist or whitelist; action must be intercept or drop"})
			return
		}
		existing.Kind = kind
		existing.Action = action
		if body.Enabled != nil {
			existing.Enabled = *body.Enabled
		}
		if body.SyncInterval != nil {
			if *body.SyncInterval <= 0 {
				c.JSON(400, map[string]string{"error": "sync_interval must be positive"})
				return
			}
			existing.SyncInterval = *body.SyncInterval
		}
		if body.SiteID != nil {
			existing.SiteID = *body.SiteID
		}
		if err := repo.Update(existing); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, existing)
	}
}

// DeleteThreatIntelFeed 删除订阅源及其派生的所有 IP 条目，随后触发 reload。
func DeleteThreatIntelFeed(repo *repository.ThreatIntelRepo, reload func() error) app.HandlerFunc {
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

// SyncThreatIntelFeed 手动立即同步指定订阅源。
func SyncThreatIntelFeed(repo *repository.ThreatIntelRepo, syncer ThreatIntelSyncer) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		id, err := shared.ParseUintParam(c, "id")
		if err != nil {
			c.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if syncer == nil {
			c.JSON(503, map[string]string{"error": "threat intel manager unavailable"})
			return
		}
		if err := syncer.SyncNow(id); err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		item, err := repo.Get(id)
		if err != nil {
			c.JSON(200, map[string]string{"status": "synced"})
			return
		}
		c.JSON(200, item)
	}
}
