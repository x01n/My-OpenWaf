package system

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"

	"My-OpenWaf/internal/admin/auth"
	"My-OpenWaf/internal/admin/shared"
	"My-OpenWaf/internal/store"
	"My-OpenWaf/internal/store/repository"
)

// ThreatIntelSyncer 抽象订阅管理器的手动同步能力，避免 admin 直接依赖具体实现。
type ThreatIntelSyncer interface {
	SyncNow(feedID uint) error
}

// maskedThreatIntelItems 遮蔽列表项的认证头值，避免订阅令牌明文落入
// 低权限（operator/readonly）用户的列表响应。admin 角色与 API key
// （同为 admin 角色）保持明文，便于管理面回显。
func maskedThreatIntelItems(c *app.RequestContext, items []store.ThreatIntelFeed) []store.ThreatIntelFeed {
	if role, _ := c.Get("auth_role"); role == auth.RoleAdmin {
		return items
	}
	masked := make([]store.ThreatIntelFeed, len(items))
	copy(masked, items)
	for i := range masked {
		if masked[i].AuthHeaderValue == "" {
			continue
		}
		masked[i].AuthHeaderValue = maskAuthHeaderValue(masked[i].AuthHeaderValue)
	}
	return masked
}

// maskAuthHeaderValue 遮蔽认证头值：长度不足 5 的全部标星，否则保留前 4 位加 ***。
func maskAuthHeaderValue(value string) string {
	if value == "" {
		return ""
	}
	if len(value) < 5 {
		return "***"
	}
	return value[:4] + "***"
}

// ListThreatIntelFeeds 列出全部威胁情报订阅源。
func ListThreatIntelFeeds(repo *repository.ThreatIntelRepo) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		items, err := repo.List()
		if err != nil {
			c.JSON(500, map[string]string{"error": err.Error()})
			return
		}
		c.JSON(200, map[string]any{"items": maskedThreatIntelItems(c, items), "total": len(items)})
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
	if kind == string(store.IPListWhite) {
		return kind, "intercept", true
	}
	return kind, normAction, true
}

// CreateThreatIntelFeed 新建订阅源。
func CreateThreatIntelFeed(repo *repository.ThreatIntelRepo, reload func() error) app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var body store.ThreatIntelFeed
		// 先填模型声明的默认值，再让请求体覆盖：json 只写出现过的字段，
		// 这样「未提供」保留默认值，「显式传 false/0」才能如实落库。
		_ = store.ApplyModelDefaults(&body)
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
		// 可选认证头：trim 掉两侧空白，避免无意义地发送纯空格头。
		body.AuthHeaderName = strings.TrimSpace(body.AuthHeaderName)
		body.AuthHeaderValue = strings.TrimSpace(body.AuthHeaderValue)
		if len(body.AuthHeaderName) > 100 || len(body.AuthHeaderValue) > 512 {
			c.JSON(400, map[string]string{"error": "auth header name/value too long"})
			return
		}
		// 忽略客户端传入的运行态字段。
		body.LastSyncAt = nil
		body.LastError = ""
		body.EntryCount = 0

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
			Name            *string         `json:"name"`
			URL             *string         `json:"url"`
			Kind            *string         `json:"kind"`
			Action          *string         `json:"action"`
			Enabled         *bool           `json:"enabled"`
			SyncInterval    *int            `json:"sync_interval"`
			SiteID          json.RawMessage `json:"site_id"`
			AuthHeaderName  *string         `json:"auth_header_name"`
			AuthHeaderValue *string         `json:"auth_header_value"`
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
		if body.AuthHeaderName != nil {
			existing.AuthHeaderName = strings.TrimSpace(*body.AuthHeaderName)
		}
		if body.AuthHeaderValue != nil {
			existing.AuthHeaderValue = strings.TrimSpace(*body.AuthHeaderValue)
		}
		if len(existing.AuthHeaderName) > 100 || len(existing.AuthHeaderValue) > 512 {
			c.JSON(400, map[string]string{"error": "auth header name/value too long"})
			return
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
			// SyncNow 失败时完整错误已落入该 feed 的 LastError 列（recordResult），
			// 同步日志表保留 1000 字节明细；HTTP 层只回错误摘要，避免把拉取
			// 超时/响应采样等长文本整体透传给 500 客户端页面。
			c.JSON(500, map[string]string{"error": "同步失败，详情见该订阅源的 last_error 与同步日志"})
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
