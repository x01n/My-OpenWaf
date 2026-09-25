package store

import "time"

/**
 * ThreatIntelFeed 威胁情报订阅源。
 *
 * 每条记录描述一个可在线订阅的 IP/CIDR 列表来源（URL），系统按 SyncInterval
 * 定期拉取并全量替换该来源在 IPListEntry 中的条目。参考雷池 WAF 的
 * “IP 组通过 URL 在线订阅”能力设计。
 */
type ThreatIntelFeed struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Name   string `gorm:"size:100;not null" json:"name"`
	URL    string `gorm:"size:500;not null" json:"url"`
	Kind   string `gorm:"size:16;not null" json:"kind"`              // "blacklist" / "whitelist"
	Action string `gorm:"size:16;default:'intercept'" json:"action"` // "intercept" / "drop"
	// AuthHeaderName 可选认证头名（如 Authorization），与 AuthHeaderValue 同时非空时拉取才附带。
	AuthHeaderName string `gorm:"size:100" json:"auth_header_name,omitempty"`
	// AuthHeaderValue 可选认证头值（如 "Bearer xxx"），与 AuthHeaderName 同时非空才生效；明文存储。
	AuthHeaderValue string `gorm:"size:512" json:"auth_header_value,omitempty"`
	Enabled         bool   `gorm:"default:true" json:"enabled"`

	SyncInterval int   `gorm:"default:3600" json:"sync_interval"` // 同步间隔（秒）
	SiteID       *uint `gorm:"index" json:"site_id,omitempty"`    // nil = 全局

	LastSyncAt *time.Time `json:"last_sync_at,omitempty"`
	LastError  string     `gorm:"size:500" json:"last_error,omitempty"`
	EntryCount int        `json:"entry_count"`
}
