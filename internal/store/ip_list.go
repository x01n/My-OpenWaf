package store

import (
	"time"

	"gorm.io/gorm"
)

type IPListKind string

const (
	IPListBlack IPListKind = "blacklist"
	IPListWhite IPListKind = "whitelist"
)

// IPListEntry stores one blacklist or whitelist record (IP or CIDR).
type IPListEntry struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Kind    IPListKind `gorm:"size:16;not null;index" json:"kind"`
	Value   string     `gorm:"size:64;not null;index" json:"value"`
	Note    string     `gorm:"size:255" json:"note"`
	Enabled bool       `gorm:"default:true" json:"enabled"`
	Action  string     `json:"action" gorm:"default:'intercept'"` // "intercept" or "block"
	SiteID  *uint      `gorm:"index" json:"site_id,omitempty"`    // nil = 全局
	FeedID  *uint      `gorm:"index" json:"feed_id,omitempty"`    // nil = 手动添加，有值 = 来自订阅源
}
