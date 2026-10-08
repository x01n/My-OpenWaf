package migrations

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// v7 访问控制模型的表结构定义，与 internal/store 中的字段保持一致，
// 仅用于在迁移包内建表，避免迁移包反向依赖 store 包。
type accessControlSiteConfig struct {
	ID                 uint   `gorm:"primarykey"`
	SiteID             uint   `gorm:"uniqueIndex;not null"`
	Enabled            bool   `gorm:"default:false"`
	SharedPasswordHash string `gorm:"size:255"`
	SessionTTL         int    `gorm:"default:86400"`
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (accessControlSiteConfig) TableName() string { return "site_access_configs" }

type accessControlProvider struct {
	ID        uint   `gorm:"primarykey"`
	SiteID    uint   `gorm:"index;not null"`
	Type      string `gorm:"size:20;not null"`
	Name      string `gorm:"size:100;not null"`
	Priority  int    `gorm:"default:0"`
	Enabled   bool   `gorm:"default:true"`
	Config    string `gorm:"type:text"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (accessControlProvider) TableName() string { return "access_providers" }

type accessControlUser struct {
	ID           uint   `gorm:"primarykey"`
	SiteID       uint   `gorm:"not null;uniqueIndex:ux_access_user_site_name"`
	Username     string `gorm:"size:100;not null;uniqueIndex:ux_access_user_site_name"`
	PasswordHash string `gorm:"size:255;not null"`
	Enabled      bool   `gorm:"default:true"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (accessControlUser) TableName() string { return "access_users" }

type accessControlPathRule struct {
	ID        uint   `gorm:"primarykey"`
	SiteID    uint   `gorm:"index;not null"`
	Path      string `gorm:"size:500;not null"`
	Action    string `gorm:"size:20;not null;default:'require_auth'"`
	Priority  int    `gorm:"default:0"`
	Enabled   bool   `gorm:"default:true"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (accessControlPathRule) TableName() string { return "access_path_rules" }

type accessControlSession struct {
	ID        uint      `gorm:"primarykey"`
	SiteID    uint      `gorm:"index;not null"`
	Token     string    `gorm:"uniqueIndex;size:64;not null"`
	Identity  string    `gorm:"size:255"`
	Provider  string    `gorm:"size:20"`
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
}

func (accessControlSession) TableName() string { return "access_sessions" }

// V7MigrateAccessControl 创建站点访问控制相关的所有表及其索引。
// 这些均为新表，使用 AutoMigrate 建表并按标签补齐索引，多次执行保持幂等。
func V7MigrateAccessControl(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&accessControlSiteConfig{},
		&accessControlProvider{},
		&accessControlUser{},
		&accessControlPathRule{},
		&accessControlSession{},
	); err != nil {
		return fmt.Errorf("failed to migrate access control tables: %w", err)
	}
	return nil
}
