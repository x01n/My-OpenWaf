package store

import (
	"time"

	"gorm.io/gorm"
)

// JS 插件的执行阶段。
const (
	JSStageRequest  = "request"
	JSStageResponse = "response"
)

// JS 插件遇到执行错误时的处理模式。
const (
	JSFailureModeOpen   = "fail_open"
	JSFailureModeClosed = "fail_closed"
)

// JSPlugin 是一段用户自定义的 JavaScript 边缘脚本配置。
//
// 字段只描述持久化契约，不包含具体 JavaScript runtime 的执行语义。
// 默认值和字段取值校验由上层 handler 或运行时负责。
type JSPlugin struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name   string `gorm:"size:128;not null" json:"name"`
	Source string `gorm:"type:text;not null" json:"source"`

	Enabled  bool  `json:"enabled"`
	Priority int   `json:"priority"`
	SiteID   *uint `gorm:"index" json:"site_id"`

	Stage       string `gorm:"size:16;not null;index" json:"stage"`
	FailureMode string `gorm:"size:16;not null" json:"failure_mode"`
	TimeoutMS   int    `json:"timeout_ms"`
	Description string `gorm:"size:512" json:"description"`
}

func (JSPlugin) TableName() string { return "js_plugins" }
