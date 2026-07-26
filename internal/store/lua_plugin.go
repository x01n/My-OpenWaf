package store

import (
	"time"

	"gorm.io/gorm"
)

// Lua 插件的执行阶段。与 luaplugin.Stage 保持一致。
const (
	// LuaStagePre 在 ACL 之后、OWASP 之前执行，可在昂贵检测前提早判定。
	LuaStagePre = "pre"
	// LuaStagePost 在全部内置阶段之后执行，能读到内置判定并对误报放行。
	LuaStagePost = "post"
)

// LuaPlugin 是一段用户自定义的 Lua 策略脚本。
type LuaPlugin struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name string `gorm:"size:128;not null" json:"name"`
	// Stage 取 pre 或 post，见上方常量。
	Stage string `gorm:"size:16;not null;index" json:"stage"`
	// Source 是 Lua 源码，必须定义全局函数 handle(ctx)。
	//
	// 不设 DB 默认值：MySQL 禁止 BLOB/TEXT 列带 DEFAULT（Error 1101），
	// 带上会让 AutoMigrate 直接失败。
	Source  string `gorm:"type:text;not null" json:"source"`
	Enabled bool   `gorm:"default:true" json:"enabled"`
	// Priority 决定同阶段内的执行顺序，数值小者先执行。
	Priority int `gorm:"default:100" json:"priority"`
	// SiteID 为 0 表示全站生效；非 0 时仅对该站点生效。
	//
	// 用 *uint 而非 uint：需要区分「未指定（全站）」与「指定站点 0」。
	SiteID *uint `gorm:"index" json:"site_id"`
	// TimeoutMS 覆盖该脚本的执行超时（毫秒），0 表示用默认值。
	TimeoutMS int `gorm:"default:0" json:"timeout_ms"`
	// Description 供运维标注脚本用途。
	Description string `gorm:"size:512" json:"description"`
}

func (LuaPlugin) TableName() string { return "lua_plugins" }

// ValidLuaStage 报告 stage 取值是否受支持。
func ValidLuaStage(stage string) bool {
	return stage == LuaStagePre || stage == LuaStagePost
}
