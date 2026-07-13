package store

import (
	"time"

	"gorm.io/gorm"
)

/**
 * FalsePositiveReport 记录管理员标记的误报事件。
 *
 * 管理员在攻击详情中点击"这是误报"时创建一条记录，供后续人工审查或
 * 用于规则调优反馈。冗余保存源事件的关键字段（rule_id_str/category/
 * client_ip 等），即使原始 SecurityEvent 已被归档也能查询。
 */
type FalsePositiveReport struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// 关联的安全事件（仅记录 ID，事件本身可能已过期归档）。
	SecurityEventID uint   `gorm:"index" json:"security_event_id"`
	RequestID       string `gorm:"size:64;index" json:"request_id"`

	// 冗余字段：即使原事件已归档，反馈记录仍可查询完整上下文。
	RuleIDStr string `gorm:"size:100;index" json:"rule_id_str"`
	Category  string `gorm:"size:64;index" json:"category"`
	ClientIP  string `gorm:"size:64" json:"client_ip"`
	Host      string `gorm:"size:255" json:"host"`
	Path      string `gorm:"size:1024" json:"path"`
	MatchDesc string `gorm:"size:1024" json:"match_desc"`

	// 提交者信息与备注。
	SubmittedBy string `gorm:"size:100;index" json:"submitted_by"`
	Note        string `gorm:"size:2000" json:"note"`

	// 审查状态：pending / confirmed / rejected。
	Status string `gorm:"size:20;default:'pending';index" json:"status"`
}
