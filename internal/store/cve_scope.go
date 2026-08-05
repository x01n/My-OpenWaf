package store

import "time"

const (
	CVEScopeGlobal = "global"
	CVEScopePolicy = "policy"
	CVEScopeSite   = "site"
)

// CVERuleScopeOverride stores nullable per-field CVE configuration at one explicit scope.
type CVERuleScopeOverride struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	RuleID      uint      `gorm:"not null;uniqueIndex:ux_cve_rule_scope" json:"rule_id"`
	ScopeType   string    `gorm:"size:16;not null;uniqueIndex:ux_cve_rule_scope" json:"scope"`
	ScopeID     uint      `gorm:"not null;uniqueIndex:ux_cve_rule_scope" json:"scope_id"`
	Enabled     *bool     `json:"enabled,omitempty"`
	Action      *string   `gorm:"size:32" json:"action,omitempty"`
	Sensitivity *string   `gorm:"size:32" json:"sensitivity,omitempty"`
	StatusCode  *int      `json:"status_code,omitempty"`
	RedirectTo  *string   `gorm:"type:text" json:"redirect_to,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
