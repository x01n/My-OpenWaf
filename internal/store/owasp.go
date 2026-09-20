package store

import "time"

// OWASPRuleCatalog stores metadata for built-in detector rules without duplicating executable patterns.
type OWASPRuleCatalog struct {
	ID                 uint      `gorm:"primaryKey" json:"id"`
	RuleID             string    `gorm:"size:128;not null;uniqueIndex;index:idx_owasp_active_rule_id,priority:2;index:idx_owasp_active_category_rule_id,priority:3" json:"builtin_id"`
	Category           string    `gorm:"size:64;not null;index;index:idx_owasp_active_category_rule_id,priority:2" json:"category"`
	Name               string    `gorm:"size:255;not null" json:"name"`
	Description        string    `gorm:"type:text" json:"description"`
	DefaultEnabled     bool      `gorm:"not null;default:true" json:"default_enabled"`
	DefaultAction      string    `gorm:"size:32;not null;default:'intercept'" json:"default_action"`
	DefaultSensitivity string    `gorm:"size:32" json:"default_sensitivity"`
	BuiltinVersion     string    `gorm:"size:32;not null;default:'1'" json:"builtin_version"`
	Active             bool      `gorm:"not null;default:true;index;index:idx_owasp_active_rule_id,priority:1;index:idx_owasp_active_category_rule_id,priority:1" json:"active"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// PolicyOWASPRuleConfig stores nullable per-policy overrides for one built-in rule.
type PolicyOWASPRuleConfig struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	PolicyID    uint      `gorm:"not null;uniqueIndex:ux_policy_owasp_rule" json:"policy_id"`
	RuleID      string    `gorm:"size:128;not null;uniqueIndex:ux_policy_owasp_rule" json:"builtin_id"`
	Enabled     *bool     `json:"enabled,omitempty"`
	Action      *string   `gorm:"size:32" json:"action,omitempty"`
	Sensitivity *string   `gorm:"size:32" json:"sensitivity,omitempty"`
	StatusCode  *int      `json:"status_code,omitempty"`
	RedirectTo  *string   `gorm:"type:text" json:"redirect_to,omitempty"`
	CaptchaType *string   `gorm:"size:16" json:"captcha_type,omitempty"`
	Whitelist   *string   `gorm:"type:text" json:"whitelist_json,omitempty"`
	Note        *string   `gorm:"type:text" json:"note,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
