package store

import (
	"time"

	"gorm.io/gorm"
)

// Policy is a named container for a group of rules.
type Policy struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name        string `gorm:"size:128;not null" json:"name"`
	Description string `gorm:"type:text" json:"description"`
	DefaultSlot *uint  `gorm:"uniqueIndex:ux_policies_default_slot" json:"-"`
	IsDefault   bool   `gorm:"-" json:"is_default"`
}

func (p *Policy) AfterFind(_ *gorm.DB) error {
	p.IsDefault = p.DefaultSlot != nil && *p.DefaultSlot == 1
	return nil
}

type RulePhase string

const (
	PhaseACL       RulePhase = "acl"
	PhaseRateLimit RulePhase = "rate_limit"
	PhaseOWASP     RulePhase = "owasp_default"
	PhaseSignature RulePhase = "signature"
	PhaseCustom    RulePhase = "custom"
)

type RuleAction string

const (
	ActionAllow            RuleAction = "allow"
	ActionIntercept        RuleAction = "intercept"
	ActionObserve          RuleAction = "observe"
	ActionDrop             RuleAction = "drop"
	ActionChallenge        RuleAction = "challenge"
	ActionCaptchaChallenge RuleAction = "captcha_challenge"
	ActionShieldChallenge  RuleAction = "shield_challenge"
	ActionChainChallenge   RuleAction = "chain_challenge"
	ActionRedirect         RuleAction = "redirect"
	ActionRateLimit        RuleAction = "rate_limit"
	ActionTag              RuleAction = "tag"

	// Legacy values for backward compatibility with existing DB rows.
	ActionBlock   RuleAction = "block"
	ActionLogOnly RuleAction = "log_only"
)

// NormalizeAction maps legacy action strings to canonical form.
func NormalizeAction(a RuleAction) RuleAction {
	switch a {
	case ActionBlock:
		return ActionIntercept
	case ActionLogOnly:
		return ActionObserve
	default:
		return a
	}
}

// Rule is a single rule entry that belongs to a Policy.
type Rule struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name       string     `gorm:"size:128" json:"name"`
	PolicyID   uint       `gorm:"not null;index" json:"policy_id"`
	Phase      RulePhase  `gorm:"size:32;not null;index" json:"phase"`
	Pattern    string     `gorm:"type:text;not null" json:"pattern"`
	Action     RuleAction `gorm:"size:32;not null" json:"action"`
	Priority   int        `gorm:"default:100" json:"priority"`
	Enabled    bool       `gorm:"default:true" json:"enabled"`
	StatusCode int        `gorm:"default:0" json:"status_code"`
	RedirectTo string     `gorm:"size:2048" json:"redirect_to"`
	// CaptchaType 为空时继承全局验证码类型，仅对 captcha_challenge 生效。
	CaptchaType string `gorm:"size:16" json:"captcha_type,omitempty"`

	// WindowSeconds 与 RequestCount 是规则级频次限制参数（秒 / 次数）。
	// 二者同时大于 0 时，规则条件在快照编译期被包装成 cc_rate 复合条件：
	// 命中本规则条件的请求按 clientIP|host 计数，窗口内达到 RequestCount
	// 次后执行本规则的 Action。任一为 0 表示不做频次限制。
	WindowSeconds int `gorm:"default:0" json:"window_seconds"`
	RequestCount  int `gorm:"default:0" json:"request_count"`
	// CaptchaMinutes 是规则级验证码通过有效期（分钟），语义与保护配置的
	// captcha_pass_ttl 一致，但作用于单条规则；0 表示继承全局配置。
	CaptchaMinutes int `gorm:"default:0" json:"captcha_minutes"`
}
